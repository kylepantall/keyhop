#!/usr/bin/env bash
set -euo pipefail

# Installs keyhop from GitHub on macOS: a private Bun if needed, the app, the
# Touch ID helper (compiled here with swiftc) and a launcher in ~/.local/bin.
# KEYHOP_SOURCE_DIR installs from a local checkout instead of downloading.
KEYHOP_REPO="${KEYHOP_REPO:-kylepantall/keyhop}"
BUN_VERSION=1.4.3

step() { printf '\n==> %s\n' "$*"; }
info() { printf '    %s\n' "$*"; }

# Runs a noisy command quietly, showing its output only if it fails.
quiet() {
  local log="$KEYHOP_INSTALL_TEMP/step.log"
  if ! "$@" >"$log" 2>&1; then
    sed 's/^/    | /' "$log" >&2
    return 1
  fi
}

sha256() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  else sha256sum "$1" | awk '{print $1}'; fi
}

main() {
  local ref='main' register_claude=false run_setup=true
  while (($#)); do
    case "$1" in
      --help | -h)
        printf 'Usage: bash install.sh [--claude] [--no-setup] [REF]\n'
        printf 'Installs %s (branch, tag or commit; default main) under ~/.local/share/keyhop\n' "$KEYHOP_REPO"
        printf 'with a launcher in ~/.local/bin, then runs "keyhop setup" on a first install.\n'
        printf '%s\n' '--claude registers it with Claude Code (user scope) without asking.'
        printf 'Override with KEYHOP_INSTALL_DIR, KEYHOP_BIN_DIR, KEYHOP_REPO and KEYHOP_SOURCE_DIR.\n'
        return
        ;;
      --claude) register_claude=true ;;
      --no-setup) run_setup=false ;;
      -*) printf 'Unknown option: %s\n' "$1" >&2; return 1 ;;
      *) ref="$1" ;;
    esac
    shift
  done
  if [[ ! "$ref" =~ ^[A-Za-z0-9._/-]+$ || "$ref" == *..* || "$ref" == /* || "$ref" == */ ]]; then
    printf 'Invalid ref: %s\n' "$ref" >&2
    return 1
  fi
  [[ -n "${HOME:-}" ]] || { printf 'HOME must be set.\n' >&2; return 1; }
  if [[ "$(uname -s)" != Darwin ]]; then
    printf 'keyhop needs Touch ID (macOS) or Windows Hello (use install.ps1 on Windows).\n' >&2
    return 1
  fi
  local source_label="$KEYHOP_REPO@$ref"
  [[ -z "${KEYHOP_SOURCE_DIR:-}" ]] || source_label="$KEYHOP_SOURCE_DIR"
  printf 'keyhop installer — %s\n' "$source_label"

  KEYHOP_INSTALL_TEMP="$(mktemp -d)"
  local temp_dir="$KEYHOP_INSTALL_TEMP"
  trap 'rm -rf -- "$KEYHOP_INSTALL_TEMP"' EXIT

  step 'Checking tools'
  command -v swiftc >/dev/null 2>&1 || {
    printf 'swiftc not found. Install the Xcode command line tools, then rerun:\n  xcode-select --install\n' >&2
    return 1
  }
  info "swiftc: $(command -v swiftc)"
  if command -v op >/dev/null 2>&1; then info "1Password CLI: $(command -v op)"
  else info '1Password CLI not found (optional): brew install 1password-cli'; fi

  local install_dir="${KEYHOP_INSTALL_DIR:-$HOME/.local/share/keyhop}"
  local bin_dir="${KEYHOP_BIN_DIR:-$HOME/.local/bin}"
  mkdir -p "$install_dir" "$bin_dir"
  install_dir="$(cd "$install_dir" && pwd)"
  bin_dir="$(cd "$bin_dir" && pwd)"

  step 'Bun runtime'
  local bun_bin
  if command -v bun >/dev/null 2>&1 &&
    bun -e "process.exit(Bun.semver.satisfies(Bun.version, '>=$BUN_VERSION') ? 0 : 1)" >/dev/null 2>&1; then
    bun_bin="$(command -v bun)"
    info "Using $bun_bin ($("$bun_bin" --version))"
  elif [[ -x "$install_dir/runtime/bun-$BUN_VERSION/bun" ]]; then
    bun_bin="$install_dir/runtime/bun-$BUN_VERSION/bun"
    info "Using private Bun $BUN_VERSION from a previous install"
  else
    local arch archive expected base="https://github.com/oven-sh/bun/releases/download/bun-v$BUN_VERSION"
    case "$(uname -m)" in
      arm64 | aarch64) arch=aarch64 ;;
      x86_64) arch=x64-baseline ;;
      *) printf 'Unsupported architecture. Install Bun %s+ first.\n' "$BUN_VERSION" >&2; return 1 ;;
    esac
    archive="bun-darwin-$arch.zip"
    info "Downloading a private Bun $BUN_VERSION ($archive) and verifying its checksum"
    curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 "$base/SHASUMS256.txt" -o "$temp_dir/SHASUMS256.txt"
    expected="$(awk -v file="$archive" '$2 == file || $2 == ("*" file) {print $1; exit}' "$temp_dir/SHASUMS256.txt")"
    [[ "$expected" =~ ^[a-f0-9]{64}$ ]] || { printf 'Bun archive checksum not found.\n' >&2; return 1; }
    curl -fsSL --connect-timeout 10 --max-time 120 --retry 2 "$base/$archive" -o "$temp_dir/$archive"
    [[ "$(sha256 "$temp_dir/$archive")" == "$expected" ]] || { printf 'Bun checksum mismatch.\n' >&2; return 1; }
    unzip -q "$temp_dir/$archive" -d "$temp_dir"
    local runtime_dir="$install_dir/runtime/bun-$BUN_VERSION"
    mkdir -p "$runtime_dir"
    cp "$temp_dir/${archive%.zip}/bun" "$runtime_dir/.bun-new"
    chmod +x "$runtime_dir/.bun-new"
    mv -f "$runtime_dir/.bun-new" "$runtime_dir/bun"
    bun_bin="$runtime_dir/bun"
    info "Installed to $bun_bin"
  fi

  # Build into a fresh directory and swap it in, so a failed build leaves the
  # working install untouched. Vault data lives elsewhere (~/.config/keyhop).
  local staging="$install_dir/app.new"
  rm -rf -- "$staging"
  mkdir -p "$staging"
  step 'Fetching source'
  if [[ -n "${KEYHOP_SOURCE_DIR:-}" ]]; then
    info "Copying $KEYHOP_SOURCE_DIR"
    (cd "$KEYHOP_SOURCE_DIR" && git ls-files -z --cached --others --exclude-standard |
      xargs -0 tar -cf - --) | tar -xf - -C "$staging"
  else
    info "Downloading github.com/$KEYHOP_REPO ($ref)"
    curl -fsSL --connect-timeout 10 --max-time 300 --retry 2 \
      "https://codeload.github.com/$KEYHOP_REPO/tar.gz/$ref" -o "$temp_dir/source.tar.gz"
    tar -xzf "$temp_dir/source.tar.gz" -C "$staging" --strip-components 1
  fi

  step 'Installing dependencies'
  (cd "$staging" && quiet "$bun_bin" install --frozen-lockfile --production --ignore-scripts)
  info 'Done'

  step 'Building the Touch ID helper'
  mkdir -p "$staging/native/build"
  (cd "$staging" && quiet swiftc -O native/macos/keyhop-auth.swift -o native/build/keyhop-auth)
  info 'Done'

  rm -rf -- "$install_dir/app.old"
  [[ ! -d "$install_dir/app" ]] || mv "$install_dir/app" "$install_dir/app.old"
  mv "$staging" "$install_dir/app"
  rm -rf -- "$install_dir/app.old"
  info "Installed into $install_dir/app"

  step 'Installing launcher'
  local launcher
  launcher="$(mktemp "$bin_dir/.keyhop.XXXXXX")"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'export KEYHOP_LAUNCHER=%q\n' "$bin_dir/keyhop"
    printf 'exec %q %q "$@"\n' "$bun_bin" "$install_dir/app/src/index.ts"
  } >"$launcher"
  chmod +x "$launcher"
  mv -f "$launcher" "$bin_dir/keyhop"
  info "$bin_dir/keyhop (version $("$bin_dir/keyhop" --version 2>&1))"

  if [[ "$register_claude" == true ]]; then
    step 'Registering with Claude Code'
    command -v claude >/dev/null 2>&1 || { printf 'claude CLI not found.\n' >&2; return 1; }
    if claude mcp get keyhop >/dev/null 2>&1; then
      info 'Already registered.'
    elif quiet claude mcp add --transport stdio --scope user keyhop -- "$bin_dir/keyhop" serve; then
      info 'Added "keyhop" (user scope). Start a new Claude session to load it.'
    else
      printf 'Re-add it with:\n  claude mcp add --transport stdio --scope user keyhop -- %q serve\n' "$bin_dir/keyhop" >&2
      return 1
    fi
  fi

  case ":$PATH:" in
    *":$bin_dir:"*) ;;
    *) printf '\nAdd %s to your PATH to run keyhop from a terminal.\n' "$bin_dir" ;;
  esac

  local data_dir="${KEYHOP_HOME:-${XDG_CONFIG_HOME:-$HOME/.config}/keyhop}"
  # Under curl | bash, stdin is the pipe. Bun can't watch /dev/tty itself
  # (kqueue: EINVAL), so hand setup the real terminal device behind stdout.
  local tty_dev=''
  if [[ -t 0 ]]; then
    tty_dev=/dev/stdin
  elif [[ -t 1 ]]; then
    tty_dev="$(tty <&1 2>/dev/null)" || tty_dev=''
  fi
  if [[ "$run_setup" == true && ! -f "$data_dir/vault.enc" && "$tty_dev" == /dev/* && "$tty_dev" != /dev/tty ]]; then
    step 'Setup'
    "$bin_dir/keyhop" setup <"$tty_dev" || info 'Setup did not finish; rerun it any time with: keyhop setup'
  else
    printf '\nkeyhop installed. Next: keyhop setup (first time) or keyhop doctor\n'
  fi
}

main "$@"
