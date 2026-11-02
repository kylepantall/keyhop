# keyhop

[![CI](https://github.com/kylepantall/keyhop/actions/workflows/ci.yml/badge.svg)](https://github.com/kylepantall/keyhop/actions/workflows/ci.yml) [![MIT license](https://img.shields.io/badge/license-MIT-716e65)](LICENSE)

Let Claude **use** your API keys without **seeing** them. keyhop syncs secrets from 1Password (and other password tools, or your own scripts) into a local encrypted vault that unlocks with **Touch ID** or **Windows Hello**. Claude runs commands with those secrets as environment variables. It never gets their values back.

## Install

**macOS** (needs the Xcode command line tools: `xcode-select --install`)

```bash
curl -fsSL https://raw.githubusercontent.com/kylepantall/keyhop/main/scripts/install.sh | bash
```

**Windows (PowerShell)**

```powershell
& ([scriptblock]::Create((irm https://raw.githubusercontent.com/kylepantall/keyhop/main/scripts/install.ps1)))
```

On a first install the installer starts `keyhop setup`, which:

1. creates the vault (one Touch ID / Hello prompt)
2. finds the password tools you already have and lets you pick items from them
3. asks which commands each secret may be given to
4. runs the first sync and registers keyhop with Claude Code

| Option | macOS / Linux | Windows |
|---|---|---|
| Register with Claude Code, no prompt | `bash -s -- --claude` | `-Claude` |
| Skip the setup wizard | `--no-setup` | `-NoSetup` |
| Install a branch or tag | `bash -s -- v0.2.0` | `-Ref v0.2.0` |

## Commands

| Command | Does |
|---|---|
| `keyhop setup` | Guided setup; rerun it to link more secrets |
| `keyhop sync` | Pull everything from linked tools and `sync.d` scripts |
| `keyhop list` | Names, sources and allowed commands (never values) |
| `keyhop add NAME REF [--allow gh,npm]` | Link one secret |
| `keyhop allow NAME gh` / `deny NAME gh` | Change which commands get a secret (prompts) |
| `keyhop remove NAME` | Unlink and delete a secret |
| `keyhop doctor` | Check biometrics, vault, tools, scripts and Claude Code |
| `keyhop update [--check]` | Install the latest version from GitHub |

## Linked password tools

| Tool | Reference | Signed in when |
|---|---|---|
| 1Password | `op://Vault/Item/field` | desktop app CLI integration is on, or `op signin` |
| Bitwarden | `bw://Item name` | `BW_SESSION` is set (`bw unlock --raw`) |
| LastPass | `lastpass://Folder/Item` | `lpass login` |
| pass | `pass://path/to/entry` | gpg-agent can decrypt |
| macOS Keychain | `keychain://service` | login keychain unlocked |

## Your own sync scripts

Put scripts in the `sync.d` folder (`~/.config/keyhop/sync.d` or `%APPDATA%\keyhop\sync.d`). Each prints `NAME=value` lines or one JSON object.

- **Order:** steps run in number order: linked tools as `00-<tool>`, then `10-aws.sh`, `20-env.ps1`… A later step overrides a name set earlier.
- **Languages:** `.sh`, `.ps1`, `.mjs`/`.js`/`.ts` (keyhop's Bun), `.py`, `.cmd` (Windows), or any executable without an extension (macOS).
- **Disable** a script by starting its name with `_`.
- **Failure:** any failing step stops the sync, and the vault stays as it was.
- **Examples:** [`examples/sync.d`](examples/sync.d).

## MCP tools

| Tool | Returns |
|---|---|
| `list_secrets` | Names, sources, allowed command paths |
| `run_with_secrets` | Exit code + redacted stdout/stderr |
| `sync_secrets` | Steps run and counts |
| `lock_vault` | Forgets the key until the next prompt |

## How it keeps values from Claude

| Guard | Detail |
|---|---|
| Hardware-bound key | macOS: a Secure Enclave key, used only after Touch ID. Windows: a Windows Hello key signs a challenge. Copying the files to another machine gets nothing. |
| Encrypted vault | AES-256-GCM. The access rules live inside it, so editing a config file can't widen them. |
| Per-secret allowlist | A secret is only injected into executables you allowed. Each is pinned by real path and SHA-256, so a swapped binary or symlink is refused (re-allow after upgrading a tool). Shells and interpreters (`bash`, `node`, `python3.12`, `env`…) are refused. |
| Bound to its source | Rules are tied to the exact ref or script content that filled the name. Editing `config.json` or a `sync.d` script, or overriding the name from another step, clears them. |
| No shell | `run_with_secrets` runs the program directly, so `$TOKEN` in an argument is never expanded. |
| Redaction | Values, plus their base64, hex and URL-encoded forms, are scrubbed from output. |
| Unlock window | The MCP server keeps the key for `unlockMinutes` (default 15, in `config.json`). Rule changes always prompt again. |

⚠️ **Limits**

| Risk | Example |
|---|---|
| Allowed tools read config from the working directory | A planted `.npmrc` pointing `npm` at another registry sends it `NPM_TOKEN`; `.git/config` can run commands |
| Endpoint flags | `--registry`, `--hostname`, `--endpoint-url` can send a token elsewhere |
| Tools that run code | git hooks, `npm run`, `make`: only allow tools you'd trust with the key |
| Prompts can be triggered by any process running as you | Don't approve a Touch ID / Hello prompt you didn't expect. Windows Hello shows the same prompt for unlocks and rule changes |
| The install folder is yours to write | A process running as you could patch keyhop itself, then wait for your next unlock |

## Develop

```bash
bun install && bun run build:helper && bun test && bun run typecheck
```

Data lives in `~/.config/keyhop` (macOS) or `%APPDATA%\keyhop`; override with `KEYHOP_HOME`. MIT licensed.
