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

On Windows this installs the latest [release](https://github.com/kylepantall/keyhop/releases): `keyhop.exe` plus `keyhop-hello.exe` (the Windows Hello helper), checked against the release's `SHA256SUMS`. No PowerShell runs after install. You can also download `keyhop-windows-x64.zip` yourself, unzip it, and run `keyhop.exe setup`.

On a first install the installer starts `keyhop setup`, which:

1. creates the vault (one Touch ID / Hello prompt)
2. finds the password tools you already have and lets you pick items from them
3. asks which commands each secret may be given to
4. runs the first sync and registers keyhop with Claude Code

| Option | macOS / Linux | Windows |
|---|---|---|
| Register with Claude Code, no prompt | `bash -s -- --claude` | `-Claude` |
| Skip the setup wizard | `--no-setup` | `-NoSetup` |
| Install a branch, tag or version | `bash -s -- v0.2.0` | `-Version 0.4.0` (releases only) |

## Commands

| Command | Does |
|---|---|
| `keyhop setup` | Guided setup; rerun it to link more secrets |
| `keyhop sync` | Pull everything from linked tools and `sync.d` scripts |
| `keyhop list` | Names, sources and allowed commands (never values) |
| `keyhop add NAME REF [--allow gh,npm]` | Link one secret |
| `keyhop allow NAME gh` / `deny NAME gh` | Change which commands get a secret (prompts) |
| `keyhop remove NAME` | Unlink and delete a secret |
| `keyhop client add NAME --runtime P --entry P --root DIR [--prefix X_]` | Pin a suite client (dialog + Touch ID) |
| `keyhop client list [--json]` / `client remove NAME` | Show or unpin suite clients |
| `keyhop client get` / `client put` | For suite clients: JSON on stdin, JSON on stdout |
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

### Whole 1Password vaults

`keyhop setup` → 1Password → **Whole vaults** syncs every item in the vaults you pick, and new items arrive on the next `keyhop sync`.

| | |
|---|---|
| Names | `ITEM_FIELD`, e.g. `STRIPE_SECRET_KEY`; clashes get `_2`, `_3` |
| Fields | hidden fields (passwords, API keys) by default, or every field with a value; never one-time codes |
| Linked by name | a secret you linked one by one keeps its name and wins over a vault field |
| Access rules | bound to the field's 1Password id, so renaming an item renames the secret, which starts with no allowed commands |
| Config | `onePassword.vaults` in `config.json`: `[{ "id": "…", "fields": "concealed" }]` |
| Later syncs | only new or changed items are fetched (by 1Password's item version); deleted items drop out. The cache lives inside the encrypted vault. `keyhop sync --full` refetches everything |

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
| `list_secrets` | Names, sources, allowed programs and how each may receive the secret |
| `run_with_secrets` | Exit code + redacted stdout/stderr |
| `sync_secrets` | Steps run and counts |
| `lock_vault` | Forgets the key until the next prompt |

### Four ways to hand a program a secret

| Way | Claude asks with | What the program sees |
|---|---|---|
| env | `secrets: ["NAME"]` | An environment variable |
| stdin | `stdin: "NAME"` | The value on standard input, then end of input (`gh secret set`, `wrangler secret put`, `docker login --password-stdin`) |
| file | `{{file:NAME}}` in any argument, e.g. `ANTHROPIC_KEY=@{{file:ANTHROPIC_KEY}}` | A path that reads as the value, **once**. macOS: an inherited pipe (`/dev/fd/3`) no other process can open. Windows: an owner-only named pipe served only to that program. Never written to disk. |
| arg | `{{arg:NAME}}` | The value itself in the argument. ⚠️ Shows in the process list while it runs. |

Each program is allowed per way: `keyhop allow NAME gh` means env only, and `keyhop allow NAME infisical --as file` adds the file way. A program trusted with an environment variable might still upload a file it's handed (`gh gist create`, `curl -d @file`), so the ways are granted separately. The access dialog can grant env, stdin and file. `arg` can only be granted in your terminal.

### When a secret isn't allowed

If Claude runs a program a secret isn't allowed for, keyhop asks you directly in a dialog showing the secrets, the real program path, its arguments and the folder:

| Button | Then |
|---|---|
| Deny | Refused. No request can ask again for 30 s, doubling with each deny (up to 15 min) until you approve one |
| Allow once | Touch ID / Hello, then this run only; nothing saved |
| Always allow | Touch ID / Hello, then saved like `keyhop allow` (any arguments, this exact file) |

Shells and interpreters are still refused without asking, and only one request can be open at a time. Line breaks and invisible or right-to-left characters in the path, folder or arguments are shown as `\u{…}`, and a program outside system and package-manager folders gets a ⚠️ warning. Turn the dialog off with `"askForAccess": false` in `config.json`.

## Suite clients

Apps in the hop suite (vpnhop, hopsql) keep their own secrets in keyhop. Each is pinned once by its installer with `keyhop client add`, then spawns `keyhop client get|put` as a direct child.

| | |
|---|---|
| Pinned | Runtime real path + SHA-256, entry real path (inside the root), root tree hash: SHA-256 over sorted `relpath NUL sha256 NUL`, `node_modules` included. No symlinks; no world-writable root |
| Verified per call, before any prompt | Parent's executable (`lsof`), argv exactly `<runtime> <entry> …` (kernel argv, no flags first), no `NODE_*`/`BUN_*` variables except `NODE_ENV`, `NODE_NO_WARNINGS`, `NODE_DISABLE_COLORS`, no `DYLD_*`/`LD_*`, readable environment, working folder inside the root (client launchers `cd` there), tree unchanged. Bun runtimes: no `bunfig.toml` in home |
| Own names | Names starting with the prefix (`VPNHOP_`): read after Touch ID, written after Touch ID |
| Other names | Dialog with the client, names and purpose, then Touch ID. "Always allow" is saved per client and bound to the secret's source |
| Sync | Entries written by clients (source `client:NAME`) survive `keyhop sync` |
| Exit codes | 0 ok · 1 error · 2 `cancelled` · 3 not a verified client · 4 `denied` · 5 unknown names |

Updating a client changes its tree hash, so its installer reruns `keyhop client add`, which asks again.

## How it keeps values from Claude

| Guard | Detail |
|---|---|
| Hardware-bound key | macOS: a Secure Enclave key, used only after Touch ID. Windows: a Windows Hello key signs a challenge. Copying the files to another machine gets nothing. |
| Encrypted vault | AES-256-GCM. The access rules live inside it, so editing a config file can't widen them. |
| Per-secret allowlist | A secret is only injected into executables you allowed, ahead of time or in the access dialog (which always needs a fresh Touch ID / Hello). Each is pinned by real path and SHA-256, so a swapped binary or symlink is refused (re-allow after upgrading a tool). Shells and interpreters (`bash`, `node`, `python3.12`, `env`…) are refused. |
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
| A process running as you can read a running program's environment | On macOS, `ps eww` (so Claude's own shell) can see an env secret while the program runs. Prefer stdin or file for long-running programs |
| Programs in folders you can write to | A file swapped between keyhop's hash check and launch runs with the secret. Be wary of allowing programs Claude could have written |
| The install folder is yours to write | A process running as you could patch keyhop itself, then wait for your next unlock |
| Suite client checks run when keyhop starts | A process running as you could edit a client's files, start it, and restore them before it calls keyhop; or start keyhop and then `exec` the real client. The Touch ID prompt is the last guard: don't approve one you didn't expect |

## Develop

```bash
bun install && bun run build:helper && bun test && bun run typecheck
```

`build:helper` uses `swiftc` on macOS and the .NET SDK on Windows. `scripts/build-windows.ps1` builds the Windows release zip. To release, bump `package.json`, then push a `vX.Y.Z` tag; `.github/workflows/release.yml` builds and publishes it.

End-to-end runs without Touch ID: `NODE_ENV=test KEYHOP_TEST_AUTH=1 KEYHOP_HOME=<temp dir>` swaps in a test authenticator and auto-answers dialogs with `KEYHOP_TEST_DIALOG` (`once`, `always`, `deny`). It works only in a git checkout (installs have no `.git`), refuses the default data folder, and only opens vaults it created, so it can't unlock a real one.

Data lives in `~/.config/keyhop` (macOS) or `%APPDATA%\keyhop`; override with `KEYHOP_HOME`. MIT licensed.
