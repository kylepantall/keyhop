# Changelog

## 0.5.0

- Faster syncs: whole 1Password vaults fetch only items that are new or changed since the last sync (by item version). The cache is kept inside the encrypted vault. `keyhop sync --full` refetches everything.
- ⚠️ With whole vaults linked, sync asks for Touch ID / Windows Hello before talking to 1Password (to read the cache), still once per sync.

## 0.4.0

- Windows now installs from GitHub Releases: a compiled `keyhop.exe` and a C# `keyhop-hello.exe` for Windows Hello and the access dialog. Antivirus flagged the old `.cmd` launcher and PowerShell helpers; no PowerShell runs after install. `keyhop update` downloads and verifies the release itself.
- Security: keyhop never loads `bunfig.toml` or `.env` from the folder it is started in (macOS launcher starts in its own folder; Windows exe built without autoload). keyhop's own runtime can't be allowed for secrets, and `BUN_*` names are reserved.
- Upgrading from 0.3.x on Windows re-points the Claude Code registration from `keyhop.cmd` to `keyhop.exe`.

## 0.3.2

- Fix (Windows): creating the vault failed with `Cannot convert … to type "Windows.Storage.Streams.IBuffer"`. The buffer conversions are now tested on Windows CI.

## 0.3.1

- Fix (Windows): creating the vault failed with `Cannot find an overload for "ToArray"`.
- Setup offers to replace a Windows Hello key left by a setup that didn't finish.

## 0.3.0

- Access requests: when Claude runs a program a secret isn't allowed for, keyhop asks you (Deny / Allow once / Always allow), confirmed with Touch ID / Windows Hello. Off with `"askForAccess": false`.
- Windows: system programs (PowerShell, cmd, taskkill) run by full path, so a copy planted in the working folder is never used.

## 0.2.2

- `keyhop sync` and setup show a spinner with each step and a progress bar per 1Password vault.

## 0.2.1

- Fix: whole-vault sync failed with `"-" isn't an item`; items are now fetched one by one (six at a time).
- `keyhop update` and `doctor` check main's latest commit, so a cached `package.json` can't hide a release.

## 0.2.0

- Sync whole 1Password vaults: every item becomes `ITEM_FIELD` secrets, and new items arrive on each sync. `keyhop setup` offers it first.
- Fix: the installer's setup wizard crashed under `curl | bash` (`EINVAL … kqueue`).

## 0.1.0

- First release: Touch ID / Windows Hello vault, 1Password, Bitwarden, LastPass, pass and Keychain sync, ordered `sync.d` scripts, setup wizard, doctor and update commands.
