# Changelog

## 0.4.0

- Windows: keyhop is now two compiled programs, `keyhop.exe` (built with `bun build --compile`) and `keyhop-hello.exe` (C#: Windows Hello signing and the access dialog), so nothing runs PowerShell with `-ExecutionPolicy Bypass` or a `.cmd` launcher any more. Antivirus (Bitdefender) quarantined those as malware-like.
- Windows: CI builds both programs for each version tag and publishes them on a GitHub Release with `SHA256SUMS`. The installer and `keyhop update` download a release and check every file before installing it. The installer removes the old `keyhop.cmd`, source copy and private Bun, and re-registers keyhop with Claude Code if the registration pointed at `keyhop.cmd`.
- Windows installer: `-Version v0.4.0` replaces `-Ref`.

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
