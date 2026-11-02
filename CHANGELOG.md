# Changelog

## 0.2.1

- Fix: whole-vault sync failed with `"-" isn't an item`; items are now fetched one by one (six at a time).
- `keyhop update` and `doctor` check main's latest commit, so a cached `package.json` can't hide a release.

## 0.2.0

- Sync whole 1Password vaults: every item becomes `ITEM_FIELD` secrets, and new items arrive on each sync. `keyhop setup` offers it first.
- Fix: the installer's setup wizard crashed under `curl | bash` (`EINVAL … kqueue`).

## 0.1.0

- First release: Touch ID / Windows Hello vault, 1Password, Bitwarden, LastPass, pass and Keychain sync, ordered `sync.d` scripts, setup wizard, doctor and update commands.
