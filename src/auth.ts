import { randomBytes } from 'node:crypto';
import { constants, existsSync } from 'node:fs';
import { mkdir, open, stat } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { appRoot } from './paths.ts';
import { runProcess } from './process.ts';
import { testAuthenticator, testSeamEnabled } from './testauth.ts';
import type { AuthAction, Authenticator, KeyFile } from './types.ts';

export class AuthCancelledError extends Error {}
/** Windows: a keyhop Hello key already exists (one Hello key per Windows account). */
export class KeyExistsError extends Error {}

/** Exit code both helpers use when the user cancels or fails the prompt. */
const CANCELLED = 2;
/** Windows helper: a Hello key already exists and --replace was not given. */
const KEY_EXISTS = 3;

export const macHelperPath = join(appRoot, 'native', 'build', 'keyhop-auth');
/** Built by CI into the release (and by `bun run build:helper` in a checkout). */
export const windowsHelperPath = join(appRoot, 'native', 'build', 'keyhop-hello.exe');

export function supportsBiometricAuth(): boolean {
  return process.platform === 'darwin' || process.platform === 'win32';
}

/** A portable auto-auth key is a private file, so other accounts must not be able to replace it. */
export async function prepareKeyDirectory(file: string): Promise<void> {
  const dir = dirname(file);
  await mkdir(dir, { recursive: true, mode: 0o700 });
  await checkKeyDirectory(dir);
}

async function checkKeyDirectory(dir: string): Promise<void> {
  if (process.platform === 'win32') return; // DPAPI protects the key under the Windows account.
  const info = await stat(dir);
  if (info.uid !== process.getuid?.() || (info.mode & 0o022) !== 0)
    throw new Error(`Auto auth requires the vault directory to be owned by your account and writable only by you: ${dir}`);
}

/** Check the same file descriptor used for reading, with symlinks disallowed on POSIX. */
export async function readKeyFile(file: string): Promise<KeyFile> {
  const flags = process.platform === 'win32' ? constants.O_RDONLY :
    constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK;
  const handle = await open(file, flags);
  try {
    const info = await handle.stat();
    if (!info.isFile() || info.size > 16 * 1024) throw new Error('Invalid vault key file.');
    let key: KeyFile;
    try {
      key = JSON.parse(await handle.readFile('utf8')) as KeyFile;
    } catch {
      throw new Error('The vault key file is not valid JSON.');
    }
    if (!key || key.version !== 1 || typeof key.platform !== 'string' || typeof key.peer !== 'string' || typeof key.salt !== 'string' ||
        (key.auth !== undefined && key.auth !== 'auto'))
      throw new Error('The vault key file has an unknown format.');
    if (key.auth === 'auto' && process.platform !== 'win32') {
      if (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0)
        throw new Error(`Auto auth requires an owner-only vault key file. Check ownership and run chmod 600 on ${file}.`);
      await checkKeyDirectory(dirname(file));
    }
    return key;
  } finally {
    await handle.close();
  }
}

function requireBiometricPlatform(): void {
  if (!supportsBiometricAuth())
    throw new Error('Biometric unlock requires macOS or Windows. Create an automatic vault with keyhop setup --auto-auth.');
}

async function runHelper(args: string[], input: object): Promise<string> {
  const command = process.platform === 'darwin' ? macHelperPath : windowsHelperPath;
  if (!existsSync(command))
    throw new Error('The native helper is missing. Rerun the installer, or in a checkout run: bun run build:helper');
  const result = await runProcess(command, args, {
    input: JSON.stringify(input),
    timeoutMs: 120_000,
  });
  if (result.code === CANCELLED) throw new AuthCancelledError('Authentication was cancelled.');
  if (result.code === KEY_EXISTS)
    throw new KeyExistsError('A keyhop Windows Hello key already exists. To replace it (any old vault becomes unreadable), run: keyhop setup --reset');
  if (result.code !== 0 || result.timedOut)
    throw new Error(`Native helper failed: ${result.stderr.trim() || `exit ${result.code}`}`);
  return result.stdout.trim();
}

export function platformAuthenticator(): Authenticator {
  // Auto-auth vaults always use the real automatic backend. The test backend only opens its own throwaway vaults.
  const test = testSeamEnabled() ? testAuthenticator() : undefined;
  return {
    async create({ autoAuth, biometryOnly, replace }) {
      if (autoAuth) {
        const secret = randomBytes(32);
        try {
          const peer = process.platform === 'win32'
            ? await runHelper(['protect-auto-key'], { peer: secret.toString('base64') })
            : secret.toString('base64');
          return { auth: 'auto', peer };
        } finally {
          secret.fill(0);
        }
      }
      if (test) return test.create({ biometryOnly, replace });
      requireBiometricPlatform();
      const flags = [...(biometryOnly ? ['--biometry-only'] : []), ...(replace ? ['--replace'] : [])];
      const out = await runHelper(['create', ...flags], {});
      const created = JSON.parse(out) as { peer: string; seKey?: string };
      return { peer: created.peer, seKey: created.seKey, biometryOnly };
    },
    async derive(key: KeyFile, action: AuthAction) {
      if (key.auth !== 'auto' && test) return test.derive(key, action);
      if (key.platform !== process.platform)
        throw new Error(`This vault was created on ${key.platform}; it cannot be unlocked here.`);
      if (key.auth === 'auto') {
        const encoded = process.platform === 'win32'
          ? await runHelper(['unprotect-auto-key'], { peer: key.peer })
          : key.peer;
        const secret = Buffer.from(encoded, 'base64');
        if (secret.length !== 32 || secret.toString('base64') !== encoded)
          throw new Error('Invalid automatic vault key.');
        return secret;
      }
      requireBiometricPlatform();
      const out = await runHelper(['derive', action], {
        peer: key.peer,
        seKey: key.seKey,
        biometryOnly: key.biometryOnly ?? false,
      });
      const secret = Buffer.from(out, 'base64');
      if (secret.length < 32) throw new Error('Biometric helper returned a short secret.');
      return secret;
    },
  };
}
