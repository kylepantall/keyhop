import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { appRoot } from './paths.ts';
import { runProcess } from './process.ts';
import type { AuthAction, Authenticator, KeyFile } from './types.ts';

export class AuthCancelledError extends Error {}

/** Exit code both helpers use when the user cancels or fails the prompt. */
const CANCELLED = 2;
/** Windows helper: a Hello key already exists and --replace was not given. */
const KEY_EXISTS = 3;

export const macHelperPath = join(appRoot, 'native', 'build', 'keyhop-auth');
export const windowsHelperPath = join(appRoot, 'native', 'windows', 'keyhop-auth.ps1');

export function isSupportedPlatform(): boolean {
  return process.platform === 'darwin' || process.platform === 'win32';
}

async function runHelper(args: string[], input: object): Promise<string> {
  const [command, prefix] =
    process.platform === 'darwin'
      ? [macHelperPath, []]
      : [
          'powershell.exe',
          ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', windowsHelperPath],
        ];
  if (process.platform === 'darwin' && !existsSync(macHelperPath))
    throw new Error('Touch ID helper is not built. Rerun the installer, or run: bun run build:helper');
  const result = await runProcess(command, [...prefix, ...args], {
    input: JSON.stringify(input),
    timeoutMs: 120_000,
  });
  if (result.code === CANCELLED) throw new AuthCancelledError('Authentication was cancelled.');
  if (result.code === KEY_EXISTS)
    throw new Error('A keyhop Windows Hello key already exists. To replace it (any old vault becomes unreadable), run: keyhop setup --reset');
  if (result.code !== 0 || result.timedOut)
    throw new Error(`Biometric helper failed: ${result.stderr.trim() || `exit ${result.code}`}`);
  return result.stdout.trim();
}

export function platformAuthenticator(): Authenticator {
  if (!isSupportedPlatform())
    throw new Error('keyhop needs Touch ID (macOS) or Windows Hello (Windows).');
  return {
    async create({ biometryOnly, replace }) {
      const flags = [...(biometryOnly ? ['--biometry-only'] : []), ...(replace ? ['--replace'] : [])];
      const out = await runHelper(['create', ...flags], {});
      const created = JSON.parse(out) as { peer: string; seKey?: string };
      return { peer: created.peer, seKey: created.seKey, biometryOnly };
    },
    async derive(key: KeyFile, action: AuthAction) {
      if (key.platform !== process.platform)
        throw new Error(`This vault was created on ${key.platform}; it cannot be unlocked here.`);
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
