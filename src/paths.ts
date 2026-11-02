import { randomBytes } from 'node:crypto';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of this checkout or install (holds src/, native/). */
export const appRoot = fileURLToPath(new URL('..', import.meta.url));

export const REPO = process.env.KEYHOP_REPO ?? 'kylepantall/keyhop';

export function dataDir(): string {
  if (process.env.KEYHOP_HOME) return process.env.KEYHOP_HOME;
  if (process.platform === 'win32')
    return join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'keyhop');
  return join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'keyhop');
}

export interface Paths {
  dir: string;
  config: string;
  key: string;
  vault: string;
  syncDir: string;
}

export function paths(dir = dataDir()): Paths {
  return {
    dir,
    config: join(dir, 'config.json'),
    key: join(dir, 'key.json'),
    vault: join(dir, 'vault.enc'),
    syncDir: join(dir, 'sync.d'),
  };
}

/** Writes owner-only, via a temp file and rename so readers never see a partial file. */
export async function writePrivate(file: string, contents: string): Promise<void> {
  await mkdir(dirname(file), { recursive: true, mode: 0o700 });
  const temp = `${file}.${randomBytes(8).toString('hex')}.tmp`;
  await writeFile(temp, contents, { mode: 0o600 });
  await rename(temp, file);
}
