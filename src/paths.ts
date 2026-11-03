import { randomBytes } from 'node:crypto';
import { mkdir, rename, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { dirname, join, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';

/** Replaced with `true` by `bun build --define` (scripts/build-windows.ps1); never set at runtime. */
declare const KEYHOP_COMPILED: boolean | undefined;

/**
 * True inside the compiled release executable (keyhop.exe), whose sources
 * live in Bun's virtual file system rather than on disk.
 */
export const compiled = typeof KEYHOP_COMPILED !== 'undefined' && KEYHOP_COMPILED === true;

/**
 * Root of this checkout or install (holds native/, examples/). For the
 * compiled release, the folder holding keyhop.exe.
 */
export const appRoot = compiled ? dirname(process.execPath) : fileURLToPath(new URL('..', import.meta.url));

export const REPO = process.env.KEYHOP_REPO ?? 'kylepantall/keyhop';

/**
 * Full paths to Windows system programs. Windows searches the working
 * directory before PATH, so a bare `powershell.exe` could run a planted copy.
 */
export function windowsSystem(program: 'powershell.exe' | 'cmd.exe' | 'taskkill.exe' | 'tar.exe'): string {
  const system32 = win32.join(process.env.SystemRoot ?? 'C:\\Windows', 'System32');
  return program === 'powershell.exe'
    ? win32.join(system32, 'WindowsPowerShell', 'v1.0', program)
    : win32.join(system32, program);
}

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
