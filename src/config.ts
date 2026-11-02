import { readFile } from 'node:fs/promises';
import { writePrivate, type Paths } from './paths.ts';
import type { Config } from './types.ts';

/** Secret names double as environment variable names. */
export const NAME_PATTERN = /^[A-Z_][A-Z0-9_]*$/;

/** Variables that change how programs load or where they look, so never secret names. */
const RESERVED = /^(PATH|PATHEXT|HOME|USER|USERNAME|SHELL|TMPDIR|TEMP|TMP|PWD|COMSPEC|SYSTEMROOT|WINDIR|APPDATA|LOCALAPPDATA|USERPROFILE|NODE_OPTIONS|BUN_OPTIONS|KEYHOP_.*|DYLD_.*|LD_.*)$/;

export function assertName(name: string): void {
  if (!NAME_PATTERN.test(name))
    throw new Error(`Invalid secret name "${name}": use A-Z, 0-9 and _, like GITHUB_TOKEN.`);
  if (RESERVED.test(name)) throw new Error(`"${name}" is a reserved environment variable name.`);
}

export async function loadConfig(p: Paths): Promise<Config> {
  let text: string;
  try {
    text = await readFile(p.config, 'utf8');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return {};
    throw error;
  }
  try {
    return JSON.parse(text) as Config;
  } catch {
    throw new Error(`${p.config} is not valid JSON.`);
  }
}

export async function saveConfig(p: Paths, config: Config): Promise<void> {
  await writePrivate(p.config, JSON.stringify(config, null, 2) + '\n');
}

/** How long the MCP server keeps the vault unlocked: 1–60 minutes, default 15. */
export function unlockMs(config: Config): number {
  const minutes = Number(config.unlockMinutes);
  return (Number.isFinite(minutes) ? Math.min(Math.max(minutes, 1), 60) : 15) * 60_000;
}
