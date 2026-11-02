/**
 * Whole-vault 1Password sync: every item in a linked vault becomes secrets
 * named ITEM_FIELD, so new items in 1Password arrive on the next sync without
 * linking them one by one. Talks to the `op` CLI, so its desktop-app unlock applies.
 */

import { assertName } from './config.ts';
import { locate, PROVIDERS } from './providers.ts';
import { runProcess } from './process.ts';
import type { Config, OnePasswordVault } from './types.ts';

export interface OpField {
  id: string;
  type?: string;
  purpose?: string;
  label?: string;
  value?: string;
  section?: { id?: string };
}

export interface OpItem {
  id: string;
  title: string;
  vault?: { id: string };
  fields?: OpField[];
}

/** Values that aren't usable as a credential on their own. */
const SKIPPED_TYPES = new Set(['OTP']);
const MAX_OUTPUT = 64 * 1024 * 1024;
const GET_CONCURRENCY = 6;

export function toSecretName(...parts: string[]): string {
  return parts
    .join('_')
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/^(\d)/, '_$1');
}

/** `op item get -` prints one JSON object per item, back to back; also accepts an array. */
export function parseJsonObjects(text: string): unknown[] {
  const trimmed = text.trim();
  if (!trimmed) return [];
  try {
    if (trimmed.startsWith('[')) return JSON.parse(trimmed) as unknown[];
  } catch {
    throw new Error('1Password returned invalid JSON.');
  }
  const objects: unknown[] = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;
  for (let i = 0; i < trimmed.length; i++) {
    const c = trimmed[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === '\\') escaped = true;
      else if (c === '"') inString = false;
    } else if (c === '"') inString = true;
    else if (c === '{') {
      if (depth++ === 0) start = i;
    } else if (c === '}' && --depth === 0) {
      try {
        objects.push(JSON.parse(trimmed.slice(start, i + 1)));
      } catch {
        throw new Error('1Password returned invalid JSON.');
      }
    }
  }
  // Never echo the text: it holds secret values.
  if (depth !== 0 || inString) throw new Error('1Password returned incomplete JSON.');
  return objects;
}

/** Stable origin for a field: ids survive renames, so access rules stay bound. */
function fieldOrigin(vaultId: string, item: OpItem, field: OpField): string {
  return `op://${vaultId}/${item.id}/${field.section?.id ? `${field.section.id}/` : ''}${field.id}`;
}

function fieldLabel(field: OpField): string {
  if (field.purpose === 'NOTES') return 'notes';
  return field.label || field.purpose?.toLowerCase() || field.id;
}

/**
 * Turns items into secrets. Names that clash get _2, _3 … in a stable order;
 * fields whose name can't be an environment variable are skipped.
 */
export function itemsToSecrets(
  items: OpItem[],
  vaultId: string,
  fields: OnePasswordVault['fields'],
  taken: Set<string>
): Record<string, { value: string; origin: string }> {
  const out: Record<string, { value: string; origin: string }> = {};
  const sorted = [...items].sort((a, b) => a.title.localeCompare(b.title) || a.id.localeCompare(b.id));
  for (const item of sorted) {
    for (const field of item.fields ?? []) {
      if (!field.value || SKIPPED_TYPES.has(field.type ?? '')) continue;
      if (fields !== 'all' && field.type !== 'CONCEALED') continue;
      const base = toSecretName(item.title, fieldLabel(field));
      let name = base;
      for (let n = 2; taken.has(name); n++) name = `${base}_${n}`;
      try {
        assertName(name);
      } catch {
        continue;
      }
      taken.add(name);
      out[name] = { value: field.value, origin: fieldOrigin(vaultId, item, field) };
    }
  }
  return out;
}

function accountArgs(config: Config): string[] {
  return config.onePassword?.account ? ['--account', config.onePassword.account] : [];
}

/** Runs `op … --format json`; errors carry op's stderr, never stdout. */
export async function opJson(op: string, args: string[], config: Config, timeoutMs: number): Promise<string> {
  const result = await runProcess(op, [...args, ...accountArgs(config), '--format', 'json'], {
    timeoutMs,
    maxBytes: MAX_OUTPUT,
  });
  if (result.timedOut) throw new Error(`op ${args.slice(0, 2).join(' ')} timed out.`);
  if (result.code !== 0) throw new Error(result.stderr.trim() || `op ${args.slice(0, 2).join(' ')} exited ${result.code}`);
  if (result.truncated) throw new Error(`op ${args.slice(0, 2).join(' ')} printed more than 64 MB.`);
  return result.stdout;
}

/** Reads every item (with values) from each linked vault. */
export async function readVaults(
  config: Config,
  timeoutMs: number,
  taken: Set<string>
): Promise<Record<string, { value: string; origin: string }>> {
  const vaults = config.onePassword?.vaults ?? [];
  if (!vaults.length) return {};
  const provider = PROVIDERS.find((p) => p.id === '1password')!;
  const op = locate(provider);
  if (!op) throw new Error(`1Password CLI (op) not found. Install: ${provider.install}`);
  const out: Record<string, { value: string; origin: string }> = {};
  for (const vault of vaults) {
    const label = vault.name ?? vault.id;
    try {
      const list = JSON.parse(await opJson(op, ['item', 'list', '--vault', vault.id], config, timeoutMs)) as { id: string }[];
      const get = async (id: string) =>
        parseJsonObjects(await opJson(op, ['item', 'get', id, '--vault', vault.id, '--reveal'], config, timeoutMs)) as OpItem[];
      // op won't read item ids from a Bun stdin pipe, so fetch each item. The
      // first call alone, so 1Password shows one approval; then a few at a time.
      const items: OpItem[] = list.length ? await get(list[0]!.id) : [];
      for (let i = 1; i < list.length; i += GET_CONCURRENCY)
        items.push(...(await Promise.all(list.slice(i, i + GET_CONCURRENCY).map((item) => get(item.id)))).flat());
      Object.assign(out, itemsToSecrets(items, vault.id, vault.fields, taken));
    } catch (error) {
      throw new Error(`1Password vault ${label}: ${(error as Error).message} ${provider.signInHint}`);
    }
  }
  return out;
}
