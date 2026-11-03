/**
 * Whole-vault 1Password sync: every item in a linked vault becomes secrets
 * named ITEM_FIELD, so new items in 1Password arrive on the next sync without
 * linking them one by one. Talks to the `op` CLI, so its desktop-app unlock applies.
 */

import { assertName } from './config.ts';
import { locate, PROVIDERS } from './providers.ts';
import { runProcess } from './process.ts';
import type { Config, OnePasswordVault, OnePasswordVaultCache, OpField, OpItem, Progress, SyncCacheState } from './types.ts';

export type { OpField, OpItem };

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

/** Fields that become secrets under this vault's field setting. */
function keptFields(item: OpItem, fields: OnePasswordVault['fields']): OpField[] {
  return (item.fields ?? []).filter(
    (field) => field.value && !SKIPPED_TYPES.has(field.type ?? '') && (fields === 'all' || field.type === 'CONCEALED')
  );
}

/** `op item list` stamp that changes on every edit; empty when op gives none (always refetch). */
function versionStamp(listed: { version?: number | string; updated_at?: string }): string {
  return listed.version === undefined && !listed.updated_at ? '' : `${listed.version ?? ''}@${listed.updated_at ?? ''}`;
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
    for (const field of keptFields(item, fields)) {
      const base = toSecretName(item.title, fieldLabel(field));
      let name = base;
      for (let n = 2; taken.has(name); n++) name = `${base}_${n}`;
      try {
        assertName(name);
      } catch {
        continue;
      }
      taken.add(name);
      out[name] = { value: field.value!, origin: fieldOrigin(vaultId, item, field) };
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

function bar(done: number, total: number, width = 20): string {
  const filled = Math.round((done / total) * width);
  return `${'█'.repeat(filled)}${'░'.repeat(width - filled)}`;
}

/**
 * Reads every item (with values) from each linked vault. With `cache`, items
 * whose version stamp matches the last sync come from it, and only new or
 * changed items are fetched; the fetched result is written to `cache.next`.
 */
export async function readVaults(
  config: Config,
  timeoutMs: number,
  taken: Set<string>,
  onProgress?: Progress,
  cache?: SyncCacheState
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
      onProgress?.(`1Password ${label}: listing items`);
      const list = JSON.parse(await opJson(op, ['item', 'list', '--vault', vault.id], config, timeoutMs)) as {
        id: string;
        version?: number | string;
        updated_at?: string;
      }[];
      const fields = vault.fields ?? 'concealed';
      const previous = cache?.previous.onePassword?.[vault.id];
      const known = previous?.fields === fields ? previous.items : {};
      const kept: OnePasswordVaultCache['items'] = {};
      const stale = list.filter((listed) => {
        const version = versionStamp(listed);
        const hit = known[listed.id];
        if (version && hit?.version === version) kept[listed.id] = hit;
        return !kept[listed.id];
      });
      let done = 0;
      const get = async (listed: (typeof list)[number]) => {
        const [item] = parseJsonObjects(
          await opJson(op, ['item', 'get', listed.id, '--vault', vault.id, '--reveal'], config, timeoutMs)
        ) as OpItem[];
        // Keep only what becomes a secret, so the cache holds no more than the vault already does.
        if (item) kept[listed.id] = { version: versionStamp(listed), item: { ...item, fields: keptFields(item, fields) } };
        done++;
        onProgress?.(`1Password ${label}: ${bar(done, stale.length)} ${done}/${stale.length} changed items`);
      };
      if (!stale.length) onProgress?.(`1Password ${label}: no changes in ${list.length} items`);
      // op won't read item ids from a Bun stdin pipe, so fetch each item. The
      // first call alone, so 1Password shows one approval; then a few at a time.
      if (stale.length) await get(stale[0]!);
      for (let i = 1; i < stale.length; i += GET_CONCURRENCY)
        await Promise.all(stale.slice(i, i + GET_CONCURRENCY).map(get));
      if (cache) (cache.next.onePassword ??= {})[vault.id] = { fields, items: kept };
      // Deleted items are simply absent from `list`, so they drop out here.
      const items = list.map((listed) => kept[listed.id]?.item).filter((item): item is OpItem => !!item);
      Object.assign(out, itemsToSecrets(items, vault.id, vault.fields, taken));
    } catch (error) {
      throw new Error(`1Password vault ${label}: ${(error as Error).message} ${provider.signInHint}`);
    }
  }
  return out;
}
