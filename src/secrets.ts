import { assertName, loadConfig } from './config.ts';
import { assertAllowable, pinExecutable, resolveExecutable } from './policy.ts';
import type { VaultStore } from './store.ts';
import { collectSecrets, planSteps } from './sync.ts';
import type { AllowedExecutable, Progress, SyncResult, VaultData } from './types.ts';

export function syncedSecrets(vault: VaultData): Record<string, string> {
  return Object.fromEntries(Object.entries(vault.secrets).map(([name, entry]) => [name, entry.value]));
}

/**
 * Runs every sync step, then replaces the vault's secrets with the result.
 * Access rules survive a name disappearing, but are cleared when a name comes
 * back from a different origin (another ref, or an edited script).
 */
export async function syncVault(store: VaultStore, onProgress?: Progress): Promise<SyncResult> {
  const config = await loadConfig(store.paths);
  const timeoutMs = Math.min(Math.max(Number(config.stepTimeoutSeconds) || 120, 1), 3600) * 1000;
  const collected = await collectSecrets(await planSteps(config, store.paths.syncDir, timeoutMs, onProgress), onProgress);
  const now = new Date().toISOString();
  onProgress?.(`Saving ${Object.keys(collected.values).length} secret(s) to the vault`);
  return store.update('unlock', (vault) => {
    const removed = Object.keys(vault.secrets).filter((name) => !collected.values[name]);
    const rulesCleared: string[] = [];
    for (const [name, { origin }] of Object.entries(collected.values)) {
      const policy = vault.policy[name];
      if (policy?.allow.length && policy.boundTo !== origin) {
        vault.policy[name] = { allow: [] };
        rulesCleared.push(name);
      }
    }
    vault.secrets = Object.fromEntries(
      Object.entries(collected.values).map(([name, { value, source, origin }]) => {
        const previous = vault.secrets[name];
        const unchanged = previous?.value === value && previous.origin === origin;
        return [name, { value, source, origin, updatedAt: unchanged ? previous.updatedAt : now }];
      })
    );
    vault.syncedAt = now;
    return { steps: collected.steps, total: Object.keys(vault.secrets).length, removed, rulesCleared };
  });
}

/** Resolves command names to absolute paths, refusing shells and interpreters. */
export function resolveAllowed(commands: string[]): string[] {
  return commands.map((command) => {
    const path = resolveExecutable(command);
    assertAllowable(path);
    return path;
  });
}

export interface AllowChange {
  /** Absolute paths to pin and allow, or entries already pinned (when the user approved that exact file). */
  add?: (string | AllowedExecutable)[];
  /** Paths (as allowed, or their real paths) to take away. */
  remove?: string[];
  /** Origin to bind the rules to when the secret is not synced yet (its ref). */
  bindTo?: string;
  /** Delete the secret and its rules. */
  drop?: boolean;
}

/** Adds or removes executables a secret may be injected into. Always prompts. */
export async function changeAllowed(
  store: VaultStore,
  changes: Record<string, AllowChange>
): Promise<Record<string, string[]>> {
  const pinned = new Map<string, AllowedExecutable>();
  for (const [name, change] of Object.entries(changes)) {
    assertName(name);
    for (const entry of change.add ?? []) {
      if (typeof entry !== 'string') pinned.set(entry.path, entry);
      else if (!pinned.has(entry)) pinned.set(entry, await pinExecutable(entry));
    }
  }
  return store.update('change', (vault) => {
    const result: Record<string, string[]> = {};
    for (const [name, change] of Object.entries(changes)) {
      if (change.drop) {
        delete vault.policy[name];
        delete vault.secrets[name];
        continue;
      }
      const origin = change.bindTo ?? vault.secrets[name]?.origin;
      if (change.add?.length && !origin)
        throw new Error(`${name} has not been synced yet. Link it with keyhop add, or run keyhop sync first.`);
      const current = vault.policy[name];
      // Rules granted for another origin don't carry over.
      const kept = current && current.boundTo === origin ? current.allow : [];
      const removing = new Set(change.remove ?? []);
      const adding = (change.add ?? []).map((entry) => pinned.get(typeof entry === 'string' ? entry : entry.path)!);
      const allow = kept.filter(
        (e) => !removing.has(e.path) && !removing.has(e.realPath) && !adding.some((a) => a.path === e.path)
      );
      allow.push(...adding);
      allow.sort((a, b) => a.path.localeCompare(b.path));
      vault.policy[name] = { allow, boundTo: origin };
      result[name] = allow.map((e) => e.path);
    }
    return result;
  });
}

export interface SecretSummary {
  name: string;
  source: string;
  updatedAt: string;
  allowedCommands: string[];
  description?: string;
}

/** Everything about the secrets except their values. */
export async function summarize(store: VaultStore): Promise<{ syncedAt: string | null; secrets: SecretSummary[] }> {
  const [vault, config] = await Promise.all([store.read(), loadConfig(store.paths)]);
  return {
    syncedAt: vault.syncedAt,
    secrets: Object.entries(vault.secrets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([name, entry]) => {
        const policy = vault.policy[name];
        return {
          name,
          source: entry.source,
          updatedAt: entry.updatedAt,
          allowedCommands: policy?.boundTo === entry.origin ? policy.allow.map((e) => e.path) : [],
          description: config.secrets?.[name]?.description,
        };
      }),
  };
}
