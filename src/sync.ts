/**
 * Sync pipeline. Steps run in name order (numeric-aware, so 9-x before 10-y):
 * one built-in `00-<tool>` step per linked password tool, plus every script in
 * sync.d. A later step overrides a name an earlier one set.
 *
 * A script prints its secrets on stdout, either as a JSON object of strings or
 * as NAME=value lines (blank lines and # comments ignored, `export ` allowed).
 */

import { readdir } from 'node:fs/promises';
import { extname, join } from 'node:path';
import { assertName } from './config.ts';
import { readVaults } from './onepassword.ts';
import { readSecret, providerFor } from './providers.ts';
import { compiled, windowsSystem } from './paths.ts';
import { hashFile } from './policy.ts';
import { runProcess } from './process.ts';
import { redactor } from './redact.ts';
import type { Config, Progress, StepResult } from './types.ts';

export interface Produced {
  value: string;
  /** Tool ref, or script name + content hash; access rules are bound to it. */
  origin: string;
}

export interface SyncStep {
  name: string;
  kind: 'tool' | 'script';
  run(): Promise<Record<string, Produced>>;
}

export interface CollectedSecrets {
  values: Record<string, Produced & { source: string }>;
  steps: StepResult[];
}

const IGNORED = /^[._]|\.(md|txt|disabled)$/i;

export function compareSteps(a: string, b: string): number {
  return a.localeCompare(b, 'en', { numeric: true });
}

export async function listScripts(syncDir: string): Promise<string[]> {
  let entries;
  try {
    entries = await readdir(syncDir, { withFileTypes: true });
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw error;
  }
  return entries
    .filter((entry) => entry.isFile() && !IGNORED.test(entry.name))
    .map((entry) => entry.name)
    .sort(compareSteps);
}

/** How to run a sync script on this platform, or a reason it cannot run. */
export function interpreterFor(
  file: string,
  platform: NodeJS.Platform = process.platform
): { command: string; args: string[]; env?: Record<string, string> } | { error: string } {
  const windows = platform === 'win32';
  switch (extname(file).toLowerCase()) {
    case '.sh': {
      const bash = windows ? Bun.which('bash') : 'bash';
      return bash ? { command: bash, args: [file] } : { error: 'needs bash (Git for Windows)' };
    }
    case '.ps1':
      return windows
        ? { command: windowsSystem('powershell.exe'), args: ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', file] }
        : { command: 'pwsh', args: ['-NoProfile', '-NonInteractive', '-File', file] };
    case '.js':
    case '.mjs':
    case '.cjs':
    case '.ts':
      // The compiled keyhop.exe is Bun inside; BUN_BE_BUN makes it run the script, not keyhop.
      return { command: process.execPath, args: [file], ...(compiled ? { env: { BUN_BE_BUN: '1' } } : {}) };
    case '.py':
      return { command: windows ? 'python' : 'python3', args: [file] };
    case '.cmd':
    case '.bat':
      return windows ? { command: windowsSystem('cmd.exe'), args: ['/d', '/c', file] } : { error: 'Windows only' };
    case '':
      return windows ? { error: 'add an extension (.ps1, .cmd, .mjs …)' } : { command: file, args: [] };
    default:
      return { error: `unsupported extension ${extname(file)}` };
  }
}

export function parseStepOutput(stdout: string, step: string): Record<string, string> {
  const text = stdout.trim();
  const values: Record<string, string> = {};
  if (!text) return values;
  if (text.startsWith('{')) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      throw new Error(`${step}: output starts with { but is not valid JSON.`);
    }
    for (const [name, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (typeof value !== 'string') throw new Error(`${step}: value of ${name} is not a string.`);
      assertName(name);
      values[name] = value;
    }
    return values;
  }
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trim();
    if (!line || line.startsWith('#')) return;
    const match = /^(?:export\s+)?([^=\s]+)\s*=(.*)$/.exec(line);
    // Never echo the line: it may hold a secret.
    if (!match) throw new Error(`${step}: line ${index + 1} is not NAME=value.`);
    const name = match[1]!;
    assertName(name);
    let value = match[2]!.trim();
    if (value.length >= 2 && (value[0] === '"' || value[0] === "'") && value.at(-1) === value[0])
      value = value.slice(1, -1);
    values[name] = value;
  });
  return values;
}

export async function planSteps(
  config: Config,
  syncDir: string,
  stepTimeoutMs: number,
  onProgress?: Progress
): Promise<SyncStep[]> {
  const byTool = new Map<string, [string, string][]>();
  for (const [name, source] of Object.entries(config.secrets ?? {})) {
    assertName(name);
    const id = providerFor(source.ref).id;
    byTool.set(id, [...(byTool.get(id) ?? []), [name, source.ref]]);
  }
  if (config.onePassword?.vaults?.length && !byTool.has('1password')) byTool.set('1password', []);
  const steps: SyncStep[] = [...byTool].map(([id, entries]) => ({
    name: `00-${id}`,
    kind: 'tool',
    async run() {
      // Whole vaults first; a secret linked by name overrides the same name from a vault.
      const values: Record<string, Produced> =
        id === '1password'
          ? await readVaults(config, stepTimeoutMs, new Set(entries.map(([name]) => name)), onProgress)
          : {};
      // One at a time: tools such as op show a single unlock prompt this way.
      for (const [name, ref] of entries) {
        try {
          values[name] = { value: await readSecret(ref, config, stepTimeoutMs), origin: ref };
        } catch (error) {
          // collectSecrets redacts earlier steps; this step's own values are only known here.
          const own = Object.fromEntries(Object.entries(values).map(([k, v]) => [k, v.value]));
          throw new Error(redactor(own)((error as Error).message));
        }
      }
      return values;
    },
  }));
  for (const file of await listScripts(syncDir)) {
    const path = join(syncDir, file);
    steps.push({
      name: file,
      kind: 'script',
      async run() {
        const how = interpreterFor(path);
        if ('error' in how) throw new Error(`${file}: cannot run (${how.error}).`);
        // Editing the script changes its origin, which clears its secrets' access rules.
        const origin = `${file}#${await hashFile(path)}`;
        const result = await runProcess(how.command, how.args, {
          cwd: syncDir,
          env: { ...process.env, ...how.env, KEYHOP_STEP: file, KEYHOP_SYNC_DIR: syncDir },
          timeoutMs: stepTimeoutMs,
        });
        if (result.timedOut) throw new Error(`${file}: timed out after ${stepTimeoutMs / 1000}s.`);
        if (result.code !== 0) {
          const values = safeParse(result.stdout, file);
          const tail = redactor(values)(result.stderr.trim()).slice(-500);
          throw new Error(`${file}: exited ${result.code}${tail ? `: ${tail}` : ''}`);
        }
        const values = parseStepOutput(result.stdout, file);
        return Object.fromEntries(Object.entries(values).map(([name, value]) => [name, { value, origin }]));
      },
    });
  }
  return steps.sort((a, b) => compareSteps(a.name, b.name));
}

function safeParse(stdout: string, step: string): Record<string, string> {
  try {
    return parseStepOutput(stdout, step);
  } catch {
    return {};
  }
}

/** Runs every step; any failure aborts the whole sync so the vault stays as it was. */
export async function collectSecrets(steps: SyncStep[], onProgress?: Progress): Promise<CollectedSecrets> {
  const values: CollectedSecrets['values'] = {};
  const results: StepResult[] = [];
  for (const [index, step] of steps.entries()) {
    let produced: Record<string, Produced>;
    onProgress?.(`[${index + 1}/${steps.length}] ${step.name}`);
    try {
      produced = await step.run();
    } catch (error) {
      const message = redactor(Object.fromEntries(Object.entries(values).map(([k, v]) => [k, v.value])))(
        (error as Error).message
      );
      throw new Error(`Sync stopped at ${step.name}; the vault was not changed. ${message}`);
    }
    for (const [name, entry] of Object.entries(produced)) values[name] = { ...entry, source: step.name };
    results.push({ step: step.name, count: Object.keys(produced).length });
  }
  return { values, steps: results };
}
