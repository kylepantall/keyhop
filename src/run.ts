import { existsSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { AccessGate } from './approve.ts';
import { assertAllowable, findAllowed, pinExecutable, resolveExecutable, verifyPinned } from './policy.ts';
import { runProcess } from './process.ts';
import { redactor } from './redact.ts';
import type { VaultStore } from './store.ts';
import { changeAllowed, syncedSecrets } from './secrets.ts';

export interface RunOptions {
  /** Asks the user about secrets not allowed for the program; without it they are refused. */
  gate?: AccessGate;
}

export interface RunRequest {
  command: string;
  args: string[];
  secrets: string[];
  cwd?: string;
  timeoutSeconds?: number;
}

export interface RunResult {
  command: string;
  exitCode: number | null;
  signal: string | null;
  timedOut: boolean;
  truncated: boolean;
  stdout: string;
  stderr: string;
}

const MAX_CHARS = 30_000;

function clip(text: string): [string, boolean] {
  return text.length > MAX_CHARS ? [text.slice(0, MAX_CHARS), true] : [text, false];
}

export async function runWithSecrets(store: VaultStore, request: RunRequest, options: RunOptions = {}): Promise<RunResult> {
  if (!request.secrets.length) throw new Error('Name at least one secret to inject.');
  const path = resolveExecutable(request.command);
  assertAllowable(path);
  // The launcher starts keyhop in its own folder (so Bun never loads a planted
  // bunfig.toml or .env) and passes the folder it was started from.
  const cwd = request.cwd ?? process.env.KEYHOP_CWD ?? process.cwd();
  if (!isAbsolute(cwd) || !existsSync(cwd) || !statSync(cwd).isDirectory())
    throw new Error(`cwd must be an existing absolute directory: ${cwd}`);

  const vault = await store.read();
  const missing = request.secrets.filter((name) => !vault.secrets[name]);
  if (missing.length) throw new Error(`Unknown secret(s): ${missing.join(', ')}. Call list_secrets.`);
  const grants = request.secrets.map((name) => {
    const policy = vault.policy[name];
    // Rules only count for the origin they were granted for.
    const bound = policy?.boundTo === vault.secrets[name]!.origin ? policy : undefined;
    return { name, allowed: findAllowed(bound, path) };
  });
  const denied = grants.filter((g) => !g.allowed).map((g) => g.name);
  if (denied.length) {
    const hint =
      `Only the user can allow it, by running: ` +
      denied.map((name) => `keyhop allow ${name} ${request.command}`).join(' && ');
    if (!options.gate) throw new Error(`${denied.join(', ')} may not be used with ${path}. ${hint}`);
    // Pin now, so the file the user approves is the file that runs.
    const pinned = await pinExecutable(path);
    const outcome = await options.gate.ask(
      { secrets: denied, executable: pinned.realPath, args: request.args, cwd },
      () => store.confirm('grant')
    );
    if (outcome === 'busy') throw new Error('Another access request is waiting for the user. Try again once they answer.');
    if (outcome === 'cooling')
      throw new Error(`The user recently denied an access request, so keyhop won't ask again yet. ${hint}`);
    if (outcome === 'deny') throw new Error(`The user denied ${denied.join(', ')} for ${path}.`);
    if (outcome === 'always')
      await changeAllowed(
        store,
        Object.fromEntries(denied.map((name) => [name, { add: [pinned], bindTo: vault.secrets[name]!.origin }]))
      );
    for (const grant of grants) grant.allowed ??= pinned;
  }
  // Same file as when allowed; run the verified real path so a symlink swap can't redirect it.
  let executable = path;
  for (const grant of grants) executable = await verifyPinned(path, grant.allowed!, grant.name);

  const all = syncedSecrets(vault);
  const env: NodeJS.ProcessEnv = { ...process.env };
  for (const name of Object.keys(all)) delete env[name];
  for (const name of request.secrets) env[name] = all[name];

  const timeoutSeconds = Math.min(Math.max(request.timeoutSeconds ?? 120, 1), 600);
  const result = await runProcess(executable, request.args, {
    cwd,
    env,
    timeoutMs: timeoutSeconds * 1000,
    killTree: true,
  });
  const redact = redactor(all);
  const [stdout, cutOut] = clip(redact(result.stdout));
  const [stderr, cutErr] = clip(redact(result.stderr));
  return {
    command: executable,
    exitCode: result.code,
    signal: result.signal,
    timedOut: result.timedOut,
    truncated: result.truncated || cutOut || cutErr,
    stdout,
    stderr,
  };
}
