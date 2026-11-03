import { existsSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { AccessGate } from './approve.ts';
import { openSecretPipe, type SecretPipe } from './pipes.ts';
import { assertAllowable, findAllowed, pinExecutable, resolveExecutable, verifyPinned } from './policy.ts';
import { runProcess } from './process.ts';
import { redactor } from './redact.ts';
import type { VaultStore } from './store.ts';
import { changeAllowed, syncedSecrets } from './secrets.ts';
import type { Delivery, VaultData } from './types.ts';

export interface RunOptions {
  /** Asks the user about secrets not allowed for the program; without it they are refused. */
  gate?: AccessGate;
}

export interface RunRequest {
  command: string;
  /** May hold {{file:NAME}} (a named-pipe path that reads as the value) and {{arg:NAME}} (the value itself). */
  args: string[];
  /** Set as environment variables. */
  secrets?: string[];
  /** Written to the program's standard input, which is then closed. */
  stdin?: string;
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
const PLACEHOLDER = /\{\{(file|arg):([A-Z_][A-Z0-9_]*)\}\}/g;

function clip(text: string): [string, boolean] {
  return text.length > MAX_CHARS ? [text.slice(0, MAX_CHARS), true] : [text, false];
}

/** Every secret the request uses, and how. */
export function deliveries(request: RunRequest): Map<string, Set<Delivery>> {
  const uses = new Map<string, Set<Delivery>>();
  const use = (name: string, how: Delivery) => uses.set(name, (uses.get(name) ?? new Set()).add(how));
  for (const name of request.secrets ?? []) use(name, 'env');
  if (request.stdin) use(request.stdin, 'stdin');
  for (const arg of request.args)
    for (const [, kind, name] of arg.matchAll(PLACEHOLDER)) use(name!, kind as Delivery);
  return uses;
}

function boundPolicy(vault: VaultData, name: string) {
  const policy = vault.policy[name];
  // Rules only count for the origin they were granted for.
  return policy?.boundTo === vault.secrets[name]!.origin ? policy : undefined;
}

export async function runWithSecrets(store: VaultStore, request: RunRequest, options: RunOptions = {}): Promise<RunResult> {
  const uses = deliveries(request);
  if (!uses.size) throw new Error('Name at least one secret: in secrets, stdin, or an argument as {{file:NAME}} / {{arg:NAME}}.');
  const names = [...uses.keys()];
  const path = resolveExecutable(request.command);
  assertAllowable(path);
  // The launcher starts keyhop in its own folder (so Bun never loads a planted
  // bunfig.toml or .env) and passes the folder it was started from.
  const cwd = request.cwd ?? process.env.KEYHOP_CWD ?? process.cwd();
  if (!isAbsolute(cwd) || !existsSync(cwd) || !statSync(cwd).isDirectory())
    throw new Error(`cwd must be an existing absolute directory: ${cwd}`);

  const vault = await store.read();
  const missing = names.filter((name) => !vault.secrets[name]);
  if (missing.length) throw new Error(`Unknown secret(s): ${missing.join(', ')}. Call list_secrets.`);
  // A value in an argument shows in the process list, so it needs its own opt-in.
  const noArg = names.filter((name) => uses.get(name)!.has('arg') && !boundPolicy(vault, name)?.asArgument);
  if (noArg.length)
    throw new Error(
      `${noArg.join(', ')} may not be placed in an argument (it would show in the process list). ` +
        `Use {{file:NAME}} or stdin instead, or the user can opt in with: ` +
        noArg.map((name) => `keyhop allow-arg ${name}`).join(' && ')
    );
  const grants = names.map((name) => ({ name, allowed: findAllowed(boundPolicy(vault, name), path) }));
  const denied = grants.filter((g) => !g.allowed).map((g) => g.name);
  if (denied.length) {
    const hint =
      `Only the user can allow it, by running: ` +
      denied.map((name) => `keyhop allow ${name} ${request.command}`).join(' && ');
    if (!options.gate) throw new Error(`${denied.join(', ')} may not be used with ${path}. ${hint}`);
    // Pin now, so the file the user approves is the file that runs.
    const pinned = await pinExecutable(path);
    const outcome = await options.gate.ask(
      {
        secrets: denied,
        delivery: Object.fromEntries(denied.map((name) => [name, [...uses.get(name)!]])),
        executable: pinned.realPath,
        args: request.args,
        cwd,
      },
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
  for (const name of request.secrets ?? []) env[name] = all[name];

  const pipes = new Map<string, SecretPipe>();
  try {
    for (const name of names)
      if (uses.get(name)!.has('file')) pipes.set(name, await openSecretPipe(all[name]!));
    const args = request.args.map((arg) =>
      arg.replace(PLACEHOLDER, (_, kind: string, name: string) => (kind === 'file' ? pipes.get(name)!.path : all[name]!))
    );
    const timeoutSeconds = Math.min(Math.max(request.timeoutSeconds ?? 120, 1), 600);
    const result = await runProcess(executable, args, {
      cwd,
      env,
      timeoutMs: timeoutSeconds * 1000,
      killTree: true,
      input: request.stdin ? all[request.stdin] : undefined,
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
  } finally {
    await Promise.all([...pipes.values()].map((pipe) => pipe.close()));
  }
}
