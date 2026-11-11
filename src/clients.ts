/**
 * Suite clients (vpnhop, hopsql …): apps keyhop has pinned, which may read and
 * write secrets through `keyhop client get|put` after keyhop has verified that
 * its parent process is that exact app. See docs in README ("Suite clients").
 */

import { realpathSync, statSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { isAbsolute, sep } from 'node:path';
import { AccessGate, inert, type Dialog } from './approve.ts';
import { AuthCancelledError } from './auth.ts';
import { assertName, NAME_PATTERN } from './config.ts';
import { writePrivate, type Paths } from './paths.ts';
import { hashFile } from './policy.ts';
import type { VaultStore } from './store.ts';
import type { ClientPin, SuiteClient, VaultData } from './types.ts';
import { assertSafeRoot, treeHash, verifyParent, VerifyError, type ProcessInspector } from './verify.ts';

/** Exit codes of every `keyhop client` subcommand. */
export const EXIT = { ok: 0, error: 1, cancelled: 2, unverified: 3, denied: 4, unknown: 5 } as const;
export type ExitCode = (typeof EXIT)[keyof typeof EXIT];

export class ClientError extends Error {
  constructor(
    readonly exitCode: ExitCode,
    message: string
  ) {
    super(message);
  }
}

export const CLIENT_NAME = /^[a-z][a-z0-9-]{0,31}$/;
const MAX_PURPOSE = 200;
const MAX_VALUE_BYTES = 1024 * 1024;
const MAX_NAMES = 1000;
const MAX_PATH_CHARS = 300;

export interface ClientDeps {
  store: VaultStore;
  /** Native dialog; null where there is none. */
  dialog: Dialog | null;
  inspector: ProcessInspector;
  /** The process to verify: keyhop's parent. */
  ppid: number;
  platform: NodeJS.Platform;
}

export function defaultPrefix(name: string): string {
  return `${name.toUpperCase().replaceAll('-', '_')}_`;
}

function assertClientName(name: unknown): asserts name is string {
  if (typeof name !== 'string' || !CLIENT_NAME.test(name))
    throw new ClientError(EXIT.error, 'Client names are a-z, 0-9 and -, starting with a letter, at most 32 characters.');
}

function assertPrefix(prefix: string): void {
  if (!NAME_PATTERN.test(prefix) || !prefix.endsWith('_') || !/[A-Z0-9]/.test(prefix))
    throw new ClientError(EXIT.error, `Invalid prefix "${prefix}": use A-Z, 0-9 and _, ending in _, like VPNHOP_.`);
  // A prefix like BUN_ or KEYHOP_ would only allow reserved names.
  assertName(`${prefix}X`);
}

/** Two clients may not share names: neither prefix may start the other. */
function overlapping(clients: Record<string, ClientPin>, name: string, prefix: string): string | undefined {
  return Object.entries(clients).find(
    ([other, pin]) => other !== name && (pin.prefix.startsWith(prefix) || prefix.startsWith(pin.prefix))
  )?.[0];
}

function isWithin(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir.endsWith(sep) ? dir : dir + sep);
}

function absolute(option: string, path: string | undefined): string {
  if (!path || !isAbsolute(path)) throw new ClientError(EXIT.error, `${option} needs an absolute path.`);
  return path;
}

/** Pins a client: real paths, the runtime's SHA-256 and the root's tree hash. */
export async function pinClient(options: { runtime?: string; entry?: string; root?: string; prefix: string }): Promise<ClientPin> {
  const runtime = absolute('--runtime', options.runtime);
  const entry = absolute('--entry', options.entry);
  const root = absolute('--root', options.root);
  try {
    const runtimeReal = realpathSync(runtime);
    if (!statSync(runtimeReal).isFile()) throw new Error(`${runtime} is not a file.`);
    const rootReal = realpathSync(root);
    if (!statSync(rootReal).isDirectory()) throw new Error(`${root} is not a folder.`);
    const entryReal = realpathSync(entry);
    if (!statSync(entryReal).isFile()) throw new Error(`${entry} is not a file.`);
    // The entry's content must be covered by the tree hash.
    if (!isWithin(entryReal, rootReal)) throw new Error(`${entry} is not inside ${root}.`);
    assertSafeRoot(rootReal);
    return {
      runtime: { path: runtime, realPath: runtimeReal, sha256: await hashFile(runtimeReal) },
      entry: { path: entry, realPath: entryReal },
      root: { path: root, realPath: rootReal, treeHash: await treeHash(rootReal) },
      prefix: options.prefix,
      addedAt: new Date().toISOString(),
    };
  } catch (error) {
    if (error instanceof ClientError) throw error;
    const message = error instanceof VerifyError ? error.message : (error as Error).message;
    throw new ClientError(EXIT.error, message);
  }
}

function samePin(a: ClientPin, b: ClientPin): boolean {
  const key = (p: ClientPin) => JSON.stringify([p.runtime, p.entry, p.root, p.prefix]);
  return key(a) === key(b);
}

// ---------------------------------------------------------------------------
// clients.json: the pins without grants, readable before any prompt.

interface Mirror {
  version: 1;
  clients: Record<string, ClientPin>;
}

export async function loadMirror(p: Paths): Promise<Record<string, ClientPin>> {
  try {
    const mirror = JSON.parse(await readFile(p.clients, 'utf8')) as Mirror;
    return mirror.clients ?? {};
  } catch {
    return {};
  }
}

async function saveMirror(p: Paths, clients: Record<string, SuiteClient>): Promise<void> {
  const pins = Object.fromEntries(Object.entries(clients).map(([name, { allow: _allow, ...pin }]) => [name, pin]));
  await writePrivate(p.clients, JSON.stringify({ version: 1, clients: pins } satisfies Mirror, null, 2) + '\n');
}

// ---------------------------------------------------------------------------
// Dialog text. Every model- or client-chosen field is quoted and made inert.

export function describeAdd(name: string, pin: ClientPin, replacing: boolean): string {
  return [
    `Register "${name}" as a keyhop suite client?`,
    '',
    `It may read and write secrets starting with ${pin.prefix} (after Touch ID each time), and ask you for others.`,
    '',
    `Client:  ${name}`,
    `Runtime:  "${inert(pin.runtime.realPath, MAX_PATH_CHARS)}"`,
    `Entry:  "${inert(pin.entry.realPath, MAX_PATH_CHARS)}"`,
    `Root:  "${inert(pin.root.realPath, MAX_PATH_CHARS)}"`,
    `Prefix:  ${pin.prefix}`,
    ...(replacing ? ['', `This replaces the current registration of ${name}.`] : []),
    '',
    "Only allow this if you are installing or updating this app yourself.",
  ].join('\n');
}

export function describeGrant(name: string, pin: ClientPin, names: string[], purpose: string): string {
  return [
    `The keyhop suite client "${name}" wants secrets outside its own ${pin.prefix} names:`,
    '',
    `Secrets:  ${inert(names.join(', '), MAX_PATH_CHARS)}`,
    `Purpose:  "${inert(purpose, MAX_PURPOSE)}"`,
    `Program:  "${inert(pin.entry.realPath, MAX_PATH_CHARS)}"`,
    '',
    `"Always allow" lets ${name} read these secrets again without this dialog (Touch ID is still needed).`,
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Registration.

export async function addClient(
  deps: Pick<ClientDeps, 'store' | 'dialog'>,
  name: string,
  options: { runtime?: string; entry?: string; root?: string; prefix?: string }
): Promise<ClientPin> {
  assertClientName(name);
  const prefix = options.prefix ?? defaultPrefix(name);
  assertPrefix(prefix);
  const pin = await pinClient({ ...options, prefix });
  const mirror = await loadMirror(deps.store.paths);
  const clash = overlapping(mirror, name, prefix);
  if (clash) throw new ClientError(EXIT.error, `Prefix ${prefix} overlaps ${clash}'s ${mirror[clash]!.prefix}.`);
  if (!deps.dialog) throw new ClientError(EXIT.error, 'keyhop has no dialog on this platform to approve a client.');
  if ((await deps.dialog(describeAdd(name, pin, !!mirror[name]), 'confirm').catch(() => 'deny')) === 'deny')
    throw new ClientError(EXIT.denied, 'denied');
  const clients = await deps.store.update('change', (vault) => {
    vault.clients ??= {};
    const taken = overlapping(vault.clients, name, prefix);
    if (taken) throw new ClientError(EXIT.error, `Prefix ${prefix} overlaps ${taken}'s ${vault.clients[taken]!.prefix}.`);
    vault.clients[name] = { ...pin, allow: vault.clients[name]?.allow ?? [] };
    return vault.clients;
  });
  await saveMirror(deps.store.paths, clients);
  return pin;
}

export async function removeClient(store: VaultStore, name: string): Promise<void> {
  assertClientName(name);
  const clients = await store.update('change', (vault) => {
    if (!vault.clients?.[name]) throw new ClientError(EXIT.error, `${name} is not a registered client.`);
    delete vault.clients[name];
    return vault.clients;
  });
  await saveMirror(store.paths, clients);
}

export interface ClientSummary {
  name: string;
  prefix: string;
  runtime: string;
  entry: string;
  root: string;
  /** Names outside the prefix the user always allowed. */
  allow: string[];
  addedAt: string;
}

export async function listClients(store: VaultStore): Promise<ClientSummary[]> {
  const vault = await store.read();
  return Object.entries(vault.clients ?? {})
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([name, c]) => ({
      name,
      prefix: c.prefix,
      runtime: c.runtime.realPath,
      entry: c.entry.realPath,
      root: c.root.realPath,
      allow: c.allow.map((a) => a.name),
      addedAt: c.addedAt,
    }));
}

// ---------------------------------------------------------------------------
// get / put.

function object(input: unknown): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) throw new ClientError(EXIT.error, 'stdin must be a JSON object.');
  return input as Record<string, unknown>;
}

function nameList(value: unknown, field: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_NAMES || !value.every((n) => typeof n === 'string' && NAME_PATTERN.test(n)))
    throw new ClientError(EXIT.error, `${field} must be an array of secret names (A-Z, 0-9, _).`);
  return [...new Set(value as string[])];
}

function purposeOf(value: unknown): string {
  if (value === undefined) return '';
  if (typeof value !== 'string') throw new ClientError(EXIT.error, 'purpose must be a string.');
  return value.slice(0, MAX_PURPOSE);
}

/**
 * Checks the caller against the copy of its pin in clients.json, before any
 * prompt, so an unregistered or tampered caller never gets a Touch ID prompt.
 */
async function verifyCaller(deps: ClientDeps, client: string): Promise<ClientPin> {
  if (deps.platform === 'win32') throw new VerifyError('platform', 'suite clients are supported on macOS and Linux only.');
  const pin = (await loadMirror(deps.store.paths))[client];
  if (!pin) throw new ClientError(EXIT.unverified, `registration: ${client} is not a registered client. Run: keyhop client add ${client} …`);
  await verifyParent(pin, deps.ppid, deps.inspector, { platform: deps.platform });
  return pin;
}

/** After the unlock: the vault's pin (the authority) must be the one just verified. */
function pinnedIn(vault: VaultData, client: string, verified: ClientPin): SuiteClient {
  const pin = vault.clients?.[client];
  if (!pin || !samePin(pin, verified))
    throw new ClientError(EXIT.unverified, `registration: ${client}'s pin in the vault differs from clients.json. Run: keyhop client add ${client} …`);
  return pin;
}

export async function getSecrets(deps: ClientDeps, input: unknown): Promise<{ values: Record<string, string> }> {
  const request = object(input);
  assertClientName(request.client);
  const client = request.client;
  const names = nameList(request.names, 'names');
  if (!names.length) throw new ClientError(EXIT.error, 'names must list at least one secret.');
  const purpose = purposeOf(request.purpose);

  const verified = await verifyCaller(deps, client);
  const vault = await deps.store.read('unlock');
  const pin = pinnedIn(vault, client, verified);
  const unknown = names.filter((name) => !vault.secrets[name]);
  if (unknown.length) throw new ClientError(EXIT.unknown, unknown.join(', '));

  const granted = (name: string) =>
    name.startsWith(pin.prefix) || pin.allow.some((a) => a.name === name && a.origin === vault.secrets[name]!.origin);
  const ungranted = names.filter((name) => !granted(name));
  if (ungranted.length) {
    if (!deps.dialog) throw new ClientError(EXIT.error, 'keyhop has no dialog on this platform to ask for access.');
    const dialog = deps.dialog;
    let cancelled = false;
    const gate = new AccessGate<string>((message) => dialog(message, 'grant'));
    const outcome = await gate.ask(describeGrant(client, pin, ungranted, purpose), async () => {
      try {
        await deps.store.confirm('grant');
      } catch (error) {
        if (error instanceof AuthCancelledError) cancelled = true;
        throw error;
      }
    });
    if (outcome !== 'once' && outcome !== 'always')
      throw cancelled ? new ClientError(EXIT.cancelled, 'cancelled') : new ClientError(EXIT.denied, 'denied');
    if (outcome === 'always')
      await deps.store.update('change', (latest) => {
        const current = pinnedIn(latest, client, verified);
        const kept = current.allow.filter((a) => !ungranted.includes(a.name));
        const added = ungranted.filter((name) => latest.secrets[name]).map((name) => ({ name, origin: latest.secrets[name]!.origin }));
        current.allow = [...kept, ...added].sort((a, b) => a.name.localeCompare(b.name));
      });
  }
  return { values: Object.fromEntries(names.map((name) => [name, vault.secrets[name]!.value])) };
}

export async function putSecrets(deps: ClientDeps, input: unknown): Promise<{ saved: string[]; removed: string[] }> {
  const request = object(input);
  assertClientName(request.client);
  const client = request.client;
  const values = request.values === undefined ? {} : object(request.values);
  const saving = Object.keys(values);
  const removing = nameList(request.remove, 'remove');
  purposeOf(request.purpose);
  if (!saving.length && !removing.length) throw new ClientError(EXIT.error, 'Nothing to save or remove.');
  if (saving.length > MAX_NAMES) throw new ClientError(EXIT.error, `At most ${MAX_NAMES} values at once.`);
  const both = saving.filter((name) => removing.includes(name));
  if (both.length) throw new ClientError(EXIT.error, `${both.join(', ')} is both saved and removed.`);
  for (const [name, value] of Object.entries(values)) {
    if (typeof value !== 'string' || /\p{Cs}/u.test(value))
      throw new ClientError(EXIT.error, `${name} must be a UTF-8 string.`);
    if (Buffer.byteLength(value, 'utf8') > MAX_VALUE_BYTES) throw new ClientError(EXIT.error, `${name} is over 1 MiB.`);
  }

  const verified = await verifyCaller(deps, client);
  for (const name of [...saving, ...removing]) {
    if (!NAME_PATTERN.test(name) || !name.startsWith(verified.prefix))
      throw new ClientError(EXIT.error, `${client} may only write names starting with ${verified.prefix}.`);
    assertName(name);
  }
  const owner = `client:${client}`;
  return deps.store.update('change', (vault) => {
    pinnedIn(vault, client, verified);
    const now = new Date().toISOString();
    for (const name of saving) {
      const value = values[name] as string;
      const previous = vault.secrets[name];
      const unchanged = previous?.value === value && previous.origin === owner;
      vault.secrets[name] = { value, source: owner, origin: owner, updatedAt: unchanged ? previous.updatedAt : now };
    }
    const removed = removing.filter((name) => vault.secrets[name]);
    for (const name of removed) delete vault.secrets[name];
    return { saved: saving.sort(), removed: removed.sort() };
  });
}

// ---------------------------------------------------------------------------
// CLI.

export interface ClientIO {
  stdin(): Promise<string>;
  stdout(text: string): void;
  stderr(text: string): void;
}

function takeOption(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new ClientError(EXIT.error, `${name} needs a value.`);
  args.splice(index, 2);
  return value;
}

async function readRequest(io: ClientIO): Promise<unknown> {
  try {
    return JSON.parse(await io.stdin());
  } catch {
    throw new ClientError(EXIT.error, 'stdin must be a JSON object.');
  }
}

const USAGE = `Usage:
  keyhop client add NAME --runtime PATH --entry PATH --root DIR [--prefix PREFIX_]
  keyhop client list [--json]
  keyhop client remove NAME
  keyhop client get   (JSON request on stdin)
  keyhop client put   (JSON request on stdin)`;

/** Runs `keyhop client …` and returns its exit code. Never writes a secret value to stderr. */
export async function runClient(argv: string[], deps: ClientDeps, io: ClientIO): Promise<ExitCode> {
  const [sub, ...args] = argv;
  try {
    switch (sub) {
      case 'add': {
        const runtime = takeOption(args, '--runtime');
        const entry = takeOption(args, '--entry');
        const root = takeOption(args, '--root');
        const prefix = takeOption(args, '--prefix');
        const [name] = args;
        if (!name || args.length > 1) throw new ClientError(EXIT.error, USAGE);
        const pin = await addClient(deps, name, { runtime, entry, root, prefix });
        io.stdout(`Registered ${name}: it may use secrets starting with ${pin.prefix}.\n`);
        return EXIT.ok;
      }
      case 'list': {
        const json = args.includes('--json');
        const clients = await listClients(deps.store);
        if (json) io.stdout(JSON.stringify(clients) + '\n');
        else if (!clients.length) io.stdout('No suite clients.\n');
        else
          for (const c of clients)
            io.stdout(`  ${c.name}  ${c.prefix}*  ${c.runtime} ${c.entry}${c.allow.length ? `  also: ${c.allow.join(', ')}` : ''}\n`);
        return EXIT.ok;
      }
      case 'remove': {
        const [name] = args;
        if (!name || args.length > 1) throw new ClientError(EXIT.error, USAGE);
        await removeClient(deps.store, name);
        io.stdout(`Removed ${name}. Its secrets stay in the vault; delete them with keyhop remove NAME.\n`);
        return EXIT.ok;
      }
      case 'get':
        io.stdout(JSON.stringify(await getSecrets(deps, await readRequest(io))) + '\n');
        return EXIT.ok;
      case 'put':
        io.stdout(JSON.stringify(await putSecrets(deps, await readRequest(io))) + '\n');
        return EXIT.ok;
      default:
        throw new ClientError(EXIT.error, USAGE);
    }
  } catch (error) {
    const { code, message } = exitFor(error);
    io.stderr(code === EXIT.cancelled || code === EXIT.denied || code === EXIT.unknown ? `${message}\n` : `keyhop: ${message}\n`);
    return code;
  }
}

export function exitFor(error: unknown): { code: ExitCode; message: string } {
  if (error instanceof ClientError)
    return {
      code: error.exitCode,
      message: error.exitCode === EXIT.cancelled ? 'cancelled' : error.exitCode === EXIT.denied ? 'denied' : error.message,
    };
  if (error instanceof VerifyError) return { code: EXIT.unverified, message: `client check failed: ${error.message}` };
  if (error instanceof AuthCancelledError) return { code: EXIT.cancelled, message: 'cancelled' };
  return { code: EXIT.error, message: (error as Error)?.message ?? String(error) };
}
