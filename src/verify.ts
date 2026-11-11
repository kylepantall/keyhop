/**
 * Proves that the process which started keyhop is a pinned suite client: the
 * pinned runtime binary, started on the pinned entry file with no runtime
 * flags, no code-injecting environment, from an install tree that still hashes
 * the same. Everything the OS reports comes through a ProcessInspector so tests
 * can fake it.
 */

import { createHash } from 'node:crypto';
import { existsSync, realpathSync, statSync } from 'node:fs';
import { readdir, readFile, readlink } from 'node:fs/promises';
import { homedir } from 'node:os';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';
import { hashFile } from './policy.ts';
import { runProcess } from './process.ts';
import type { ClientPin } from './types.ts';

/** What the OS says about a process. Each returns null when it can't be read. */
export interface ProcessInspector {
  /** The running executable: `lsof -a -p PID -d txt -Fn`, first `n` line. */
  executable(pid: number): Promise<string | null>;
  /** Exact argv (macOS: KERN_PROCARGS2, the data `ps -ww -o command=` prints joined by spaces). */
  argv(pid: number): Promise<string[] | null>;
  /** Environment as NAME=value (macOS: KERN_PROCARGS2, as `ps -E` shows). Empty means unreadable. */
  env(pid: number): Promise<string[] | null>;
  /** Working directory: `lsof -a -p PID -d cwd -Fn`. */
  cwd(pid: number): Promise<string | null>;
}

export type VerifyCheck = 'platform' | 'executable' | 'runtime-hash' | 'argv' | 'environment' | 'bunfig' | 'root' | 'tree';

export class VerifyError extends Error {
  constructor(
    readonly check: VerifyCheck,
    message: string
  ) {
    super(`${check}: ${message}`);
  }
}

/** Variables that load code into node or bun, or into any program via the dynamic loader. */
const INJECTING = /^(NODE_OPTIONS|NODE_PATH|BUN_OPTIONS|BUN_INSPECT.*|DYLD_.*|LD_.*)$/;

export function injectingVariables(env: string[]): string[] {
  return env.map((entry) => entry.slice(0, Math.max(entry.indexOf('='), 0)) || entry).filter((name) => INJECTING.test(name));
}

function isWithin(path: string, dir: string): boolean {
  return path === dir || path.startsWith(dir.endsWith(sep) ? dir : dir + sep);
}

/** Refuses a root that is, or sits inside, a world-writable directory (which anyone could swap). */
export function assertSafeRoot(realRoot: string): void {
  if (process.platform === 'win32') return;
  for (let dir = realRoot; ; dir = dirname(dir)) {
    if (statSync(dir).mode & 0o002) throw new VerifyError('root', `${dir} is world-writable.`);
    if (dirname(dir) === dir) return;
  }
}

/**
 * SHA-256 over `relpath NUL sha256 NUL` for every regular file under `root`
 * (node_modules included), sorted by path bytes. Symlinks and special files
 * are refused.
 */
export async function treeHash(root: string): Promise<string> {
  const files: string[] = [];
  const walk = async (dir: string, rel: string): Promise<void> => {
    for (const entry of await readdir(dir, { withFileTypes: true })) {
      const relPath = rel ? `${rel}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) throw new VerifyError('tree', `${relPath} is a symlink; client trees may not contain symlinks.`);
      if (entry.isDirectory()) await walk(join(dir, entry.name), relPath);
      else if (entry.isFile()) files.push(relPath);
      else throw new VerifyError('tree', `${relPath} is not a regular file.`);
    }
  };
  await walk(root, '');
  files.sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)));
  const hashes = new Array<string>(files.length);
  // A few at a time: node_modules can hold thousands of small files.
  let next = 0;
  await Promise.all(
    Array.from({ length: Math.min(16, files.length) }, async () => {
      while (next < files.length) {
        const i = next++;
        hashes[i] = await hashFile(join(root, files[i]!));
      }
    })
  );
  const tree = createHash('sha256');
  files.forEach((file, i) => tree.update(`${file}\0${hashes[i]}\0`));
  return tree.digest('hex');
}

function realOrNull(path: string): string | null {
  try {
    return realpathSync(path);
  } catch {
    return null;
  }
}

/**
 * Checks every rule; throws VerifyError naming the first that fails.
 * `tree: false` skips the tree hash (when it was just checked against the same pin).
 */
export async function verifyParent(
  pin: ClientPin,
  pid: number,
  inspector: ProcessInspector,
  options: { platform?: NodeJS.Platform; tree?: boolean } = {}
): Promise<void> {
  const platform = options.platform ?? process.platform;
  if (platform !== 'darwin' && platform !== 'linux')
    throw new VerifyError('platform', 'suite clients are supported on macOS and Linux only.');

  const executable = await inspector.executable(pid);
  if (!executable || (executable !== pin.runtime.realPath && realOrNull(executable) !== pin.runtime.realPath))
    throw new VerifyError('executable', `the caller is ${executable ?? 'unknown'}, not ${pin.runtime.realPath}.`);
  if ((await hashFile(pin.runtime.realPath).catch(() => null)) !== pin.runtime.sha256)
    throw new VerifyError('runtime-hash', `${pin.runtime.realPath} has changed since the client was added.`);

  // argv[0] is only a name (the binary was checked above), but it must be the
  // runtime's; argv[1] must be the entry itself, so no runtime flag comes first.
  const argv = await inspector.argv(pid);
  const names = new Set([pin.runtime.path, pin.runtime.realPath, basename(pin.runtime.path), basename(pin.runtime.realPath)]);
  const script = argv?.[1];
  if (!argv || !names.has(argv[0]!) || !script || !isAbsolute(script) || realOrNull(script) !== pin.entry.realPath || !statSync(script).isFile())
    throw new VerifyError('argv', `the caller must be started as: ${pin.runtime.path} ${pin.entry.realPath} [args…].`);

  const env = await inspector.env(pid);
  if (!env?.length) throw new VerifyError('environment', "the caller's environment can't be read.");
  const injecting = injectingVariables(env);
  if (injecting.length) throw new VerifyError('environment', `the caller has ${injecting.join(', ')} set.`);

  // Bun preloads code named in bunfig.toml from the working directory or home.
  if (/^bun/i.test(basename(pin.runtime.realPath))) {
    const cwd = await inspector.cwd(pid);
    if (!cwd) throw new VerifyError('bunfig', "the caller's working directory can't be read.");
    const realCwd = realOrNull(cwd) ?? cwd;
    const config = process.env.XDG_CONFIG_HOME;
    const found = [
      ...(isWithin(realCwd, pin.root.realPath) ? [] : [join(realCwd, 'bunfig.toml')]),
      join(homedir(), '.bunfig.toml'),
      ...(config ? [join(config, '.bunfig.toml')] : []),
    ].filter((file) => existsSync(file));
    if (found.length) throw new VerifyError('bunfig', `${found.join(', ')} could preload code into the client.`);
  }

  assertSafeRoot(pin.root.realPath);
  if (options.tree !== false) {
    const current = await treeHash(pin.root.realPath).catch((error: Error) => {
      if (error instanceof VerifyError) throw error;
      throw new VerifyError('tree', `${pin.root.realPath} can't be read.`);
    });
    if (current !== pin.root.treeHash) throw new VerifyError('tree', `files under ${pin.root.realPath} changed since the client was added.`);
  }
}

// ---------------------------------------------------------------------------
// The real inspector.

async function lsofName(pid: number, fd: 'txt' | 'cwd'): Promise<string | null> {
  const result = await runProcess('/usr/sbin/lsof', ['-a', '-p', String(pid), '-d', fd, '-Fn'], { timeoutMs: 10_000 });
  if (result.code !== 0) return null;
  const line = result.stdout.split('\n').find((l) => l.startsWith('n'));
  return line ? line.slice(1) : null;
}

const CTL_KERN = 1;
const KERN_ARGMAX = 8;
const KERN_PROCARGS2 = 49;

/**
 * macOS KERN_PROCARGS2: argc, the exec path, then argv and the environment as
 * NUL-terminated strings. Read directly because `ps` joins argv with spaces,
 * so argv ["node /entry.js", "/evil.js"] would print exactly like a real call.
 */
export function parseProcArgs(buffer: Buffer): { argv: string[]; env: string[] } | null {
  if (buffer.length < 4) return null;
  const argc = buffer.readInt32LE(0);
  const end = (from: number) => {
    const at = buffer.indexOf(0, from);
    return at === -1 ? buffer.length : at;
  };
  let i = end(4); // skip the exec path
  while (i < buffer.length && buffer[i] === 0) i++;
  const argv: string[] = [];
  while (i < buffer.length && argv.length < argc) {
    const j = end(i);
    argv.push(buffer.toString('utf8', i, j));
    i = j + 1;
  }
  if (argv.length !== argc) return null;
  const env: string[] = [];
  while (i < buffer.length && buffer[i] !== 0) {
    const j = end(i);
    env.push(buffer.toString('utf8', i, j));
    i = j + 1;
  }
  return { argv, env };
}

async function macProcArgs(pid: number): Promise<{ argv: string[]; env: string[] } | null> {
  const { dlopen, FFIType, ptr } = await import('bun:ffi');
  const lib = dlopen('/usr/lib/libSystem.B.dylib', {
    sysctl: { args: [FFIType.ptr, FFIType.u32, FFIType.ptr, FFIType.ptr, FFIType.ptr, FFIType.u64], returns: FFIType.i32 },
  });
  try {
    const max = new Int32Array(1);
    const maxSize = new BigUint64Array([4n]);
    if (lib.symbols.sysctl(ptr(new Int32Array([CTL_KERN, KERN_ARGMAX])), 2, ptr(max), ptr(maxSize), null, 0n) !== 0) return null;
    const buffer = new Uint8Array(max[0]!);
    const size = new BigUint64Array([BigInt(buffer.length)]);
    if (lib.symbols.sysctl(ptr(new Int32Array([CTL_KERN, KERN_PROCARGS2, pid])), 3, ptr(buffer), ptr(size), null, 0n) !== 0)
      return null;
    return parseProcArgs(Buffer.from(buffer.buffer, 0, Number(size[0])));
  } finally {
    lib.close();
  }
}

async function procList(pid: number, file: 'cmdline' | 'environ'): Promise<string[] | null> {
  try {
    const text = await readFile(`/proc/${pid}/${file}`, 'utf8');
    return text.split('\0').filter((part, i, all) => i < all.length - 1 || part !== '');
  } catch {
    return null;
  }
}

export function systemInspector(platform: NodeJS.Platform = process.platform): ProcessInspector {
  if (platform === 'linux')
    return {
      executable: (pid) => readlink(`/proc/${pid}/exe`).catch(() => null),
      argv: (pid) => procList(pid, 'cmdline'),
      env: (pid) => procList(pid, 'environ'),
      cwd: (pid) => readlink(`/proc/${pid}/cwd`).catch(() => null),
    };
  return {
    executable: (pid) => lsofName(pid, 'txt'),
    argv: async (pid) => (await macProcArgs(pid))?.argv ?? null,
    env: async (pid) => (await macProcArgs(pid))?.env ?? null,
    cwd: (pid) => lsofName(pid, 'cwd'),
  };
}
