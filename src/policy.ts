/**
 * Which executables a secret may be injected into. Commands run without a
 * shell, so `$TOKEN` in an argument is never expanded; only programs that read
 * the variable themselves (gh, npm, aws …) see it. Shells and interpreters are
 * refused because they would let a caller print the value in some new form.
 *
 * An allowed executable is pinned by its real path and SHA-256, so swapping
 * the file (or a symlink in a user-writable bin directory) for something else
 * is caught before any secret is handed over.
 */

import { createHash } from 'node:crypto';
import { createReadStream, existsSync, realpathSync, statSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import type { AllowedExecutable, SecretPolicy } from './types.ts';

const BLOCKED = new Set([
  'sh', 'bash', 'zsh', 'fish', 'dash', 'ksh', 'csh', 'tcsh', 'nu', 'elvish', 'xonsh',
  'pwsh', 'powershell', 'powershell_ise', 'cmd', 'wsl', 'wscript', 'cscript', 'mshta',
  'node', 'bun', 'deno', 'ruby', 'perl', 'php', 'lua', 'luajit', 'tclsh', 'wish',
  'java', 'dotnet', 'osascript', 'swift', 'expect', 'awk', 'gawk', 'mawk', 'nawk', 'sed', 'jq', 'm4',
  'env', 'xargs', 'find', 'sudo', 'doas', 'su', 'nohup', 'time', 'timeout', 'watch', 'script',
  'nice', 'exec', 'eval', 'open', 'start', 'npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'make',
  'vi', 'vim', 'nvim', 'emacs', 'nano', 'ed', 'ex', 'less', 'more', 'man',
  'printenv', 'set', 'echo', 'cat', 'tee', 'base64', 'xxd', 'od', 'hexdump', 'strings',
  // The compiled keyhop.exe is Bun inside (BUN_BE_BUN runs any script).
  'keyhop',
]);

/** python3.12, perl5.34, tclsh8.6 … */
const VERSIONED_INTERPRETER = /^(python|pypy|perl|ruby|tclsh|wish|lua|luajit|php|node|pwsh)[\d.]*$/;

const WINDOWS_SCRIPT = /\.(cmd|bat|ps1|vbs|js|wsf|hta)$/i;

export function commandName(path: string): string {
  // Split on both separators so Windows paths are judged the same on any OS.
  return (path.split(/[\\/]/).pop() ?? path).toLowerCase().replace(/\.exe$/, '');
}

/** Thrown for shells and interpreters; a one-time bypass can get past it, nothing else can. */
export class GuardedProgramError extends Error {
  constructor(readonly program: string) {
    super(`${program} can run arbitrary code or print its environment, so it cannot be given secrets.`);
  }
}

function assertNameAllowable(path: string, bypass: boolean): void {
  const name = commandName(path);
  if (!bypass && (BLOCKED.has(name) || VERSIONED_INTERPRETER.test(name))) throw new GuardedProgramError(name);
  // keyhop itself stays refused even with a bypass: it would reach the vault.
  if (name === 'keyhop') throw new Error(`${name} is keyhop's own runtime, so it cannot be given secrets.`);
  if (WINDOWS_SCRIPT.test(path))
    throw new Error(`${name} is a script run by an interpreter; allow the real .exe instead.`);
}

/**
 * Checks both the path asked for and what it really points at. `bypass` (a
 * one-time run the user approved in person) lets shells and interpreters
 * through, but never keyhop's own runtime or a Windows script file.
 */
export function assertAllowable(path: string, { bypass = false } = {}): void {
  assertNameAllowable(path, bypass);
  if (!existsSync(path)) return;
  const real = realpathSync(path);
  assertNameAllowable(real, bypass);
  // keyhop's own runtime (Bun, or the compiled keyhop.exe) under any name.
  if (real === realpathSync(process.execPath))
    throw new Error(`${path} is keyhop's own runtime, so it cannot be given secrets.`);
}

/** A bare command name looked up on PATH, or an absolute path. */
export function resolveExecutable(command: string): string {
  if (isAbsolute(command)) {
    if (!existsSync(command) || !statSync(command).isFile()) throw new Error(`${command} does not exist.`);
    return command;
  }
  if (/[\\/]/.test(command)) throw new Error('Give a command name (gh) or an absolute path, not a relative path.');
  const found = Bun.which(command);
  if (!found) throw new Error(`${command} was not found on PATH.`);
  return found;
}

export function hashFile(path: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash('sha256');
    createReadStream(path)
      .on('data', (chunk) => hash.update(chunk))
      .on('error', reject)
      .on('end', () => resolve(hash.digest('hex')));
  });
}

/** Pins an executable for an allowlist (or, with `bypass`, for one run only). */
export async function pinExecutable(path: string, { bypass = false } = {}): Promise<AllowedExecutable> {
  assertAllowable(path, { bypass });
  const realPath = realpathSync(path);
  return { path, realPath, sha256: await hashFile(realPath) };
}

function samePath(a: string, b: string): boolean {
  return process.platform === 'win32' ? a.toLowerCase() === b.toLowerCase() : a === b;
}

export function findAllowed(policy: SecretPolicy | undefined, path: string): AllowedExecutable | undefined {
  return policy?.allow.find((allowed) => samePath(allowed.path, path));
}

/**
 * Re-pins `path` and checks it still matches what was allowed. Returns the
 * real path to execute, so a later symlink swap can't change what runs.
 */
export async function verifyPinned(
  path: string,
  allowed: AllowedExecutable,
  name: string,
  { bypass = false } = {}
): Promise<string> {
  const current = await pinExecutable(path, { bypass });
  if (!samePath(allowed.realPath, current.realPath) || allowed.sha256 !== current.sha256)
    throw new Error(
      `${path} has changed since it was allowed for ${name} (now ${current.realPath}). ` +
        `If you updated it yourself, the user can re-allow it with: keyhop allow ${name} ${commandName(path)}`
    );
  return current.realPath;
}
