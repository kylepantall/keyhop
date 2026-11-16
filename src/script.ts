/**
 * Works out which code a shell or interpreter will run, so the one-time
 * bypass dialog can show it ("View script"), and makes sure the code shown is
 * the code that runs:
 *
 * - inline code (python3 -c, node -e, bash -c …) is an argument, so it can't
 *   change after the user sees it;
 * - a script file is read once, and a private read-only copy of exactly those
 *   bytes is what the interpreter is given, so editing or swapping the file
 *   after the dialog changes nothing. The copy sits next to the original
 *   (so relative imports still work) and is deleted after the run.
 *
 * Arguments are parsed strictly: anything keyhop doesn't recognise (a module,
 * a preload, a value-taking option) means "can't tell", and the dialog says
 * so instead of showing something that may not be what runs.
 */

import { createHash, randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { chmod, mkdtemp, readFile, rm, rmdir, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, extname, isAbsolute, join, resolve } from 'node:path';
import { commandName } from './policy.ts';

export type Language = 'python' | 'shell' | 'javascript' | 'ruby' | 'perl' | 'powershell' | 'batch' | 'applescript' | 'text';

export interface Script {
  /** Inline: the code is in args[index] (or args[index…] joined, for PowerShell and cmd). File: args[index] is its path. */
  kind: 'inline' | 'file';
  language: Language;
  code: string;
  /** File scripts: absolute path as given. */
  path?: string;
  /** Index in args of the file path (file scripts only). */
  index?: number;
}

/** Biggest script keyhop will show and run in a bypass. */
export const MAX_SCRIPT_BYTES = 256 * 1024;

const PLACEHOLDER = /\{\{(file|arg):[A-Z_][A-Z0-9_]*\}\}/;

type Found = { inline: string } | { file: number } | null;

/** Short-option cluster like -uB or -ec: every letter must be known. */
function cluster(arg: string, flags: string, valued = ''): { letters: string[]; valueFor?: string; rest: string } | null {
  if (!/^[-+][A-Za-z0-9]/.test(arg) || arg.startsWith('--')) return null;
  const letters: string[] = [];
  for (let i = 1; i < arg.length; i++) {
    const letter = arg[i]!;
    if (valued.includes(letter)) return { letters, valueFor: letter, rest: arg.slice(i + 1) };
    if (!flags.includes(letter)) return null;
    letters.push(letter);
  }
  return { letters, rest: '' };
}

function python(args: string[]): Found {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--') return i + 1 < args.length ? { file: i + 1 } : null;
    if (!arg.startsWith('-') || arg === '-') return arg === '-' ? null : { file: i };
    const parsed = cluster(arg, 'bBdEiIOPqsSuvx', 'c');
    if (!parsed) return null;
    if (parsed.valueFor === 'c') {
      const code = parsed.rest || args[i + 1];
      return code === undefined ? null : { inline: code };
    }
  }
  return null;
}

function shell(args: string[]): Found {
  let command = false;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--' || arg === '-') {
      i++;
      if (i >= args.length) return null;
      return command ? { inline: args[i]! } : { file: i };
    }
    if (arg === '--login' || arg === '--norc' || arg === '--noprofile' || arg === '--posix') continue;
    if (!/^[-+]/.test(arg)) return command ? { inline: arg } : { file: i };
    const parsed = cluster(arg, 'aefhkmnpuvxBCEHPTilc', 'o');
    if (!parsed) return null;
    if (parsed.letters.includes('c')) command = true;
    if (parsed.valueFor === 'o') {
      if (parsed.rest) return null;
      i++; // -o pipefail
    }
  }
  return null;
}

const NODE_FLAGS = new Set(['--no-warnings', '--no-deprecation', '--enable-source-maps', '--trace-warnings', '--trace-uncaught']);

function node(args: string[]): Found {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (NODE_FLAGS.has(arg)) continue;
    let code: string | undefined;
    if (arg === '-e' || arg === '--eval' || arg === '-p' || arg === '--print') code = args[++i];
    else if (/^--(eval|print)=/.test(arg)) code = arg.slice(arg.indexOf('=') + 1);
    else if (arg === '--') return i + 1 < args.length ? { file: i + 1 } : null;
    else if (!arg.startsWith('-')) return { file: i };
    else return null;
    // Node may still read options after the code: only plain arguments may follow.
    if (code === undefined || args.slice(i + 1).some((rest) => rest.startsWith('-'))) return null;
    return { inline: code };
  }
  return null;
}

function bun(args: string[]): Found {
  const rest = args[0] === 'run' ? args.slice(1) : args;
  const offset = args.length - rest.length;
  const found = node(rest);
  if (found && 'file' in found) {
    // `bun run build` may be a package.json script: only an existing file counts (checked later).
    return { file: found.file + offset };
  }
  return found;
}

const DENO_FLAG = /^(-A|-q|--quiet|--no-prompt|--no-check|--allow-[a-z-]+(=[^\s]*)?)$/;

function deno(args: string[]): Found {
  const [sub, ...rest] = args;
  if (sub !== 'run' && sub !== 'eval') return null;
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i]!;
    if (DENO_FLAG.test(arg)) continue;
    if (arg.startsWith('-')) return null;
    return sub === 'eval' ? (i === rest.length - 1 ? { inline: arg } : null) : { file: i + 1 };
  }
  return null;
}

/** ruby / perl: options until the first operand; -e may repeat. */
function rubyPerl(args: string[], flags: string): Found {
  const code: string[] = [];
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--') {
      if (code.length) return { inline: code.join('\n') };
      return i + 1 < args.length ? { file: i + 1 } : null;
    }
    if (!arg.startsWith('-') || arg === '-') {
      if (code.length) return { inline: code.join('\n') };
      return arg === '-' ? null : { file: i };
    }
    const parsed = cluster(arg, flags, 'e');
    if (!parsed) return null;
    if (parsed.valueFor === 'e') {
      const value = parsed.rest || args[++i];
      if (value === undefined) return null;
      code.push(value);
    }
  }
  return code.length ? { inline: code.join('\n') } : null;
}

const PS_FLAGS = new Set(['-noprofile', '-nop', '-noninteractive', '-noni', '-nologo']);

function powershell(args: string[]): Found {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!.toLowerCase();
    if (PS_FLAGS.has(arg)) continue;
    if (arg === '-executionpolicy' || arg === '-ep') {
      i++;
      continue;
    }
    if (arg === '-command' || arg === '-c') {
      const rest = args.slice(i + 1);
      return rest.length && !(rest.length === 1 && rest[0] === '-') ? { inline: rest.join(' ') } : null;
    }
    if (arg === '-encodedcommand' || arg === '-ec' || arg === '-e') {
      const value = args[i + 1];
      if (!value || i + 2 !== args.length || !/^[A-Za-z0-9+/=]+$/.test(value)) return null;
      return { inline: Buffer.from(value, 'base64').toString('utf16le') };
    }
    if (arg === '-file' || arg === '-f') return i + 1 < args.length ? { file: i + 1 } : null;
    return null;
  }
  return null;
}

function cmd(args: string[]): Found {
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!.toLowerCase();
    if (arg === '/d' || arg === '/q' || arg === '/s') continue;
    if (arg === '/c') return i + 1 < args.length ? { inline: args.slice(i + 1).join(' ') } : null;
    return null;
  }
  return null;
}

function osascript(args: string[]): Found {
  return rubyPerl(args, '');
}

interface Interpreter {
  language: Language;
  parse: (args: string[]) => Found;
  /** For PowerShell -Command and cmd /c: the code is every argument from the first one it starts in. */
  joined?: boolean;
}

function interpreterFor(executable: string): Interpreter | null {
  const name = commandName(executable);
  if (/^(python|pypy)[\d.]*w?$/.test(name)) return { language: 'python', parse: python };
  if (['sh', 'bash', 'zsh', 'dash', 'ksh'].includes(name)) return { language: 'shell', parse: shell };
  if (/^node[\d.]*$/.test(name) || name === 'nodejs') return { language: 'javascript', parse: node };
  if (name === 'bun') return { language: 'javascript', parse: bun };
  if (name === 'deno') return { language: 'javascript', parse: deno };
  if (/^ruby[\d.]*$/.test(name)) return { language: 'ruby', parse: (a) => rubyPerl(a, 'wWvdnpla') };
  if (/^perl[\d.]*$/.test(name)) return { language: 'perl', parse: (a) => rubyPerl(a, 'wWXnpalTtsU') };
  if (/^(pwsh[\d.]*|powershell)$/.test(name)) return { language: 'powershell', parse: powershell, joined: true };
  if (name === 'cmd') return { language: 'batch', parse: cmd, joined: true };
  if (name === 'osascript') return { language: 'applescript', parse: osascript };
  return null;
}

function languageFromPath(path: string, fallback: Language): Language {
  const ext = extname(path).toLowerCase();
  if (['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx'].includes(ext)) return 'javascript';
  if (ext === '.py') return 'python';
  if (['.sh', '.bash', '.zsh'].includes(ext)) return 'shell';
  return fallback;
}

/**
 * The code this program will run, or null when keyhop can't tell. A script
 * file is read here, once; run it through `snapshotScript` so the copy that
 * runs holds exactly these bytes.
 */
export function findScript(executable: string, args: string[], cwd: string): Script | null {
  const interpreter = interpreterFor(executable);
  if (!interpreter) return null;
  const found = interpreter.parse(args);
  if (!found) return null;
  if ('inline' in found) return { kind: 'inline', language: interpreter.language, code: found.inline };
  const given = args[found.file]!;
  // A path built from a secret would be a different file at run time.
  if (PLACEHOLDER.test(given)) return null;
  const path = isAbsolute(given) ? given : resolve(cwd, given);
  if (!existsSync(path) || !statSync(path).isFile()) return null;
  if (statSync(path).size > MAX_SCRIPT_BYTES)
    throw new Error(`${given} is over ${MAX_SCRIPT_BYTES / 1024} KB, too long to show for approval.`);
  const bytes = readFileSync(path);
  let code: string;
  try {
    code = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    // Not text keyhop can show faithfully.
    return null;
  }
  return { kind: 'file', language: languageFromPath(path, interpreter.language), code, path, index: found.file };
}

export interface Snapshot {
  /** The arguments to run, with the script path pointing at the copy. */
  args: string[];
  /** Throws if the copy no longer holds the approved bytes. */
  verify: () => Promise<void>;
  remove: () => Promise<void>;
}

const sha256 = (data: Buffer | string) => createHash('sha256').update(data).digest('hex');

/**
 * Writes the approved bytes of a script file to a new read-only file beside it
 * (or in a private temp folder if that folder isn't writable) and points the
 * arguments at it.
 */
export async function snapshotScript(script: Script, args: string[]): Promise<Snapshot> {
  if (script.kind === 'inline') return { args, verify: async () => {}, remove: async () => {} };
  const bytes = Buffer.from(script.code, 'utf8');
  const name = `.keyhop-${randomBytes(8).toString('hex')}-${basename(script.path!)}`;
  let file = join(dirname(script.path!), name);
  let folder: string | undefined;
  try {
    await writeFile(file, bytes, { flag: 'wx', mode: 0o400 });
  } catch {
    folder = await mkdtemp(join(tmpdir(), 'keyhop-script-'));
    file = join(folder, basename(script.path!));
    await writeFile(file, bytes, { flag: 'wx', mode: 0o400 });
  }
  const expected = sha256(bytes);
  const copy = [...args];
  copy[script.index!] = file;
  return {
    args: copy,
    verify: async () => {
      if (sha256(await readFile(file)) !== expected)
        throw new Error('The approved script was changed before it could run, so it was not run.');
    },
    remove: async () => {
      // Windows won't delete a read-only file.
      await chmod(file, 0o600).catch(() => {});
      await unlink(file).catch(() => {});
      if (folder) await rmdir(folder).catch(() => rm(folder!, { recursive: true, force: true }));
    },
  };
}

// --- Syntax highlighting -----------------------------------------------------

export type TokenKind = 'plain' | 'keyword' | 'string' | 'comment' | 'number' | 'hidden' | 'gutter';
export type Token = [TokenKind, string];

const KEYWORDS: Record<Language, string[]> = {
  python: ['False', 'None', 'True', 'and', 'as', 'assert', 'async', 'await', 'break', 'class', 'continue', 'def', 'del', 'elif', 'else', 'except', 'finally', 'for', 'from', 'global', 'if', 'import', 'in', 'is', 'lambda', 'nonlocal', 'not', 'or', 'pass', 'raise', 'return', 'try', 'while', 'with', 'yield', 'print', 'open', 'exec', 'eval'],
  shell: ['if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'until', 'do', 'done', 'case', 'esac', 'in', 'function', 'return', 'export', 'local', 'readonly', 'set', 'unset', 'echo', 'printf', 'exec', 'eval', 'source', 'curl', 'wget', 'nc', 'cat', 'env'],
  javascript: ['async', 'await', 'break', 'case', 'catch', 'class', 'const', 'continue', 'default', 'delete', 'do', 'else', 'export', 'extends', 'false', 'finally', 'for', 'from', 'function', 'if', 'import', 'in', 'instanceof', 'let', 'new', 'null', 'of', 'return', 'switch', 'this', 'throw', 'true', 'try', 'typeof', 'undefined', 'var', 'void', 'while', 'yield', 'require', 'process', 'fetch', 'eval'],
  ruby: ['begin', 'class', 'def', 'do', 'else', 'elsif', 'end', 'ensure', 'false', 'for', 'if', 'in', 'module', 'nil', 'puts', 'print', 'require', 'rescue', 'return', 'self', 'then', 'true', 'unless', 'until', 'when', 'while', 'yield', 'ENV', 'eval', 'system'],
  perl: ['my', 'our', 'local', 'sub', 'if', 'elsif', 'else', 'unless', 'while', 'until', 'for', 'foreach', 'return', 'use', 'require', 'print', 'printf', 'open', 'close', 'eval', 'system', 'exec', 'die'],
  powershell: ['begin', 'break', 'catch', 'continue', 'do', 'else', 'elseif', 'end', 'exit', 'filter', 'finally', 'for', 'foreach', 'function', 'if', 'in', 'param', 'process', 'return', 'switch', 'throw', 'trap', 'try', 'until', 'while', 'Invoke-WebRequest', 'Invoke-RestMethod', 'Invoke-Expression', 'Write-Output', 'Write-Host', 'Set-Content', 'Out-File'],
  batch: ['echo', 'set', 'if', 'else', 'for', 'in', 'do', 'goto', 'call', 'exit', 'not', 'exist', 'defined', 'setlocal', 'endlocal', 'type', 'curl'],
  applescript: ['tell', 'end', 'set', 'to', 'if', 'then', 'else', 'repeat', 'return', 'on', 'do', 'shell', 'script', 'of', 'application', 'display', 'dialog'],
  text: [],
};

/** Invisible or reordering characters (bidi, zero-width, control): shown as visible escapes. */
const INVISIBLE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u;

interface Syntax {
  line: string[];
  block?: [string, string];
  quotes: string[];
  triple?: boolean;
}

const SYNTAX: Record<Language, Syntax> = {
  python: { line: ['#'], quotes: ['"', "'"], triple: true },
  shell: { line: ['#'], quotes: ['"', "'"] },
  javascript: { line: ['//'], block: ['/*', '*/'], quotes: ['"', "'", '`'] },
  ruby: { line: ['#'], quotes: ['"', "'"] },
  perl: { line: ['#'], quotes: ['"', "'"] },
  powershell: { line: ['#'], block: ['<#', '#>'], quotes: ['"', "'"] },
  batch: { line: ['REM ', 'rem ', '::'], quotes: ['"'] },
  applescript: { line: ['--', '#'], block: ['(*', '*)'], quotes: ['"'] },
  text: { line: [], quotes: [] },
};

function escapeChar(c: string): string {
  return `\\u{${c.codePointAt(0)!.toString(16).toUpperCase()}}`;
}

/** Splits text into tokens of `kind`, pulling out invisible characters as 'hidden'. */
function pushText(tokens: Token[], kind: TokenKind, text: string): void {
  let plain = '';
  for (const c of text) {
    if (c !== '\n' && c !== '\t' && INVISIBLE.test(c)) {
      if (plain) tokens.push([kind, plain]);
      plain = '';
      tokens.push(['hidden', escapeChar(c)]);
    } else plain += c;
  }
  if (plain) tokens.push([kind, plain]);
}

/**
 * A small, forgiving highlighter: comments, strings, numbers and keywords.
 * Its only job is readability; whatever it gets wrong, every character of the
 * code is still shown, and invisible ones are made visible.
 */
export function highlight(code: string, language: Language): Token[] {
  const syntax = SYNTAX[language];
  const keywords = new Set(KEYWORDS[language]);
  const tokens: Token[] = [];
  // CRLF reads the same as LF; a lone CR stays visible.
  const text = code.replace(/\r\n/g, '\n');
  let i = 0;
  let plain = '';
  const flush = () => {
    if (plain) pushText(tokens, 'plain', plain);
    plain = '';
  };
  while (i < text.length) {
    const rest = text.slice(i, i + 4);
    const lineComment = syntax.line.find((start) => text.startsWith(start, i));
    if (lineComment && (language !== 'shell' || i === 0 || /\s/.test(text[i - 1]!))) {
      const end = text.indexOf('\n', i);
      flush();
      pushText(tokens, 'comment', text.slice(i, end === -1 ? text.length : end));
      i = end === -1 ? text.length : end;
      continue;
    }
    if (syntax.block && text.startsWith(syntax.block[0], i)) {
      const end = text.indexOf(syntax.block[1], i + syntax.block[0].length);
      const stop = end === -1 ? text.length : end + syntax.block[1].length;
      flush();
      pushText(tokens, 'comment', text.slice(i, stop));
      i = stop;
      continue;
    }
    const quote = syntax.quotes.find((q) => text[i] === q);
    if (quote) {
      const triple = syntax.triple && rest.startsWith(quote.repeat(3)) ? quote.repeat(3) : '';
      const close = triple || quote;
      let j = i + close.length;
      while (j < text.length && !text.startsWith(close, j)) {
        if (text[j] === '\\' && !(quote === "'" && language === 'shell')) {
          j += 2;
          continue;
        }
        if (!triple && quote !== '`' && language !== 'shell' && text[j] === '\n') break;
        j++;
      }
      const stop = Math.min(text.length, j + (text.startsWith(close, j) ? close.length : 0));
      flush();
      pushText(tokens, 'string', text.slice(i, stop));
      i = stop;
      continue;
    }
    const word = /^[A-Za-z_][\w-]*/.exec(text.slice(i, i + 64));
    if (word && (i === 0 || !/[\w$]/.test(text[i - 1]!))) {
      // Shell, PowerShell and batch words may contain '-'; elsewhere stop at it.
      const value = language === 'powershell' || language === 'shell' || language === 'batch' ? word[0] : word[0].replace(/-.*$/, '');
      if (keywords.has(value) || (language === 'powershell' && keywords.has(value.toLowerCase()))) {
        flush();
        tokens.push(['keyword', value]);
      } else plain += value;
      i += value.length;
      continue;
    }
    const number = /^\d[\d_.xXa-fA-F]*/.exec(text.slice(i, i + 64));
    if (number && (i === 0 || !/[\w$]/.test(text[i - 1]!))) {
      flush();
      tokens.push(['number', number[0]]);
      i += number[0].length;
      continue;
    }
    plain += text[i];
    i++;
  }
  flush();
  return withLineNumbers(tokens);
}

/** Adds a line-number gutter, so wrapped or very long lines are easy to tell apart. */
function withLineNumbers(tokens: Token[]): Token[] {
  const lines = tokens.reduce((n, [, text]) => n + (text.match(/\n/g)?.length ?? 0), 0) + 1;
  const width = String(lines).length;
  const gutter = (n: number): Token => ['gutter', `${String(n).padStart(width)}  `];
  const out: Token[] = [gutter(1)];
  let line = 1;
  for (const [kind, text] of tokens) {
    const parts = text.split('\n');
    parts.forEach((part, index) => {
      if (index > 0) {
        out.push([kind === 'gutter' ? 'plain' : kind, '\n'], gutter(++line));
      }
      if (part) out.push([kind, part]);
    });
  }
  return out;
}

/** Warnings about a script that could hide something from a quick read. */
export function scriptWarnings(code: string): string[] {
  const warnings: string[] = [];
  if ([...code].some((c) => c !== '\n' && c !== '\t' && c !== '\r' && INVISIBLE.test(c)))
    warnings.push('The script contains invisible or reordering characters (shown in red). They can make code read differently from how it runs.');
  if (/[ \t]{80,}\S/.test(code)) warnings.push('The script has long runs of spaces or tabs that can push code out of view. Scroll to check.');
  return warnings;
}

export const lineCount = (code: string) => code.replace(/\r\n/g, '\n').split('\n').length;
