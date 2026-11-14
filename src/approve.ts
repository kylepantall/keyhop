/**
 * Asks the user, outside Claude, whether a command may use secrets it isn't
 * allowed for: a native dialog (Deny / Allow once / Always allow). The caller
 * then confirms an approval with Touch ID / Windows Hello, so clicking the
 * dialog alone is never enough.
 */

import { existsSync } from 'node:fs';
import { macHelperPath, windowsHelperPath } from './auth.ts';
import { commandName } from './policy.ts';
import { runProcess } from './process.ts';
import { highlight, lineCount, scriptWarnings, type Script, type Token } from './script.ts';
import type { Delivery } from './types.ts';

export type Decision = 'deny' | 'once' | 'always';

export interface AccessRequest {
  secrets: string[];
  /** How each secret would reach the program. */
  delivery?: Record<string, Delivery[]>;
  /** Resolved real path of the program. */
  executable: string;
  args: string[];
  cwd: string;
  /** A shell or interpreter the user is asked to let through for this one run. */
  bypass?: boolean;
  /** Who is asking, as `clientLabel` puts it ("Claude Code"). */
  client?: string;
  /** Why, in the client's own words. Shown quoted and inert. */
  reason?: string;
  /** Bypass only: the code it will run, if keyhop can tell; null when it can't. */
  script?: Script | null;
}

export type Approver<R = AccessRequest> = (request: R) => Promise<Decision>;

/**
 * A native dialog showing `message`. `grant`: Deny / Allow once / Always allow.
 * `confirm` and `bypass`: Deny / Allow, answered as 'deny' or 'once'. With a
 * `prompt`, the helper shows that richer layout instead (sections the user
 * can expand, and the script); `message` is the plain-text fallback.
 */
export type Dialog = (message: string, kind: 'grant' | 'confirm' | 'bypass', prompt?: Prompt) => Promise<Decision>;

/** What the rich dialog shows. Every string in it is fixed wording or already inert. */
export interface Prompt {
  title: string;
  headline: string;
  message: string;
  reason?: string;
  details: [label: string, value: string][];
  warnings: string[];
  secrets: [name: string, how: string][];
  script?: { label: string; tokens: Token[] };
  /** Shown in place of the script when keyhop can't tell what code runs. */
  noScript?: string;
  footer: string;
  buttons: 'grant' | 'once';
}

const DELIVERY_LABEL: Record<Delivery, string> = {
  env: 'environment variable',
  stdin: 'standard input',
  file: 'file (named pipe)',
  arg: 'argument, visible in the process list',
};

const MAX_ARGS_CHARS = 600;
const MAX_PATH_CHARS = 300;
const MAX_REASON_CHARS = 300;
const ANSWER_MS = 125_000;
/** The rich dialog waits longer: reading a script takes a while. */
const PROMPT_ANSWER_MS = 185_000;

/** MCP client names (from the client's own initialize message) keyhop knows how to say. */
const KNOWN_CLIENTS: Record<string, string> = {
  'claude-code': 'Claude Code',
  'claude-ai': 'Claude',
  claude: 'Claude',
  'claude-desktop': 'Claude',
  'Claude Desktop': 'Claude',
  'claude-cowork': 'Claude',
};

/**
 * Who to name in the dialog. A client names itself, so an unknown name is
 * shown as its claim, plainly, and only if it is short and ordinary text.
 * `undefined`: keyhop run, from a terminal.
 */
export function clientLabel(name: string | undefined): string {
  if (name === undefined) return 'A command in your terminal';
  if (KNOWN_CLIENTS[name]) return KNOWN_CLIENTS[name]!;
  if (/^[A-Za-z0-9][A-Za-z0-9 ._()-]{0,39}$/.test(name)) return `An app calling itself "${name}"`;
  return 'An MCP client';
}

/** Where package managers and the OS put programs; anything else gets a warning. */
const USUAL_PLACES = /^(\/usr\/|\/bin\/|\/sbin\/|\/opt\/homebrew\/|\/Applications\/|[A-Za-z]:\\(Program Files|Program Files \(x86\)|Windows)\\)/i;

/**
 * Shows text the model chose (paths, folder, arguments) inert: line breaks,
 * control, bidi and zero-width characters become visible \u escapes, so
 * nothing can draw its own "Program:" line or reorder what the user reads.
 */
export function inert(text: string, max: number): string {
  const escaped = text.replace(
    /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu,
    (c) => `\\u{${c.codePointAt(0)!.toString(16).toUpperCase()}}`
  );
  return escaped.length > max ? `${escaped.slice(0, max)}…` : escaped;
}

function argsText(request: AccessRequest): string {
  let args = request.args.map((arg) => inert(JSON.stringify(arg), MAX_ARGS_CHARS)).join(' ');
  if (args.length > MAX_ARGS_CHARS) args = `${args.slice(0, MAX_ARGS_CHARS)} … (${request.args.length} arguments)`;
  return args || '(none)';
}

function secretHow(request: AccessRequest, name: string): string {
  const how = request.delivery?.[name];
  return how?.length ? `as ${how.map((d) => DELIVERY_LABEL[d]).join(', ')}` : 'as environment variable';
}

/** The fixed wording both dialogs share. */
function wording(request: AccessRequest) {
  const client = request.client ?? 'Claude';
  const program = inert(commandName(request.executable), 60);
  const script = request.bypass ? request.script : undefined;
  const headline = !request.bypass
    ? `${client} would like to run ${program} with secrets it isn't allowed to use yet.`
    : script
      ? `${client} would like to run a script. It will have access to your secrets.`
      : `${client} would like to run ${program} with access to your secrets.`;
  const message = request.bypass
    ? `${program} is a shell or interpreter, which keyhop never gives secrets to. It can run any code, so it ` +
      'could print, save or send these secrets anywhere. Only allow it if you asked for this.'
    : 'Check the program and what it will be given before you allow it.';
  const reason = request.reason?.trim() ? inert(request.reason.trim(), MAX_REASON_CHARS) : undefined;
  const warnings: string[] = [];
  if (!USUAL_PLACES.test(request.executable))
    warnings.push('This program is not in a system or package-manager folder. Claude may have created it.');
  if (script) warnings.push(...scriptWarnings(script.code));
  const noScript =
    request.bypass && !script
      ? `keyhop can't tell exactly which code ${program} will run with these arguments. Check them, and deny if you're unsure.`
      : undefined;
  const footer = request.bypass
    ? '"Allow" runs this once. Nothing is remembered; the next run asks again.'
    : '"Always allow" lets this program use these secrets with any arguments.';
  return { client, headline, message, reason, warnings, noScript, footer, script };
}

function scriptLabel(script: Script): string {
  const lines = lineCount(script.code);
  const size = `${lines} line${lines === 1 ? '' : 's'}`;
  return script.kind === 'file'
    ? `"${inert(script.path!, MAX_PATH_CHARS)}" (${size}). This exact copy is what runs; it can still load other files.`
    : `Inline code from the arguments (${size}).`;
}

/** Plain-text dialog (the osascript fallback, and older helpers). Every field is quoted and made inert. */
export function describeRequest(request: AccessRequest): string {
  const words = wording(request);
  const lines = [
    request.bypass ? `⚠️ ONE-TIME BYPASS. ${words.headline}` : words.headline,
    '',
    words.message,
    '',
  ];
  if (words.reason) lines.push(`Why, in ${words.client}'s words: "${words.reason}"`, '');
  lines.push(
    `Secrets:  ${request.secrets
      .map((name) => (request.delivery?.[name]?.length ? `${name} (${secretHow(request, name)})` : name))
      .join(', ')}`,
    `Program:  "${inert(request.executable, MAX_PATH_CHARS)}"`,
    `Arguments:  ${argsText(request)}`,
    `Folder:  "${inert(request.cwd, MAX_PATH_CHARS)}"`,
    ''
  );
  if (words.script) lines.push(`Script:  ${scriptLabel(words.script)}`, '');
  if (words.noScript) lines.push(`⚠️ ${words.noScript}`, '');
  for (const warning of words.warnings) lines.push(`⚠️ ${warning}`, '');
  lines.push(words.footer);
  return lines.join('\n');
}

/** The rich dialog: the same facts, with the secrets and the script in sections the user can open. */
export function describePrompt(request: AccessRequest): Prompt {
  const words = wording(request);
  return {
    title: request.bypass ? 'keyhop: one-time bypass' : 'keyhop: allow access?',
    headline: words.headline,
    message: words.message,
    reason: words.reason && `Why, in ${words.client}'s words: "${words.reason}"`,
    details: [
      ['Program', `"${inert(request.executable, MAX_PATH_CHARS)}"`],
      ['Arguments', argsText(request)],
      ['Folder', `"${inert(request.cwd, MAX_PATH_CHARS)}"`],
    ],
    warnings: words.warnings,
    secrets: request.secrets.map((name) => [name, secretHow(request, name)]),
    script: words.script ? { label: scriptLabel(words.script), tokens: highlight(words.script.code, words.script.language) } : undefined,
    noScript: words.noScript,
    footer: words.footer,
    buttons: request.bypass ? 'once' : 'grant',
  };
}

const b64 = (text: string) => Buffer.from(text, 'utf8').toString('base64');

/**
 * The prompt as lines of tab-separated fields, every value base64 (UTF-8), so
 * both helpers can read it without a JSON parser and no text can break a line.
 */
export function encodePrompt(prompt: Prompt): string {
  const lines: string[][] = [
    ['title', b64(prompt.title)],
    ['headline', b64(prompt.headline)],
    ['message', b64(prompt.message)],
    ['buttons', prompt.buttons],
    ['footer', b64(prompt.footer)],
  ];
  if (prompt.reason) lines.push(['reason', b64(prompt.reason)]);
  for (const [label, value] of prompt.details) lines.push(['detail', b64(label), b64(value)]);
  for (const warning of prompt.warnings) lines.push(['warning', b64(warning)]);
  for (const [name, how] of prompt.secrets) lines.push(['secret', b64(name), b64(how)]);
  if (prompt.noScript) lines.push(['noscript', b64(prompt.noScript)]);
  if (prompt.script) {
    lines.push(['scriptlabel', b64(prompt.script.label)]);
    for (const [kind, text] of prompt.script.tokens) lines.push(['token', kind, b64(text)]);
  }
  return lines.map((fields) => fields.join('\t')).join('\n') + '\n';
}

const macScript = (title: string, buttons: string) => [
  'on run argv',
  `set answer to display dialog (item 1 of argv) with title "${title}" ` +
    `buttons ${buttons} default button "Deny" cancel button "Deny" ` +
    'with icon caution giving up after 120',
  'if gave up of answer then return "Deny"',
  'return button returned of answer',
  'end run',
];

const MAC_SCRIPTS = {
  grant: macScript('keyhop: allow access?', '{"Deny", "Allow once", "Always allow"}'),
  confirm: macScript('keyhop: confirm', '{"Deny", "Allow"}'),
  bypass: macScript('keyhop: one-time bypass', '{"Deny", "Allow"}'),
};

const MAC_ANSWERS: Record<string, Decision> = { 'Allow once': 'once', 'Always allow': 'always', Allow: 'once' };

function answerOf(kind: 'grant' | 'confirm' | 'bypass', answer: Decision): Decision {
  return kind === 'grant' || answer === 'deny' ? answer : 'once';
}

/** Native dialog for this platform; null where there is none. */
export function platformDialog(): Dialog | null {
  if (process.platform === 'darwin') {
    const osascript = async (message: string, kind: 'grant' | 'confirm' | 'bypass'): Promise<Decision> => {
      // The message is an argument, never part of the script.
      const result = await runProcess(
        '/usr/bin/osascript',
        [...MAC_SCRIPTS[kind].flatMap((line) => ['-e', line]), message],
        { timeoutMs: ANSWER_MS }
      );
      return answerOf(kind, (result.code === 0 && MAC_ANSWERS[result.stdout.trim()]) || 'deny');
    };
    return async (message, kind, prompt) => {
      if (!prompt || !existsSync(macHelperPath)) return osascript(message, kind);
      const result = await runProcess(macHelperPath, ['ask'], { input: encodePrompt(prompt), timeoutMs: PROMPT_ANSWER_MS });
      // A helper built before `ask` existed: fall back to the plain dialog.
      if (result.code === 1 && /Unknown command/.test(result.stderr)) return osascript(message, kind);
      const answer = result.stdout.trim();
      if (result.code !== 0 || (answer !== 'once' && answer !== 'always')) return 'deny';
      return answerOf(kind, answer);
    };
  }
  if (process.platform === 'win32')
    return async (message, kind, prompt) => {
      // Older helpers ignore --once and show all three buttons; the answer is still read as once.
      // They also ignore --prompt and show KEYHOP_ASK_MESSAGE as before.
      const args = ['ask', ...(kind === 'grant' ? [] : ['--once']), ...(prompt ? ['--prompt'] : [])];
      const result = await runProcess(windowsHelperPath, args, {
        timeoutMs: prompt ? PROMPT_ANSWER_MS : ANSWER_MS,
        input: prompt ? encodePrompt(prompt) : undefined,
        env: { ...process.env, KEYHOP_ASK_MESSAGE: message },
      });
      const answer = result.stdout.trim();
      if (result.code !== 0 || (answer !== 'once' && answer !== 'always')) return 'deny';
      return answerOf(kind, answer);
    };
  return null;
}

/** Shows an access request in `dialog`: the rich layout where the helper has one, text otherwise. */
export function approverFor(dialog: Dialog): Approver {
  return (request) => dialog(describeRequest(request), request.bypass ? 'bypass' : 'grant', describePrompt(request));
}

/** The access-request dialog for run_with_secrets; null where there is none. */
export function platformApprover(): Approver | null {
  const dialog = platformDialog();
  return dialog && approverFor(dialog);
}

const BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 15 * 60_000;

/**
 * One request at a time, and after any deny no request (for any secret or
 * program) can ask for a while: 30 s, doubling per deny up to 15 min, reset
 * by an approval. So Claude can't wear the user down with prompts.
 */
export class AccessGate<R = AccessRequest> {
  private pending = false;
  private strikes = 0;
  private blockedUntil = 0;

  constructor(
    private readonly approver: Approver<R>,
    private readonly now: () => number = Date.now
  ) {}

  /**
   * Shows the dialog, then runs `confirm` (the biometric prompt) for an
   * approval. A cancelled confirm counts as a deny.
   */
  async ask(request: R, confirm: () => Promise<void>): Promise<Decision | 'busy' | 'cooling'> {
    if (this.now() < this.blockedUntil) return 'cooling';
    if (this.pending) return 'busy';
    this.pending = true;
    try {
      const decision = await this.approver(request).catch((): Decision => 'deny');
      if (decision !== 'deny') {
        try {
          await confirm();
          this.strikes = 0;
          return decision;
        } catch {
          // Cancelled or failed Touch ID / Hello.
        }
      }
      this.blockedUntil = this.now() + Math.min(BACKOFF_MS * 2 ** this.strikes++, MAX_BACKOFF_MS);
      return 'deny';
    } finally {
      this.pending = false;
    }
  }
}
