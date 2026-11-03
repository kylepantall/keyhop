/**
 * Asks the user, outside Claude, whether a command may use secrets it isn't
 * allowed for: a native dialog (Deny / Allow once / Always allow). The caller
 * then confirms an approval with Touch ID / Windows Hello, so clicking the
 * dialog alone is never enough.
 */

import { windowsHelperPath } from './auth.ts';
import { runProcess } from './process.ts';

export type Decision = 'deny' | 'once' | 'always';

export interface AccessRequest {
  secrets: string[];
  /** Resolved real path of the program. */
  executable: string;
  args: string[];
  cwd: string;
}

export type Approver = (request: AccessRequest) => Promise<Decision>;

const MAX_ARGS_CHARS = 600;
const MAX_PATH_CHARS = 300;
const ANSWER_MS = 125_000;

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

/** Dialog text. Every field is quoted and made inert. */
export function describeRequest(request: AccessRequest): string {
  let args = request.args.map((arg) => inert(JSON.stringify(arg), MAX_ARGS_CHARS)).join(' ');
  if (args.length > MAX_ARGS_CHARS) args = `${args.slice(0, MAX_ARGS_CHARS)} … (${request.args.length} arguments)`;
  const lines = [
    'Claude wants to run a command with secrets it is not allowed to use:',
    '',
    `Secrets:  ${request.secrets.join(', ')}`,
    `Program:  "${inert(request.executable, MAX_PATH_CHARS)}"`,
    `Arguments:  ${args || '(none)'}`,
    `Folder:  "${inert(request.cwd, MAX_PATH_CHARS)}"`,
    '',
  ];
  if (!USUAL_PLACES.test(request.executable))
    lines.push('⚠️ This program is not in a system or package-manager folder. Claude may have created it.', '');
  lines.push('"Always allow" lets this program use these secrets with any arguments.');
  return lines.join('\n');
}

const MAC_SCRIPT = [
  'on run argv',
  'set answer to display dialog (item 1 of argv) with title "keyhop: allow access?" ' +
    'buttons {"Deny", "Allow once", "Always allow"} default button "Deny" cancel button "Deny" ' +
    'with icon caution giving up after 120',
  'if gave up of answer then return "Deny"',
  'return button returned of answer',
  'end run',
];

const MAC_ANSWERS: Record<string, Decision> = { 'Allow once': 'once', 'Always allow': 'always' };

/** Native dialog for this platform; null where there is none. */
export function platformApprover(): Approver | null {
  if (process.platform === 'darwin')
    return async (request) => {
      // The message is an argument, never part of the script.
      const result = await runProcess(
        '/usr/bin/osascript',
        [...MAC_SCRIPT.flatMap((line) => ['-e', line]), describeRequest(request)],
        { timeoutMs: ANSWER_MS }
      );
      return (result.code === 0 && MAC_ANSWERS[result.stdout.trim()]) || 'deny';
    };
  if (process.platform === 'win32')
    return async (request) => {
      const result = await runProcess(windowsHelperPath, ['ask'], {
        timeoutMs: ANSWER_MS,
        env: { ...process.env, KEYHOP_ASK_MESSAGE: describeRequest(request) },
      });
      const answer = result.stdout.trim();
      return result.code === 0 && (answer === 'once' || answer === 'always') ? answer : 'deny';
    };
  return null;
}

const BACKOFF_MS = 30_000;
const MAX_BACKOFF_MS = 15 * 60_000;

/**
 * One request at a time, and after any deny no request (for any secret or
 * program) can ask for a while: 30 s, doubling per deny up to 15 min, reset
 * by an approval. So Claude can't wear the user down with prompts.
 */
export class AccessGate {
  private pending = false;
  private strikes = 0;
  private blockedUntil = 0;

  constructor(
    private readonly approver: Approver,
    private readonly now: () => number = Date.now
  ) {}

  /**
   * Shows the dialog, then runs `confirm` (the biometric prompt) for an
   * approval. A cancelled confirm counts as a deny.
   */
  async ask(request: AccessRequest, confirm: () => Promise<void>): Promise<Decision | 'busy' | 'cooling'> {
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
