import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import { inert, isSystemExecutable, type AccessGate, type Dialog, type Prompt } from './approve.ts';
import { samePin } from './clients.ts';
import { assertName, NAME_PATTERN } from './config.ts';
import { GuardedProgramError, pinExecutable, resolveExecutable } from './policy.ts';
import { deliveries, realDirectory, runApprovedCommand, type RunRequest } from './run.ts';
import { findScript, type Script } from './script.ts';
import { prepareVpnStep, runVpnStep, vpnClient, VpnStep } from './session-vpn.ts';
import type { VaultLease, VaultStore } from './store.ts';
import type { AllowedExecutable, SuiteClient, VaultData } from './types.ts';

const MAX_STEPS = 8;
const MAX_REVIEW_BYTES = 24 << 10;
const SESSION_MS = 10 * 60_000;
const secretName = z.string().max(128).regex(NAME_PATTERN);

const CommandStep = z.strictObject({
  kind: z.literal('command'),
  command: z.string().min(1).max(4096),
  args: z.array(z.string().max(8192)).max(64).default([]),
  secrets: z.array(secretName).max(16).default([]),
  stdin: secretName.optional(),
  cwd: z.string().max(4096).optional(),
  timeoutSeconds: z.number().int().min(1).max(600).default(120),
  bypassGuard: z.boolean().optional().describe('Only if explicitly requested by the user. The script itself must be inspectable.'),
});

export const SessionInput = {
  purpose: z.string().trim().min(1).max(300).describe('Why this exact plan needs access, shown to the user.'),
  steps: z.array(z.discriminatedUnion('kind', [CommandStep, VpnStep])).min(1).max(MAX_STEPS),
};

const SessionPlan = z.strictObject(SessionInput);
type SessionPlan = z.infer<typeof SessionPlan>;
type PreparedCommand = {
  kind: 'command';
  request: RunRequest;
  program: AllowedExecutable;
  cwd: string;
  script: Script | null;
};
type PreparedStep = PreparedCommand | VpnStep;

async function prepareStep(step: SessionPlan['steps'][number]): Promise<PreparedStep> {
  if (step.kind === 'vpn_http') return prepareVpnStep(step);
  const { kind, ...request } = step;
  const uses = deliveries(request);
  if (!uses.size) throw new Error('A command step must name at least one secret.');
  for (const [name, modes] of uses) {
    assertName(name);
    if (modes.has('arg')) throw new Error('Session plans use environment variables, stdin, or {{file:NAME}} for secrets.');
  }

  const cwd = realDirectory(request.cwd);
  const path = resolveExecutable(request.command);
  let program: AllowedExecutable;
  let script: Script | null = null;
  try {
    program = await pinExecutable(path);
  } catch (error) {
    if (!(error instanceof GuardedProgramError) || !request.bypassGuard) throw error;
    program = await pinExecutable(path, { bypass: true });
    script = findScript(program.realPath, request.args, cwd);
    if (!script) throw new Error('Keyhop could not identify the code for this script step. Use an inspectable script file or inline script.');
  }
  return { kind, request, program, cwd, script };
}

function namesOf(step: PreparedStep): Iterable<string> {
  return step.kind === 'vpn_http' ? step.secretNames : deliveries(step.request).keys();
}

function reviewOf(steps: PreparedStep[], purpose: string, client: string): Prompt {
  const lines = steps.map((step, index) => {
    const heading = `Step ${index + 1} · `;
    if (step.kind === 'vpn_http') {
      const { kind: _kind, ...request } = step;
      const fields = JSON.stringify(request, null, 2).split('\n').map((line) => inert(line, Infinity));
      return heading + 'VPNHop HTTP request\n' + fields.join('\n');
    }
    const { request, program, cwd, script } = step;
    const fields = [
      `Program: ${JSON.stringify(program.realPath)}`,
      `Arguments: ${JSON.stringify(request.args)}`,
      `Folder: ${JSON.stringify(cwd)}`,
      `Timeout: ${request.timeoutSeconds} seconds`,
      ...Array.from(deliveries(request), ([name, modes]) => `Secret: ${name} (${[...modes].join(', ')})`),
    ];
    if (!isSystemExecutable(program.realPath)) fields.push('This program is outside a system or package-manager folder.');
    if (script) {
      fields.push('One-time script bypass. This code can read, save or send its secrets.', 'Reviewed script:');
      fields.push(...script.code.split('\n').map((line) => '  | ' + line));
    }
    return heading + (script ? 'Script with secrets' : 'Command with secrets') +
      '\n' + fields.map((line) => inert(line, Infinity)).join('\n');
  }).join('\n\n');
  if (Buffer.byteLength(lines) > MAX_REVIEW_BYTES) throw new Error('The plan is too large to review. Submit fewer or shorter steps.');
  return {
    title: 'Keyhop plan approval',
    headline: `${client} requests a session for ${steps.length} ${steps.length === 1 ? 'step' : 'steps'}.`,
    message: 'Review each operation, its arguments or destination, and the secrets it can use.',
    reason: `Purpose: ${inert(JSON.stringify(purpose), 2400)}`,
    details: [],
    warnings: [],
    secrets: [],
    plan: lines,
    footer: 'Allow to run these steps in order. Biometric vaults ask you to authenticate once. This session expires in 10 minutes.',
    buttons: 'once',
  };
}

type ActiveSession = {
  id: string;
  expiresAt: number;
  steps: PreparedStep[];
  secrets: Map<string, { origin: string; updatedAt: string }>;
  lease: VaultLease;
  vpn?: SuiteClient;
  stop: AbortController;
  timer: ReturnType<typeof setTimeout>;
  next: number;
  running: boolean;
};

export class PlanSession {
  private active?: ActiveSession;
  private opening = false;
  private revision = 0;

  constructor(
    private readonly store: VaultStore,
    private readonly gate: AccessGate,
    private readonly dialog: Dialog
  ) {}

  async open(input: unknown, client: string, signal: AbortSignal) {
    if (this.active) throw new Error('A plan session is already open. Complete it or call close_session first.');
    if (!this.store.initialized) throw new Error('No vault yet. Run: keyhop setup');
    const { purpose, steps: requested } = SessionPlan.parse(input);
    const revision = this.revision;
    const steps = await Promise.all(requested.map(prepareStep));
    const prompt = reviewOf(steps, purpose, client);
    const check = () => {
      signal.throwIfAborted();
      if (this.revision !== revision) throw new Error('The vault was locked while the plan was awaiting approval.');
      if (this.active) throw new Error('A plan session is already open.');
    };
    check();
    if (this.opening) throw new Error('Another plan is waiting for the user.');
    this.opening = true;
    let lease: VaultLease | undefined;
    try {
      const decision = await this.gate.askDialog(() => this.dialog('', 'plan', prompt), async () => {
        check();
        lease = await this.store.lease();
      });
      if (decision === 'busy') throw new Error('Another access request is waiting for the user.');
      if (decision === 'cooling') throw new Error('The user recently denied access. Wait before requesting another plan.');
      if (!lease) throw new Error('The user denied the plan or authentication was cancelled.');
      const vault = await lease.read();
      const names = new Set(steps.flatMap((step) => [...namesOf(step)]));
      const secrets = new Map<string, { origin: string; updatedAt: string }>();
      for (const name of names) {
        if (!Object.hasOwn(vault.secrets, name)) throw new Error(`Unknown secret: ${name}`);
        const { origin, updatedAt } = vault.secrets[name]!;
        secrets.set(name, { origin, updatedAt });
      }
      const vpn = steps.some((step) => step.kind === 'vpn_http') ? vpnClient(vault) : undefined;
      check();

      const id = randomUUID();
      const expiresAt = Date.now() + SESSION_MS;
      const timer = setTimeout(() => this.revoke(id), SESSION_MS);
      timer.unref?.();
      this.active = { id, expiresAt, steps, secrets, lease, vpn, timer, next: 0, running: false, stop: new AbortController() };
      lease = undefined;
      return { sessionId: id, expiresAt: new Date(expiresAt).toISOString(), steps: steps.length, nextStep: 1 };
    } finally {
      lease?.close();
      this.opening = false;
    }
  }

  async run(id: string, stepNumber: number, signal: AbortSignal) {
    const session = this.active;
    if (!session || session.id !== id) throw new Error('This plan session is closed, expired or belongs to a different connection.');
    if (Date.now() >= session.expiresAt) {
      this.revoke(id);
      throw new Error('The plan session expired.');
    }
    if (session.running) throw new Error('A step is already running in this session.');
    if (stepNumber !== session.next + 1) throw new Error(`The next approved step is ${session.next + 1}.`);

    const step = session.steps[session.next++]!;
    session.running = true;
    const running = AbortSignal.any([signal, session.stop.signal]);
    const readVault = async () => {
      running.throwIfAborted();
      const vault = await session.lease.read();
      for (const name of namesOf(step)) {
        const current = Object.hasOwn(vault.secrets, name) ? vault.secrets[name] : undefined;
        const approved = session.secrets.get(name)!;
        if (current?.origin !== approved.origin || current.updatedAt !== approved.updatedAt)
          throw new Error(`Secret ${name} changed after plan approval.`);
      }
      return vault;
    };
    try {
      let result: unknown;
      let succeeded: boolean;
      if (step.kind === 'command') {
        const command = await runApprovedCommand(readVault, step.request, step.program, step.cwd, step.script, running);
        result = command;
        succeeded = command.exitCode === 0 && !command.timedOut;
      } else {
        const vault: VaultData = await readVault();
        const pin = vpnClient(vault);
        if (!session.vpn || !samePin(session.vpn, pin)) throw new Error('The approved VPNHop registration changed.');
        const response = await runVpnStep(step, pin, vault, running);
        result = response;
        succeeded = response.status < 400;
      }
      running.throwIfAborted();
      const closed = !succeeded || session.next === session.steps.length;
      if (closed) this.revoke(id);
      return { step: stepNumber, succeeded, closed, nextStep: closed ? null : session.next + 1, result };
    } catch (error) {
      this.revoke(id);
      throw error;
    } finally {
      session.running = false;
    }
  }

  revoke(id?: string): boolean {
    if (id === undefined) this.revision++;
    const session = this.active;
    if (!session || (id !== undefined && id !== session.id)) return false;
    this.active = undefined;
    clearTimeout(session.timer);
    session.lease.close();
    session.stop.abort(new Error('The plan session closed.'));
    return true;
  }
}
