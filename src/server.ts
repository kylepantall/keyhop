import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { AccessGate, approverFor, clientLabel, platformDialog, type Dialog } from './approve.ts';
import { loadConfig, unlockMs } from './config.ts';
import { platformAuthenticator } from './auth.ts';
import { paths } from './paths.ts';
import { runWithSecrets } from './run.ts';
import { summarize, syncVault } from './secrets.ts';
import { PlanSession, SessionInput } from './session.ts';
import { VaultStore } from './store.ts';
import { testDialog, testSeamEnabled } from './testauth.ts';
import { VERSION } from './version.ts';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

async function respond(work: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return { content: [{ type: 'text', text: JSON.stringify(await work(), null, 2) }] };
  } catch (error) {
    return { content: [{ type: 'text', text: (error as Error).message }], isError: true };
  }
}

export function createServer(store: VaultStore, gate?: AccessGate, dialog?: Dialog): McpServer {
  const session = gate && dialog ? new PlanSession(store, gate, dialog) : undefined;
  const server = new McpServer(
    { name: 'keyhop', version: VERSION },
    {
      instructions:
        'keyhop holds API keys and passwords you can use but never read. Call list_secrets to see names and ' +
        'which commands each may be given to, then run_with_secrets to run one of those commands with the ' +
        'secrets as environment variables, on stdin, or as a {{file:NAME}} path. Output is redacted. Unlocking prompts the user for Touch ID or ' +
        'Windows Hello. Only the user can change which commands a secret may be used with: if a secret is ' +
        'not allowed for a program, keyhop may ask the user directly (a dialog plus Touch ID / Windows ' +
        'Hello) and the call waits for their answer. Do not retry a denied request.' +
        (session
          ? ' For a multi-step task, use open_session before any step is run. It shows the user the entire plan for one ' +
            'approval and biometric check. Then use run_session_step in order. Use VPNHop session_profile to prepare ' +
            'any vpn_http steps. Keep the session ID in this connection and close the session if the plan changes.'
          : ''),
    }
  );

  if (session) {
    server.server.onclose = () => { session.revoke(); };
    server.registerTool(
      'open_session',
      {
        title: 'Approve a Keyhop plan',
        description:
          'Shows all exact command and VPNHop HTTP steps for one local approval and biometric check. ' +
          'Does not run any step or return secret values. Use secret names and placeholders for credentials. ' +
          'For each vpn_http step, copy profileHash and secretNames from VPNHop session_profile.',
        inputSchema: SessionInput,
        annotations: { openWorldHint: false, destructiveHint: false },
      },
      (input, { signal }) =>
        respond(() => session.open(input, clientLabel(server.server.getClientVersion()?.name ?? ''), signal))
    );
    server.registerTool(
      'run_session_step',
      {
        title: 'Run the next approved step',
        description:
          'Runs one approved step exactly as shown. Use nextStep returned by open_session or the previous ' +
          'run_session_step. A step runs at most once. The session closes on failure or after the last step.',
        inputSchema: { sessionId: z.uuid(), step: z.number().int().positive() },
        annotations: { openWorldHint: true, destructiveHint: true },
      },
      ({ sessionId, step }, { signal }) => respond(() => session.run(sessionId, step, signal))
    );
    server.registerTool(
      'close_session',
      {
        title: 'Close a Keyhop plan session',
        description: 'Revokes remaining steps in this plan and cancels any running step.',
        inputSchema: { sessionId: z.uuid() },
        annotations: { openWorldHint: false, destructiveHint: false, idempotentHint: true },
      },
      ({ sessionId }) => respond(async () => ({ closed: session.revoke(sessionId) }))
    );
  }

  server.registerTool(
    'list_secrets',
    {
      title: 'List secrets',
      description:
        'Names of the secrets in the vault (never their values), where each came from, and the absolute ' +
        'executable paths each may be injected into. May prompt the user to unlock.',
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    () => respond(() => summarize(store))
  );

  server.registerTool(
    'run_with_secrets',
    {
      title: 'Run a command with secrets',
      description:
        'Runs a program directly (no shell, so $VARS in args are not expanded) and hands it secrets in one ' +
        'of four ways: as environment variables (secrets), on standard input (stdin, e.g. for ' +
        '`gh secret set`, `wrangler secret put`, `docker login --password-stdin`), as a file path ' +
        '({{file:NAME}} in an argument becomes the path of a named pipe that reads as the value, e.g. ' +
        '`ANTHROPIC_KEY=@{{file:ANTHROPIC_KEY}}`; nothing is written to disk), or inside an argument ' +
        '({{arg:NAME}}; prefer file or stdin). Each program is allowed per secret and per way (list_secrets ' +
        'shows both as allowedCommands[].as). Anything not yet allowed makes keyhop ask the user to deny, ' +
        'allow once or always allow, and the call waits for them; arg is never asked, only the user can ' +
        'grant it from their terminal. A {{file:NAME}} path can be read once, by this program only. Secret ' +
        'values and their common encodings are redacted from stdout/stderr.',
      inputSchema: {
        command: z.string().min(1).describe('Program name on PATH (gh) or absolute path. Not a shell.'),
        args: z
          .array(z.string())
          .default([])
          .describe('Arguments, passed as-is apart from {{file:NAME}} and {{arg:NAME}} placeholders.'),
        secrets: z.array(z.string()).default([]).describe('Secret names to set as environment variables.'),
        stdin: z.string().optional().describe('Secret name whose value is written to standard input.'),
        cwd: z.string().optional().describe('Absolute working directory; defaults to the server cwd.'),
        timeoutSeconds: z.number().int().min(1).max(600).optional().describe('Default 120.'),
        bypassGuard: z
          .boolean()
          .optional()
          .describe(
            'Only when the user explicitly asked to run a shell or interpreter (python3, node, bash …) with ' +
              'secrets. keyhop shows them a one-time bypass warning plus Touch ID / Windows Hello; nothing is ' +
              'remembered. Never set it on your own initiative, and never in place of a normal allowed command.'
          ),
        reason: z
          .string()
          .max(300)
          .optional()
          .describe(
            'One short sentence for the user on why this needs the secrets (e.g. "Upload the build to the ' +
              'staging bucket"). Shown, quoted as your words, if keyhop asks them to approve.'
          ),
      },
      annotations: { destructiveHint: true, openWorldHint: true },
    },
    // The client names itself when it connects; the dialog says who is asking.
    (input) => respond(() => runWithSecrets(store, input, { gate, client: clientLabel(server.server.getClientVersion()?.name ?? '') }))
  );

  server.registerTool(
    'sync_secrets',
    {
      title: 'Sync secrets',
      description:
        'Pulls secrets from the linked password tools and sync.d scripts into the vault. The user may see ' +
        'prompts from their password manager and Touch ID / Windows Hello.',
      inputSchema: {},
    },
    () => respond(() => syncVault(store))
  );

  server.registerTool(
    'lock_vault',
    {
      title: 'Lock vault',
      description: 'Forgets the unlocked vault key and closes any plan session on this connection.',
      inputSchema: {},
    },
    () =>
      respond(async () => {
        session?.revoke();
        store.lock();
        return { locked: true };
      })
  );

  return server;
}

export async function serve(): Promise<void> {
  const p = paths();
  const config = await loadConfig(p);
  const store = new VaultStore(p, platformAuthenticator(), unlockMs(config));
  const dialog = config.askForAccess === false ? null : testSeamEnabled() ? testDialog() : platformDialog();
  await createServer(store, dialog ? new AccessGate(approverFor(dialog)) : undefined, dialog ?? undefined)
    .connect(new StdioServerTransport());
}
