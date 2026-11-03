import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { AccessGate, platformApprover } from './approve.ts';
import { loadConfig, unlockMs } from './config.ts';
import { platformAuthenticator } from './auth.ts';
import { paths } from './paths.ts';
import { runWithSecrets } from './run.ts';
import { summarize, syncVault } from './secrets.ts';
import { VaultStore } from './store.ts';
import { VERSION } from './version.ts';

type ToolResult = { content: { type: 'text'; text: string }[]; isError?: boolean };

async function respond(work: () => Promise<unknown>): Promise<ToolResult> {
  try {
    return { content: [{ type: 'text', text: JSON.stringify(await work(), null, 2) }] };
  } catch (error) {
    return { content: [{ type: 'text', text: (error as Error).message }], isError: true };
  }
}

export function createServer(store: VaultStore, gate?: AccessGate): McpServer {
  const server = new McpServer(
    { name: 'keyhop', version: VERSION },
    {
      instructions:
        'keyhop holds API keys and passwords you can use but never read. Call list_secrets to see names and ' +
        'which commands each may be given to, then run_with_secrets to run one of those commands with the ' +
        'secrets as environment variables. Output is redacted. Unlocking prompts the user for Touch ID or ' +
        'Windows Hello. Only the user can change which commands a secret may be used with: if a secret is ' +
        'not allowed for a program, keyhop may ask the user directly (a dialog plus Touch ID / Windows ' +
        'Hello) and the call waits for their answer. Do not retry a denied request.',
    }
  );

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
        'Runs a program directly (no shell, so $VARS in args are not expanded) with the named secrets set ' +
        'as environment variables. A secret not allowed for this program (see list_secrets) makes keyhop ' +
        'ask the user to deny, allow once or always allow; the call waits for them. Secret values and ' +
        'their common encodings are redacted from stdout/stderr.',
      inputSchema: {
        command: z.string().min(1).describe('Program name on PATH (gh) or absolute path. Not a shell.'),
        args: z.array(z.string()).default([]).describe('Arguments, passed as-is.'),
        secrets: z.array(z.string()).min(1).describe('Secret names to set as environment variables.'),
        cwd: z.string().optional().describe('Absolute working directory; defaults to the server cwd.'),
        timeoutSeconds: z.number().int().min(1).max(600).optional().describe('Default 120.'),
      },
      annotations: { destructiveHint: true, openWorldHint: true },
    },
    (input) => respond(() => runWithSecrets(store, input, { gate }))
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
      description: 'Forgets the unlocked vault key; the next use prompts the user again.',
      inputSchema: {},
    },
    () =>
      respond(async () => {
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
  const approver = config.askForAccess === false ? null : platformApprover();
  await createServer(store, approver ? new AccessGate(approver) : undefined).connect(new StdioServerTransport());
}
