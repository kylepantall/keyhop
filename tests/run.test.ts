import { afterEach, describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { chmod, mkdir, rm, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { assertAllowable, findAllowed, resolveExecutable } from '../src/policy.ts';
import { redactor } from '../src/redact.ts';
import { runWithSecrets } from '../src/run.ts';
import { changeAllowed, syncVault } from '../src/secrets.ts';
import { createServer } from '../src/server.ts';
import { newStore, tempHome } from './support.ts';

const unix = process.platform !== 'win32';
const SECRET = 'tok_live_9f8e7d6c5b4a';

describe('redactor', () => {
  const redact = redactor({ TOKEN: SECRET, SHORT: 'abc' });

  test('redacts the value and common encodings', () => {
    const bytes = Buffer.from(SECRET);
    for (const form of [SECRET, bytes.toString('base64'), bytes.toString('hex'), encodeURIComponent(SECRET)])
      expect(redact(`x ${form} y`)).toBe('x [REDACTED:TOKEN] y');
  });

  test('leaves very short values alone', () => {
    expect(redact('abc')).toBe('abc');
  });
});

describe('policy', () => {
  test('refuses shells and interpreters', () => {
    for (const name of ['/bin/bash', '/usr/bin/env', '/usr/local/bin/node', 'C:\\Windows\\System32\\cmd.exe'])
      expect(() => assertAllowable(name)).toThrow();
    expect(() => assertAllowable('/opt/homebrew/bin/gh')).not.toThrow();
  });

  test('rejects relative paths', () => {
    expect(() => resolveExecutable('./gh')).toThrow();
    expect(() => resolveExecutable('bin/gh')).toThrow();
  });

  test('refuses versioned interpreters', () => {
    for (const name of ['/usr/bin/python3.12', '/usr/bin/perl5.34', '/usr/bin/tclsh8.6', '/usr/bin/m4'])
      expect(() => assertAllowable(name)).toThrow();
  });

  test('matches exact paths only', () => {
    const entry = { path: '/usr/bin/gh', realPath: '/usr/bin/gh', sha256: 'x' };
    expect(findAllowed({ allow: [entry] }, '/usr/bin/gh')).toBe(entry);
    expect(findAllowed({ allow: [entry] }, '/tmp/gh')).toBeUndefined();
    expect(findAllowed(undefined, '/usr/bin/gh')).toBeUndefined();
  });

  test.if(unix)('judges a symlink by what it points at', async () => {
    const home = await tempHome();
    try {
      const link = join(home.p.dir, 'gh');
      await mkdir(home.p.dir, { recursive: true });
      await symlink('/bin/sh', link);
      expect(() => assertAllowable(link)).toThrow();
    } finally {
      await home.cleanup();
    }
  });
});

describe.if(unix)('run_with_secrets', () => {
  let cleanup: () => Promise<void> = async () => {};
  afterEach(() => cleanup());

  async function setup() {
    const home = await tempHome();
    cleanup = home.cleanup;
    const p = home.p;
    await mkdir(p.syncDir, { recursive: true });
    await writeFile(join(p.syncDir, '10-a.mjs'), `console.log("TOKEN=${SECRET}\\nOTHER=other-secret-1")`);
    const tool = join(p.dir, 'show-token');
    await writeFile(tool, '#!/bin/sh\necho "token=$TOKEN other=${OTHER:-unset} arg=$1"\n');
    await chmod(tool, 0o755);
    const store = await newStore(p);
    await syncVault(store);
    return { p, store, tool };
  }

  test('refuses a secret that does not allow the command', async () => {
    const { store, tool } = await setup();
    expect(runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] })).rejects.toThrow(/keyhop allow TOKEN/);
  });

  test('refuses unknown secrets', async () => {
    const { store, tool } = await setup();
    expect(runWithSecrets(store, { command: tool, args: [], secrets: ['NOPE'] })).rejects.toThrow(/NOPE/);
  });

  test('injects only the named secrets, without a shell, and redacts output', async () => {
    const { store, tool } = await setup();
    await changeAllowed(store, { TOKEN: { add: [tool] } });
    process.env.OTHER = 'ambient';
    try {
      const result = await runWithSecrets(store, { command: tool, args: ['$TOKEN'], secrets: ['TOKEN'] });
      expect(result.exitCode).toBe(0);
      expect(result.stdout).not.toContain(SECRET);
      expect(result.stdout).toContain('[REDACTED:TOKEN]');
      // Not injected, and the ambient value of a vault name is dropped.
      expect(result.stdout).toContain('other=unset');
      // No shell: the argument is passed literally.
      expect(result.stdout).toContain('arg=$TOKEN');
    } finally {
      delete process.env.OTHER;
    }
  });

  test('refuses an allowed executable whose contents changed', async () => {
    const { store, tool } = await setup();
    await changeAllowed(store, { TOKEN: { add: [tool] } });
    await writeFile(tool, '#!/bin/sh\nprintenv TOKEN | rev\n');
    expect(runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] })).rejects.toThrow(/changed/);
  });

  test('refuses an allowed path swapped for a symlink to a shell', async () => {
    const { store, tool } = await setup();
    await changeAllowed(store, { TOKEN: { add: [tool] } });
    await rm(tool);
    await symlink('/bin/sh', tool);
    expect(runWithSecrets(store, { command: tool, args: ['-c', 'echo $TOKEN'], secrets: ['TOKEN'] })).rejects.toThrow();
  });

  test('kills leftover child processes when the command exits', async () => {
    const { p, store } = await setup();
    const marker = join(p.dir, 'late');
    const tool = join(p.dir, 'spawner');
    await writeFile(tool, `#!/bin/sh\n(sleep 1; touch "${marker}") &\necho started\n`);
    await chmod(tool, 0o755);
    await changeAllowed(store, { TOKEN: { add: [tool] } });
    const result = await runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] });
    expect(result.stdout).toContain('started');
    await Bun.sleep(1500);
    expect(existsSync(marker)).toBe(false);
  });

  test('MCP tools never return secret values', async () => {
    const { store, tool } = await setup();
    await changeAllowed(store, { TOKEN: { add: [tool] } });
    const [clientSide, serverSide] = InMemoryTransport.createLinkedPair();
    const server = createServer(store);
    await server.connect(serverSide);
    const client = new Client({ name: 'test', version: '1' });
    await client.connect(clientSide);
    const tools = await client.listTools();
    expect(tools.tools.map((t) => t.name).sort()).toEqual(['list_secrets', 'lock_vault', 'run_with_secrets', 'sync_secrets']);
    const responses = [
      await client.callTool({ name: 'list_secrets', arguments: {} }),
      await client.callTool({ name: 'run_with_secrets', arguments: { command: tool, secrets: ['TOKEN'] } }),
      await client.callTool({ name: 'sync_secrets', arguments: {} }),
    ];
    for (const response of responses) {
      expect(response.isError).toBeFalsy();
      const text = JSON.stringify(response);
      expect(text).not.toContain(SECRET);
      expect(text).not.toContain('other-secret-1');
    }
    await client.close();
  });
});
