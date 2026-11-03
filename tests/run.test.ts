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
import { AccessGate, describeRequest, type AccessRequest, type Decision } from '../src/approve.ts';
import { VaultStore } from '../src/store.ts';
import { fakeAuth, newStore, tempHome } from './support.ts';

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

  describe('asking the user', () => {
    const gateFor = (decision: Decision) => {
      const asked: AccessRequest[] = [];
      let now = 0;
      const gate = new AccessGate(async (request) => {
        asked.push(request);
        return decision;
      }, () => now);
      return { gate, asked, advance: (ms: number) => (now += ms) };
    };

    test('allow once runs after Touch ID and saves no rule', async () => {
      const { store, tool, p } = await setup();
      const auth = fakeAuth();
      const fresh = new VaultStore(p, auth, 0);
      const { gate, asked } = gateFor('once');
      const result = await runWithSecrets(fresh, { command: tool, args: ['x'], secrets: ['TOKEN'] }, { gate });
      expect(result.exitCode).toBe(0);
      expect(asked).toHaveLength(1);
      expect(asked[0]!.secrets).toEqual(['TOKEN']);
      expect(auth.prompts).toContain('grant');
      expect(runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] })).rejects.toThrow();
    });

    test('always allow saves a rule bound to the secret', async () => {
      const { store, tool } = await setup();
      const { gate } = gateFor('always');
      await runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] }, { gate });
      const again = await runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] });
      expect(again.exitCode).toBe(0);
    });

    test('cancelling Touch ID denies, and the same request cools down', async () => {
      const { p, tool } = await setup();
      const auth = fakeAuth();
      const fresh = new VaultStore(p, auth, 0);
      await fresh.read();
      const { gate, asked, advance } = gateFor('once');
      auth.cancelNext = true;
      const request = { command: tool, args: [], secrets: ['TOKEN'] };
      expect(runWithSecrets(fresh, request, { gate })).rejects.toThrow();
      await Bun.sleep(10);
      expect(runWithSecrets(fresh, request, { gate })).rejects.toThrow();
      await Bun.sleep(10);
      expect(asked).toHaveLength(1);
      advance(121_000);
      expect((await runWithSecrets(fresh, request, { gate })).exitCode).toBe(0);
      expect(asked).toHaveLength(2);
    });

    test('a deny never runs the command', async () => {
      const { store, tool, p } = await setup();
      const marker = join(p.dir, 'ran');
      await writeFile(tool, `#!/bin/sh\ntouch ${marker}\n`);
      const { gate } = gateFor('deny');
      expect(runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] }, { gate })).rejects.toThrow();
      await Bun.sleep(50);
      expect(existsSync(marker)).toBe(false);
    });

    test('shells are refused without asking', async () => {
      const { store } = await setup();
      const { gate, asked } = gateFor('always');
      expect(runWithSecrets(store, { command: '/bin/sh', args: ['-c', 'env'], secrets: ['TOKEN'] }, { gate })).rejects.toThrow();
      await Bun.sleep(10);
      expect(asked).toHaveLength(0);
    });

    test('a second request while one is open is refused', async () => {
      const { store, tool } = await setup();
      let release: (d: Decision) => void = () => {};
      const gate = new AccessGate(() => new Promise<Decision>((resolve) => (release = resolve)));
      const first = runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] }, { gate });
      await Bun.sleep(20);
      expect(runWithSecrets(store, { command: tool, args: [], secrets: ['TOKEN'] }, { gate })).rejects.toThrow();
      release('deny');
      expect(first).rejects.toThrow();
    });

    test('after a deny, any other secret or program also waits, and the wait doubles', async () => {
      const { gate, asked, advance } = gateFor('deny');
      const confirm = async () => {};
      const request = (executable: string): AccessRequest => ({ secrets: ['A'], executable, args: [], cwd: '/' });
      expect(await gate.ask(request('/a'), confirm)).toBe('deny');
      expect(await gate.ask(request('/b'), confirm)).toBe('cooling');
      advance(31_000);
      expect(await gate.ask(request('/b'), confirm)).toBe('deny');
      advance(31_000);
      expect(await gate.ask(request('/c'), confirm)).toBe('cooling');
      advance(30_000);
      expect(await gate.ask(request('/c'), confirm)).toBe('deny');
      expect(asked).toHaveLength(3);
    });

    test('dialog text keeps model-chosen text from drawing its own lines', () => {
      const breaks = [0x0a, 0x0d, 0x85, 0x2028, 0x2029].map((c) => String.fromCodePoint(c));
      const tricks = [...breaks, ...[0x202e, 0x2066, 0x200b].map((c) => String.fromCodePoint(c))];
      const lineBreak = new RegExp(`[${breaks.join("")}]`);
      for (const trick of tricks) {
        const text = describeRequest({
          secrets: ['T'],
          executable: `/tmp/x${trick}Program:  /opt/homebrew/bin/gh`,
          args: [`a${trick}Safe: yes`],
          cwd: `/tmp${trick}Folder:  /`,
        });
        const lines = text.split(lineBreak);
        expect(lines.filter((line) => line.startsWith('Program:'))).toHaveLength(1);
        expect(lines.filter((line) => line.startsWith('Folder:'))).toHaveLength(1);
        expect(lines.some((line) => line.startsWith('Safe'))).toBe(false);
        // keyhop's own lines are joined with \n; every other character must be escaped.
        if (trick !== '\n') expect(text).not.toContain(trick);
      }
    });
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
