import { expect, test } from 'bun:test';
import { chmod, mkdir, readFile, rename, symlink, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { platformAuthenticator } from '../src/auth.ts';
import { runProcess } from '../src/process.ts';
import { VaultStore } from '../src/store.ts';
import { newStore, tempHome } from './support.ts';

const unix = process.platform !== 'win32';
const cli = fileURLToPath(new URL('../src/index.ts', import.meta.url));
const secret = 'headless-test-token-43';

function command(file: string, ...args: string[]) {
  return runProcess(process.execPath, [cli, ...args], {
    env: { ...process.env, KEYHOP_HOME: file, KEYHOP_TEST_AUTH: '0' },
    timeoutMs: 12_000,
  });
}

test('the CLI creates an automatic vault and opens it in a fresh process', async () => {
  const home = await tempHome();
  try {
    const setup = await command(home.p.dir, 'setup', '--auto-auth', '--vault-only');
    if (setup.code !== 0) throw new Error(setup.stderr || setup.stdout);

    const file = JSON.parse(await readFile(home.p.key, 'utf8'));
    expect(file).toMatchObject({ auth: 'auto', platform: process.platform, version: 1 });
    const keyBytes = Buffer.from(file.peer, 'base64').length;
    if (unix) expect(keyBytes).toBe(32);
    else expect(keyBytes).toBeGreaterThan(32);
    const store = new VaultStore(home.p, platformAuthenticator(), 0);
    await store.update('change', (vault) => {
      vault.secrets.TOKEN = { origin: 'test', source: 'test', updatedAt: '1', value: secret };
    });
    store.lock();

    const listed = await command(home.p.dir, 'list');
    expect(listed.code).toBe(0);
    expect(listed.stdout).toContain('TOKEN');
    expect(listed.stdout).not.toContain(secret);
    expect(listed.stdout).not.toContain(file.peer);
    expect(await readFile(home.p.vault, 'utf8')).not.toContain(secret);

    const again = await command(home.p.dir, 'setup', '--vault-only');
    expect(again.code).toBe(0);
    expect(JSON.parse(await readFile(home.p.key, 'utf8'))).toEqual(file);

    const fake = await runProcess(process.execPath, [cli, 'list'], {
      env: { ...process.env, NODE_ENV: 'test', KEYHOP_HOME: home.p.dir, KEYHOP_TEST_AUTH: '1', KEYHOP_TEST_DIALOG: 'always' },
      timeoutMs: 12_000,
    });
    expect(fake.code).toBe(1);
    expect(fake.stderr).toContain('only opens vaults it created');
  } finally {
    await home.cleanup();
  }
}, 25_000);

test('automatic setup refuses to silently convert an existing biometric vault', async () => {
  const home = await tempHome();
  try {
    await newStore(home.p);
    const original = await readFile(home.p.key, 'utf8');
    const result = await command(home.p.dir, 'setup', '--auto-auth', '--vault-only');
    expect(result.code).toBe(1);
    expect(result.stderr).toContain('uses biometric unlock');
    expect(await readFile(home.p.key, 'utf8')).toBe(original);
  } finally {
    await home.cleanup();
  }
});

test.if(unix)('automatic unlock refuses group-readable and symlinked keys', async () => {
  const home = await tempHome();
  try {
    const store = new VaultStore(home.p, platformAuthenticator(), 0);
    await store.initialize({ autoAuth: true, biometryOnly: false });
    store.lock();
    await chmod(home.p.key, 0o640);
    await expect(store.read()).rejects.toThrow('owner-only');
    await chmod(home.p.key, 0o600);
    const original = join(home.p.dir, 'original-key');
    await rename(home.p.key, original);
    await symlink(original, home.p.key);
    await expect(store.read()).rejects.toThrow();
  } finally {
    await home.cleanup();
  }
});

test.if(process.platform === 'linux')('headless commands follow the allowlist with automatic unlock', async () => {
  const home = await tempHome();
  const client = new Client({ name: 'headless-test', version: '1' });
  try {
    expect((await command(home.p.dir, 'setup', '--auto-auth', '--vault-only')).code).toBe(0);
    await mkdir(home.p.syncDir);
    const source = JSON.stringify({ TOKEN: secret, OTHER_TOKEN: 'another-test-token' });
    await writeFile(join(home.p.syncDir, '10-test.mjs'), `console.log(${JSON.stringify(source)})`);
    expect((await command(home.p.dir, 'sync')).code).toBe(0);

    const program = join(home.p.dir, 'approved-command');
    await writeFile(program, '#!/bin/sh\nprintf "%s" "$TOKEN"\n', { mode: 0o700 });
    const run = () => command(home.p.dir, 'run', '--secrets', 'TOKEN', '--', program);
    const denied = await run();
    expect(denied.code).toBe(1);
    expect(denied.stderr).toContain('may not be used with');
    expect((await command(home.p.dir, 'allow', 'TOKEN', program)).code).toBe(0);
    const approved = await run();
    expect(approved.code).toBe(0);
    expect(approved.stdout).toBe('[REDACTED:TOKEN]');

    await client.connect(new StdioClientTransport({
      command: process.execPath,
      args: [cli, 'serve'],
      env: { KEYHOP_HOME: home.p.dir, KEYHOP_TEST_AUTH: '0' },
    }));
    const runTool = (name: string) => client.callTool({
      name: 'run_with_secrets',
      arguments: { command: program, secrets: [name] },
    });
    const allowed = await runTool('TOKEN');
    expect(allowed.isError).toBeFalsy();
    expect(JSON.stringify(allowed.content)).toContain('[REDACTED:TOKEN]');
    expect(JSON.stringify(allowed.content)).not.toContain(secret);
    const unrelated = await runTool('OTHER_TOKEN');
    expect(unrelated.isError).toBe(true);
    expect(JSON.stringify(unrelated.content)).toContain('OTHER_TOKEN may not be used with');

    const bypass = await command(home.p.dir, 'run', '--bypass', '--secrets', 'TOKEN', '--', '/bin/sh', '-c', 'exit 0');
    expect(bypass.code).toBe(1);
    expect(bypass.stderr).toContain('approve it in a dialog');
  } finally {
    await client.close();
    await home.cleanup();
  }
}, 25_000);
