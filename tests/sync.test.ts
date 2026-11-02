import { afterEach, describe, expect, test } from 'bun:test';
import { chmod, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { saveConfig, unlockMs } from '../src/config.ts';
import { changeAllowed, summarize, syncVault, syncedSecrets } from '../src/secrets.ts';
import { compareSteps, interpreterFor, listScripts, parseStepOutput, planSteps } from '../src/sync.ts';
import { newStore, tempHome } from './support.ts';

const unix = process.platform !== 'win32';

describe('parseStepOutput', () => {
  test('reads NAME=value lines with comments, export and quotes', () => {
    const out = parseStepOutput('# c\n\nexport A=1\nB = "two words"\nC=\'x=y\'\n', 's');
    expect(out).toEqual({ A: '1', B: 'two words', C: 'x=y' });
  });

  test('reads a JSON object', () => {
    expect(parseStepOutput('{"A":"1","B":"2"}', 's')).toEqual({ A: '1', B: '2' });
  });

  test('rejects non-string JSON values', () => {
    expect(() => parseStepOutput('{"A":1}', 's')).toThrow();
  });

  test('rejects a malformed line without echoing it', () => {
    let message = '';
    try {
      parseStepOutput('A=1\nhunter2-not-a-pair\n', 's');
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).not.toBe('');
    expect(message).not.toContain('hunter2');
  });

  test('rejects reserved and invalid names', () => {
    expect(() => parseStepOutput('PATH=/tmp', 's')).toThrow();
    expect(() => parseStepOutput('DYLD_INSERT_LIBRARIES=x', 's')).toThrow();
    expect(() => parseStepOutput('lower=x', 's')).toThrow();
  });
});

describe('unlockMs', () => {
  test('clamps to 1-60 minutes and ignores junk', () => {
    expect(unlockMs({})).toBe(15 * 60_000);
    expect(unlockMs({ unlockMinutes: 0 })).toBe(60_000);
    expect(unlockMs({ unlockMinutes: -5 })).toBe(60_000);
    expect(unlockMs({ unlockMinutes: 1e9 })).toBe(60 * 60_000);
    expect(unlockMs({ unlockMinutes: 'x' as unknown as number })).toBe(15 * 60_000);
  });
});

describe('step order', () => {
  test('is numeric-aware', () => {
    expect(['10-b', '2-a', '00-1password', '1-c'].sort(compareSteps)).toEqual(['00-1password', '1-c', '2-a', '10-b']);
  });

  test('picks interpreters by extension', () => {
    expect(interpreterFor('/x/a.mjs')).toEqual({ command: process.execPath, args: ['/x/a.mjs'] });
    expect(interpreterFor('C:\\a.ps1', 'win32')).toMatchObject({ command: 'powershell.exe' });
    expect(interpreterFor('/x/a.cmd', 'darwin')).toHaveProperty('error');
    expect(interpreterFor('/x/a.exe', 'darwin')).toHaveProperty('error');
  });
});

describe('sync', () => {
  let cleanup: () => Promise<void> = async () => {};
  afterEach(() => cleanup());

  async function setup() {
    const home = await tempHome();
    cleanup = home.cleanup;
    await mkdir(home.p.syncDir, { recursive: true });
    return home.p;
  }

  test('lists scripts in order and skips disabled files', async () => {
    const p = await setup();
    for (const f of ['20-b.mjs', '3-a.mjs', '_off.mjs', '.hidden', 'README.md', '10-x.mjs.disabled'])
      await writeFile(join(p.syncDir, f), '');
    expect(await listScripts(p.syncDir)).toEqual(['3-a.mjs', '20-b.mjs']);
  });

  test('later steps override earlier ones and every step is recorded', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=first\\nB=b")');
    await writeFile(join(p.syncDir, '20-b.mjs'), 'console.log(JSON.stringify({ A: "second" }))');
    const store = await newStore(p);
    const result = await syncVault(store);
    expect(result.steps).toEqual([
      { step: '10-a.mjs', count: 2 },
      { step: '20-b.mjs', count: 1 },
    ]);
    const vault = await store.read();
    expect(syncedSecrets(vault)).toEqual({ A: 'second', B: 'b' });
    expect(vault.secrets.A!.source).toBe('20-b.mjs');
  });

  test.if(unix)('runs shell and executable scripts', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.sh'), 'echo "SH=$KEYHOP_STEP"');
    await writeFile(join(p.syncDir, '20-exec'), '#!/bin/sh\necho EXEC=ok\n');
    await chmod(join(p.syncDir, '20-exec'), 0o755);
    const store = await newStore(p);
    await syncVault(store);
    expect(syncedSecrets(await store.read())).toEqual({ SH: '10-a.sh', EXEC: 'ok' });
  });

  test('a failing step aborts the sync and leaves the vault unchanged', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=1")');
    const store = await newStore(p);
    await syncVault(store);
    const before = await readFile(p.vault, 'utf8');
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=2")');
    await writeFile(join(p.syncDir, '20-fail.mjs'), 'console.error("boom A=2"); process.exit(3)');
    expect(syncVault(store)).rejects.toThrow(/20-fail\.mjs/);
    await Bun.sleep(50);
    expect(await readFile(p.vault, 'utf8')).toBe(before);
  });

  test('error output from a failing step is redacted', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("TOKEN=s3cr3t-value")');
    await writeFile(join(p.syncDir, '20-fail.mjs'), 'console.error("leaked s3cr3t-value"); process.exit(1)');
    const store = await newStore(p);
    const error = await syncVault(store).catch((e: Error) => e);
    expect(error).toBeInstanceOf(Error);
    expect((error as Error).message).not.toContain('s3cr3t-value');
  });

  test.if(unix)('a name that disappears is removed but keeps its access rules', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=1\\nB=2")');
    const store = await newStore(p);
    await syncVault(store);
    await changeAllowed(store, { B: { add: ['/usr/bin/true'] } });
    await rename(join(p.syncDir, '10-a.mjs'), join(p.syncDir, '_10-a.mjs'));
    await writeFile(join(p.syncDir, '20-a.mjs'), 'console.log("A=1")');
    const result = await syncVault(store);
    expect(result.removed).toEqual(['B']);
    const vault = await store.read();
    expect(vault.secrets.B).toBeUndefined();
    expect(vault.policy.B!.allow.map((e) => e.path)).toEqual(['/usr/bin/true']);
  });

  test.if(unix)('editing the script that fills a name clears its access rules', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=1")');
    const store = await newStore(p);
    await syncVault(store);
    await changeAllowed(store, { A: { add: ['/usr/bin/true'] } });
    expect((await syncVault(store)).rulesCleared).toEqual([]);
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=other-item")');
    expect((await syncVault(store)).rulesCleared).toEqual(['A']);
    expect((await summarize(store)).secrets[0]!.allowedCommands).toEqual([]);
  });

  test.if(unix)('a later script overriding an allowed name clears its rules', async () => {
    const p = await setup();
    await writeFile(join(p.syncDir, '10-a.mjs'), 'console.log("A=1")');
    const store = await newStore(p);
    await syncVault(store);
    await changeAllowed(store, { A: { add: ['/usr/bin/true'] } });
    await writeFile(join(p.syncDir, '90-evil.mjs'), 'console.log("A=2")');
    expect((await syncVault(store)).rulesCleared).toEqual(['A']);
  });

  test.if(unix)('rules granted before the first sync bind to the given ref', async () => {
    const p = await setup();
    const store = await newStore(p);
    await changeAllowed(store, { A: { add: ['/usr/bin/true'], bindTo: 'op://Dev/A/token' } });
    const vault = await store.read();
    expect(vault.policy.A!.boundTo).toBe('op://Dev/A/token');
  });

  test.if(unix)('allowing a name that was never synced or linked is refused', async () => {
    const p = await setup();
    const store = await newStore(p);
    expect(changeAllowed(store, { A: { add: ['/usr/bin/true'] } })).rejects.toThrow();
  });

  test('linked tools become 00-<tool> steps', async () => {
    const p = await setup();
    await saveConfig(p, { secrets: { GH: { ref: 'op://Dev/GitHub/token' }, X: { ref: 'bw://item' } } });
    await writeFile(join(p.syncDir, '05-a.mjs'), '');
    const steps = await planSteps(
      { secrets: { GH: { ref: 'op://Dev/GitHub/token' }, X: { ref: 'bw://item' } } },
      p.syncDir,
      1000
    );
    expect(steps.map((s) => s.name)).toEqual(['00-1password', '00-bitwarden', '05-a.mjs']);
  });

  test('an unknown reference scheme is rejected', async () => {
    const p = await setup();
    expect(planSteps({ secrets: { A: { ref: 'vault://x' } } }, p.syncDir, 1000)).rejects.toThrow();
  });
});
