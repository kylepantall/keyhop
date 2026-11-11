import { afterEach, describe, expect, test } from 'bun:test';
import { createHash } from 'node:crypto';
import { realpathSync } from 'node:fs';
import { chmod, mkdir, readFile, symlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';
import type { Decision, Dialog } from '../src/approve.ts';
import { ClientError, EXIT, defaultPrefix, getSecrets, putSecrets, runClient, type ClientDeps } from '../src/clients.ts';
import type { Paths } from '../src/paths.ts';
import { syncVault } from '../src/secrets.ts';
import { VaultStore } from '../src/store.ts';
import { testAuthenticator, testSeamEnabled } from '../src/testauth.ts';
import type { ClientPin } from '../src/types.ts';
import { injectingVariables, parseProcArgs, treeHash, verifyParent, VerifyError, type ProcessInspector } from '../src/verify.ts';
import { fakeAuth, newStore, tempHome } from './support.ts';

const unix = process.platform !== 'win32';

interface Fixture {
  p: Paths;
  runtime: string;
  entry: string;
  root: string;
}

let cleanup: () => Promise<void> = async () => {};
afterEach(() => cleanup());

async function fixture(): Promise<Fixture> {
  const home = await tempHome();
  cleanup = home.cleanup;
  const bin = join(home.p.dir, 'bin');
  const root = join(home.p.dir, 'app');
  await mkdir(bin, { recursive: true });
  await mkdir(join(root, 'dist'), { recursive: true });
  await mkdir(join(root, 'node_modules', 'dep'), { recursive: true });
  const runtime = join(bin, 'node');
  await writeFile(runtime, 'fake node binary');
  await writeFile(join(root, 'dist', 'index.js'), 'console.log("client")');
  await writeFile(join(root, 'node_modules', 'dep', 'index.js'), 'module.exports = 1');
  await writeFile(join(root, 'package.json'), '{}');
  return { p: home.p, runtime: realpathSync(runtime), entry: realpathSync(join(root, 'dist', 'index.js')), root: realpathSync(root) };
}

/** What a correctly started client looks like to the OS. */
function inspectorFor(f: Fixture, overrides: Partial<{ executable: string | null; argv: string[] | null; env: string[] | null; cwd: string | null }> = {}): ProcessInspector {
  const value = <K extends keyof typeof overrides>(key: K, fallback: (typeof overrides)[K]) => (key in overrides ? overrides[key] : fallback);
  return {
    executable: async () => value('executable', f.runtime) ?? null,
    argv: async () => value('argv', [f.runtime, f.entry, 'connect']) ?? null,
    env: async () => value('env', ['PATH=/usr/bin', 'HOME=/Users/me']) ?? null,
    cwd: async () => value('cwd', f.root) ?? null,
  };
}

function fakeDialog(answer: Decision = 'once'): Dialog & { shown: { message: string; kind: string }[]; answer: Decision } {
  const dialog = Object.assign(
    async (message: string, kind: 'grant' | 'confirm') => {
      dialog.shown.push({ message, kind });
      return dialog.answer;
    },
    { shown: [] as { message: string; kind: string }[], answer }
  );
  return dialog;
}

function io(stdin = '') {
  const out = { stdout: '', stderr: '' };
  return {
    out,
    io: { stdin: async () => stdin, stdout: (t: string) => void (out.stdout += t), stderr: (t: string) => void (out.stderr += t) },
  };
}

async function setup(answer: Decision = 'once') {
  const f = await fixture();
  const auth = fakeAuth();
  await newStore(f.p, auth);
  auth.prompts.length = 0;
  const dialog = fakeDialog(answer);
  /** Each `keyhop client …` is its own process, with its own unlock. */
  const deps = (overrides: Partial<ClientDeps> = {}): ClientDeps => ({
    store: new VaultStore(f.p, auth, 0),
    dialog,
    inspector: inspectorFor(f),
    ppid: 4242,
    platform: 'darwin',
    ...overrides,
  });
  const add = async (name = 'vpnhop', extra: string[] = []) => {
    const run = io();
    const code = await runClient(['add', name, '--runtime', f.runtime, '--entry', f.entry, '--root', f.root, ...extra], deps(), run.io);
    return { code, ...run.out };
  };
  const call = async (sub: 'get' | 'put', request: object, overrides: Partial<ClientDeps> = {}) => {
    const run = io(JSON.stringify(request));
    const code = await runClient([sub], deps(overrides), run.io);
    return { code, ...run.out, json: code === 0 ? JSON.parse(run.out.stdout) : undefined };
  };
  const vault = () => new VaultStore(f.p, fakeAuth(), 0).read();
  return { f, auth, dialog, deps, add, call, vault };
}

async function pinFor(f: Fixture): Promise<ClientPin> {
  return {
    runtime: { path: f.runtime, realPath: f.runtime, sha256: createHash('sha256').update('fake node binary').digest('hex') },
    entry: { path: f.entry, realPath: f.entry },
    root: { path: f.root, realPath: f.root, treeHash: await treeHash(f.root) },
    prefix: 'VPNHOP_',
    addedAt: '2026-01-01T00:00:00.000Z',
  };
}

describe('tree hash', () => {
  test('is SHA-256 over sorted "relpath NUL sha256 NUL", node_modules included', async () => {
    const f = await fixture();
    const sha = (text: string) => createHash('sha256').update(text).digest('hex');
    const files: [string, string][] = [
      ['dist/index.js', 'console.log("client")'],
      ['node_modules/dep/index.js', 'module.exports = 1'],
      ['package.json', '{}'],
    ];
    const expected = createHash('sha256');
    for (const [rel, content] of files) expected.update(`${rel}\0${sha(content)}\0`);
    expect(await treeHash(f.root)).toBe(expected.digest('hex'));
  });

  test('changes when any file changes, including under node_modules', async () => {
    const f = await fixture();
    const before = await treeHash(f.root);
    await writeFile(join(f.root, 'node_modules', 'dep', 'index.js'), 'module.exports = 2');
    expect(await treeHash(f.root)).not.toBe(before);
  });

  test.if(unix)('refuses symlinks', async () => {
    const f = await fixture();
    await symlink(f.entry, join(f.root, 'link.js'));
    expect(treeHash(f.root)).rejects.toBeInstanceOf(VerifyError);
  });
});

describe('process inspection helpers', () => {
  test('parses KERN_PROCARGS2: argc, exec path, padding, argv, env', () => {
    const argc = Buffer.alloc(4);
    argc.writeInt32LE(2);
    const buffer = Buffer.concat([argc, Buffer.from('/bin/node\0\0\0\0node /x.js\0/evil.js\0A=1\0NODE_OPTIONS=-r y\0\0\0')]);
    // argv[0] containing a space stays one argument: ps would print this like `node /x.js /evil.js`.
    expect(parseProcArgs(buffer)).toEqual({ argv: ['node /x.js', '/evil.js'], env: ['A=1', 'NODE_OPTIONS=-r y'] });
  });

  test('flags code-injecting variables only', () => {
    expect(
      injectingVariables(['PATH=/bin', 'NODE_OPTIONS=--require x', 'NODE_PATH=/x', 'BUN_OPTIONS=--preload x', 'DYLD_INSERT_LIBRARIES=x', 'LD_PRELOAD=x', 'NODE_ENV=test'])
    ).toEqual(['NODE_OPTIONS', 'NODE_PATH', 'BUN_OPTIONS', 'DYLD_INSERT_LIBRARIES', 'LD_PRELOAD']);
  });
});

describe.if(unix)('parent verification', () => {
  const check = async (f: Fixture, inspector: ProcessInspector, pin?: ClientPin, platform: NodeJS.Platform = 'darwin') => {
    try {
      await verifyParent(pin ?? (await pinFor(f)), 1, inspector, { platform });
      return 'ok';
    } catch (error) {
      if (error instanceof VerifyError) return error.check;
      throw error;
    }
  };

  test('passes for the pinned runtime, entry, clean env and unchanged tree', async () => {
    const f = await fixture();
    expect(await check(f, inspectorFor(f))).toBe('ok');
    // argv[0] may be a bare name.
    expect(await check(f, inspectorFor(f, { argv: ['node', f.entry] }))).toBe('ok');
  });

  test('fails each check', async () => {
    const f = await fixture();
    expect(await check(f, inspectorFor(f, { executable: '/usr/bin/python3' }))).toBe('executable');
    expect(await check(f, inspectorFor(f, { executable: null }))).toBe('executable');
    expect(await check(f, inspectorFor(f, { argv: [f.runtime, '--import', '/tmp/evil.mjs', f.entry] }))).toBe('argv');
    expect(await check(f, inspectorFor(f, { argv: [f.runtime, '-r', '/tmp/evil.js', f.entry] }))).toBe('argv');
    expect(await check(f, inspectorFor(f, { argv: [`node ${f.entry}`, '/tmp/evil.js'] }))).toBe('argv');
    expect(await check(f, inspectorFor(f, { argv: [f.runtime, '-e', 'evil()'] }))).toBe('argv');
    expect(await check(f, inspectorFor(f, { argv: ['python3', f.entry] }))).toBe('argv');
    expect(await check(f, inspectorFor(f, { argv: null }))).toBe('argv');
    expect(await check(f, inspectorFor(f, { env: ['PATH=/bin', 'NODE_OPTIONS=--require /tmp/x.js'] }))).toBe('environment');
    expect(await check(f, inspectorFor(f, { env: ['DYLD_INSERT_LIBRARIES=/tmp/x.dylib'] }))).toBe('environment');
    expect(await check(f, inspectorFor(f, { env: null }))).toBe('environment');
    expect(await check(f, inspectorFor(f, { env: [] }))).toBe('environment');
    expect(await check(f, inspectorFor(f), undefined, 'win32')).toBe('platform');
  });

  test('fails when the runtime binary changed', async () => {
    const f = await fixture();
    const pin = await pinFor(f);
    await writeFile(f.runtime, 'patched node');
    expect(await check(f, inspectorFor(f), pin)).toBe('runtime-hash');
  });

  test('fails when the tree changed', async () => {
    const f = await fixture();
    const pin = await pinFor(f);
    await writeFile(join(f.root, 'node_modules', 'dep', 'extra.js'), 'evil()');
    expect(await check(f, inspectorFor(f), pin)).toBe('tree');
  });

  test('fails when the root is world-writable', async () => {
    const f = await fixture();
    const pin = await pinFor(f);
    await chmod(f.root, 0o777);
    expect(await check(f, inspectorFor(f), pin)).toBe('root');
  });

  test('a bun runtime may not start in a folder with bunfig.toml outside the root', async () => {
    const f = await fixture();
    const bun = join(f.p.dir, 'bin', 'bun');
    await writeFile(bun, 'fake node binary');
    const pin = await pinFor(f);
    pin.runtime = { ...pin.runtime, path: bun, realPath: realpathSync(bun) };
    const project = join(f.p.dir, 'project');
    await mkdir(project);
    const bunInspector = (cwd: string) => inspectorFor(f, { executable: pin.runtime.realPath, argv: ['bun', f.entry], cwd });
    expect(await check(f, bunInspector(project), pin)).toBe('ok');
    await writeFile(join(project, 'bunfig.toml'), 'preload = ["./evil.ts"]');
    expect(await check(f, bunInspector(project), pin)).toBe('bunfig');
    expect(await check(f, inspectorFor(f, { executable: pin.runtime.realPath, argv: ['bun', f.entry], cwd: null }), pin)).toBe('bunfig');
  });
});

describe.if(unix)('client add / list / remove', () => {
  test('pins runtime, entry and tree in the vault and clients.json, after the dialog and Touch ID', async () => {
    const { f, auth, dialog, add, vault } = await setup();
    const result = await add();
    expect(result.code).toBe(EXIT.ok);
    expect(dialog.shown.map((d) => d.kind)).toEqual(['confirm']);
    expect(auth.prompts).toEqual(['change']);
    const client = (await vault()).clients!.vpnhop!;
    expect(client.prefix).toBe('VPNHOP_');
    expect(client.runtime.realPath).toBe(f.runtime);
    expect(client.runtime.sha256).toBe(createHash('sha256').update('fake node binary').digest('hex'));
    expect(client.entry.realPath).toBe(f.entry);
    expect(client.root.treeHash).toBe(await treeHash(f.root));
    expect(client.allow).toEqual([]);
    const mirror = JSON.parse(await readFile(f.p.clients, 'utf8'));
    expect(mirror.clients.vpnhop.root.treeHash).toBe(client.root.treeHash);
    expect(mirror.clients.vpnhop.allow).toBeUndefined();
  });

  test('derives the prefix from the name', () => {
    expect(defaultPrefix('vpnhop')).toBe('VPNHOP_');
    expect(defaultPrefix('my-app')).toBe('MY_APP_');
  });

  test('a denied dialog changes nothing (exit 4); a cancelled Touch ID exits 2', async () => {
    const { auth, dialog, add, vault } = await setup('deny');
    const denied = await add();
    expect(denied.code).toBe(EXIT.denied);
    expect(denied.stderr.trim()).toBe('denied');
    expect(auth.prompts).toEqual([]);
    dialog.answer = 'once';
    auth.cancelNext = true;
    const cancelled = await add();
    expect(cancelled.code).toBe(EXIT.cancelled);
    expect(cancelled.stderr.trim()).toBe('cancelled');
    expect((await vault()).clients).toBeUndefined();
  });

  test('refuses bad names, reserved or overlapping prefixes, an entry outside the root, and symlinks', async () => {
    const { f, add, dialog } = await setup();
    expect((await add('VPNHOP')).code).toBe(EXIT.error);
    expect((await add('keyhop-x')).code).toBe(EXIT.error); // KEYHOP_X_ is reserved
    expect((await add('vpnhop')).code).toBe(EXIT.ok);
    expect((await add('other', ['--prefix', 'VPNHOP_AWS_'])).code).toBe(EXIT.error);
    expect((await add('other', ['--prefix', 'VPN_'])).code).toBe(EXIT.ok);
    const outside = join(f.p.dir, 'outside.js');
    await writeFile(outside, '');
    const run = io();
    const deps: ClientDeps = { store: new VaultStore(f.p, fakeAuth(), 0), dialog, inspector: inspectorFor(f), ppid: 1, platform: 'darwin' };
    expect(await runClient(['add', 'third', '--runtime', f.runtime, '--entry', outside, '--root', f.root], deps, run.io)).toBe(EXIT.error);
    await symlink(f.entry, join(f.root, 'link.js'));
    expect((await add('fourth')).code).toBe(EXIT.error);
  });

  test('re-adding asks again and keeps grants; list and remove', async () => {
    const { dialog, add, deps, vault } = await setup();
    await add();
    const store = new VaultStore(deps().store.paths, fakeAuth(), 0);
    await store.update('change', (v) => void (v.clients!.vpnhop!.allow = [{ name: 'VPN_PASSWORD', origin: 'op://x' }]));
    expect((await add()).code).toBe(EXIT.ok);
    expect(dialog.shown.length).toBe(2);
    expect((await vault()).clients!.vpnhop!.allow.map((a) => a.name)).toEqual(['VPN_PASSWORD']);

    const listed = io();
    expect(await runClient(['list', '--json'], deps(), listed.io)).toBe(EXIT.ok);
    const clients = JSON.parse(listed.out.stdout);
    expect(clients.map((c: { name: string; prefix: string; allow: string[] }) => [c.name, c.prefix, c.allow])).toEqual([
      ['vpnhop', 'VPNHOP_', ['VPN_PASSWORD']],
    ]);

    expect(await runClient(['remove', 'vpnhop'], deps(), io().io)).toBe(EXIT.ok);
    expect((await vault()).clients).toEqual({});
    expect(await runClient(['remove', 'vpnhop'], deps(), io().io)).toBe(EXIT.error);
  });
});

describe.if(unix)('client put / get', () => {
  async function registered(answer: Decision = 'once') {
    const s = await setup('once');
    await s.add();
    s.dialog.answer = answer;
    s.auth.prompts.length = 0;
    s.dialog.shown.length = 0;
    return s;
  }

  test('put saves prefixed names as client entries after Touch ID (change); get reads them after one unlock', async () => {
    const { auth, dialog, call, vault } = await registered();
    const put = await call('put', { client: 'vpnhop', values: { VPNHOP_AWS_CONFIG: 'conf' }, purpose: 'Save VPN profile "aws"' });
    expect(put.code).toBe(EXIT.ok);
    expect(put.json).toEqual({ saved: ['VPNHOP_AWS_CONFIG'], removed: [] });
    expect(auth.prompts).toEqual(['change']);
    const entry = (await vault()).secrets.VPNHOP_AWS_CONFIG!;
    expect([entry.value, entry.source, entry.origin]).toEqual(['conf', 'client:vpnhop', 'client:vpnhop']);

    auth.prompts.length = 0;
    const get = await call('get', { client: 'vpnhop', names: ['VPNHOP_AWS_CONFIG'], purpose: 'Connect' });
    expect(get.code).toBe(EXIT.ok);
    expect(get.json).toEqual({ values: { VPNHOP_AWS_CONFIG: 'conf' } });
    expect(auth.prompts).toEqual(['unlock']);
    expect(dialog.shown).toEqual([]);
    expect(get.stderr).toBe('');
  });

  test('put removes only names that exist, and refuses names outside the prefix or over 1 MiB', async () => {
    const { auth, call, vault } = await registered();
    await call('put', { client: 'vpnhop', values: { VPNHOP_A: 'a', VPNHOP_B: 'b' } });
    const removed = await call('put', { client: 'vpnhop', remove: ['VPNHOP_A', 'VPNHOP_GONE'] });
    expect(removed.json).toEqual({ saved: [], removed: ['VPNHOP_A'] });
    expect(Object.keys((await vault()).secrets)).toEqual(['VPNHOP_B']);

    auth.prompts.length = 0;
    expect((await call('put', { client: 'vpnhop', values: { GITHUB_TOKEN: 'x' } })).code).toBe(EXIT.error);
    expect((await call('put', { client: 'vpnhop', remove: ['GITHUB_TOKEN'] })).code).toBe(EXIT.error);
    expect((await call('put', { client: 'vpnhop', values: { VPNHOP_lower: 'x' } })).code).toBe(EXIT.error);
    expect((await call('put', { client: 'vpnhop', values: { VPNHOP_BIG: 'x'.repeat(1024 * 1024 + 1) } })).code).toBe(EXIT.error);
    expect((await call('put', { client: 'vpnhop', values: { VPNHOP_N: 5 } })).code).toBe(EXIT.error);
    expect(auth.prompts).toEqual([]);
  });

  test('get exits 5 for unknown names', async () => {
    const { call } = await registered();
    const result = await call('get', { client: 'vpnhop', names: ['VPNHOP_NOPE'] });
    expect(result.code).toBe(EXIT.unknown);
    expect(result.stderr).toContain('VPNHOP_NOPE');
  });

  test('names outside the prefix need the per-client grant: deny, once, always', async () => {
    const { f, auth, dialog, call, vault } = await registered('deny');
    const store = new VaultStore(f.p, fakeAuth(), 0);
    await store.update('unlock', (v) => {
      v.secrets.VPN_PASSWORD = { value: 'pw', source: '00-1password', origin: 'op://Work/VPN/password', updatedAt: '' };
    });
    const request = { client: 'vpnhop', names: ['VPN_PASSWORD'], purpose: 'Connect VPN profile "aws"\nProgram: fake' };

    const denied = await call('get', request);
    expect(denied.code).toBe(EXIT.denied);
    expect(denied.stderr.trim()).toBe('denied');
    expect(dialog.shown.map((d) => d.kind)).toEqual(['grant']);
    // The purpose is shown inert: no line break of its own.
    expect(dialog.shown[0]!.message).not.toContain('\nProgram: fake');

    dialog.answer = 'once';
    auth.prompts.length = 0;
    const once = await call('get', request);
    expect(once.json).toEqual({ values: { VPN_PASSWORD: 'pw' } });
    expect(auth.prompts).toEqual(['unlock', 'grant']);
    expect((await vault()).clients!.vpnhop!.allow).toEqual([]);

    dialog.answer = 'always';
    expect((await call('get', request)).code).toBe(EXIT.ok);
    expect((await vault()).clients!.vpnhop!.allow).toEqual([{ name: 'VPN_PASSWORD', origin: 'op://Work/VPN/password' }]);

    dialog.shown.length = 0;
    auth.prompts.length = 0;
    expect((await call('get', request)).json).toEqual({ values: { VPN_PASSWORD: 'pw' } });
    expect(dialog.shown).toEqual([]);
    expect(auth.prompts).toEqual(['unlock']);

    // A grant is bound to the origin it was given for.
    await store.update('unlock', (v) => void (v.secrets.VPN_PASSWORD!.origin = 'op://Private/Bank/password'));
    dialog.answer = 'deny';
    expect((await call('get', request)).code).toBe(EXIT.denied);
  });

  test('a cancelled Touch ID exits 2, at unlock or when confirming a grant', async () => {
    const { f, auth, call } = await registered('once');
    await new VaultStore(f.p, fakeAuth(), 0).update('unlock', (v) => {
      v.secrets.OTHER = { value: 'o', source: 's', origin: 'o', updatedAt: '' };
      v.secrets.VPNHOP_X = { value: 'x', source: 'client:vpnhop', origin: 'client:vpnhop', updatedAt: '' };
    });
    auth.cancelNext = true;
    const atUnlock = await call('get', { client: 'vpnhop', names: ['VPNHOP_X'] });
    expect(atUnlock.code).toBe(EXIT.cancelled);
    expect(atUnlock.stderr.trim()).toBe('cancelled');
    // Unlock succeeds, then the grant's Touch ID is cancelled.
    const real = auth.derive.bind(auth);
    let calls = 0;
    auth.derive = async (key, action) => {
      if (++calls === 2) auth.cancelNext = true;
      return real(key, action);
    };
    const atGrant = await call('get', { client: 'vpnhop', names: ['OTHER'] });
    expect(atGrant.code).toBe(EXIT.cancelled);
  });

  test('an unregistered or unverified caller exits 3 before any prompt', async () => {
    const { f, auth, dialog, call } = await registered();
    expect((await call('get', { client: 'hopsql', names: ['HOPSQL_X'] })).code).toBe(EXIT.unverified);
    for (const inspector of [
      inspectorFor(f, { executable: '/usr/bin/python3' }),
      inspectorFor(f, { argv: [f.runtime, '--require', '/tmp/x.js', f.entry] }),
      inspectorFor(f, { env: ['NODE_OPTIONS=--require /tmp/x.js'] }),
      inspectorFor(f, { env: null }),
    ]) {
      expect((await call('get', { client: 'vpnhop', names: ['VPNHOP_X'] }, { inspector })).code).toBe(EXIT.unverified);
      expect((await call('put', { client: 'vpnhop', values: { VPNHOP_X: 'x' } }, { inspector })).code).toBe(EXIT.unverified);
    }
    await writeFile(join(f.root, 'dist', 'index.js'), 'evil()');
    expect((await call('get', { client: 'vpnhop', names: ['VPNHOP_X'] })).code).toBe(EXIT.unverified);
    expect(auth.prompts).toEqual([]);
    expect(dialog.shown).toEqual([]);
  });

  test('Windows exits 3', async () => {
    const { call, auth } = await registered();
    expect((await call('get', { client: 'vpnhop', names: ['VPNHOP_X'] }, { platform: 'win32' })).code).toBe(EXIT.unverified);
    expect((await call('put', { client: 'vpnhop', values: { VPNHOP_X: 'x' } }, { platform: 'win32' })).code).toBe(EXIT.unverified);
    expect(auth.prompts).toEqual([]);
  });

  test('a clients.json that no longer matches the vault exits 3 after the unlock', async () => {
    const { f, call } = await registered();
    // Someone points clients.json at their own tree; the vault's pin still wins.
    const evilRoot = join(f.p.dir, 'evil');
    await mkdir(evilRoot);
    await writeFile(join(evilRoot, 'index.js'), 'evil()');
    const mirror = JSON.parse(await readFile(f.p.clients, 'utf8'));
    mirror.clients.vpnhop.entry = { path: join(evilRoot, 'index.js'), realPath: realpathSync(join(evilRoot, 'index.js')) };
    mirror.clients.vpnhop.root = { path: evilRoot, realPath: realpathSync(evilRoot), treeHash: await treeHash(evilRoot) };
    await writeFile(f.p.clients, JSON.stringify(mirror));
    const inspector = inspectorFor(f, { argv: [f.runtime, realpathSync(join(evilRoot, 'index.js'))] });
    expect((await call('get', { client: 'vpnhop', names: ['VPNHOP_X'] }, { inspector })).code).toBe(EXIT.unverified);
    expect((await call('put', { client: 'vpnhop', values: { VPNHOP_X: 'x' } }, { inspector })).code).toBe(EXIT.unverified);
  });

  test('bad requests exit 1', async () => {
    const { deps } = await registered();
    for (const stdin of ['not json', '[]', '{"client":"vpnhop"}', '{"client":"Bad","names":["A"]}', '{"client":"vpnhop","names":"A"}']) {
      const run = io(stdin);
      expect(await runClient(['get'], deps(), run.io)).toBe(EXIT.error);
    }
    expect(getSecrets(deps(), { client: 'vpnhop', names: [] })).rejects.toBeInstanceOf(ClientError);
    expect(putSecrets(deps(), { client: 'vpnhop' })).rejects.toBeInstanceOf(ClientError);
  });

  test('sync keeps client entries and never removes them', async () => {
    const { f, call, vault } = await registered();
    await call('put', { client: 'vpnhop', values: { VPNHOP_AWS_CONFIG: 'conf' } });
    await mkdir(f.p.syncDir, { recursive: true });
    await writeFile(join(f.p.syncDir, '10-a.mjs'), 'console.log("SYNCED=s\\nVPNHOP_AWS_CONFIG=from-sync")');
    const result = await syncVault(new VaultStore(f.p, fakeAuth(), 0));
    expect(result.removed).toEqual([]);
    const secrets = (await vault()).secrets;
    expect(secrets.VPNHOP_AWS_CONFIG!.value).toBe('conf');
    expect(secrets.VPNHOP_AWS_CONFIG!.source).toBe('client:vpnhop');
    expect(secrets.SYNCED!.value).toBe('s');

    await writeFile(join(f.p.syncDir, '10-a.mjs'), 'console.log("OTHER=o")');
    const second = await syncVault(new VaultStore(f.p, fakeAuth(), 0));
    expect(second.removed).toEqual(['SYNCED']);
    expect(Object.keys((await vault()).secrets).sort()).toEqual(['OTHER', 'VPNHOP_AWS_CONFIG']);
  });
});

describe('end-to-end test seam', () => {
  const home = '/tmp/keyhop-e2e-home';

  test('needs NODE_ENV=test, KEYHOP_TEST_AUTH=1 and a non-default KEYHOP_HOME', () => {
    expect(testSeamEnabled({ NODE_ENV: 'test', KEYHOP_TEST_AUTH: '1', KEYHOP_HOME: home })).toBe(true);
    expect(testSeamEnabled({ KEYHOP_TEST_AUTH: '1', KEYHOP_HOME: home })).toBe(false);
    expect(testSeamEnabled({ NODE_ENV: 'production', KEYHOP_TEST_AUTH: '1', KEYHOP_HOME: home })).toBe(false);
    expect(testSeamEnabled({ NODE_ENV: 'test', KEYHOP_HOME: home })).toBe(false);
    expect(testSeamEnabled({ NODE_ENV: 'test', KEYHOP_TEST_AUTH: '1' })).toBe(false);
    // Never the real data folder.
    expect(testSeamEnabled({ NODE_ENV: 'test', KEYHOP_TEST_AUTH: '1', KEYHOP_HOME: join(homedir(), '.config', 'keyhop') })).toBe(false);
  });

  test('never derives a key for a real (Secure Enclave / Hello) key file', async () => {
    const auth = testAuthenticator();
    const created = await auth.create({ biometryOnly: false });
    const key = { version: 1 as const, platform: 'darwin' as const, salt: '', ...created };
    expect((await auth.derive(key, 'unlock')).length).toBe(32);
    expect(auth.derive({ ...key, peer: Buffer.alloc(65, 4).toString('base64'), seKey: 'blob' }, 'unlock')).rejects.toThrow();
    expect(auth.derive({ ...key, seKey: 'blob' }, 'unlock')).rejects.toThrow();
  });
});
