import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { existsSync, realpathSync } from 'node:fs';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { windowsHelperPath } from '../src/auth.ts';
import { isEmbeddedPath } from '../src/paths.ts';
import { parseSums, sha256, verify, WINDOWS_ASSETS } from '../src/release.ts';

const root = join(import.meta.dir, '..');

describe('compiled keyhop.exe', () => {
  let dir = '';
  let exe = '';
  beforeAll(async () => {
    // Real path: macOS's tmpdir is a symlink (/var -> /private/var), and Windows may give a short 8.3 name.
    dir = realpathSync.native(await mkdtemp(join(tmpdir(), 'keyhop-compile-')));
    exe = join(dir, process.platform === 'win32' ? 'keyhop.exe' : 'keyhop');
    const built = spawnSync(process.execPath, ['build', '--compile', join(root, 'src', 'index.ts'), '--outfile', exe], {
      encoding: 'utf8',
    });
    if (built.status !== 0) throw new Error(built.stderr);
  }, 120_000);
  afterAll(() => rm(dir, { recursive: true, force: true }));

  test('recognises Bun embedded paths on every OS', () => {
    expect(isEmbeddedPath('file:///$bunfs/root/keyhop')).toBe(true);
    expect(isEmbeddedPath('file:///B:/~BUN/root/keyhop.exe')).toBe(true);
    expect(isEmbeddedPath('B:\\~BUN\\root\\keyhop.exe')).toBe(true);
    expect(isEmbeddedPath('C:\\Users\\RUNNER~1\\keyhop\\src\\paths.ts')).toBe(false);
    expect(isEmbeddedPath('file:///C:/Users/me/keyhop/src/paths.ts')).toBe(false);
  });

  test('knows it is compiled and looks for its helper next to itself', () => {
    const result = spawnSync(exe, ['doctor', '--json'], {
      encoding: 'utf8',
      env: { ...process.env, KEYHOP_HOME: join(dir, 'home') },
      timeout: 60_000,
    });
    const checks = JSON.parse(result.stdout) as { area: string; detail: string }[];
    expect(checks.find((c) => c.area === 'keyhop')?.detail).toContain(`compiled: ${exe}`);
    if (process.platform === 'win32')
      expect(checks.find((c) => c.area === 'biometrics')?.detail).toContain(join(dir, 'keyhop-hello.exe'));
  }, 60_000);

  test('runs .mjs sync scripts as plain Bun', () => {
    const script = join(root, 'examples', 'sync.d', '50-example.mjs');
    const result = spawnSync(exe, [script], { encoding: 'utf8', env: { ...process.env, BUN_BE_BUN: '1' } });
    expect(result.status).toBe(0);
  });
});

describe('release checksums', () => {
  const data = new TextEncoder().encode('keyhop');
  const sums = parseSums(`${sha256(data).toUpperCase()}  keyhop.exe\r\n${'0'.repeat(64)} *keyhop-hello.exe\n`);

  test('parses sha256sum and Windows line endings', () => {
    expect([...sums.keys()]).toEqual([...WINDOWS_ASSETS]);
    expect(sums.get('keyhop.exe')).toBe(sha256(data));
  });

  test('accepts a matching file and rejects a changed or unlisted one', () => {
    expect(() => verify('keyhop.exe', data, sums)).not.toThrow();
    expect(() => verify('keyhop-hello.exe', data, sums)).toThrow(/checksum/);
    expect(() => verify('other.exe', data, sums)).toThrow(/not listed/);
  });
});

// Windows Hello can't run in CI, but every WinRT call the helper makes short
// of the prompt can. CI builds the helper (bun run build:helper) first.
describe.if(process.platform === 'win32' && existsSync(windowsHelperPath))('keyhop-hello.exe', () => {
  test('selftest: WinRT buffers both ways and the async bridge work', () => {
    const result = spawnSync(windowsHelperPath, ['selftest'], { encoding: 'utf8' });
    expect(result.stderr).toBe('');
    expect(result.stdout.trim()).toMatch(/^buffer 0102ff 16 hello (supported|unavailable)$/);
    expect(result.status).toBe(0);
  });

  test('derive without a peer fails cleanly, before any prompt', () => {
    const result = spawnSync(windowsHelperPath, ['derive', 'unlock'], { input: '{}', encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr.trim()).toBe('Input needs peer.');
  });

  test('an unknown command prints usage', () => {
    const result = spawnSync(windowsHelperPath, ['nope'], { encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('Usage: keyhop-hello');
  });
});
