import { afterEach, describe, expect, test } from 'bun:test';
import { chmod, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { itemsToSecrets, parseJsonObjects, readVaults, type OpItem } from '../src/onepassword.ts';
import { planSteps } from '../src/sync.ts';
import { tempHome } from './support.ts';

const unix = process.platform !== 'win32';

const items: OpItem[] = [
  {
    id: 'i2',
    title: 'GitHub',
    fields: [
      { id: 'username', type: 'STRING', purpose: 'USERNAME', label: 'username', value: 'kyle' },
      { id: 'password', type: 'CONCEALED', purpose: 'PASSWORD', label: 'password', value: 'gh-pass' },
      { id: 'totp', type: 'OTP', label: 'one-time password', value: 'otpauth://x' },
      { id: 'tok', type: 'CONCEALED', label: 'token', value: 'gh-token', section: { id: 'api' } },
    ],
  },
  { id: 'i1', title: 'GitHub', fields: [{ id: 'password', type: 'CONCEALED', label: 'password', value: 'other' }] },
  { id: 'i3', title: 'Keyhop', fields: [{ id: 'x', type: 'CONCEALED', label: 'home', value: 'v' }] },
  { id: 'i4', title: 'Notes', fields: [{ id: 'notesPlain', type: 'STRING', purpose: 'NOTES', label: 'notesPlain', value: 'n' }] },
  { id: 'i5', title: 'Empty', fields: [{ id: 'password', type: 'CONCEALED', label: 'password', value: '' }] },
];

describe('parseJsonObjects', () => {
  test('reads back-to-back objects, including braces inside strings', () => {
    const text = '{"id":"a","v":"}{\\""}\n{"id":"b"}\n';
    expect(parseJsonObjects(text).map((o) => (o as { id: string }).id)).toEqual(['a', 'b']);
  });

  test('reads an array', () => {
    expect(parseJsonObjects('[{"id":"a"}]')).toHaveLength(1);
  });

  test('rejects truncated output', () => {
    expect(() => parseJsonObjects('{"id":"a"')).toThrow();
  });
});

describe('itemsToSecrets', () => {
  test('hidden fields only by default; clashes get a suffix in a stable order', () => {
    const out = itemsToSecrets(items, 'v1', undefined, new Set());
    expect(Object.keys(out).sort()).toEqual(['GITHUB_PASSWORD', 'GITHUB_PASSWORD_2', 'GITHUB_TOKEN']);
    expect(out.GITHUB_PASSWORD!.origin).toBe('op://v1/i1/password');
    expect(out.GITHUB_TOKEN!.origin).toBe('op://v1/i2/api/tok');
  });

  test('all fields adds usernames and notes but never one-time codes', () => {
    const out = itemsToSecrets(items, 'v1', 'all', new Set());
    expect(out.GITHUB_USERNAME?.value).toBe('kyle');
    expect(out.NOTES_NOTES?.value).toBe('n');
    expect(Object.values(out).some((s) => s.value.startsWith('otpauth'))).toBe(false);
  });

  test('names already taken are not overwritten', () => {
    const out = itemsToSecrets(items, 'v1', undefined, new Set(['GITHUB_PASSWORD']));
    expect(out.GITHUB_PASSWORD).toBeUndefined();
    expect(out.GITHUB_PASSWORD_2).toBeDefined();
  });

  test('reserved names are skipped', () => {
    const out = itemsToSecrets(items, 'v1', undefined, new Set());
    expect(Object.keys(out).some((n) => n.startsWith('KEYHOP'))).toBe(false);
  });
});

describe.if(unix)('readVaults through op', () => {
  const originalPath = process.env.PATH;
  const cleanups: (() => Promise<void>)[] = [];
  afterEach(async () => {
    process.env.PATH = originalPath;
    await Promise.all(cleanups.splice(0).map((c) => c()));
  });

  test('fetches every listed item and keeps linked names', async () => {
    const { p, cleanup } = await tempHome();
    cleanups.push(cleanup);
    const bin = join(p.dir, 'bin');
    await mkdir(bin);
    // Fake op: 8 items (more than one batch); like real op, `item get -` is refused.
    await writeFile(
      join(bin, 'op'),
      `#!/bin/sh
case "$1 $2" in
  "item list") echo '[{"id":"i1"},{"id":"i2"},{"id":"i3"},{"id":"i4"},{"id":"i5"},{"id":"i6"},{"id":"i7"},{"id":"i8"}]' ;;
  "item get")
    case "$3" in
      i1) echo '{"id":"i1","title":"Stripe","fields":[{"id":"k","type":"CONCEALED","label":"key","value":"sk_1"}]}' ;;
      i2) echo '{"id":"i2","title":"Linked","fields":[{"id":"k","type":"CONCEALED","label":"key","value":"x"}]}' ;;
      i[3-8]) echo "{\\"id\\":\\"$3\\",\\"title\\":\\"Item $3\\",\\"fields\\":[{\\"id\\":\\"k\\",\\"type\\":\\"CONCEALED\\",\\"label\\":\\"key\\",\\"value\\":\\"v$3\\"}]}" ;;
      *) exit 9 ;;
    esac ;;
  *) exit 1 ;;
esac
`
    );
    await chmod(join(bin, 'op'), 0o755);
    process.env.PATH = `${bin}:${originalPath}`;
    const progress: string[] = [];
    const out = await readVaults({ onePassword: { vaults: [{ id: 'v1' }] } }, 2000, new Set(['LINKED_KEY']), (m) =>
      progress.push(m)
    );
    // One update for the listing, then one per item.
    expect(progress).toHaveLength(9);
    expect(progress.some((m) => /sk_1|vi\d/.test(m))).toBe(false);
    expect(out.STRIPE_KEY).toEqual({ value: 'sk_1', origin: 'op://v1/i1/k' });
    expect(out.ITEM_I8_KEY?.value).toBe('vi8');
    expect(Object.keys(out)).toHaveLength(8);
    expect(out.LINKED_KEY).toBeUndefined();
    expect(out.LINKED_KEY_2).toBeDefined();
  });

  test('a vault alone makes a 00-1password step', async () => {
    const { p, cleanup } = await tempHome();
    cleanups.push(cleanup);
    const steps = await planSteps({ onePassword: { vaults: [{ id: 'v1' }] } }, p.syncDir, 1000);
    expect(steps.map((s) => s.name)).toEqual(['00-1password']);
  });
});
