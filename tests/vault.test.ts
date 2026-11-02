import { afterEach, describe, expect, setSystemTime, test } from 'bun:test';
import { readFile, writeFile } from 'node:fs/promises';
import { decryptVault, deriveKek, emptyVault, encryptVault, VaultError } from '../src/vault.ts';
import { VaultStore } from '../src/store.ts';
import { fakeAuth, newStore, tempHome } from './support.ts';

describe('vault encryption', () => {
  const kek = deriveKek(Buffer.alloc(32, 3), Buffer.alloc(32, 4));

  test('round-trips', () => {
    const vault = emptyVault();
    vault.secrets.A = { value: 'secret-value', source: 'x', origin: 'x', updatedAt: 'now' };
    expect(decryptVault(encryptVault(vault, kek), kek)).toEqual(vault);
  });

  test('ciphertext does not contain the value', () => {
    const vault = emptyVault();
    vault.secrets.A = { value: 'secret-value', source: 'x', origin: 'x', updatedAt: 'now' };
    expect(encryptVault(vault, kek)).not.toContain('secret-value');
  });

  test('rejects a modified file', () => {
    const envelope = JSON.parse(encryptVault(emptyVault(), kek));
    const ct = Buffer.from(envelope.ct, 'base64');
    ct[0]! ^= 1;
    envelope.ct = ct.toString('base64');
    expect(() => decryptVault(JSON.stringify(envelope), kek)).toThrow(VaultError);
  });

  test('rejects the wrong key', () => {
    const other = deriveKek(Buffer.alloc(32, 9), Buffer.alloc(32, 4));
    expect(() => decryptVault(encryptVault(emptyVault(), kek), other)).toThrow(VaultError);
  });
});

describe('VaultStore', () => {
  let cleanup: () => Promise<void> = async () => {};
  afterEach(async () => {
    setSystemTime();
    await cleanup();
  });

  test('initialize prompts once and later reads reuse the key', async () => {
    const home = await tempHome();
    cleanup = home.cleanup;
    const auth = fakeAuth();
    const store = await newStore(home.p, auth);
    await store.read();
    await store.read();
    expect(auth.prompts).toEqual(['unlock']);
  });

  test('a rule change re-prompts once the last prompt is over a minute old', async () => {
    const home = await tempHome();
    cleanup = home.cleanup;
    const auth = fakeAuth();
    setSystemTime(new Date('2026-01-01T00:00:00Z'));
    const store = await newStore(home.p, auth);
    await store.read('change');
    expect(auth.prompts).toEqual(['unlock']);
    setSystemTime(new Date('2026-01-01T00:02:00Z'));
    await store.read('change');
    expect(auth.prompts).toEqual(['unlock', 'change']);
  });

  test('a new process must prompt again', async () => {
    const home = await tempHome();
    cleanup = home.cleanup;
    await newStore(home.p);
    const auth = fakeAuth();
    await new VaultStore(home.p, auth, 0).read();
    expect(auth.prompts).toEqual(['unlock']);
  });

  test('lock forgets the key', async () => {
    const home = await tempHome();
    cleanup = home.cleanup;
    const auth = fakeAuth();
    const store = await newStore(home.p, auth);
    store.lock();
    expect(store.unlocked).toBe(false);
    await store.read();
    expect(auth.prompts).toEqual(['unlock', 'unlock']);
  });

  test('a tampered vault file fails and leaves the store locked', async () => {
    const home = await tempHome();
    cleanup = home.cleanup;
    const store = await newStore(home.p);
    const envelope = JSON.parse(await readFile(home.p.vault, 'utf8'));
    envelope.tag = Buffer.alloc(16).toString('base64');
    await writeFile(home.p.vault, JSON.stringify(envelope));
    expect(store.read()).rejects.toThrow(VaultError);
    await Bun.sleep(0);
    expect(store.unlocked).toBe(false);
  });
});
