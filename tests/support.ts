import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { paths, type Paths } from '../src/paths.ts';
import { VaultStore } from '../src/store.ts';
import type { AuthAction, Authenticator } from '../src/types.ts';

/** Stands in for Touch ID / Windows Hello: a fixed secret and a call log. */
export function fakeAuth(): Authenticator & { prompts: AuthAction[]; cancelNext: boolean } {
  const secret = Buffer.alloc(32, 7);
  const auth = {
    prompts: [] as AuthAction[],
    cancelNext: false,
    async create() {
      return { peer: Buffer.alloc(32, 1).toString('base64') };
    },
    async derive(_key: unknown, action: AuthAction) {
      auth.prompts.push(action);
      if (auth.cancelNext) {
        auth.cancelNext = false;
        throw new Error('cancelled');
      }
      return secret;
    },
  };
  return auth;
}

export async function tempHome(): Promise<{ p: Paths; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), 'keyhop-test-'));
  return { p: paths(dir), cleanup: () => rm(dir, { recursive: true, force: true }) };
}

export async function newStore(p: Paths, auth = fakeAuth()): Promise<VaultStore> {
  const store = new VaultStore(p, auth, 0);
  await store.initialize({ biometryOnly: false });
  return store;
}
