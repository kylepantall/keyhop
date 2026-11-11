/**
 * End-to-end test seam: a stand-in for Touch ID / Windows Hello and the native
 * dialog, so `keyhop client …` can be run for real against a throwaway vault.
 *
 * It can't reach a real vault, even if someone sets the variables:
 * - it needs NODE_ENV=test and KEYHOP_TEST_AUTH=1, an explicit KEYHOP_HOME that
 *   isn't the default data folder, and a git checkout: installs (source
 *   tarball, `git ls-files` copy, or the compiled Windows release) have no .git;
 * - it only derives a key for key files it created itself (a marker peer and
 *   no Secure Enclave blob). A real vault's key comes from the Secure Enclave /
 *   Hello key, which this never touches, so its AES-GCM vault won't decrypt.
 */

import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import type { Decision, Dialog } from './approve.ts';
import { appRoot, compiled } from './paths.ts';
import type { Authenticator, KeyFile } from './types.ts';

const TEST_PEER = Buffer.from('keyhop-test-authenticator-not-a-real-key').toString('base64');

function defaultDataDirs(): string[] {
  return [
    join(process.env.XDG_CONFIG_HOME ?? join(homedir(), '.config'), 'keyhop'),
    join(homedir(), '.config', 'keyhop'),
    join(process.env.APPDATA ?? join(homedir(), 'AppData', 'Roaming'), 'keyhop'),
  ].map((dir) => resolve(dir));
}

export function testSeamEnabled(env: NodeJS.ProcessEnv = process.env): boolean {
  if (compiled || env.NODE_ENV !== 'test' || env.KEYHOP_TEST_AUTH !== '1' || !env.KEYHOP_HOME) return false;
  if (!existsSync(join(appRoot, '.git'))) return false;
  return !defaultDataDirs().includes(resolve(env.KEYHOP_HOME));
}

export function testAuthenticator(): Authenticator {
  return {
    async create() {
      return { peer: TEST_PEER };
    },
    async derive(key: KeyFile) {
      if (key.peer !== TEST_PEER || key.seKey) throw new Error('The test authenticator only opens vaults it created.');
      if (process.env.KEYHOP_TEST_CANCEL === '1') {
        const { AuthCancelledError } = await import('./auth.ts');
        throw new AuthCancelledError('Authentication was cancelled.');
      }
      return createHash('sha256').update('keyhop test authenticator').digest();
    },
  };
}

/** Answers every dialog with KEYHOP_TEST_DIALOG (deny, once or always; default deny). */
export function testDialog(): Dialog {
  return async () => {
    const answer = process.env.KEYHOP_TEST_DIALOG;
    return answer === 'once' || answer === 'always' ? (answer as Decision) : 'deny';
  };
}
