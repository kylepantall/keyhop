import { randomBytes } from 'node:crypto';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { writePrivate, type Paths } from './paths.ts';
import { decryptVault, deriveKek, emptyVault, encryptVault } from './vault.ts';
import type { AuthAction, Authenticator, KeyFile, VaultData } from './types.ts';

const RECENT_PROMPT_MS = 60_000;

/**
 * The encrypted vault plus the in-memory key. The key is kept for `ttlMs`
 * after a prompt (0: for the life of the process); changes to access rules
 * prompt again unless the user just answered a prompt. Operations run one at a
 * time, so concurrent calls share one prompt and never interleave writes.
 */
export class VaultStore {
  private kek: Buffer | null = null;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private promptedAt = 0;
  private queue: Promise<unknown> = Promise.resolve();

  constructor(
    readonly paths: Paths,
    private readonly auth: Authenticator,
    private readonly ttlMs: number
  ) {}

  get initialized(): boolean {
    return existsSync(this.paths.key) && existsSync(this.paths.vault);
  }

  get unlocked(): boolean {
    return this.kek !== null;
  }

  /**
   * Creates the platform key and an empty vault. Refuses while a key file
   * exists, so deleting vault.enc alone can't trick setup into replacing it.
   */
  initialize(options: { biometryOnly: boolean; replace?: boolean }): Promise<void> {
    return this.exclusive(async () => {
      if (existsSync(this.paths.key) && !options.replace)
        throw new Error(`${this.paths.key} already exists. To start over (losing the vault), run: keyhop setup --reset`);
      const created = await this.auth.create(options);
      const key: KeyFile = {
        version: 1,
        platform: process.platform as KeyFile['platform'],
        salt: randomBytes(32).toString('base64'),
        ...created,
      };
      this.remember(deriveKek(await this.auth.derive(key, 'unlock'), Buffer.from(key.salt, 'base64')));
      await writePrivate(this.paths.key, JSON.stringify(key, null, 2) + '\n');
      await this.write(emptyVault());
    });
  }

  read(action: AuthAction = 'unlock'): Promise<VaultData> {
    return this.exclusive(() => this.readUnlocked(action));
  }

  update<T>(action: AuthAction, change: (vault: VaultData) => T): Promise<T> {
    return this.exclusive(async () => {
      const vault = await this.readUnlocked(action);
      const result = change(vault);
      await this.write(vault);
      return result;
    });
  }

  lock(): void {
    this.kek?.fill(0);
    this.kek = null;
    clearTimeout(this.timer);
  }

  private exclusive<T>(work: () => Promise<T>): Promise<T> {
    const run = this.queue.then(work, work);
    this.queue = run.catch(() => undefined);
    return run;
  }

  private async readUnlocked(action: AuthAction): Promise<VaultData> {
    if (!this.initialized) throw new Error('No vault yet. Run: keyhop setup');
    // A rule change needs a fresh prompt, unless the user just answered one.
    const stale = Date.now() - this.promptedAt > RECENT_PROMPT_MS;
    if (!this.kek || (action === 'change' && stale)) {
      const key = JSON.parse(await readFile(this.paths.key, 'utf8')) as KeyFile;
      this.remember(deriveKek(await this.auth.derive(key, action), Buffer.from(key.salt, 'base64')));
    }
    try {
      return decryptVault(await readFile(this.paths.vault, 'utf8'), this.kek!);
    } catch (error) {
      this.lock();
      throw error;
    }
  }

  private async write(vault: VaultData): Promise<void> {
    if (!this.kek) throw new Error('Vault is locked.');
    await writePrivate(this.paths.vault, encryptVault(vault, this.kek));
  }

  private remember(kek: Buffer): void {
    this.lock();
    this.kek = kek;
    this.promptedAt = Date.now();
    if (this.ttlMs > 0) {
      this.timer = setTimeout(() => this.lock(), this.ttlMs);
      this.timer.unref?.();
    }
  }
}
