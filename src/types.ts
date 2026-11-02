/** Shared shapes for the config file, key file and decrypted vault. */

/** config.json: non-secret settings. Anything here can be read or edited by any process. */
export interface Config {
  /** Minutes the MCP server keeps the vault unlocked after a Touch ID / Hello prompt. */
  unlockMinutes?: number;
  /** Seconds each sync step may run. */
  stepTimeoutSeconds?: number;
  onePassword?: { account?: string };
  /** Secrets pulled from linked password tools; each tool is a `00-<tool>` sync step. */
  secrets?: Record<string, SecretSource>;
}

export interface SecretSource {
  /** Reference whose scheme picks the tool, e.g. op://Dev/GitHub/token or bw://GitHub */
  ref: string;
  description?: string;
}

export type ProviderId = '1password' | 'bitwarden' | 'lastpass' | 'pass' | 'keychain';

/** key.json: how to re-derive the vault key with the platform authenticator. */
export interface KeyFile {
  version: 1;
  platform: 'darwin' | 'win32';
  /** HKDF salt, base64. */
  salt: string;
  /** macOS: software P-256 public key to agree with. Windows: challenge to sign. Base64. */
  peer: string;
  /** macOS only: Secure Enclave key blob (usable only on this Mac's Secure Enclave). */
  seKey?: string;
  biometryOnly?: boolean;
}

export interface SecretEntry {
  value: string;
  /** Sync step that produced it, e.g. `00-1password` or `20-aws.sh`. */
  source: string;
  /** What exactly produced it: a tool ref, or a script name plus content hash. */
  origin: string;
  updatedAt: string;
}

export interface AllowedExecutable {
  /** Path as found on PATH when allowed, e.g. /opt/homebrew/bin/gh */
  path: string;
  /** What it resolved to then. */
  realPath: string;
  sha256: string;
}

export interface SecretPolicy {
  allow: AllowedExecutable[];
  /**
   * The origin these rules were granted for. If a sync fills the name from a
   * different ref or an edited script, the rules are cleared, so editing
   * config.json or sync.d can't route another item into an allowed name.
   */
  boundTo?: string;
}

/**
 * Decrypted vault. Policy lives here (not in config.json) so changing what a
 * secret may be injected into needs the same biometric unlock as reading it.
 */
export interface VaultData {
  version: 1;
  syncedAt: string | null;
  secrets: Record<string, SecretEntry>;
  policy: Record<string, SecretPolicy>;
}

export type AuthAction = 'unlock' | 'change';

/** Platform biometric backend (Secure Enclave + Touch ID, or Windows Hello). */
export interface Authenticator {
  /** `replace` overwrites an existing Windows Hello key; macOS keys are never shared. */
  create(options: { biometryOnly: boolean; replace?: boolean }): Promise<Pick<KeyFile, 'peer' | 'seKey' | 'biometryOnly'>>;
  /** Prompts the user, then returns a stable secret for this key file. */
  derive(key: KeyFile, action: AuthAction): Promise<Buffer>;
}

export interface StepResult {
  step: string;
  count: number;
}

export interface SyncResult {
  steps: StepResult[];
  total: number;
  removed: string[];
  /** Names whose origin changed, so their allowlists were cleared. */
  rulesCleared: string[];
}
