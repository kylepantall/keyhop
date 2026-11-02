import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import type { VaultData } from './types.ts';

const AAD = Buffer.from('keyhop-vault-v1');
const INFO = 'keyhop vault v1';

export class VaultError extends Error {}

export function emptyVault(): VaultData {
  return { version: 1, syncedAt: null, secrets: {}, policy: {} };
}

/** Vault key from the authenticator's secret; the salt is per install. */
export function deriveKek(secret: Buffer, salt: Buffer): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, salt, INFO, 32));
}

export function encryptVault(data: VaultData, kek: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', kek, iv);
  cipher.setAAD(AAD);
  const ct = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  return JSON.stringify({
    v: 1,
    iv: iv.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    ct: ct.toString('base64'),
  });
}

export function decryptVault(text: string, kek: Buffer): VaultData {
  let envelope: { v?: number; iv?: string; tag?: string; ct?: string };
  try {
    envelope = JSON.parse(text);
  } catch {
    throw new VaultError('Vault file is not valid JSON.');
  }
  if (envelope.v !== 1 || !envelope.iv || !envelope.tag || !envelope.ct)
    throw new VaultError('Vault file has an unknown format.');
  try {
    const decipher = createDecipheriv('aes-256-gcm', kek, Buffer.from(envelope.iv, 'base64'));
    decipher.setAAD(AAD);
    decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
    const plain = Buffer.concat([
      decipher.update(Buffer.from(envelope.ct, 'base64')),
      decipher.final(),
    ]);
    return JSON.parse(plain.toString('utf8')) as VaultData;
  } catch {
    throw new VaultError('Vault could not be decrypted: wrong key or the file was modified.');
  }
}
