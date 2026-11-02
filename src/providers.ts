/**
 * Password tools keyhop can read from. Each is picked by the scheme of a
 * secret's ref and read with the tool's own CLI, so its usual sign-in (for
 * example 1Password's desktop-app unlock) applies.
 */

import { existsSync } from 'node:fs';
import { runProcess } from './process.ts';
import type { Config, ProviderId } from './types.ts';

export interface Provider {
  id: ProviderId;
  label: string;
  scheme: string;
  binary: string;
  example: string;
  platforms?: NodeJS.Platform[];
  install: string;
  /** argv (without the binary) that prints the secret. */
  readArgs(ref: string, config: Config): string[];
  /** argv that exits 0 when the tool is signed in / unlocked. */
  statusArgs: string[];
  signInHint: string;
  /** Some tools print the secret followed by extra lines. */
  firstLineOnly?: boolean;
}

export const PROVIDERS: Provider[] = [
  {
    id: '1password',
    label: '1Password',
    scheme: 'op://',
    binary: 'op',
    example: 'op://Dev/GitHub/token',
    install: 'brew install 1password-cli / winget install AgileBits.1Password.CLI',
    readArgs: (ref, config) => [
      'read',
      '--no-newline',
      ...(config.onePassword?.account ? ['--account', config.onePassword.account] : []),
      ref,
    ],
    statusArgs: ['whoami'],
    signInHint:
      'Turn on 1Password > Settings > Developer > "Integrate with 1Password CLI", or run: op signin',
  },
  {
    id: 'bitwarden',
    label: 'Bitwarden',
    scheme: 'bw://',
    binary: 'bw',
    example: 'bw://GitHub token',
    install: 'brew install bitwarden-cli / winget install Bitwarden.CLI',
    readArgs: (ref) => ['get', 'password', ref.slice('bw://'.length)],
    statusArgs: ['unlock', '--check'],
    signInHint: 'Run: export BW_SESSION="$(bw unlock --raw)" before keyhop sync',
  },
  {
    id: 'lastpass',
    label: 'LastPass',
    scheme: 'lastpass://',
    binary: 'lpass',
    example: 'lastpass://Dev/GitHub',
    install: 'brew install lastpass-cli',
    readArgs: (ref) => ['show', '--password', ref.slice('lastpass://'.length)],
    statusArgs: ['status', '--quiet'],
    signInHint: 'Run: lpass login <email>',
  },
  {
    id: 'pass',
    label: 'pass (password-store)',
    scheme: 'pass://',
    binary: 'pass',
    example: 'pass://dev/github-token',
    install: 'brew install pass',
    readArgs: (ref) => ['show', ref.slice('pass://'.length)],
    statusArgs: ['ls'],
    signInHint: 'Unlock your GPG key (gpg-agent) and run: pass ls',
    firstLineOnly: true,
  },
  {
    id: 'keychain',
    label: 'macOS Keychain',
    scheme: 'keychain://',
    binary: '/usr/bin/security',
    example: 'keychain://my-service',
    platforms: ['darwin'],
    install: 'Built into macOS',
    readArgs: (ref) => ['find-generic-password', '-w', '-s', ref.slice('keychain://'.length)],
    statusArgs: ['show-keychain-info'],
    signInHint: 'Unlock your login keychain',
    firstLineOnly: true,
  },
];

export function providerFor(ref: string): Provider {
  const provider = PROVIDERS.find((p) => ref.startsWith(p.scheme));
  if (!provider) {
    const schemes = PROVIDERS.map((p) => p.scheme).join(', ');
    throw new Error(`Unknown reference "${ref}": start it with one of ${schemes}`);
  }
  if (ref.length === provider.scheme.length) throw new Error(`Reference "${ref}" names no item.`);
  return provider;
}

export function availableProviders(): Provider[] {
  return PROVIDERS.filter((p) => !p.platforms || p.platforms.includes(process.platform));
}

export function locate(provider: Provider): string | null {
  if (provider.binary.startsWith('/')) return existsSync(provider.binary) ? provider.binary : null;
  return Bun.which(provider.binary);
}

export async function isSignedIn(provider: Provider): Promise<boolean> {
  const binary = locate(provider);
  if (!binary) return false;
  try {
    const result = await runProcess(binary, provider.statusArgs, { timeoutMs: 15_000 });
    return result.code === 0;
  } catch {
    return false;
  }
}

export async function readSecret(ref: string, config: Config, timeoutMs: number): Promise<string> {
  const provider = providerFor(ref);
  const binary = locate(provider);
  if (!binary) throw new Error(`${provider.label} CLI (${provider.binary}) not found. Install: ${provider.install}`);
  const result = await runProcess(binary, provider.readArgs(ref, config), { timeoutMs });
  if (result.timedOut) throw new Error(`${provider.label} timed out reading ${ref}.`);
  if (result.code !== 0)
    throw new Error(
      `${provider.label} could not read ${ref}: ${result.stderr.trim() || `exit ${result.code}`}. ${provider.signInHint}`
    );
  const value = provider.firstLineOnly ? result.stdout.split(/\r?\n/)[0]! : result.stdout.replace(/\r?\n$/, '');
  if (!value) throw new Error(`${provider.label} returned an empty value for ${ref}.`);
  return value;
}
