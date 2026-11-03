import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { isSupportedPlatform, macHelperPath, windowsHelperPath } from './auth.ts';
import { claudeRegistration } from './claude.ts';
import { loadConfig } from './config.ts';
import { appRoot, type Paths } from './paths.ts';
import type { Config } from './types.ts';
import { availableProviders, isSignedIn, locate, providerFor } from './providers.ts';
import { interpreterFor, listScripts } from './sync.ts';
import { availableVersion, compareVersions } from './update.ts';
import { VERSION } from './version.ts';

export type CheckStatus = 'ok' | 'warn' | 'fail' | 'info';

export interface Check {
  area: string;
  status: CheckStatus;
  detail: string;
  fix?: string;
}

/** Inspects the install without unlocking the vault. */
export async function runChecks(p: Paths): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (area: string, status: CheckStatus, detail: string, fix?: string) =>
    checks.push({ area, status, detail, fix });

  add('keyhop', 'info', `${VERSION} (${process.platform}/${process.arch}, ${appRoot === null ? `compiled: ${process.execPath}` : `source: ${appRoot}`}, data in ${p.dir})`);
  try {
    const latest = await availableVersion();
    if (compareVersions(latest, VERSION) > 0) add('update', 'warn', `${latest} is available`, 'keyhop update');
  } catch {
    add('update', 'info', 'could not check GitHub for a newer version');
  }

  if (!isSupportedPlatform()) {
    add('biometrics', 'fail', `${process.platform} has no supported biometric unlock`, 'Use macOS or Windows');
  } else if (process.platform === 'darwin') {
    if (existsSync(macHelperPath)) add('biometrics', 'ok', 'Touch ID helper built');
    else add('biometrics', 'fail', 'Touch ID helper missing', 'xcode-select --install, then rerun the installer');
  } else {
    if (existsSync(windowsHelperPath)) add('biometrics', 'ok', `Windows Hello helper present (${windowsHelperPath})`);
    else
      add(
        'biometrics',
        'fail',
        `Windows Hello helper missing (${windowsHelperPath})`,
        appRoot === null ? 'Rerun the installer' : 'bun run build:helper (needs the .NET SDK)'
      );
  }

  if (existsSync(p.key) && existsSync(p.vault)) add('vault', 'ok', 'created');
  else add('vault', 'fail', 'not created yet', 'keyhop setup');

  const config: Config = await loadConfig(p).catch((error: Error) => {
    add('config', 'fail', error.message);
    return {};
  });
  const linked = new Map<string, number>();
  for (const [, source] of Object.entries(config.secrets ?? {})) {
    try {
      const id = providerFor(source.ref).id;
      linked.set(id, (linked.get(id) ?? 0) + 1);
    } catch (error) {
      add('config', 'fail', (error as Error).message, `Fix ${p.config}`);
    }
  }
  const vaults = config.onePassword?.vaults?.length ?? 0;
  for (const provider of availableProviders()) {
    const count = linked.get(provider.id) ?? 0;
    const vaultCount = provider.id === '1password' ? vaults : 0;
    const what = [vaultCount && `${vaultCount} whole vault(s)`, count && `${count} secret(s)`].filter(Boolean).join(' + ');
    const binary = locate(provider);
    const area = `tool: ${provider.label}`;
    if (!binary) {
      if (what) add(area, 'fail', `${what} linked but ${provider.binary} is not installed`, provider.install);
      continue;
    }
    if (!what) {
      add(area, 'info', `installed, not linked`, 'keyhop setup');
      continue;
    }
    if (await isSignedIn(provider)) add(area, 'ok', `${what}, signed in`);
    else add(area, 'warn', `${what}, not signed in or locked`, provider.signInHint);
  }

  const scripts = await listScripts(p.syncDir);
  if (!scripts.length) add('sync.d', 'info', `no scripts in ${p.syncDir}`);
  for (const file of scripts) {
    const how = interpreterFor(join(p.syncDir, file));
    if ('error' in how) add(`sync.d: ${file}`, 'fail', how.error);
    else if (!how.command.includes('/') && !how.command.includes('\\') && !Bun.which(how.command))
      add(`sync.d: ${file}`, 'fail', `${how.command} not found`);
    else add(`sync.d: ${file}`, 'ok', `runs with ${how.command}`);
  }

  const claude = await claudeRegistration();
  if (claude === 'registered') add('claude code', 'ok', 'keyhop MCP server registered');
  else if (claude === 'missing') add('claude code', 'warn', 'not registered', 'keyhop setup');
  else add('claude code', 'info', 'claude CLI not found');
  return checks;
}

const ICONS: Record<CheckStatus, string> = { ok: '✓', warn: '!', fail: '✗', info: '·' };

export function formatChecks(checks: Check[]): string {
  const width = Math.max(...checks.map((c) => c.area.length));
  return checks
    .map((c) => `${ICONS[c.status]} ${c.area.padEnd(width)}  ${c.detail}${c.fix ? `\n  ${' '.repeat(width)}  → ${c.fix}` : ''}`)
    .join('\n');
}

export async function runDoctor(p: Paths, args: string[]): Promise<number> {
  const checks = await runChecks(p);
  process.stdout.write((args.includes('--json') ? JSON.stringify(checks, null, 2) : formatChecks(checks)) + '\n');
  return checks.some((c) => c.status === 'fail') ? 1 : 0;
}
