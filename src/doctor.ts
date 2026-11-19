import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { macHelperPath, readKeyFile, supportsBiometricAuth, windowsHelperPath } from './auth.ts';
import { claudeRegistration } from './claude.ts';
import { loadConfig } from './config.ts';
import type { Paths } from './paths.ts';
import type { Config, KeyFile } from './types.ts';
import { availableProviders, isSignedIn, locate, providerFor } from './providers.ts';
import { interpreterFor, listScripts } from './sync.ts';
import { compareVersions, latestVersion, resolveRef } from './update.ts';
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

  add('keyhop', 'info', `${VERSION} (${process.platform}/${process.arch}, data in ${p.dir})`);
  try {
    const latest = await latestVersion(await resolveRef('main'));
    if (compareVersions(latest, VERSION) > 0) add('update', 'warn', `${latest} is available`, 'keyhop update');
  } catch {
    add('update', 'info', 'could not check GitHub for a newer version');
  }

  let key: KeyFile | undefined;
  const hasKey = existsSync(p.key);
  if (hasKey) {
    key = await readKeyFile(p.key).catch((error: Error) => {
      add('vault', 'fail', error.message);
      return undefined;
    });
  }
  if (key?.auth === 'auto') {
    if (key.platform !== process.platform)
      add('authentication', 'fail', `This automatic vault was created on ${key.platform}`);
    else if (process.platform === 'win32' && !existsSync(windowsHelperPath))
      add('authentication', 'fail', 'The Windows helper for automatic unlock is missing', 'Rerun the installer');
    else
      add('authentication', 'ok', `Automatic unlock via ${process.platform === 'win32' ? 'Windows account protection (DPAPI)' : 'an owner-only key file'}`);
  } else if (!supportsBiometricAuth()) {
    add('biometrics', 'info', `${process.platform} supports automatic unlock`, 'keyhop setup --auto-auth');
  } else if (process.platform === 'darwin') {
    if (existsSync(macHelperPath)) add('biometrics', 'ok', 'Touch ID helper built');
    else add('biometrics', 'fail', 'Touch ID helper missing', 'xcode-select --install, then rerun the installer');
  } else {
    if (existsSync(windowsHelperPath)) add('biometrics', 'ok', 'Windows Hello helper present');
    else add('biometrics', 'fail', 'Windows Hello helper (keyhop-hello.exe) is missing', 'Rerun the installer');
  }

  if (key && existsSync(p.vault)) add('vault', 'ok', 'created');
  else if (!hasKey || key) add('vault', 'fail', 'not created yet', supportsBiometricAuth() ? 'keyhop setup' : 'keyhop setup --auto-auth');

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
