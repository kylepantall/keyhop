/** `keyhop setup`: guided first run — vault, password tools, allowlists, first sync. */

import * as ui from '@clack/prompts';
import { copyFile, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { isSupportedPlatform } from './auth.ts';
import { claudeRegistration, registerWithClaude } from './claude.ts';
import { assertName, loadConfig, saveConfig } from './config.ts';
import { formatChecks, runChecks } from './doctor.ts';
import { opJson, toSecretName } from './onepassword.ts';
import { appRoot } from './paths.ts';
import { availableProviders, isSignedIn, locate, providerFor, type Provider } from './providers.ts';
import { changeAllowed, resolveAllowed, syncVault } from './secrets.ts';
import type { VaultStore } from './store.ts';
import type { Config } from './types.ts';

interface Pending {
  name: string;
  ref: string;
  allow: string[];
}

function bail<T>(value: T): Exclude<T, symbol> {
  if (ui.isCancel(value)) {
    ui.cancel('Setup cancelled; nothing after the last completed step was saved.');
    process.exit(1);
  }
  return value as Exclude<T, symbol>;
}

function validateName(taken: Set<string>) {
  return (value: string | undefined) => {
    try {
      assertName(value ?? '');
    } catch (error) {
      return (error as Error).message;
    }
    return taken.has(value!) ? `${value} is already used.` : undefined;
  };
}

function validateCommands(value: string | undefined): string | undefined {
  try {
    resolveAllowed(splitList(value));
  } catch (error) {
    return (error as Error).message;
  }
  return undefined;
}

function splitList(value: string | undefined): string[] {
  return (value ?? '').split(/[\s,]+/).filter(Boolean);
}

async function listJson<T>(op: string, args: string[], config: Config): Promise<T> {
  return JSON.parse(await opJson(op, args, config, 60_000)) as T;
}

/** Links whole vaults, so every item (and every new one) syncs without picking. */
async function linkVaults(op: string, config: Config): Promise<void> {
  const vaults = await listJson<{ id: string; name: string }[]>(op, ['vault', 'list'], config);
  if (!vaults.length) {
    ui.log.warn('No 1Password vaults found.');
    return;
  }
  const previous = new Map((config.onePassword?.vaults ?? []).map((v) => [v.id, v]));
  const chosen = bail(
    await ui.multiselect({
      message: '1Password vaults to sync in full',
      options: vaults.map((v) => ({ value: v.id, label: v.name, hint: previous.has(v.id) ? 'linked' : undefined })),
      initialValues: vaults.filter((v) => previous.has(v.id)).map((v) => v.id),
      required: false,
    })
  );
  if (!chosen.length) {
    config.onePassword = { ...config.onePassword, vaults: [] };
    return;
  }
  const fields = bail(
    await ui.select({
      message: 'Which fields become secrets?',
      options: [
        { value: 'concealed' as const, label: 'Hidden fields only', hint: 'passwords, API keys, credentials; recommended' },
        { value: 'all' as const, label: 'Every field with a value', hint: 'adds usernames, URLs and notes' },
      ],
    })
  );
  config.onePassword = {
    ...config.onePassword,
    vaults: chosen.map((id) => ({ id, name: vaults.find((v) => v.id === id)!.name, fields })),
  };
  ui.log.success('Every item syncs as ITEM_FIELD, e.g. GITHUB_CREDENTIAL. See the names with: keyhop list');
}

/** Vault → item → field picker, so nobody has to type an op:// reference. */
async function pickFromOnePassword(op: string, config: Config): Promise<{ ref: string; suggested: string } | null> {
  const vaults = await listJson<{ id: string; name: string }[]>(op, ['vault', 'list'], config);
  if (!vaults.length) return null;
  const vault = bail(
    await ui.select({ message: '1Password vault', options: vaults.map((v) => ({ value: v.id, label: v.name })) })
  );
  const items = await listJson<{ id: string; title: string; category: string }[]>(op, ['item', 'list', '--vault', vault], config);
  if (!items.length) {
    ui.log.warn('That vault has no items.');
    return null;
  }
  const itemId = bail(
    await ui.autocomplete({
      message: 'Item (type to filter)',
      options: items.map((i) => ({ value: i.id, label: i.title, hint: i.category.toLowerCase() })),
    })
  );
  const item = await listJson<{ title: string; fields?: { label?: string; type?: string; purpose?: string; reference?: string }[] }>(
    op,
    ['item', 'get', itemId, '--vault', vault],
    config
  );
  const fields = (item.fields ?? []).filter((f) => f.reference);
  if (!fields.length) {
    ui.log.warn('That item has no fields to link.');
    return null;
  }
  // Concealed fields (passwords, credentials, API keys) first.
  fields.sort((a, b) => Number(b.type === 'CONCEALED') - Number(a.type === 'CONCEALED'));
  const field = bail(
    await ui.select({
      message: 'Field',
      options: fields.map((f) => ({ value: f, label: f.label || f.purpose || 'field', hint: f.type?.toLowerCase() })),
    })
  );
  return { ref: field.reference!, suggested: toSecretName(item.title, field.label ?? '') };
}

async function linkTool(provider: Provider, taken: Set<string>, config: Config): Promise<Pending[]> {
  const binary = locate(provider)!;
  if (!(await isSignedIn(provider))) {
    ui.log.warn(`${provider.label} is not signed in or is locked. ${provider.signInHint}`);
    if (!bail(await ui.confirm({ message: `Link ${provider.label} anyway?`, initialValue: false }))) return [];
  }
  if (provider.id === '1password') {
    const mode = bail(
      await ui.select({
        message: 'How should keyhop pull from 1Password?',
        options: [
          { value: 'vaults', label: 'Whole vaults', hint: 'every item, and new ones on each sync; recommended' },
          { value: 'items', label: 'Pick items one by one' },
        ],
      })
    );
    if (mode === 'vaults') {
      await linkVaults(binary, config).catch((error: Error) => ui.log.error(`Could not list 1Password vaults: ${error.message}`));
      return [];
    }
  }
  const linked: Pending[] = [];
  for (;;) {
    let ref: string;
    let suggested = '';
    if (provider.id === '1password') {
      const picked = await pickFromOnePassword(binary, config).catch((error: Error) => {
        ui.log.error(`Could not browse 1Password: ${error.message}`);
        return null;
      });
      if (!picked) break;
      ({ ref, suggested } = picked);
    } else {
      ref = bail(
        await ui.text({
          message: `${provider.label} reference`,
          placeholder: provider.example,
          initialValue: provider.scheme,
          validate: (value) => {
            try {
              if (providerFor(value ?? '').id !== provider.id) return `Start it with ${provider.scheme}`;
            } catch (error) {
              return (error as Error).message;
            }
            return undefined;
          },
        })
      );
      suggested = toSecretName(ref.slice(provider.scheme.length).split('/').pop() ?? '');
    }
    const name = bail(
      await ui.text({
        message: 'Name (the environment variable Claude asks for)',
        initialValue: suggested,
        validate: validateName(taken),
      })
    );
    const commands = bail(
      await ui.text({
        message: `Commands ${name} may be given to (space or comma separated, e.g. gh npm). Leave empty to decide later.`,
        defaultValue: '',
        validate: validateCommands,
      })
    );
    taken.add(name);
    linked.push({ name, ref, allow: resolveAllowed(splitList(commands)) });
    if (!bail(await ui.confirm({ message: `Add another from ${provider.label}?`, initialValue: false }))) break;
  }
  return linked;
}

async function offerStarterScript(syncDir: string): Promise<void> {
  await mkdir(syncDir, { recursive: true, mode: 0o700 });
  const add = bail(
    await ui.confirm({
      message: `Add your own sync script too? Scripts in ${syncDir} run in number order (10-…, 20-…).`,
      initialValue: false,
    })
  );
  if (!add) return;
  const windows = process.platform === 'win32';
  const file = bail(
    await ui.select({
      message: 'Language',
      options: [
        windows ? { value: '50-example.ps1', label: 'PowerShell (.ps1)' } : { value: '50-example.sh', label: 'Shell (.sh)' },
        { value: '50-example.mjs', label: 'JavaScript (.mjs, runs with Bun)' },
        windows ? { value: '50-example.sh', label: 'Shell (.sh, needs Git Bash)' } : { value: '50-example.ps1', label: 'PowerShell (.ps1, needs pwsh)' },
      ],
    })
  );
  const target = join(syncDir, `_${file}`);
  if (existsSync(target)) {
    ui.log.info(`${target} already exists.`);
    return;
  }
  await copyFile(join(appRoot, 'examples', 'sync.d', file), target);
  ui.log.success(`Wrote ${target}. Edit it, then rename it without the leading _ to enable it.`);
}

export async function runSetup(store: VaultStore, args: string[] = []): Promise<number> {
  ui.intro('keyhop setup');
  if (!isSupportedPlatform()) {
    ui.cancel('keyhop needs Touch ID (macOS) or Windows Hello (Windows).');
    return 1;
  }
  const reset = args.includes('--reset');
  if (reset) {
    const sure = bail(
      await ui.confirm({
        message: `Delete the vault in ${store.paths.dir} and start over? Secrets can be re-synced; allowlists are lost.`,
        initialValue: false,
      })
    );
    if (!sure) return 1;
  }

  if (!store.initialized || reset) {
    if (!reset && existsSync(store.paths.key)) {
      ui.cancel(`${store.paths.vault} is missing but its key file is still there. Rerun with --reset to start over.`);
      return 1;
    }
    const biometryOnly =
      process.platform === 'darwin' &&
      bail(
        await ui.select({
          message: 'How should the vault unlock?',
          options: [
            { value: false, label: 'Touch ID, or your login password as a fallback', hint: 'recommended' },
            { value: true, label: 'Touch ID only', hint: 'adding a fingerprint makes the vault unreadable' },
          ],
        })
      );
    ui.log.step(process.platform === 'darwin' ? 'Creating your vault — confirm with Touch ID.' : 'Creating your vault — confirm with Windows Hello (twice).');
    await store.initialize({ biometryOnly, replace: reset });
    ui.log.success(`Vault created in ${store.paths.dir}`);
  } else {
    ui.log.info(`Using the existing vault in ${store.paths.dir}`);
  }

  const config: Config = await loadConfig(store.paths);
  const spinner = ui.spinner();
  spinner.start('Looking for password tools');
  const tools = await Promise.all(
    availableProviders().map(async (provider) => ({
      provider,
      installed: !!locate(provider),
      signedIn: locate(provider) ? await isSignedIn(provider) : false,
    }))
  );
  spinner.stop('Password tools');
  for (const tool of tools.filter((t) => !t.installed))
    ui.log.message(`${tool.provider.label}: not installed (${tool.provider.install})`);
  const installed = tools.filter((t) => t.installed);
  const pending: Pending[] = [];
  if (installed.length) {
    const chosen = bail(
      await ui.multiselect({
        message: 'Which tools should keyhop pull secrets from?',
        options: installed.map((t) => ({
          value: t.provider.id,
          label: t.provider.label,
          hint: t.signedIn ? 'signed in' : 'locked or signed out',
        })),
        initialValues: installed.filter((t) => t.signedIn && t.provider.id === '1password').map((t) => t.provider.id),
        required: false,
      })
    );
    const taken = new Set(Object.keys(config.secrets ?? {}));
    for (const id of chosen)
      pending.push(...(await linkTool(installed.find((t) => t.provider.id === id)!.provider, taken, config)));
  } else {
    ui.log.warn('No supported password tools found; you can still use sync scripts.');
  }

  // Whole-vault links change config even when nothing is pending.
  config.secrets = { ...config.secrets, ...Object.fromEntries(pending.map((p) => [p.name, { ref: p.ref }])) };
  await saveConfig(store.paths, config);
  if (pending.length) {
    const rules = Object.fromEntries(
      pending.filter((p) => p.allow.length).map((p) => [p.name, { add: p.allow, bindTo: p.ref }])
    );
    if (Object.keys(rules).length) await changeAllowed(store, rules);
    ui.log.success(`Linked ${pending.map((p) => p.name).join(', ')}`);
  }

  await offerStarterScript(store.paths.syncDir);

  spinner.start('Syncing (your password tools may ask you to approve)');
  try {
    const result = await syncVault(store);
    spinner.stop(`Synced ${result.total} secret(s): ${result.steps.map((s) => `${s.step} (${s.count})`).join(', ') || 'no steps yet'}`);
  } catch (error) {
    spinner.error('Sync failed');
    ui.log.error((error as Error).message);
  }

  if ((await claudeRegistration()) === 'missing') {
    if (bail(await ui.confirm({ message: 'Register keyhop with Claude Code (user scope)?' }))) {
      await registerWithClaude()
        .then(() => ui.log.success('Registered. Start a new Claude Code session to load it.'))
        .catch((error: Error) => ui.log.error(error.message));
    }
  }

  ui.note(formatChecks(await runChecks(store.paths)), 'keyhop doctor');
  ui.outro('Done. Allow more commands with: keyhop allow NAME gh   ·   Add more with: keyhop setup');
  return 0;
}
