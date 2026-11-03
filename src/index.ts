#!/usr/bin/env bun
import * as ui from '@clack/prompts';
import { platformAuthenticator } from './auth.ts';
import { assertName, loadConfig, saveConfig } from './config.ts';
import { runDoctor } from './doctor.ts';
import { paths } from './paths.ts';
import { providerFor } from './providers.ts';
import { changeAllowed, resolveAllowed, summarize, syncVault } from './secrets.ts';
import { serve } from './server.ts';
import { runSetup } from './setup.ts';
import { VaultStore } from './store.ts';
import { runUpdateCommand } from './update.ts';
import { VERSION } from './version.ts';

const HELP = `keyhop ${VERSION} — secrets Claude can use but never read

Usage: keyhop <command>

  setup [--reset]               Guided setup: vault, password tools, allowlists, first sync
  sync [--full]                 Pull secrets from linked tools and sync.d scripts
                                (1Password vaults fetch only changed items; --full refetches all)
  list                          Show secret names, sources and allowed commands (no values)
  add NAME REF [--allow a,b] [--description text]
                                Link one secret, e.g. keyhop add GH_TOKEN op://Dev/GitHub/token --allow gh
  remove NAME                   Unlink a secret and delete it from the vault
  allow NAME COMMAND...         Let COMMAND (gh, /usr/local/bin/aws …) receive NAME
  deny NAME COMMAND...          Take that back
  allow-arg NAME / deny-arg NAME
                                Let NAME be placed in an argument ({{arg:NAME}}); it shows in the process list
  doctor [--json]               Check biometrics, vault, tools, scripts and Claude Code
  update [--check] [--ref R]    Install the latest version from GitHub
  serve                         Run the MCP server (stdio); Claude Code starts this

References: op://… (1Password), bw://… (Bitwarden), lastpass://…, pass://…, keychain://… (macOS)
Sync scripts: put them in the sync.d folder (see keyhop doctor); they run in number order.`;

function store(): VaultStore {
  // CLI processes are short-lived; keep the key for the whole command.
  return new VaultStore(paths(), platformAuthenticator(), 0);
}

function option(args: string[], name: string): string | undefined {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  const value = args[index + 1];
  if (!value || value.startsWith('--')) throw new Error(`${name} needs a value.`);
  args.splice(index, 2);
  return value;
}

async function main(argv: string[]): Promise<number> {
  const [command, ...args] = argv;
  switch (command) {
    case undefined:
    case 'help':
    case '--help':
    case '-h':
      console.log(HELP);
      return 0;
    case '--version':
    case '-v':
      console.log(VERSION);
      return 0;
    case 'serve':
      await serve();
      return -1;
    case 'setup':
      return runSetup(store(), args);
    case 'doctor':
      return runDoctor(paths(), args);
    case 'update':
      return runUpdateCommand(args);
    case 'sync': {
      // A spinner only on a terminal; piped output stays plain.
      const spinner = process.stdout.isTTY ? ui.spinner() : null;
      spinner?.start('Syncing (your password tools may ask you to approve)');
      let result;
      try {
        result = await syncVault(store(), spinner ? (message) => spinner.message(message) : undefined, {
          full: args.includes('--full'),
        });
      } catch (error) {
        spinner?.error('Sync failed');
        throw error;
      }
      spinner?.stop('Synced');
      for (const step of result.steps) console.log(`  ${step.step}: ${step.count}`);
      console.log(`Synced ${result.total} secret(s).${result.removed.length ? ` Removed: ${result.removed.join(', ')}` : ''}`);
      if (result.rulesCleared.length)
        console.log(`Their source changed, so these lost their allowed commands: ${result.rulesCleared.join(', ')}. Re-allow with keyhop allow.`);
      return 0;
    }
    case 'list': {
      const { syncedAt, secrets } = await summarize(store());
      console.log(`Last sync: ${syncedAt ?? 'never'}`);
      for (const s of secrets)
        console.log(
          `  ${s.name}  (${s.source})  ${s.allowedCommands.length ? s.allowedCommands.join(', ') : 'no commands allowed'}` +
            (s.asArgument ? '  [may be an argument]' : '')
        );
      return 0;
    }
    case 'add': {
      const allow = option(args, '--allow');
      const description = option(args, '--description');
      const [name, ref] = args;
      if (!name || !ref || args.length > 2) throw new Error('Usage: keyhop add NAME REF [--allow a,b] [--description text]');
      assertName(name);
      providerFor(ref);
      const allowed = allow ? resolveAllowed(allow.split(',')) : [];
      const p = paths();
      const config = await loadConfig(p);
      config.secrets = { ...config.secrets, [name]: { ref, ...(description ? { description } : {}) } };
      await saveConfig(p, config);
      if (allowed.length) await changeAllowed(store(), { [name]: { add: allowed, bindTo: ref } });
      console.log(`Linked ${name}. Run keyhop sync to pull it.`);
      return 0;
    }
    case 'remove': {
      const [name] = args;
      if (!name || args.length > 1) throw new Error('Usage: keyhop remove NAME');
      const s = store();
      await changeAllowed(s, { [name]: { drop: true } });
      const config = await loadConfig(s.paths);
      if (config.secrets?.[name]) {
        delete config.secrets[name];
        await saveConfig(s.paths, config);
      }
      console.log(`Removed ${name}. A sync.d script that still prints it will add it back on the next sync.`);
      return 0;
    }
    case 'allow':
    case 'deny': {
      const [name, ...commands] = args;
      if (!name || !commands.length) throw new Error(`Usage: keyhop ${command} NAME COMMAND...`);
      const resolved = command === 'allow' ? resolveAllowed(commands) : commands.map((c) => (Bun.which(c) ?? c));
      const result = await changeAllowed(store(), { [name]: command === 'allow' ? { add: resolved } : { remove: resolved } });
      console.log(`${name} may be used with: ${result[name]!.join(', ') || 'nothing'}`);
      return 0;
    }
    case 'allow-arg':
    case 'deny-arg': {
      const [name] = args;
      if (!name || args.length > 1) throw new Error(`Usage: keyhop ${command} NAME`);
      await changeAllowed(store(), { [name]: { asArgument: command === 'allow-arg' } });
      console.log(
        command === 'allow-arg'
          ? `${name} may now be placed in an argument ({{arg:${name}}}) for its allowed commands. It shows in the process list while they run.`
          : `${name} may no longer be placed in an argument.`
      );
      return 0;
    }
    default:
      throw new Error(`Unknown command: ${command}. Run keyhop help.`);
  }
}

main(process.argv.slice(2)).then(
  (code) => {
    if (code >= 0) process.exit(code);
  },
  (error: Error) => {
    console.error(`keyhop: ${error.message}`);
    process.exit(1);
  }
);
