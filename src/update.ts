/**
 * `keyhop update [--check] [--ref <branch|tag>] [--force]`: compare with the
 * version on GitHub and install it. macOS reruns the installer for main's
 * commit; Windows downloads the release's programs and checks their SHA-256
 * (see release.ts). Data in the keyhop data directory is never touched.
 */

import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { appRoot, REPO } from './paths.ts';
import { cleanupOldPrograms, findRelease, installWindowsRelease } from './release.ts';
import { VERSION } from './version.ts';

const REF = /^[A-Za-z0-9._/-]+$/;

function raw(ref: string, path: string): string {
  return `https://raw.githubusercontent.com/${REPO}/${ref}/${path}`;
}

async function fetchText(url: string): Promise<string> {
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`GET ${url} returned ${response.status}`);
  return response.text();
}

/**
 * Resolves a branch or tag to its commit. raw.githubusercontent caches a
 * branch URL for up to 5 minutes; a commit URL is never stale.
 */
export async function resolveRef(ref: string): Promise<string> {
  try {
    const response = await fetch(`https://api.github.com/repos/${REPO}/commits/${ref}`, {
      headers: { Accept: 'application/vnd.github.sha' },
      signal: AbortSignal.timeout(10_000),
    });
    const sha = response.ok ? (await response.text()).trim() : '';
    return /^[0-9a-f]{40}$/.test(sha) ? sha : ref;
  } catch {
    // Rate-limited or offline: fall back to the (possibly cached) branch URL.
    return ref;
  }
}

export async function latestVersion(ref: string): Promise<string> {
  const pkg = JSON.parse(await fetchText(raw(ref, 'package.json'))) as { version?: string };
  if (!pkg.version) throw new Error('package.json on GitHub has no version.');
  return pkg.version;
}

/** The newest version `keyhop update` would install here. */
export async function availableVersion(): Promise<string> {
  if (process.platform === 'win32') return (await findRelease()).version;
  return latestVersion(await resolveRef('main'));
}

export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => v.split(/[.-]/).slice(0, 3).map((n) => Number.parseInt(n, 10) || 0);
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i]! - y[i]!;
  return 0;
}

async function updateWindows(args: string[]): Promise<number> {
  let tag: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--ref') tag = args[++i] ?? '';
    else if (!['--check', '--force'].includes(arg))
      throw new Error(`Unknown option: ${arg}. Usage: keyhop update [--check] [--ref <v1.2.3>] [--force]`);
  }
  const release = await findRelease(tag);
  const diff = compareVersions(release.version, VERSION);
  console.log(`Installed ${VERSION}; the ${tag ? release.tag : 'latest'} release on GitHub is ${release.version}.`);
  if (args.includes('--check')) return diff > 0 ? 10 : 0;
  if (diff <= 0 && !args.includes('--force')) {
    console.log(diff === 0 ? 'Already up to date.' : 'Installed version is newer; use --force to install it anyway.');
    return 0;
  }
  if (appRoot !== null) throw new Error('This copy runs from source; update it with git pull.');
  const binDir = dirname(process.execPath);
  await cleanupOldPrograms(process.execPath);
  await installWindowsRelease(release, binDir);
  console.log(`Updated to ${release.version}. Restart Claude Code to load it.`);
  return 0;
}

export async function runUpdateCommand(args: string[]): Promise<number> {
  if (process.platform === 'win32') return updateWindows(args);
  let ref = 'main';
  for (let i = 0; i < args.length; i++) {
    const arg = args[i]!;
    if (arg === '--ref') ref = args[++i] ?? '';
    else if (!['--check', '--force'].includes(arg))
      throw new Error(`Unknown option: ${arg}. Usage: keyhop update [--check] [--ref <branch|tag>] [--force]`);
  }
  if (!REF.test(ref) || ref.includes('..')) throw new Error(`Invalid ref: ${ref}`);
  const force = args.includes('--force');

  const commit = await resolveRef(ref);
  const latest = await latestVersion(commit);
  const diff = compareVersions(latest, VERSION);
  console.log(`Installed ${VERSION}; ${REPO}@${ref} has ${latest}.`);
  // Install exactly the commit that was checked.
  ref = commit;
  if (args.includes('--check')) return diff > 0 ? 10 : 0;
  if (diff <= 0 && !force) {
    console.log(diff === 0 ? 'Already up to date.' : 'Installed version is newer; use --force to install it anyway.');
    return 0;
  }
  if (!process.env.KEYHOP_LAUNCHER)
    throw new Error('This copy was not installed by the installer; update it with git pull.');

  const dir = await mkdtemp(join(tmpdir(), 'keyhop-update-'));
  try {
    const script = join(dir, 'install.sh');
    await writeFile(script, await fetchText(raw(ref, 'scripts/install.sh')));
    const code = await new Promise<number>((resolve, reject) => {
      const child = spawn('bash', [script, ref], { stdio: 'inherit' });
      child.on('error', reject);
      child.on('close', (status) => resolve(status ?? 1));
    });
    if (code === 0) console.log(`Updated to ${latest}. Restart Claude Code to load it.`);
    return code;
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}
