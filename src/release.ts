/**
 * Windows installs come from GitHub Releases: CI builds keyhop.exe and
 * keyhop-hello.exe for each version tag and publishes them with SHA256SUMS.
 * This downloads a release, checks every file against SHA256SUMS, and swaps
 * the programs in next to the running keyhop.exe.
 */

import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import { mkdtemp, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { REPO } from './paths.ts';

/** What a Windows release ships; the installer and update install exactly these. */
export const WINDOWS_ASSETS = ['keyhop.exe', 'keyhop-hello.exe'] as const;
export const SUMS_FILE = 'SHA256SUMS';

const TAG = /^v\d+\.\d+\.\d+([.-][0-9A-Za-z.-]+)?$/;

export interface Release {
  tag: string;
  version: string;
}

async function get(url: string, timeoutMs = 15_000): Promise<Response> {
  const response = await fetch(url, {
    headers: { 'User-Agent': 'keyhop', Accept: 'application/vnd.github+json' },
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!response.ok) throw new Error(`GET ${url} returned ${response.status}`);
  return response;
}

/** The latest release, or the one tagged `tag` (v1.2.3). */
export async function findRelease(tag?: string): Promise<Release> {
  if (tag !== undefined && !TAG.test(tag)) throw new Error(`Invalid release tag: ${tag} (expected v1.2.3)`);
  const url = `https://api.github.com/repos/${REPO}/releases/${tag ? `tags/${tag}` : 'latest'}`;
  const body = (await (await get(url)).json()) as { tag_name?: string };
  if (!body.tag_name || !TAG.test(body.tag_name)) throw new Error(`Release on GitHub has an unexpected tag: ${body.tag_name}`);
  return { tag: body.tag_name, version: body.tag_name.slice(1) };
}

/** Parses `sha256  name` lines (sha256sum / Get-FileHash style); digests come back lower-cased. */
export function parseSums(text: string): Map<string, string> {
  const sums = new Map<string, string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^([0-9a-fA-F]{64})\s+\*?(\S+)\s*$/.exec(line);
    if (match) sums.set(match[2]!, match[1]!.toLowerCase());
  }
  return sums;
}

export function sha256(data: Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

/** Throws unless `data` is listed in SHA256SUMS under `name` with a matching hash. */
export function verify(name: string, data: Uint8Array, sums: Map<string, string>): void {
  const expected = sums.get(name);
  if (!expected) throw new Error(`${name} is not listed in ${SUMS_FILE}.`);
  if (sha256(data) !== expected) throw new Error(`${name} does not match its SHA-256 checksum; nothing was changed.`);
}

/**
 * Downloads and verifies the release's Windows programs, then replaces the
 * ones in `binDir`. A running exe can't be overwritten on Windows but can be
 * renamed, so each old file moves to `<name>.old` first.
 */
export async function installWindowsRelease(release: Release, binDir: string): Promise<void> {
  const base = `https://github.com/${REPO}/releases/download/${release.tag}`;
  const sums = parseSums(await (await get(`${base}/${SUMS_FILE}`)).text());
  const staging = await mkdtemp(join(binDir, '.update-'));
  try {
    for (const name of WINDOWS_ASSETS) {
      console.log(`Downloading ${name} (${release.tag})`);
      const data = new Uint8Array(await (await get(`${base}/${name}`, 300_000)).arrayBuffer());
      verify(name, data, sums);
      await writeFile(join(staging, name), data);
    }
    for (const name of WINDOWS_ASSETS) {
      const target = join(binDir, name);
      const old = `${target}.old`;
      await rm(old, { force: true }).catch(() => {});
      if (existsSync(target)) await rename(target, old);
      await rename(join(staging, name), target);
    }
  } finally {
    await rm(staging, { recursive: true, force: true });
  }
}

/** Removes `.old` programs a previous update left behind (they were running then). */
export async function cleanupOldPrograms(execPath: string): Promise<void> {
  const binDir = dirname(execPath);
  await Promise.all(WINDOWS_ASSETS.map((name) => rm(join(binDir, `${name}.old`), { force: true }).catch(() => {})));
}
