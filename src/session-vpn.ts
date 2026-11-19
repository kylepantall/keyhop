import { z } from 'zod';
import { assertName, NAME_PATTERN } from './config.ts';
import { commandName } from './policy.ts';
import { runProcess } from './process.ts';
import { redactor } from './redact.ts';
import type { SuiteClient, VaultData } from './types.ts';
import { injectingVariables, verifyClientFiles } from './verify.ts';

const secretName = z.string().max(128).regex(NAME_PATTERN);

// Wire format v1 for the pinned VPNHop client. Requests are intentionally limited to a single HTTPS/HTTP target.
export const VpnStep = z.strictObject({
  kind: z.literal('vpn_http'),
  profile: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,40}$/),
  profileHash: z.string().regex(/^[a-f0-9]{64}$/).describe('Copy from VPNHop session_profile.'),
  secretNames: z.array(secretName).max(8).describe('Copy from VPNHop session_profile.'),
  url: z.url({ protocol: /^https?$/ }).max(4096),
  method: z.enum(['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']).default('GET'),
  headers: z.record(z.string().regex(/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/), z.string().regex(/^[^\r\n\0]*$/)).default({}),
  body: z.string().max(8192).optional(),
  timeoutSeconds: z.number().int().min(1).max(60).default(30),
});

export type VpnStep = z.infer<typeof VpnStep>;

export function prepareVpnStep(step: VpnStep): VpnStep {
  const url = new URL(step.url);
  if (url.username || url.password) throw new Error('A VPN plan URL cannot contain credentials.');
  const secretNames = [...new Set(step.secretNames)].sort();
  secretNames.forEach(assertName);
  return { ...step, url: url.href, secretNames };
}

export function vpnClient(vault: VaultData): SuiteClient {
  if (process.platform === 'win32') throw new Error('VPN plan steps require VPNHop suite client support on macOS or Linux.');
  const pin = vault.clients?.vpnhop;
  if (!pin || !['node', 'nodejs'].includes(commandName(pin.runtime.realPath)))
    throw new Error('Register VPNHop with its Node runtime using vpnhop keyhop-register.');
  return pin;
}

const Response = z.object({
  status: z.number().int(),
  redirectUrl: z.string().optional(),
  url: z.string(),
  headers: z.record(z.string(), z.array(z.string())),
  body: z.string(),
  bodyEncoding: z.enum(['utf8', 'base64']),
  truncated: z.boolean(),
  timeMs: z.number(),
});

export async function runVpnStep(step: VpnStep, pin: SuiteClient, vault: VaultData, signal: AbortSignal) {
  await verifyClientFiles(pin);
  const { kind: _kind, profileHash, secretNames, ...request } = step;
  const values = Object.fromEntries(secretNames.map((name) => [name, vault.secrets[name]!.value]));
  const env = { ...process.env };
  for (const name of [...Object.keys(vault.secrets), ...injectingVariables(Object.keys(env))]) delete env[name];

  const result = await runProcess(pin.runtime.realPath, [pin.entry.realPath, 'keyhop-session-v1'], {
    cwd: pin.root.realPath,
    input: JSON.stringify({ profileHash, request, values }),
    env,
    signal,
    killTree: true,
    timeoutMs: 8 * 60_000,
    maxBytes: 512 << 10,
  });
  // Errors from VPNHop may contain VPN credentials. Never return helper stdout on error.
  const redact = redactor(values);
  if (result.code !== 0 || result.truncated) {
    const detail = result.truncated ? '' : redact(result.stderr).trim().slice(0, 1000);
    throw new Error(detail ? `VPN plan step failed: ${detail}` : 'VPN plan step failed.');
  }
  let response;
  try {
    response = Response.parse(JSON.parse(result.stdout));
  } catch {
    throw new Error('VPNHop returned an unexpected session response. Update the registered VPNHop installation.');
  }
  return {
    ...response,
    url: redact(response.url),
    redirectUrl: response.redirectUrl === undefined ? undefined : redact(response.redirectUrl),
    headers: Object.fromEntries(Object.entries(response.headers).map(([name, vals]) => [redact(name), vals.map(redact)])),
    body: redact(response.body),
  };
}
