import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { windowsSystem } from '../src/paths.ts';

// Windows Hello itself can't run in CI, but the buffer conversions the helper
// uses around it can: Windows PowerShell 5.1 must round-trip bytes through
// a projected WinRT IBuffer.
describe.if(process.platform === 'win32')('Windows Hello helper plumbing', () => {
  test('CryptographicBuffer round-trips base64 under Windows PowerShell 5.1', () => {
    const script = [
      "$ErrorActionPreference = 'Stop'",
      'Add-Type -AssemblyName System.Runtime.WindowsRuntime',
      '$b = [Windows.Security.Cryptography.CryptographicBuffer, Windows.Security.Cryptography, ContentType = WindowsRuntime]',
      "$b::EncodeToBase64String($b::DecodeFromBase64String('AAECAwQFBgc='))",
    ].join('; ');
    const result = spawnSync(windowsSystem('powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command', script], {
      encoding: 'utf8',
    });
    expect(result.status).toBe(0);
    expect(result.stdout.trim()).toBe('AAECAwQFBgc=');
  });
});
