import { describe, expect, test } from 'bun:test';
import { spawnSync } from 'node:child_process';
import { join } from 'node:path';
import { windowsSystem } from '../src/paths.ts';

const buffers = join(import.meta.dir, '..', 'native', 'windows', 'keyhop-buffers.ps1');

function powershell(lines: string[]) {
  const script = ["$ErrorActionPreference = 'Stop'", `. '${buffers}'`, ...lines].join('; ');
  return spawnSync(windowsSystem('powershell.exe'), ['-NoProfile', '-NonInteractive', '-Command', script], {
    encoding: 'utf8',
  });
}

// Windows Hello can't run in CI, but the exact buffer helpers the Hello
// helper uses can, under the same Windows PowerShell 5.1.
describe.if(process.platform === 'win32')('Windows Hello buffer helpers', () => {
  test('a buffer WinRT returns (a COM object) converts to bytes', () => {
    const result = powershell([
      '$b = [Windows.Security.Cryptography.CryptographicBuffer, Windows.Security.Cryptography, ContentType = WindowsRuntime]',
      '(ConvertFrom-WinRtBuffer ($b::GenerateRandom(16))).Length',
    ]);
    expect(result.stderr).toBe('');
    expect(result.stdout.trim()).toBe('16');
  });

  test('bytes convert to a buffer WinRT accepts', () => {
    const result = powershell([
      '$b = [Windows.Security.Cryptography.CryptographicBuffer, Windows.Security.Cryptography, ContentType = WindowsRuntime]',
      '$b::EncodeToHexString((ConvertTo-WinRtBuffer ([byte[]](1, 2, 255))))',
    ]);
    expect(result.stderr).toBe('');
    expect(result.stdout.trim()).toBe('0102ff');
  });
});
