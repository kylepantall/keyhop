// Builds the macOS Touch ID helper for a checkout (the installer does this itself).
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';

if (process.platform !== 'darwin') {
  console.log('Nothing to build: the Windows Hello helper is a PowerShell script.');
  process.exit(0);
}
mkdirSync('native/build', { recursive: true });
const result = spawnSync('swiftc', ['-O', 'native/macos/keyhop-auth.swift', '-o', 'native/build/keyhop-auth'], {
  stdio: 'inherit',
});
process.exit(result.status ?? 1);
