// Builds the biometric helper for a checkout into native/build: the Touch ID
// helper on macOS (swiftc), keyhop-hello.exe on Windows (dotnet SDK). The
// installers and the release workflow build their own copies.
import { spawnSync } from 'node:child_process';
import { mkdirSync } from 'node:fs';

mkdirSync('native/build', { recursive: true });
const [command, args] =
  process.platform === 'win32'
    ? ['dotnet', ['build', 'native/windows/KeyhopHello', '-c', 'Release', '-o', 'native/build', '--nologo']]
    : ['swiftc', ['-O', 'native/macos/keyhop-auth.swift', '-o', 'native/build/keyhop-auth']];
const result = spawnSync(command, args, { stdio: 'inherit' });
process.exit(result.status ?? 1);
