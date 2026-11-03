// Builds this platform's native helper into native/build for a checkout:
//  - macOS: the Touch ID helper (the installer does this itself).
//  - Windows: keyhop-hello.exe, Windows Hello signing and the access dialog
//    (needs the .NET SDK; releases ship it prebuilt).
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, readFileSync } from 'node:fs';

const run = (command, args) => {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
};

mkdirSync('native/build', { recursive: true });
if (process.platform === 'darwin') {
  run('swiftc', ['-O', 'native/macos/keyhop-auth.swift', '-o', 'native/build/keyhop-auth']);
} else if (process.platform === 'win32') {
  const { version } = JSON.parse(readFileSync('package.json', 'utf8'));
  const out = 'native/build/hello';
  run('dotnet', ['build', 'native/windows/KeyhopHello/KeyhopHello.csproj', '-c', 'Release', '-o', out, '--nologo', `-p:Version=${version}`]);
  copyFileSync(`${out}/keyhop-hello.exe`, 'native/build/keyhop-hello.exe');
  console.log('Built native/build/keyhop-hello.exe');
} else {
  console.log('Nothing to build: keyhop runs on macOS and Windows.');
}
