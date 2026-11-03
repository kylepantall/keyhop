// Builds a Windows release into dist/: keyhop.exe (bun build --compile),
// keyhop-hello.exe (C#, via build-helper.mjs) and SHA256SUMS. Run on Windows
// with the .NET SDK; CI's release workflow publishes dist/ as-is.
//
//   bun scripts/build-windows.mjs [--exe-only]
// --exe-only builds just keyhop.exe, which works from any OS.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

const exeOnly = process.argv.includes('--exe-only');
const { version, description } = JSON.parse(readFileSync('package.json', 'utf8'));

const run = (command, args) => {
  const result = spawnSync(command, args, { stdio: 'inherit' });
  if (result.error) throw result.error;
  if (result.status !== 0) process.exit(result.status ?? 1);
};

rmSync('dist', { recursive: true, force: true });
mkdirSync('dist');

// Baseline: runs on x64 CPUs without AVX2, and under emulation on Windows on Arm.
const compile = ['build', '--compile', '--target=bun-windows-x64-baseline', 'src/index.ts', '--outfile', 'dist/keyhop.exe'];
// File properties (settable only when building on Windows) let people and AV see what the program is.
if (process.platform === 'win32')
  compile.push(
    '--windows-title=keyhop',
    '--windows-publisher=Kyle Pantall',
    `--windows-version=${version}.0`,
    `--windows-description=${description}`,
    '--windows-copyright=MIT License'
  );
run(process.execPath, compile);

const files = ['keyhop.exe'];
if (!exeOnly) {
  if (process.platform !== 'win32') throw new Error('keyhop-hello.exe builds on Windows only; use --exe-only elsewhere.');
  run(process.execPath, ['scripts/build-helper.mjs']);
  copyFileSync('native/build/keyhop-hello.exe', 'dist/keyhop-hello.exe');
  files.push('keyhop-hello.exe');
}

const sums = files.map((name) => `${createHash('sha256').update(readFileSync(`dist/${name}`)).digest('hex')}  ${name}`);
writeFileSync('dist/SHA256SUMS', sums.join('\n') + '\n');
console.log(`dist/ (keyhop ${version}):\n${sums.join('\n')}`);
