import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { windowsHelperPath } from '../src/auth.ts';
import { openWindowsPipe } from '../src/pipes.ts';
import { runProcess } from '../src/process.ts';
import { windowsSystem } from '../src/paths.ts';

// macOS/Linux use inherited /dev/fd pipes, covered end to end in run.test.ts.
// On Windows keyhop-hello.exe serves the pipe; CI builds it before the tests.
describe.if(process.platform === 'win32')('Windows secret pipe', () => {
  test('the program it is attached to reads the value; nothing else does', async () => {
    expect(existsSync(windowsHelperPath)).toBe(true);
    const pipe = await openWindowsPipe('pipe-value-1');
    try {
      // This test process is not the attached program, so it is turned away.
      const stranger = readFile(pipe.path, 'utf8');
      const reader = await runProcess(
        windowsSystem('powershell.exe'),
        ['-NoProfile', '-NonInteractive', '-Command', `[IO.File]::ReadAllText('${pipe.path}')`],
        { timeoutMs: 30_000, onSpawn: (pid) => pipe.attach(pid) }
      );
      expect(reader.stdout.trim()).toBe('pipe-value-1');
      expect(await stranger.catch(() => '')).not.toBe('pipe-value-1');
    } finally {
      await pipe.close();
    }
  });

  test('the helper exits when keyhop closes it', async () => {
    const pipe = await openWindowsPipe('pipe-value-2');
    await pipe.close();
    await Bun.sleep(500);
    expect(readFile(pipe.path, 'utf8')).rejects.toThrow();
  });
});
