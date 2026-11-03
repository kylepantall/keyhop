import { describe, expect, test } from 'bun:test';
import { existsSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { windowsHelperPath } from '../src/auth.ts';
import { openSecretPipe } from '../src/pipes.ts';

// macOS/Linux pipes are covered end to end in run.test.ts. On Windows the pipe
// is served by keyhop-hello.exe, which CI builds before the tests.
describe.if(process.platform === 'win32')('Windows secret pipe', () => {
  test('reads as the value, more than once, and is gone after close', async () => {
    expect(existsSync(windowsHelperPath)).toBe(true);
    const pipe = await openSecretPipe('pipe-value-1');
    try {
      expect(pipe.path.startsWith('\\\\.\\pipe\\keyhop-')).toBe(true);
      expect(await readFile(pipe.path, 'utf8')).toBe('pipe-value-1');
      expect(await readFile(pipe.path, 'utf8')).toBe('pipe-value-1');
    } finally {
      await pipe.close();
    }
    await Bun.sleep(300);
    expect(readFile(pipe.path, 'utf8')).rejects.toThrow();
  });
});
