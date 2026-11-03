/**
 * Hands a secret to a program as a file path without writing it to disk: a
 * named pipe that serves the value every time it is opened, until closed.
 *
 * macOS/Linux: a FIFO (mode 600) in a fresh private temp folder (mode 700).
 * Windows: keyhop-hello.exe serves an owner-only `\\.\pipe\` (Node's own
 * named pipes let Everyone read), killed on close.
 */

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { closeSync, constants, openSync } from 'node:fs';
import { mkdtemp, open, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { windowsHelperPath } from './auth.ts';
import { runProcess } from './process.ts';

export interface SecretPipe {
  path: string;
  close(): Promise<void>;
}

export function openSecretPipe(value: string): Promise<SecretPipe> {
  return process.platform === 'win32' ? windowsPipe(value) : fifo(value);
}

async function fifo(value: string): Promise<SecretPipe> {
  const dir = await mkdtemp(join(tmpdir(), 'keyhop-'));
  const path = join(dir, 'secret');
  const made = await runProcess('/usr/bin/mkfifo', ['-m', '600', path], { timeoutMs: 5_000 }).catch(() => null);
  if (made?.code !== 0) {
    await rm(dir, { recursive: true, force: true });
    throw new Error('Could not create a named pipe for the secret.');
  }
  let closed = false;
  // Opening a FIFO for writing waits for a reader; serve each reader in turn.
  const serving = (async () => {
    while (!closed) {
      const handle = await open(path, 'w').catch(() => null);
      if (!handle) return;
      try {
        if (!closed) await handle.write(value);
      } catch {
        // The reader went away early.
      } finally {
        await handle.close().catch(() => undefined);
      }
    }
  })();
  return {
    path,
    async close() {
      closed = true;
      // Release a writer still waiting for a reader.
      try {
        closeSync(openSync(path, constants.O_RDONLY | constants.O_NONBLOCK));
      } catch {
        // Nothing waiting.
      }
      await Promise.race([serving, Bun.sleep(1_000)]);
      await rm(dir, { recursive: true, force: true });
    },
  };
}

async function windowsPipe(value: string): Promise<SecretPipe> {
  const name = `keyhop-${randomBytes(16).toString('hex')}`;
  const child = spawn(windowsHelperPath, ['pipe', name], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  // The helper prints "ready" once the pipe exists; the value goes over stdin, never argv.
  const ready = new Promise<void>((resolve, reject) => {
    let out = '';
    child.stdout!.on('data', (chunk: Buffer) => {
      out += chunk.toString('utf8');
      if (out.includes('ready')) resolve();
    });
    child.once('error', reject);
    child.once('exit', (code) => reject(new Error(`keyhop-hello pipe exited ${code}`)));
    setTimeout(() => reject(new Error('keyhop-hello pipe did not start')), 10_000).unref();
  });
  child.stdin!.end(Buffer.from(value, 'utf8').toString('base64'));
  try {
    await ready;
  } catch (error) {
    child.kill();
    throw new Error(`Could not create a named pipe for the secret: ${(error as Error).message}`);
  }
  return {
    path: `\\\\.\\pipe\\${name}`,
    async close() {
      child.kill();
    },
  };
}
