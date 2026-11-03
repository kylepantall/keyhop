/**
 * Windows: hands a secret to a program as a file path without writing it to
 * disk. keyhop-hello.exe serves an owner-only `\\.\pipe\` once, and only to
 * the program keyhop started (or a process it started), so another process
 * of the same user (a shell Claude runs) can't read it. It exits when keyhop
 * closes its stdin, including if keyhop dies.
 *
 * macOS/Linux don't need this: the program gets an inherited pipe at
 * /dev/fd/N (see ProcessOptions.extraInputs), which no other process can open.
 */

import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { windowsHelperPath } from './auth.ts';

export interface SecretPipe {
  path: string;
  /** Tells the pipe which process may read it, once that process runs. */
  attach(pid: number): void;
  close(): Promise<void>;
}

export async function openWindowsPipe(value: string): Promise<SecretPipe> {
  const name = `keyhop-${randomBytes(16).toString('hex')}`;
  const child = spawn(windowsHelperPath, ['pipe', name], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
  child.stdin!.on('error', () => undefined);
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
  // The value goes over stdin, never argv; stdin stays open for the pid line.
  child.stdin!.write(`${Buffer.from(value, 'utf8').toString('base64')}\n`);
  try {
    await ready;
  } catch (error) {
    child.kill();
    throw new Error(`Could not create a named pipe for the secret: ${(error as Error).message}`);
  }
  return {
    path: `\\\\.\\pipe\\${name}`,
    attach(pid) {
      child.stdin!.write(`${pid}\n`);
    },
    async close() {
      child.stdin!.end();
      child.kill();
    },
  };
}
