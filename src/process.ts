import { spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { windowsSystem } from './paths.ts';

export interface ProcessResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  /** Output beyond maxBytes was dropped. */
  truncated: boolean;
}

export interface ProcessOptions {
  input?: string;
  cwd?: string;
  env?: NodeJS.ProcessEnv;
  timeoutMs?: number;
  /** Per stream. */
  maxBytes?: number;
  /**
   * Run in its own process group and kill the whole group when the program
   * exits or times out, so no descendant keeps injected secrets running.
   */
  killTree?: boolean;
  /**
   * Values written to extra inherited pipes, fd 3, 4 … (read as /dev/fd/3 …).
   * macOS/Linux only; no other process can open them.
   */
  extraInputs?: string[];
  /** Called with the child's pid right after it starts. */
  onSpawn?: (pid: number) => void;
}

/** After exit, how long to wait for descendants still holding the pipes. */
const DRAIN_MS = 1_000;

function killGroup(child: ChildProcess): void {
  if (!child.pid) return;
  try {
    if (process.platform === 'win32') spawnSync(windowsSystem('taskkill.exe'), ['/T', '/F', '/PID', String(child.pid)], { windowsHide: true });
    else process.kill(-child.pid, 'SIGKILL');
  } catch {
    // Already gone.
  }
}

/** Runs a program directly (never through a shell) and collects its output. */
export function runProcess(command: string, args: string[], options: ProcessOptions = {}): Promise<ProcessResult> {
  const maxBytes = options.maxBytes ?? 1024 * 1024;
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, {
      cwd: options.cwd,
      env: options.env ?? process.env,
      shell: false,
      windowsHide: true,
      detached: !!options.killTree && process.platform !== 'win32',
      stdio: [
        options.input === undefined ? 'ignore' : 'pipe',
        'pipe',
        'pipe',
        ...(options.extraInputs ?? []).map(() => 'pipe' as const),
      ],
    });
    if (child.pid) options.onSpawn?.(child.pid);
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    const size = { out: 0, err: 0 };
    let truncated = false;
    const collect = (chunks: Buffer[], key: 'out' | 'err') => (chunk: Buffer) => {
      if (size[key] >= maxBytes) {
        truncated = true;
        return;
      }
      const room = maxBytes - size[key];
      if (chunk.length > room) truncated = true;
      chunks.push(chunk.subarray(0, room));
      size[key] += Math.min(chunk.length, room);
    };
    child.stdout!.on('data', collect(out, 'out'));
    child.stderr!.on('data', collect(err, 'err'));

    let timedOut = false;
    let settled = false;
    let exit: { code: number | null; signal: NodeJS.Signals | null } | null = null;
    const finish = () => {
      if (settled || !exit) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(drain);
      child.stdout!.destroy();
      child.stderr!.destroy();
      resolve({
        ...exit,
        stdout: Buffer.concat(out).toString('utf8'),
        stderr: Buffer.concat(err).toString('utf8'),
        timedOut,
        truncated,
      });
    };
    let drain: ReturnType<typeof setTimeout> | undefined;
    const timer = options.timeoutMs
      ? setTimeout(() => {
          timedOut = true;
          if (options.killTree) killGroup(child);
          else child.kill('SIGKILL');
        }, options.timeoutMs)
      : undefined;
    child.on('error', (error) => {
      clearTimeout(timer);
      settled = true;
      reject(error);
    });
    child.on('exit', (code, signal) => {
      exit = { code, signal };
      if (options.killTree) killGroup(child);
      // A descendant may still hold stdout/stderr open; don't wait on it forever.
      drain = setTimeout(finish, DRAIN_MS);
    });
    child.on('close', finish);
    // A program may exit without reading its input; that EPIPE must not crash keyhop.
    const feed = (stream: NodeJS.WritableStream | null | undefined, value: string) => {
      if (!stream) return;
      stream.on('error', () => undefined);
      stream.end(value);
    };
    if (options.input !== undefined) feed(child.stdin, options.input);
    (options.extraInputs ?? []).forEach((value, i) => feed(child.stdio[3 + i] as NodeJS.WritableStream, value));
  });
}
