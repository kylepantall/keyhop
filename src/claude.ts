import { join } from 'node:path';
import { appRoot } from './paths.ts';
import { runProcess } from './process.ts';

/** argv that starts this install's MCP server. */
export function serverCommand(): string[] {
  const launcher = process.env.KEYHOP_LAUNCHER;
  if (launcher) return process.platform === 'win32' ? ['cmd', '/c', launcher, 'serve'] : [launcher, 'serve'];
  return [process.execPath, join(appRoot, 'src', 'index.ts'), 'serve'];
}

export async function claudeRegistration(): Promise<'registered' | 'missing' | 'no-claude'> {
  const claude = Bun.which('claude');
  if (!claude) return 'no-claude';
  const result = await runProcess(claude, ['mcp', 'get', 'keyhop'], { timeoutMs: 20_000 }).catch(() => null);
  return result?.code === 0 ? 'registered' : 'missing';
}

export async function registerWithClaude(): Promise<void> {
  const claude = Bun.which('claude');
  if (!claude) throw new Error('claude CLI not found.');
  const result = await runProcess(
    claude,
    ['mcp', 'add', '--transport', 'stdio', '--scope', 'user', 'keyhop', '--', ...serverCommand()],
    { timeoutMs: 30_000 }
  );
  if (result.code !== 0) throw new Error(`claude mcp add failed: ${result.stderr.trim() || result.stdout.trim()}`);
}
