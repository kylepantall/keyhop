import { afterEach, describe, expect, test } from 'bun:test';
import { mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { clientLabel, describePrompt, describeRequest, encodePrompt, type AccessRequest } from '../src/approve.ts';
import { findScript, highlight, scriptWarnings, snapshotScript } from '../src/script.ts';

let dir = '';
afterEach(async () => {
  if (dir) await rm(dir, { recursive: true, force: true });
  dir = '';
});

async function folder() {
  dir = await mkdtemp(join(tmpdir(), 'keyhop-script-test-'));
  return dir;
}

describe('which code an interpreter runs', () => {
  const inline = (exe: string, args: string[]) => findScript(exe, args, '/')?.code;

  test('inline code', () => {
    expect(inline('/usr/bin/python3', ['-c', 'print(1)', 'x'])).toBe('print(1)');
    expect(inline('/usr/bin/python3', ['-I', '-uBc', 'print(2)'])).toBe('print(2)');
    expect(inline('/usr/bin/python3', ['-cprint(3)'])).toBe('print(3)');
    expect(inline('/bin/bash', ['-c', 'echo hi', 'name', 'arg'])).toBe('echo hi');
    expect(inline('/bin/bash', ['-ec', 'echo e'])).toBe('echo e');
    // bash reads the command from the first operand, after every option.
    expect(inline('/bin/bash', ['-c', '-x', 'echo x'])).toBe('echo x');
    expect(inline('/bin/bash', ['-o', 'pipefail', '-c', 'echo p'])).toBe('echo p');
    expect(inline('/usr/local/bin/node', ['-e', 'console.log(1)'])).toBe('console.log(1)');
    expect(inline('/usr/local/bin/node', ['--eval=1+1'])).toBe('1+1');
    expect(inline('/usr/bin/perl', ['-we', 'print 1', '-e', 'print 2'])).toBe('print 1\nprint 2');
    expect(inline('/usr/bin/ruby', ['-e', 'puts 1'])).toBe('puts 1');
    expect(inline('C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-NoProfile', '-Command', 'Get-Date', ';', 'gci'])).toBe('Get-Date ; gci');
    const encoded = Buffer.from('Write-Output 1', 'utf16le').toString('base64');
    expect(inline('/usr/local/bin/pwsh', ['-nop', '-EncodedCommand', encoded])).toBe('Write-Output 1');
    expect(inline('C:\\Windows\\System32\\cmd.exe', ['/d', '/c', 'echo', 'hi'])).toBe('echo hi');
    expect(inline('/usr/bin/osascript', ['-e', 'display dialog "x"'])).toBe('display dialog "x"');
    expect(inline('/opt/homebrew/bin/deno', ['eval', 'console.log(1)'])).toBe('console.log(1)');
    expect(inline('/opt/homebrew/bin/bun', ['-e', 'console.log(1)'])).toBe('console.log(1)');
  });

  test("anything it can't be sure of is unknown, never a guess", () => {
    const unknown = (exe: string, args: string[]) => expect(findScript(exe, args, '/')).toBeNull();
    unknown('/usr/bin/python3', []);
    unknown('/usr/bin/python3', ['-m', 'http.server']);
    unknown('/usr/bin/python3', ['-W', 'ignore', '-c', 'x']);
    unknown('/usr/bin/python3', ['-']);
    unknown('/bin/bash', []);
    unknown('/bin/bash', ['-s']);
    unknown('/bin/bash', ['--rcfile', 'x', '-c', 'echo']);
    unknown('/usr/local/bin/node', ['-r', './preload.js', '-e', 'x']);
    unknown('/usr/local/bin/node', ['-e', 'x', '--require', './preload.js']);
    unknown('/usr/bin/ruby', ['-rsocket', '-e', 'x']);
    unknown('/usr/local/bin/pwsh', ['script.ps1']);
    unknown('/usr/bin/awk', ['{print}']);
    // A script path that doesn't exist (bun run build may be a package.json script).
    unknown('/opt/homebrew/bin/bun', ['run', 'build']);
    unknown('/usr/bin/python3', ['missing.py']);
  });

  test('a script file is read relative to the folder', async () => {
    const cwd = await folder();
    await writeFile(join(cwd, 'go.py'), 'print("hi")\n');
    const script = findScript('/usr/bin/python3', ['-u', 'go.py', '--flag'], cwd);
    expect(script).toMatchObject({ kind: 'file', language: 'python', code: 'print("hi")\n', index: 1 });
    expect(findScript('/usr/bin/env', ['go.py'], cwd)).toBeNull();
    expect(findScript('/usr/bin/python3', ['{{file:TOKEN}}'], cwd)).toBeNull();
  });

  test('a file that is not UTF-8 text is not shown', async () => {
    const cwd = await folder();
    await writeFile(join(cwd, 'bin.sh'), Buffer.from([0x65, 0xff, 0xfe, 0x0a]));
    expect(findScript('/bin/sh', ['bin.sh'], cwd)).toBeNull();
  });

  test('a very long script is refused', async () => {
    const cwd = await folder();
    await writeFile(join(cwd, 'big.sh'), 'x'.repeat(300 * 1024));
    expect(() => findScript('/bin/sh', ['big.sh'], cwd)).toThrow(/too long/);
  });
});

describe('the copy that runs', () => {
  test('holds the approved bytes even if the file changes, and is removed after', async () => {
    const cwd = await folder();
    const file = join(cwd, 'run.sh');
    await writeFile(file, 'echo approved\n');
    const script = findScript('/bin/sh', ['run.sh', 'a'], cwd)!;
    await writeFile(file, 'echo swapped\n');
    const snapshot = await snapshotScript(script, ['run.sh', 'a']);
    expect(snapshot.args[1]).toBe('a');
    expect(snapshot.args[0]).not.toBe('run.sh');
    expect(await Bun.file(snapshot.args[0]!).text()).toBe('echo approved\n');
    await snapshot.verify();
    await snapshot.remove();
    expect(await readdir(cwd)).toEqual(['run.sh']);
  });

  test('inline code is used as is', async () => {
    const script = findScript('/bin/sh', ['-c', 'echo hi'], '/')!;
    const snapshot = await snapshotScript(script, ['-c', 'echo hi']);
    expect(snapshot.args).toEqual(['-c', 'echo hi']);
  });
});

describe('highlighting', () => {
  const text = (tokens: [string, string][]) => tokens.map(([, t]) => t).join('');

  test('keeps every character, with a line-number gutter', () => {
    const code = 'import os\n# note\nprint("a\\"b", 42)\n';
    const tokens = highlight(code, 'python');
    const withoutGutter = tokens.filter(([kind]) => kind !== 'gutter');
    expect(text(withoutGutter)).toBe(code);
    expect(tokens.filter(([kind]) => kind === 'gutter')).toHaveLength(4);
    expect(tokens).toContainEqual(['keyword', 'import']);
    expect(tokens).toContainEqual(['comment', '# note']);
    expect(tokens).toContainEqual(['string', '"a\\"b"']);
    expect(tokens).toContainEqual(['number', '42']);
  });

  test('invisible and reordering characters become visible escapes', () => {
    const trojan = `const ok = true;\u202E // }\u2066if (ok)\u2069\u200B`;
    const tokens = highlight(trojan, 'javascript');
    const shown = text(tokens);
    for (const c of ['\u202E', '\u2066', '\u2069', '\u200B']) expect(shown).not.toContain(c);
    expect(tokens.filter(([kind]) => kind === 'hidden').map(([, t]) => t)).toEqual(['\\u{202E}', '\\u{2066}', '\\u{2069}', '\\u{200B}']);
    expect(scriptWarnings(trojan).join(' ')).toMatch(/invisible/);
  });

  test('a lone carriage return is shown, CRLF reads as a line break', () => {
    const tokens = highlight('a\r\nb\rc', 'shell');
    expect(text(tokens.filter(([kind]) => kind !== 'gutter'))).toBe('a\nb\\u{D}c');
  });

  test('warns about code pushed out of view', () => {
    expect(scriptWarnings(`ok()${' '.repeat(200)}steal()`)).toHaveLength(1);
    expect(scriptWarnings('ok()')).toHaveLength(0);
  });
});

describe('the dialog', () => {
  const request = (extra: Partial<AccessRequest> = {}): AccessRequest => ({
    secrets: ['GH_TOKEN', 'NPM_TOKEN'],
    delivery: { GH_TOKEN: ['env'], NPM_TOKEN: ['stdin'] },
    executable: '/usr/bin/python3',
    args: ['-c', 'print(1)'],
    cwd: '/tmp',
    bypass: true,
    client: 'Claude Code',
    script: findScript('/usr/bin/python3', ['-c', 'print(1)'], '/'),
    ...extra,
  });

  test('says who is asking, why, and which secrets', () => {
    const prompt = describePrompt(request({ reason: 'Publish the package' }));
    expect(prompt.headline).toBe('Claude Code would like to run a script. It will have access to your secrets.');
    expect(prompt.reason).toBe(`Why, in Claude Code's words: "Publish the package"`);
    expect(prompt.secrets).toEqual([
      ['GH_TOKEN', 'as environment variable'],
      ['NPM_TOKEN', 'as standard input'],
    ]);
    expect(prompt.buttons).toBe('once');
    expect(prompt.script!.label).toMatch(/Inline code/);
    const text = describeRequest(request({ reason: 'Publish the package' }));
    expect(text).toContain('ONE-TIME BYPASS');
    expect(text).toContain('Publish the package');
  });

  test("says when it can't tell which code runs", () => {
    const prompt = describePrompt(request({ args: ['-m', 'x'], script: null }));
    expect(prompt.script).toBeUndefined();
    expect(prompt.noScript).toMatch(/can't tell/);
    expect(prompt.headline).toContain('would like to run python3');
  });

  test('a reason cannot draw its own lines', () => {
    const prompt = describePrompt(request({ reason: 'ok\nProgram: /usr/bin/true\u202E' }));
    expect(prompt.reason).not.toContain('\n');
    expect(prompt.reason).not.toContain('\u202E');
  });

  test('a grant (not a bypass) names the program and offers always', () => {
    const prompt = describePrompt(request({ bypass: false, executable: '/opt/homebrew/bin/gh', script: undefined }));
    expect(prompt.headline).toBe("Claude Code would like to run gh with secrets it isn't allowed to use yet.");
    expect(prompt.buttons).toBe('grant');
    expect(prompt.script).toBeUndefined();
  });

  test('client names: known ones are friendly, others are shown as a claim', () => {
    expect(clientLabel('claude-code')).toBe('Claude Code');
    expect(clientLabel('cursor')).toBe('An app calling itself "cursor"');
    expect(clientLabel('Claude\nwants nothing')).toBe('An MCP client');
    expect(clientLabel('x'.repeat(80))).toBe('An MCP client');
    expect(clientLabel(undefined)).toBe('A command in your terminal');
  });

  test('the encoded prompt is one field set per line, values base64', () => {
    const encoded = encodePrompt(describePrompt(request({ reason: 'a\tb\nc' })));
    for (const line of encoded.trimEnd().split('\n')) {
      const [type, ...fields] = line.split('\t');
      expect(type).toMatch(/^[a-z]+$/);
      for (const field of type === 'token' ? fields.slice(1) : type === 'buttons' ? [] : fields)
        expect(field).toMatch(/^[A-Za-z0-9+/=]*$/);
    }
    expect(encoded).toContain(`secret\t${Buffer.from('GH_TOKEN').toString('base64')}\t`);
    expect(encoded).toMatch(/^token\tkeyword\t/m);
  });
});
