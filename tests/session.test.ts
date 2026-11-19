import { expect, test } from 'bun:test';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { AccessGate, type Dialog } from '../src/approve.ts';
import { createServer } from '../src/server.ts';
import { PlanSession } from '../src/session.ts';
import { fakeAuth, newStore, tempHome } from './support.ts';

const value = 'only-used-by-the-approved-command';
const signal = new AbortController().signal;
const unix = process.platform !== 'win32';

async function fixture() {
  const home = await tempHome();
  const auth = fakeAuth();
  const store = await newStore(home.p, auth);
  await store.update('change', (vault) => {
    vault.secrets.TOKEN = { value, origin: 'test:token', source: 'test', updatedAt: '1' };
  });
  const command = join(home.p.dir, 'example-command');
  const text = '#!/bin/sh\necho "$1:$TOKEN"\n';
  if (unix) await writeFile(command, text, { mode: 0o700 });
  store.lock();
  auth.prompts.length = 0;
  return { home, auth, store, command };
}

test.if(unix)('MCP plan reviews the exact commands, asks once, executes in order and closes', async () => {
  const { home, auth, store, command } = await fixture();
  const reviews: string[] = [];
  const dialog: Dialog = async (_, kind, prompt) => {
    expect(kind).toBe('plan');
    reviews.push(prompt?.plan ?? '');
    expect(auth.prompts).toEqual([]);
    return 'once';
  };
  const client = new Client({ name: 'test-client', version: '1' });
  const second = new Client({ name: 'another-client', version: '1' });
  const [a, b] = InMemoryTransport.createLinkedPair();
  const [c, d] = InMemoryTransport.createLinkedPair();
  await createServer(store, new AccessGate(async () => 'deny'), dialog).connect(a);
  await createServer(store, new AccessGate(async () => 'deny'), dialog).connect(c);
  await Promise.all([client.connect(b), second.connect(d)]);
  try {
    const call = (name: string, args: Record<string, unknown> = {}, target = client) =>
      target.callTool({ name, arguments: args });
    const plan = await call('open_session', {
      purpose: 'Run two steps',
      steps: ['first', 'second'].map((arg) => ({ kind: 'command', command, args: [arg], secrets: ['TOKEN'] })),
    });
    const session = JSON.parse((plan.content as { text: string }[])[0]!.text);
    expect(reviews).toHaveLength(1);
    expect(reviews[0]).toContain('Arguments: ["first"]');
    expect(reviews[0]).toContain('Arguments: ["second"]');
    expect(reviews[0]).not.toContain(value);
    expect(auth.prompts).toEqual(['grant']);
    expect(store.unlocked).toBe(false);
    const step = (number: number, target = client) => call('run_session_step', { sessionId: session.sessionId, step: number }, target);
    expect((await step(1, second)).isError).toBe(true);
    expect((await step(2)).isError).toBe(true);
    const first = await step(1);
    expect(JSON.parse((first.content as { text: string }[])[0]!.text)).toMatchObject({
      nextStep: 2,
      result: { stdout: 'first:[REDACTED:TOKEN]\n' },
    });
    expect((await step(1)).isError).toBe(true);
    const last = await step(2);
    expect(JSON.parse((last.content as { text: string }[])[0]!.text)).toMatchObject({
      closed: true,
      result: { stdout: 'second:[REDACTED:TOKEN]\n' },
    });
    expect((await step(2)).isError).toBe(true);
    expect(auth.prompts).toEqual(['grant']);
  } finally {
    await Promise.all([client.close(), second.close()]);
    await home.cleanup();
  }
});

test.if(unix)('denial does not authenticate and an edited binary closes an approved session', async () => {
  const { home, auth, store, command } = await fixture();
  const plan = { purpose: 'Use test credentials', steps: [{ kind: 'command', command, secrets: ['TOKEN'] }] };
  const sessions = new PlanSession(store, new AccessGate(async () => 'deny'), async () => 'once');
  try {
    const denied = new PlanSession(store, new AccessGate(async () => 'deny'), async () => 'deny');
    await expect(denied.open(plan, 'Test client', signal)).rejects.toThrow('denied');
    expect(auth.prompts).toEqual([]);
    const { sessionId } = await sessions.open(plan, 'Test client', signal);
    await writeFile(command, '#!/bin/sh\necho changed\n');
    await expect(sessions.run(sessionId, 1, signal)).rejects.toThrow('has changed');
    await expect(sessions.run(sessionId, 1, signal)).rejects.toThrow('closed');
    expect(auth.prompts).toEqual(['grant']);
  } finally {
    sessions.revoke();
    await home.cleanup();
  }
});

test.if(unix)('an approved script is snapshotted before display and lock revokes unused steps', async () => {
  const { home, auth, store } = await fixture();
  const script = join(home.p.dir, 'approved.sh');
  await writeFile(script, 'echo "reviewed:$TOKEN"\n');
  const sessions = new PlanSession(store, new AccessGate(async () => 'deny'), async (_, __, prompt) => {
    expect(prompt?.plan).toContain('echo "reviewed:$TOKEN"');
    await writeFile(script, 'echo edited\n');
    return 'once';
  });
  try {
    const step = { kind: 'command', command: '/bin/sh', args: [script], secrets: ['TOKEN'], bypassGuard: true };
    const { sessionId } = await sessions.open({ purpose: 'Run a script twice', steps: [step, step] }, 'Test client', signal);
    expect(await sessions.run(sessionId, 1, signal)).toMatchObject({ result: { stdout: 'reviewed:[REDACTED:TOKEN]\n' } });
    sessions.revoke();
    await expect(sessions.run(sessionId, 2, signal)).rejects.toThrow('closed');
    expect(auth.prompts).toEqual(['grant']);
  } finally {
    sessions.revoke();
    await home.cleanup();
  }
});
