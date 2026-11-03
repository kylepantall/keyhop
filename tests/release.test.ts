import { describe, expect, test } from 'bun:test';
import { expectedSum, WINDOWS_ASSET } from '../src/release.ts';

describe('expectedSum', () => {
  const hash = 'a'.repeat(64);

  test('reads both sha256sum formats', () => {
    expect(expectedSum(`${hash}  ${WINDOWS_ASSET}\n`, WINDOWS_ASSET)).toBe(hash);
    expect(expectedSum(`${hash} *${WINDOWS_ASSET}\r\n`, WINDOWS_ASSET)).toBe(hash);
  });

  test('matches the exact file name only', () => {
    expect(expectedSum(`${hash}  evil-${WINDOWS_ASSET}\n`, WINDOWS_ASSET)).toBeUndefined();
    expect(expectedSum(`${hash.slice(1)}  ${WINDOWS_ASSET}\n`, WINDOWS_ASSET)).toBeUndefined();
  });
});
