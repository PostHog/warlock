import { describe, it, expect, vi } from 'vitest';

// Wrap the real node:fs, but make the first readdirSync call throw to simulate a
// transient, recoverable load failure (the rules directory being momentarily
// unavailable). Every other fs call — including the retry's readdirSync —
// delegates to the real implementation. We mock the module rather than vi.spyOn
// because ESM namespace exports aren't configurable and can't be spied on.
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:fs')>();
  let failedOnce = false;
  return {
    ...actual,
    readdirSync: (...args: Parameters<typeof actual.readdirSync>) => {
      if (!failedOnce) {
        failedOnce = true;
        throw new Error('ENOENT: rules directory temporarily missing');
      }
      return (actual.readdirSync as (...a: unknown[]) => unknown)(...args);
    },
  };
});

import { scan } from '../engine.js';

// Separate test file on purpose: engine.ts caches the compiled rules in a
// module-level promise that is shared across tests in a single file. Once any
// test loads the rules successfully, the failure path can't be exercised again.
// A fresh test file gets a clean module instance, so the very first scan() here
// is the one that triggers the (forced-to-fail) load.
describe('engine.scan rule-load recovery', () => {
  it('retries rule loading after a transient failure', async () => {
    await expect(scan('anything')).rejects.toThrow(/rules directory/);

    // The cache was cleared by the rejection, so this call reloads and succeeds.
    const result = await scan('hello world, nothing dangerous here');
    expect(result.matched).toBe(false);
  });
});
