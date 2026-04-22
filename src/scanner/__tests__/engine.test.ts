import { describe, it, expect } from 'vitest';
import { scan } from '../engine.js';

describe('engine.scan', () => {
  it('returns matched: false for safe, unrelated content', async () => {
    const result = await scan('hello world, nothing dangerous here');
    expect(result.matched).toBe(false);
  });

  it('returns a proper unmatched ScanResult shape when no rules fire', async () => {
    const result = await scan('a perfectly ordinary sentence');
    expect(result).toEqual({ matched: false });
  });
});
