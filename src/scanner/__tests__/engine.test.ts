import { describe, it, expect } from 'vitest';
import { scan } from '../engine.js';

describe('scan', () => {
  it('returns matched: false for safe content', async () => {
    const result = await scan('hello world, nothing dangerous here');
    expect(result.matched).toBe(false);
  });

  it('matches the canary rule when its string is present', async () => {
    const result = await scan('content with WARLOCK_SCAFFOLD_CANARY embedded');
    expect(result.matched).toBe(true);
    if (result.matched) {
      expect(result.matches).toHaveLength(1);
      expect(result.matches[0].rule).toBe('scaffold_canary');
    }
  });

  it('extracts metadata from the matching rule', async () => {
    const result = await scan('WARLOCK_SCAFFOLD_CANARY');
    expect(result.matched).toBe(true);
    if (result.matched) {
      const match = result.matches[0];
      expect(match.metadata.severity).toBe('low');
      expect(match.metadata.description).toContain('Scaffold');
    }
  });
});
