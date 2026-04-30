import { describe, it, expect } from 'vitest';
import { scan } from '../../engine.js';
import { expectRuleMetadata } from '../helpers.js';

// 120 base64-safe characters, comfortably above the 40-char floor
const LONG_B64 = 'A'.repeat(120);
// 40 chars unpadded — at the floor, should match
const FLOOR_UNPADDED = 'A'.repeat(40);
// 40 chars + `==` padding — at the floor, should match
const FLOOR_PADDED = 'A'.repeat(40) + '==';
// 30 chars unpadded — below floor, should NOT match
const SHORT_UNPADDED = 'A'.repeat(30);
// 30 chars + `==` padding — below floor, should NOT match
const SHORT_PADDED = 'A'.repeat(30) + '==';

describe('prompt_injection_base64_in_comment', () => {
  describe('positive cases — should match', () => {
    it('matches long base64 in a JS/TS // comment', async () => {
      const result = await scan(`// ${LONG_B64}\nconst x = 1;`);
      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.matches.some((m) => m.rule === 'prompt_injection_base64_in_comment')).toBe(true);
      }
    });

    it('matches long base64 in a /* block comment */', async () => {
      const result = await scan(`/* ${LONG_B64} */`);
      expect(result.matched).toBe(true);
    });

    it('matches long base64 in a Python # comment', async () => {
      const result = await scan(`def foo():\n    # ${LONG_B64}\n    pass`);
      expect(result.matched).toBe(true);
    });

    it('matches long base64 in a shell # comment', async () => {
      const result = await scan(`#!/bin/bash\n# ${LONG_B64}\necho hi`);
      expect(result.matched).toBe(true);
    });

    it('matches long base64 in a SQL -- comment', async () => {
      const result = await scan(`SELECT 1;\n-- ${LONG_B64}\nSELECT 2;`);
      expect(result.matched).toBe(true);
    });

    it('matches long base64 in an HTML <!-- comment -->', async () => {
      const result = await scan(`<div>x</div>\n<!-- ${LONG_B64} -->`);
      expect(result.matched).toBe(true);
    });

    it('matches base64 with trailing "=" padding', async () => {
      const result = await scan(`// ${LONG_B64}==\n`);
      expect(result.matched).toBe(true);
    });

    it('matches a 40-char padded blob (at the floor)', async () => {
      const result = await scan(`// ${FLOOR_PADDED}\n`);
      expect(result.matched).toBe(true);
    });

    it('matches a 40-char unpadded blob (at the floor)', async () => {
      const result = await scan(`// ${FLOOR_UNPADDED}\n`);
      expect(result.matched).toBe(true);
    });
  });

  describe('negative cases — should NOT match', () => {
    it('does NOT match a 30-char padded blob (under the floor)', async () => {
      const result = await scan(`// ${SHORT_PADDED}`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match a 30-char unpadded blob (under the floor)', async () => {
      const result = await scan(`// ${SHORT_UNPADDED}`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match long base64 in actual code (not a comment)', async () => {
      const result = await scan(`const HASH = "${LONG_B64}";`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match a normal code comment', async () => {
      const result = await scan(`// This function adds two numbers together for tests.`);
      expect(result.matched).toBe(false);
    });

    it('does NOT fire on unrelated content', async () => {
      const result = await scan(`regular sentence with no base64 whatsoever`);
      expect(result.matched).toBe(false);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `// ${LONG_B64}`,
        'prompt_injection_base64_in_comment',
        { severity: 'critical', category: 'prompt_injection', action: 'block' },
      );
    });
  });
});
