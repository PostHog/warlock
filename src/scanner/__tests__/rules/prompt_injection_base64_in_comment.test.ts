import { describe, it, expect } from 'vitest';
import { scan } from '../../engine.js';
import { expectRuleMetadata } from '../helpers.js';

// 120 base64-safe characters, comfortably above the 100-char floor,
// clearly synthetic
const LONG_B64 = 'A'.repeat(120);
const SHORT_B64 = 'A'.repeat(50);

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
  });

  describe('negative cases — should NOT match', () => {
    it('does NOT match short base64 under the 100-char floor', async () => {
      const result = await scan(`// ${SHORT_B64}`);
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
