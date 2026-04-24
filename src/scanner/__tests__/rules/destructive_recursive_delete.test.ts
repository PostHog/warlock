import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'destructive_recursive_delete';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches rm -rf node_modules', async () => {
      await expectRuleMatch(`rm -rf node_modules`, RULE);
    });

    it('matches rm -rf build/', async () => {
      await expectRuleMatch(`rm -rf build/`, RULE);
    });

    it('matches rm -fr dist', async () => {
      await expectRuleMatch(`rm -fr dist`, RULE);
    });

    it('matches rm -Rf some-folder', async () => {
      await expectRuleMatch(`rm -Rf some-folder`, RULE);
    });

    it('matches rm -r -f tmp', async () => {
      await expectRuleMatch(`rm -r -f tmp`, RULE);
    });

    it('matches rm --recursive --force cache', async () => {
      await expectRuleMatch(`rm --recursive --force cache`, RULE);
    });

    it('matches find ./logs -delete', async () => {
      await expectRuleMatch(`find ./logs -name "*.log" -delete`, RULE);
    });

    it('matches find . -exec rm -rf {}', async () => {
      await expectRuleMatch(`find . -type d -name "__pycache__" -exec rm -rf {} +`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match non-recursive rm', async () => {
      await expectRuleDidNotMatch(`rm ./tmp/file.txt`, RULE);
    });

    it('does NOT match rm -i (interactive, safer)', async () => {
      await expectRuleDidNotMatch(`rm -i some-file.txt`, RULE);
    });

    it('does NOT match find . -name with no delete', async () => {
      await expectRuleDidNotMatch(`find . -name "*.log"`, RULE);
    });

    it('does NOT match unrelated prose', async () => {
      await expectRuleDidNotMatch(`We cleaned up the build directory before shipping.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `rm -rf node_modules`,
        RULE,
        { severity: 'medium', category: 'destructive_operations', action: 'warn' },
      );
    });
  });
});
