import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'destructive_git_force_push';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches git push --force on a feature branch', async () => {
      await expectRuleMatch(`git push --force origin feature/my-thing`, RULE);
    });

    it('matches git push -f on a branch', async () => {
      await expectRuleMatch(`git push -f origin feature/x`, RULE);
    });

    it('matches git push --force-with-lease', async () => {
      await expectRuleMatch(`git push --force-with-lease origin feature/x`, RULE);
    });

    it('matches git push --delete <branch>', async () => {
      await expectRuleMatch(`git push --delete origin old-feature`, RULE);
    });

    it('matches git push origin :old-branch (colon deletion)', async () => {
      await expectRuleMatch(`git push origin :old-branch`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match a plain git push', async () => {
      await expectRuleDidNotMatch(`git push origin feature/x`, RULE);
    });

    it('does NOT match git pull', async () => {
      await expectRuleDidNotMatch(`git pull origin main`, RULE);
    });

    it('does NOT match git fetch', async () => {
      await expectRuleDidNotMatch(`git fetch --all`, RULE);
    });

    it('does NOT match unrelated prose', async () => {
      await expectRuleDidNotMatch(`We pushed the new feature out this morning.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `git push --force origin feature/x`,
        RULE,
        { severity: 'medium', category: 'destructive_operations', action: 'warn' },
      );
    });
  });
});
