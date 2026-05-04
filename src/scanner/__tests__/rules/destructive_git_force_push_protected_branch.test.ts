import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'destructive_git_force_push_protected_branch';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches git push --force origin main', async () => {
      await expectRuleMatch(`git push --force origin main`, RULE);
    });

    it('matches git push -f origin master', async () => {
      await expectRuleMatch(`git push -f origin master`, RULE);
    });

    it('matches git push --force origin develop', async () => {
      await expectRuleMatch(`git push --force origin develop`, RULE);
    });

    it('matches git push --force origin production', async () => {
      await expectRuleMatch(`git push --force origin production`, RULE);
    });

    it('matches git push --delete origin main', async () => {
      await expectRuleMatch(`git push --delete origin main`, RULE);
    });

    it('matches git push origin :main (colon deletion syntax)', async () => {
      await expectRuleMatch(`git push origin :main`, RULE);
    });

    it('matches git push --mirror', async () => {
      await expectRuleMatch(`git push --mirror origin`, RULE);
    });

    it('matches git push --prune', async () => {
      await expectRuleMatch(`git push --prune origin`, RULE);
    });

    it('matches git push --force origin staging', async () => {
      await expectRuleMatch(`git push --force origin staging`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match git push --force on a feature branch', async () => {
      await expectRuleDidNotMatch(`git push --force origin feature/my-thing`, RULE);
    });

    it('does NOT match a plain git push to main', async () => {
      await expectRuleDidNotMatch(`git push origin main`, RULE);
    });

    it('does NOT match git pull', async () => {
      await expectRuleDidNotMatch(`git pull origin main`, RULE);
    });

    it('does NOT match unrelated prose', async () => {
      await expectRuleDidNotMatch(`We pushed the release branch out to production today.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `git push --force origin main`,
        RULE,
        { severity: 'critical', category: 'destructive_operations', action: 'block' },
      );
    });
  });
});
