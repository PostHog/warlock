import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'destructive_git_working_tree_loss';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches git reset --hard', async () => {
      await expectRuleMatch(`git reset --hard`, RULE);
    });

    it('matches git reset --hard HEAD', async () => {
      await expectRuleMatch(`git reset --hard HEAD`, RULE);
    });

    it('matches git clean -fd', async () => {
      await expectRuleMatch(`git clean -fd`, RULE);
    });

    it('matches git clean -xfd', async () => {
      await expectRuleMatch(`git clean -xfd`, RULE);
    });

    it('matches git clean -f -d', async () => {
      await expectRuleMatch(`git clean -f -d`, RULE);
    });

    it('matches git restore .', async () => {
      await expectRuleMatch(`git restore .`, RULE);
    });

    it('matches git checkout .', async () => {
      await expectRuleMatch(`git checkout .`, RULE);
    });

    it('matches git stash drop', async () => {
      await expectRuleMatch(`git stash drop`, RULE);
    });

    it('matches git stash clear', async () => {
      await expectRuleMatch(`git stash clear`, RULE);
    });

    it('matches git reflog expire --expire=now --all', async () => {
      await expectRuleMatch(`git reflog expire --expire=now --all`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match git reset (no --hard)', async () => {
      await expectRuleDidNotMatch(`git reset HEAD~1`, RULE);
    });

    it('does NOT match git reset --soft', async () => {
      await expectRuleDidNotMatch(`git reset --soft HEAD~1`, RULE);
    });

    it('does NOT match git restore on a specific file', async () => {
      await expectRuleDidNotMatch(`git restore src/foo.ts`, RULE);
    });

    it('does NOT match git checkout <branch>', async () => {
      await expectRuleDidNotMatch(`git checkout main`, RULE);
    });

    it('does NOT match git stash push', async () => {
      await expectRuleDidNotMatch(`git stash push -m "wip"`, RULE);
    });

    it('does NOT match unrelated prose', async () => {
      await expectRuleDidNotMatch(`We rolled back the config after the incident.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `git reset --hard`,
        RULE,
        { severity: 'high', category: 'destructive_operations', action: 'block' },
      );
    });
  });
});
