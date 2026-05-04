import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'exfiltration_gh_api_write';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches gh api -X POST', async () => {
      await expectRuleMatch(`gh api -X POST /repos/foo/bar/issues`, RULE);
    });

    it('matches gh api -X PUT', async () => {
      await expectRuleMatch(`gh api -X PUT /repos/foo/bar/contents/x`, RULE);
    });

    it('matches gh api -X PATCH', async () => {
      await expectRuleMatch(`gh api -X PATCH /repos/foo/bar/issues/1`, RULE);
    });

    it('matches gh api -X DELETE', async () => {
      await expectRuleMatch(`gh api -X DELETE /repos/foo/bar/issues/1`, RULE);
    });

    it('matches gh api --method POST (long form)', async () => {
      await expectRuleMatch(`gh api --method POST /repos/foo/bar/issues`, RULE);
    });

    it('matches gh api with endpoint before -X flag', async () => {
      await expectRuleMatch(`gh api /repos/foo/bar/issues -X POST`, RULE);
    });

    it('matches -X=POST (equals-sign delimiter)', async () => {
      await expectRuleMatch(`gh api -X=POST /repos/foo/bar/issues`, RULE);
    });

    it('matches --method=DELETE (equals-sign, long form)', async () => {
      await expectRuleMatch(`gh api --method=DELETE /repos/foo/bar/issues/1`, RULE);
    });

    it('matches lowercase method (gh api -X post)', async () => {
      await expectRuleMatch(`gh api -X post /repos/foo/bar/issues`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match bare gh api (defaults to GET)', async () => {
      await expectRuleDidNotMatch(`gh api /repos/foo/bar`, RULE);
    });

    it('does NOT match gh api -X GET (explicit read)', async () => {
      await expectRuleDidNotMatch(`gh api -X GET /repos/foo/bar`, RULE);
    });

    it('does NOT match gh api --method GET', async () => {
      await expectRuleDidNotMatch(`gh api --method GET /repos/foo/bar`, RULE);
    });

    it('does NOT match other gh subcommands', async () => {
      await expectRuleDidNotMatch(`gh repo create my-repo`, RULE);
    });

    it('does NOT match prose mentioning gh api', async () => {
      await expectRuleDidNotMatch(`See the gh api docs for details.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `gh api -X POST /repos/foo/bar/issues`,
        RULE,
        { severity: 'high', category: 'exfiltration', action: 'warn' },
      );
    });
  });
});
