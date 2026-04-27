import { describe, it } from 'vitest';
import {
  expectRuleMatch,
  expectRuleDidNotMatch,
  expectRuleMetadata,
  FAKE_GITHUB_PAT_CLASSIC,
  FAKE_GITHUB_PAT_SERVER,
} from '../helpers.js';

const RULE = 'hardcoded_github_pat';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches a ghp_ classic personal access token', async () => {
      await expectRuleMatch(
        `const token = "${FAKE_GITHUB_PAT_CLASSIC}";`,
        RULE,
      );
    });

    it('matches a ghs_ server-to-server token', async () => {
      await expectRuleMatch(
        `const token = "${FAKE_GITHUB_PAT_SERVER}";`,
        RULE,
      );
    });

    it('matches a ghr_ refresh token', async () => {
      await expectRuleMatch(
        `const refresh = "ghr_111122223333444455556666777788889999";`,
        RULE,
      );
    });

    it('matches a ghp_ token in a .env-style line', async () => {
      await expectRuleMatch(
        `GITHUB_TOKEN=${FAKE_GITHUB_PAT_CLASSIC}`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match a github_pat_ fine-grained token (different shape, separate rule)', async () => {
      await expectRuleDidNotMatch(
        `const token = "github_pat_11AAAAAAA0AAAAAAAAAAAAAA_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";`,
        RULE,
      );
    });

    it('does NOT match a ghp_ token with only 35 chars after the prefix', async () => {
      await expectRuleDidNotMatch(
        `const tooShort = "ghp_11112222333344445555666677778888999";`,
        RULE,
      );
    });

    it('does NOT match ghp_ embedded inside a longer word-char identifier', async () => {
      await expectRuleDidNotMatch(
        `const id = "PREFIXghp_111122223333444455556666777788889999";`,
        RULE,
      );
    });

    it('does NOT match an uppercase GHP_ prefix (real tokens are lowercase)', async () => {
      await expectRuleDidNotMatch(
        `const token = "GHP_111122223333444455556666777788889999";`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `const token = "${FAKE_GITHUB_PAT_CLASSIC}";`,
        RULE,
        { severity: 'critical', category: 'hardcoded_secret', action: 'remediate' },
      );
    });
  });
});
