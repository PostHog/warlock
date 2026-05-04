import { describe, it } from 'vitest';
import {
  expectRuleMatch,
  expectRuleDidNotMatch,
  expectRuleMetadata,
  FAKE_AWS_ACCESS_KEY,
  FAKE_AWS_SESSION_TOKEN,
} from '../helpers.js';

const RULE = 'hardcoded_aws_credential';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches an AKIA access key in a direct variable assignment', async () => {
      await expectRuleMatch(
        `const accessKey = "${FAKE_AWS_ACCESS_KEY}";`,
        RULE,
      );
    });

    it('matches an AKIA access key in an AWS SDK config object', async () => {
      await expectRuleMatch(
        `new S3Client({ credentials: { accessKeyId: "${FAKE_AWS_ACCESS_KEY}", secretAccessKey: "..." } })`,
        RULE,
      );
    });

    it('matches an AKIA access key in a .env-style line', async () => {
      await expectRuleMatch(
        `AWS_ACCESS_KEY_ID=${FAKE_AWS_ACCESS_KEY}`,
        RULE,
      );
    });

    it('matches an ASIA session token in code', async () => {
      await expectRuleMatch(
        `const sessionToken = "${FAKE_AWS_SESSION_TOKEN}";`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match an AGPA prefix (group ID, not a credential)', async () => {
      await expectRuleDidNotMatch(
        `const groupId = "AGPA1111222233334444";`,
        RULE,
      );
    });

    it('does NOT match a string with only 15 chars after AKIA', async () => {
      await expectRuleDidNotMatch(
        `const tooShort = "AKIA111122223333444";`,
        RULE,
      );
    });

    it('does NOT match AKIA embedded inside a longer word-char identifier', async () => {
      await expectRuleDidNotMatch(
        `const id = "PREFIXAKIA1111222233334444";`,
        RULE,
      );
    });

    it('does NOT match a lowercase akia prefix', async () => {
      await expectRuleDidNotMatch(
        `const id = "akia1111222233334444";`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `const accessKey = "${FAKE_AWS_ACCESS_KEY}";`,
        RULE,
        { severity: 'critical', category: 'hardcoded_secret', action: 'remediate' },
      );
    });
  });
});
