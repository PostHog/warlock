import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata, FAKE_PROJECT_TOKEN } from '../helpers.js';

const RULE = 'posthog_hardcoded_project_token';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches a phc_ token in a string literal assignment', async () => {
      await expectRuleMatch(`const TOKEN = "${FAKE_PROJECT_TOKEN}";`, RULE);
    });

    it('matches a phc_ token in a posthog.init() call', async () => {
      await expectRuleMatch(`posthog.init("${FAKE_PROJECT_TOKEN}", { api_host: "https://us.posthog.com" });`, RULE);
    });

    it('matches a phc_ token in a config YAML value', async () => {
      await expectRuleMatch(`posthog_project_api_key: ${FAKE_PROJECT_TOKEN}`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match an env var reference (no literal token)', async () => {
      await expectRuleDidNotMatch(`posthog.init(process.env.POSTHOG_PROJECT_KEY);`, RULE);
    });

    it('does NOT match an obvious placeholder token', async () => {
      await expectRuleDidNotMatch(`const TOKEN = "phc_your1111111111222222222233333333334444";`, RULE);
    });

    it('does NOT match a short placeholder (under 30 chars)', async () => {
      await expectRuleDidNotMatch(`const TOKEN = "phc_YOUR_TOKEN_HERE";`, RULE);
    });

    it('does NOT match phc_ embedded in a longer identifier', async () => {
      await expectRuleDidNotMatch(`const my_phc_variable_1111111111222222222233333333334444 = true;`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `const TOKEN = "${FAKE_PROJECT_TOKEN}";`,
        RULE,
        { severity: 'medium', category: 'posthog_hardcoded_key', action: 'remediate' },
      );
    });
  });
});
