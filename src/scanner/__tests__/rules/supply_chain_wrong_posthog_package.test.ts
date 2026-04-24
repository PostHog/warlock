import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'supply_chain_wrong_posthog_package';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches npm install posthog', async () => {
      await expectRuleMatch(`npm install posthog`, RULE);
    });

    it('matches npm i posthog', async () => {
      await expectRuleMatch(`npm i posthog`, RULE);
    });

    it('matches pnpm add posthog', async () => {
      await expectRuleMatch(`pnpm add posthog`, RULE);
    });

    it('matches yarn add posthog', async () => {
      await expectRuleMatch(`yarn add posthog`, RULE);
    });

    it('matches bun add posthog', async () => {
      await expectRuleMatch(`bun add posthog`, RULE);
    });

    it('matches deno add posthog', async () => {
      await expectRuleMatch(`deno add posthog`, RULE);
    });

    it('matches npm install --save posthog', async () => {
      await expectRuleMatch(`npm install --save posthog`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match npm install posthog-js', async () => {
      await expectRuleDidNotMatch(`npm install posthog-js`, RULE);
    });

    it('does NOT match npm install posthog-node', async () => {
      await expectRuleDidNotMatch(`npm install posthog-node`, RULE);
    });

    it('does NOT match yarn add posthog-react-native', async () => {
      await expectRuleDidNotMatch(`yarn add posthog-react-native`, RULE);
    });

    it('does NOT match pip install posthog (Python SDK is correct bare)', async () => {
      await expectRuleDidNotMatch(`pip install posthog`, RULE);
    });

    it('does NOT match gem install posthog-ruby', async () => {
      await expectRuleDidNotMatch(`gem install posthog-ruby`, RULE);
    });

    it('does NOT match unrelated prose', async () => {
      await expectRuleDidNotMatch(`We just set up PostHog in the new service.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `npm install posthog`,
        RULE,
        { severity: 'high', category: 'supply_chain', action: 'block' },
      );
    });
  });
});
