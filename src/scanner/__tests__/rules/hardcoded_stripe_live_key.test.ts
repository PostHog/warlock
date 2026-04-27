import { describe, it } from 'vitest';
import {
  expectRuleMatch,
  expectRuleDidNotMatch,
  expectRuleMetadata,
  FAKE_STRIPE_LIVE_SECRET,
  FAKE_STRIPE_LIVE_RESTRICTED,
  FAKE_STRIPE_TEST_KEY,
  FAKE_STRIPE_PUBLISHABLE_KEY,
} from '../helpers.js';

const RULE = 'hardcoded_stripe_live_key';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches an sk_live_ secret key in a direct variable assignment', async () => {
      await expectRuleMatch(
        `const stripeKey = "${FAKE_STRIPE_LIVE_SECRET}";`,
        RULE,
      );
    });

    it('matches an sk_live_ secret key in a Stripe SDK init call', async () => {
      await expectRuleMatch(
        `const stripe = new Stripe("${FAKE_STRIPE_LIVE_SECRET}");`,
        RULE,
      );
    });

    it('matches an rk_live_ restricted key in code', async () => {
      await expectRuleMatch(
        `const restricted = "${FAKE_STRIPE_LIVE_RESTRICTED}";`,
        RULE,
      );
    });

    it('matches an sk_live_ key in a .env-style line', async () => {
      await expectRuleMatch(
        `STRIPE_SECRET_KEY=${FAKE_STRIPE_LIVE_SECRET}`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match an sk_test_ key (test mode is not sensitive)', async () => {
      await expectRuleDidNotMatch(
        `const stripeKey = "${FAKE_STRIPE_TEST_KEY}";`,
        RULE,
      );
    });

    it('does NOT match a pk_live_ publishable key (designed to be public)', async () => {
      await expectRuleDidNotMatch(
        `const stripeKey = "${FAKE_STRIPE_PUBLISHABLE_KEY}";`,
        RULE,
      );
    });

    it('does NOT match an sk_live_ key with only 23 chars after the prefix', async () => {
      await expectRuleDidNotMatch(
        `const tooShort = "sk_live_1111222233334444aaaabbb";`,
        RULE,
      );
    });

    it('does NOT match sk_live_ embedded inside a longer word-char identifier', async () => {
      await expectRuleDidNotMatch(
        `const id = "PREFIXsk_live_1111222233334444aaaabbbb";`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `const stripeKey = "${FAKE_STRIPE_LIVE_SECRET}";`,
        RULE,
        { severity: 'critical', category: 'hardcoded_secret', action: 'remediate' },
      );
    });
  });
});
