import { describe, it } from 'vitest';
import {
  expectRuleMatch,
  expectRuleDidNotMatch,
  expectRuleMetadata,
} from '../helpers.js';

const RULE = 'posthog_pii_value_in_tracking_call';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches an email literal under an innocuous key in capture()', async () => {
      await expectRuleMatch(
        `posthog.capture('signup', { referrer: 'jane@example.com' })`,
        RULE,
      );
    });

    it('matches a dashed SSN value in capture()', async () => {
      await expectRuleMatch(
        `posthog.capture('kyc', { value: '123-45-6789' })`,
        RULE,
      );
    });

    it('matches a dashed SSN value in identify()', async () => {
      await expectRuleMatch(
        `posthog.identify('user-1', { note: '123-45-6789' })`,
        RULE,
      );
    });

    it('matches a space-grouped card number in capture()', async () => {
      await expectRuleMatch(
        `posthog.capture('payment', { num: '4111 1111 1111 1111' })`,
        RULE,
      );
    });

    it('matches a dash-grouped card number in setPersonProperties()', async () => {
      await expectRuleMatch(
        `posthog.setPersonProperties({ ref: '4111-1111-1111-1111' })`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match an email value in identify() (the standard pattern)', async () => {
      await expectRuleDidNotMatch(
        `posthog.identify('user-1', { email: 'jane@example.com' })`,
        RULE,
      );
    });

    it('does NOT match an unseparated 16-digit run (no Luhn check available)', async () => {
      await expectRuleDidNotMatch(
        `posthog.capture('order', { orderId: '4111111111111111' })`,
        RULE,
      );
    });

    it('does NOT match a capture call with no PII-shaped value', async () => {
      await expectRuleDidNotMatch(
        `posthog.capture('clicked', { button: 'subscribe', plan: 'pro' })`,
        RULE,
      );
    });

    it('does NOT match an SSN value nested inside a $set object', async () => {
      await expectRuleDidNotMatch(
        `posthog.setPersonProperties({ $set: { ssn: '123-45-6789' } })`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes required metadata fields', async () => {
      await expectRuleMetadata(
        `posthog.capture('signup', { referrer: 'jane@example.com' })`,
        RULE,
        { severity: 'high', category: 'posthog_pii', action: 'remediate' },
      );
    });
  });
});
