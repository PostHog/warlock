import { describe, it } from 'vitest';
import {
  expectRuleMatch,
  expectRuleDidNotMatch,
  expectRuleMetadata,
} from '../helpers.js';

const RULE = 'posthog_pii_in_person_properties';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches an SSN in setPersonProperties()', async () => {
      await expectRuleMatch(
        `posthog.setPersonProperties({ ssn: userSsn })`,
        RULE,
      );
    });

    it('matches a credit card in register()', async () => {
      await expectRuleMatch(
        `posthog.register({ credit_card: card })`,
        RULE,
      );
    });

    it('matches a date of birth in setPersonPropertiesForFlags()', async () => {
      await expectRuleMatch(
        `posthog.setPersonPropertiesForFlags({ dateOfBirth: dob })`,
        RULE,
      );
    });

    it('matches a bank account in register_once()', async () => {
      await expectRuleMatch(
        `posthog.register_once({ bank_account: acct })`,
        RULE,
      );
    });

    it('matches a quoted-key JSON-style config', async () => {
      await expectRuleMatch(
        `posthog.setPersonProperties({ "passport_number": value })`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match email (a standard person property)', async () => {
      await expectRuleDidNotMatch(
        `posthog.setPersonProperties({ email: user.email })`,
        RULE,
      );
    });

    it('does NOT match a name (a standard person property)', async () => {
      await expectRuleDidNotMatch(
        `posthog.register({ first_name: user.firstName })`,
        RULE,
      );
    });

    it('does NOT match sensitive PII in capture() (handled by the sibling rule)', async () => {
      await expectRuleDidNotMatch(
        `posthog.capture('checkout', { ssn: userSsn })`,
        RULE,
      );
    });

    it('does NOT match a nested $set object (FP-avoidance scoping)', async () => {
      await expectRuleDidNotMatch(
        `posthog.setPersonProperties({ $set: { ssn: userSsn } })`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes required metadata fields', async () => {
      await expectRuleMetadata(
        `posthog.setPersonProperties({ ssn: userSsn })`,
        RULE,
        { severity: 'high', category: 'posthog_pii', action: 'remediate' },
      );
    });
  });
});
