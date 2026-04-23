import { describe, it, expect } from 'vitest';
import { scan } from '../../engine.js';
import { expectRuleMetadata } from '../helpers.js';

describe('posthog_pii_in_capture_call', () => {
  describe('positive cases — should match', () => {
    it('matches email in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('signup', { email: user.email });`);
      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.matches.some((m) => m.rule === 'posthog_pii_in_capture_call')).toBe(true);
      }
    });

    it('matches emailAddress (camelCase variant) in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('signup', { emailAddress: user.emailAddress });`);
      expect(result.matched).toBe(true);
    });

    it('matches phone in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('form', { phone: user.phone });`);
      expect(result.matched).toBe(true);
    });

    it('matches phoneNumber (camelCase variant)', async () => {
      const result = await scan(`posthog.capture('form', { phoneNumber: '555-1234' });`);
      expect(result.matched).toBe(true);
    });

    it('matches full_name in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('signup', { full_name: 'Jane Doe' });`);
      expect(result.matched).toBe(true);
    });

    it('matches ssn in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('kyc', { ssn: user.ssn });`);
      expect(result.matched).toBe(true);
    });

    it('matches date_of_birth in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('kyc', { date_of_birth: '1990-01-01' });`);
      expect(result.matched).toBe(true);
    });

    it('matches street_address in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('order', { street_address: '123 Main St' });`);
      expect(result.matched).toBe(true);
    });

    it('matches credit_card in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('checkout', { credit_card: '4111...' });`);
      expect(result.matched).toBe(true);
    });

    it('matches $ip in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('pageview', { $ip: request.ip });`);
      expect(result.matched).toBe(true);
    });

    it('matches passport in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('kyc', { passport: user.passport });`);
      expect(result.matched).toBe(true);
    });

    it('matches drivers_license in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('kyc', { drivers_license: 'D12345' });`);
      expect(result.matched).toBe(true);
    });

    it('matches bank_account in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('payout', { bank_account: '12345' });`);
      expect(result.matched).toBe(true);
    });

    it('matches medical_record in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('visit', { medical_record: 'MRN-123' });`);
      expect(result.matched).toBe(true);
    });

    it('matches national_id in posthog.capture()', async () => {
      const result = await scan(`posthog.capture('signup', { national_id: 'X123' });`);
      expect(result.matched).toBe(true);
    });

    it('matches ssn in posthog.identify() (sensitive PII in identify is NOT ok)', async () => {
      const result = await scan(`posthog.identify(userId, { ssn: user.ssn });`);
      expect(result.matched).toBe(true);
    });

    it('matches credit_card in posthog.identify()', async () => {
      const result = await scan(`posthog.identify(userId, { credit_card: '4111...' });`);
      expect(result.matched).toBe(true);
    });

    it('matches email inside $set property object', async () => {
      const result = await scan(`posthog.capture('event', { $set: { email: user.email } });`);
      expect(result.matched).toBe(true);
    });

    it('matches with JSON-style key quoting', async () => {
      const result = await scan(`posthog.capture('event', { "email": user.email });`);
      expect(result.matched).toBe(true);
    });

    it('matches with single-quoted Python-style keys', async () => {
      const result = await scan(`posthog.capture('event', { 'email': user.email })`);
      expect(result.matched).toBe(true);
    });
  });

  describe('negative cases — should NOT match', () => {
    it('does NOT match email_verified (prefix of email, but different field)', async () => {
      const result = await scan(`posthog.capture('event', { email_verified: true });`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match phone_call_duration (prefix of phone, but different field)', async () => {
      const result = await scan(`posthog.capture('event', { phone_call_duration: 30 });`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match addressBook (prefix of address, but different field)', async () => {
      const result = await scan(`posthog.capture('event', { addressBook_count: 42 });`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match safe capture call with non-PII properties', async () => {
      const result = await scan(`posthog.capture('button_clicked', { button: 'submit', page: '/signup' });`);
      expect(result.matched).toBe(false);
    });

    it('ALLOWS email in posthog.identify() — standard identifying field', async () => {
      const result = await scan(`posthog.identify(userId, { email: user.email });`);
      expect(result.matched).toBe(false);
    });

    it('ALLOWS firstName/lastName in posthog.identify() — standard identifying fields', async () => {
      const result = await scan(`posthog.identify(userId, { firstName: 'Jane', lastName: 'Doe' });`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match capture() with no PII', async () => {
      const result = await scan(`posthog.capture('pageview');`);
      expect(result.matched).toBe(false);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `posthog.capture('signup', { email: user.email });`,
        'posthog_pii_in_capture_call',
        { severity: 'high', category: 'posthog_pii', action: 'revert' },
      );
    });
  });
});
