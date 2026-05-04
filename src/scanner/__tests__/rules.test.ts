/**
 * Rule tests for the Warlock.
 *
 * Organized by rule category (matching `src/scanner/rules/`), not by test
 * type. Add new rules in their category's section; add new categories in
 * the order they appear in `CATEGORIES` (see `src/scanner/types.ts`).
 *
 * Every rule block follows the same structure:
 *   - "positive cases – should match"    (what the rule is meant to catch)
 *   - "negative cases – should NOT match" (FP guards per CONTRIBUTING.md)
 *   - "metadata"                          (required-field contract)
 *
 * Category sections in use:
 *   ┌─ PostHog API (posthog_pii, posthog_hardcoded_key)
 *   └─ (prompt_injection, exfiltration, destructive_operations,
 *       supply_chain – coming in future PRs)
 */

import { describe, it, expect } from 'vitest';
import { scan } from '../engine.js';

// ═══════════════════════════════════════════════════════════════════════════
// TEST UTILITIES
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Asserts a matched rule exposes every required metadata field
 * (`description`, `remediation`, `severity`, `category`, `action`).
 *
 * Each rule's describe block calls this once via a "metadata" sub-block so
 * a future contributor can't ship a rule missing required fields.
 */
async function expectRuleMetadata(
  content: string,
  ruleName: string,
  expected: { severity: string; category: string; action: string },
) {
  const result = await scan(content);
  if (!result.matched) throw new Error(`expected scan to match for rule ${ruleName}`);

  const match = result.matches.find((m) => m.rule === ruleName);
  expect(match).toBeDefined();
  expect(typeof match?.metadata.description).toBe('string');
  expect(match?.metadata.description).toBeTruthy();
  expect(typeof match?.metadata.remediation).toBe('string');
  expect(match?.metadata.remediation).toBeTruthy();
  expect(match?.metadata.severity).toBe(expected.severity);
  expect(match?.metadata.category).toBe(expected.category);
  expect(match?.metadata.action).toBe(expected.action);
}

// ─── Fake-key fixtures ─────────────────────────────────────────────────────
//
// Structurally valid (trigger the rule) but visually unambiguous as fake
// (repeating-digit bodies). Real enough to match our 30+ alphanumeric floor,
// clearly not a real token to human readers or secret scanners.
const FAKE_PERSONAL_KEY = 'phx_1111111111222222222233333333334444';

// ═══════════════════════════════════════════════════════════════════════════
// CATEGORY: POSTHOG API
// ═══════════════════════════════════════════════════════════════════════════
//
// Rules that detect misuse of PostHog-specific SDK surfaces: PII in tracking
// calls, hardcoded keys/tokens in source.

// ─── posthog_pii_in_capture_call ───────────────────────────────────────────

describe('posthog_pii_in_capture_call', () => {
  describe('positive cases – should match', () => {
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

    it('matches with JSON-style key quoting', async () => {
      const result = await scan(`posthog.capture('event', { "email": user.email });`);
      expect(result.matched).toBe(true);
    });

    it('matches with single-quoted Python-style keys', async () => {
      const result = await scan(`posthog.capture('event', { 'email': user.email })`);
      expect(result.matched).toBe(true);
    });
  });

  describe('negative cases – should NOT match', () => {
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

    it('does NOT match email in posthog.identify() – allowed as standard identifying field', async () => {
      const result = await scan(`posthog.identify(userId, { email: user.email });`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match firstName/lastName in posthog.identify() – allowed as standard identifying fields', async () => {
      const result = await scan(`posthog.identify(userId, { firstName: 'Jane', lastName: 'Doe' });`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match email inside $set property object – standard person-property pattern', async () => {
      const result = await scan(`posthog.capture('event', { $set: { email: user.email } });`);
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
        { severity: 'high', category: 'posthog_pii', action: 'remediate' },
      );
    });
  });
});

// ─── posthog_hardcoded_personal_api_key ────────────────────────────────────

describe('posthog_hardcoded_personal_api_key', () => {
  describe('positive cases – should match', () => {
    it('matches a phx_ key in a string literal assignment', async () => {
      const result = await scan(`const KEY = "${FAKE_PERSONAL_KEY}";`);
      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.matches.some((m) => m.rule === 'posthog_hardcoded_personal_api_key')).toBe(true);
      }
    });

    it('matches a phx_ key in a config YAML value', async () => {
      const result = await scan(`posthog_personal_api_key: ${FAKE_PERSONAL_KEY}`);
      expect(result.matched).toBe(true);
    });

    it('matches a phx_ key in a URL query param', async () => {
      const result = await scan(`https://app.posthog.com/api/v1/feature_flags?token=${FAKE_PERSONAL_KEY}`);
      expect(result.matched).toBe(true);
    });

    it('matches a phx_ key in a curl Authorization header', async () => {
      const result = await scan(`curl -H "Authorization: Bearer ${FAKE_PERSONAL_KEY}" https://app.posthog.com/api`);
      expect(result.matched).toBe(true);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match env var reference (no literal key)', async () => {
      const result = await scan(`const key = process.env.POSTHOG_PERSONAL_API_KEY;`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match short placeholder keys (under 30 chars)', async () => {
      const result = await scan(`const KEY = "phx_YOUR_KEY_HERE";`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match phx_ embedded in a longer identifier', async () => {
      const result = await scan(`const my_phx_variable_1111111111222222222233333333334444 = true;`);
      expect(result.matched).toBe(false);
    });

    it('does NOT fire on unrelated content', async () => {
      const result = await scan(`hello world, nothing sensitive here`);
      expect(result.matched).toBe(false);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `const KEY = "${FAKE_PERSONAL_KEY}";`,
        'posthog_hardcoded_personal_api_key',
        { severity: 'critical', category: 'posthog_hardcoded_key', action: 'remediate' },
      );
    });
  });
});

