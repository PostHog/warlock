import { describe, it } from 'vitest';
import {
  expectRuleMatch,
  expectRuleDidNotMatch,
  expectRuleMetadata,
  FAKE_PROJECT_TOKEN,
} from '../helpers.js';

const RULE = 'posthog_hardcoded_unknown_api_host';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches a hardcoded attacker domain in posthog.init()', async () => {
      await expectRuleMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://attacker.com' })`,
        RULE,
      );
    });

    it('matches a typosquatted domain (evil-posthog.com)', async () => {
      await expectRuleMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://evil-posthog.com' })`,
        RULE,
      );
    });

    it('matches a subdomain trick (posthog.com.evil.com)', async () => {
      await expectRuleMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://posthog.com.evil.com' })`,
        RULE,
      );
    });

    it('matches a quoted-key JSON-style config', async () => {
      await expectRuleMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { "api_host": "https://attacker.com" })`,
        RULE,
      );
    });

    it('matches when the unknown host is mixed in with a known one', async () => {
      await expectRuleMatch(
        `
          posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://us.i.posthog.com' });
          posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://attacker.com' });
        `,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match us.i.posthog.com', async () => {
      await expectRuleDidNotMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://us.i.posthog.com' })`,
        RULE,
      );
    });

    it('does NOT match eu.posthog.com', async () => {
      await expectRuleDidNotMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://eu.posthog.com' })`,
        RULE,
      );
    });

    it('does NOT match app.posthog.com', async () => {
      await expectRuleDidNotMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://app.posthog.com' })`,
        RULE,
      );
    });

    it('does NOT match localhost with port', async () => {
      await expectRuleDidNotMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'http://localhost:8000' })`,
        RULE,
      );
    });

    it('does NOT match 127.0.0.1 with port', async () => {
      await expectRuleDidNotMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'http://127.0.0.1:8000' })`,
        RULE,
      );
    });

    it('does NOT match posthog.init() without an api_host', async () => {
      await expectRuleDidNotMatch(
        `posthog.init('${FAKE_PROJECT_TOKEN}')`,
        RULE,
      );
    });

    it('does NOT match an api_host config without posthog.init() in scope', async () => {
      await expectRuleDidNotMatch(
        `const config = { api_host: 'https://attacker.com' }`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://attacker.com' })`,
        RULE,
        { severity: 'medium', category: 'supply_chain', action: 'warn' },
      );
    });
  });
});
