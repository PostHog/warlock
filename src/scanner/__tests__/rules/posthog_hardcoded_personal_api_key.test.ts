import { describe, it, expect } from 'vitest';
import { scan } from '../../engine.js';
import { expectRuleMetadata, FAKE_PERSONAL_KEY } from '../helpers.js';

describe('posthog_hardcoded_personal_api_key', () => {
  describe('positive cases — should match', () => {
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

  describe('negative cases — should NOT match', () => {
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
        { severity: 'critical', category: 'posthog_hardcoded_key', action: 'revert' },
      );
    });
  });
});
