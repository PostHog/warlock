import { describe, it, expect } from 'vitest';
import { scan } from '../../engine.js';
import { expectRuleMetadata, FAKE_PROJECT_TOKEN } from '../helpers.js';

describe('posthog_hardcoded_project_token', () => {
  describe('positive cases — should match', () => {
    it('matches a phc_ token in a string literal assignment', async () => {
      const result = await scan(`const TOKEN = "${FAKE_PROJECT_TOKEN}";`);
      expect(result.matched).toBe(true);
      if (result.matched) {
        expect(result.matches.some((m) => m.rule === 'posthog_hardcoded_project_token')).toBe(true);
      }
    });

    it('matches a phc_ token in posthog.init()', async () => {
      const result = await scan(`posthog.init('${FAKE_PROJECT_TOKEN}', { api_host: 'https://app.posthog.com' });`);
      expect(result.matched).toBe(true);
    });

    it('matches a phc_ token in a JSON config file', async () => {
      const result = await scan(`{ "posthog_token": "${FAKE_PROJECT_TOKEN}" }`);
      expect(result.matched).toBe(true);
    });

    it('matches a phc_ token in a TOML config file', async () => {
      const result = await scan(`posthog_token = "${FAKE_PROJECT_TOKEN}"`);
      expect(result.matched).toBe(true);
    });

    it('matches a phc_ token in a URL query param', async () => {
      const result = await scan(`https://app.posthog.com/signup?token=${FAKE_PROJECT_TOKEN}`);
      expect(result.matched).toBe(true);
    });
  });

  describe('negative cases — should NOT match', () => {
    it('does NOT match env var reference', async () => {
      const result = await scan(`posthog.init(process.env.POSTHOG_KEY);`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match short placeholder tokens (under 30 chars)', async () => {
      const result = await scan(`const TOKEN = "phc_EXAMPLE";`);
      expect(result.matched).toBe(false);
    });

    it('does NOT match phc_ embedded in a longer identifier', async () => {
      const result = await scan(`const my_phc_thing_1111111111222222222233333333334444 = true;`);
      expect(result.matched).toBe(false);
    });

    it('does NOT fire on unrelated content', async () => {
      const result = await scan(`just a plain old comment with no tokens`);
      expect(result.matched).toBe(false);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `const TOKEN = "${FAKE_PROJECT_TOKEN}";`,
        'posthog_hardcoded_project_token',
        { severity: 'medium', category: 'posthog_hardcoded_key', action: 'revert' },
      );
    });
  });
});
