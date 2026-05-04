import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'supply_chain_npm_install_global';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches npm install -g', async () => {
      await expectRuleMatch(`npm install -g typescript`, RULE);
    });

    it('matches npm install --global', async () => {
      await expectRuleMatch(`npm install --global typescript`, RULE);
    });

    it('matches npm i -g', async () => {
      await expectRuleMatch(`npm i -g typescript`, RULE);
    });

    it('matches npm install <pkg> -g (flag after package)', async () => {
      await expectRuleMatch(`npm install typescript -g`, RULE);
    });

    it('matches pnpm add -g', async () => {
      await expectRuleMatch(`pnpm add -g some-pkg`, RULE);
    });

    it('matches pnpm install -g', async () => {
      await expectRuleMatch(`pnpm install -g some-pkg`, RULE);
    });

    it('matches pnpm add --global', async () => {
      await expectRuleMatch(`pnpm add --global some-pkg`, RULE);
    });

    it('matches pnpm i -g', async () => {
      await expectRuleMatch(`pnpm i -g some-pkg`, RULE);
    });

    it('matches yarn global add', async () => {
      await expectRuleMatch(`yarn global add some-pkg`, RULE);
    });

    it('matches bun add -g', async () => {
      await expectRuleMatch(`bun add -g some-pkg`, RULE);
    });

    it('matches bun add --global', async () => {
      await expectRuleMatch(`bun add --global some-pkg`, RULE);
    });

    it('matches deno install -g', async () => {
      await expectRuleMatch(`deno install -g some-pkg`, RULE);
    });

    it('matches deno install --global', async () => {
      await expectRuleMatch(`deno install --global some-pkg`, RULE);
    });

    it('matches cnpm install -g', async () => {
      await expectRuleMatch(`cnpm install -g some-pkg`, RULE);
    });

    it('matches cnpm i --global', async () => {
      await expectRuleMatch(`cnpm i --global some-pkg`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match a local npm install', async () => {
      await expectRuleDidNotMatch(`npm install typescript`, RULE);
    });

    it('does NOT match a local pnpm add', async () => {
      await expectRuleDidNotMatch(`pnpm add some-pkg`, RULE);
    });

    it('does NOT match a local yarn add', async () => {
      await expectRuleDidNotMatch(`yarn add some-pkg`, RULE);
    });

    it('does NOT match yarn workspace add (no -g)', async () => {
      await expectRuleDidNotMatch(`yarn workspace foo add some-pkg`, RULE);
    });

    it('does NOT match --globalize (longer flag, not --global)', async () => {
      await expectRuleDidNotMatch(`npm install --globalize some-pkg`, RULE);
    });

    it('does NOT match prose mentioning "globally"', async () => {
      await expectRuleDidNotMatch(`The package is available globally on npm.`, RULE);
    });

    it('does NOT match a local bun add', async () => {
      await expectRuleDidNotMatch(`bun add some-pkg`, RULE);
    });

    it('does NOT match a local deno install', async () => {
      await expectRuleDidNotMatch(`deno install some-pkg`, RULE);
    });

    it('does NOT match a local cnpm install', async () => {
      await expectRuleDidNotMatch(`cnpm install some-pkg`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `npm install -g typescript`,
        RULE,
        { severity: 'high', category: 'supply_chain', action: 'block' },
      );
    });
  });
});
