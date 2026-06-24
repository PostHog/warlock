import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'supply_chain_npx_in_skill';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches npx with a package name', async () => {
      await expectRuleMatch(`npx create-next-app my-app`, RULE);
    });

    it('matches npx with a scoped package', async () => {
      await expectRuleMatch(`npx @angular/cli new my-app`, RULE);
    });

    it('matches pnpm dlx with a package', async () => {
      await expectRuleMatch(`pnpm dlx some-tool`, RULE);
    });

    it('matches yarn dlx with a package', async () => {
      await expectRuleMatch(`yarn dlx some-tool`, RULE);
    });

    it('matches bunx with a package', async () => {
      await expectRuleMatch(`bunx some-tool`, RULE);
    });

    it('matches npx in a markdown code block', async () => {
      await expectRuleMatch(
        '```bash\nnpx some-tool --flag\n```',
        RULE,
      );
    });

    it('matches npx in a SKILL.md instruction', async () => {
      await expectRuleMatch(
        `To get started, run:\nnpx some-scaffolder init`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match bare npx without a package', async () => {
      await expectRuleDidNotMatch(`npx --help`, RULE);
    });

    it('does NOT match npx followed by a flag only (no package)', async () => {
      await expectRuleDidNotMatch(
        `npx --version`,
        RULE,
      );
    });

    it('does NOT match npm install (different command)', async () => {
      await expectRuleDidNotMatch(`npm install typescript`, RULE);
    });

    it('does NOT match pnpm add (different subcommand)', async () => {
      await expectRuleDidNotMatch(`pnpm add some-pkg`, RULE);
    });

    it('does NOT match yarn add (different subcommand)', async () => {
      await expectRuleDidNotMatch(`yarn add some-pkg`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `npx create-next-app my-app`,
        RULE,
        { severity: 'high', category: 'supply_chain', action: 'warn' },
      );
    });
  });
});
