import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'exfiltration_credential_file_read';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches cat ~/.ssh/id_rsa', async () => {
      await expectRuleMatch(`cat ~/.ssh/id_rsa`, RULE);
    });

    it('matches cat ~/.ssh/id_ed25519', async () => {
      await expectRuleMatch(`cat ~/.ssh/id_ed25519`, RULE);
    });

    it('matches cat ~/.ssh/id_ecdsa', async () => {
      await expectRuleMatch(`cat ~/.ssh/id_ecdsa`, RULE);
    });

    it('matches cat ~/.ssh/id_dsa', async () => {
      await expectRuleMatch(`cat ~/.ssh/id_dsa`, RULE);
    });

    it('matches a bare private-key filename (after cd)', async () => {
      await expectRuleMatch(`head id_rsa`, RULE);
    });

    it('matches an absolute-path SSH key reference', async () => {
      await expectRuleMatch(`cat /home/user/.ssh/id_rsa`, RULE);
    });

    it('matches a backup of a private key (id_rsa.bak)', async () => {
      await expectRuleMatch(`cp id_rsa id_rsa.bak`, RULE);
    });

    it('matches a Python-style read of an SSH key', async () => {
      await expectRuleMatch(
        `python3 -c "open('/home/user/.ssh/id_rsa').read()"`,
        RULE,
      );
    });

    it('matches ~/.aws/credentials', async () => {
      await expectRuleMatch(`cat ~/.aws/credentials`, RULE);
    });

    it('matches ~/.netrc', async () => {
      await expectRuleMatch(`cat ~/.netrc`, RULE);
    });

    it('matches gcloud application default credentials', async () => {
      await expectRuleMatch(
        `cat ~/.config/gcloud/application_default_credentials.json`,
        RULE,
      );
    });

    it('matches ~/.gitconfig', async () => {
      await expectRuleMatch(`cat ~/.gitconfig`, RULE);
    });

    it('matches ~/.git-credentials', async () => {
      await expectRuleMatch(`cat ~/.git-credentials`, RULE);
    });

    it('matches a private key even when its public key is also present', async () => {
      // count(priv) = 2 (id_rsa standalone + id_rsa inside id_rsa.pub),
      // count(pub) = 1 → fires.
      await expectRuleMatch(
        `
          cat ~/.ssh/id_rsa
          cat ~/.ssh/id_rsa.pub
        `,
        RULE,
      );
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match id_rsa.pub (public key)', async () => {
      await expectRuleDidNotMatch(`cat ~/.ssh/id_rsa.pub`, RULE);
    });

    it('does NOT match id_ed25519.pub (public key)', async () => {
      await expectRuleDidNotMatch(`cat ~/.ssh/id_ed25519.pub`, RULE);
    });

    it('does NOT match ~/.ssh/known_hosts', async () => {
      await expectRuleDidNotMatch(`cat ~/.ssh/known_hosts`, RULE);
    });

    it('does NOT match ~/.ssh/config', async () => {
      await expectRuleDidNotMatch(`cat ~/.ssh/config`, RULE);
    });

    it('does NOT match ~/.ssh/authorized_keys', async () => {
      await expectRuleDidNotMatch(`cat ~/.ssh/authorized_keys`, RULE);
    });

    it('does NOT match ~/.aws/config (not credentials)', async () => {
      await expectRuleDidNotMatch(`cat ~/.aws/config`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `cat ~/.ssh/id_rsa`,
        RULE,
        { severity: 'critical', category: 'exfiltration', action: 'block' },
      );
    });
  });
});
