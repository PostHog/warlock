import { describe, it } from 'vitest';
import { expectRuleMatch, expectRuleDidNotMatch, expectRuleMetadata } from '../helpers.js';

const RULE = 'destructive_recursive_delete_high_risk';

describe(RULE, () => {
  describe('positive cases – should match', () => {
    it('matches rm -rf /', async () => {
      await expectRuleMatch(`rm -rf /`, RULE);
    });

    it('matches rm -rf /*', async () => {
      await expectRuleMatch(`rm -rf /*`, RULE);
    });

    it('matches rm -rf ~', async () => {
      await expectRuleMatch(`rm -rf ~`, RULE);
    });

    it('matches rm -rf ~/', async () => {
      await expectRuleMatch(`rm -rf ~/`, RULE);
    });

    it('matches rm -rf .', async () => {
      await expectRuleMatch(`rm -rf .`, RULE);
    });

    it('matches rm -rf ..', async () => {
      await expectRuleMatch(`cd somewhere && rm -rf ..`, RULE);
    });

    it('matches rm -rf /etc', async () => {
      await expectRuleMatch(`rm -rf /etc/nginx`, RULE);
    });

    it('matches rm -Rf /Users (macOS capital R)', async () => {
      await expectRuleMatch(`rm -Rf /Users/someone/important`, RULE);
    });

    it('matches rm --recursive --force /', async () => {
      await expectRuleMatch(`rm --recursive --force /`, RULE);
    });

    it('matches rm -r -f /', async () => {
      await expectRuleMatch(`rm -r -f /`, RULE);
    });

    it('matches rm -rf $VAR (unquoted variable)', async () => {
      await expectRuleMatch(`rm -rf $BUILD_DIR`, RULE);
    });

    it('matches rm -rf ${VAR} (unquoted brace variable)', async () => {
      await expectRuleMatch(`rm -rf \${TARGET}`, RULE);
    });

    it('matches sudo rm -rf node_modules (sudo escalates)', async () => {
      await expectRuleMatch(`sudo rm -rf node_modules`, RULE);
    });

    it('matches find / -delete', async () => {
      await expectRuleMatch(`find / -name "*.log" -delete`, RULE);
    });

    it('matches find ~ -exec rm -rf {}', async () => {
      await expectRuleMatch(`find ~ -type f -exec rm -rf {} +`, RULE);
    });

    it('matches sudo find / -delete', async () => {
      await expectRuleMatch(`sudo find /var/log -delete`, RULE);
    });
  });

  describe('negative cases – should NOT match', () => {
    it('does NOT match rm -rf node_modules', async () => {
      await expectRuleDidNotMatch(`rm -rf node_modules`, RULE);
    });

    it('does NOT match rm -rf build/', async () => {
      await expectRuleDidNotMatch(`rm -rf build/`, RULE);
    });

    it('does NOT match rm -rf ./dist', async () => {
      await expectRuleDidNotMatch(`rm -rf ./dist`, RULE);
    });

    it('does NOT match non-recursive rm', async () => {
      await expectRuleDidNotMatch(`rm /tmp/file.txt`, RULE);
    });

    it('does NOT match find . -name with no delete', async () => {
      await expectRuleDidNotMatch(`find . -name "*.log"`, RULE);
    });

    it('does NOT match unrelated prose', async () => {
      await expectRuleDidNotMatch(`We recently cleaned up old log files on the server.`, RULE);
    });
  });

  describe('metadata', () => {
    it('exposes all required metadata fields on a match', async () => {
      await expectRuleMetadata(
        `rm -rf /`,
        RULE,
        { severity: 'critical', category: 'destructive_operations', action: 'block' },
      );
    });
  });
});
