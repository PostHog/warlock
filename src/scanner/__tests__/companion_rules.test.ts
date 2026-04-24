/**
 * Tests for companion-rule pairs: inputs where two related rules are both
 * expected to fire. Per-rule tests can't catch the case where one companion
 * silently stops matching while the other picks up the slack – these tests
 * lock in the joint-firing design intent.
 *
 * Each companion pair is documented in its own rule header. When both rules
 * match, consumers typically surface the higher-severity one to the user.
 */

import { describe, it } from 'vitest';
import { expectRulesMatch } from './helpers.js';

describe('companion-rule pairs', () => {
  describe('destructive_recursive_delete + destructive_recursive_delete_high_risk', () => {
    const PAIR = [
      'destructive_recursive_delete',
      'destructive_recursive_delete_high_risk',
    ];

    it('both fire on rm -rf /', async () => {
      await expectRulesMatch(`rm -rf /`, PAIR);
    });

    it('both fire on rm -rf $UNSET_VAR', async () => {
      await expectRulesMatch(`rm -rf $BUILD_DIR`, PAIR);
    });

    it('both fire on sudo rm -rf node_modules (sudo escalates a safe target)', async () => {
      await expectRulesMatch(`sudo rm -rf node_modules`, PAIR);
    });
  });

  describe('destructive_git_force_push + destructive_git_force_push_protected_branch', () => {
    const PAIR = [
      'destructive_git_force_push',
      'destructive_git_force_push_protected_branch',
    ];

    it('both fire on git push --force origin main', async () => {
      await expectRulesMatch(`git push --force origin main`, PAIR);
    });

    it('both fire on git push -f origin master', async () => {
      await expectRulesMatch(`git push -f origin master`, PAIR);
    });

    it('both fire on git push --delete origin main', async () => {
      await expectRulesMatch(`git push --delete origin main`, PAIR);
    });
  });
});
