/**
 * Shared test helpers and fixtures for Warlock rule tests.
 *
 * Each rule has its own test file under `__tests__/rules/` — helpers live
 * here so every rule test imports the same metadata assertion and fake-key
 * fixtures :)
 */

import { expect } from 'vitest';
import { scan } from '../engine.js';
import type { Action, Category, Severity } from '../types.js';

/**
 * Asserts that scanning `content` produces a match from `ruleName`.
 *
 * Stronger than `expect(result.matched).toBe(true)` – catches cases where
 * a companion rule matches but the rule under test is broken or renamed.
 * Every positive rule test should use this so companion-rule matches can't
 * silently mask a missing or misnamed rule.
 */
export async function expectRuleMatch(content: string, ruleName: string): Promise<void> {
  const result = await scan(content);
  expect(result.matched).toBe(true);
  if (!result.matched) return;
  const ruleMatched = result.matches.some((m) => m.rule === ruleName);
  expect(ruleMatched).toBe(true);
}

/**
 * Asserts that scanning `content` produces a match from every rule in `ruleNames`.
 *
 * Use this for companion-rule pairs where the design intent is that both
 * rules fire on the same input (e.g. a broad-severity rule and a
 * high-severity rule that both match on clearly dangerous content). A
 * per-rule test can't catch the case where one companion silently stops
 * matching – this helper locks in the joint-firing contract.
 */
export async function expectRulesMatch(content: string, ruleNames: string[]): Promise<void> {
  const result = await scan(content);
  expect(result.matched).toBe(true);
  if (!result.matched) return;
  const firedRules = new Set(result.matches.map((m) => m.rule));
  for (const ruleName of ruleNames) {
    expect(firedRules.has(ruleName)).toBe(true);
  }
}

/**
 * Asserts that scanning `content` does NOT produce a match from `ruleName`.
 *
 * Other rules may still match – this only asserts the specific rule under
 * test stayed silent. Use for negative tests, especially when the rule has
 * a companion that legitimately fires on the same input (e.g. the broad
 * `destructive_recursive_delete` matches content the high-risk rule should
 * stay silent on).
 */
export async function expectRuleDidNotMatch(content: string, ruleName: string): Promise<void> {
  const result = await scan(content);
  if (!result.matched) return;
  const ruleMatched = result.matches.some((m) => m.rule === ruleName);
  expect(ruleMatched).toBe(false);
}

/**
 * Asserts a matched rule exposes every required metadata field
 * (`description`, `remediation`, `severity`, `category`, `action`).
 *
 * Each rule's test file calls this once via a "metadata" sub-block so a
 * future contributor can't ship a rule missing required fields.
 */
export async function expectRuleMetadata(
  content: string,
  ruleName: string,
  expected: { severity: Severity; category: Category; action: Action },
) {
  const result = await scan(content);
  expect(result.matched).toBe(true);
  if (!result.matched) return;

  const match = result.matches.find((m) => m.rule === ruleName);
  expect(match).toBeDefined();
  expect(typeof match?.metadata.description).toBe('string');
  expect(match?.metadata.description).toBeTruthy();
  expect(typeof match?.metadata.remediation).toBe('string');
  expect(match?.metadata.remediation).toBeTruthy();
  expect(match?.metadata.severity).toBe(expected.severity);
  expect(match?.metadata.category).toBe(expected.category);
  expect(match?.metadata.action).toBe(expected.action);
}

// ─── Fake-key fixtures ─────────────────────────────────────────────────────
//
// Structurally valid (trigger the rule) but visually unambiguous as fake
// (repeating-digit bodies). Real enough to match our 30+ alphanumeric floor,
// clearly not a real token to human readers or secret scanners.
export const FAKE_PERSONAL_KEY = 'phx_1111111111222222222233333333334444';
export const FAKE_PROJECT_TOKEN = 'phc_1111111111222222222233333333334444';
export const FAKE_AWS_ACCESS_KEY = 'AKIA1111222233334444';
export const FAKE_AWS_SESSION_TOKEN = 'ASIA1111222233334444';
// Stripe fakes split prefix + body in source so GitHub's secret-scanning
// push protection doesn't flag these fixtures as real keys. JS reassembles
// at runtime, so the YARA rule still fires on the full string.
const STRIPE_FAKE_BODY = '1111222233334444aaaabbbb';
export const FAKE_STRIPE_LIVE_SECRET = 'sk_live_' + STRIPE_FAKE_BODY;
export const FAKE_STRIPE_LIVE_RESTRICTED = 'rk_live_' + STRIPE_FAKE_BODY;
export const FAKE_STRIPE_TEST_KEY = 'sk_test_' + STRIPE_FAKE_BODY;
export const FAKE_STRIPE_PUBLISHABLE_KEY = 'pk_live_' + STRIPE_FAKE_BODY;
export const FAKE_GITHUB_PAT_CLASSIC = 'ghp_111122223333444455556666777788889999';
export const FAKE_GITHUB_PAT_SERVER = 'ghs_111122223333444455556666777788889999';
