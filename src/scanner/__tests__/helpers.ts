/**
 * Shared test helpers and fixtures for Warlock rule tests.
 *
 * Each rule has its own test file under `__tests__/rules/` — helpers live
 * here so every rule test imports the same metadata assertion and fake-key
 * fixtures :)
 */

import { expect } from 'vitest';
import { scan } from '../engine.js';

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
  expected: { severity: string; category: string; action: string },
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
