/**
 * Type definitions for @posthog/warlock scan results.
 */

/**
 * YARA rule categories the Warlock recognizes. All categories are security-focused.
 *
 * API contract: this list is append-only. Values may be added over time, but
 * never removed or renamed – consumers rely on these strings for routing logic.
 * If a category becomes obsolete, stop writing rules for it; leave the value.
 *
 * See README.md#api-stability for the full rule and contingency policy.
 */
export const CATEGORIES = [
  'prompt_injection',
  'exfiltration',
  'destructive_operations',
  'supply_chain',
  'posthog_pii',
  'posthog_hardcoded_key',
] as const;

export type Category = (typeof CATEGORIES)[number];

/**
 * Severity levels for rule metadata.
 * Append-only – add new levels only, never remove or rename.
 * See README.md#api-stability for the full rule and contingency policy.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Actions the Warlock recommends consumers take on a rule match. This is the
 * rule-author's recommendation, consumers decide how and when to invoke.
 *
 * API contract: this list is append-only. Values may be added over time, but
 * never removed or renamed – consumers rely on these strings for dispatch logic.
 *
 * See README.md#api-stability for the full rule and contingency policy.
 */
export const ACTIONS = ['warn', 'block', 'remediate'] as const;

export type Action = (typeof ACTIONS)[number];

/**
 * Metadata extracted from a YARA rule's `meta:` block.
 * Known keys are typed; rule authors can include additional free-form metadata.
 */
export interface RuleMetadata {
  description?: string;
  severity?: Severity;
  category?: Category;
  action?: Action;
  [key: string]: string | number | boolean | undefined;
}

/**
 * A single rule match returned by the scanner.
 */
export interface ScanMatch {
  /** Name of the YARA rule that matched (from `rule <name> { ... }`) */
  rule: string;
  /** Metadata from the rule's `meta:` block */
  metadata: RuleMetadata;
}

/**
 * Result of scanning content against loaded rules.
 * Discriminated union – TypeScript narrows based on the `matched` field.
 */
export type ScanResult =
  | { matched: false }
  | { matched: true; matches: ScanMatch[] };
