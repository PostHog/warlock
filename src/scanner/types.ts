/**
 * Type definitions for @posthog/warlock scan results.
 */

/**
 * YARA rule categories warlock recognizes. All categories are security-focused.
 *
 * API contract: this list is append-only. Values may be added over time, but
 * never removed or renamed — consumers rely on these strings for routing logic.
 * If a category becomes obsolete, stop writing rules for it; leave the value.
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
 * Append-only — add new levels only, never remove or rename.
 */
export type Severity = 'critical' | 'high' | 'medium' | 'low';

/**
 * Metadata extracted from a YARA rule's `meta:` block.
 * Known keys are typed; rule authors can include additional free-form metadata.
 */
export interface RuleMetadata {
  description?: string;
  severity?: Severity;
  category?: Category;
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
 * Discriminated union — TypeScript narrows based on the `matched` field.
 */
export type ScanResult =
  | { matched: false }
  | { matched: true; matches: ScanMatch[] };
