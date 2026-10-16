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
  'hardcoded_secret',
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
  /**
   * Text that tripped the rule, lifted from the scanned content so triage can
   * judge the real trigger instead of guessing. Deduped and length-capped.
   * Always present; an empty array means no span was recovered.
   */
  matchedStrings: string[];
  /**
   * Where each pattern hit starts and ends in the scanned string, as UTF-16
   * indices. Unlike `matchedStrings` it is never capped, so triage can show
   * the model every hit that fired the rule.
   */
  matchedRanges?: Array<[number, number]>;
}

/**
 * Result of scanning content against loaded rules.
 * Discriminated union – TypeScript narrows based on the `matched` field.
 */
export type ScanResult =
  | { matched: false }
  | { matched: true; matches: ScanMatch[] };

/**
 * Verdict from LLM triage on a single match.
 */
export type TriageVerdict = 'true_positive' | 'false_positive';

/**
 * A scan match annotated with an LLM triage verdict.
 */
export interface TriageMatch extends ScanMatch {
  triage: {
    verdict: TriageVerdict;
    reason: string;
  };
}

/**
 * A question for the classifier. A `bool` answer is the probability that
 * `criteria.true` holds, and a `choice` answer is a probability per criterion.
 * Same shapes as pi-ai's `ClassifierBoolQuestion` and `ClassifierChoiceQuestion`.
 */
export type TriageQuestion =
  | { type: 'bool'; instructions: string; criteria: { true: string; false: string } }
  | { type: 'choice'; instructions: string; criteria: Record<string, string> };

/** What triage asks the classifier. Same shape as pi-ai's `ClassifierContext`. */
export interface TriageClassifierContext {
  state: { content: string };
  questions: Record<string, TriageQuestion>;
}

/**
 * The classifier's answers, one per question id. Same shape as pi-ai's
 * `ClassifierResult`, which reports a failed call in `stopReason` and
 * `errorMessage` rather than throwing.
 */
export interface TriageClassifierResult {
  answers: Record<string, { type: string; probability?: number; probabilities?: Record<string, number> }>;
  stopReason?: string;
  errorMessage?: string;
}

/**
 * Callback that consumers provide to reach a classifier model, such as
 * `(context) => classify(model, context, { apiKey })` with pi-ai.
 */
export type TriageClassifier = (context: TriageClassifierContext) => Promise<TriageClassifierResult>;
