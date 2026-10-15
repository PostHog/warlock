export { scan } from './scanner/engine.js';
export { triageMatches } from './scanner/triage.js';
export { triageMatchesByDecision, TRIAGE_TOO_MUCH_TO_REVIEW } from './scanner/decision-triage.js';
export { CATEGORIES } from './scanner/types.js';
export type {
  Category,
  Severity,
  RuleMetadata,
  ScanMatch,
  ScanResult,
  TriageMatch,
  TriageVerdict,
  LLMProvider,
  TriageOptions,
  DecisionProvider,
  DecisionRequest,
  DecisionQuestion,
  DecisionResponse,
} from './scanner/types.js';
