export { scan } from './scanner/engine.js';
export { triageMatches, TRIAGE_TOO_MUCH_TO_REVIEW } from './scanner/triage.js';
export { CATEGORIES } from './scanner/types.js';
export type {
  Category,
  Severity,
  RuleMetadata,
  ScanMatch,
  ScanResult,
  TriageMatch,
  TriageVerdict,
  TriageClassifier,
  TriageClassifierContext,
  TriageClassifierResult,
  TriageQuestion,
} from './scanner/types.js';
