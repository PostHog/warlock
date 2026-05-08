export { scan } from './scanner/engine.js';
export { triageMatches } from './scanner/triage.js';
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
} from './scanner/types.js';
