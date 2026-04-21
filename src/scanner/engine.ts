import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ScanResult, ScanMatch, RuleMetadata } from './types.js';

// Cached compiled-rules promise. Loaded lazily on first scan call.
let rulesPromise: Promise<any> | null = null;

async function loadRules(): Promise<any> {
  // Dynamic import bridges the gap between warlock (CommonJS)
  // and yara-x (ES Module — they don't otherwise interoperate).
  const yaraX = await import('@virustotal/yara-x');

  // yara-x's default init uses fetch() which doesn't work in Node.
  // Load the WASM bytes manually and use initSync instead.
  const yaraXPkg = require.resolve('@virustotal/yara-x/package.json');
  const wasmPath = path.join(path.dirname(yaraXPkg), 'pkg', 'yara_x_js_bg.wasm');
  const wasmBytes = fs.readFileSync(wasmPath);
  yaraX.initSync({ module: wasmBytes });

  const compiler = new yaraX.Compiler();
  const rulesDir = path.join(__dirname, 'rules');
  const ruleFiles = fs.readdirSync(rulesDir).filter((f) => f.endsWith('.yar'));

  for (const file of ruleFiles) {
    const source = fs.readFileSync(path.join(rulesDir, file), 'utf8');
    compiler.addSource(source);
  }

  return compiler.build();
}

// yara-x returns rule metadata as an array of {identifier, value} pairs.
// Convert that into a flat object to match our RuleMetadata type.
function normalizeMetadata(
  raw: Array<{ identifier: string; value: string | number | boolean }>,
): RuleMetadata {
  const result: RuleMetadata = {};
  for (const { identifier, value } of raw) {
    result[identifier] = value;
  }
  return result;
}

/**
 * Scan content against all loaded YARA rules.
 *
 * Rules are compiled on the first call and cached for subsequent calls.
 * Consumers that only care about a subset of rules can filter the result.
 */
export async function scan(content: string): Promise<ScanResult> {
  if (!rulesPromise) {
    rulesPromise = loadRules();
  }
  const rules = await rulesPromise;

  const payload = new TextEncoder().encode(content);
  const result = rules.scan(payload);

  if (!result.matches || result.matches.length === 0) {
    return { matched: false };
  }

  const matches: ScanMatch[] = result.matches.map((m: any) => ({
    rule: m.identifier,
    metadata: normalizeMetadata(m.metadata || []),
  }));

  return { matched: true, matches };
}
