import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';
import type { ScanResult, ScanMatch, RuleMetadata } from './types.js';

const require = createRequire(import.meta.url);

// Cached compiled-rules promise. Loaded lazily on first scan call.
let rulesPromise: Promise<any> | null = null;

async function loadRules(): Promise<any> {
  const yaraX = await import('@virustotal/yara-x');

  // yara-x's default init uses fetch() which doesn't work in Node.
  // Load the WASM bytes manually and use initSync instead.
  const yaraXPkg = require.resolve('@virustotal/yara-x/package.json');
  const wasmPath = path.join(path.dirname(yaraXPkg), 'pkg', 'yara_x_js_bg.wasm');
  const wasmBytes = fs.readFileSync(wasmPath);
  yaraX.initSync({ module: wasmBytes });

  const compiler = new yaraX.Compiler();
  const rulesDir = path.join(import.meta.dirname, 'rules');
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

// Cap how much matched text we keep per rule match. Triage only needs to see
// the offending snippet(s) to judge them, so we dedupe occurrences and never
// let a single huge span bloat the result (or the triage prompt downstream).
const MAX_MATCHED_STRINGS = 5;
const MAX_MATCHED_STRING_LENGTH = 200;

const matchedTextDecoder = new TextDecoder();

/**
 * Pull the actual matched text out of a yara-x match.
 *
 * yara-x reports each pattern hit as a byte `offset` + `length` into the scanned
 * payload, so we slice the BYTES (not the decoded JS string) and decode the
 * slice — slicing the string by a byte offset would misalign on multi-byte
 * characters. Results are deduped and capped.
 */
function extractMatchedStrings(
  payload: Uint8Array,
  patterns: Array<{ matches?: Array<{ offset: number; length: number }> }> | undefined,
): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const pattern of patterns || []) {
    for (const occurrence of pattern.matches || []) {
      if (out.length >= MAX_MATCHED_STRINGS) return out;
      const end = occurrence.offset + Math.min(occurrence.length, MAX_MATCHED_STRING_LENGTH);
      const text = matchedTextDecoder.decode(payload.slice(occurrence.offset, end));
      if (!seen.has(text)) {
        seen.add(text);
        out.push(text);
      }
    }
  }
  return out;
}

/**
 * Scan content against all loaded YARA rules.
 *
 * Rules are compiled on the first call and cached for subsequent calls.
 * Consumers that only care about a subset of rules can filter the result.
 */
export async function scan(content: string): Promise<ScanResult> {
  if (!rulesPromise) {
    // Cache the compile work, but if it fails, clear the cache so the next
    // scan() retries instead of replaying a permanently-rejected promise.
    rulesPromise = loadRules().catch((err) => {
      rulesPromise = null;
      throw err;
    });
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
    matchedStrings: extractMatchedStrings(payload, m.patterns),
  }));

  return { matched: true, matches };
}
