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
 * Every pattern hit as a `[start, end)` range of UTF-16 indices into the
 * scanned string, listed in the same order extractMatchedStrings reads hits.
 *
 * yara-x reports each hit as a byte offset and length into the UTF-8 payload.
 * JS strings are indexed in UTF-16 code units, and the two differ once the
 * content has non-ASCII text: 'é' is 2 bytes but 1 unit, '😀' is 4 bytes but
 * 2 units. So each byte offset is converted before it is returned.
 */
function extractMatchedRanges(
  payload: Uint8Array,
  patterns: Array<{ matches?: Array<{ offset: number; length: number }> }> | undefined,
): Array<[number, number]> {
  const byteRanges: Array<{ start: number; end: number }> = [];
  for (const pattern of patterns || []) {
    for (const hit of pattern.matches || []) {
      byteRanges.push({ start: hit.offset, end: hit.offset + hit.length });
    }
  }

  const everyByteOffset = byteRanges.flatMap((range) => [range.start, range.end]);
  const utf16IndexAt = utf16IndexesAtByteOffsets(payload, everyByteOffset);
  // Every offset was passed in above, so every lookup finds one.
  const toUtf16 = (byteOffset: number) => utf16IndexAt.get(byteOffset)!;

  return byteRanges.map((range): [number, number] => [toUtf16(range.start), toUtf16(range.end)]);
}

/**
 * Converts byte offsets in a UTF-8 payload to UTF-16 indices in the string it
 * was encoded from. It sorts the offsets, then walks the payload once from the
 * front, counting UTF-16 units as it passes each character. That costs
 * O(payload bytes + offsets × log offsets).
 *
 * In UTF-8 every character starts with a byte that isn't `10xxxxxx`. A
 * character of 1 to 3 bytes is 1 UTF-16 unit. A 4-byte character starts with
 * `11110xxx` and is a surrogate pair, 2 units.
 */
function utf16IndexesAtByteOffsets(payload: Uint8Array, byteOffsets: number[]): Map<number, number> {
  const ascendingOffsets = [...new Set(byteOffsets)].sort((a, b) => a - b);
  const utf16IndexAt = new Map<number, number>();

  let byte = 0;
  let utf16Index = 0;
  for (const offset of ascendingOffsets) {
    while (byte < offset) {
      const startsACharacter = (payload[byte] & 0b1100_0000) !== 0b1000_0000;
      if (startsACharacter) {
        const startsAFourByteCharacter = payload[byte] >= 0b1111_0000;
        utf16Index += startsAFourByteCharacter ? 2 : 1;
      }
      byte++;
    }
    utf16IndexAt.set(offset, utf16Index);
  }

  return utf16IndexAt;
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
    matchedStrings: extractMatchedStrings(payload, m.patterns),
    matchedRanges: extractMatchedRanges(payload, m.patterns),
  }));

  return { matched: true, matches };
}
