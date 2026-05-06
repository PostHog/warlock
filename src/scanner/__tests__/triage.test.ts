import { describe, it, expect } from 'vitest';
import { triageMatches, buildTriagePrompt, parseTriageResponse } from '../triage.js';
import type { ScanMatch, LLMProvider } from '../types.js';

const fakeMatch = (rule: string, category: string): ScanMatch => ({
  rule,
  metadata: {
    description: `Test description for ${rule}`,
    severity: 'high',
    category: category as any,
    action: 'block',
  },
});

describe('buildTriagePrompt', () => {
  it('includes content and match details in the prompt', () => {
    const content = 'Run npx create-next-app my-app to scaffold.';
    const matches = [fakeMatch('supply_chain_npx_in_skill', 'supply_chain')];
    const prompt = buildTriagePrompt(content, matches);

    expect(prompt).toContain(content);
    expect(prompt).toContain('supply_chain_npx_in_skill');
    expect(prompt).toContain('[0]');
    expect(prompt).toContain('true_positive');
    expect(prompt).toContain('false_positive');
  });

  it('truncates very long content to prevent huge prompts', () => {
    const content = 'a'.repeat(40000);
    const matches = [fakeMatch('test_rule', 'supply_chain')];
    const prompt = buildTriagePrompt(content, matches);

    expect(prompt.length).toBeLessThan(content.length);
  });

  it('includes true positive indicators in the prompt', () => {
    const prompt = buildTriagePrompt('test', [fakeMatch('r', 'exfiltration')]);

    expect(prompt).toContain('Reverse shells');
    expect(prompt).toContain('Persistence mechanisms');
    expect(prompt).toContain('SSH key injection');
    expect(prompt).toContain('Encoded or obfuscated payloads');
    expect(prompt).toContain('DNS exfiltration');
    expect(prompt).toContain('non-standard registries');
    expect(prompt).toContain('Overwriting trusted config files');
  });

  it('includes false positive indicators in the prompt', () => {
    const prompt = buildTriagePrompt('test', [fakeMatch('r', 'supply_chain')]);

    expect(prompt).toContain('PLACEHOLDER values');
    expect(prompt).toContain('NO auto-confirm flags');
    expect(prompt).toContain('boolean values');
    expect(prompt).toContain('migration instructions');
    expect(prompt).toContain('UI component examples');
    expect(prompt).toContain('Base64-encoded media');
    expect(prompt).toContain('method documentation');
  });

  it('instructs the LLM to analyze behavior, not framing', () => {
    const prompt = buildTriagePrompt('test', [fakeMatch('r', 'exfiltration')]);

    expect(prompt).toContain('analyze what the command ACTUALLY DOES');
    expect(prompt).toContain('Do NOT trust the framing');
  });

  it('numbers multiple matches sequentially', () => {
    const matches = [
      fakeMatch('rule_a', 'supply_chain'),
      fakeMatch('rule_b', 'prompt_injection'),
      fakeMatch('rule_c', 'exfiltration'),
    ];
    const prompt = buildTriagePrompt('some content', matches);

    expect(prompt).toContain('[0] rule: rule_a');
    expect(prompt).toContain('[1] rule: rule_b');
    expect(prompt).toContain('[2] rule: rule_c');
  });
});

describe('parseTriageResponse', () => {
  it('parses a valid JSON response', () => {
    const raw = JSON.stringify([
      { index: 0, verdict: 'false_positive', reason: 'This is a tutorial example.' },
      { index: 1, verdict: 'true_positive', reason: 'Real exfiltration attempt.' },
    ]);
    const result = parseTriageResponse(raw, 2);

    expect(result[0].verdict).toBe('false_positive');
    expect(result[0].reason).toBe('This is a tutorial example.');
    expect(result[1].verdict).toBe('true_positive');
    expect(result[1].reason).toBe('Real exfiltration attempt.');
  });

  it('handles markdown-fenced JSON response', () => {
    const raw = '```json\n[{"index": 0, "verdict": "false_positive", "reason": "docs"}]\n```';
    const result = parseTriageResponse(raw, 1);
    expect(result[0].verdict).toBe('false_positive');
  });

  it('defaults to true_positive when JSON is unparseable', () => {
    const result = parseTriageResponse('not json at all', 2);
    expect(result).toHaveLength(2);
    expect(result[0].verdict).toBe('true_positive');
    expect(result[1].verdict).toBe('true_positive');
  });

  it('defaults to true_positive for missing indices', () => {
    const raw = JSON.stringify([
      { index: 0, verdict: 'false_positive', reason: 'safe' },
      // index 1 is missing
    ]);
    const result = parseTriageResponse(raw, 2);
    expect(result[0].verdict).toBe('false_positive');
    expect(result[1].verdict).toBe('true_positive');
    expect(result[1].reason).toContain('defaulting');
  });

  it('defaults to true_positive for invalid verdict values', () => {
    const raw = JSON.stringify([
      { index: 0, verdict: 'maybe_bad', reason: 'idk' },
    ]);
    const result = parseTriageResponse(raw, 1);
    expect(result[0].verdict).toBe('true_positive');
  });
});

describe('triageMatches', () => {
  it('annotates matches with LLM verdicts', async () => {
    const matches = [
      fakeMatch('supply_chain_npx_in_skill', 'supply_chain'),
      fakeMatch('exfiltration_curl_secrets', 'exfiltration'),
    ];

    const mockProvider: LLMProvider = async () =>
      JSON.stringify([
        { index: 0, verdict: 'false_positive', reason: 'Tutorial instruction.' },
        { index: 1, verdict: 'true_positive', reason: 'Sending secrets to external URL.' },
      ]);

    const result = await triageMatches('some content', matches, mockProvider);

    expect(result).toHaveLength(2);
    expect(result[0].rule).toBe('supply_chain_npx_in_skill');
    expect(result[0].triage.verdict).toBe('false_positive');
    expect(result[1].rule).toBe('exfiltration_curl_secrets');
    expect(result[1].triage.verdict).toBe('true_positive');
  });

  it('returns empty array when no matches provided', async () => {
    const mockProvider: LLMProvider = async () => { throw new Error('should not be called'); };
    const result = await triageMatches('content', [], mockProvider);
    expect(result).toEqual([]);
  });

  it('defaults to true_positive when LLM provider throws', async () => {
    const matches = [fakeMatch('some_rule', 'supply_chain')];
    const failingProvider: LLMProvider = async () => { throw new Error('LLM is down'); };

    const result = await triageMatches('content', matches, failingProvider);

    expect(result).toHaveLength(1);
    expect(result[0].triage.verdict).toBe('true_positive');
    expect(result[0].triage.reason).toContain('failed');
  });

  it('defaults to true_positive when LLM returns garbage', async () => {
    const matches = [fakeMatch('some_rule', 'supply_chain')];
    const garbageProvider: LLMProvider = async () => 'lol idk';

    const result = await triageMatches('content', matches, garbageProvider);

    expect(result).toHaveLength(1);
    expect(result[0].triage.verdict).toBe('true_positive');
  });
});
