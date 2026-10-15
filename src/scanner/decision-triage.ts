import type { ScanMatch, TriageMatch, TriageVerdict, DecisionProvider, DecisionRequest, DecisionQuestion } from './types.js';
import { rangesIntoThisContent } from './triage.js';

/**
 * The reason every match gets when there is too much flagged content to
 * triage in one request: more than 256 distinct hits, or content too big for
 * the decision route's 1 MiB request. Consumers match on it to ask for a
 * narrower request rather than treating it as a detected threat.
 */
export const TRIAGE_TOO_MUCH_TO_REVIEW =
  'Too much flagged content to triage in one request — narrow it (a smaller range or a more specific search) and try again.';

// A hit is a threat when the mean of the two answers below reaches this.
const THREAT_THRESHOLD = 0.5;
// Two questions per hit, and the gateway takes at most 32 per request.
const HITS_PER_REQUEST = 16;
// Keeps a burst of requests under the gateway's 10 per second per team.
const MAX_REQUESTS_IN_FLIGHT = 4;
const MAX_DISTINCT_HITS = 256;
// The gateway's request body limit, less room for the model id the consumer adds.
const MAX_REQUEST_BYTES = (1 << 20) - 1_024;
const SURROUNDING_RADIUS_CHARS = 100;

// The two questions asked about every hit, exactly as measured in the Luna
// eval. The model leans toward answering "no", so asking both ways and
// averaging cancels the lean: 88% of planted attacks caught, 0 false positives.
const THREAT_QUESTION = {
  question: 'Question: Is this occurrence a real security threat to the AI agent or its user?',
  criteria: {
    true: 'This occurrence is a real security threat to the AI agent or its user.',
    false: 'This occurrence is not a real security threat to the AI agent or its user.',
  },
};
const BENIGN_QUESTION = {
  question: 'Question: Is this occurrence benign for the AI agent and its user?',
  criteria: {
    true: 'This occurrence is benign for the AI agent and its user.',
    false: 'This occurrence is not benign for the AI agent and its user.',
  },
};

/** One distinct piece of text a match fired on, at its first occurrence. */
interface Hit {
  matchIndex: number;
  rule: string;
  description: string;
  text: string;
  start: number;
  end: number;
  line: number;
}

type HitOutcome = { verdict: TriageVerdict; reason: string };

/**
 * Triage scan matches with the AI gateway's decision model.
 *
 * The whole content is the state. Every distinct hit gets two questions, and
 * a match is a threat when any of its hits scores 0.5 or more. Hits go 16 per
 * request, with up to 4 requests in flight.
 *
 * Fail-safe: a match is true_positive when its text can't be found, when an
 * answer is refused or missing, when the call fails, or when there is too
 * much to triage (reason TRIAGE_TOO_MUCH_TO_REVIEW).
 */
export async function triageMatchesByDecision(
  content: string,
  matches: ScanMatch[],
  decide: DecisionProvider,
): Promise<TriageMatch[]> {
  if (matches.length === 0) {
    return [];
  }
  const annotate = (outcomeFor: (matchIndex: number) => HitOutcome): TriageMatch[] =>
    matches.map((match, matchIndex) => ({ ...match, triage: outcomeFor(matchIndex) }));
  const tooMuch: HitOutcome = { verdict: 'true_positive', reason: TRIAGE_TOO_MUCH_TO_REVIEW };

  const { hits, unlocated } = hitsIn(content, matches);
  const requestHits: Hit[][] = [];
  for (let i = 0; i < hits.length; i += HITS_PER_REQUEST) {
    requestHits.push(hits.slice(i, i + HITS_PER_REQUEST));
  }
  const requests = requestHits.map((batch): DecisionRequest => ({ state: content, questions: questionsFor(content, batch) }));
  const byteLength = (request: DecisionRequest) => new TextEncoder().encode(JSON.stringify(request)).length;
  if (hits.length > MAX_DISTINCT_HITS || requests.some((request) => byteLength(request) > MAX_REQUEST_BYTES)) {
    return annotate(() => tooMuch);
  }

  const outcomesPerRequest = await runWithLimit(
    requests.map((request, i) => () => judge(request, requestHits[i], decide)),
    MAX_REQUESTS_IN_FLIGHT,
  );
  const outcomes = new Map<Hit, HitOutcome>();
  requestHits.forEach((batch, i) => batch.forEach((hit, j) => outcomes.set(hit, outcomesPerRequest[i][j])));

  return annotate((matchIndex) => {
    if (unlocated.has(matchIndex)) {
      return { verdict: 'true_positive', reason: 'Matched text could not be located in the content — defaulting to true positive.' };
    }
    const matchOutcomes = hits.filter((hit) => hit.matchIndex === matchIndex).map((hit) => outcomes.get(hit)!);
    return matchOutcomes.find((outcome) => outcome.verdict === 'true_positive') ?? matchOutcomes[0];
  });
}

/** Ask one request's questions and turn each hit's two answers into an outcome. */
async function judge(request: DecisionRequest, batch: Hit[], decide: DecisionProvider): Promise<HitOutcome[]> {
  let answers: Awaited<ReturnType<DecisionProvider>>['answers'];
  try {
    ({ answers } = await decide(request));
  } catch (err) {
    if (process.env.WARLOCK_DEBUG) {
      console.error('[warlock triage] decision call failed:', err);
    }
    return batch.map(() => ({ verdict: 'true_positive', reason: 'Decision call failed — defaulting to true positive.' }));
  }

  return batch.map((hit, i) => {
    const threat = answers?.[`${i}.threat`];
    const benign = answers?.[`${i}.benign`];
    if (threat?.type !== 'noul' || typeof threat.noul !== 'number' || benign?.type !== 'noul' || typeof benign.noul !== 'number') {
      return { verdict: 'true_positive', reason: 'The decision model refused or skipped this hit — defaulting to true positive.' };
    }
    const score = (threat.noul + (1 - benign.noul)) / 2;
    return {
      verdict: score >= THREAT_THRESHOLD ? 'true_positive' : 'false_positive',
      reason: `The decision model scored ${JSON.stringify(hit.text)} ${score.toFixed(2)} as a threat (threshold ${THREAT_THRESHOLD}).`,
    };
  });
}

/** Two questions per hit, keyed `<n>.threat` and `<n>.benign`. */
function questionsFor(content: string, batch: Hit[]): Record<string, DecisionQuestion> {
  const questions: Record<string, DecisionQuestion> = {};
  batch.forEach((hit, i) => {
    const context = contextFor(content, hit);
    for (const [key, { question, criteria }] of [['threat', THREAT_QUESTION], ['benign', BENIGN_QUESTION]] as const) {
      questions[`${i}.${key}`] = { type: 'noul', instructions: `${context}\n\n${question}`, criteria };
    }
  });
  return questions;
}

/** The block every question about `hit` starts with, word for word as measured. */
function contextFor(content: string, hit: Hit): string {
  const before = content.slice(Math.max(0, hit.start - SURROUNDING_RADIUS_CHARS), hit.start);
  const after = content.slice(hit.end, hit.end + SURROUNDING_RADIUS_CHARS);
  return [
    "A pattern-matching security rule matched one span of the content in the state. The content will be loaded into an AI coding agent's context.",
    `Rule: ${hit.rule}`,
    `Rule description: ${hit.description || 'none'}`,
    `Matched text: ${JSON.stringify(hit.text)}`,
    `Position: characters ${hit.start}-${hit.end} of the content (line ${hit.line})`,
    `Surrounding text (${SURROUNDING_RADIUS_CHARS} characters on each side): ${JSON.stringify(before + hit.text + after)}`,
    'Judge this one occurrence of the matched text, in the context of the whole content.',
  ].join('\n');
}

/**
 * Every distinct (match, hit text) at its first occurrence, in content order.
 * A match with no text to find in this content is reported in `unlocated`.
 */
function hitsIn(content: string, matches: ScanMatch[]): { hits: Hit[]; unlocated: Set<number> } {
  const hits: Hit[] = [];
  const unlocated = new Set<number>();
  const lineAt = lineNumbersIn(content);

  matches.forEach((match, matchIndex) => {
    const ranges = rangesIntoThisContent(content, match) ?? occurrencesOf(content, match.matchedStrings ?? []);
    if (ranges.length === 0) {
      unlocated.add(matchIndex);
      return;
    }
    const seen = new Set<string>();
    for (const [start, end] of [...ranges].sort((a, b) => a[0] - b[0])) {
      const text = content.slice(start, end);
      if (seen.has(text)) continue;
      seen.add(text);
      hits.push({ matchIndex, rule: match.rule, description: match.metadata.description ?? '', text, start, end, line: lineAt(start) });
    }
  });

  hits.sort((a, b) => a.start - b.start || a.matchIndex - b.matchIndex);
  return { hits, unlocated };
}

/** Where each matched string occurs, for a match without usable ranges. Empty when any string is missing. */
function occurrencesOf(content: string, matchedStrings: string[]): Array<[number, number]> {
  const occurrences: Array<[number, number]> = [];
  for (const matchedString of matchedStrings) {
    // engine.ts cuts each string at a byte limit, which can split a multibyte char into U+FFFD.
    const searchText = matchedString.replace(/^�+|�+$/g, '');
    if (searchText.length === 0 || !content.includes(searchText)) {
      return [];
    }
    for (let start = content.indexOf(searchText); start !== -1; start = content.indexOf(searchText, start + searchText.length)) {
      occurrences.push([start, start + searchText.length]);
    }
  }
  return occurrences;
}

/** A lookup from a UTF-16 index to its 1-based line number. */
function lineNumbersIn(content: string): (index: number) => number {
  const newlineIndexes: number[] = [];
  for (let i = content.indexOf('\n'); i !== -1; i = content.indexOf('\n', i + 1)) {
    newlineIndexes.push(i);
  }
  return (index) => {
    let low = 0;
    let high = newlineIndexes.length;
    while (low < high) {
      const middle = (low + high) >> 1;
      if (newlineIndexes[middle] < index) low = middle + 1;
      else high = middle;
    }
    return low + 1;
  };
}

/** Run `tasks` with at most `limit` in flight, keeping their order in the results. */
async function runWithLimit<T>(tasks: Array<() => Promise<T>>, limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let next = 0;
  const worker = async () => {
    while (next < tasks.length) {
      const i = next++;
      results[i] = await tasks[i]();
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, tasks.length) }, worker));
  return results;
}
