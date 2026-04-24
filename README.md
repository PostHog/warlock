# @posthog/warlock

Security scanner for PostHog's agentic flows. It catches poisoned context, prompt injection, secret exfiltration, destructive operations, and other threats in content flowing in and out of AI agents – using [YARA-X](https://virustotal.github.io/yara-x/) rules under the hood.

Engine-only by design. the Warlock scans, you decide when and what.

---

## Charter

the Warlock is the content-scanning engine behind PostHog's agentic tooling. You give it a string, it gives you back a list of rule matches – each tagged with a category, severity, and recommended action. It's deliberately narrow:

- **It's a detection engine**, not a policy engine. the Warlock surfaces findings – consumers decide how to respond.
- **It's agnostic** to when or where it runs. Consumers choose the lifecycle (pre-tool-call, post-agent-response, whatever fits).
- **It ships its own rules.** Rules are bundled in-package – no plugin API for external rule sources.

## Audience

**Who this is for:**

- PostHog's [wizard](https://github.com/PostHog/wizard) – the Warlock replaces the hand-rolled JS-regex scanner at `src/lib/yara-scanner.ts` with real YARA rules.
- The context mill and other PostHog context infrastructure.
- Future PostHog-internal consumers that need to scan untrusted content flowing through AI agents.

**Who this is *not* for:**

- External customers looking to install a security scanner directly – the Warlock protects PostHog's agents and the customers who use them. It's not a general-purpose security product :)
- General application security scanning (static analysis of source code, dependency scanning, secret scanning in git history). There are better tools out there for those jobs.

## Scope and anti-goals

the Warlock is **security only** – it detects content that could harm PostHog's agents or the users of PostHog's products. Anything that looks like a "best-practice" or "code quality" check belongs elsewhere.

I get that it's tempting to slip in extra checks here ("we already have a scanner, why not?") – but keeping the Warlock strictly security is what keeps it useful and trustworthy. Best-practice stuff lives in the wizard or context-mill, where it can be treated as rich context for the agent instead of a security finding.

**Anti-goals – things the Warlock must never become:**

1. **A general-purpose linter or code-quality tool.** Rules need to catch genuine security risks – prompt injection, exfiltration, destructive operations, poisoned context, that kind of thing. Best-practice checks ("did you enable feature X?") belong in the wizard or a dedicated linter, not here.
2. **A policy or enforcement engine that takes action.** the Warlock detects, consumers decide. Each rule's `action` field is a *recommendation* (`block`, `revert`, `warn`), not a command. The consumer implements the actual response.
3. **An orchestration engine that dictates when or where to scan.** the Warlock is engine-only. It knows nothing about phases, tools, agents, or workflows. Consumers wire up the timing themselves.
4. **A wizard-specific tool.** the Warlock has to serve context-mill and future consumers equally. No wizard-only assumptions (tool names, phase names, wizard-specific categories) belong in the Warlock itself.

**Concrete rules that got rejected during the initial port** for violating scope:

- `autocapture_disabled` – best-practice, belongs in wizard
- `session_recording_disabled` – best-practice, belongs in wizard
- `opt_out_capturing` – best-practice, belongs in wizard

Use these as a template when you're evaluating borderline cases: *is this rule catching something an attacker could abuse, or is it about a recommended config?* If it's the latter, it doesn't belong here.

## Design decisions

Every non-obvious choice is documented here so future you (or a future contributor) doesn't have to reverse-engineer the reasoning from the code. Where a decision has a real cost, that cost is called out too – no hiding the trade-offs.

### Engine-only – no phase, tool, or workflow awareness

the Warlock takes a string and returns matches. It doesn't know whether the content came from a tool call, an agent response, a file read, or a user prompt. It doesn't know what action was about to be taken. That context lives in the consumer.

- **Why:** Consumers have the full picture of their own lifecycle. Baking assumptions about phases or tools into the Warlock would make it less reusable across consumers that structure their flows differently.
- **Cost:** Consumers repeat a small amount of wiring to invoke `scan()` at the right moments. We're OK with that – see *Centralize complexity* below for why.

### Rules bundled in-package, lazily compiled, cached as a singleton

YARA rules live in `src/scanner/rules/*.yar` and get compiled on the first call to `scan()`. The compiled rule set is cached for the lifetime of the process.

- **Why bundled:** The rule set *is* the product. Consumers shouldn't have to assemble their own rule bundles or wire up loaders – that's our job.
- **Why lazy:** yara-x's WASM init is async. Doing it at module load would force every `import` of the Warlock to be async too. Paying the cost on first `scan()` instead keeps `import` synchronous (which is so much nicer to work with).
- **Why singleton:** Compiling rules is expensive, scanning is cheap. Recompiling on every call would be wasteful.

### Consumer-side filtering

the Warlock returns *all* matches from *all* rules. If a consumer only cares about `prompt_injection` findings, they filter the result on their end.

- **Why:** Engine-side filtering adds an API surface (options, config) that every consumer has to learn. A filter in consumer code is one line and totally obvious – why complicate it?
- **When to revisit:** If engine-side filtering ever becomes necessary for performance, we can add it as an optional parameter to `scan()` later. It would be a backward-compatible change.

### `action` field as a recommendation, not a command

Every rule's metadata includes an `action` (`block`, `revert`, or `warn`). This is the rule author's *opinion* about how serious the finding is and what the consumer should do – not a directive.

- **Why:** Rule authors know the detection context best, consumers know the execution context best. The rule says "this looks like attempted exfiltration, you probably want to block it." The consumer decides whether to actually block, log, notify, escalate, or do something else entirely.

### Centralize complexity in the Warlock and keep the consumer API clean

When an implementation choice forces a trade-off between "ugly code in the Warlock" and "ugly code at every consumer call-site" – the Warlock eats the ugly code. Every time.

- **Why:** the Warlock has one maintainer. Consumers have many call-sites. Paying the complexity tax once is way cheaper than paying it over and over.
- **Examples:** The CommonJS / ESM bridge (below) and metadata normalization (below).

### CommonJS package – ESM-only yara-x bridged via dynamic `import()`

the Warlock ships as a CommonJS package.

- **Why:** CJS maximizes compatibility with consumers that haven't migrated to ESM. CJS can be imported from both CJS and ESM contexts – the reverse is awkward. Keeping the Warlock CJS concentrates the bridging code in a single file (`src/scanner/engine.ts`), so consumers don't have to deal with it themselves. We can add a dual CJS/ESM build later if it's needed.
- **Cost:** yara-x is ESM-only, so the Warlock uses a dynamic `await import('@virustotal/yara-x')` inside `loadRules()`. This is why `scan()` is async – the dynamic import returns a Promise.
- **When to revisit:** If future consumers are ESM-native, or Node itself deprecates CJS, this trade-off might flip.

### Why `yara-x` over classic YARA

yara-x is the actively-maintained Rust rewrite of YARA by VirusTotal – the same team that created classic YARA in the first place. Classic YARA is [now in maintenance mode](https://github.com/VirusTotal/yara) and all the new development happens on [yara-x](https://github.com/VirusTotal/yara-x). VirusTotal's [own announcement](https://blog.virustotal.com/2024/05/yara-is-dead-long-live-yara-x.html) positions yara-x as the replacement, so we're going where the maintainers are going.

- **Why this matters for the Warlock:** yara-x ships first-class Node/WASM bindings out of the box. Classic YARA is a C library – using it from Node would mean native bindings, and that's a whole headache. WASM sidesteps all of it: one file, same on every operating system.
- **Performance:** yara-x is a Rust rewrite with meaningful performance gains over classic YARA, especially on regex-heavy and loop-heavy rules – aka the kind of rules the Warlock writes :)

### WASM init workaround – manual `initSync` with filesystem-loaded bytes

yara-x is compiled with `wasm-pack --target web`. Its default `await init()` path tries to load the WASM binary via `fetch()`, which doesn't exist in Node :/

- **The workaround:** In `src/scanner/engine.ts`, we load the WASM bytes from disk (`fs.readFileSync`) and pass them to `yaraX.initSync({ module: wasmBytes })`. The path is resolved via `require.resolve('@virustotal/yara-x/package.json')` so it stays robust across different install layouts.
- **When to revisit:** If yara-x ships a Node-target build or fixes its default init to work in Node, this workaround can go away. :prayge:

### Metadata normalized from yara-x's array format to an object

yara-x returns rule metadata as `Array<{ identifier, value }>`. the Warlock normalizes this to a flat `{ [key]: value }` object before handing it back to consumers.

This means consumers can write `match.metadata.severity` instead of `match.metadata.find(m => m.identifier === 'severity')?.value`. Every call-site is so much cleaner this way – the Warlock absorbs the conversion once and consumers get a clean shape.

### Types derived from `CATEGORIES as const`

The `CATEGORIES` array is the single source of truth – the `Category` type is derived from it via `(typeof CATEGORIES)[number]`.

This means adding a category is just editing one array. The TypeScript type updates automatically. No hand-maintained union to drift out of sync :)

## API stability

the Warlock publishes a small number of string values that consumers use for routing and filtering. Those values are an API contract – we treat them as load-bearing.

### Append-only `CATEGORIES`

The `CATEGORIES` array in [`src/scanner/types.ts`](src/scanner/types.ts) is **append-only**. New categories can be added over time, but existing values can never be removed or renamed :( I know – annoying. But consumers rely on these strings to filter and route findings, and quietly changing the shape of the API breaks their code in ways that are really hard to spot.

If a category becomes obsolete, just stop writing rules for it. Don't delete the value.

### Append-only `Severity`

The `Severity` union (`critical | high | medium | low`) is append-only for the same reason. New severities can be added, but existing ones can't be removed or renamed.

### What is *not* part of the API contract

**Individual rules are not part of the API.** Rule names, rule counts, and rule internals are detection logic, not interface – they evolve as threats evolve. Rules might get renamed, removed, merged, or split as our detection strategy changes.

- Consumers filtering by `match.metadata.category` or `match.metadata.severity` are on stable ground. These are the append-only API contract.
- Consumers filtering by `match.rule` (a specific rule name) are opting into finer-grained behavior that might need updates when the Warlock releases a new version. It's a valid trade-off – precision in exchange for a little maintenance cost – just know it's not guaranteed-stable.

If you need precise control over which findings you act on, prefer filtering by `category` + `severity` over filtering by rule name. It's the safer bet.

Heads up – changing a rule's severity after the fact is sneaky-breaking. Consumers might have routing built on severity tiers (critical = page someone, low = log it), and a quiet shift can mess that up. So if a rule's severity gets reclassified (e.g., `high` to `medium` after we have more real-world data), we'll always flag it loudly in the changelog. Promise.

### Breaking the rule and contingency plans

OK, this is real life – there are *sometimes* reasons to rename or remove a category or severity. This is the documented exception path. The bar is intentionally high.

**Criteria – acceptable reasons to break append-only:**

- Legal, compliance, or safety reasons (e.g., a category name becomes trademark-problematic, offensive, or regulator-flagged).
- A category is actively causing harm that outweighs the breakage cost (e.g., misleading security teams in a dangerous way).

**Reasons that are *not* acceptable** (these get rationalized into seeming legitimate – they're not):

- "We thought of a better name."
- "We'd prefer a more consistent naming scheme across categories."
- "The new name better matches the rule names in this category."
- "Industry terminology has shifted slightly and ours now feels outdated." (Unless it's crossed into actively causing harm – that's a separate, much higher bar.)
- "A new contributor pointed out the name is awkward."
- "We're worried it sounds unprofessional."
- "Refactoring the rule set surfaced an inconsistency in how we named things."
- "Consumer X asked us to rename it for their use case."

If a proposed rename can be talked into one of these buckets, the answer is no. Add a new value alongside instead :)

**Process if the criteria are met:**

1. **The Docs & Wizard team evaluates the proposal** against the criteria above and against the "not acceptable" list. Most proposals stop here – the owners are the first and primary gatekeepers.
2. **Consult relevant stakeholders** based on the reason for the break:
   - Legal or compliance reasons → loop in legal.
   - Safety reasons or risk of misleading security teams → loop in security.
   - All cases → notify known consumers (wizard, context-mill, others) since they'll need to migrate.
3. **The Docs & Wizard team makes the final decision** as the owners of the Warlock.
4. **Major version bump** (semver `1.x.x → 2.0.0`) to signal a breaking change.
5. **Deprecation period** – ship the old and new values side-by-side for at least one release, with the old value marked deprecated.
6. **Migration guide in the changelog** – what changed, what to replace it with, by when.

**Default answer to "can we rename X?":** Nope. Add a new value alongside instead.

## Public API reference

the Warlock exports a single async function and a set of types.

### `scan(content: string): Promise<ScanResult>`

Scans the given content against every loaded rule. On the first call, rules get compiled and cached for the life of the process.

```typescript
import { scan } from '@posthog/warlock';

const result = await scan(someContent);
if (result.matched) {
  for (const match of result.matches) {
    console.log(`${match.rule} [${match.metadata.severity}]: ${match.metadata.description}`);
  }
}
```

### Types

```typescript
type ScanResult =
  | { matched: false }
  | { matched: true; matches: ScanMatch[] };

interface ScanMatch {
  rule: string;              // the YARA rule name that matched
  metadata: RuleMetadata;    // metadata from the rule's meta: block
}

interface RuleMetadata {
  description?: string;
  severity?: Severity;
  category?: Category;
  [key: string]: string | number | boolean | undefined;
}

type Category =
  | 'prompt_injection'
  | 'exfiltration'
  | 'destructive_operations'
  | 'supply_chain'
  | 'posthog_pii'
  | 'posthog_hardcoded_key';

type Severity = 'critical' | 'high' | 'medium' | 'low';
```

`CATEGORIES` is also exported as a runtime value (the `as const` array) for consumers that need to iterate over all categories.

## Installation

```bash
pnpm install @posthog/warlock
```

the Warlock needs Node `^20.20.0` or `>=22.22.0`. Older versions won't work, sorry :/

## Usage

Minimal usage:

```typescript
import { scan } from '@posthog/warlock';

const result = await scan(someContent);
if (result.matched) {
  for (const match of result.matches) {
    console.log(`Rule matched: ${match.rule}`);
    console.log(`Severity: ${match.metadata.severity}`);
  }
}
```

Filtering by category on the consumer side (the Warlock returns all matches, you pick which ones to act on):

```typescript
import { scan } from '@posthog/warlock';

const result = await scan(someContent);
if (result.matched) {
  const injectionFindings = result.matches.filter(
    (m) => m.metadata.category === 'prompt_injection',
  );
  // ...decide what to do with injectionFindings
}
```

These are minimal examples to get you started. For the full integration guide – filtering trade-offs, response patterns, error handling, performance notes, and versioning guidance – head over to [INTEGRATING.md](INTEGRATING.md) :)

## Development

```bash
pnpm install      # install dependencies
pnpm test         # run tests
pnpm test:watch   # run tests in watch mode
pnpm build        # compile TypeScript and copy rule files to dist/
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution process, review model, rule-writing guide, and category-addition policy.

Heads up – the Warlock is security-critical, so the contribution bar is intentionally tight. Please read the guide in full before opening a PR :)
