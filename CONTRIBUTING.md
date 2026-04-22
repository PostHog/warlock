# Contributing to the Warlock

Welcome to the Warlock :)

The Warlock is security-critical infrastructure for PostHog's agentic flows, so the contribution bar here is intentionally tighter than other PostHog repos. Small mistakes in a security scanner can have real downstream consequences, so we want to be careful. Please read this guide in full before opening a PR.

Quick context first: the Warlock's charter, scope, anti-goals, and design decisions live in the [README](README.md). This guide covers the *process* of contributing — the README covers the *what* and *why* of the project. If something in this guide conflicts with the README, the README wins and this guide is out of date. Please open a PR to fix it!

## Who this guide is for

- Engineers on the Docs & Wizard team who own the Warlock day-to-day
- Security-team members reviewing PRs to the Warlock and weighing in on rule / category changes
- Other PostHog-internal contributors adding rules, fixing bugs, or improving documentation

Heads up — the Warlock is currently an internal project and isn't currently accepting contributions from outside PostHog.

## Ownership model

**The Docs & Wizard team owns the Warlock.** That means they're the ones responsible for keeping the Warlock within scope, maintaining its quality bar, and shipping releases.

**Security team is consulted** on security-sensitive changes. Their job is to weigh in with security expertise as needed. The final decision on any change rests with the Docs & Wizard team.

This split exists because the Warlock evolves at a faster cadence than the security team can own end-to-end, but security expertise is essential on the changes that matter most. So we get the speed of single ownership *and* the rigor of security input where it counts :)

## Rule-writing guide

All YARA rules live in [`src/scanner/rules/*.yar`](src/scanner/rules/). For every new rule, here's what you need to do:

### Use the required metadata fields

Every rule's `meta:` block must include:

| Field | Type | Allowed values | Purpose |
| --- | --- | --- | --- |
| `description` | string | free text | Plain-language sentence describing what this rule catches. Ends up in logs and alerts — write it for a human on-call. |
| `severity` | string | `critical`, `high`, `medium`, `low` | Match severity to real-world impact, not detection confidence. See [README § API stability](README.md#api-stability). |
| `category` | string | any value in `CATEGORIES` | Must be an existing category (see `src/scanner/types.ts`). Do not add one inline — see *Category-addition policy* below. |
| `action` | string | `block`, `revert`, `warn` | Rule author's recommendation to the consumer. Not a command — consumers decide what to actually do. |

### Name the rule clearly

Rule names show up in logs and match output, so make them readable! Use snake_case, lead with the threat class, and be specific. Good: `prompt_injection_ignore_previous`, `exfiltration_base64_in_url`. Bad: `rule1`, `bad_thing`.

### Put the rule in the right file

The Warlock uses **one rule per file**. The filename matches the rule name:

- New rule `prompt_injection_ignore_previous` → `src/scanner/rules/prompt_injection_ignore_previous.yar`
- New rule `exfiltration_base64_in_url` → `src/scanner/rules/exfiltration_base64_in_url.yar`

Why one-per-file? A few reasons:

- **Direct lookup** — rule name → file path. No scanning inside a bigger file to find the right block.
- **Safer for agent-assisted edits** — we're all using agents to write code. A single-rule file means an agent can edit it without risk of accidentally matching a sibling rule's similar pattern.
- **Cleaner diffs** — adding a rule is one new file. Removing one is one deleted file. No whitespace or ordering churn in an existing file.
- **Category navigation still works** — to see every rule in a category, glob by prefix: `ls src/scanner/rules/prompt_injection_*.yar`

### Add at least one test

Every new rule needs a vitest test in [`src/scanner/__tests__/`](src/scanner/__tests__/) that:

1. Exercises a positive case — content that *should* match.
2. Exercises a negative case — similar content that should *not* match. This is what guards against false positives, which is super important for a security tool!

## Category-addition policy

The `CATEGORIES` array is **append-only** and protected by the API-stability rules in the [README](README.md#api-stability). Adding a new category is a real commitment — once it ships, the value can never be renamed or removed without a major version bump and a documented migration path. So we want to be thoughtful here!

Before proposing a new category, check:

1. **Is it security?** the Warlock is security-only. Best-practice checks, code-quality rules, and product-telemetry checks belong elsewhere. See [README § Scope and anti-goals](README.md#scope-and-anti-goals) for concrete rejected examples.
2. **Does an existing category fit?** Reuse before you add. New categories fragment consumer routing logic.
3. **Has security been consulted?** New categories need security-team input per the table above.
4. **Append only.** Add the new string to the end of `CATEGORIES` in `src/scanner/types.ts`. Don't rearrange existing values.
5. **Minor version bump.** Additions are non-breaking, so a minor bump is enough.

If your proposal feels like a borderline case ("is this really security?"), the precedent for rejecting similar proposals is documented in the [README anti-goals section](README.md#scope-and-anti-goals). When in doubt, ask!

## Commit hygiene

Heads up — the Warlock's repository visibility may change. It's currently private, but the precedent leans toward making PostHog's agent infrastructure public (wizard is already public and its rules are visible). So treat the repo as if it could go public at any time:

- No internal-only notes, tickets, or context in commit messages or PR descriptions.
- No credentials, API keys, or production data in tests, fixtures, or comments.
- If something is sensitive, keep it in Slack or an internal doc and reference it indirectly.

## What NOT to contribute

Before opening a PR, double-check that your change isn't pushing the Warlock toward any of its [anti-goals](README.md#scope-and-anti-goals):

- **Code-quality or best-practice rules.** These belong in the wizard, context mill, or a dedicated linter, not the Warlock.
- **Policy or enforcement logic.** the Warlock recommends, consumers decide. Don't add code that blocks, reverts, or warns *on behalf of* the consumer.
- **Orchestration, phase awareness, or tool awareness.** the Warlock is engine-only. It doesn't know about tool calls, agent phases, or workflow steps. Don't add this knowledge to the engine.
- **Wizard-specific assumptions.** the Warlock is designed to serve multiple consumers. Anything that only makes sense in the wizard's world belongs in the wizard.

If you're not sure whether your change lands in an anti-goal, just ask the Docs & Wizard team before investing too much effort. We're happy to help :)
