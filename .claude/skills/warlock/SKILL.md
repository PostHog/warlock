---
name: warlock
description: Guardrails for AI agents editing @posthog/warlock, adding or porting rules, proposing new categories, or reviewing Warlock PRs. Load when working in /warlock or on a PR that touches the Warlock source, rules, or docs.
version: "0.1"
---

# Working on the Warlock

The Warlock is a security-critical YARA-based content scanner for PostHog's agentic flows. This skill exists so AI agents don't have to reconstruct the project's charter and rules from source code alone. It is intentionally thin – the authoritative sources are the [README](../../../README.md) and [CONTRIBUTING](../../../CONTRIBUTING.md). Follow the links when you need depth.

## When to use this skill

- Editing any file under `/warlock`
- Porting rules into the Warlock from wizard's legacy `src/lib/yara-scanner.ts`
- Proposing or reviewing a new rule, category, or severity
- Modifying the Warlock's public API, `scan()` signature, or integration-facing docs ([INTEGRATING.md](../../../INTEGRATING.md))
- Reviewing a Warlock PR

## Non-negotiables

The Warlock must never become any of the following. If the change you are considering violates one of these, stop and reconsider.

1. A general-purpose linter or code-quality tool (the Warlock is security-only)
2. A policy or enforcement engine that takes action (the Warlock detects; consumers decide)
3. An orchestration engine that dictates when or where to scan (the Warlock is engine-only – no phase, tool, or workflow awareness)
4. A wizard-specific tool (the Warlock must serve context-mill and future consumers equally)

Full reasoning: [README § Scope and anti-goals](../../../README.md#scope-and-anti-goals).

## Before adding a rule

Run through the checklist in [CONTRIBUTING § Rule-writing guide](../../../CONTRIBUTING.md#rule-writing-guide). In short:

- Required `meta:` fields: `description`, `severity`, `category`, `action`
- Use an existing `Category` value (see `src/scanner/types.ts`); do not invent one inline
- Add both a positive-match and a negative-match vitest test
- Prefer a narrow, specific rule name (e.g., `prompt_injection_ignore_previous`)
- One rule per file – filename matches the rule name (e.g., `prompt_injection_ignore_previous.yar`). See [CONTRIBUTING § Put the rule in the right file](../../../CONTRIBUTING.md#put-the-rule-in-the-right-file)

## Before adding a category

`CATEGORIES` is append-only. New categories are an API commitment – once shipped, they cannot be renamed or removed without a major version bump and a migration path. See [README § API stability](../../../README.md#api-stability).

Before proposing one, confirm:

- It is *security*, not best-practice
- No existing category fits
- A security-team consult has happened (per [CONTRIBUTING ownership model](../../../CONTRIBUTING.md#ownership-model))

## Centralize complexity in the Warlock, not the consumer

When forced to choose between ugly code inside the Warlock and ugly code at every consumer call-site, the Warlock eats the ugly code. Examples: the CommonJS / ESM bridge, yara-x metadata normalization. Full principle: [README § Centralize complexity](../../../README.md#centralize-complexity-in-the-warlock-and-keep-the-consumer-api-clean).

## Ownership model (for PR reviews)

- **The Docs & Wizard team owns the Warlock.** Approval from the Docs & Wizard team is required on every non-trivial PR.
- **Security team is consulted** (not co-owner) on security-sensitive changes: new rules, new categories, API changes, anti-goal-adjacent proposals.
- The self-serve vs. security-consult split is in [CONTRIBUTING](../../../CONTRIBUTING.md#self-serve-vs-security-consult-needed).

## When opening a PR

Every PR description must state (a) the problem this change addresses in one to three sentences, and (b) why the Warlock is the right home for this change as opposed to the wizard, context-mill, or another tool. This guards against scope drift. See [CONTRIBUTING § Acceptable-goal statement on every PR](../../../CONTRIBUTING.md#acceptable-goal-statement-on-every-pr).

## Further reading

- [README.md](../../../README.md) – charter, audience, design decisions, API stability, public API reference
- [CONTRIBUTING.md](../../../CONTRIBUTING.md) – contribution process, rule-writing guide, category-addition policy
- [INTEGRATING.md](../../../INTEGRATING.md) – guide for engineers integrating the Warlock into a consumer application; update this when changing the public API
- [.github/pull_request_template.md](../../../.github/pull_request_template.md) – PR template used for every Warlock PR
