## Problem and acceptable goal

**Problem this change addresses**

<!-- What security gap, bug, or deficiency are you solving? -->

**Why the Warlock is the right home for this change:**

<!--
Rule of thumb: every Warlock PR states *why this belongs in the Warlock* as
opposed to wizard, context-mill, or another tool. Scope drift is the Warlock's
biggest risk, and this question catches it early :)
-->

## Changes

<!-- Short bulleted summary of the diff. -->

## Anti-goal check

Confirm your change isn't pushing the Warlock toward any of its [anti-goals](../README.md#scope-and-anti-goals):

- [ ] This is **not** a code-quality or best-practice check (those belong in wizard or a linter)
- [ ] This does **not** add policy or enforcement logic (the Warlock detects, consumers decide)
- [ ] This does **not** add phase, tool, or workflow awareness to the engine (the Warlock is engine-only)
- [ ] This does **not** encode wizard-specific assumptions (the Warlock serves multiple consumers)

If any of these is unchecked, explain below why the change is still right for the Warlock.

## Test plan

<!--
How did you verify this change?
-->

- [ ] Existing tests pass (`pnpm test`)
- [ ] Build succeeds (`pnpm build`)
- [ ] For new rules: added a positive-match test (content that *should* match)
- [ ] For new rules: added a negative-match test (similar content that should *not* match – guards against false positives)
- [ ] For new rules: includes `scan_context` metadata (`command`, `input`, or `output`)
- [ ] For API changes: verified consuming projects (wizard, context-mill) against the change
