// Catches any npx / pnpm dlx / yarn dlx / bunx invocation, even without
// auto-confirm flags.
//
// A legitimate skill should never tell an AI agent to fetch and execute a
// remote package. If a tool is needed, it should be declared as a project
// dependency — not installed on the fly via npx. Any npx call in a skill
// file is suspicious and warrants review.
//
// This is the softer companion to supply_chain_npx_auto_confirm, which
// catches the critical case (--yes / -y bypassing the install prompt).
// This rule catches the rest: npx without auto-confirm still prompts the
// user, so there is a human checkpoint — hence warn instead of block.
//
// Known false positive: documentation or tutorials that mention npx as
// an example. Consumers should allow-list educational content if needed.

rule supply_chain_npx_in_skill
{
    meta:
        description = "npx / pnpm dlx / yarn dlx / bunx invocation. Skills should not instruct an AI agent to fetch and execute remote packages — dependencies should be declared explicitly."
        remediation = "Remove the npx/dlx/bunx call. If the tool is needed, add it as a project dependency instead."
        severity = "high"
        category = "supply_chain"
        action = "warn"

    strings:
        $npx      = /\bnpx\s+[a-zA-Z@]/
        $pnpm_dlx = /\bpnpm\s+dlx\s+[a-zA-Z@]/
        $yarn_dlx = /\byarn\s+dlx\s+[a-zA-Z@]/
        $bunx     = /\bbunx\s+[a-zA-Z@]/

    condition:
        any of them
}
