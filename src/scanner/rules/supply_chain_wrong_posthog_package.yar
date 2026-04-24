// Catches install commands that reach for a bare "posthog" package in
// the JS ecosystem — npm, pnpm, yarn, bun, deno. PostHog's JS SDKs
// are always suffixed (posthog-js, posthog-node, posthog-react-native,
// etc.), so a bare `posthog` install in JS is either a typo or a
// supply-chain attack (the bare name is available on npm and could be
// compromised or squatted).
//
// Scoped to JS install commands deliberately. `pip install posthog`
// is correct on Python — the Python SDK publishes under the bare
// name. Ruby, Go, PHP, Composer etc. have their own conventions and
// don't fit this rule's shape.
//
// Known FP: `npm install posthog posthog-js` in a single command
// matches both strings, so the condition suppresses the alert. Rare
// in practice, so accepting the gap.

rule supply_chain_wrong_posthog_package
{
    meta:
        description = "A JS package-manager command installing a bare 'posthog' package. PostHog's JS SDKs are always suffixed (posthog-js, posthog-node, etc.), so this is either a typo or a supply-chain attack against the bare 'posthog' npm name."
        remediation = "Refuse to run the install. Confirm which PostHog SDK the codebase actually needs (posthog-js for browser, posthog-node for server) and install that one explicitly."
        severity = "high"
        category = "supply_chain"
        action = "block"

    strings:
        // JS install command targeting bare "posthog"
        $install_bare_posthog = /\b(npm\s+install|npm\s+i|pnpm\s+(add|install|i)|yarn\s+add|bun\s+(add|install|i)|deno\s+(add|install))\s+([^\n]{0,80}\s)?posthog(\s|$|@)/

        // Same managers installing a suffixed PostHog package — used as
        // a negative signal in the condition so commands like "yarn add
        // posthog-node" don't trip the bare-name pattern
        $install_suffixed_posthog = /\b(npm\s+install|npm\s+i|pnpm\s+(add|install|i)|yarn\s+add|bun\s+(add|install|i)|deno\s+(add|install))\s+([^\n]{0,80}\s)?posthog-[a-z]/

    condition:
        $install_bare_posthog and not $install_suffixed_posthog
}
