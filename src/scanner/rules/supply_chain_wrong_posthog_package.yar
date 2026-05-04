// Catches install commands reaching for a bare "posthog" package in
// JS (npm, pnpm, yarn, bun, deno). PostHog's JS SDKs are always
// suffixed (posthog-js, posthog-node, etc.), so a bare install is
// either a typo or a supply-chain attack on the bare npm name.
//
// JS-only by design – `pip install posthog` is correct on Python.
// Known FP: `npm install posthog posthog-js` matches both strings,
// so the suffixed pattern suppresses the alert.

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
