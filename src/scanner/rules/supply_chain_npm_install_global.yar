// Catches global package installs (npm, pnpm, yarn). Globally-installed
// packages run lifecycle scripts (preinstall, install, postinstall) with
// broader permissions than a local install – a known supply-chain vector.
//
// Modern workflows rarely need this; `npx`, `pnpm dlx`, or project-scoped
// scripts cover one-off CLI usage instead.

rule supply_chain_npm_install_global
{
    meta:
        description = "Package-manager command installing globally (-g, --global, or yarn global add). Global installs run lifecycle scripts (preinstall, install, postinstall) with broader permissions than a project-local install."
        remediation = "Drop the global flag and install locally. For one-off CLI use, run `npx <pkg>` or `pnpm dlx <pkg>` instead."
        severity = "high"
        category = "supply_chain"
        action = "block"

    strings:
        // npm install -g | --global, flag in either position
        // (npm install -g foo  OR  npm install foo -g).
        $npm_global  = /\bnpm\s+(install|i)\s+([^\n]{0,80}\s)?(-g|--global)\b/

        // pnpm add | install | i, same flag handling.
        $pnpm_global = /\bpnpm\s+(add|install|i)\s+([^\n]{0,80}\s)?(-g|--global)\b/

        // yarn 1's global-install syntax (yarn 2+ removed it).
        $yarn_global = /\byarn\s+global\s+add\b/

    condition:
        any of them
}
