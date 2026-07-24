// Catches package-manager installs that pull from a non-registry source –
// a remote tarball URL (.tgz/.tar.gz) or a git repo (git+https, git+ssh,
// git://, git@host:, or the github:/gitlab:/bitbucket: shorthands).
//
// Installing straight from a URL or git repo bypasses the registry's
// published-version review and runs the fetched package's lifecycle
// scripts (preinstall, install, postinstall) from arbitrary repo/tarball
// state – a supply-chain vector. This shape is worth flagging on its own
// now that bare `npm i` / `pnpm i` shorthands are allowlisted for agents:
// a plain `npm i <pkg-name>` no longer prompts, so `npm i <remote-source>`
// would otherwise slip through unreviewed.
//
// Deliberately narrow: it does NOT flag a normal registry install
// (`npm i posthog-js`), a custom-registry flag (`npm i --registry
// https://... pkg`, which points at a registry root, not a tarball), or a
// local path install. deno is excluded – URL installs are idiomatic there.

rule supply_chain_install_remote_source
{
    meta:
        description = "A JS package-manager command installing from a non-registry source (a remote .tgz/.tar.gz tarball URL or a git repository). This bypasses registry review and runs the fetched package's lifecycle scripts from arbitrary state – a supply-chain vector."
        remediation = "Do not install from an ad-hoc URL or git repo. Install the package from the registry by name (e.g. `npm i posthog-js`). If a git or tarball source is genuinely required, confirm its provenance with a human first."
        severity = "high"
        category = "supply_chain"
        action = "block"
        scan_context = "command"

    strings:
        // Install verb across the JS package managers. Reused verbatim in
        // both patterns below via the alternation prefix.

        // Remote tarball: install fetching a .tgz / .tar.gz / .tar over http(s).
        $tarball = /\b(npm\s+(install|i)|pnpm\s+(add|install|i)|yarn\s+add|bun\s+(add|install|i)|cnpm\s+(install|i))\s+([^\n]{0,80}\s)?https?:\/\/[^\s]+\.(tgz|tar\.gz|tar)\b/ nocase

        // Git repo: git+https / git+ssh / git:// URLs, the scp-like
        // git@host: form, and the github:/gitlab:/bitbucket: shorthands.
        $git = /\b(npm\s+(install|i)|pnpm\s+(add|install|i)|yarn\s+add|bun\s+(add|install|i)|cnpm\s+(install|i))\s+([^\n]{0,80}\s)?(git\+(https?|ssh):\/\/|git:\/\/|git@[\w.-]+:|github:|gitlab:|bitbucket:)/ nocase

    condition:
        any of them
}
