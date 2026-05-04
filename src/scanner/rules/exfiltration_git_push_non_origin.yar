// Detects `git push` to a remote that isn't `origin` – arbitrary remote
// names (`upstream`, `heroku`) and full URLs (https://, git@). Push-to-
// fork is the cheapest path for an agent or compromised script to
// exfiltrate the working tree off the user's machine.
//
// Warn, not block: legitimate non-origin pushes are common (forks pushing
// upstream, deploy targets, multi-mirror setups). Consumers layer their
// own allowlist.

rule exfiltration_git_push_non_origin
{
    meta:
        description = "`git push` to a remote other than `origin`. Push-to-fork exfiltrates the entire working tree to attacker-controlled storage."
        remediation = "Confirm the destination – non-origin pushes are legitimate for forks, deploy targets, and mirrors. If unintentional, reject the push."
        severity = "high"
        category = "exfiltration"
        action = "warn"

    strings:
        // Any push to a remote argument (identifier or URL). Optional
        // flag prefix sees through `git push -u <remote>` and
        // `git push --force <remote>`. The identifier-start requirement
        // filters out `git push 2>&1` and `git push --tags`.
        $any_push    = /\bgit\s+push\s+(--?[a-zA-Z][a-zA-Z0-9-]*\s+)*([a-zA-Z_][\w.-]*|https?:\/\/\S+|git@\S+)/

        // Pushes to `origin`. Trailing (\s|:|$) prevents `origin-mirror`
        // and `originally` from looking like origin.
        $origin_push = /\bgit\s+push\s+(--?[a-zA-Z][a-zA-Z0-9-]*\s+)*origin(\s|:|$)/

    condition:
        #any_push > #origin_push
}
