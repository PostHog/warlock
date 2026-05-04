// Detects `gh api` calls using a write HTTP method (POST, PUT, PATCH,
// DELETE). Writes through the GitHub CLI can post repository contents
// or secrets to attacker-controlled issues, comments, or repos.
//
// Warn because legitimate agent flows do open real PRs and leave real
// comments via `gh api`. `gh api graphql` uses a different shape and
// isn't covered here.

rule exfiltration_gh_api_write
{
    meta:
        description = "`gh api` with a write method (POST, PUT, PATCH, DELETE). GitHub CLI writes can post data to attacker-controlled resources."
        remediation = "Confirm the call is intentional – legitimate writes happen (real PRs, real comments). If unintentional, reject."
        severity = "high"
        category = "exfiltration"
        action = "warn"

    strings:
        // Method flag in either position. Delimiter can be a space or `=`
        // (e.g. -X POST, -X=POST, --method=DELETE). Case insensitive
        // because the CLI accepts lowercase methods too.
        $gh_api_write = /\bgh\s+api\s+([^\n]{0,80}\s)?(-X|--method)(\s+|=)(POST|PUT|PATCH|DELETE)\b/i

    condition:
        $gh_api_write
}
