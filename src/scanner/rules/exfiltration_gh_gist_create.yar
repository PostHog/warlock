// Detects `gh gist create`. Posts file contents to a
// public or secret GitHub gist. Even "secret" gists are URL-accessible
// to anyone with the link, so this is a one-line exfiltration path.
//
// Block, not warn: legitimate gist creation is rare in agent contexts
// and the FP cost is lower than the cost of a missed exfil.

rule exfiltration_gh_gist_create
{
    meta:
        description = "`gh gist create`. Posts file contents to a GitHub gist – public and secret gists are both URL-accessible."
        remediation = "Reject. For sharing snippets, use a controlled internal channel; gists are externally addressable."
        severity = "high"
        category = "exfiltration"
        action = "block"

    strings:
        $gh_gist_create = /\bgh\s+gist\s+create\b/

    condition:
        $gh_gist_create
}
