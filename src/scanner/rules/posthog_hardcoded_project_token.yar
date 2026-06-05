// Detects hardcoded PostHog project tokens (phc_ prefix).
//
// Project tokens are write-only (they can send events but not read data
// or modify the organization). A leaked project token is lower-severity
// than a personal API key, but hardcoding is still a hygiene problem:
// committed tokens can be used to send junk events, exhaust ingestion
// quota, or spoof traffic patterns.
//
// Pattern approach:
//   - Match `phc_` followed by 30+ alphanumeric characters (real PostHog
//     tokens are 40+ chars; 30 is a conservative floor)
//   - Leading \b avoids matching when `phc_` is embedded in a longer
//     identifier
//   - Excludes obvious placeholder tokens (phc_your_*, phc_example_*, etc.)

rule posthog_hardcoded_project_token
{
    meta:
        description = "PostHog project token (phc_ prefix) hardcoded in source."
        remediation = "Move the token to an environment variable and rotate the exposed value. Committed tokens can be used to send junk events, exhaust ingestion quota, or spoof traffic even though they are write-only."
        severity = "medium"
        category = "posthog_hardcoded_key"
        action = "remediate"
        scan_context = "output"

    strings:
        $phc_key = /\bphc_[a-zA-Z0-9]{30,}/

        // Obvious placeholder tokens — not real secrets
        $phc_placeholder = /\bphc_(your|placeholder|example|test|fake|dummy|xxx|replace|sample|changeme|todo|insert)[a-zA-Z0-9_]*/i

    condition:
        $phc_key and not $phc_placeholder
}
