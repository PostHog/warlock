// Detects hardcoded PostHog personal API keys (phx_ prefix).
//
// Pattern: `phx_` + 30+ alphanumeric chars (real tokens are 40+; 30 is a
// conservative floor). Leading \b so `phx_` embedded in a longer identifier
// (e.g. `my_phx_thing_AAAA...`) doesn't match.

rule posthog_hardcoded_personal_api_key
{
    meta:
        description = "PostHog personal API key (phx_ prefix) hardcoded in source. Personal keys grant admin access to the organization."
        remediation = "Rotate the key in the PostHog admin UI and replace the hardcoded value with an environment variable. Audit recent access – committed keys can be used immediately."
        severity = "critical"
        category = "posthog_hardcoded_key"
        action = "revert"

    strings:
        $phx_key = /\bphx_[a-zA-Z0-9]{30,}/

    condition:
        $phx_key
}
