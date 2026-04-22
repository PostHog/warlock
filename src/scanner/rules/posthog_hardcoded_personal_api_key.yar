// Detects hardcoded PostHog personal API keys (phx_ prefix).
//
// Personal API keys grant admin access to a PostHog organization: they can
// read and modify projects, feature flags, annotations, and any other
// authenticated resource. A leaked phx_ key is a real credential incident
// and should be rotated immediately.
//
// Pattern approach:
//   - Match `phx_` followed by 30+ alphanumeric characters (real PostHog
//     token bodies are 40+ chars; 30 is a conservative floor)
//   - Leading \b avoids matching when `phx_` is embedded in a longer
//     identifier (e.g., `my_phx_thing_AAAAAAAAAAAA...` should not match)

rule posthog_hardcoded_personal_api_key
{
    meta:
        description = "PostHog personal API key (phx_ prefix) hardcoded in source. Personal keys grant admin access to the organization."
        remediation = "Rotate the exposed key via the PostHog admin UI, then move authentication to an environment variable or a secrets manager. Treat this as a credential leak and audit recent access to the organization."
        severity = "critical"
        category = "posthog_hardcoded_key"
        action = "revert"

    strings:
        $phx_key = /\bphx_[a-zA-Z0-9]{30,}/

    condition:
        $phx_key
}
