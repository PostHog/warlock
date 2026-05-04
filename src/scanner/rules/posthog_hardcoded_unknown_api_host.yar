// Detects a hardcoded api_host in posthog.init() pointing somewhere
// other than *.posthog.com, localhost, or 127.0.0.1. Host injection
// routes captured analytics (including identify() and session replays)
// to attacker-controlled storage.
//
// Warn, not block: PostHog supports reverse-proxy setups where api_host
// can legitimately point at a non-posthog.com domain.

rule posthog_hardcoded_unknown_api_host
{
    meta:
        description = "Hardcoded api_host in posthog.init() pointing at a domain other than *.posthog.com, localhost, or 127.0.0.1. An unknown host receives all captured analytics, including identify() calls and session replays."
        remediation = "Confirm the host is intentional – reverse-proxy setups are legitimate. If unintentional, replace the value with your PostHog endpoint and rotate the project token."
        severity = "medium"
        category = "supply_chain"
        action = "warn"

    strings:
        // Anchor to posthog.init() so unrelated libraries with an
        // `api_host` config key don't trigger.
        $posthog_init = /posthog\.init\s*\(/

        // Any api_host config with a quoted value.
        $any_api_host = /\bapi_host['"]?\s*[:=]\s*['"][^'"]+['"]/

        // Known-good hosts. Trailing port/path/quote anchoring
        // prevents posthog.com.evil.com from looking known.
        $known_api_host = /\bapi_host['"]?\s*[:=]\s*['"](https?:\/\/)?(([a-zA-Z0-9-]+\.)*posthog\.com|localhost|127\.0\.0\.1)(:[0-9]+)?(\/[^'"]*)?['"]/

    condition:
        $posthog_init and #any_api_host > #known_api_host
}
