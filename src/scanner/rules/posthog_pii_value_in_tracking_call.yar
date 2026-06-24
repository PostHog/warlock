// Detects PII-shaped literal VALUES passed to a PostHog tracking call,
// regardless of the property key. Complements posthog_pii_in_capture_call
// (which matches by key NAME) by catching PII hidden under an innocuous key,
// e.g. `posthog.capture('signup', { referrer: 'jane@example.com' })`.
//
// FP avoidance (same scoping as the key-name rule): only the top-level of the
// first `{ ... }` object is searched. Value patterns are deliberately
// high-precision to keep false positives low:
//   - email: real address shape, and only in capture() — an email value in
//     identify()/person-properties is the standard, correct pattern.
//   - ssn: dashed US SSN (123-45-6789).
//   - card: separator-grouped 16-digit PAN. YARA-X cannot run a Luhn check,
//     so an unseparated 16-digit run is intentionally NOT matched (too noisy).
//
// Known limit: only catches quoted/literal values, not variables (e.g.
// `{ email: userEmail }`). Runtime triage catches most of those at the
// payload level; this rule is the static-analysis backstop for hardcoded
// leaks.

rule posthog_pii_value_in_tracking_call
{
    meta:
        description = "A PII-shaped literal value (email address, US SSN, or formatted credit-card number) passed to a PostHog tracking call."
        remediation = "Remove the literal PII value from the event. Reference users by distinct ID and keep raw PII out of PostHog – https://posthog.com/docs/product-analytics/person-properties"
        severity = "high"
        category = "posthog_pii"
        action = "remediate"
        scan_context = "output"

    strings:
        // Email value — capture() only (email is a valid identify/person property).
        $val_email = /\.capture\s*\([^{]*\{[^{}]*['"][a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}['"]/i
        // Sensitive PII values — flagged across every tracking call-site.
        $val_ssn   = /\.(capture|identify|register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b\d{3}-\d{2}-\d{4}\b/
        $val_card  = /\.(capture|identify|register|register_once|setPersonProperties|setPersonPropertiesForFlags)\s*\([^{]*\{[^{}]*\b\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{4}\b/

    condition:
        any of them
}
