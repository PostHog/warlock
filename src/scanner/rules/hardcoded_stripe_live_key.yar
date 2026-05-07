// Detects hardcoded Stripe live secret (sk_live_) and restricted (rk_live_) keys.
// Test-mode (sk_test_) and publishable (pk_live_) keys are deliberately
// excluded – test keys aren't sensitive; publishable keys are designed to
// be public.

rule hardcoded_stripe_live_key
{
    meta:
        description = "Stripe live secret (sk_live_) or restricted (rk_live_) key hardcoded in source."
        remediation = "Roll the key in the Stripe dashboard and replace the hardcoded value with an environment variable. Audit recent API events – committed live keys can charge cards immediately."
        severity = "critical"
        category = "hardcoded_secret"
        action = "remediate"
        scan_context = "output"

    strings:
        $stripe_live_key = /\b(sk|rk)_live_[a-zA-Z0-9]{24,}/

    condition:
        $stripe_live_key
}
