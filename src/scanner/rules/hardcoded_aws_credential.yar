// Detects hardcoded AWS access keys (AKIA) and session tokens (ASIA).
// Pattern: prefix + exactly 16 uppercase alphanumerics. Leading \b
// prevents matches inside longer identifiers.

rule hardcoded_aws_credential
{
    meta:
        description = "AWS access key (AKIA) or session token (ASIA) hardcoded in source."
        remediation = "Rotate the credential in IAM (or invalidate the session) and replace the hardcoded value with an environment variable. Audit recent CloudTrail events – committed credentials can be used immediately."
        severity = "critical"
        category = "hardcoded_secret"
        action = "remediate"
        scan_context = "output"

    strings:
        $aws_credential = /\b(AKIA|ASIA)[A-Z0-9]{16}/

    condition:
        $aws_credential
}
