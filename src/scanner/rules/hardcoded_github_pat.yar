// Detects hardcoded GitHub access tokens (ghp_, ghs_, gho_, ghu_, ghr_).
// Pattern: 4-char prefix + 36+ alphanumerics. Fine-grained PATs
// (github_pat_ prefix) have a different shape and aren't covered.

rule hardcoded_github_pat
{
    meta:
        description = "GitHub access token (ghp_, ghs_, gho_, ghu_, or ghr_) hardcoded in source."
        remediation = "Revoke the token in GitHub settings and replace the hardcoded value with an environment variable. Audit recent repository and account activity – committed tokens can be used immediately."
        severity = "critical"
        category = "hardcoded_secret"
        action = "remediate"
        scan_context = "output"

    strings:
        $github_pat = /\bgh[psoru]_[A-Za-z0-9]{36,}/

    condition:
        $github_pat
}
