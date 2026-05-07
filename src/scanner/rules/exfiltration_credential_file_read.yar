// Detects references to high-value credential files: private SSH keys
// (id_rsa, id_ed25519, id_ecdsa, id_dsa), `.aws/credentials`, `.netrc`,
// and gcloud's application default credentials. Reading any of these is
// a direct path to external account takeover.
//
// Scope is narrow on purpose – `.ssh/known_hosts`, `.ssh/config`,
// `.ssh/authorized_keys`, and `.aws/config` are legitimately touched by
// setup scripts and excluded.

rule exfiltration_credential_file_read
{
    meta:
        description = "Reference to a sensitive credential file (private SSH key, `.aws/credentials`, `.netrc`, or gcloud ADC). Direct path to external account compromise."
        remediation = "Reject. Tooling needing these credentials should use a secret manager (1Password CLI, vault, ssh-agent), not read files directly."
        severity = "critical"
        category = "exfiltration"
        action = "block"
        scan_context = "command"

    strings:
        // SSH private keys – id_rsa, id_ed25519, id_ecdsa, id_dsa.
        $ssh_priv_key = /\bid_(rsa|ed25519|ecdsa|dsa)\b/

        // `.pub` exclusion: public keys are shareable, not credentials.
        $ssh_pub_key = /\bid_(rsa|ed25519|ecdsa|dsa)\.pub\b/

        // Specific files only – `.aws/config` (region/profile) is excluded.
        $aws_creds = /\.aws\/credentials\b/

        $netrc = /\.netrc\b/
        $gcloud_adc = /\.config\/gcloud\/application_default_credentials\.json\b/

        // Git credential stores – .gitconfig can hold tokens via
        // credential helpers; .git-credentials stores plaintext creds.
        $git_creds = /\.(gitconfig|git-credentials)\b/

    condition:
        (#ssh_priv_key > #ssh_pub_key) or $aws_creds or $netrc or $gcloud_adc or $git_creds
}
