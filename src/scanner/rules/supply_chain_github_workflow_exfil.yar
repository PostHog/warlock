// Catches exfil patterns planted inside a GitHub Actions workflow: an
// agent edits the workflow so the runner ships a secret on next push/PR.
// Critical because runners hold org secrets and run before human review.
//
// Payload list is narrow on purpose – generic "curl + secret" would drown
// CI in FPs. Patterns here are shapes that are almost never legit in CI.
//
// Out of scope: composite actions (action.yml), this will be a separate rule.

rule supply_chain_github_workflow_exfil
{
    meta:
        description = "A GitHub Actions workflow containing a clear exfiltration shape (raw TCP channel, credential-file read, gh gist create, DNS smuggling, or a GitHub secret piped to a data-sink). These patterns are almost never legitimate in CI."
        remediation = "Refuse to write the workflow. Inspect the diff – these patterns do not appear in normal CI. Rotate any secret that may have been referenced and revert the edit."
        severity = "critical"
        category = "supply_chain"
        action = "block"
        scan_context = "input"

    strings:
        // Anchor: top-level jobs: key (every workflow has one)
        $anchor_jobs = /\bjobs:\s*\n/

        // Bash /dev/tcp channel – never legit in CI
        $payload_dev_tcp = /\/dev\/tcp\/[A-Za-z0-9.-]+\/[0-9]+/

        // base64 piped to a network tool
        $payload_base64_to_net = /\bbase64\b[^\n]{0,200}\|\s*(curl|wget|nc\b|netcat\b|socat)/

        // Cred file read and piped to a network tool.
        // Mirrors $pipe_cred_file_to_net in exfiltration_secret_via_shell – keep in sync.
        $payload_cred_file_to_net = /\b(cat|grep|tail|head|awk|sed)\s+[^\n]{0,100}([A-Za-z0-9_-]*\.env(\.[a-z]+)?|~\/\.(aws|ssh|kube|docker|gnupg)|\.netrc|secrets\.ya?ml|credentials\.json)[^\n]{0,100}\|\s*(curl|wget|nc\b|netcat\b|socat)/i

        // Cred file pulled by curl / wget / scp / rsync.
        // Mirrors $cred_file_remote in exfiltration_secret_via_shell – keep in sync.
        $payload_cred_file_remote = /\b(curl|wget|scp|rsync)\b[^\n]{0,200}([A-Za-z0-9_-]*\.env(\.(production|local|staging|dev|development|prod|test))?|~\/\.(aws|ssh|kube|docker|gnupg)|id_rsa|id_ed25519|\.netrc|secrets\.ya?ml|credentials\.json|\.kube\/config|\.docker\/config\.json)/i

        // DNS-based exfil: dig / nslookup / host with a secret smuggled into the hostname
        $payload_dns_exfil = /\b(dig|nslookup|host)\s[^\n]{0,100}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // gh gist create – creating a gist in CI is almost always exfil
        $payload_gh_gist_create = /\bgh\s+gist\s+create\b/

        // ${{ secrets.X }} piped to a raw data-sink (netcat, /dev/tcp, file upload)
        $payload_gh_secret_to_sink = /\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}[^\n]{0,200}(\|\s*(nc|netcat|socat)\b|\/dev\/tcp\/|-F\s+["']?[A-Za-z_]+=@|--upload-file\b|--data-binary\s+@)/

        // PostHog personal or project key shipped via curl / wget
        $payload_posthog_key_to_net = /\b(curl|wget)\b[^\n]{0,200}ph[cx]_[a-zA-Z0-9]{30,}/

        // Secret-shaped env var piped into a netcat-style sink
        $payload_pipe_env_to_netcat = /\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)[^\n]{0,200}\|\s*(nc|netcat|socat)\s+[A-Za-z0-9.-]+/

        // ssh executing a remote command that reaches for a secret env var
        $payload_ssh_remote_env_secret = /\bssh\s[^\n]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

    condition:
        $anchor_jobs and (
            $payload_dev_tcp or
            $payload_base64_to_net or
            $payload_cred_file_to_net or
            $payload_cred_file_remote or
            $payload_dns_exfil or
            $payload_gh_gist_create or
            $payload_gh_secret_to_sink or
            $payload_posthog_key_to_net or
            $payload_pipe_env_to_netcat or
            $payload_ssh_remote_env_secret
        )
}
