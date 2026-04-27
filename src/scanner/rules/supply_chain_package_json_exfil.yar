// Catches exfiltration patterns planted inside a package.json
// "scripts" value. The attack: an agent edits package.json so that a
// later `npm install` or `npm run <script>` reads a secret-shaped env
// var (or credential file) and ships it out – the allowlist treats
// the npm command itself as normal. Severity is critical because
// lifecycle scripts (preinstall/postinstall/prepare) run
// automatically on install.
//
// Known gap: payload-in-a-separate-file indirection (e.g. a
// postinstall that runs node ./foo.js where ./foo.js is the real
// payload) is not caught here – that is a diff-review concern.

rule supply_chain_package_json_exfil
{
    meta:
        description = "A package.json 'scripts' value containing a secret-exfiltration pattern. Matches the attack shape where a malicious edit plants an exfil command that later runs via npm install or npm run."
        remediation = "Refuse to write the file. Inspect the diff – any script that reads a secret env var, credential file, or opens a raw TCP channel is almost certainly hostile. Rotate any secret that may have been referenced and revert the edit."
        severity = "critical"
        category = "supply_chain"
        action = "block"

    strings:
        // Anchor: content looks like a package.json (has a scripts block)
        $anchor_scripts_block = /"scripts"\s*:\s*\{/

        // Secret-shaped env var reaching a network tool inside a script value.
        // Script-value fence: "<key>"\s*:\s*"...<payload>..."
        $payload_env_secret_to_net = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\b(curl|wget|httpie|nc|netcat|socat|scp|rsync|ssh)\b[^"]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/

        // /dev/tcp channel inside a script value – raw TCP writes, almost always exfil
        $payload_dev_tcp = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\/dev\/tcp\/[A-Za-z0-9.-]+\/[0-9]+/

        // base64 piped to a network tool inside a script value
        $payload_base64_to_net = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\bbase64\b[^"]{0,200}\|\s*(curl|wget|nc|netcat|socat)/

        // Credential file read piped to network inside a script value.
        // The .env pattern matches both dotfile prefix (.env, .env.local) and
        // basename suffix (secrets.env, app.env, config.env) – mirrors
        // $pipe_cred_file_to_net in exfiltration_secret_via_shell, keep in sync.
        $payload_cred_file_to_net = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\b(cat|grep|tail|head|awk|sed)\s+[^"]{0,100}([A-Za-z0-9_-]*\.env(\.[a-z]+)?|~\/\.(aws|ssh|kube|docker|gnupg)|\.netrc|secrets\.ya?ml|credentials\.json)[^"]{0,100}\|\s*(curl|wget|nc|netcat|socat)/

        // PostHog personal key or project token shipped via curl/wget inside a script value
        $payload_posthog_key_to_net = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\b(curl|wget)\b[^"]{0,200}ph[cx]_[a-zA-Z0-9]{30,}/

        // Language one-liner reading an env secret inside a script value
        $payload_lang_env_secret = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\b(python3?|node|perl|ruby)\s+-[ce]\b[^"]{0,400}(os\.environ|process\.env|ENV\[)[^"]{0,40}(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // Credential file pulled via curl/wget/scp/rsync inside a script value.
        // The .env pattern matches both dotfile prefix and basename suffix –
        // mirrors $cred_file_remote in exfiltration_secret_via_shell, keep in sync.
        $payload_cred_file_remote = /"[A-Za-z0-9_:-]+"\s*:\s*"[^"]{0,300}\b(curl|wget|scp|rsync)\b[^"]{0,200}([A-Za-z0-9_-]*\.env(\.(production|local|staging|dev|development|prod|test))?|~\/\.(aws|ssh|kube|docker|gnupg)|id_rsa|id_ed25519|\.netrc|secrets\.ya?ml|credentials\.json|\.kube\/config|\.docker\/config\.json)/i

    condition:
        $anchor_scripts_block and (
            $payload_env_secret_to_net or
            $payload_dev_tcp or
            $payload_base64_to_net or
            $payload_cred_file_to_net or
            $payload_posthog_key_to_net or
            $payload_lang_env_secret or
            $payload_cred_file_remote
        )
}
