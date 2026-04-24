// Catches shell commands that pair a secret (env var, credentials file,
// PostHog API key) with a tool that can move data off the machine.
// Broader than "curl $TOKEN" — covers network tools (curl, wget,
// httpie, nc, socat), language one-liners (python -c, node -e),
// DNS smuggling (dig, nslookup), remote-copy tools (scp, rsync, ssh),
// PowerShell web cmdlets, and bash's /dev/tcp channel. Bounded
// .{0,200} windows keep the patterns from grabbing unrelated text
// further along in a shell script.
//
// Known FP: legitimate operational commands (e.g. curl to an internal
// API with a real auth header) will fire. Consumers that need
// finer-grained scoping should allow-list known-good destinations.

rule exfiltration_secret_via_shell
{
    meta:
        description = "A shell command that combines a secret (env var, credential file, or API token) with a tool that can move data off the machine. Looks like an attempt to exfiltrate a secret."
        remediation = "Refuse to run the command. Confirm the destination — if it isn't an approved internal service, treat the command as hostile and rotate the secret that was referenced."
        severity = "critical"
        category = "exfiltration"
        action = "block"

    strings:
        // curl / wget with a secret-shaped env var in args or header
        $curl_wget_env_secret = /\b(curl|wget)\s[^\n]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // httpie (http / https commands) with a secret-shaped env var
        $httpie_env_secret = /\b(https?|httpie)\s[^\n]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // PowerShell Invoke-WebRequest / Invoke-RestMethod with $env:SECRET
        $powershell_web_env_secret = /Invoke-(WebRequest|RestMethod)[^\n]{0,200}\$env:[A-Za-z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // Language one-liner reaching for a shell-style $SECRET env var
        $lang_oneliner_shell_var = /\b(python3?|node|perl|ruby)\s+-[ce]\b[^\n]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // Language one-liner reaching for a secret via language-native env
        // access (os.environ[...], process.env.X, ENV['X']) — realistic
        // exfil shape because these commands usually inline the env-read
        $lang_oneliner_env_access = /\b(python3?|node|perl|ruby)\s+-[ce]\b[^\n]{0,400}(os\.environ|process\.env|ENV\[)[^\n]{0,40}(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // curl uploading a file out (--upload-file / -T / -F file=@...)
        $curl_file_upload = /\bcurl\s[^\n]{0,200}(--upload-file|-T\s|-F\s+["']?[A-Za-z_]+=@)/i

        // Secret-shaped env var piped into a network tool
        $pipe_env_secret_to_net = /\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)[^\n]{0,200}\|\s*(curl|wget|nc\b|netcat\b|http\s|httpie|socat)/i

        // Credential file (.env, ~/.aws, ~/.ssh, etc.) read and piped to network
        $pipe_cred_file_to_net = /\b(cat|grep|tail|head|awk|sed)\s+[^\n]{0,100}(\.env(\.[a-z]+)?|~\/\.(aws|ssh|kube|docker|gnupg)|\.netrc|secrets\.ya?ml|credentials\.json)[^\n]{0,100}\|\s*(curl|wget|nc\b|netcat\b|http\s|httpie|socat)/i

        // Base64-encode a secret and pipe it out (common obfuscation)
        $pipe_base64_to_net = /\bbase64\b[^\n]{0,200}\|\s*(curl|wget|nc\b|netcat\b|socat)/i

        // PostHog personal API key or project token shipped to a URL
        $posthog_key_to_net = /\b(curl|wget)\b[^\n]{0,200}ph[cx]_[a-zA-Z0-9]{30,}/

        // curl / wget / scp / rsync reaching for a credential file
        $cred_file_remote = /\b(curl|wget|scp|rsync)\b[^\n]{0,200}(\.env(\.(production|local|staging|dev|development|prod|test))?|~\/\.(aws|ssh|kube|docker|gnupg)|id_rsa|id_ed25519|\.netrc|secrets\.ya?ml|credentials\.json|\.kube\/config|\.docker\/config\.json)/i

        // DNS-based exfil: dig / nslookup with a secret smuggled into hostname
        $dns_exfil_env_secret = /\b(dig|nslookup|host)\s[^\n]{0,100}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // Bash /dev/tcp channel — raw TCP writes, almost always exfil
        $bash_dev_tcp = /\/dev\/tcp\/[A-Za-z0-9.-]+\/[0-9]+/

        // socat with a secret-shaped env var
        $socat_env_secret = /\bsocat\b[^\n]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

        // Piping into a bare netcat — legitimate uses are rare, almost always exfil
        $pipe_to_netcat = /\|\s*(nc|netcat)\s+[A-Za-z0-9.-]+\s+[0-9]+/

        // ssh running a remote command that reaches for a secret
        $ssh_remote_env_secret = /\bssh\s[^\n]{0,200}\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|API|PRIVATE|ACCESS|PASSPHRASE|JWT|SESSION|COOKIE)/i

    condition:
        any of them
}
