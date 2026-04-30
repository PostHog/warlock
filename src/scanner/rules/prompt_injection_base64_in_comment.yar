// Catches base64 blobs hidden in code comments — a smuggling technique
// for prompt-injection payloads. Human reviewer sees gibberish and
// scrolls past; an agent that reads or decodes the file sees the real
// payload.
//
// 40-char floor (padded or unpadded). Long unbroken alphanumeric
// runs in comments are rare in real code, so the floor stays low
// without bloating false positives.
//
// Comments only for this rule. Non-comment base64 detection is a separate rule

rule prompt_injection_base64_in_comment
{
    meta:
        description = "Base64 blob (40+ chars) embedded in a code comment. A common way to hide prompt-injection instructions from human reviewers."
        remediation = "Refuse to process the content. Decode the base64 and check what's inside before deciding whether to allow it — if the comment can't explain why the blob is there, treat it as hostile."
        severity = "critical"
        category = "prompt_injection"
        action = "block"

    strings:
        // JS/TS/Go/Rust/Java etc single-line comment: "// <base64 40+>"
        $b64_slash_comment = /\/\/[ \t]*[A-Za-z0-9+\/]{40,}={0,2}/

        // JS/TS/C block comment: "/* <base64 40+> */"
        $b64_block_comment = /\/\*[ \t\r\n]*[A-Za-z0-9+\/]{40,}={0,2}/

        // Python/shell/YAML/TOML: "# <base64 40+>"
        $b64_hash_comment = /(^|\n)[ \t]*#[ \t]*[A-Za-z0-9+\/]{40,}={0,2}/

        // SQL single-line: "-- <base64 40+>"
        $b64_sql_comment = /(^|\n)[ \t]*--[ \t]*[A-Za-z0-9+\/]{40,}={0,2}/

        // HTML/Markdown comment: "<!-- <base64 40+> -->"
        $b64_html_comment = /<!--[ \t\r\n]*[A-Za-z0-9+\/]{40,}={0,2}/

    condition:
        any of them
}
