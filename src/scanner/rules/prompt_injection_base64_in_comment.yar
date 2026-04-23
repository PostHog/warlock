// Catches long base64 blobs hidden in code comments — a smuggling
// technique for prompt-injection payloads. Human reviewer sees
// gibberish and scrolls past; an agent that reads or decodes the file
// sees the real payload.
//
// Two deliberate scope choices:
//   - 100-char floor: legit short base64 in comments (hashes, short
//     cipher examples) sits well below that, real payloads need the
//     bytes to encode actual instructions
//   - Comments only: long base64 in real code (like `const HASH =
//     "..."`) is a legitimate pattern and would false positive constantly. Broader
//     coverage tracked in the Warlock backlog

rule prompt_injection_base64_in_comment
{
    meta:
        description = "Long base64 blob (100+ chars) embedded in a code comment. A common way to hide prompt-injection instructions from human reviewers."
        remediation = "Refuse to process the content. Decode the base64 and check what's inside before deciding whether to allow it — if the comment can't explain why the blob is there, treat it as hostile."
        severity = "critical"
        category = "prompt_injection"
        action = "block"

    strings:
        // JS/TS/Go/Rust/Java etc single-line comment: "// <base64 100+>"
        $b64_slash_comment = /\/\/[ \t]*[A-Za-z0-9+\/]{100,}={0,2}/

        // JS/TS/C block comment: "/* <base64 100+> */" (bounded, tolerates
        // whitespace between the opener and the blob)
        $b64_block_comment = /\/\*[ \t\r\n]*[A-Za-z0-9+\/]{100,}={0,2}/

        // Python/shell/YAML/TOML: "# <base64 100+>"
        $b64_hash_comment = /(^|\n)[ \t]*#[ \t]*[A-Za-z0-9+\/]{100,}={0,2}/

        // SQL single-line: "-- <base64 100+>"
        $b64_sql_comment = /(^|\n)[ \t]*--[ \t]*[A-Za-z0-9+\/]{100,}={0,2}/

        // HTML/Markdown comment: "<!-- <base64 100+> -->"
        $b64_html_comment = /<!--[ \t\r\n]*[A-Za-z0-9+\/]{100,}={0,2}/

    condition:
        any of them
}
