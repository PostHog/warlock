// Catches the classic "ignore everything above and do X instead" shape
// — the most common prompt injection attack. Fires on an override verb
// (ignore/disregard/forget/override/skip/bypass) paired with an
// instruction-y noun (instructions/prompts/rules/directives/system
// prompt). Verb alone is too common: "ignore previous errors" stays
// quiet; "ignore previous instructions" fires.
//
// Note: this rule (and all prompt_injection_* rules) matches on content
// that describes the attack — own docs, tests, rule files. Consumers
// handle scope exclusions for their own repo content.

rule prompt_injection_instruction_override
{
    meta:
        description = "An attempt to make the model ignore, disregard, forget, or override its prior instructions."
        remediation = "Refuse to process the content. Don't pass it through to the model — treat it as hostile input."
        severity = "critical"
        category = "prompt_injection"
        action = "block"

    strings:
        // "ignore / disregard / forget / override / skip / bypass [the]
        //  [all] (previous|prior|above|earlier|initial|original|any|every)
        //  (instructions|prompts|rules|directives|commands|guidelines|
        //   system prompt)"
        $override_noun = /\b(ignore|disregard|forget|override|skip|bypass)\s+(the\s+)?(all\s+)?(previous|prior|above|earlier|initial|original|any|every)\s+(instructions?|prompts?|rules?|directives?|commands?|guidelines?|system\s+prompt)\b/i

        // "ignore / disregard / forget everything above" and similar
        $override_everything = /\b(ignore|disregard|forget)\s+everything\s+(above|before|prior|you\s+(were|have\s+been)\s+told)/i

        // "ignore what you were told / said / instructed"
        $override_what_told = /\b(ignore|disregard|forget)\s+what\s+(you\s+were\s+|you\s+have\s+been\s+|the\s+user\s+)?(told|said|instructed|asked)/i

        // "start over" / "reset" style resets targeting instructions
        $override_reset = /\b(start\s+over|reset|clear)\s+(your\s+)?(instructions|context|memory|system\s+prompt)/i

    condition:
        any of them
}
