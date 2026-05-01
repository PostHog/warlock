// Catches the classic "ignore everything above and do X instead" shape
// — the most common prompt injection attack. Fires on an override verb
// (ignore/disregard/forget/override/skip/bypass/stop following) paired
// with an instruction-y noun (instructions/prompts/rules/directives/
// system prompt). The instruction-y noun is what makes this fire —
// verb alone matches too much code. "ignore the cache" stays quiet;
// "ignore the instructions" fires.
//
// English-only by design. Multilingual prompt injection is a separate rule
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

        // Passive voice: "(prior|previous|above) instructions should be
        // ignored / must be ignored / are to be ignored"
        $override_passive = /\b(the\s+)?(all\s+)?(previous|prior|above|earlier|initial|original|any|every)\s+(instructions?|prompts?|rules?|directives?|commands?|guidelines?|system\s+prompt)\s+(should\s+be|must\s+be|have\s+to\s+be|are\s+to\s+be|need\s+to\s+be|be)\s+(ignored|disregarded|forgotten|overridden|bypassed|skipped)\b/i

        // Bare-noun + spatial qualifier coming after the noun:
        // "ignore instructions above" (qualifier follows noun, not before)
        $override_noun_then_qualifier = /\b(ignore|disregard|forget|override|skip|bypass)\s+(the\s+)?(instructions?|prompts?|rules?|directives?|commands?|guidelines?)\s+(above|below|earlier|previously|before|prior)\b/i

        // Synonym verbs: "stop following" / "don't follow" / "do not follow"
        // / "cease following" + (optional qualifier) + instruction noun
        $override_stop_following = /\b(stop\s+following|cease\s+following|(don'?t|do\s+not)\s+follow|cease\s+to\s+follow)\s+(the\s+)?(all\s+)?(previous|prior|above|earlier|initial|original|any|every)?\s*(instructions?|prompts?|rules?|directives?|commands?|guidelines?|system\s+prompt)\b/i

        // Synonym nouns: "ignore your training / role / guidelines"
        // — verb + "your" + persona-side noun (no qualifier needed,
        // "your" itself is the determiner)
        $override_your_noun = /\b(ignore|disregard|forget|override|skip|bypass)\s+your\s+(instructions?|prompts?|rules?|directives?|commands?|guidelines?|training|role|system\s+prompt)\b/i

        // "ignore / disregard / forget everything above" and similar
        $override_everything = /\b(ignore|disregard|forget)\s+everything\s+(above|before|prior|you\s+(were|have\s+been)\s+told)/i

        // "ignore what you were told / said / instructed"
        $override_what_told = /\b(ignore|disregard|forget)\s+what\s+(you\s+were\s+|you\s+have\s+been\s+|the\s+user\s+)?(told|said|instructed|asked)/i

        // "start over" / "reset" style resets targeting instructions
        $override_reset = /\b(start\s+over|reset|clear)\s+(your\s+)?(instructions|context|memory|system\s+prompt)/i

    condition:
        any of them
}
