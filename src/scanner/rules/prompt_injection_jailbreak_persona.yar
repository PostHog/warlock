// Catches named jailbreak personas (DAN, STAN, DUDE, AIM, BetterDAN)
// and generic modes (developer mode, god mode, jailbreak mode). Short
// names are too short on their own — "Dan Brown writes novels"
// shouldn't fire — so they only match when paired with an activation
// verb ("enable DAN") or a persona noun ("DAN mode"). Generic modes
// need an on/enabled/active word after them so "the IDE has a developer
// mode toggle" stays quiet.

rule prompt_injection_jailbreak_persona
{
    meta:
        description = "Use of a well-known jailbreak persona or mode (DAN, STAN, DUDE, AIM, developer mode, god mode, jailbreak mode)."
        remediation = "Refuse to process the content. These personas exist specifically to move the model out of its safety rules and should be treated as hostile input."
        severity = "critical"
        category = "prompt_injection"
        action = "block"
        scan_context = "input"

    strings:
        // Activation: "enable/activate/enter/switch to/turn on" + persona
        $persona_activation = /\b(enable|activate|enter|switch\s+to|turn\s+on|engage)\s+(the\s+)?(DAN|STAN|DUDE|AIM|BetterDAN|developer\s+mode|god\s+mode|jailbreak\s+mode|dev\s+mode|admin\s+mode)\b/i

        // Persona + role noun: "DAN mode", "DAN persona", "DAN character"
        $persona_as_noun = /\b(DAN|STAN|DUDE|AIM|BetterDAN)\s+(mode|persona|character|jailbreak|prompt)/

        // "Do Anything Now" — long form of DAN, less likely to false-match
        $persona_do_anything_now = /\bDo\s+Anything\s+Now\b/i

        // "developer mode on/enabled/active" — common jailbreak framing
        $persona_developer_mode = /\bdeveloper\s+mode\s+(on|enabled|active|activated|is\s+on|is\s+enabled)\b/i

        // "god mode on/enabled/active"
        $persona_god_mode = /\bgod\s+mode\s+(on|enabled|active|activated|is\s+on|is\s+enabled)\b/i

        // "jailbreak mode" / "jailbroken mode" in any active-voice phrasing
        $persona_jailbreak_mode = /\b(jailbreak|jailbroken)\s+mode\b/i

        // "unrestricted / uncensored / unfiltered AI" — generic jailbreak
        // personas without a named acronym
        $persona_generic_unrestricted = /\b(unrestricted|uncensored|unfiltered|no[\s-]restrictions)\s+(AI|assistant|model|mode|version|chatbot)\b/i

    condition:
        any of them
}
