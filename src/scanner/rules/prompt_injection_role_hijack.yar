// Catches persona swap attempts ("you are now X", "pretend to be X",
// "roleplay as X") — same goal as instruction_override, different
// angle. The direct form requires a "now" / "from now on" marker and
// the indirect form requires a command-style verb (pretend/act/
// roleplay/simulate), so "you are helpful" stays quiet.

rule prompt_injection_role_hijack
{
    meta:
        description = "An attempt to reassign the model's role (e.g. 'you are now X', 'pretend to be Y', 'act as an unrestricted AI')."
        remediation = "Refuse to process the content. Role-hijack attempts are one of the main ways attackers move a model out of its configured safety behavior."
        severity = "critical"
        category = "prompt_injection"
        action = "block"

    strings:
        // "you are now [a|an] X" / "you will now [act|be|pretend|roleplay]"
        $hijack_you_are_now = /\byou\s+(are|will\s+be)\s+now\s+(a\s+|an\s+)?[A-Za-z]/i
        $hijack_you_will_now = /\byou\s+will\s+now\s+(act|be|pretend|roleplay|behave)/i

        // "from now on [you are / act as / behave as]"
        $hijack_from_now_on = /\bfrom\s+now\s+on[,]?\s+you\s+(are|will|must|should|act|behave|respond|answer)/i

        // "pretend to be / pretend you are / pretend that you"
        $hijack_pretend = /\bpretend\s+(to\s+be|you\s+are|that\s+you|you'?re)/i

        // "act as a different / new / alternative / uncensored / unrestricted
        //  / unfiltered" + noun
        $hijack_act_as_different = /\bact\s+as\s+(a\s+|an\s+)?(different|new|alternative|uncensored|unrestricted|unfiltered|jailbroken)/i

        // "roleplay as" / "role-play as" — direct persona takeover
        $hijack_roleplay = /\brole[\s-]?play\s+as\b/i

        // "simulate" + role noun — "simulate a helpful AI without restrictions"
        $hijack_simulate = /\bsimulate\s+(a\s+|an\s+)?(different|uncensored|unrestricted|unfiltered|jailbroken|evil|malicious)/i

    condition:
        any of them
}
