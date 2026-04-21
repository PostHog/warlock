// TODO: remove once real rules exist

rule scaffold_canary
{
    meta:
        description = "Scaffold verification rule. Matches a distinct canary string only used to confirm the engine is wired up."
        severity = "low"

    strings:
        $canary = "WARLOCK_SCAFFOLD_CANARY"

    condition:
        $canary
}
