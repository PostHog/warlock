// Fires on any recursive deletion – rm -rf and variants, find -delete,
// find -exec rm. Medium + warn because legitimate cleanup (rm -rf
// node_modules, build/) is routine; consumers allow-list the everyday
// patterns. See destructive_recursive_delete_high_risk for the
// dangerous-target and sudo cases – when both fire, surface that one.

rule destructive_recursive_delete
{
    meta:
        description = "A recursive file deletion (rm -rf, find -delete, or find -exec rm). Legitimate in many contexts but worth surfacing so the operator can confirm the target is correct."
        remediation = "Confirm the target path is what you meant to delete. If the deletion is part of a known cleanup flow (build output, node_modules, caches), allow-list that pattern in the consumer."
        severity = "medium"
        category = "destructive_operations"
        action = "warn"

    strings:
        // rm -rf / -fr / -Rf / -fR / -r -f / -f -r / --recursive --force / --force --recursive
        $rm_recursive = /\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)\b/

        // find ... -delete
        $find_delete = /\bfind\s+[^\n]{0,200}-delete\b/

        // find ... -exec rm -rf (or -fr / -Rf)
        $find_exec_rm = /\bfind\s+[^\n]{0,200}-exec\s+rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[rR]\s+-f|--recursive\s+--force)/

    condition:
        any of them
}
