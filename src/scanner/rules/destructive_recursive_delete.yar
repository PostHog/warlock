// Fires on any recursive deletion — rm -rf / -fr / -Rf, the long
// form --recursive --force, find -delete, and find -exec rm. Medium
// severity + warn action because legitimate cleanup (rm -rf
// node_modules, rm -rf build/) is a daily occurrence; consumers
// allow-list the everyday patterns and keep visibility on the rest.
//
// The companion rule destructive_recursive_delete_high_risk fires in
// addition to this one when the target is dangerous (root, home,
// system paths, unquoted variables) or the command is run under sudo.
// Consumers seeing both matches on the same input should prefer the
// high-risk severity.

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
