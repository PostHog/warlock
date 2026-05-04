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
        // rm with recursive + force flags. The flag alternation covers:
        //   -[…r…f]  combined flags, r/R before f (rm -rf, rm -rvf, …)
        //   -[…f…r]  combined flags, f before r/R    (rm -fr, rm -fR, …)
        //   -r -f    separate flags, either order
        //   --recursive --force   long-form flags, either order
        $rm_recursive = /\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)\b/

        // find <path> -delete  (up to 200 chars between find and -delete
        // to stay on the same logical command)
        $find_delete = /\bfind\s+[^\n]{0,200}-delete\b/

        // find <path> -exec rm -rf  (same flag alternation as above,
        // minus the separate-flag and long-form variants which are rare
        // inside -exec)
        $find_exec_rm = /\bfind\s+[^\n]{0,200}-exec\s+rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[rR]\s+-f|--recursive\s+--force)/

    condition:
        any of them
}
