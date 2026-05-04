// Catches git commands that throw away local, uncommitted work:
// reset --hard, clean -fd, restore / checkout on ".", stash
// drop/clear, and the reflog-wiping variant that blocks recovery.
// High severity but not critical because the damage is local-only and
// often reflog-recoverable — but a developer who runs one of these
// without meaning to just lost work, and an agent that runs one
// without asking almost certainly made a mistake.

rule destructive_git_working_tree_loss
{
    meta:
        description = "A git command that throws away local working-tree or stash state (reset --hard, clean -fd, restore/checkout on '.', stash drop/clear, or reflog expire)."
        remediation = "Refuse to run the command. Confirm the operator wants to lose the uncommitted changes — if not, stash or commit them first."
        severity = "high"
        category = "destructive_operations"
        action = "block"

    strings:
        // git reset --hard (with or without a target)
        $reset_hard = /\bgit\s+reset\s+[^\n]{0,100}--hard\b/

        // git clean -fd / -xfd / -dfx / -f -d (deletes untracked files)
        $clean_fd = /\bgit\s+clean\s+(-[a-zA-Z]*[fd][a-zA-Z]*[fd][a-zA-Z]*|-f\s+-d|-d\s+-f|--force\s+-d|-d\s+--force|--force\s+--[a-z]+)/

        // git restore . (discards all uncommitted tracked changes)
        $restore_dot = /\bgit\s+restore\s+[^\n]{0,100}(\.\s|\.$|--\s+\.)/

        // git checkout . (same effect in older git syntax)
        $checkout_dot = /\bgit\s+checkout\s+[^\n]{0,100}(\.\s|\.$|--\s+\.)/

        // git stash drop / git stash clear
        $stash_destroy = /\bgit\s+stash\s+(drop|clear)\b/

        // git reflog expire --expire=now --all (blocks reflog recovery)
        $reflog_wipe = /\bgit\s+reflog\s+expire\s+[^\n]{0,100}--expire=now[^\n]{0,100}--all\b/

    condition:
        any of them
}
