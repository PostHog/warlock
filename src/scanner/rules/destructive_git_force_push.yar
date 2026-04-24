// Fires on any git force push or remote-ref deletion regardless of
// branch name. Covers --force, -f, --force-with-lease, --delete, and
// the older "git push remote :branch" deletion syntax. Medium + warn
// because force-pushing a short-lived feature branch is routine; the
// companion rule destructive_git_force_push_protected_branch covers
// the critical case where the target is a protected branch.
//
// --force-with-lease lives here (not in the protected-branch rule)
// because it's designed to be the safer alternative — it aborts if
// the remote has commits the local ref doesn't know about.

rule destructive_git_force_push
{
    meta:
        description = "A git force push or remote-branch deletion. Legitimate on feature branches but worth surfacing so the operator can confirm the branch is safe to rewrite."
        remediation = "Confirm the branch isn't shared with other collaborators before force-pushing. If this is a routine feature-branch flow, allow-list the pattern in the consumer."
        severity = "medium"
        category = "destructive_operations"
        action = "warn"

    strings:
        // git push --force (long flag)
        $force_long = /\bgit\s+push\s+[^\n]{0,100}--force\b/

        // git push -f / -fu / -uf etc (short flag, alone or bundled)
        $force_short = /\bgit\s+push\s+(-f|-[a-zA-Z]*f[a-zA-Z]*)\s/

        // git push --force-with-lease (safer variant, still worth surfacing)
        $force_with_lease = /\bgit\s+push\s+[^\n]{0,100}--force-with-lease\b/

        // git push --delete <remote> <branch>
        $delete_flag = /\bgit\s+push\s+[^\n]{0,100}--delete\s+[A-Za-z0-9_-]+\s+[A-Za-z0-9_\/-]+/

        // git push <remote> :<branch> (older deletion syntax)
        $colon_delete = /\bgit\s+push\s+[A-Za-z0-9_-]+\s+:\s*[A-Za-z0-9_\/-]+/

    condition:
        any of them
}
