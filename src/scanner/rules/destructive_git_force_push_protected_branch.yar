// Fires on force pushes aimed at a branch name most teams protect
// (main, master, develop, release, staging, production, qa, uat) and
// on repo-wide destructive pushes (--mirror, --prune) which delete
// remote refs regardless of target. The companion rule
// destructive_git_force_push fires on everyday force pushes to other
// branches and is severity medium + warn; this one is critical +
// block because rewriting shared history on a protected branch
// typically destroys other people's work.

rule destructive_git_force_push_protected_branch
{
    meta:
        description = "A git force push aimed at a protected branch (main, master, develop, release, staging, production, qa, uat) or a repo-wide destructive push (--mirror, --prune)."
        remediation = "Refuse to run the push. Force-pushing a protected branch rewrites shared history — confirm with the branch owners that the rewrite is intentional before proceeding."
        severity = "critical"
        category = "destructive_operations"
        action = "block"

    strings:
        // git push --force <remote> <protected-branch>
        $force_long_protected = /\bgit\s+push\s+[^\n]{0,100}--force\b[^\n]{0,100}\b(main|master|develop|development|release|staging|stage|production|prod|qa|uat)\b/

        // git push -f <remote> <protected-branch>
        $force_short_protected = /\bgit\s+push\s+(-f|-[a-zA-Z]*f[a-zA-Z]*)\s+[^\n]{0,100}\b(main|master|develop|development|release|staging|stage|production|prod|qa|uat)\b/

        // git push --delete <remote> <protected-branch>
        $delete_flag_protected = /\bgit\s+push\s+[^\n]{0,100}--delete\s+[^\n]{0,100}\b(main|master|develop|development|release|staging|stage|production|prod|qa|uat)\b/

        // git push <remote> :<protected-branch> (older deletion syntax)
        $colon_delete_protected = /\bgit\s+push\s+[A-Za-z0-9_-]+\s+:\s*(main|master|develop|development|release|staging|stage|production|prod|qa|uat)\b/

        // git push --mirror — mirrors full repo, deletes remote refs not present locally
        $mirror = /\bgit\s+push\s+[^\n]{0,100}--mirror\b/

        // git push --prune — deletes remote refs not present in the source
        $prune = /\bgit\s+push\s+[^\n]{0,100}--prune\b/

    condition:
        any of them
}
