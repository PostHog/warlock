// Catches recursive deletions aimed at dangerous targets (root, home,
// system paths, bare wildcards, unquoted shell variables) or run under
// sudo. Critical + block because a typo or unset variable here can
// wipe the machine. See destructive_recursive_delete for the everyday
// cleanup companion; if both fire, surface this one.

rule destructive_recursive_delete_high_risk
{
    meta:
        description = "A recursive file deletion aimed at a dangerous target (root, home, a system path, a bare wildcard, an unquoted variable, or anything run under sudo)."
        remediation = "Refuse to run the command. Confirm the operator actually meant to delete that target — a typo or an unset variable here wipes the machine."
        severity = "critical"
        category = "destructive_operations"
        action = "block"

    strings:
        // rm -rf (and -fr / -Rf / -fR / etc) aimed at root, home, bare
        // wildcard, bare dot / dotdot, or a canonical system path
        $rm_recursive_dangerous = /\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)\s+("\/"|'\/'|\/($|\s|\*)|~($|\/|\s)|\.($|\s)|\.\.($|\s)|\*($|\s)|\/(etc|bin|sbin|usr|var|home|Users|sys|boot|lib|opt|root)(\/|\s|$))/

        // rm recursive aimed at an unquoted shell variable — one unset
        // variable turns this into rm -rf /
        $rm_recursive_unquoted_var = /\brm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)\s+\$[A-Za-z_{]/

        // sudo + any recursive rm (target doesn't matter, sudo escalates the blast radius)
        $sudo_rm_recursive = /\bsudo\s+rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*[rR]|-[rR]\s+-f|-f\s+-[rR]|--recursive\s+--force|--force\s+--recursive)\b/

        // find -delete aimed at a dangerous root
        $find_delete_dangerous = /\bfind\s+("\/"|'\/'|\/($|\s|\*)|~($|\/|\s)|\.($|\s)|\.\.($|\s)|\*($|\s)|\/(etc|bin|sbin|usr|var|home|Users|sys|boot|lib|opt|root)(\/|\s|$))[^\n]{0,200}-delete\b/

        // find -exec rm -rf aimed at a dangerous root
        $find_exec_rm_dangerous = /\bfind\s+("\/"|'\/'|\/($|\s|\*)|~($|\/|\s)|\.($|\s)|\.\.($|\s)|\*($|\s)|\/(etc|bin|sbin|usr|var|home|Users|sys|boot|lib|opt|root)(\/|\s|$))[^\n]{0,200}-exec\s+rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[rR]\s+-f|--recursive\s+--force)/

        // sudo + find -delete / find -exec rm (blast radius again)
        $sudo_find_delete = /\bsudo\s+find\b[^\n]{0,200}(-delete|-exec\s+rm\s+(-[a-zA-Z]*[rR][a-zA-Z]*f|-[rR]\s+-f))/

    condition:
        any of them
}
