---
description: Run a comprehensive security audit on an indexed repository
---

# Security Scan

Run a comprehensive security audit on the repository specified by the user. If no repository is specified, first use `list_repos` to show available repositories and ask which one to scan.

## Heuristic findings — verify before reporting

Most rules in narsil's output (CWE-787-001, CWE-119-001,
CWE-125-001, CWE-89-001, ...) are regex token matches: they identify
*call sites of dangerous patterns*, not verified vulnerabilities. A
smaller set (e.g. CWE-476-002) are analytically verified via
tree-sitter dataflow; the rule ID and message indicate which is
which.

**For every heuristic finding in security-sensitive code** —
setuid/setgid binaries, parsers of untrusted input, IPC handlers,
network protocols, anything with attacker-controllable input — you
MUST perform the verification yourself in this pass:

1. Locate the destination buffer's allocation site (may be
   cross-file). Use `get_callers`, `find_call_path`, and
   `go_to_definition`.
2. Compare the allocated size to the actual write width.
   Format-string expansion counts: `sprintf(buf, "%s#%s", a, b)`
   writes `strlen(a) + 1 + strlen(b) + 1` bytes, not
   `strlen(a) + 1`.
3. State explicitly which size each side resolves to.

**An audit is not complete until step 3 has been done for every
heuristic finding in privileged code.** Phrases like "manual pass
needed", "the scanner could not do", "warrants verification",
"focused review", "separate pass", "follow-up audit", or any
equivalent rephrasing are signals of incomplete work — they belong
in narsil bug reports, not in audit output to the user. The audit
IS the review.

If you cannot complete the verification (tool limits, time,
complexity), mark the audit **INCOMPLETE** and explain why. Do not
produce a final priority list with deferred items.

Heuristic findings in clearly non-privileged code (examples, unit
tests, fixtures) may be dismissed at scale.

## Workflow

Execute the following steps:

1. **Get security overview**: Use `get_security_summary` to get an overview of the security posture

2. **Scan for vulnerabilities**: Use `scan_security` with `severity_threshold="medium"` to find medium and above findings

3. **Check OWASP Top 10**: Use `check_owasp_top10` to check for web application vulnerabilities

4. **Check dependencies**: Use `check_dependencies` to find known CVEs in dependencies

5. **Check licenses**: Use `check_licenses` to identify license compliance issues

6. **Verify heuristic findings in privileged code**: For each
   heuristic finding in security-sensitive code (setuid binaries,
   parsers of untrusted input, IPC handlers, network protocols),
   perform the verification checklist from the "Heuristic findings
   — verify before reporting" section above. Do not proceed to
   step 7 until verification is complete for every privileged-code
   heuristic finding, or until the audit has been marked INCOMPLETE.

7. **Summarize findings**: Present a summary organized by:
   - Critical/High severity findings (immediate attention needed)
   - Medium severity findings (should address soon)
   - Dependency vulnerabilities with available fixes
   - License issues

8. **For each critical finding**: Use `explain_vulnerability` to
   provide context and `suggest_fix` to show remediation

## Arguments

If $ARGUMENTS is provided, use it as the repository name. Otherwise, list available repositories first.

Repository to scan: $ARGUMENTS
