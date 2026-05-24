---
description: Run the full multi-pass security audit on an indexed repository using the security_audit aggregator tool
---

# Security Audit

Run a single-call, multi-pass security audit on the repository specified
by the user. Prefer `security_audit` over chaining `scan_security`,
`check_owasp_top10`, `check_cwe_top25`, and `trace_taint` by hand —
`security_audit` runs them all and deduplicates the result.

If no repository is specified, first use `list_repos` to show available
repositories and ask which one to audit.

## When to use `security_audit` vs. the individual tools

| Question | Tool |
|----------|------|
| "Is this codebase healthy?" — one call | `security_audit` |
| "Show every pattern-rule finding above severity X" | `scan_security` |
| "OWASP Top 10 only" | `check_owasp_top10` |
| "CWE Top 25 only" | `check_cwe_top25` |
| "Where does this specific source flow?" | `trace_taint` from a known line |
| "List user-input sources in this file" | `get_taint_sources` |
| "Explain a single finding's CWE" | `explain_vulnerability` |
| "Suggest a fix for a finding" | `suggest_fix` |

`security_audit` already includes:

- Pattern rules (CWE Top 25 + OWASP Top 10 + any custom ruleset YAML)
- Symbolic heap-overflow detection (CWE-122) for C and C++
- Taint-flow analysis with unsanitised source-to-sink flows folded into
  the unified findings list

Reach for the individual tools when you need a *narrower* answer than
the audit gives you, or when you want to drill into one specific
finding after the audit pointed at it.

## Workflow

1. **Run the audit**: call `security_audit` with optional
   `severity_threshold` (default: low) and `exclude_tests` (default:
   true). For a quick first pass use
   `severity_threshold="medium"` to focus on actionable findings.

2. **Triage the summary panel**: the audit output starts with an
   "At a Glance" section sourced from `get_security_summary`. Use it
   to decide whether the codebase needs deep attention or a light
   review.

3. **For each Critical/High finding**: call
   `explain_vulnerability` to surface the CWE context and
   `suggest_fix` for a concrete remediation snippet.

4. **For tainted flows (TAINT-* rule ids)**: the finding already
   names the sink; if you want the full source-to-sink path, call
   `trace_taint` with the file path and the sink line.

5. **For CWE-122-001 heap-overflow findings**: the audit message
   spells out the symbolic write-vs-allocation comparison. The fix is
   almost always to widen the allocation, not narrow the write.

6. **Supply-chain follow-ups**: the audit covers *code* paths only.
   For dependency CVEs and license issues, run `check_dependencies`
   and `check_licenses` separately — these intentionally live outside
   the code-scan aggregator since they require a different network
   posture.

## Arguments

If `$ARGUMENTS` is provided, use it as the repository name. Otherwise,
list available repositories first.

Repository to audit: $ARGUMENTS
