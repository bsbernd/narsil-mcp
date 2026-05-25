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
- Symbolic heap-overflow detection (CWE-122) for C and C++, including
  cross-translation-unit resolution: allocator helpers defined in one
  `.c` file are followed via the project call graph to writes in
  another, so under-sized buffers passed across TU boundaries are
  caught (not only intra-file shapes)
- Partial integer-overflow-to-buffer detection (CWE-680) for C and C++
- Taint-flow analysis with unsanitised source-to-sink flows folded into
  the unified findings list

## Partial-coverage rules — important caveats

Some rules in the audit are partial by design. The rule's `message`
field always carries the caveat verbatim, but it is worth surfacing
the limitations up front when you summarise the output to a user:

- **CWE-680-001** (literal-constant wraparound): fires only when an
  allocator's size arithmetic uses literal operands that provably
  wrap u64. Cannot reason about non-literal operands. A clean scan
  does **not** prove the file is free of CWE-680.
- **CWE-680-002** (variable × sizeof(T)): fires on the structural
  exploit shape but has no value-range analysis and does not follow
  helper calls. May miss bugs where bounds checking happens in a
  caller or via a wrapper; may false-flag safe code whose bounds
  check happens elsewhere.
- **CWE-122-001** (heap overflow): the audit path follows allocator
  helpers across translation units via the project call graph. The
  per-file `scan_security`/`check_cwe_top25` path does **not** —
  those callers are intentionally per-TU so single-file scans stay
  predictable. If a user runs a single-file scan and gets nothing,
  re-run via `security_audit` for the full picture.

When you report a clean CWE-680 result to a user, say so explicitly:
"no CWE-680 findings — but the rule is partial; a separate audit is
warranted for high-risk allocator code paths."

Reach for the individual tools when you need a *narrower* answer than
the audit gives you, or when you want to drill into one specific
finding after the audit pointed at it.

## Heuristic findings — verify before reporting

Most rules in narsil's output (CWE-787-001, CWE-119-001,
CWE-125-001, CWE-89-001, ...) are regex token matches: they identify
*call sites of dangerous patterns*, not verified vulnerabilities. A
smaller set (e.g. CWE-476-002, CWE-122-001) are analytically
verified via tree-sitter dataflow; the rule ID and message indicate
which is which.

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

1. **Run the audit**: call `security_audit` with optional
   `severity_threshold` (default: low) and `exclude_tests` (default:
   true). For a quick first pass use
   `severity_threshold="medium"` to focus on actionable findings.

2. **Triage the summary panel**: the audit output starts with an
   "At a Glance" section sourced from `get_security_summary`. Use it
   to decide whether the codebase needs deep attention or a light
   review.

3. **Verify heuristic findings in privileged code**: for each
   heuristic finding in security-sensitive code (setuid binaries,
   parsers of untrusted input, IPC handlers, network protocols),
   perform the verification checklist from the "Heuristic findings —
   verify before reporting" section above. Do not proceed to step 4
   until verification is complete for every privileged-code heuristic
   finding, or until the audit has been marked INCOMPLETE.

4. **For each Critical/High finding**: call
   `explain_vulnerability` to surface the CWE context and
   `suggest_fix` for a concrete remediation snippet.

5. **For tainted flows (TAINT-* rule ids)**: the finding already
   names the sink; if you want the full source-to-sink path, call
   `trace_taint` with the file path and the sink line.

6. **For CWE-122-001 heap-overflow findings**: the audit message
   spells out the symbolic write-vs-allocation comparison and notes
   whether cross-translation-unit resolution was available (it is,
   through the audit path; single-file callers see only per-TU
   shapes). The fix is almost always to widen the allocation, not
   narrow the write.

7. **Supply-chain follow-ups**: the audit covers *code* paths only.
   For dependency CVEs and license issues, run `check_dependencies`
   and `check_licenses` separately — these intentionally live outside
   the code-scan aggregator since they require a different network
   posture.

## Arguments

If `$ARGUMENTS` is provided, use it as the repository name. Otherwise,
list available repositories first.

Repository to audit: $ARGUMENTS
