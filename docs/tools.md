# Tool reference

narsil-mcp exposes 71 MCP tools. This page says what each one answers, which
group it belongs to, and which ones not to trust.

Tool schemas cost context on **every** request, not once per session: the MCP
protocol is stateless, so the client re-sends the whole tool block with each
turn. The full set is 33,276 bytes (~8.3k tokens). `--expose` selects which
groups ship, so a session that only navigates source does not carry the
security scanner's schemas in its context window all day.

## Choosing groups

```console
$ narsil-mcp --expose code,git            # recommended default
$ narsil-mcp --expose code                # navigation only
$ narsil-mcp --expose code,git,security   # when auditing
$ narsil-mcp --expose code,git,analysis   # when you want metrics and graphs
```

Comma-separated and composable. `base` is always included. An empty `--expose`
falls back to `--preset` (`minimal` / `balanced` / `full` / `security-focused`),
which is the older, coarser knob; the two compose by intersection — a group can
never re-enable what the preset excluded, and vice versa.

Groups can also be set without touching the command line, which matters when
the invocation comes from an editor plugin. First match wins:

| where | example |
|---|---|
| `--expose` flag | `narsil-mcp --expose code,git` |
| `NARSIL_EXPOSE` env | `NARSIL_EXPOSE=code,git` |
| the selected profile | `profiles: { dev: { expose: [code, git] } }` |
| top-level config | `expose: [code, git]` in `config.yaml` |

The last one is the machine-wide default. Note that a stdio instance which
delegates to a running SSE daemon (see `--transport sse`) serves the
**daemon's** tool list — its own `--expose` cannot apply, and it says so in a
warning.

### What `--expose` does and does not do

It filters `tools/list` — what a client is told about — and `tools/call`
refuses anything outside the groups, so the two agree. The refusal names the
group and says not to retry:

```
Tool 'find_dead_stores' is not available on this server: its group 'lint' is
not exposed (this server serves: base, code, git). This is a fixed server
configuration, not a transient failure — do not retry 'find_dead_stores', and
expect every other 'lint' tool to be unavailable too. To enable it, add 'lint'
to --expose or to `expose:` in config.yaml and restart the server.
```

Clients are also told when the set changes. The server advertises
`"tools": {"listChanged": true}`, and after the stdio proxy transparently
reconnects to a restarted daemon it emits
`notifications/tools/list_changed` to the client, which re-reads `tools/list`.

That one path is the only place a client's view can go stale without it
noticing — the tool set is fixed for a process lifetime, so nothing polls or
diffs anything. The notification is a single ~60-byte line per reconnect, and
it is skipped entirely when the request that hit the restart was itself a
`tools/list`, since that reply already carries the new list.

Two limits worth knowing. `--preset` is **not** enforced this way — only
`--expose` is, because exposed groups are a server-wide statement while a
preset can be selected per client during `initialize`. And the HTTP
`/tools/call` route used by the visualization frontend is unaffected; it is a
local UI surface, not an MCP client. So `--expose` is a context-window budget
with a guard rail, not an access-control boundary.

| group | tools | schema bytes | in the recommended default? |
|---|---|---|---|
| `base` | 7 | 2,426 | always |
| `code` | 20 | 11,570 | yes |
| `git` | 9 | 3,205 | yes |
| `analysis` | 7 | 2,949 | no — derived from source you can already read |
| `lint` | 5 | 1,987 | no — the compiler already reports these |
| `security` | 11 | 5,519 | no — enable for an audit |
| `supply-chain` | 4 | 1,933 | no — enable for a dependency review |
| `retrieval` | 8 | 3,694 | no — see caveats |

`--expose code,git` is 36 tools and 17,199 bytes (~4.3k tokens), 52% of the
full block.

The line between `code` and the two opt-in analysis groups is **retrieval
versus restatement**. A tool belongs in `code` when it answers something the
caller cannot work out from source it is already holding — where a symbol
lives, who calls it, what the LSP knows. A tool belongs in `analysis` when its
answer is derivable from code already in view: a complexity number, a listing
of the branches in a function you are reading. Paying schema bytes on every
request to offer the second kind is a bad trade. `lint` is separate again:
"does it compile clean" is a real question, but one your build already answers.

Two tools sit in `code` despite looking like analysis. `get_call_graph` returns
callers, callees and metrics in one round trip instead of two calls, and
`get_reaching_definitions` answers "where did this value come from" across a
function too long to hold in view — both are retrieval in substance.

### `base` — which repos, and is the index fresh

Always exposed. Without these a client cannot name a repository or recover from
a stale index. If a navigation call returns nothing unexpectedly, `reindex` is
the documented first move.

### `code` — what is this code

The bulk of everyday use: symbols, references, search, file text, LSP lookups,
call edges per-symbol and as a graph, def-use chains. Seven of these tools
carry 87% of all recorded traffic.

### `git` — why is it like this

Blame, file and symbol history, commit diffs, branch state, contributors.
Belongs in the default: with git tools absent an agent told to use narsil for
blame finds nothing and falls back to raw `git`, which is what routing it here
was meant to prevent.

### `analysis` — derived from code you can already read

Complexity metrics, connectivity hotspots, import graphs, cycles, and
per-function control and data flow. A model holding the source can work all of
this out unaided, so it is off by default.

Enable it deliberately, and read the caveats first — four of the seven return
wrong answers today: `get_function_hotspots` ranks std method names
(`len`, `is_empty`) as the codebase's most-connected functions,
`find_unused_exports` reports 100% of exports as unused, `get_import_graph`
repeats a row per dependent, and `get_data_flow` takes ~13 s for one function
and emits the false positives described below. `get_complexity` and
`find_circular_imports` are correct.

### `lint` — does it compile clean

**Off by default, and read the caveats before enabling.** Every tool here
duplicates a diagnostic your build already emits:

| tool | already covered by |
|---|---|
| `find_uninitialized` | rustc E0381 (hard error); gcc/clang `-Wuninitialized`, `-Wmaybe-uninitialized` |
| `find_dead_stores` | rustc `unused_assignments`; `-Wunused-but-set-variable`; clang DeadStores |
| `find_dead_code` | rustc `dead_code`; `-Wunreachable-code` |
| `check_type_errors` | mypy / tsc — refuses on anything that is not Python/JS/TS |
| `infer_types` | same language restriction |

All of these fire on an ordinary build of the code being indexed — `dead_code`
and `unused_assignments` are warn-by-default in rustc, `-Wall -Wextra` covers
the C equivalents — and they are produced with type and borrow information
narsil does not have. narsil's own CI runs `cargo clippy --all-targets -D
warnings`, which is stricter still.

### `security` — is it exploitable

Pattern rules, taint tracking, CWE/OWASP passes, and `security_audit` as the
aggregate. Enable for an audit; there is no reason to carry 5.5 KB of scanner
schemas through a refactor.

### `supply-chain` — what does it depend on, and is that safe

SBOM generation, OSV vulnerability lookup, licence compliance, upgrade paths.

### `retrieval` — chunk and embedding internals

Mostly diagnostics for the machinery under `semantic_search` and
`hybrid_search`, plus similarity search. Three known defects; see caveats.

## Tools by group

<!-- BEGIN GENERATED: narsil-mcp tools list --format markdown -->

### `base`

| tool | required args | what it answers |
|---|---|---|
| `discover_repos` | path | Auto-discover repositories in a directory by detecting VCS roots and project markers |
| `get_incremental_status` | — | Get status of incremental indexing including Merkle tree root hash, file counts, and change statistics |
| `get_index_status` | — | Get status of the search index and enabled features |
| `get_metrics` | — | Get performance metrics including tool execution times, indexing statistics, and server uptime |
| `list_repos` | — | List indexed repositories (path, file/line counts) |
| `reindex` | — | Re-index one repository or all of them |
| `validate_repo` | path | Check whether a path is a repository narsil can index, before adding it |

### `code`

| tool | required args | what it answers |
|---|---|---|
| `find_call_path` | from, to | Find the call path between two functions |
| `find_references` | symbol | Every reference to a symbol, unioning LSP hits with text matches |
| `find_symbol_usages` | symbol | Usages of a symbol including its imports and re-exports, cross-language aware for JS/TS |
| `find_symbols` | — | Find structs, classes, enums, interfaces, functions and methods by name pattern or kind |
| `get_call_graph` | — | Callers, callees and complexity for one function in a single call, or the whole repository's graph |
| `get_callees` | function | Find functions called by a given function |
| `get_callers` | function | Find functions that call a given function |
| `get_dependencies` | path | Imports and module dependencies of one source file |
| `get_excerpt` | path, lines | Context around a list of specific line numbers, expanded to function or class boundaries |
| `get_export_map` | path | Get the export map for a file or module showing all exported symbols and their types |
| `get_file` | path | File contents, optionally one contiguous start_line..end_line range |
| `get_hover_info` | path, line, character | Get hover information (type info, documentation) for a symbol at a specific position |
| `get_project_structure` | — | Get the directory structure and key files of a repository |
| `get_reaching_definitions` | path, function | Get reaching definitions analysis - which variable assignments reach each point in the code |
| `get_symbol_definition` | symbol | Get the full definition of a symbol with surrounding context |
| `get_type_info` | path, line, character | Get precise type information for a symbol |
| `go_to_definition` | path, line, character | Find the definition location of a symbol at a specific position |
| `hybrid_search` | query | Fuses keyword ranking with TF-IDF similarity (Reciprocal Rank Fusion) |
| `search_code` | query | Keyword and phrase search across code — the default when you know the terms to look for |
| `semantic_search` | query | Ranked search for a natural-language description of code, using BM25 with code-aware tokenization |

### `git`

| tool | required args | what it answers |
|---|---|---|
| `get_blame` | path | Get git blame information for a file |
| `get_branch_info` | — | Get current branch name and repository status |
| `get_commit_diff` | commit | Get the diff for a specific commit |
| `get_contributors` | — | Get contributors to a file or repository |
| `get_file_history` | path | Get git commit history for a file |
| `get_hotspots` | — | Find code hotspots - files with high churn and complexity |
| `get_modified_files` | — | Get list of modified files in the working tree |
| `get_recent_changes` | — | Get recent commits across the repository |
| `get_symbol_history` | path, symbol | Get commits that modified a specific symbol/function |

### `analysis`

| tool | required args | what it answers |
|---|---|---|
| `find_circular_imports` | — | Detect circular import dependencies in the codebase |
| `find_unused_exports` | — | Detect exported symbols never imported by other files in repo |
| `get_complexity` | function | Get complexity metrics (cyclomatic, cognitive) for a function |
| `get_control_flow` | path, function | Get the control flow graph (CFG) for a function, showing basic blocks, branches, and loops |
| `get_data_flow` | path, function | Get data flow analysis for a function, showing variable definitions and uses |
| `get_function_hotspots` | — | Find highly connected functions (potential refactoring targets) based on call graph analysis |
| `get_import_graph` | — | Build and analyze the import/dependency graph for a codebase |

### `lint`

| tool | required args | what it answers |
|---|---|---|
| `check_type_errors` | path | Find potential type errors in Python/JavaScript/TypeScript code without running mypy/tsc |
| `find_dead_code` | path | Find unreachable code blocks in a function or file using control flow analysis |
| `find_dead_stores` | path | Find variable assignments that are never read (dead stores) |
| `find_uninitialized` | path | Find variables that may be used before being initialized |
| `infer_types` | path, function | Infer types for variables in a Python/JavaScript/TypeScript function |

### `security`

| tool | required args | what it answers |
|---|---|---|
| `check_cwe_top25` | — | Scan for CWE Top 25 Most Dangerous Software Weaknesses including buffer overflows, injection, improper input validation |
| `check_owasp_top10` | — | Scan specifically for OWASP Top 10 2021 vulnerabilities including injection, broken auth, XSS, SSRF, etc |
| `explain_vulnerability` | — | Get detailed explanation of a security vulnerability type including examples, references, and remediation guidance |
| `find_injection_vulnerabilities` | — | Find injection vulnerabilities (SQL injection, XSS, command injection, path traversal) using taint analysis |
| `get_security_summary` | — | Get a comprehensive security summary for a repository including vulnerability counts and risk assessment |
| `get_taint_sources` | — | List all identified taint sources (user inputs, file reads, network data) in the codebase |
| `get_typed_taint_flow` | path, source_line | Enhanced taint analysis with type information |
| `scan_security` | — | Scan repository for security issues using the security rules engine |
| `security_audit` | — | Run every security pass the engine supports (pattern rules, symbolic CWE-122 heap-overflow detection, taint-flow analysis) and return a single ranked report with a summary panel up top |
| `suggest_fix` | path, line | Suggested remediation for one security finding, by file and line |
| `trace_taint` | path, line | Trace how tainted data flows from a source location through the code |

### `supply-chain`

| tool | required args | what it answers |
|---|---|---|
| `check_dependencies` | — | Check project dependencies for known vulnerabilities using the OSV (Open Source Vulnerabilities) database |
| `check_licenses` | — | Analyze dependency licenses for compliance issues |
| `find_upgrade_path` | — | Find safe upgrade paths for vulnerable dependencies |
| `generate_sbom` | — | Generate a Software Bill of Materials (SBOM) for a project |

### `retrieval`

| tool | required args | what it answers |
|---|---|---|
| `find_similar_code` | query | Code resembling a snippet you supply, by TF-IDF vector similarity |
| `find_similar_to_symbol` | symbol | Near-duplicates of a named symbol, by TF-IDF vector similarity |
| `get_chunk_stats` | — | Chunk counts and sizes for a repository — diagnostics for the chunker, not a code query |
| `get_chunks` | path | Inspect how the chunker split one file |
| `get_code_graph` | — | Whole-repo graph data as raw JSON for the visualization frontend |
| `get_embedding_stats` | — | Document count, vocabulary size and dimension of the TF-IDF index behind find_similar_code |
| `search_chunks` | query | Search at chunk granularity, each hit carrying its symbol context |
| `workspace_symbol_search` | query | Typo-tolerant trigram symbol search across every indexed repo — takes no repo argument and is far slower than find_symbols |
<!-- END GENERATED -->

## Paging

Result size is capped per tool. Which argument does the capping is not
consistent, so check before assuming:

| argument | tools |
|---|---|
| `limit` | `find_references`, `find_symbols`, `get_callers`, `get_callees`, `get_contributors`, `workspace_symbol_search` |
| `offset` | `find_references`, `get_callers`, `get_callees`, `get_contributors`, `scan_security` |
| `max_results` | `search_code`, `semantic_search`, `hybrid_search`, `search_chunks`, `find_similar_code`, `find_similar_to_symbol` |

Everything else is capped by defaults it does not let you change. A response
over 48 KB is truncated on a line boundary by the response budget with a notice
naming what was dropped.

## While an index is updating

A branch switch, a `reindex` and the initial index all rebuild a repo's index.
For as long as that lasts, a tool that reads the index answers with JSON-RPC
error **-32001** and a message starting `EAGAIN: index update in progress` —
retry the same request rather than treating the failure as an answer. The
alternative would be a reply mixing both branches, or an empty one, with
nothing to distinguish it from the truth.

The base and git groups are never refused, so `get_index_status`, `list_repos`,
`reindex` and the git tools still work while a rebuild is running. A request
that names no `repo` reads every indexed repo, so one repo mid-update is enough
to refuse it.

## Caveats

Behaviour verified by measurement, not read off the descriptions. Each is
tracked in `../../CLAUDE-narsil-mcp.issues`.

**`find_uninitialized`, `find_dead_stores` — false positives, both C and Rust.**
The dataflow engine does not seed function parameters as definitions and treats
a write that escapes the function (an out-parameter, a value moved into a
struct literal) as never read. On `get_sq_cq_entries` in liburing all six
warnings were wrong. The engine's def-use chains are fine — the seeding and the
escape modelling are not.

**`check_type_errors`, `infer_types` — Python, JavaScript and TypeScript only.**
They return a clear error on other languages, which is the right behaviour, but
means they are permanently inert on a C or Rust tree.

**`find_similar_code`, `find_similar_to_symbol` — only the last-indexed repo
works.** `EmbeddingEngine::finalize()` re-embeds every stored document and then
clears the stored content; since it runs once per repository against a shared
store, each repository's embeddings are zeroed by the next one's indexing pass.
Similarity comes back as `0.000` for every repository except the last, and hits
are ranked from whichever repository still has vectors.

**`find_similar_to_symbol` — silent zero results.** Returns "Found 0 similar
snippets" when the symbol has no signature recorded at index time, which is
indistinguishable from "nothing is similar".

**`find_unused_exports` — unbounded.** 49 KB / 849 lines on a 144-file repo,
with no `limit` or `offset`.

**`get_code_graph` — should not be reachable over MCP.** Its own description
says "HTTP-only tool, not available via MCP"; calling it returns ~714 KB of raw
JSON that only the response budget keeps from flooding the session. The HTTP
`/graph` route is its real caller.

**`get_branch_info` — grows with the branch.** Prints one line per ahead-commit
and per working-tree entry, uncapped: 15 KB on a branch 187 commits ahead.

**`workspace_symbol_search` — slow.** ~3 s against ~10 ms for `find_symbols` on
a comparable query. It buys typo tolerance; pay for it deliberately. It also
takes no `repo` argument, so it is always workspace-wide.

## Tools that exist but are not exposed

Twenty handlers are registered internally and absent from `tools/list`: the CCG
export/import set (`export_ccg`, `export_ccg_architecture`, `export_ccg_full`,
`export_ccg_index`, `export_ccg_manifest`, `import_ccg`,
`import_ccg_from_registry`, `get_ccg_manifest`, `get_ccg_access_info`,
`get_ccg_acl`, `query_ccg`), the SPARQL set (`sparql_query`,
`run_sparql_template`, `list_sparql_templates`), the neural set
(`neural_search`, `find_semantic_clones`, `get_neural_stats`) and the remote
set (`add_remote_repo`, `get_remote_file`, `list_remote_files`). They are
reachable over HTTP or gated behind feature flags. Their execution times still
appear in `get_metrics`.

## Keeping this current

The section between the `BEGIN GENERATED` and `END GENERATED` markers is
produced from the tool registry:

```console
$ narsil-mcp tools list --format markdown > /tmp/tools.md
```

Everything outside the markers is hand-written. CI checks that the generated
block matches the registry, the same way `make autofmt-check` guards
formatting — a tool added to `tool_metadata.rs` without a group assignment
fails the build rather than silently becoming unreachable.
