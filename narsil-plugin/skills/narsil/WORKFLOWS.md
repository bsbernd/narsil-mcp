# Narsil Workflows

Detailed workflow examples for common code intelligence tasks.

## Codebase Exploration

### First Contact with Unknown Codebase

Goal: Understand structure and main components.

```
1. list_repos
   → Get repository name(s)

2. get_project_structure(repo, max_depth=3)
   → See top-level directory structure

3. find_symbols(repo, symbol_type="class", file_pattern="src/**/*")
   → Find main data structures

4. find_symbols(repo, symbol_type="function", pattern="*main*")
   → Find entry points

```

> Note: `explain_codebase` is registered as an MCP **prompt**, not a tool. It can't be called from a tool-calling workflow — surface it through the client's prompt UI (or via the `/narsil:explore` slash command, which captures the same intent through the steps above).

### Finding Where a Feature Lives

Goal: Locate implementation of a specific feature.

```
1. hybrid_search(query="feature description in natural language")
   → Semantic search for relevant code (BM25 + TF-IDF, Reciprocal Rank Fusion)

2. find_symbols(repo, pattern="*FeatureName*")
   → Find related symbols

3. For each candidate:
   find_symbol_usages(repo, symbol)
   → Confirm it's widely used

4. get_symbol_definition(repo, symbol)
   → Read the implementation
```

> Note: `find_implementation` is registered as an MCP **prompt**, not a tool. The slash command `/narsil:find-feature` runs the equivalent tool sequence above.

## Call Graph Analysis

### Understanding Function Impact

Goal: Assess impact of changing a function.

```
1. get_callers(repo, function, transitive=true, max_depth=5)
   → All functions that depend on this one

2. get_callees(repo, function, transitive=true)
   → All functions this one depends on

3. get_complexity(repo, function)
   → Cyclomatic and cognitive complexity

4. get_function_hotspots(repo, min_connections=10)
   → Identify highly connected functions
```

### Tracing Execution Path

Goal: Understand how data flows from A to B.

```
1. find_call_path(repo, from="entry_function", to="target_function")
   → Path between two functions

2. For each function in path:
   get_control_flow(repo, path, function)
   → See branches and loops

3. get_data_flow(repo, path, function)
   → Track variable definitions and uses
```

### Symbol Reference Tracking

Goal: Understand how a symbol is used across the codebase.

```
1. find_references(repo, symbol)
   → All references to the symbol

2. find_symbol_usages(repo, symbol, include_imports=true)
   → Cross-file usages including imports

3. get_export_map(repo, path)
   → See what the module exports

4. get_dependencies(repo, path, direction="imported_by")
   → Find files that depend on this module
```

## Static Analysis Workflows

### Control Flow Analysis

Goal: Understand function logic flow.

```
1. get_control_flow(repo, path, function)
   → Basic blocks, branches, loops

2. get_reaching_definitions(repo, path, function)
   → Which assignments reach each point
```

## Git History Analysis

Requires `--git` flag.

### Understanding Code Evolution

Goal: Track how code changed over time.

```
1. get_file_history(repo, path, max_commits=20)
   → Recent changes to file

2. get_symbol_history(repo, path, symbol, max_commits=10)
   → Commits that touched specific function

3. get_blame(repo, path, start_line=X, end_line=Y)
   → Who wrote each line

4. get_commit_diff(repo, commit)
   → See exact changes in a commit
```

### Finding Code Hotspots

Goal: Identify high-churn areas needing attention.

```
1. get_hotspots(repo, days=30, min_complexity=10)
   → Files with high churn + complexity

2. get_contributors(repo, path)
   → Who knows this code best

3. get_recent_changes(repo, days=7)
   → Recent activity in repo
```

### Pre-Commit Analysis

Goal: Check changes before committing.

```
1. get_modified_files(repo)
   → See uncommitted changes

2. get_branch_info(repo)
   → Current branch and status
```

## Search Strategy

### When to Use Each Search Tool

| Scenario | Tool | Why |
|----------|------|-----|
| Know exact function name | `find_symbols` | Direct lookup |
| Know partial name | `find_symbols` with a glob pattern | Wildcard matching |
| Searching for concept | `hybrid_search` | Semantic understanding |
| Looking for text | `search_code` | Keyword search |

### Narrowing Large Result Sets

```
1. Start broad:
   search_code(query="authentication", max_results=50)

2. Filter by file type:
   search_code(query="authentication", file_pattern="*.py")

3. Focus on specific directory:
   search_code(query="authentication", repo="myrepo", file_pattern="src/auth/**/*")
```

## Performance Tips

1. **Use `file_pattern`** - Always filter when you know the file types
2. **Use `max_results`** - Don't fetch more than you need
3. **Batch related queries** - Call multiple tools in parallel when independent
4. **Check feature status first** - Use `get_index_status` to avoid wasted calls
5. **Use excerpts over full files** - `get_excerpt` is faster than `get_file` for specific lines
