---
description: Deep dive analysis of a specific function including callers, callees, complexity, and data flow
---

# Analyze Function

Perform a deep analysis of a specific function to understand its role, complexity, and impact.

## Prerequisites

This command requires the `--call-graph` flag to be enabled when starting narsil-mcp. Check `get_index_status` to verify.

## Workflow

The user should provide a function name. Parse $ARGUMENTS to extract:
- Repository name (if provided)
- Function name (required)

1. **Find the function**: Use `find_symbols` to locate the function if the exact location is unknown

2. **Get the source**: Use `get_symbol_definition` to read the function code

3. **Analyze callers**: Use `get_callers` with `transitive=true` and `max_depth=3` to see what calls this function

4. **Analyze callees**: Use `get_callees` with `transitive=true` to see what this function calls

5. **Check complexity**: Use `get_complexity` to get cyclomatic and cognitive complexity metrics

6. **Data flow** (if path is known): Use `get_data_flow` to understand variable definitions and uses

7. **Control flow** (if path is known): Use `get_control_flow` to see branches and loops

8. **Summarize**:
   - Function purpose (based on code and naming)
   - Complexity assessment (simple/moderate/complex)
   - Dependency analysis (what it depends on, what depends on it)
   - Risk assessment for modifications
   - Suggestions for refactoring if complexity is high

## Arguments

Function to analyze: $ARGUMENTS

Example usage:
- `/narsil:analyze-function handle_request`
- `/narsil:analyze-function myrepo process_payment`
