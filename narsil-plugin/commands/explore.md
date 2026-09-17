---
description: Explore and understand an unfamiliar codebase
---

# Explore Codebase

Help the user understand the structure and organization of an unfamiliar codebase.

## Workflow

Execute the following steps:

1. **Identify repository**: If $ARGUMENTS is provided, use it as the repo name. Otherwise, use `list_repos` to show available repositories and ask which one to explore.

2. **Check capabilities**: Use `get_index_status` to see which features are enabled (git, call-graph, etc.)

3. **Show structure**: Use `get_project_structure` with `max_depth=3` to show the directory tree

4. **Find main components**:
   - Use `find_symbols` with `symbol_type="class"` to find main data structures
   - Use `find_symbols` with `symbol_type="function"` and `pattern="*main*"` to find entry points

5. **Understand dependencies**: Use `get_dependencies` on the main files to show how modules connect

6. **Summarize**: Provide a clear summary of:
   - Project structure and organization
   - Key modules and their purposes
   - Entry points

## Arguments

Repository to explore: $ARGUMENTS
