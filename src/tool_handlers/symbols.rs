//! Symbol-related tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;
use crate::response_budget::DEFAULT_LIST_LIMIT;

/// Symbol rows returned when the caller passes no `limit`. Higher than the
/// generic list default because a symbol line is the whole answer, but far
/// below the old 500 — that was ~80 KB of response on a large repo.
const DEFAULT_SYMBOL_LIMIT: u64 = 100;

/// Handler for find_symbols tool
pub struct FindSymbolsHandler;

#[async_trait::async_trait]
impl ToolHandler for FindSymbolsHandler {
    fn name(&self) -> &'static str {
        "find_symbols"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let symbol_type = args.get_str("symbol_type");
        // Accept `query` as an alias for `pattern`: it is the filter key callers most
        // often reach for (search_code/semantic_search/hybrid_search all name it
        // `query`), and without the alias it silently degrades to a match-all dump.
        let pattern = args.get_str("pattern").or_else(|| args.get_str("query"));
        let file_pattern = args.get_str("file_pattern");
        let exclude_tests = args.get_bool("exclude_tests");
        let limit = args.get_u64_or("limit", DEFAULT_SYMBOL_LIMIT) as usize;
        engine
            .find_symbols(
                repo,
                symbol_type,
                pattern,
                file_pattern,
                exclude_tests,
                limit,
            )
            .await
    }
}

/// Handler for get_symbol_definition tool
pub struct GetSymbolDefinitionHandler;

#[async_trait::async_trait]
impl ToolHandler for GetSymbolDefinitionHandler {
    fn name(&self) -> &'static str {
        "get_symbol_definition"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let symbol = args.get_str("symbol").unwrap_or("");
        let context_lines = args.get_u64_or("context_lines", 5) as usize;
        engine
            .get_symbol_definition(repo, symbol, context_lines)
            .await
    }
}

/// Handler for find_references tool
pub struct FindReferencesHandler;

#[async_trait::async_trait]
impl ToolHandler for FindReferencesHandler {
    fn name(&self) -> &'static str {
        "find_references"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let symbol = super::require_arg(&args, "symbol", "find_references")?;
        let include_def = args.get_bool_or("include_definition", true);
        let exclude_tests = args.get_bool("exclude_tests");
        let window = super::list_window(&args, DEFAULT_LIST_LIMIT as u64);
        engine
            .find_references(repo, symbol, include_def, exclude_tests, window)
            .await
    }
}

/// Handler for get_dependencies tool
pub struct GetDependenciesHandler;

#[async_trait::async_trait]
impl ToolHandler for GetDependenciesHandler {
    fn name(&self) -> &'static str {
        "get_dependencies"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_dependencies")?;
        let direction = args.get_str("direction").unwrap_or("both");
        engine.get_dependencies(repo, path, direction).await
    }
}

/// Handler for find_symbol_usages tool
pub struct FindSymbolUsagesHandler;

#[async_trait::async_trait]
impl ToolHandler for FindSymbolUsagesHandler {
    fn name(&self) -> &'static str {
        "find_symbol_usages"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let symbol = super::require_arg(&args, "symbol", "find_symbol_usages")?;
        let include_imports = args.get_bool_or("include_imports", true);
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .find_symbol_usages(repo, symbol, include_imports, exclude_tests)
            .await
    }
}

/// Handler for get_export_map tool
pub struct GetExportMapHandler;

#[async_trait::async_trait]
impl ToolHandler for GetExportMapHandler {
    fn name(&self) -> &'static str {
        "get_export_map"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_export_map")?;
        engine.get_export_map(repo, path).await
    }
}

/// Handler for workspace_symbol_search tool
pub struct WorkspaceSymbolSearchHandler;

#[async_trait::async_trait]
impl ToolHandler for WorkspaceSymbolSearchHandler {
    fn name(&self) -> &'static str {
        "workspace_symbol_search"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let query = args.get_str("query").unwrap_or("");
        let kind = args.get_str("kind");
        let limit = args.get_u64_or("limit", 20) as usize;
        engine.workspace_symbol_search(query, kind, limit).await
    }
}
