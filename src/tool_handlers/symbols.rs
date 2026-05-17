//! Symbol-related tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;

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
        let pattern = args.get_str("pattern");
        let file_pattern = args.get_str("file_pattern");
        let exclude_tests = args.get_bool("exclude_tests");
        let limit = args.get_u64_or("limit", 500) as usize;
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
        let symbol = args.get_str("symbol").unwrap_or("");
        let include_def = args.get_bool_or("include_definition", true);
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .find_references(repo, symbol, include_def, exclude_tests)
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
        let path = args.get_str("path").unwrap_or("");
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
        let symbol = args.get_str("symbol").unwrap_or("");
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
        let path = args.get_str("path").unwrap_or("");
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
