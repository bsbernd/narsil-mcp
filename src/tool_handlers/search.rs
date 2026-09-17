//! Search-related tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;

/// Handler for search_code tool
pub struct SearchCodeHandler;

#[async_trait::async_trait]
impl ToolHandler for SearchCodeHandler {
    fn name(&self) -> &'static str {
        "search_code"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let query = super::require_arg(&args, "query", "search_code")?;
        let file_pattern = args.get_str("file_pattern");
        let max_results = args.get_u64_or("max_results", 10) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .search_code(repo, query, file_pattern, max_results, exclude_tests)
            .await
    }
}

/// Handler for semantic_search tool
pub struct SemanticSearchHandler;

#[async_trait::async_trait]
impl ToolHandler for SemanticSearchHandler {
    fn name(&self) -> &'static str {
        "semantic_search"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let query = super::require_arg(&args, "query", "semantic_search")?;
        let max_results = args.get_u64_or("max_results", 10) as usize;
        let doc_type = args.get_str("doc_type");
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .semantic_search(repo, query, max_results, doc_type, exclude_tests)
            .await
    }
}

/// Handler for hybrid_search tool
pub struct HybridSearchHandler;

#[async_trait::async_trait]
impl ToolHandler for HybridSearchHandler {
    fn name(&self) -> &'static str {
        "hybrid_search"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let query = super::require_arg(&args, "query", "hybrid_search")?;
        let max_results = args.get_u64_or("max_results", 10) as usize;
        let mode = args.get_str("mode").unwrap_or("hybrid");
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .hybrid_search(query, repo, max_results, mode, exclude_tests)
            .await
    }
}
