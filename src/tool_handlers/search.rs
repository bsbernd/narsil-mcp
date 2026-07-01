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

/// Handler for neural_search tool
pub struct NeuralSearchHandler;

#[async_trait::async_trait]
impl ToolHandler for NeuralSearchHandler {
    fn name(&self) -> &'static str {
        "neural_search"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let query = args.get_str("query").unwrap_or("");
        let max_results = args.get_u64_or("max_results", 10) as usize;
        engine.neural_search(repo, query, max_results).await
    }
}

/// Handler for search_chunks tool
pub struct SearchChunksHandler;

#[async_trait::async_trait]
impl ToolHandler for SearchChunksHandler {
    fn name(&self) -> &'static str {
        "search_chunks"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let query = args.get_str("query").unwrap_or("");
        let chunk_type = args.get_str("chunk_type");
        let max_results = args.get_u64_or("max_results", 10) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .search_chunks(query, repo, chunk_type, max_results, exclude_tests)
            .await
    }
}

/// Handler for find_similar_code tool
pub struct FindSimilarCodeHandler;

#[async_trait::async_trait]
impl ToolHandler for FindSimilarCodeHandler {
    fn name(&self) -> &'static str {
        "find_similar_code"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let query = args.get_str("query").unwrap_or("");
        let max_results = args.get_u64_or("max_results", 10) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .find_similar_code(repo, query, max_results, exclude_tests)
            .await
    }
}

/// Handler for find_similar_to_symbol tool
pub struct FindSimilarToSymbolHandler;

#[async_trait::async_trait]
impl ToolHandler for FindSimilarToSymbolHandler {
    fn name(&self) -> &'static str {
        "find_similar_to_symbol"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let symbol = args.get_str("symbol").unwrap_or("");
        let max_results = args.get_u64_or("max_results", 10) as usize;
        engine
            .find_similar_to_symbol(repo, symbol, max_results)
            .await
    }
}

/// Handler for find_semantic_clones tool
pub struct FindSemanticClonesHandler;

#[async_trait::async_trait]
impl ToolHandler for FindSemanticClonesHandler {
    fn name(&self) -> &'static str {
        "find_semantic_clones"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let function = args.get_str("function").unwrap_or("");
        let threshold = args
            .get("threshold")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.8) as f32;
        engine
            .find_semantic_clones(repo, path, function, threshold)
            .await
    }
}

/// Handler for get_embedding_stats tool
pub struct GetEmbeddingStatsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetEmbeddingStatsHandler {
    fn name(&self) -> &'static str {
        "get_embedding_stats"
    }

    async fn execute(&self, engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        engine.get_embedding_stats().await
    }
}

/// Handler for get_neural_stats tool
pub struct GetNeuralStatsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetNeuralStatsHandler {
    fn name(&self) -> &'static str {
        "get_neural_stats"
    }

    async fn execute(&self, engine: &CodeIntelEngine, _args: Value) -> Result<String> {
        engine.get_neural_stats().await
    }
}

/// Handler for get_chunk_stats tool
pub struct GetChunkStatsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetChunkStatsHandler {
    fn name(&self) -> &'static str {
        "get_chunk_stats"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        engine.get_chunk_stats(repo).await
    }
}

/// Handler for get_chunks tool
pub struct GetChunksHandler;

#[async_trait::async_trait]
impl ToolHandler for GetChunksHandler {
    fn name(&self) -> &'static str {
        "get_chunks"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        let include_imports = args.get_bool_or("include_imports", true);
        engine.get_chunks(repo, path, include_imports).await
    }
}
