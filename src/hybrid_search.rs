//! Hybrid search combining BM25 keyword search with TF-IDF semantic similarity.
//!
//! Uses Reciprocal Rank Fusion (RRF) to combine results from multiple search methods.

use crate::chunking::{ChunkType, CodeChunk};
use crate::embeddings::{EmbeddingEngine, SimilarityResult};
use crate::search::{ConcurrentSearchIndex, DocType, SearchDocument, SearchResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// Configuration for hybrid search
#[derive(Debug, Clone)]
pub struct HybridSearchConfig {
    /// RRF k parameter (typically 60)
    /// Higher values reduce the impact of high rankings
    pub rrf_k: f64,
    /// Weight for BM25 results (0.0 to 1.0)
    pub bm25_weight: f64,
    /// Weight for TF-IDF/semantic results (0.0 to 1.0)
    pub tfidf_weight: f64,
    /// Boost factor for exact name matches
    pub exact_match_boost: f64,
    /// Boost factor for function/method matches
    pub function_boost: f64,
    /// Number of candidates to fetch from each index before fusion
    pub candidate_multiplier: usize,
}

impl Default for HybridSearchConfig {
    fn default() -> Self {
        Self {
            rrf_k: 60.0,
            bm25_weight: 1.0,
            tfidf_weight: 1.0,
            exact_match_boost: 2.0,
            function_boost: 1.5,
            candidate_multiplier: 3,
        }
    }
}

/// A result from hybrid search with combined scoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridResult {
    /// Unique identifier
    pub id: String,
    /// File path
    pub file_path: String,
    /// Content or snippet
    pub content: String,
    /// Start line in file
    pub start_line: usize,
    /// End line in file
    pub end_line: usize,
    /// Combined RRF score
    pub score: f64,
    /// BM25 rank (if found)
    pub bm25_rank: Option<usize>,
    /// TF-IDF rank (if found)
    pub tfidf_rank: Option<usize>,
    /// Terms that matched
    pub matched_terms: Vec<String>,
    /// Symbol context if available
    pub symbol_name: Option<String>,
    /// Type of result
    pub result_type: String,
}

/// Document info for merging results
#[derive(Debug, Clone)]
struct DocumentInfo {
    id: String,
    file_path: String,
    content: String,
    start_line: usize,
    end_line: usize,
    matched_terms: Vec<String>,
    symbol_name: Option<String>,
    result_type: String,
}

/// Hybrid search engine combining BM25 and TF-IDF
pub struct HybridSearchEngine {
    /// BM25 keyword search index
    bm25_index: Arc<ConcurrentSearchIndex>,
    /// TF-IDF embedding engine
    tfidf_engine: Arc<EmbeddingEngine>,
    /// Configuration
    config: HybridSearchConfig,
}

impl HybridSearchEngine {
    /// Create a new hybrid search engine
    pub fn new(bm25_index: Arc<ConcurrentSearchIndex>, tfidf_engine: Arc<EmbeddingEngine>) -> Self {
        Self {
            bm25_index,
            tfidf_engine,
            config: HybridSearchConfig::default(),
        }
    }

    /// Create with custom configuration
    pub fn with_config(
        bm25_index: Arc<ConcurrentSearchIndex>,
        tfidf_engine: Arc<EmbeddingEngine>,
        config: HybridSearchConfig,
    ) -> Self {
        Self {
            bm25_index,
            tfidf_engine,
            config,
        }
    }

    /// Perform hybrid search combining BM25 and TF-IDF results
    /// Searches are run in parallel for better performance
    pub fn search(&self, query: &str, limit: usize) -> Vec<HybridResult> {
        let candidate_limit = limit * self.config.candidate_multiplier;

        // Run BM25 and TF-IDF searches in parallel using rayon::join
        let (bm25_results, tfidf_results) = rayon::join(
            || self.bm25_index.search(query, candidate_limit),
            || self.tfidf_engine.find_similar_code(query, candidate_limit),
        );

        // Combine using RRF
        self.reciprocal_rank_fusion(bm25_results, tfidf_results, query, limit)
    }

    /// Perform BM25-only search
    pub fn search_bm25(&self, query: &str, limit: usize) -> Vec<HybridResult> {
        let results = self.bm25_index.search(query, limit);

        results
            .into_iter()
            .enumerate()
            .map(|(rank, r)| HybridResult {
                id: r.document.id.clone(),
                file_path: r.document.file_path.clone(),
                content: r.snippet.clone(),
                start_line: r.document.start_line,
                end_line: r.document.end_line,
                score: r.score,
                bm25_rank: Some(rank),
                tfidf_rank: None,
                matched_terms: r.matched_terms,
                symbol_name: None,
                result_type: format!("{:?}", r.document.doc_type),
            })
            .collect()
    }

    /// Perform TF-IDF-only search
    pub fn search_tfidf(&self, query: &str, limit: usize) -> Vec<HybridResult> {
        let results = self.tfidf_engine.find_similar_code(query, limit);

        results
            .into_iter()
            .enumerate()
            .map(|(rank, r)| HybridResult {
                id: r.document.id.clone(),
                file_path: r.document.file_path.clone(),
                content: r.document.content.clone(),
                start_line: r.document.start_line,
                end_line: r.document.end_line,
                score: r.similarity as f64,
                bm25_rank: None,
                tfidf_rank: Some(rank),
                matched_terms: Vec::new(),
                symbol_name: None,
                result_type: "embedding".to_string(),
            })
            .collect()
    }

    /// Reciprocal Rank Fusion of BM25 and TF-IDF results
    fn reciprocal_rank_fusion(
        &self,
        bm25_results: Vec<SearchResult>,
        tfidf_results: Vec<SimilarityResult>,
        query: &str,
        limit: usize,
    ) -> Vec<HybridResult> {
        let mut scores: HashMap<String, f64> = HashMap::new();
        let mut ranks: HashMap<String, (Option<usize>, Option<usize>)> = HashMap::new();
        let mut doc_info: HashMap<String, DocumentInfo> = HashMap::new();

        let k = self.config.rrf_k;
        let query_lower = query.to_lowercase();

        // Process BM25 results
        for (rank, result) in bm25_results.iter().enumerate() {
            let id = &result.document.id;
            let rrf_score = self.config.bm25_weight / (k + rank as f64 + 1.0);

            // Apply boosts
            let mut boost = 1.0;
            if id.to_lowercase().contains(&query_lower) {
                boost *= self.config.exact_match_boost;
            }
            if matches!(
                result.document.doc_type,
                DocType::Function | DocType::Method
            ) {
                boost *= self.config.function_boost;
            }

            *scores.entry(id.clone()).or_default() += rrf_score * boost;
            ranks.entry(id.clone()).or_insert((None, None)).0 = Some(rank);

            doc_info.entry(id.clone()).or_insert_with(|| DocumentInfo {
                id: id.clone(),
                file_path: result.document.file_path.clone(),
                content: result.snippet.clone(),
                start_line: result.document.start_line,
                end_line: result.document.end_line,
                matched_terms: result.matched_terms.clone(),
                symbol_name: None,
                result_type: format!("{:?}", result.document.doc_type),
            });
        }

        // Process TF-IDF results
        for (rank, result) in tfidf_results.iter().enumerate() {
            let id = &result.document.id;
            let rrf_score = self.config.tfidf_weight / (k + rank as f64 + 1.0);

            // Apply boosts
            let mut boost = 1.0;
            if id.to_lowercase().contains(&query_lower) {
                boost *= self.config.exact_match_boost;
            }

            *scores.entry(id.clone()).or_default() += rrf_score * boost;
            ranks.entry(id.clone()).or_insert((None, None)).1 = Some(rank);

            doc_info.entry(id.clone()).or_insert_with(|| DocumentInfo {
                id: id.clone(),
                file_path: result.document.file_path.clone(),
                content: result.document.content.clone(),
                start_line: result.document.start_line,
                end_line: result.document.end_line,
                matched_terms: Vec::new(),
                symbol_name: None,
                result_type: "embedding".to_string(),
            });
        }

        // Sort by combined score
        let mut combined: Vec<_> = scores.into_iter().collect();
        combined.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        // Take top results
        combined
            .into_iter()
            .take(limit)
            .filter_map(|(id, score)| {
                let info = doc_info.get(&id)?;
                let (bm25_rank, tfidf_rank) = ranks.get(&id).copied().unwrap_or((None, None));

                Some(HybridResult {
                    id: info.id.clone(),
                    file_path: info.file_path.clone(),
                    content: info.content.clone(),
                    start_line: info.start_line,
                    end_line: info.end_line,
                    score,
                    bm25_rank,
                    tfidf_rank,
                    matched_terms: info.matched_terms.clone(),
                    symbol_name: info.symbol_name.clone(),
                    result_type: info.result_type.clone(),
                })
            })
            .collect()
    }

    /// Index a code chunk for both BM25 and TF-IDF search
    pub fn index_chunk(&self, chunk: &CodeChunk) {
        // Index in BM25
        let doc_type = match chunk.chunk_type {
            ChunkType::Function => DocType::Function,
            ChunkType::Method => DocType::Method,
            ChunkType::Class => DocType::Class,
            ChunkType::Trait => DocType::Class,
            _ => DocType::Other,
        };

        let tokens = crate::search::tokenize_code(&chunk.content);
        let doc_len = tokens.len();
        let term_freq = tokens
            .into_iter()
            .fold(std::collections::HashMap::new(), |mut acc, t| {
                *acc.entry(t).or_default() += 1;
                acc
            });
        let search_doc = SearchDocument {
            id: chunk.id.clone(),
            file_path: chunk.file_path.clone(),
            content: Some(chunk.content.clone()),
            doc_type,
            start_line: chunk.start_line,
            end_line: chunk.end_line,
            doc_len,
            term_freq,
        };

        self.bm25_index.inner.write().add_document(search_doc);

        // Index in TF-IDF
        self.tfidf_engine.index_snippet(
            chunk.id.clone(),
            chunk.file_path.clone(),
            chunk.content.clone(),
            chunk.start_line,
            chunk.end_line,
        );
    }

    /// Clear all indices
    pub fn clear(&self) {
        self.bm25_index.clear();
        self.tfidf_engine.clear();
    }

    /// Get statistics about the hybrid index
    pub fn stats(&self) -> HybridSearchStats {
        let bm25_stats = self.bm25_index.stats();
        let (tfidf_stats, doc_count) = self.tfidf_engine.stats();

        HybridSearchStats {
            bm25_documents: bm25_stats.total_documents,
            bm25_terms: bm25_stats.total_terms,
            tfidf_documents: doc_count,
            tfidf_vocab_size: tfidf_stats.vocab_size,
        }
    }
}

/// Statistics about the hybrid search index
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSearchStats {
    pub bm25_documents: usize,
    pub bm25_terms: usize,
    pub tfidf_documents: usize,
    pub tfidf_vocab_size: usize,
}

/// Builder for hybrid search configuration
pub struct HybridSearchConfigBuilder {
    config: HybridSearchConfig,
}

impl HybridSearchConfigBuilder {
    pub fn new() -> Self {
        Self {
            config: HybridSearchConfig::default(),
        }
    }

    pub fn rrf_k(mut self, k: f64) -> Self {
        self.config.rrf_k = k;
        self
    }

    pub fn bm25_weight(mut self, weight: f64) -> Self {
        self.config.bm25_weight = weight;
        self
    }

    pub fn tfidf_weight(mut self, weight: f64) -> Self {
        self.config.tfidf_weight = weight;
        self
    }

    pub fn exact_match_boost(mut self, boost: f64) -> Self {
        self.config.exact_match_boost = boost;
        self
    }

    pub fn function_boost(mut self, boost: f64) -> Self {
        self.config.function_boost = boost;
        self
    }

    pub fn candidate_multiplier(mut self, multiplier: usize) -> Self {
        self.config.candidate_multiplier = multiplier;
        self
    }

    pub fn build(self) -> HybridSearchConfig {
        self.config
    }
}

impl Default for HybridSearchConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to create a hybrid search engine with default config
pub fn create_hybrid_engine(
    bm25_index: Arc<ConcurrentSearchIndex>,
    tfidf_engine: Arc<EmbeddingEngine>,
) -> HybridSearchEngine {
    HybridSearchEngine::new(bm25_index, tfidf_engine)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_engine() -> HybridSearchEngine {
        let bm25_index = Arc::new(ConcurrentSearchIndex::new());
        let tfidf_engine = Arc::new(EmbeddingEngine::new(100));
        HybridSearchEngine::new(bm25_index, tfidf_engine)
    }

    #[test]
    fn test_hybrid_search_creation() {
        let engine = create_test_engine();
        let stats = engine.stats();
        assert_eq!(stats.bm25_documents, 0);
        assert_eq!(stats.tfidf_documents, 0);
    }

    #[test]
    fn test_index_and_search() {
        let engine = create_test_engine();

        // Create a test chunk
        let chunk = CodeChunk {
            id: "test.rs:0:hello".to_string(),
            content: "fn hello_world() { println!(\"Hello, world!\"); }".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 1,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        engine.index_chunk(&chunk);

        let stats = engine.stats();
        assert_eq!(stats.bm25_documents, 1);
        assert_eq!(stats.tfidf_documents, 1);

        // Search for it
        let results = engine.search("hello world", 10);
        assert!(!results.is_empty());
        assert!(results[0].content.contains("hello_world"));
    }

    #[test]
    fn test_bm25_only_search() {
        let engine = create_test_engine();

        let chunk = CodeChunk {
            id: "test.rs:0:foo".to_string(),
            content: "fn foo_bar() { let x = 42; }".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 1,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        engine.index_chunk(&chunk);

        let results = engine.search_bm25("foo bar", 10);
        assert!(!results.is_empty());
        assert!(results[0].bm25_rank.is_some());
        assert!(results[0].tfidf_rank.is_none());
    }

    #[test]
    fn test_tfidf_only_search() {
        let engine = create_test_engine();

        let chunk = CodeChunk {
            id: "test.rs:0:baz".to_string(),
            content: "fn baz_qux() { let y = 100; }".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 1,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        engine.index_chunk(&chunk);

        let results = engine.search_tfidf("baz qux function", 10);
        assert!(!results.is_empty());
        assert!(results[0].bm25_rank.is_none());
        assert!(results[0].tfidf_rank.is_some());
    }

    #[test]
    fn test_rrf_ranking() {
        let engine = create_test_engine();

        // Index multiple chunks
        for i in 0..5 {
            let chunk = CodeChunk {
                id: format!("test.rs:{}:func{}", i, i),
                content: format!(
                    "fn function_{}() {{ let value = {}; calculate(value); }}",
                    i, i
                ),
                file_path: "test.rs".to_string(),
                start_line: i + 1,
                end_line: i + 1,
                language: "rust".to_string(),
                symbol_context: None,
                chunk_type: ChunkType::Function,
                doc_comment: None,
                imports: Vec::new(),
            };
            engine.index_chunk(&chunk);
        }

        let results = engine.search("function calculate", 5);

        // Results should be ranked by score (descending)
        for i in 1..results.len() {
            assert!(
                results[i - 1].score >= results[i].score,
                "Results should be sorted by score"
            );
        }
    }

    #[test]
    fn test_exact_match_boost() {
        let engine = create_test_engine();

        let chunk1 = CodeChunk {
            id: "test.rs:0:authenticate".to_string(),
            content: "fn authenticate() { check_password(); }".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 1,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        let chunk2 = CodeChunk {
            id: "test.rs:1:auth_related".to_string(),
            content: "fn login() { verify_credentials(); }".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 2,
            end_line: 2,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        engine.index_chunk(&chunk1);
        engine.index_chunk(&chunk2);

        // Search for "authenticate" - exact match should be boosted
        let results = engine.search("authenticate", 10);
        assert!(!results.is_empty());
        // First result should be the one with "authenticate" in the name
        assert!(results[0].id.contains("authenticate"));
    }

    #[test]
    fn test_config_builder() {
        let config = HybridSearchConfigBuilder::new()
            .rrf_k(80.0)
            .bm25_weight(0.8)
            .tfidf_weight(0.6)
            .exact_match_boost(3.0)
            .function_boost(2.0)
            .candidate_multiplier(5)
            .build();

        assert_eq!(config.rrf_k, 80.0);
        assert_eq!(config.bm25_weight, 0.8);
        assert_eq!(config.tfidf_weight, 0.6);
        assert_eq!(config.exact_match_boost, 3.0);
        assert_eq!(config.function_boost, 2.0);
        assert_eq!(config.candidate_multiplier, 5);
    }

    #[test]
    fn test_clear() {
        let engine = create_test_engine();

        let chunk = CodeChunk {
            id: "test.rs:0:test".to_string(),
            content: "fn test() {}".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 1,
            end_line: 1,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        engine.index_chunk(&chunk);
        assert_eq!(engine.stats().bm25_documents, 1);

        engine.clear();
        assert_eq!(engine.stats().bm25_documents, 0);
        assert_eq!(engine.stats().tfidf_documents, 0);
    }

    #[test]
    fn test_empty_search() {
        let engine = create_test_engine();
        let results = engine.search("nonexistent query", 10);
        assert!(results.is_empty());
    }

    #[test]
    fn test_hybrid_result_fields() {
        let engine = create_test_engine();

        let chunk = CodeChunk {
            id: "test.rs:0:my_func".to_string(),
            content: "fn my_func() { do_something(); }".to_string(),
            file_path: "test.rs".to_string(),
            start_line: 5,
            end_line: 7,
            language: "rust".to_string(),
            symbol_context: None,
            chunk_type: ChunkType::Function,
            doc_comment: None,
            imports: Vec::new(),
        };

        engine.index_chunk(&chunk);

        let results = engine.search("my func", 10);
        assert!(!results.is_empty());

        let result = &results[0];
        assert_eq!(result.file_path, "test.rs");
        assert_eq!(result.start_line, 5);
        assert_eq!(result.end_line, 7);
        assert!(result.score > 0.0);
    }

    #[test]
    fn test_custom_config_engine() {
        let bm25_index = Arc::new(ConcurrentSearchIndex::new());
        let tfidf_engine = Arc::new(EmbeddingEngine::new(100));

        let config = HybridSearchConfig {
            rrf_k: 30.0,
            bm25_weight: 0.7,
            tfidf_weight: 0.3,
            exact_match_boost: 1.5,
            function_boost: 1.2,
            candidate_multiplier: 2,
        };

        let engine = HybridSearchEngine::with_config(bm25_index, tfidf_engine, config);
        assert_eq!(engine.config.rrf_k, 30.0);
    }
}
