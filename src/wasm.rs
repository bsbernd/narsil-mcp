//! WebAssembly bindings for narsil-mcp
//!
//! Provides a subset of code intelligence functionality for browser-based usage.
//! Enables in-browser code analysis, symbol extraction, and search without a backend server.
//!
//! # Features
//! - Multi-language parsing (Rust, Python, JavaScript, TypeScript, Go, C, C++, Java, C#)
//! - Symbol extraction (functions, classes, structs, etc.)
//! - Full-text search with BM25 ranking
//! - TF-IDF similarity search
//! - In-memory file storage

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use wasm_bindgen::prelude::*;

use crate::embeddings::EmbeddingEngine;
use crate::parser::LanguageParser;
use crate::search::{DocType, SearchDocument, SearchIndex};
use crate::symbols::{Symbol, SymbolKind};

/// Statistics about the WASM engine state
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmStats {
    pub files: usize,
    pub symbols: usize,
    pub embeddings: usize,
}

/// A simplified search result for WASM
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmSearchResult {
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub content: String,
    pub score: f64,
}

/// A similar code result for WASM
#[derive(Debug, Serialize, Deserialize)]
pub struct WasmSimilarCode {
    pub id: String,
    pub file: String,
    pub start_line: usize,
    pub end_line: usize,
    pub similarity: f64,
}

/// WASM-compatible code intelligence engine
///
/// This provides core code analysis capabilities without file system access.
/// All files are stored in memory and indexed for search.
#[wasm_bindgen]
pub struct WasmCodeIntel {
    parser: LanguageParser,
    symbols: Vec<Symbol>,
    search_index: SearchIndex,
    embeddings: EmbeddingEngine,
    files: HashMap<String, String>,
}

#[wasm_bindgen]
impl WasmCodeIntel {
    /// Create a new WASM code intelligence engine
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmCodeIntel, JsValue> {
        // Set up panic hook for better error messages
        #[cfg(feature = "wasm")]
        console_error_panic_hook::set_once();

        let parser = LanguageParser::new().map_err(|e| JsValue::from_str(&e.to_string()))?;

        Ok(Self {
            parser,
            symbols: Vec::new(),
            search_index: SearchIndex::new(),
            embeddings: EmbeddingEngine::new(500), // Larger vocab for better similarity
            files: HashMap::new(),
        })
    }

    /// Index a file from its content
    ///
    /// # Arguments
    /// * `path` - The file path (used for language detection and identification)
    /// * `content` - The file content
    ///
    /// # Returns
    /// `true` on success, throws on error
    #[wasm_bindgen]
    pub fn index_file(&mut self, path: &str, content: &str) -> Result<bool, JsValue> {
        use std::path::Path;

        // Store content
        self.files.insert(path.to_string(), content.to_string());

        // Detect language from extension
        let file_path = Path::new(path);

        // Parse and extract symbols
        match self.parser.parse_file(file_path, content) {
            Ok(parsed) => {
                // Add symbols
                for symbol in &parsed.symbols {
                    // Index symbol for similarity search
                    if let Some(body) = self.get_symbol_body(path, symbol) {
                        let doc_id = format!("{}:{}:{}", path, symbol.name, symbol.start_line);
                        self.embeddings.index_snippet(
                            doc_id,
                            path.to_string(),
                            body,
                            symbol.start_line,
                            symbol.end_line,
                        );
                    }
                }

                self.symbols.extend(parsed.symbols);

                // Index file content for search
                let doc = SearchDocument {
                    id: path.to_string(),
                    file_path: path.to_string(),
                    content: Some(content.to_string()),
                    doc_type: DocType::File,
                    start_line: 1,
                    end_line: content.lines().count(),
                    doc_len: 0,
                    term_freq: HashMap::new(),
                };
                self.search_index.add_document(doc);

                Ok(true)
            }
            Err(e) => {
                // Still store the file even if parsing fails (unsupported language)
                // Just log the error for debugging
                web_sys::console::warn_1(&JsValue::from_str(&format!(
                    "Failed to parse {}: {}",
                    path, e
                )));
                Ok(true)
            }
        }
    }

    /// Index multiple files at once
    ///
    /// # Arguments
    /// * `files_json` - JSON array of {path: string, content: string} objects
    #[wasm_bindgen]
    pub fn index_files(&mut self, files_json: &str) -> Result<usize, JsValue> {
        #[derive(Deserialize)]
        struct FileInput {
            path: String,
            content: String,
        }

        let files: Vec<FileInput> =
            serde_json::from_str(files_json).map_err(|e| JsValue::from_str(&e.to_string()))?;

        let mut count = 0;
        for file in files {
            if self.index_file(&file.path, &file.content)? {
                count += 1;
            }
        }

        Ok(count)
    }

    /// Find symbols matching a pattern
    ///
    /// # Arguments
    /// * `pattern` - Optional pattern to filter by (case-insensitive substring match)
    /// * `kind` - Optional symbol kind filter ("function", "class", "struct", etc.)
    ///
    /// # Returns
    /// JSON array of matching symbols
    #[wasm_bindgen]
    pub fn find_symbols(&self, pattern: Option<String>, kind: Option<String>) -> String {
        let kind_filter = kind.as_ref().and_then(|k| parse_symbol_kind(k));

        let results: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| {
                // Pattern filter
                let pattern_match = pattern
                    .as_ref()
                    .is_none_or(|p| s.name.to_lowercase().contains(&p.to_lowercase()));

                // Kind filter
                let kind_match = kind_filter.as_ref().is_none_or(|k| &s.kind == k);

                pattern_match && kind_match
            })
            .take(100)
            .collect();

        serde_json::to_string(&results).unwrap_or_else(|_| "[]".to_string())
    }

    /// Search code using full-text search
    ///
    /// # Arguments
    /// * `query` - The search query
    /// * `max_results` - Maximum number of results (default: 10)
    ///
    /// # Returns
    /// JSON array of search results
    #[wasm_bindgen]
    pub fn search(&self, query: &str, max_results: Option<usize>) -> String {
        let limit = max_results.unwrap_or(10);

        let results = self.search_index.search(query, limit);

        let wasm_results: Vec<WasmSearchResult> = results
            .into_iter()
            .map(|r| WasmSearchResult {
                file: r.document.file_path,
                start_line: r.document.start_line,
                end_line: r.document.end_line,
                content: r.snippet,
                score: r.score,
            })
            .collect();

        serde_json::to_string(&wasm_results).unwrap_or_else(|_| "[]".to_string())
    }

    /// Find similar code using TF-IDF embeddings
    ///
    /// # Arguments
    /// * `code` - The code snippet to find similar code for
    /// * `max_results` - Maximum number of results (default: 10)
    ///
    /// # Returns
    /// JSON array of similar code results
    #[wasm_bindgen]
    pub fn find_similar(&self, code: &str, max_results: Option<usize>) -> String {
        let limit = max_results.unwrap_or(10);

        let results = self.embeddings.find_similar_code(code, limit);

        let wasm_results: Vec<WasmSimilarCode> = results
            .into_iter()
            .map(|result| WasmSimilarCode {
                id: result.document.id,
                file: result.document.file_path,
                start_line: result.document.start_line,
                end_line: result.document.end_line,
                similarity: result.similarity as f64,
            })
            .collect();

        serde_json::to_string(&wasm_results).unwrap_or_else(|_| "[]".to_string())
    }

    /// Get file content by path
    ///
    /// # Arguments
    /// * `path` - The file path
    ///
    /// # Returns
    /// File content or null if not found
    #[wasm_bindgen]
    pub fn get_file(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    /// Get file content with line range
    ///
    /// # Arguments
    /// * `path` - The file path
    /// * `start_line` - Start line (1-indexed)
    /// * `end_line` - End line (1-indexed, inclusive)
    ///
    /// # Returns
    /// File content excerpt or null if not found
    #[wasm_bindgen]
    pub fn get_file_lines(&self, path: &str, start_line: usize, end_line: usize) -> Option<String> {
        let content = self.files.get(path)?;
        let lines: Vec<&str> = content.lines().collect();

        let start = start_line.saturating_sub(1);
        let end = end_line.min(lines.len());

        if start >= lines.len() {
            return None;
        }

        Some(lines[start..end].join("\n"))
    }

    /// Get symbol at a specific line
    ///
    /// # Arguments
    /// * `path` - The file path
    /// * `line` - The line number (1-indexed)
    ///
    /// # Returns
    /// JSON representation of the symbol or null if not found
    #[wasm_bindgen]
    pub fn symbol_at(&self, path: &str, line: usize) -> Option<String> {
        let symbol = self
            .symbols
            .iter()
            .find(|s| s.file_path == path && s.start_line <= line && s.end_line >= line)?;

        serde_json::to_string(symbol).ok()
    }

    /// Get all symbols in a file
    ///
    /// # Arguments
    /// * `path` - The file path
    ///
    /// # Returns
    /// JSON array of symbols in the file
    #[wasm_bindgen]
    pub fn symbols_in_file(&self, path: &str) -> String {
        let symbols: Vec<&Symbol> = self
            .symbols
            .iter()
            .filter(|s| s.file_path == path)
            .collect();

        serde_json::to_string(&symbols).unwrap_or_else(|_| "[]".to_string())
    }

    /// Get all indexed file paths
    ///
    /// # Returns
    /// JSON array of file paths
    #[wasm_bindgen]
    pub fn list_files(&self) -> String {
        let paths: Vec<&String> = self.files.keys().collect();
        serde_json::to_string(&paths).unwrap_or_else(|_| "[]".to_string())
    }

    /// Remove a file from the index
    ///
    /// # Arguments
    /// * `path` - The file path to remove
    ///
    /// # Returns
    /// `true` if the file was removed
    #[wasm_bindgen]
    pub fn remove_file(&mut self, path: &str) -> bool {
        let removed = self.files.remove(path).is_some();

        if removed {
            // Remove symbols from this file
            self.symbols.retain(|s| s.file_path != path);
        }

        removed
    }

    /// Clear all indexed data
    #[wasm_bindgen]
    pub fn clear(&mut self) {
        self.files.clear();
        self.symbols.clear();
        self.search_index = SearchIndex::new();
        self.embeddings.clear();
    }

    /// Get statistics about the engine state
    ///
    /// # Returns
    /// JSON object with stats
    #[wasm_bindgen]
    pub fn stats(&self) -> String {
        let (_, doc_count) = self.embeddings.stats();
        let stats = WasmStats {
            files: self.files.len(),
            symbols: self.symbols.len(),
            embeddings: doc_count,
        };

        serde_json::to_string(&stats).unwrap_or_else(|_| "{}".to_string())
    }

    /// Get supported file extensions
    ///
    /// # Returns
    /// JSON array of supported extensions
    #[wasm_bindgen]
    pub fn supported_extensions(&self) -> String {
        let extensions = vec![
            "rs", "py", "pyi", "js", "jsx", "mjs", "ts", "tsx", "go", "c", "h", "cpp", "cc", "cxx",
            "hpp", "hxx", "hh", "java", "cs",
        ];

        serde_json::to_string(&extensions).unwrap_or_else(|_| "[]".to_string())
    }

    // Private helper methods

    fn get_symbol_body(&self, path: &str, symbol: &Symbol) -> Option<String> {
        let content = self.files.get(path)?;
        let lines: Vec<&str> = content.lines().collect();

        let start = symbol.start_line.saturating_sub(1);
        let end = symbol.end_line.min(lines.len());

        if start >= lines.len() {
            return None;
        }

        Some(lines[start..end].join("\n"))
    }
}

impl Default for WasmCodeIntel {
    fn default() -> Self {
        Self::new().expect("Failed to create WasmCodeIntel")
    }
}

/// Parse a symbol kind string into SymbolKind
fn parse_symbol_kind(s: &str) -> Option<SymbolKind> {
    match s.to_lowercase().as_str() {
        "function" | "func" | "fn" => Some(SymbolKind::Function),
        "method" => Some(SymbolKind::Method),
        "class" => Some(SymbolKind::Class),
        "struct" | "structure" => Some(SymbolKind::Struct),
        "enum" => Some(SymbolKind::Enum),
        "interface" => Some(SymbolKind::Interface),
        "trait" => Some(SymbolKind::Trait),
        "type" | "typealias" => Some(SymbolKind::TypeAlias),
        "module" | "mod" => Some(SymbolKind::Module),
        "namespace" => Some(SymbolKind::Namespace),
        "constant" | "const" => Some(SymbolKind::Constant),
        "variable" | "var" => Some(SymbolKind::Variable),
        _ => None,
    }
}

/// Initialize the WASM module
/// This is called automatically when the WASM module is loaded
#[wasm_bindgen(start)]
pub fn init() {
    #[cfg(feature = "wasm")]
    console_error_panic_hook::set_once();
}

/// Get the version of the WASM module
#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_symbol_kind() {
        assert_eq!(parse_symbol_kind("function"), Some(SymbolKind::Function));
        assert_eq!(parse_symbol_kind("FUNCTION"), Some(SymbolKind::Function));
        assert_eq!(parse_symbol_kind("class"), Some(SymbolKind::Class));
        assert_eq!(parse_symbol_kind("struct"), Some(SymbolKind::Struct));
        assert_eq!(parse_symbol_kind("unknown"), None);
    }
}
