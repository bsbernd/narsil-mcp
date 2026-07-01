//! Repository and file management tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::extract::ExcerptConfig;
use crate::index::CodeIntelEngine;

/// Handler for list_repos tool
pub struct ListReposHandler;

#[async_trait::async_trait]
impl ToolHandler for ListReposHandler {
    fn name(&self) -> &'static str {
        "list_repos"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        let detail = args.get_bool_or("detail", false);
        engine.list_repos_scoped(repo, detail).await
    }
}

/// Handler for get_project_structure tool
pub struct GetProjectStructureHandler;

#[async_trait::async_trait]
impl ToolHandler for GetProjectStructureHandler {
    fn name(&self) -> &'static str {
        "get_project_structure"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let max_depth = args.get_u64_or("max_depth", 4) as usize;
        engine.get_project_structure(repo, max_depth).await
    }
}

/// Handler for get_file tool
pub struct GetFileHandler;

#[async_trait::async_trait]
impl ToolHandler for GetFileHandler {
    fn name(&self) -> &'static str {
        "get_file"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_file")?;
        let start_line = args.get_u64("start_line").map(|v| v as usize);
        let end_line = args.get_u64("end_line").map(|v| v as usize);
        engine.get_file(repo, path, start_line, end_line).await
    }
}

/// Handler for get_excerpt tool
pub struct GetExcerptHandler;

#[async_trait::async_trait]
impl ToolHandler for GetExcerptHandler {
    fn name(&self) -> &'static str {
        "get_excerpt"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = args.get_str("path").unwrap_or("");
        if path.is_empty() {
            // The recurring mistake is calling this tool with get_file's
            // arguments (file/start_line/end_line); name the real ones so the
            // error points at the fix instead of a downstream read failure.
            return Err(anyhow::anyhow!(
                "get_excerpt requires 'path' (a file path) and 'lines' (an array \
                 of line numbers to extract context around); for a literal \
                 start/end line range use get_file instead"
            ));
        }
        let lines: Vec<usize> = args
            .get_array("lines")
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as usize))
                    .collect()
            })
            .unwrap_or_default();
        if lines.is_empty() && (args.get("start_line").is_some() || args.get("end_line").is_some())
        {
            // Same mistake as the missing-path case, just with a valid path:
            // start_line/end_line belong to get_file, not get_excerpt. Without
            // this check the empty `lines` silently yields "0 excerpt(s)"
            // instead of pointing at the fix.
            return Err(anyhow::anyhow!(
                "get_excerpt takes 'lines' (an array of line numbers to \
                 extract context around), not 'start_line'/'end_line'; for a \
                 literal start/end line range use get_file instead"
            ));
        }
        let config = ExcerptConfig {
            context_before: args.get_u64_or("context_before", 5) as usize,
            context_after: args.get_u64_or("context_after", 5) as usize,
            max_lines: args.get_u64_or("max_lines", 50) as usize,
            expand_to_scope: args.get_bool_or("expand_to_scope", true),
            ..Default::default()
        };

        engine.get_excerpt(repo, path, &lines, config).await
    }
}

/// Handler for discover_repos tool
pub struct DiscoverReposHandler;

#[async_trait::async_trait]
impl ToolHandler for DiscoverReposHandler {
    fn name(&self) -> &'static str {
        "discover_repos"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let path = args.get_str("path").unwrap_or("");
        let max_depth = args.get_u64_or("max_depth", 3) as usize;
        engine.discover_repos(path, max_depth).await
    }
}

/// Handler for validate_repo tool
pub struct ValidateRepoHandler;

#[async_trait::async_trait]
impl ToolHandler for ValidateRepoHandler {
    fn name(&self) -> &'static str {
        "validate_repo"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let path = args.get_str("path").unwrap_or("");
        engine.validate_repo(path).await
    }
}

/// Handler for reindex tool
pub struct ReindexHandler;

#[async_trait::async_trait]
impl ToolHandler for ReindexHandler {
    fn name(&self) -> &'static str {
        "reindex"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        engine.reindex(repo).await
    }
}

/// Handler for get_index_status tool
pub struct GetIndexStatusHandler;

#[async_trait::async_trait]
impl ToolHandler for GetIndexStatusHandler {
    fn name(&self) -> &'static str {
        "get_index_status"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo");
        engine.get_index_status(repo).await
    }
}

/// Handler for get_incremental_status tool
pub struct GetIncrementalStatusHandler;

#[async_trait::async_trait]
impl ToolHandler for GetIncrementalStatusHandler {
    fn name(&self) -> &'static str {
        "get_incremental_status"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        engine.get_incremental_status(repo).await
    }
}

/// Handler for get_metrics tool
pub struct GetMetricsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetMetricsHandler {
    fn name(&self) -> &'static str {
        "get_metrics"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let format = args.get_str("format").unwrap_or("markdown");
        engine.get_metrics(format).await
    }
}
