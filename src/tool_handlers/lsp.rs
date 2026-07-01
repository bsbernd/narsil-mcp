//! LSP integration tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;

/// Handler for get_hover_info tool
pub struct GetHoverInfoHandler;

#[async_trait::async_trait]
impl ToolHandler for GetHoverInfoHandler {
    fn name(&self) -> &'static str {
        "get_hover_info"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_hover_info")?;
        let line = args.get_u64_or("line", 1) as usize;
        let character = args.get_u64_or("character", 0) as usize;
        engine.get_hover_info(repo, path, line, character).await
    }
}

/// Handler for get_type_info tool
pub struct GetTypeInfoHandler;

#[async_trait::async_trait]
impl ToolHandler for GetTypeInfoHandler {
    fn name(&self) -> &'static str {
        "get_type_info"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_type_info")?;
        let line = args.get_u64_or("line", 1) as usize;
        let character = args.get_u64_or("character", 0) as usize;
        engine.get_type_info(repo, path, line, character).await
    }
}

/// Handler for go_to_definition tool
pub struct GoToDefinitionHandler;

#[async_trait::async_trait]
impl ToolHandler for GoToDefinitionHandler {
    fn name(&self) -> &'static str {
        "go_to_definition"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "go_to_definition")?;
        let line = args.get_u64_or("line", 1) as usize;
        let character = args.get_u64_or("character", 0) as usize;
        engine.go_to_definition(repo, path, line, character).await
    }
}
