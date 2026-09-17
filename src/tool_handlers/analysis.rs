//! Code analysis tool handlers (CFG, DFG)

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;

/// Handler for get_control_flow tool
pub struct GetControlFlowHandler;

#[async_trait::async_trait]
impl ToolHandler for GetControlFlowHandler {
    fn name(&self) -> &'static str {
        "get_control_flow"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_control_flow")?;
        let function = args.get_str("function").unwrap_or("");
        engine.get_control_flow(repo, path, function).await
    }
}

/// Handler for get_data_flow tool
pub struct GetDataFlowHandler;

#[async_trait::async_trait]
impl ToolHandler for GetDataFlowHandler {
    fn name(&self) -> &'static str {
        "get_data_flow"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_data_flow")?;
        let function = args.get_str("function").unwrap_or("");
        engine.get_data_flow(repo, path, function).await
    }
}

/// Handler for get_reaching_definitions tool
pub struct GetReachingDefinitionsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetReachingDefinitionsHandler {
    fn name(&self) -> &'static str {
        "get_reaching_definitions"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let path = super::require_arg(&args, "path", "get_reaching_definitions")?;
        let function = args.get_str("function").unwrap_or("");
        engine.get_reaching_definitions(repo, path, function).await
    }
}
