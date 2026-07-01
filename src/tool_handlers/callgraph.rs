//! Call graph analysis tool handlers

use anyhow::Result;
use serde_json::Value;

use super::{ArgExtractor, ToolHandler};
use crate::index::CodeIntelEngine;

/// Handler for get_call_graph tool
pub struct GetCallGraphHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCallGraphHandler {
    fn name(&self) -> &'static str {
        "get_call_graph"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let function = function_arg(&args);
        let depth = args.get_u64_or("depth", 3) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .get_call_graph(repo, function, depth, exclude_tests)
            .await
    }
}

/// The function/symbol name for a call-graph tool. The schema names this
/// `function`, but `symbol` (used by the definition/reference tools) is a very
/// natural mistake, so accept it as an alias rather than silently resolving an
/// empty name to a wrong node.
fn function_arg(args: &Value) -> &str {
    args.get_str("function")
        .or_else(|| args.get_str("symbol"))
        .unwrap_or("")
}

/// Handler for get_callers tool
pub struct GetCallersHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCallersHandler {
    fn name(&self) -> &'static str {
        "get_callers"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let function = function_arg(&args);
        let transitive = args.get_bool_or("transitive", false);
        let max_depth = args.get_u64_or("max_depth", 5) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .get_callers(repo, function, transitive, max_depth, exclude_tests)
            .await
    }
}

/// Handler for get_callees tool
pub struct GetCalleesHandler;

#[async_trait::async_trait]
impl ToolHandler for GetCalleesHandler {
    fn name(&self) -> &'static str {
        "get_callees"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let function = function_arg(&args);
        let transitive = args.get_bool_or("transitive", false);
        let max_depth = args.get_u64_or("max_depth", 5) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .get_callees(repo, function, transitive, max_depth, exclude_tests)
            .await
    }
}

/// Handler for find_call_path tool
pub struct FindCallPathHandler;

#[async_trait::async_trait]
impl ToolHandler for FindCallPathHandler {
    fn name(&self) -> &'static str {
        "find_call_path"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let from = super::require_arg(&args, "from", "find_call_path")?;
        let to = super::require_arg(&args, "to", "find_call_path")?;
        engine.find_call_path(repo, from, to).await
    }
}

/// Handler for get_complexity tool
pub struct GetComplexityHandler;

#[async_trait::async_trait]
impl ToolHandler for GetComplexityHandler {
    fn name(&self) -> &'static str {
        "get_complexity"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let function = super::require_arg(&args, "function", "get_complexity")?;
        engine.get_complexity(repo, function).await
    }
}

/// Handler for get_function_hotspots tool
pub struct GetFunctionHotspotsHandler;

#[async_trait::async_trait]
impl ToolHandler for GetFunctionHotspotsHandler {
    fn name(&self) -> &'static str {
        "get_function_hotspots"
    }

    async fn execute(&self, engine: &CodeIntelEngine, args: Value) -> Result<String> {
        let repo = args.get_str("repo").unwrap_or("");
        let min_connections = args.get_u64_or("min_connections", 5) as usize;
        let exclude_tests = args.get_bool("exclude_tests");
        engine
            .get_function_hotspots(repo, min_connections, exclude_tests)
            .await
    }
}
