/// Integration tests for editor detection, MCP flow, and configuration
///
/// This test binary runs integration tests for Phase 3 (Editor Integration)
/// and Phase 5 (Testing & Polish)
mod integration;

// Re-export integration tests
pub use integration::editor_tests;
pub use integration::full_flow_tests;
pub use integration::mcp_flow_tests;
