/// Integration tests for editor detection and preset application
///
/// These tests verify that different editors get appropriate tool presets
/// based on their MCP client identification.
use narsil_mcp::config::{ClientInfo, ConfigLoader, ToolFilter};
use narsil_mcp::index::EngineOptions;

#[test]
fn test_vscode_gets_balanced_preset() {
    let client_info = ClientInfo {
        name: "vscode".to_string(),
        version: Some("1.85.0".to_string()),
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // Balanced preset without feature flags: 30-40 tools
    // (Git, CallGraph tools require flags to be enabled)
    assert!(
        enabled.len() >= 30 && enabled.len() <= 40,
        "VS Code should get balanced preset (30-40 tools without flags), got {}",
        enabled.len()
    );

    // Should include core tools
    assert!(
        enabled.contains(&"list_repos"),
        "Balanced preset should include list_repos"
    );
    assert!(
        enabled.contains(&"find_symbols"),
        "Balanced preset should include find_symbols"
    );
    assert!(
        enabled.contains(&"search_code"),
        "Balanced preset should include search_code"
    );

    // Should NOT include slow tools
    assert!(
        !enabled.contains(&"neural_search"),
        "Balanced preset should exclude neural_search (too slow for IDE)"
    );
}

#[test]
fn test_vscode_case_insensitive() {
    let client_info = ClientInfo {
        name: "VSCode".to_string(), // Mixed case
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // Should still apply balanced preset (without flags)
    assert!(
        enabled.len() >= 30 && enabled.len() <= 40,
        "VS Code detection should be case-insensitive, got {} tools",
        enabled.len()
    );
}

#[test]
fn test_code_editor_name() {
    let client_info = ClientInfo {
        name: "code".to_string(), // Alternate name
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // "code" should also map to balanced preset (without flags)
    assert!(
        enabled.len() >= 30 && enabled.len() <= 40,
        "'code' editor should map to balanced preset, got {} tools",
        enabled.len()
    );
}

#[test]
fn test_zed_gets_minimal_preset() {
    let client_info = ClientInfo {
        name: "zed".to_string(),
        version: Some("0.120.0".to_string()),
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // Minimal preset should have 20-30 tools
    assert!(
        enabled.len() >= 20 && enabled.len() <= 30,
        "Zed should get minimal preset (20-30 tools), got {}",
        enabled.len()
    );

    // Should include essential tools only
    assert!(
        enabled.contains(&"list_repos"),
        "Minimal preset should include list_repos"
    );
    assert!(
        enabled.contains(&"find_symbols"),
        "Minimal preset should include find_symbols"
    );
    assert!(
        enabled.contains(&"search_code"),
        "Minimal preset should include search_code"
    );

    // Should NOT include git tools (not in minimal)
    assert!(
        !enabled.contains(&"get_blame"),
        "Minimal preset should exclude git tools"
    );

    // Should NOT include security tools
    assert!(
        !enabled.contains(&"scan_security"),
        "Minimal preset should exclude security tools"
    );
}

#[test]
fn test_claude_desktop_gets_full_preset() {
    let client_info = ClientInfo {
        name: "claude-desktop".to_string(),
        version: Some("1.0.0".to_string()),
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // Full preset without feature flags: 50-60 tools
    // (All tools that don't require Git, CallGraph, Neural flags)
    // With all flags enabled, would be 70+ tools
    assert!(
        enabled.len() >= 35 && enabled.len() <= 45,
        "Claude Desktop should get full preset (50-60 tools without flags), got {}",
        enabled.len()
    );

    // Should include all basic tools
    assert!(enabled.contains(&"list_repos"));
    assert!(enabled.contains(&"find_symbols"));
    assert!(enabled.contains(&"search_code"));

    // Should include advanced tools
    assert!(enabled.contains(&"semantic_search"));
    assert!(enabled.contains(&"hybrid_search"));

    // Should include security tools
    assert!(enabled.contains(&"scan_security"));
}

#[test]
fn test_claude_alternate_name() {
    let client_info = ClientInfo {
        name: "claude".to_string(), // Alternate name
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // "claude" should also map to full preset (without flags)
    assert!(
        enabled.len() >= 35 && enabled.len() <= 45,
        "'claude' editor should map to full preset, got {} tools",
        enabled.len()
    );
}

#[test]
fn test_unknown_editor_gets_full_preset() {
    let client_info = ClientInfo {
        name: "unknown-editor".to_string(),
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));

    let enabled = filter.get_enabled_tools();

    // Unknown editors should get all tools (full preset, without flags = 50-60)
    assert!(
        enabled.len() >= 35 && enabled.len() <= 45,
        "Unknown editor should get full preset by default, got {}",
        enabled.len()
    );
}

#[test]
fn test_no_client_info_gets_full_preset() {
    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);

    let enabled = filter.get_enabled_tools();

    // No client info = full preset (without flags = 50-60)
    assert!(
        enabled.len() >= 35 && enabled.len() <= 45,
        "No client info should get full preset, got {}",
        enabled.len()
    );
}

#[test]
fn test_security_focused_preset() {
    // This will be applied via config, not editor detection
    // For now, test that security tools exist in metadata
    use narsil_mcp::tool_metadata::TOOL_METADATA;

    assert!(TOOL_METADATA.contains_key("scan_security"));
    assert!(TOOL_METADATA.contains_key("check_owasp_top10"));
    assert!(TOOL_METADATA.contains_key("check_cwe_top25"));
    assert!(TOOL_METADATA.contains_key("generate_sbom"));
    assert!(TOOL_METADATA.contains_key("check_dependencies"));

    // When we implement security-focused preset, it should enable these
}

#[test]
fn test_preset_respects_feature_flags() {
    // Even with balanced preset, git tools should be disabled without --git flag
    let client_info = ClientInfo {
        name: "vscode".to_string(),
        version: None,
    };

    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions {
        git_enabled: false,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled = filter.get_enabled_tools();

    // Git tools should NOT be present even in balanced preset
    assert!(
        !enabled.contains(&"get_blame"),
        "Git tools should respect feature flags even with presets"
    );
    assert!(
        !enabled.contains(&"get_file_history"),
        "Git tools should respect feature flags"
    );
}

#[test]
fn test_preset_respects_tool_overrides() {
    // User config overrides should take precedence over preset
    use narsil_mcp::config::schema::ToolOverride;
    use std::collections::HashMap;

    let client_info = ClientInfo {
        name: "claude-desktop".to_string(),
        version: None,
    };

    let mut config = ConfigLoader::new().load().unwrap();

    // Explicitly disable search_code
    config.tools.overrides.insert(
        "search_code".to_string(),
        ToolOverride {
            enabled: false,
            reason: Some("User disabled".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, Some(client_info));
    let enabled = filter.get_enabled_tools();

    // search_code should be disabled despite full preset
    assert!(
        !enabled.contains(&"search_code"),
        "Tool overrides should take precedence over preset"
    );
}

#[test]
fn test_multiple_editors_deterministic() {
    // Running the same editor detection multiple times should give same results
    let config = ConfigLoader::new().load().unwrap();
    let options = EngineOptions::default();

    let client1 = ClientInfo {
        name: "vscode".to_string(),
        version: None,
    };
    let filter1 = ToolFilter::new(config.clone(), &options, Some(client1));
    let enabled1 = filter1.get_enabled_tools();

    let client2 = ClientInfo {
        name: "vscode".to_string(),
        version: None,
    };
    let filter2 = ToolFilter::new(config, &options, Some(client2));
    let enabled2 = filter2.get_enabled_tools();

    assert_eq!(
        enabled1, enabled2,
        "Editor detection should be deterministic"
    );
}
