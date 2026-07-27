/// Tests for ToolFilter - dynamic tool filtering based on configuration
///
/// These tests verify that the filtering logic correctly applies:
/// 1. Feature flags (git_enabled → Git tools)
/// 2. Category configuration
/// 3. Tool overrides
/// 4. Editor presets (future)
/// 5. Performance budgets
use narsil_mcp::config::schema::{CategoryConfig, PerformanceConfig, ToolConfig, ToolOverride};
use narsil_mcp::config::ConfigLoader;
use narsil_mcp::index::EngineOptions;
use narsil_mcp::tool_metadata::{FeatureFlag, TOOL_METADATA};
use std::collections::HashMap;
use std::time::{Duration, Instant};

// Import ToolFilter (will be implemented)
use narsil_mcp::config::{ExposeGroup, ToolFilter};

#[test]
fn test_filter_by_feature_flags_git() {
    // Git enabled, call graph disabled
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: false,
        ..Default::default()
    };

    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Git tools should be included
    assert!(
        enabled.contains(&"get_blame"),
        "Git tools should be enabled when git_enabled=true"
    );
    assert!(
        enabled.contains(&"get_file_history"),
        "Git tools should be enabled"
    );

    // Call graph tools should NOT be included
    assert!(
        !enabled.contains(&"get_call_graph"),
        "Call graph tools should be disabled when call_graph_enabled=false"
    );
    assert!(
        !enabled.contains(&"get_callers"),
        "Call graph tools should be disabled"
    );
}

#[test]
fn test_filter_by_feature_flags_call_graph() {
    // Call graph enabled, git disabled
    let options = EngineOptions {
        git_enabled: false,
        call_graph_enabled: true,
        ..Default::default()
    };

    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Call graph tools should be included
    assert!(
        enabled.contains(&"get_call_graph"),
        "Call graph tools should be enabled"
    );
    assert!(
        enabled.contains(&"get_callers"),
        "Call graph tools should be enabled"
    );

    // Git tools should NOT be included
    assert!(
        !enabled.contains(&"get_blame"),
        "Git tools should be disabled when git_enabled=false"
    );
}

#[test]
fn test_filter_by_feature_flags_all_enabled() {
    // All flags enabled
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        persist_enabled: true,
        watch_enabled: true,
        lsp_config: narsil_mcp::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        neural_config: narsil_mcp::neural::NeuralConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let config = ToolConfig::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Should include tools from all categories
    assert!(enabled.len() >= 70, "Most tools should be enabled");
    assert!(enabled.contains(&"get_blame"));
    assert!(enabled.contains(&"get_call_graph"));
    assert!(enabled.contains(&"neural_search"));
}

#[test]
fn test_filter_by_category_disabled() {
    // Disable Search category
    let mut config = ToolConfig::default();
    config.tools.categories.insert(
        "Search".to_string(),
        CategoryConfig {
            enabled: false,
            description: None,
            required_flags: vec![],
            config: HashMap::new(),
        },
    );

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Search tools should NOT be included
    assert!(
        !enabled.contains(&"search_code"),
        "Search tools should be disabled"
    );
    assert!(
        !enabled.contains(&"semantic_search"),
        "Search tools should be disabled"
    );
    assert!(
        !enabled.contains(&"hybrid_search"),
        "Search tools should be disabled"
    );

    // Other tools should still be included
    assert!(
        enabled.contains(&"list_repos"),
        "Repository tools should be enabled"
    );
    assert!(
        enabled.contains(&"find_symbols"),
        "Symbol tools should be enabled"
    );
}

#[test]
fn test_filter_by_tool_override_disabled() {
    // Disable specific tool via override
    let mut config = ToolConfig::default();
    config.tools.overrides.insert(
        "neural_search".to_string(),
        ToolOverride {
            enabled: false,
            reason: Some("Too slow for interactive use".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let mut options = EngineOptions::default();
    options.neural_config.enabled = true; // Feature enabled, but tool overridden

    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // neural_search should be disabled despite neural flag being enabled
    assert!(
        !enabled.contains(&"neural_search"),
        "Overridden tools should be disabled"
    );

    // Other neural tools should still work if they exist
    // (find_semantic_clones requires neural flag)
}

#[test]
fn test_filter_by_tool_override_enabled() {
    // Explicitly enable a tool that would normally be disabled
    let mut config = ToolConfig::default();
    config.tools.overrides.insert(
        "get_blame".to_string(),
        ToolOverride {
            enabled: true,
            reason: Some("Always enable git blame".to_string()),
            required_flags: vec![],
            config: HashMap::new(),
            performance_impact: None,
            requires_api_key: false,
        },
    );

    let options = EngineOptions {
        git_enabled: false,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // get_blame should be enabled due to override
    // Note: This might not work if we enforce required flags strictly
    // For now, let's test that overrides take precedence
    // Uncomment if we decide overrides can bypass flag requirements:
    // assert!(enabled.contains(&"get_blame"), "Override should enable tool despite missing flag");
    //
    // OR test that override can't bypass required flags:
    assert!(
        !enabled.contains(&"get_blame"),
        "Override cannot bypass required feature flags"
    );
}

#[test]
fn test_performance_budget_respected() {
    // Set max_tool_count to 10. Use the Balanced preset because Full bypasses
    // the cap by design (see issue #23 — "Full" means "give me everything").
    let mut config = ToolConfig::default();
    config.performance.max_tool_count = 10;
    config.preset = Some("balanced".to_string());

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Should not exceed budget
    assert!(
        enabled.len() <= 10,
        "Should not exceed max_tool_count budget"
    );

    // Should prioritize low-performance-impact tools
    // Check that we got some basic tools
    assert!(!enabled.is_empty(), "Should have at least some tools");
}

#[test]
fn test_default_config_includes_all_basic_tools() {
    // Default config with no feature flags
    let config = ToolConfig::default();
    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Should include Repository, Symbols, Search categories
    assert!(enabled.contains(&"list_repos"));
    assert!(enabled.contains(&"find_symbols"));
    assert!(enabled.contains(&"search_code"));

    // Should NOT include flagged tools
    assert!(!enabled.contains(&"get_blame")); // Requires Git
    assert!(!enabled.contains(&"get_call_graph")); // Requires CallGraph
}

#[test]
fn test_filtering_performance() {
    // Test that filtering completes in <1ms
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);

    let start = Instant::now();
    let _ = filter.get_enabled_tools();
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_millis(1),
        "Filtering should complete in <1ms, took {:?}",
        elapsed
    );
}

#[test]
fn test_filtering_is_deterministic() {
    // Same config should produce same results
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config.clone(), &options, None);
    let enabled1 = filter.get_enabled_tools();

    let filter2 = ToolFilter::new(config, &options, None);
    let enabled2 = filter2.get_enabled_tools();

    assert_eq!(enabled1, enabled2, "Filtering should be deterministic");
}

#[test]
fn test_feature_flag_conversion_from_engine_options() {
    // Test that EngineOptions correctly converts to FeatureFlags
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: false,
        persist_enabled: true,
        lsp_config: narsil_mcp::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        neural_config: narsil_mcp::neural::NeuralConfig {
            enabled: false,
            ..Default::default()
        },
        ..Default::default()
    };

    let flags = ToolFilter::convert_engine_options(&options);

    assert!(flags.contains(&FeatureFlag::Git));
    assert!(!flags.contains(&FeatureFlag::CallGraph));
    assert!(flags.contains(&FeatureFlag::Persist));
    assert!(flags.contains(&FeatureFlag::Lsp));
    assert!(!flags.contains(&FeatureFlag::Neural));
}

#[test]
fn test_all_enabled_tools_have_metadata() {
    // Verify that all enabled tools exist in TOOL_METADATA
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    for tool_name in enabled {
        assert!(
            TOOL_METADATA.contains_key(tool_name),
            "Tool {} should have metadata",
            tool_name
        );
    }
}

#[test]
fn test_filter_respects_category_required_flags() {
    // Category enabled but required flag not set
    let mut config = ToolConfig::default();
    config.tools.categories.insert(
        "Git".to_string(),
        CategoryConfig {
            enabled: true,
            description: None,
            required_flags: vec!["git".to_string()],
            config: HashMap::new(),
        },
    );

    let options = EngineOptions {
        git_enabled: false,
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Git tools should NOT be included (missing required flag)
    assert!(!enabled.contains(&"get_blame"));
    assert!(!enabled.contains(&"get_file_history"));
}

#[test]
fn test_empty_config_with_all_flags_enabled() {
    // Empty config (all categories enabled by default) + all flags
    let config = ToolConfig::default();
    let options = EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        persist_enabled: true,
        watch_enabled: true,
        lsp_config: narsil_mcp::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        neural_config: narsil_mcp::neural::NeuralConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Should get most tools; some still depend on compile-time or runtime flags.
    assert!(
        enabled.len() >= 65,
        "Should have most tools enabled with all flags"
    );
}

#[test]
fn test_filter_with_loaded_config() {
    // Test with a loaded config
    let loader = ConfigLoader::new();
    let config = loader.load().unwrap();

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);
    let enabled = filter.get_enabled_tools();

    // Should have basic tools
    assert!(!enabled.is_empty());
    assert!(enabled.contains(&"list_repos"));
}

#[test]
fn test_security_focused_preset() {
    let config = ToolConfig {
        preset: Some("security-focused".to_string()),
        ..Default::default()
    };

    let options = EngineOptions::default();
    let filter = ToolFilter::new(config, &options, None);

    let enabled = filter.get_enabled_tools();
    println!("\nSecurity-focused preset tool count: {}", enabled.len());
    println!("Enabled tools:");
    for tool in &enabled {
        println!("  {}", tool);
    }

    // Should have ~32 tools as defined in preset.rs
    assert!(
        enabled.len() >= 25 && enabled.len() <= 40,
        "Security-focused preset should have 25-40 tools, got {}",
        enabled.len()
    );

    // Should include security tools
    assert!(enabled.contains(&"scan_security"));
    assert!(enabled.contains(&"check_owasp_top10"));
    assert!(enabled.contains(&"generate_sbom"));

    // Should NOT include neural tools
    assert!(!enabled.contains(&"neural_search"));
}

/// All feature flags on, so nothing below is filtered out by a missing flag.
fn all_features_enabled() -> EngineOptions {
    EngineOptions {
        git_enabled: true,
        call_graph_enabled: true,
        persist_enabled: true,
        watch_enabled: true,
        remote_enabled: true,
        lsp_config: narsil_mcp::lsp::LspConfig {
            enabled: true,
            ..Default::default()
        },
        neural_config: narsil_mcp::neural::NeuralConfig {
            enabled: true,
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn test_expose_narrows_to_selected_groups() {
    let filter = ToolFilter::new(ToolConfig::default(), &all_features_enabled(), None)
        .with_expose(&[ExposeGroup::Code, ExposeGroup::Git]);
    let enabled = filter.get_enabled_tools();

    assert!(enabled.contains(&"find_symbols"), "code group");
    assert!(enabled.contains(&"get_blame"), "git group");
    assert!(enabled.contains(&"list_repos"), "base is always folded in");

    assert!(!enabled.contains(&"scan_security"), "security not selected");
    assert!(
        !enabled.contains(&"generate_sbom"),
        "supply-chain not selected"
    );
    assert!(!enabled.contains(&"find_dead_stores"), "lint not selected");
    assert!(!enabled.contains(&"get_chunks"), "retrieval not selected");
}

/// Without the flag the filter must behave exactly as before.
#[test]
fn test_expose_empty_leaves_preset_in_charge() {
    let options = all_features_enabled();
    let before = ToolFilter::new(ToolConfig::default(), &options, None).get_enabled_tools();
    let after = ToolFilter::new(ToolConfig::default(), &options, None)
        .with_expose(&[])
        .get_enabled_tools();

    assert_eq!(before.len(), after.len());
}

/// The two compose by intersection: a group cannot re-enable what the preset
/// excluded, and the preset cannot re-enable what the groups excluded.
#[test]
fn test_expose_intersects_preset() {
    let config = ToolConfig {
        preset: Some("minimal".to_string()),
        ..Default::default()
    };

    let filter = ToolFilter::new(config, &all_features_enabled(), None)
        .with_expose(&[ExposeGroup::Code, ExposeGroup::Git]);
    let enabled = filter.get_enabled_tools();

    // In both minimal and code -> present.
    assert!(enabled.contains(&"find_symbols"));
    // In the git group but not in the minimal preset -> still excluded.
    assert!(!enabled.contains(&"get_blame"));
    // In the minimal preset but not in code/git/base -> still excluded.
    assert!(!enabled.contains(&"search_chunks"));
}

/// An explicit --expose is a deliberate narrowing, so it must not be trimmed
/// further by the editor token budget.
#[test]
fn test_expose_bypasses_performance_budget() {
    let config = ToolConfig {
        preset: Some("balanced".to_string()),
        performance: PerformanceConfig {
            max_tool_count: 5,
            ..Default::default()
        },
        ..Default::default()
    };

    let enabled = ToolFilter::new(config, &all_features_enabled(), None)
        .with_expose(&[ExposeGroup::Code])
        .get_enabled_tools();

    assert!(
        enabled.len() > 5,
        "max_tool_count must not trim an explicit --expose, got {}",
        enabled.len()
    );
}
