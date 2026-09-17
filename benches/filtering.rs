/// Performance benchmarks for configuration loading and tool filtering
///
/// Validates that we meet the performance budgets:
/// - Config loading: <10ms
/// - Tool filtering: <1ms
///
/// Run with: cargo bench --bench filtering
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use narsil_mcp::config::schema::ToolConfig;
use narsil_mcp::config::{
    filter::{ClientInfo, ToolFilter},
    ConfigLoader,
};
use narsil_mcp::index::EngineOptions;
use std::time::Duration;

/// Benchmark config loading from default (embedded)
fn bench_config_load_default(c: &mut Criterion) {
    let mut group = c.benchmark_group("config_loading");
    group.measurement_time(Duration::from_secs(5));
    group.significance_level(0.05);
    group.sample_size(100);

    group.bench_function("load_default", |b| {
        b.iter(|| {
            let loader = ConfigLoader::new();
            let config = loader.load().unwrap();
            black_box(config);
        });
    });

    group.finish();
}

/// Benchmark tool filtering with different scenarios
fn bench_tool_filtering(c: &mut Criterion) {
    let mut group = c.benchmark_group("tool_filtering");
    group.measurement_time(Duration::from_secs(5));
    group.significance_level(0.05);
    group.sample_size(100);

    // Scenario 1: No flags, no client (Full preset)
    group.bench_function("full_preset_no_flags", |b| {
        let config = ToolConfig::default();
        let options = EngineOptions::default();

        b.iter(|| {
            let filter = ToolFilter::new(
                black_box(config.clone()),
                black_box(&options),
                black_box(None),
            );
            let tools = filter.get_enabled_tools();
            black_box(tools);
        });
    });

    // Scenario 2: VS Code client (Balanced preset)
    group.bench_function("balanced_preset_vscode", |b| {
        let config = ToolConfig::default();
        let options = EngineOptions::default();
        let client = ClientInfo {
            name: "vscode".to_string(),
            version: Some("1.85.0".to_string()),
        };

        b.iter(|| {
            let filter = ToolFilter::new(
                black_box(config.clone()),
                black_box(&options),
                black_box(Some(client.clone())),
            );
            let tools = filter.get_enabled_tools();
            black_box(tools);
        });
    });

    // Scenario 3: Zed client (Minimal preset)
    group.bench_function("minimal_preset_zed", |b| {
        let config = ToolConfig::default();
        let options = EngineOptions::default();
        let client = ClientInfo {
            name: "zed".to_string(),
            version: Some("0.122.0".to_string()),
        };

        b.iter(|| {
            let filter = ToolFilter::new(
                black_box(config.clone()),
                black_box(&options),
                black_box(Some(client.clone())),
            );
            let tools = filter.get_enabled_tools();
            black_box(tools);
        });
    });

    // Scenario 4: With all feature flags enabled
    group.bench_function("full_preset_all_flags", |b| {
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
            ..Default::default()
        };

        b.iter(|| {
            let filter = ToolFilter::new(
                black_box(config.clone()),
                black_box(&options),
                black_box(None),
            );
            let tools = filter.get_enabled_tools();
            black_box(tools);
        });
    });

    // Scenario 5: Performance budget applied (max_tool_count)
    group.bench_function("performance_budget_max_20", |b| {
        let mut config = ToolConfig::default();
        config.performance.max_tool_count = 20;
        let options = EngineOptions::default();

        b.iter(|| {
            let filter = ToolFilter::new(
                black_box(config.clone()),
                black_box(&options),
                black_box(None),
            );
            let tools = filter.get_enabled_tools();
            black_box(tools);
        });
    });

    group.finish();
}

/// Benchmark complete MCP flow: initialize + tools/list
fn bench_mcp_flow_simulation(c: &mut Criterion) {
    let mut group = c.benchmark_group("mcp_flow");
    group.measurement_time(Duration::from_secs(5));
    group.significance_level(0.05);
    group.sample_size(50);

    group.bench_function("initialize_and_list_tools", |b| {
        b.iter(|| {
            // Simulate MCP initialize (config load)
            let loader = ConfigLoader::new();
            let config = loader.load().unwrap();

            // Simulate tools/list (filtering)
            let options = EngineOptions::default();
            let client = ClientInfo {
                name: "vscode".to_string(),
                version: Some("1.85.0".to_string()),
            };
            let filter = ToolFilter::new(config, &options, Some(client));
            let tools = filter.get_enabled_tools();

            black_box(tools);
        });
    });

    group.finish();
}

/// Benchmark filtering with different preset sizes
fn bench_filtering_by_preset(c: &mut Criterion) {
    let mut group = c.benchmark_group("filtering_by_preset");
    group.measurement_time(Duration::from_secs(5));

    let presets = vec![
        ("minimal", "zed"),
        ("balanced", "vscode"),
        ("full", "claude-desktop"),
        ("security-focused", "custom"),
    ];

    for (preset_name, client_name) in presets {
        group.bench_with_input(
            BenchmarkId::from_parameter(preset_name),
            &client_name,
            |b, &client| {
                let config = ToolConfig::default();
                let options = EngineOptions::default();
                let client_info = ClientInfo {
                    name: client.to_string(),
                    version: None,
                };

                b.iter(|| {
                    let filter = ToolFilter::new(
                        black_box(config.clone()),
                        black_box(&options),
                        black_box(Some(client_info.clone())),
                    );
                    let tools = filter.get_enabled_tools();
                    black_box(tools);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_config_load_default,
    bench_tool_filtering,
    bench_mcp_flow_simulation,
    bench_filtering_by_preset,
);
criterion_main!(benches);
