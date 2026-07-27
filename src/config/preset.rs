/// Preset configurations for different use cases
///
/// Presets define curated tool selections optimized for specific scenarios:
/// - **Minimal**: Fast, lightweight (Zed, quick edits) - 20-30 tools
/// - **Balanced**: Good defaults (VS Code, IntelliJ) - 40-50 tools
/// - **Full**: Everything (Claude Desktop, analysis) - 70+ tools
/// - **SecurityFocused**: Security and supply chain tools - ~30 tools
use std::collections::HashSet;

/// Available preset configurations
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Preset {
    /// Minimal tool set - essential tools only (20-30 tools)
    /// - Repository operations
    /// - Symbol search
    /// - Basic code search
    Minimal,

    /// Balanced tool set - good defaults for most IDEs (40-50 tools)
    /// - All Minimal tools
    /// - Git integration
    /// - LSP integration
    /// - Some security tools
    Balanced,

    /// Full tool set - all available tools (70+ tools)
    /// - All tools enabled
    Full,

    /// Security-focused tool set - security and supply chain (~30 tools)
    /// - Repository basics
    /// - Security scanning
    /// - Supply chain analysis
    /// - Code analysis
    SecurityFocused,
}

impl Preset {
    /// Parse a preset from a string
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "minimal" => Some(Preset::Minimal),
            "balanced" => Some(Preset::Balanced),
            "full" => Some(Preset::Full),
            "security-focused" | "security_focused" => Some(Preset::SecurityFocused),
            _ => None,
        }
    }

    /// Get the set of enabled tool names for this preset
    ///
    /// Returns a HashSet of tool names that should be enabled.
    /// Tools not in this set will be filtered out (unless required by feature flags).
    pub fn get_enabled_tools(&self) -> HashSet<&'static str> {
        match self {
            Preset::Minimal => Self::minimal_tools(),
            Preset::Balanced => Self::balanced_tools(),
            Preset::Full => Self::full_tools(),
            Preset::SecurityFocused => Self::security_focused_tools(),
        }
    }

    /// Get the set of explicitly disabled tools for this preset
    ///
    /// These tools will be disabled even if they would otherwise be enabled
    /// by category or feature flags.
    pub fn get_disabled_tools(&self) -> HashSet<&'static str> {
        match self {
            Preset::Minimal => {
                // Disable slow/advanced tools
                [
                    "neural_search",
                    "find_semantic_clones",
                    "generate_sbom",
                    "check_dependencies",
                    "check_licenses",
                    "scan_security",
                    "check_owasp_top10",
                    "check_cwe_top25",
                ]
                .iter()
                .copied()
                .collect()
            }
            Preset::Balanced => {
                // Disable only the slowest tools
                ["neural_search", "find_semantic_clones"]
                    .iter()
                    .copied()
                    .collect()
            }
            Preset::Full => HashSet::new(), // Nothing disabled
            Preset::SecurityFocused => {
                // Disable neural and some graph tools
                ["neural_search", "find_semantic_clones", "get_call_graph"]
                    .iter()
                    .copied()
                    .collect()
            }
        }
    }

    /// Minimal preset tools (20-30 tools)
    fn minimal_tools() -> HashSet<&'static str> {
        [
            // Repository & Files (10 tools)
            "list_repos",
            "get_project_structure",
            "get_file",
            "get_excerpt",
            "reindex",
            "discover_repos",
            "validate_repo",
            "get_index_status",
            "get_incremental_status",
            "get_metrics",
            // Symbols (7 tools)
            "find_symbols",
            "get_symbol_definition",
            "find_references",
            "get_dependencies",
            "find_symbol_usages",
            "get_export_map",
            "workspace_symbol_search",
            // Search (basic, 6 tools)
            "search_code",
            "semantic_search",
            "hybrid_search",
            "search_chunks",
            "get_chunk_stats",
            "get_chunks",
            // LSP (3 tools - basic, not dependent on --lsp flag)
            "get_hover_info",
            "get_type_info",
            "go_to_definition",
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Balanced preset tools (40-50 tools)
    fn balanced_tools() -> HashSet<&'static str> {
        let mut tools = Self::minimal_tools();

        // Add git tools (requires --git flag)
        tools.extend([
            "get_blame",
            "get_file_history",
            "get_recent_changes",
            "get_hotspots",
            "get_contributors",
            "get_commit_diff",
            "get_symbol_history",
            "get_branch_info",
            "get_modified_files",
        ]);

        // Add more search tools
        tools.extend([
            "find_similar_code",
            "find_similar_to_symbol",
            "get_embedding_stats",
        ]);

        // Add some call graph tools (requires --call-graph flag)
        tools.extend([
            "get_call_graph",
            "get_callers",
            "get_callees",
            "find_call_path",
            "get_complexity",
            "get_function_hotspots",
        ]);

        // Add security essentials
        tools.extend(["scan_security", "find_injection_vulnerabilities"]);

        // Add code analysis basics
        tools.extend([
            "get_control_flow",
            "find_dead_code",
            "get_data_flow",
            "get_import_graph",
            "find_circular_imports",
        ]);

        tools
    }

    /// Full preset tools (70+ tools) - all tools
    fn full_tools() -> HashSet<&'static str> {
        // Return empty set to signal "enable all"
        // ToolFilter will interpret this specially
        HashSet::new()
    }

    /// Security-focused preset tools (~30 tools)
    fn security_focused_tools() -> HashSet<&'static str> {
        [
            // Repository basics
            "list_repos",
            "get_project_structure",
            "get_file",
            "get_excerpt",
            "get_index_status",
            // Symbols for analysis
            "find_symbols",
            "get_symbol_definition",
            "find_references",
            // Search
            "search_code",
            "search_chunks",
            // Security tools (9)
            "scan_security",
            "check_owasp_top10",
            "check_cwe_top25",
            "find_injection_vulnerabilities",
            "trace_taint",
            "get_taint_sources",
            "get_security_summary",
            "explain_vulnerability",
            "suggest_fix",
            // Supply chain (4)
            "generate_sbom",
            "check_dependencies",
            "check_licenses",
            "find_upgrade_path",
            // Code analysis (useful for security)
            "get_control_flow",
            "find_dead_code",
            "get_data_flow",
            "get_reaching_definitions",
            "find_uninitialized",
            "find_dead_stores",
            "infer_types",
            "check_type_errors",
            "get_typed_taint_flow",
        ]
        .iter()
        .copied()
        .collect()
    }
}

/// One switchable band of tools. Unlike a [`Preset`], which names a single
/// bundle, several groups may be active at once — so the union a caller picked
/// never needs a name of its own.
///
/// A group earns a name when it answers a *different question*, not when it
/// answers the same question at a different scale: repo-wide call graphs sit in
/// [`ExposeGroup::Code`] beside the per-symbol lookups, while "does it compile
/// clean" is [`ExposeGroup::Lint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExposeGroup {
    /// Addressing a repo and recovering from a stale index. Always folded into
    /// the union: without these a client cannot name a repository or repair an
    /// empty answer, whatever else it selected.
    Base,
    /// What the code is, at every scale: symbols, references, search, file
    /// text, LSP lookups; call and import edges both per-symbol and as whole
    /// graphs; complexity, hotspots, cycles; per-function CFG and def-use.
    Code,
    /// Why the code is the way it is: blame, history, commit diffs, branch
    /// state, contributors.
    Git,
    /// Derived analysis of code the caller is already reading: complexity
    /// metrics, hotspots, import graphs, cycles, per-function control and data
    /// flow. Off by default — a model holding the source can work these out,
    /// so the schemas cost context to restate what is already in front of it.
    Analysis,
    /// Defect finders that duplicate compiler diagnostics. Off by default —
    /// the build already reports these, with type information narsil lacks.
    Lint,
    /// Vulnerability scanning and taint tracking.
    Security,
    /// SBOM, licences, dependency and upgrade checks.
    SupplyChain,
    /// Chunk and embedding retrieval, similarity search.
    Retrieval,
}

/// Tools registered in `TOOL_METADATA` but deliberately not reachable over MCP
/// (HTTP-only, or gated behind a feature flag). Listed so the partition test
/// can tell "intentionally ungrouped" from "someone forgot".
#[cfg(test)]
const UNGROUPED_TOOLS: [&str; 20] = [
    "add_remote_repo",
    "export_ccg",
    "export_ccg_architecture",
    "export_ccg_full",
    "export_ccg_index",
    "export_ccg_manifest",
    "find_semantic_clones",
    "get_ccg_access_info",
    "get_ccg_acl",
    "get_ccg_manifest",
    "get_neural_stats",
    "get_remote_file",
    "import_ccg",
    "import_ccg_from_registry",
    "list_remote_files",
    "list_sparql_templates",
    "neural_search",
    "query_ccg",
    "run_sparql_template",
    "sparql_query",
];

impl ExposeGroup {
    /// Every group, in the order they are printed in `--help` and the docs.
    pub const ALL: [ExposeGroup; 8] = [
        ExposeGroup::Base,
        ExposeGroup::Code,
        ExposeGroup::Git,
        ExposeGroup::Analysis,
        ExposeGroup::Lint,
        ExposeGroup::Security,
        ExposeGroup::SupplyChain,
        ExposeGroup::Retrieval,
    ];

    /// The CLI spelling of this group.
    pub fn name(&self) -> &'static str {
        match self {
            ExposeGroup::Base => "base",
            ExposeGroup::Code => "code",
            ExposeGroup::Git => "git",
            ExposeGroup::Analysis => "analysis",
            ExposeGroup::Lint => "lint",
            ExposeGroup::Security => "security",
            ExposeGroup::SupplyChain => "supply-chain",
            ExposeGroup::Retrieval => "retrieval",
        }
    }

    /// Parse a group from a string; hyphen and underscore both work.
    pub fn parse(s: &str) -> Option<Self> {
        let normalized = s.to_lowercase().replace('_', "-");
        ExposeGroup::ALL
            .iter()
            .copied()
            .find(|g| g.name() == normalized)
    }

    /// Tool names belonging to this group.
    pub fn tools(&self) -> HashSet<&'static str> {
        match self {
            ExposeGroup::Base => Self::base_tools(),
            ExposeGroup::Code => Self::code_tools(),
            ExposeGroup::Git => Self::git_tools(),
            ExposeGroup::Analysis => Self::analysis_tools(),
            ExposeGroup::Lint => Self::lint_tools(),
            ExposeGroup::Security => Self::security_tools(),
            ExposeGroup::SupplyChain => Self::supply_chain_tools(),
            ExposeGroup::Retrieval => Self::retrieval_tools(),
        }
    }

    /// Which group owns a tool. `None` for the deliberately ungrouped ones.
    /// Not a hot path — the renderer walks groups, not tools.
    pub fn of(tool: &str) -> Option<Self> {
        ExposeGroup::ALL
            .iter()
            .copied()
            .find(|g| g.tools().contains(tool))
    }

    /// Union of the selected groups, with `Base` always folded in. An empty
    /// selection yields an empty set, which the filter reads as "no group
    /// filter — defer to the preset".
    pub fn union(groups: &[ExposeGroup]) -> HashSet<&'static str> {
        if groups.is_empty() {
            return HashSet::new();
        }

        let mut tools = Self::base_tools();
        for group in groups {
            tools.extend(group.tools());
        }
        tools
    }

    fn base_tools() -> HashSet<&'static str> {
        [
            "list_repos",
            "get_index_status",
            // The documented recovery when a query comes back empty.
            "reindex",
            "discover_repos",
            "validate_repo",
            "get_metrics",
            "get_incremental_status",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn code_tools() -> HashSet<&'static str> {
        [
            "get_project_structure",
            "get_file",
            "get_excerpt",
            "find_symbols",
            "get_symbol_definition",
            "find_symbol_usages",
            "find_references",
            "get_dependencies",
            "get_export_map",
            "search_code",
            "semantic_search",
            "hybrid_search",
            "get_callers",
            "get_callees",
            "find_call_path",
            // Gated behind FeatureFlag::Lsp already, so these disappear on
            // their own when no language server is configured.
            "go_to_definition",
            "get_hover_info",
            "get_type_info",
            // Callers, callees and metrics in one round trip rather than two.
            "get_call_graph",
            // "where did this value come from" across a function too long to
            // hold in view — retrieval, not restatement.
            "get_reaching_definitions",
        ]
        .iter()
        .copied()
        .collect()
    }

    /// Derived analysis, as opposed to retrieval. The distinction that puts a
    /// tool here: its answer is something a caller holding the source can work
    /// out unaided, so paying schema bytes on every request to offer it is a
    /// bad trade. Useful to a human reading `narsil-mcp tools list` or driving
    /// the HTTP frontend, which is why these stay registered.
    fn analysis_tools() -> HashSet<&'static str> {
        [
            "get_complexity",
            "get_function_hotspots",
            "get_import_graph",
            "find_circular_imports",
            "find_unused_exports",
            "get_control_flow",
            "get_data_flow",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn git_tools() -> HashSet<&'static str> {
        [
            "get_blame",
            "get_file_history",
            "get_symbol_history",
            "get_recent_changes",
            "get_commit_diff",
            "get_branch_info",
            "get_modified_files",
            "get_contributors",
            "get_hotspots",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn lint_tools() -> HashSet<&'static str> {
        [
            "find_dead_code",
            "find_dead_stores",
            "find_uninitialized",
            "check_type_errors",
            "infer_types",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn security_tools() -> HashSet<&'static str> {
        [
            "scan_security",
            "security_audit",
            "get_security_summary",
            "check_owasp_top10",
            "check_cwe_top25",
            "find_injection_vulnerabilities",
            "trace_taint",
            "get_taint_sources",
            "get_typed_taint_flow",
            "explain_vulnerability",
            "suggest_fix",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn supply_chain_tools() -> HashSet<&'static str> {
        [
            "generate_sbom",
            "check_dependencies",
            "check_licenses",
            "find_upgrade_path",
        ]
        .iter()
        .copied()
        .collect()
    }

    fn retrieval_tools() -> HashSet<&'static str> {
        [
            "get_chunks",
            "search_chunks",
            "get_chunk_stats",
            "get_embedding_stats",
            "find_similar_code",
            "find_similar_to_symbol",
            "workspace_symbol_search",
            "get_code_graph",
        ]
        .iter()
        .copied()
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_preset_size() {
        let tools = Preset::Minimal.get_enabled_tools();
        assert!(
            tools.len() >= 20 && tools.len() <= 30,
            "Minimal preset should have 20-30 tools, got {}",
            tools.len()
        );
    }

    #[test]
    fn test_balanced_preset_size() {
        let tools = Preset::Balanced.get_enabled_tools();
        assert!(
            tools.len() >= 40 && tools.len() <= 60,
            "Balanced preset should have 40-60 tools, got {}",
            tools.len()
        );
    }

    #[test]
    fn test_minimal_includes_essentials() {
        let tools = Preset::Minimal.get_enabled_tools();
        assert!(tools.contains(&"list_repos"));
        assert!(tools.contains(&"find_symbols"));
        assert!(tools.contains(&"search_code"));
    }

    #[test]
    fn test_minimal_excludes_advanced() {
        let disabled = Preset::Minimal.get_disabled_tools();
        assert!(disabled.contains(&"neural_search"));
        assert!(disabled.contains(&"generate_sbom"));
    }

    #[test]
    fn test_balanced_includes_git() {
        let tools = Preset::Balanced.get_enabled_tools();
        assert!(tools.contains(&"get_blame"));
        assert!(tools.contains(&"get_file_history"));
    }

    #[test]
    fn test_balanced_excludes_neural() {
        let disabled = Preset::Balanced.get_disabled_tools();
        assert!(disabled.contains(&"neural_search"));
    }

    #[test]
    fn test_full_enables_all() {
        let tools = Preset::Full.get_enabled_tools();
        // Empty set means "enable all"
        assert!(tools.is_empty());
    }

    #[test]
    fn test_full_no_disabled() {
        let disabled = Preset::Full.get_disabled_tools();
        assert!(disabled.is_empty());
    }

    #[test]
    fn test_security_includes_security_tools() {
        let tools = Preset::SecurityFocused.get_enabled_tools();
        assert!(tools.contains(&"scan_security"));
        assert!(tools.contains(&"check_owasp_top10"));
        assert!(tools.contains(&"generate_sbom"));
        assert!(tools.contains(&"check_dependencies"));
    }

    #[test]
    fn test_security_excludes_neural() {
        let disabled = Preset::SecurityFocused.get_disabled_tools();
        assert!(disabled.contains(&"neural_search"));
    }

    #[test]
    fn test_parse() {
        assert_eq!(Preset::parse("minimal"), Some(Preset::Minimal));
        assert_eq!(Preset::parse("MINIMAL"), Some(Preset::Minimal));
        assert_eq!(Preset::parse("balanced"), Some(Preset::Balanced));
        assert_eq!(Preset::parse("full"), Some(Preset::Full));
        assert_eq!(
            Preset::parse("security-focused"),
            Some(Preset::SecurityFocused)
        );
        assert_eq!(
            Preset::parse("security_focused"),
            Some(Preset::SecurityFocused)
        );
        assert_eq!(Preset::parse("unknown"), None);
    }

    /// A tool added to the registry must be assigned a group or explicitly
    /// opted out; otherwise it is unreachable under any `--expose` and nothing
    /// says so.
    #[test]
    fn test_expose_groups_partition_registry() {
        use crate::tool_metadata::TOOL_METADATA;

        let ungrouped: HashSet<&str> = UNGROUPED_TOOLS.iter().copied().collect();

        for tool_name in TOOL_METADATA.keys() {
            let owners: Vec<&'static str> = ExposeGroup::ALL
                .iter()
                .filter(|g| g.tools().contains(tool_name))
                .map(|g| g.name())
                .collect();

            assert!(
                owners.len() <= 1,
                "{} belongs to several groups: {:?}",
                tool_name,
                owners
            );
            assert_eq!(
                owners.len() == 1,
                !ungrouped.contains(tool_name),
                "{}: assign it to an ExposeGroup or add it to UNGROUPED_TOOLS",
                tool_name
            );
        }

        for tool in UNGROUPED_TOOLS {
            assert!(
                TOOL_METADATA.contains_key(tool),
                "UNGROUPED_TOOLS names {}, which is not in the registry",
                tool
            );
        }
    }

    #[test]
    fn test_expose_parse() {
        assert_eq!(ExposeGroup::parse("code"), Some(ExposeGroup::Code));
        assert_eq!(ExposeGroup::parse("CODE"), Some(ExposeGroup::Code));
        assert_eq!(
            ExposeGroup::parse("supply-chain"),
            Some(ExposeGroup::SupplyChain)
        );
        assert_eq!(
            ExposeGroup::parse("supply_chain"),
            Some(ExposeGroup::SupplyChain)
        );
        assert_eq!(ExposeGroup::parse("analysis"), Some(ExposeGroup::Analysis));
        assert_eq!(ExposeGroup::parse("structure"), None);
    }

    #[test]
    fn test_expose_union_always_folds_in_base() {
        let tools = ExposeGroup::union(&[ExposeGroup::Git]);
        assert!(tools.contains("get_blame"));
        assert!(tools.contains("list_repos"), "base must always be present");
        assert!(!tools.contains("find_symbols"));
    }

    /// Empty means "no group filter", not "expose nothing" — the filter falls
    /// back to the preset.
    #[test]
    fn test_expose_union_empty_is_empty() {
        assert!(ExposeGroup::union(&[]).is_empty());
    }

    #[test]
    fn test_expose_of_names_the_owning_group() {
        assert_eq!(ExposeGroup::of("get_callers"), Some(ExposeGroup::Code));
        assert_eq!(ExposeGroup::of("get_blame"), Some(ExposeGroup::Git));
        assert_eq!(ExposeGroup::of("find_dead_stores"), Some(ExposeGroup::Lint));
        assert_eq!(
            ExposeGroup::of("get_complexity"),
            Some(ExposeGroup::Analysis)
        );
        assert_eq!(ExposeGroup::of("neural_search"), None);
    }

    /// The two kept in `code` earn it by answering something the caller cannot
    /// derive from source it is already holding; the rest moved to `analysis`.
    #[test]
    fn test_code_keeps_the_retrieval_shaped_graph_tools() {
        let code = ExposeGroup::Code.tools();
        assert!(code.contains("get_call_graph"), "saves a round trip");
        assert!(code.contains("get_reaching_definitions"), "retrieval");

        let analysis = ExposeGroup::Analysis.tools();
        for restated in [
            "get_complexity",
            "get_control_flow",
            "get_data_flow",
            "get_import_graph",
            "get_function_hotspots",
            "find_circular_imports",
            "find_unused_exports",
        ] {
            assert!(
                analysis.contains(restated),
                "{restated} belongs to analysis"
            );
            assert!(!code.contains(restated), "{restated} must leave code");
        }
    }
}
