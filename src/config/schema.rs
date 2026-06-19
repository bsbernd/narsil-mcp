/// Configuration schema structures
///
/// These structures define the YAML configuration format for narsil-mcp.
/// They are designed to be serialized/deserialized with serde.
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Default version for configuration
fn default_version() -> String {
    "1.0".to_string()
}

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolConfig {
    /// Configuration version (currently "1.0")
    #[serde(default = "default_version")]
    pub version: String,

    /// Optional preset name (minimal, balanced, full, security-focused)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,

    /// Editor-specific configurations (optional)
    #[serde(default)]
    pub editors: HashMap<String, serde_json::Value>,

    /// Named repository profiles for reusable workspace path sets.
    #[serde(default)]
    pub profiles: HashMap<String, RepoProfile>,

    /// Tool configuration (categories and overrides)
    /// Defaults to empty config when using preset-only configurations
    #[serde(default)]
    pub tools: ToolsConfig,

    /// Performance budgets and limits
    #[serde(default)]
    pub performance: PerformanceConfig,

    /// Feature flag requirements (optional)
    #[serde(default)]
    pub feature_requirements: HashMap<String, serde_json::Value>,
}

impl Default for ToolConfig {
    fn default() -> Self {
        Self {
            version: default_version(),
            preset: None,
            editors: HashMap::new(),
            profiles: HashMap::new(),
            tools: ToolsConfig::default(),
            performance: PerformanceConfig::default(),
            feature_requirements: HashMap::new(),
        }
    }
}

/// One repository in a profile: either a bare path (all defaults) or a path
/// with per-repo overrides. The untagged enum lets a YAML list mix both forms.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RepoEntry {
    /// `- ~/src/foo` — index the whole repo with the global defaults.
    Path(PathBuf),
    /// `- { path: ..., index_filter: [...], background_index: false }`.
    Detailed(RepoEntrySettings),
}

/// Per-repo overrides for a profile entry. `index_filter`/`lsp_scope` accept
/// paths relative to the repo root (no need to repeat the absolute prefix);
/// absolute entries are also matched against the absolute path.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoEntrySettings {
    /// Repository path.
    pub path: PathBuf,

    /// clangd/ccls background indexing for this repo. None = use the default
    /// (enabled). Set false on huge C repos to bound the language server.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub background_index: Option<bool>,

    /// clangd/ccls augment passes (documentSymbol + callHierarchy) for this
    /// repo. None = enabled. Set false to index with tree-sitter + gtags only,
    /// skipping the language server entirely (no warm-up, no server start).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsp: Option<bool>,

    /// Restrict the base (tree-sitter) index to these paths for this repo.
    /// Overrides the global --index-filter when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub index_filter: Vec<String>,

    /// Restrict the clangd/ccls augment pass to these paths for this repo.
    /// Overrides the global --lsp-scope when non-empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lsp_scope: Vec<String>,
}

impl RepoEntry {
    /// The repository path, regardless of entry form.
    pub fn path(&self) -> &Path {
        match self {
            RepoEntry::Path(path) => path,
            RepoEntry::Detailed(settings) => &settings.path,
        }
    }

    /// The per-repo overrides; a bare path yields all-default settings.
    pub fn settings(&self) -> RepoEntrySettings {
        match self {
            RepoEntry::Path(path) => RepoEntrySettings {
                path: path.clone(),
                ..Default::default()
            },
            RepoEntry::Detailed(settings) => settings.clone(),
        }
    }
}

/// Named workspace profile selected with `--profile NAME`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoProfile {
    /// Repository entries to index when this profile is selected. Each entry is
    /// a bare path or a path with per-repo overrides.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub repos: Vec<RepoEntry>,

    /// Optional directory to auto-discover repositories from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discover: Option<PathBuf>,

    /// Optional tool preset to apply with this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<String>,

    /// Enable git integration for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git: Option<bool>,

    /// Enable call graph analysis for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub call_graph: Option<bool>,

    /// Enable persistent index storage for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persist: Option<bool>,

    /// Enable watch mode for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<bool>,

    /// Enable LSP integration for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lsp: Option<bool>,

    /// Enable remote GitHub repository support for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<bool>,

    /// Enable neural search for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub neural: Option<bool>,

    /// Enable graph/SPARQL/CCG tools for this profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub graph: Option<bool>,

    /// TF-IDF embedding dimension (default: 512). Lower values reduce memory;
    /// higher values improve find_similar_code accuracy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dim: Option<usize>,

    /// When true, use compile_commands.json to restrict which C/C++ source files
    /// are indexed. Headers are always indexed regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub use_compile_commands: Option<bool>,

    /// Path to compile_commands.json, relative to the repo root.
    /// Defaults to "compile_commands.json".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_commands_path: Option<PathBuf>,

    /// Glob patterns (relative to repo root) for files to always index,
    /// regardless of compile_commands filtering.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub include: Vec<String>,
}

/// Tools configuration (categories and overrides)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ToolsConfig {
    /// Category-level configuration
    #[serde(default)]
    pub categories: HashMap<String, CategoryConfig>,

    /// Individual tool overrides
    #[serde(default)]
    pub overrides: HashMap<String, ToolOverride>,
}

/// Category-level configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryConfig {
    /// Whether this category is enabled
    pub enabled: bool,

    /// Optional description of the category
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Required feature flags for this category
    #[serde(default)]
    pub required_flags: Vec<String>,

    /// Additional category-specific configuration
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,
}

/// Individual tool override configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolOverride {
    /// Whether this tool is enabled
    pub enabled: bool,

    /// Optional reason for the override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    /// Required feature flags for this tool
    #[serde(default)]
    pub required_flags: Vec<String>,

    /// Tool-specific configuration
    #[serde(default)]
    pub config: HashMap<String, serde_json::Value>,

    /// Performance impact indicator (low, medium, high)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub performance_impact: Option<String>,

    /// Whether this tool requires an API key
    #[serde(default)]
    pub requires_api_key: bool,
}

/// Performance configuration with budgets and limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// Maximum number of tools to expose
    #[serde(default = "default_max_tool_count")]
    pub max_tool_count: usize,

    /// Maximum acceptable startup latency in milliseconds
    #[serde(default = "default_startup_latency")]
    pub startup_latency_ms: u64,

    /// Maximum acceptable filtering latency in milliseconds
    #[serde(default = "default_filtering_latency")]
    pub filtering_latency_ms: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            // Sized to comfortably hold the full MCP tool registry (90 today)
            // with headroom; raise as new tools land. The Full preset bypasses
            // this cap entirely (see `ToolFilter::get_enabled_tools`).
            max_tool_count: 128,
            startup_latency_ms: 10,
            filtering_latency_ms: 1,
        }
    }
}

fn default_max_tool_count() -> usize {
    128
}

fn default_startup_latency() -> u64 {
    10
}

fn default_filtering_latency() -> u64 {
    1
}

impl ToolConfig {
    /// Check if a specific category is enabled
    pub fn is_category_enabled(&self, category: &str) -> bool {
        self.tools
            .categories
            .get(category)
            .map(|c| c.enabled)
            .unwrap_or(true) // Default to enabled if not specified
    }

    /// Check if a specific tool is enabled (considering overrides)
    pub fn is_tool_enabled(&self, tool_name: &str) -> bool {
        self.tools
            .overrides
            .get(tool_name)
            .map(|o| o.enabled)
            .unwrap_or(true) // Default to enabled if not overridden
    }

    /// Get the performance impact for a tool if specified
    pub fn get_tool_performance_impact(&self, tool_name: &str) -> Option<&str> {
        self.tools
            .overrides
            .get(tool_name)
            .and_then(|o| o.performance_impact.as_deref())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_performance_config() {
        let perf = PerformanceConfig::default();
        assert_eq!(perf.max_tool_count, 128);
        assert_eq!(perf.startup_latency_ms, 10);
        assert_eq!(perf.filtering_latency_ms, 1);
    }

    #[test]
    fn test_default_tool_config() {
        let config = ToolConfig::default();
        assert_eq!(config.version, "1.0");
        assert!(config.profiles.is_empty());
        assert!(config.tools.categories.is_empty());
        assert!(config.tools.overrides.is_empty());
    }

    #[test]
    fn test_category_enabled_default() {
        let config = ToolConfig::default();
        // Categories not specified should default to enabled
        assert!(config.is_category_enabled("Repository"));
    }

    #[test]
    fn test_tool_enabled_default() {
        let config = ToolConfig::default();
        // Tools not overridden should default to enabled
        assert!(config.is_tool_enabled("list_repos"));
    }

    #[test]
    fn test_preset_only_config() {
        // Issue #5: Preset-only configs should parse without requiring tools field
        let yaml = r#"
version: "1.0"
preset: "full"
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.version, "1.0");
        assert_eq!(config.preset, Some("full".to_string()));
        assert!(config.tools.categories.is_empty());
        assert!(config.tools.overrides.is_empty());
    }

    #[test]
    fn test_repo_profile_config() {
        let yaml = r#"
version: "1.0"
profiles:
  work:
    repos:
      - ~/src/api
      - ~/src/web
    git: true
    call_graph: true
    preset: balanced
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        let profile = config.profiles.get("work").unwrap();
        assert_eq!(profile.repos.len(), 2);
        assert!(matches!(profile.repos[0], RepoEntry::Path(_)));
        assert_eq!(profile.git, Some(true));
        assert_eq!(profile.call_graph, Some(true));
        assert_eq!(profile.preset.as_deref(), Some("balanced"));
    }

    #[test]
    fn test_repo_entry_mixed_bare_and_detailed() {
        let yaml = r#"
profiles:
  work:
    repos:
      - ~/src/liburing
      - path: ~/src/linux
        background_index: false
        lsp: false
        index_filter: [fs, mm, io_uring]
        lsp_scope: [fs/fuse]
"#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        let profile = config.profiles.get("work").unwrap();
        assert_eq!(profile.repos.len(), 2);

        // Bare path -> all defaults.
        let bare = profile.repos[0].settings();
        assert_eq!(bare.background_index, None);
        assert_eq!(bare.lsp, None);
        assert!(bare.index_filter.is_empty());

        // Detailed entry -> overrides carried through.
        let detailed = profile.repos[1].settings();
        assert_eq!(detailed.path, PathBuf::from("~/src/linux"));
        assert_eq!(detailed.background_index, Some(false));
        assert_eq!(detailed.lsp, Some(false));
        assert_eq!(detailed.index_filter, vec!["fs", "mm", "io_uring"]);
        assert_eq!(detailed.lsp_scope, vec!["fs/fuse"]);
    }

    #[test]
    fn test_minimal_preset_config() {
        // Even more minimal - just preset
        let yaml = r#"preset: "minimal""#;
        let config: ToolConfig = serde_saphyr::from_str(yaml).unwrap();
        assert_eq!(config.preset, Some("minimal".to_string()));
        assert_eq!(config.version, "1.0"); // Should use default
    }
}
