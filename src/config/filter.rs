/// Tool filtering based on configuration and feature flags
///
/// Converts EngineOptions and ToolConfig into a filtered list of enabled tools.
/// Must complete in <1ms for responsive tool list queries.
use crate::config::expose::ExposeGroup;
use crate::config::schema::ToolConfig;
use crate::index::EngineOptions;
use crate::tool_metadata::{FeatureFlag, ToolMetadata, TOOL_METADATA};
use std::collections::HashSet;

/// Tool filter that applies configuration to determine enabled tools
pub struct ToolFilter {
    config: ToolConfig,
    enabled_flags: HashSet<FeatureFlag>,
    /// Tool whitelist from `--expose`, already unioned across groups. Empty
    /// means no group filter was requested.
    expose: HashSet<&'static str>,
}

impl ToolFilter {
    /// Create a new tool filter
    pub fn new(config: ToolConfig, engine_options: &EngineOptions) -> Self {
        let enabled_flags = Self::convert_engine_options(engine_options);

        // A top-level `expose:` in config.yaml is the machine-wide default,
        // for invocations whose command line comes from an editor plugin.
        // with_expose overrides it when the CLI/env/profile supplied groups.
        let expose = ExposeGroup::union(&Self::parse_config_expose(&config.expose));

        Self {
            config,
            enabled_flags,
            expose,
        }
    }

    /// Resolve `expose:` entries from config, naming any that are not groups
    /// rather than silently dropping them — a typo in a config file is
    /// otherwise invisible.
    fn parse_config_expose(names: &[String]) -> Vec<ExposeGroup> {
        names
            .iter()
            .filter_map(|name| {
                let group = ExposeGroup::parse(name);
                if group.is_none() {
                    let valid: Vec<&str> = ExposeGroup::ALL.iter().map(|g| g.name()).collect();
                    tracing::warn!(
                        "config: ignoring unknown expose group '{}'. Valid groups: {}",
                        name,
                        valid.join(", ")
                    );
                }
                group
            })
            .collect()
    }

    /// Narrow the filter to the given `--expose` groups. An empty slice keeps
    /// whatever the config file asked for, so a caller that never saw the flag
    /// does not clear the machine-wide default.
    pub fn with_expose(mut self, groups: &[ExposeGroup]) -> Self {
        if !groups.is_empty() {
            self.expose = ExposeGroup::union(groups);
        }
        self
    }

    /// Convert EngineOptions to a set of FeatureFlags
    pub fn convert_engine_options(options: &EngineOptions) -> HashSet<FeatureFlag> {
        let mut flags = HashSet::new();

        if options.git_enabled {
            flags.insert(FeatureFlag::Git);
        }
        if options.call_graph_enabled {
            flags.insert(FeatureFlag::CallGraph);
        }
        if options.persist_enabled {
            flags.insert(FeatureFlag::Persist);
        }
        if options.watch_enabled {
            flags.insert(FeatureFlag::Watch);
        }
        if options.lsp_config.enabled {
            flags.insert(FeatureFlag::Lsp);
        }

        flags
    }

    /// Get the list of enabled tools based on configuration and flags.
    pub fn get_enabled_tools(&self) -> Vec<&'static str> {
        TOOL_METADATA
            .iter()
            .filter(|(tool_name, metadata)| self.is_tool_enabled(tool_name, metadata))
            .map(|(tool_name, _)| *tool_name)
            .collect()
    }

    fn is_tool_enabled(&self, tool_name: &str, metadata: &ToolMetadata) -> bool {
        // 1. Check tool-level override first (highest priority)
        if let Some(override_config) = self.config.tools.overrides.get(tool_name) {
            if !override_config.enabled {
                return false; // Explicitly disabled
            }
            // If explicitly enabled via override, still need to check required flags
        }

        // 2. Check the --expose group whitelist.
        if !self.expose.is_empty() && !self.expose.contains(tool_name) {
            return false;
        }

        // 3. Check required feature flags
        if !metadata.required_flags.is_empty() {
            // Tool requires specific flags - must have ALL of them
            for required_flag in &metadata.required_flags {
                if !self.enabled_flags.contains(required_flag) {
                    return false; // Missing required flag
                }
            }
        }

        // 4. All checks passed
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::schema::ToolOverride;
    use std::collections::HashMap;

    #[test]
    fn test_convert_engine_options_all_enabled() {
        let options = EngineOptions {
            git_enabled: true,
            call_graph_enabled: true,
            persist_enabled: true,
            watch_enabled: true,
            lsp_config: crate::lsp::LspConfig {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };

        let flags = ToolFilter::convert_engine_options(&options);

        assert_eq!(flags.len(), 5);
        assert!(flags.contains(&FeatureFlag::Git));
        assert!(flags.contains(&FeatureFlag::CallGraph));
        assert!(flags.contains(&FeatureFlag::Persist));
        assert!(flags.contains(&FeatureFlag::Watch));
        assert!(flags.contains(&FeatureFlag::Lsp));
    }

    #[test]
    fn test_convert_engine_options_none_enabled() {
        let options = EngineOptions::default();
        let flags = ToolFilter::convert_engine_options(&options);
        assert_eq!(flags.len(), 0);
    }

    #[test]
    fn test_is_tool_enabled_basic() {
        let config = ToolConfig::default();
        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options);

        // list_repos requires no flags, should be enabled
        let meta = TOOL_METADATA.get("list_repos").unwrap();
        assert!(filter.is_tool_enabled("list_repos", meta));
    }

    #[test]
    fn test_is_tool_enabled_with_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions {
            git_enabled: true,
            ..Default::default()
        };

        let filter = ToolFilter::new(config, &options);

        // get_blame requires Git flag
        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_without_required_flag() {
        let config = ToolConfig::default();
        let options = EngineOptions::default(); // git_enabled = false

        let filter = ToolFilter::new(config, &options);

        // get_blame requires Git flag
        let meta = TOOL_METADATA.get("get_blame").unwrap();
        assert!(!filter.is_tool_enabled("get_blame", meta));
    }

    #[test]
    fn test_is_tool_enabled_override_disabled() {
        let mut config = ToolConfig::default();
        config.tools.overrides.insert(
            "list_repos".to_string(),
            ToolOverride {
                enabled: false,
                reason: Some("Test".to_string()),
                required_flags: vec![],
                config: HashMap::new(),
                performance_impact: None,
                requires_api_key: false,
            },
        );

        let options = EngineOptions::default();
        let filter = ToolFilter::new(config, &options);

        let meta = TOOL_METADATA.get("list_repos").unwrap();
        assert!(!filter.is_tool_enabled("list_repos", meta));
    }
}
