use crate::config::schema::ToolConfig;
use crate::config::{validate_config, ConfigLoader, ExposeGroup};
use crate::tool_metadata::TOOL_METADATA;
use anyhow::{Context, Result};
use std::path::PathBuf;

/// Config CLI subcommands
#[derive(Debug, clap::Subcommand)]
pub enum ConfigCommand {
    /// Show the current effective configuration
    Show {
        /// Output format (yaml or json)
        #[arg(long, default_value = "yaml")]
        format: OutputFormat,

        /// Show configuration for specific repository
        #[arg(long)]
        repo: Option<PathBuf>,
    },

    /// Validate a configuration file
    Validate {
        /// Path to config file to validate
        path: PathBuf,

        /// Show verbose validation errors
        #[arg(short, long)]
        verbose: bool,
    },

    /// Export the current effective configuration
    Export {
        /// Output format (yaml or json)
        #[arg(long, default_value = "yaml")]
        format: OutputFormat,
    },

    /// List named repository profiles
    Profiles {
        /// Output format (table, yaml, json)
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },
}

/// Tools CLI subcommands
#[derive(Debug, clap::Subcommand)]
pub enum ToolsCommand {
    /// List available tools
    List {
        /// Filter by category
        #[arg(long)]
        category: Option<String>,

        /// Filter by --expose group (code, git, analysis)
        #[arg(long)]
        group: Option<String>,

        /// Output format (table, json, yaml, markdown)
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },

    /// Search for tools by name or description
    Search {
        /// Search query
        query: String,

        /// Output format (table, json, yaml)
        #[arg(long, default_value = "table")]
        format: OutputFormat,
    },

    /// Show detailed information about a specific tool
    Show {
        /// Tool name
        tool: String,

        /// Output format (yaml, json)
        #[arg(long, default_value = "yaml")]
        format: OutputFormat,
    },
}

#[derive(Debug, Clone, PartialEq, clap::ValueEnum)]
pub enum OutputFormat {
    Yaml,
    Json,
    Table,
    /// One table per expose group, for the generated block in docs/tools.md.
    Markdown,
}

/// Handle config subcommands
pub async fn handle_config_command(cmd: ConfigCommand) -> Result<()> {
    match cmd {
        ConfigCommand::Show { format, repo } => cmd_show(format, repo),
        ConfigCommand::Validate { path, verbose } => cmd_validate(path, verbose),
        ConfigCommand::Export { format } => cmd_export(format),
        ConfigCommand::Profiles { format } => cmd_profiles(format),
    }
}

/// Handle tools subcommands
pub fn handle_tools_command(cmd: ToolsCommand) -> Result<()> {
    match cmd {
        ToolsCommand::List {
            category,
            group,
            format,
        } => cmd_tools_list(category, group, format),
        ToolsCommand::Search { query, format } => cmd_tools_search(query, format),
        ToolsCommand::Show { tool, format } => cmd_tools_show(tool, format),
    }
}

fn cmd_show(format: OutputFormat, _repo: Option<PathBuf>) -> Result<()> {
    let loader = ConfigLoader::new();
    let config = loader.load().context("Failed to load configuration")?;

    match format {
        OutputFormat::Yaml => {
            let yaml = serde_saphyr::to_string(&config)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);
        }
        // Markdown only differs for `tools list`; render the table.
        OutputFormat::Table | OutputFormat::Markdown => {
            println!("Current Configuration:");
            println!("=====================");
            println!("Version: {}", config.version);
            if !config.expose.is_empty() {
                println!("Expose: {}", config.expose.join(", "));
            }
            if !config.tools.overrides.is_empty() {
                println!("\nTool Overrides:");
                for (name, override_cfg) in &config.tools.overrides {
                    println!(
                        "  - {}: {} {}",
                        name,
                        if override_cfg.enabled {
                            "enabled"
                        } else {
                            "disabled"
                        },
                        override_cfg
                            .reason
                            .as_deref()
                            .map(|r| format!("({})", r))
                            .unwrap_or_default()
                    );
                }
            }
        }
    }

    Ok(())
}

fn cmd_validate(path: PathBuf, verbose: bool) -> Result<()> {
    // Read and parse the file
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file: {:?}", path))?;

    let config: ToolConfig =
        serde_saphyr::from_str(&content).context("Failed to parse YAML config")?;

    // Validate the config
    match validate_config(&config) {
        Ok(_) => {
            println!("✓ Configuration is valid: {:?}", path);
            if verbose {
                println!("\nConfiguration summary:");
                println!("  Version: {}", config.version);
                println!("  Tool overrides: {}", config.tools.overrides.len());
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("✗ Configuration validation failed: {:?}", path);
            if verbose {
                eprintln!("\nError details:");
                eprintln!("  {:#}", e);
            } else {
                eprintln!("  {}", e);
                eprintln!("\nUse --verbose for detailed error information");
            }
            std::process::exit(1);
        }
    }
}

fn cmd_export(format: OutputFormat) -> Result<()> {
    let loader = ConfigLoader::new();
    let config = loader.load()?;

    match format {
        OutputFormat::Yaml => {
            let yaml = serde_saphyr::to_string(&config)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config)?;
            println!("{}", json);
        }
        // Markdown only differs for `tools list`; render the table.
        OutputFormat::Table | OutputFormat::Markdown => {
            eprintln!("Error: table format not supported for export, use yaml or json");
            std::process::exit(1);
        }
    }

    Ok(())
}

fn cmd_profiles(format: OutputFormat) -> Result<()> {
    let loader = ConfigLoader::new();
    let config = loader.load()?;
    let mut profiles: Vec<_> = config.profiles.iter().collect();
    profiles.sort_by_key(|(name, _)| *name);

    match format {
        // Markdown only differs for `tools list`; render the table.
        OutputFormat::Table | OutputFormat::Markdown => {
            if profiles.is_empty() {
                println!("No repository profiles configured.");
                return Ok(());
            }

            println!("Repository Profiles ({} total):", profiles.len());
            println!("{:-<80}", "");
            for (name, profile) in profiles {
                let features = [
                    ("git", profile.git),
                    ("call-graph", profile.call_graph),
                    ("persist", profile.persist),
                    ("watch", profile.watch),
                    ("lsp", profile.lsp),
                ]
                .into_iter()
                .filter_map(|(label, enabled)| enabled.unwrap_or(false).then_some(label))
                .collect::<Vec<_>>()
                .join(",");
                println!(
                    "{:<20} repos={:<3} discover={:<20} features={}",
                    name,
                    profile.repos.len(),
                    profile
                        .discover
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|| "-".to_string()),
                    if features.is_empty() {
                        "-"
                    } else {
                        features.as_str()
                    }
                );
            }
        }
        OutputFormat::Yaml => {
            let yaml = serde_saphyr::to_string(&config.profiles)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&config.profiles)?;
            println!("{}", json);
        }
    }

    Ok(())
}

/// Required arguments of a tool, minus `repo` — nearly every tool takes it, so
/// listing it in every row is noise.
fn required_args(meta: &crate::tool_metadata::ToolMetadata) -> String {
    let args: Vec<&str> = meta
        .input_schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|entries| {
            entries
                .iter()
                .filter_map(|v| v.as_str())
                .filter(|arg| *arg != "repo")
                .collect()
        })
        .unwrap_or_default();

    if args.is_empty() {
        "—".to_string()
    } else {
        args.join(", ")
    }
}

/// First sentence of a description, escaped so it cannot break the table.
fn summarize(description: &str) -> String {
    description
        .split(". ")
        .next()
        .unwrap_or(description)
        .trim_end_matches('.')
        .replace('|', "\\|")
}

fn cmd_tools_list(
    category: Option<String>,
    group: Option<String>,
    format: OutputFormat,
) -> Result<()> {
    let group = match group {
        Some(name) => Some(ExposeGroup::parse(&name).ok_or_else(|| {
            let valid: Vec<&str> = ExposeGroup::ALL.iter().map(|g| g.name()).collect();
            anyhow::anyhow!(
                "Unknown --group '{}'. Valid groups: {}",
                name,
                valid.join(", ")
            )
        })?),
        None => None,
    };

    let tools: Vec<_> = TOOL_METADATA
        .iter()
        .filter(|(_, meta)| match &category {
            Some(cat) => meta.category.to_string() == *cat,
            None => true,
        })
        .filter(|(name, _)| match group {
            Some(g) => g.tools().contains(*name),
            None => true,
        })
        .collect();

    match format {
        OutputFormat::Markdown => {
            // One table per group, in --help order, so the output can be
            // pasted between the generated markers in docs/tools.md.
            let groups: Vec<ExposeGroup> = match group {
                Some(g) => vec![g],
                None => ExposeGroup::ALL.to_vec(),
            };

            for g in groups {
                let mut names: Vec<&str> = tools
                    .iter()
                    .map(|(name, _)| **name)
                    .filter(|name| g.tools().contains(name))
                    .collect();
                if names.is_empty() {
                    continue;
                }
                names.sort_unstable();

                println!("\n### `{}`\n", g.name());
                println!("| tool | required args | what it answers |");
                println!("|---|---|---|");
                for name in names {
                    if let Some(meta) = TOOL_METADATA.get(name) {
                        println!(
                            "| `{}` | {} | {} |",
                            name,
                            required_args(meta),
                            summarize(meta.description)
                        );
                    }
                }
            }
        }
        OutputFormat::Table => {
            println!("Available Tools ({} total):", tools.len());
            println!("{:-<80}", "");
            for (name, meta) in tools {
                println!("{:<30} {:<15} {}", name, meta.category, meta.description);
            }
        }
        OutputFormat::Yaml => {
            let tools_data: Vec<_> = tools
                .iter()
                .map(|(name, meta)| {
                    serde_json::json!({
                        "name": name,
                        "category": meta.category.to_string(),
                        "description": meta.description,
                        "stability": format!("{:?}", meta.stability),
                        "performance": format!("{:?}", meta.performance),
                    })
                })
                .collect();
            let yaml = serde_saphyr::to_string(&tools_data)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let tools_data: Vec<_> = tools
                .iter()
                .map(|(name, meta)| {
                    serde_json::json!({
                        "name": name,
                        "category": meta.category.to_string(),
                        "description": meta.description,
                        "stability": format!("{:?}", meta.stability),
                        "performance": format!("{:?}", meta.performance),
                    })
                })
                .collect();
            let json = serde_json::to_string_pretty(&tools_data)?;
            println!("{}", json);
        }
    }

    Ok(())
}

fn cmd_tools_search(query: String, format: OutputFormat) -> Result<()> {
    let query_lower = query.to_lowercase();
    let matching_tools: Vec<_> = TOOL_METADATA
        .iter()
        .filter(|(name, meta)| {
            name.to_lowercase().contains(&query_lower)
                || meta.description.to_lowercase().contains(&query_lower)
                || meta
                    .category
                    .to_string()
                    .to_lowercase()
                    .contains(&query_lower)
        })
        .collect();

    if matching_tools.is_empty() {
        println!("No tools found matching '{}'", query);
        return Ok(());
    }

    match format {
        // Markdown only differs for `tools list`; render the table.
        OutputFormat::Table | OutputFormat::Markdown => {
            println!(
                "Tools matching '{}' ({} found):",
                query,
                matching_tools.len()
            );
            println!("{:-<80}", "");
            for (name, meta) in matching_tools {
                println!("{:<30} {:<15} {}", name, meta.category, meta.description);
            }
        }
        OutputFormat::Yaml | OutputFormat::Json => {
            let tools_data: Vec<_> = matching_tools
                .iter()
                .map(|(name, meta)| {
                    serde_json::json!({
                        "name": name,
                        "category": meta.category.to_string(),
                        "description": meta.description,
                    })
                })
                .collect();

            if format == OutputFormat::Yaml {
                let yaml = serde_saphyr::to_string(&tools_data)?;
                println!("{}", yaml);
            } else {
                let json = serde_json::to_string_pretty(&tools_data)?;
                println!("{}", json);
            }
        }
    }

    Ok(())
}

fn cmd_tools_show(tool: String, format: OutputFormat) -> Result<()> {
    let meta = TOOL_METADATA
        .get(tool.as_str())
        .with_context(|| format!("Tool '{}' not found", tool))?;

    match format {
        OutputFormat::Yaml => {
            let data = serde_json::json!({
                "name": tool,
                "description": meta.description,
                "category": meta.category.to_string(),
                "stability": format!("{:?}", meta.stability),
                "performance": format!("{:?}", meta.performance),
                "requires_api_key": meta.requires_api_key,
                "required_flags": meta.required_flags.iter().map(|f| format!("{:?}", f)).collect::<Vec<_>>(),
                "input_schema": meta.input_schema,
            });
            let yaml = serde_saphyr::to_string(&data)?;
            println!("{}", yaml);
        }
        OutputFormat::Json => {
            let data = serde_json::json!({
                "name": tool,
                "description": meta.description,
                "category": meta.category.to_string(),
                "stability": format!("{:?}", meta.stability),
                "performance": format!("{:?}", meta.performance),
                "requires_api_key": meta.requires_api_key,
                "required_flags": meta.required_flags.iter().map(|f| format!("{:?}", f)).collect::<Vec<_>>(),
                "input_schema": meta.input_schema,
            });
            let json = serde_json::to_string_pretty(&data)?;
            println!("{}", json);
        }
        // Markdown only differs for `tools list`; render the table.
        OutputFormat::Table | OutputFormat::Markdown => {
            println!("Tool: {}", tool);
            println!("{:-<80}", "");
            println!("Description: {}", meta.description);
            println!("Category: {}", meta.category);
            println!("Stability: {:?}", meta.stability);
            println!("Performance: {:?}", meta.performance);
            println!("Requires API Key: {}", meta.requires_api_key);
            if !meta.required_flags.is_empty() {
                println!("Required Flags: {:?}", meta.required_flags);
            }
            println!("\nInput Schema:");
            println!("{}", serde_json::to_string_pretty(&meta.input_schema)?);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_output_format_variants() {
        // Ensure OutputFormat enum has expected variants
        let _ = OutputFormat::Yaml;
        let _ = OutputFormat::Json;
        let _ = OutputFormat::Table;
    }
}
