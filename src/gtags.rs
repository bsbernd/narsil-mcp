use std::path::{Path, PathBuf};
use tracing::debug;

/// Whether GNU Global's `global(1)` CLI is installed on `$PATH`.
///
/// Used to auto-enable gtags as a C/C++ reference backend only when it can
/// actually answer queries.
pub fn gtags_available() -> bool {
    crate::validation::binary_on_path("global")
}

/// Wrapper around the GNU Global `global(1)` CLI for C/C++ reference queries.
///
/// gtags --lsp is not available in common distros, so we drive global(1)
/// as a subprocess and parse its output.
pub struct GtagsManager {
    /// Roots are stored for potential future filtering; queries use the
    /// per-call repo_path argument.
    #[allow(dead_code)]
    repo_roots: Vec<PathBuf>,
}

impl GtagsManager {
    pub fn new(repo_roots: Vec<PathBuf>) -> Self {
        Self { repo_roots }
    }

    /// Run `global -rx SYMBOL` from `repo_path` and return parsed references.
    ///
    /// `global -rx` output format (space-separated, symbol col is fixed-width):
    ///   SYMBOL    LINE  FILE    SOURCE_TEXT
    ///
    /// Returns an empty vec when global is not installed, the GTAGS database
    /// is missing, or the symbol has no references.
    pub async fn find_references(
        &self,
        symbol: &str,
        repo_path: &Path,
    ) -> Vec<(String, usize, String)> {
        let output = tokio::process::Command::new("global")
            .args(["-rx", symbol])
            .current_dir(repo_path)
            .output()
            .await;

        match output {
            Err(e) => {
                debug!("gtags: global command unavailable: {}", e);
                vec![]
            }
            Ok(out) => Self::parse_output(&out.stdout, repo_path),
        }
    }

    fn parse_output(stdout: &[u8], repo_path: &Path) -> Vec<(String, usize, String)> {
        let text = String::from_utf8_lossy(stdout);
        let mut refs = Vec::new();

        for raw_line in text.lines() {
            // Tokenize: symbol, line_number, file_path, context...
            let mut tokens = raw_line.split_whitespace();
            let _symbol = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let line_str = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let file_str = match tokens.next() {
                Some(t) => t,
                None => continue,
            };
            let context: Vec<&str> = tokens.collect();
            let context = context.join(" ");

            let line_num: usize = match line_str.parse() {
                Ok(n) => n,
                Err(_) => continue,
            };

            // Make path relative to repo_root
            let rel = if file_str.starts_with('/') {
                let full = Path::new(file_str);
                full.strip_prefix(repo_path)
                    .unwrap_or(full)
                    .to_string_lossy()
                    .to_string()
            } else {
                file_str.to_string()
            };

            refs.push((rel, line_num, context));
        }

        refs
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_output_absolute_path() {
        let repo = PathBuf::from("/repo");
        let stdout = b"my_func          15 /repo/src/foo.c    my_func(arg);\n";
        let refs = GtagsManager::parse_output(stdout, &repo);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "src/foo.c");
        assert_eq!(refs[0].1, 15);
        assert_eq!(refs[0].2, "my_func(arg);");
    }

    #[test]
    fn test_parse_output_relative_path() {
        let repo = PathBuf::from("/repo");
        let stdout = b"my_func          42 src/bar.c    my_func();\n";
        let refs = GtagsManager::parse_output(stdout, &repo);
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].0, "src/bar.c");
        assert_eq!(refs[0].1, 42);
    }

    #[test]
    fn test_parse_output_empty() {
        let repo = PathBuf::from("/repo");
        let refs = GtagsManager::parse_output(b"", &repo);
        assert!(refs.is_empty());
    }

    #[test]
    fn test_parse_output_malformed_line_skipped() {
        let repo = PathBuf::from("/repo");
        // Only one token — should be silently skipped
        let stdout = b"only_symbol\n";
        let refs = GtagsManager::parse_output(stdout, &repo);
        assert!(refs.is_empty());
    }
}
