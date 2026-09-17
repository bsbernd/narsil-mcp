//! Shared input validation utilities for security hardening.
//!
//! This module provides reusable validation functions used across the codebase
//! to prevent command injection and path traversal.

use std::path::Path;

/// Characters forbidden in shell-sensitive contexts.
const SHELL_METACHARACTERS: &[char] = &[
    ';', '|', '&', '`', '$', '(', ')', '>', '<', '{', '}', '!', '\n', '\r', '\0', '\'', '"',
];

/// Validates that an LSP server path is safe to execute.
///
/// Blocks shell metacharacters and requires the path to be either a bare command name
/// or an absolute path (no relative traversal).
///
/// # Errors
///
/// Returns an error if the path contains shell metacharacters or is a relative path
/// with traversal components.
pub fn validate_lsp_server_path(path: &str) -> Result<(), String> {
    if path.is_empty() {
        return Err("LSP server path cannot be empty".to_string());
    }

    for ch in path.chars() {
        if SHELL_METACHARACTERS.contains(&ch) {
            return Err(format!(
                "LSP server path contains forbidden character: {:?}",
                ch
            ));
        }
    }

    // If it looks like a path (contains separator), it must be absolute
    if path.contains('/') || path.contains('\\') {
        if path.contains("..") {
            return Err("LSP server path cannot contain '..' (path traversal)".to_string());
        }
        if !path.starts_with('/') && !path.starts_with('\\') {
            // Allow drive letters on Windows (e.g., C:\...)
            let has_drive_letter = path.len() >= 3
                && path.as_bytes()[0].is_ascii_alphabetic()
                && path.as_bytes()[1] == b':';
            if !has_drive_letter {
                return Err("LSP server path with directories must be absolute".to_string());
            }
        }
    }

    Ok(())
}

/// Whether `name` resolves to an executable file.
///
/// A name containing a path separator is checked as-is; a bare name is
/// searched on `$PATH`. Used to auto-enable optional C/C++ backends
/// (clangd, ccls, gtags) only when their binary is actually installed.
pub(crate) fn binary_on_path(name: &str) -> bool {
    if name.contains('/') || name.contains('\\') {
        return is_executable_file(Path::new(name));
    }
    match std::env::var_os("PATH") {
        Some(path) => std::env::split_paths(&path).any(|dir| is_executable_file(&dir.join(name))),
        None => false,
    }
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    // Any of the execute bits (owner/group/other) qualifies as runnable.
    std::fs::metadata(path)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // validate_lsp_server_path tests
    // ========================================================================

    #[test]
    fn test_validate_lsp_path_rejects_malicious() {
        assert!(validate_lsp_server_path(";whoami").is_err());
        assert!(validate_lsp_server_path("$(cat /etc/passwd)").is_err());
        assert!(validate_lsp_server_path("`id`").is_err());
    }

    #[test]
    fn test_validate_lsp_path_rejects_relative_traversal() {
        assert!(validate_lsp_server_path("../../bin/evil").is_err());
        assert!(validate_lsp_server_path("relative/path").is_err());
    }

    #[test]
    fn test_validate_lsp_path_accepts_valid() {
        assert!(validate_lsp_server_path("rust-analyzer").is_ok());
        assert!(validate_lsp_server_path("/usr/bin/rust-analyzer").is_ok());
        assert!(validate_lsp_server_path("clangd").is_ok());
    }

    // ========================================================================
    // binary_on_path tests
    // ========================================================================

    #[test]
    fn test_binary_on_path_accepts_executable_absolute_path() {
        // The running test binary is itself an executable file. Passing its
        // absolute path exercises the path-separator branch.
        let exe = std::env::current_exe().unwrap();
        assert!(binary_on_path(exe.to_str().unwrap()));
    }

    #[test]
    fn test_binary_on_path_rejects_missing_binary() {
        // A bare name not on PATH exercises the PATH-search branch.
        assert!(!binary_on_path("narsil-definitely-not-a-real-binary-xyzzy"));
    }

    #[cfg(unix)]
    #[test]
    fn test_binary_on_path_rejects_non_executable_file() {
        // A regular file without an execute bit must not count as a binary.
        assert!(!binary_on_path("/etc/hosts"));
    }
}
