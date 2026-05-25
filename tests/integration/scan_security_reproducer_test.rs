//! Integration reproducers for `Index::scan_security` coverage gaps.
//!
//! These tests drive the real `CodeIntelEngine::scan_security` entry
//! point against on-disk multi-file C fixtures, exercising file-cache
//! enumeration, language classification, default-ruleset selection,
//! and `CallGraphContext` construction — none of which the lib-level
//! tests cover (they use synthetic source strings + `MockContext`).

use anyhow::Result;
use narsil_mcp::index::{CodeIntelEngine, EngineOptions, SecurityScanOptions};
use std::path::PathBuf;
use tempfile::TempDir;

const HELPER_C: &str = "\
int asprintf(char **, const char *, ...);

char *format_into_buf(const char *base) {
    char *out;
    int ret = asprintf(&out, \"%s\", base);
    if (ret < 0) return 0;
    return out;
}
";

const CALLER_C: &str = "\
char *format_into_buf(const char *);
int sprintf(char *, const char *, ...);

void use(const char *base, const char *prefix) {
    char *name = format_into_buf(base);
    sprintf(name, \"%s#%s\", prefix, base);
}
";

/// Builds an engine with `EngineOptions::default()` — the exact configuration
/// used by the MCP server when launched without `--call-graph`, which is the
/// failure mode the 2026-05-25 coverage report reproduces.
async fn build_engine(repo_path: PathBuf) -> Result<(CodeIntelEngine, TempDir)> {
    let index_tmp = TempDir::new()?;
    let index_path = index_tmp.path().to_path_buf();
    let engine =
        CodeIntelEngine::with_options(index_path, vec![repo_path], EngineOptions::default())
            .await?;
    engine.complete_initialization().await?;
    Ok((engine, index_tmp))
}

#[tokio::test]
async fn scan_security_emits_cwe_122_for_cross_tu_asprintf_then_sprintf_overflow() -> Result<()> {
    let repo_tmp = TempDir::new()?;
    let repo_path = repo_tmp.path().to_path_buf();
    std::fs::write(repo_path.join("helper.c"), HELPER_C)?;
    std::fs::write(repo_path.join("caller.c"), CALLER_C)?;

    let (engine, _index_tmp) = build_engine(repo_path.clone()).await?;
    let repo_name = repo_path.to_str().unwrap();

    let report = engine
        .scan_security(repo_name, SecurityScanOptions::default())
        .await?;

    let scanned_zero = report.contains("**Files Scanned**: 0\n");
    assert!(
        !scanned_zero,
        "scan_security reported zero C files scanned — engine-blind-to-C failure mode.\n\
         Full report:\n{report}"
    );

    let mentions_caller = report.contains("caller.c");
    let mentions_cwe_122 = report.contains("CWE-122");
    assert!(
        mentions_caller && mentions_cwe_122,
        "expected a CWE-122 finding on caller.c (cross-TU asprintf→sprintf overflow).\n\
         caller.c mentioned: {mentions_caller}\n\
         CWE-122 mentioned:  {mentions_cwe_122}\n\
         Full report:\n{report}"
    );

    let helper_only = engine
        .scan_security(
            repo_name,
            SecurityScanOptions {
                path: Some("helper.c"),
                ..Default::default()
            },
        )
        .await?;
    assert!(
        !(helper_only.contains("caller.c") && helper_only.contains("CWE-122")),
        "scanning only helper.c must not emit CWE-122 for caller.c (confirms cross-TU dependency).\n\
         Report:\n{helper_only}"
    );

    Ok(())
}
