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

const SINGLE_TU_C: &str = "\
unsigned long strlen(const char *);
void *calloc(unsigned long, unsigned long);
char *strcpy(char *, const char *);

void missing_check(const char *src) {
    unsigned long opts_len = strlen(src) + 1;
    char *buf = calloc(1, opts_len);
    strcpy(buf, src);
}

void has_check(const char *src) {
    unsigned long opts_len = strlen(src) + 1;
    char *buf = calloc(1, opts_len);
    if (!buf) return;
    strcpy(buf, src);
}
";

/// Builds an engine with `EngineOptions::default()` — the exact configuration
/// used by the MCP server when launched without `--call-graph`, which is the
/// failure mode the 2026-05-25 coverage report reproduces.
async fn build_engine(repo_path: PathBuf) -> Result<(CodeIntelEngine, TempDir)> {
    build_engine_with(repo_path, EngineOptions::default()).await
}

async fn build_engine_with(
    repo_path: PathBuf,
    opts: EngineOptions,
) -> Result<(CodeIntelEngine, TempDir)> {
    let index_tmp = TempDir::new()?;
    let index_path = index_tmp.path().to_path_buf();
    let engine = CodeIntelEngine::with_options(index_path, vec![repo_path], opts).await?;
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

#[tokio::test]
async fn scan_security_emits_cwe_476_for_calloc_without_null_check() -> Result<()> {
    let repo_tmp = TempDir::new()?;
    let repo_path = repo_tmp.path().to_path_buf();
    std::fs::write(repo_path.join("single_tu.c"), SINGLE_TU_C)?;

    let (engine, _index_tmp) = build_engine(repo_path.clone()).await?;
    let repo_name = repo_path.to_str().unwrap();

    let report = engine
        .scan_security(repo_name, SecurityScanOptions::default())
        .await?;

    let scanned_zero = report.contains("**Files Scanned**: 0\n");
    assert!(
        !scanned_zero,
        "scan_security reported zero C files scanned.\n\
         Full report:\n{report}"
    );

    assert!(
        report.contains("the audit IS the review"),
        "scan_security report must include the directive heuristic-severity \
         hint that forbids deferring verification of findings in privileged \
         code to a 'separate review'.\n\
         Full report:\n{report}"
    );

    // Positive: missing_check should produce a CWE-476-002 finding.
    let cwe476_002 = report.contains("CWE-476-002");
    let mentions_missing = report.contains("missing_check") || report.contains("'buf'");
    assert!(
        cwe476_002 && mentions_missing,
        "expected a CWE-476-002 finding referencing missing_check / 'buf'.\n\
         CWE-476-002 present: {cwe476_002}\n\
         missing_check/'buf' present: {mentions_missing}\n\
         Full report:\n{report}"
    );

    // Negative: has_check must not produce a CWE-476-002 finding.
    // The finding message format is "'<pointer>' from <allocator>() used
    // without NULL check"; both functions name their pointer `buf`, so we
    // disambiguate by line number — has_check's strcpy is on a different
    // line than missing_check's.
    //
    // Simpler structural assertion: the rule must emit exactly one
    // CWE-476-002 line. If it emits two, the negative case is also
    // flagged and the rule is over-greedy.
    //
    // The report header contains a heuristic-severity hint that mentions
    // CWE-476-002 as an example of an analytical rule; count occurrences
    // only in the findings section (past `**Files Scanned**`) so the
    // header mention doesn't confound the rule-emission count.
    let findings_section = report.split("**Files Scanned**").nth(1).unwrap_or("");
    let cwe476_002_count = findings_section.matches("CWE-476-002").count();
    assert_eq!(
        cwe476_002_count, 1,
        "expected exactly one CWE-476-002 finding (positive only); got {cwe476_002_count}.\n\
         Full report:\n{report}"
    );

    Ok(())
}

/// End-to-end regression for the `compile_commands.json` `file`-field
/// resolution bug. When `use_compile_commands: true` and the JSON's `file`
/// entries are *relative* (meson- and out-of-tree-CMake-shaped), the
/// indexer previously called `PathBuf::from(file).canonicalize()` — which
/// resolves relative to the process CWD, not the entry's `directory`
/// field — and produced an empty set. With an empty set, `index_repo`'s
/// `retain` filter at index.rs:695-708 drops every C source because
/// `compiled.contains(...)` is always false, so the file_cache for the
/// repo ends up with zero `.c` files and `scan_security` finds nothing
/// in C.
#[tokio::test]
async fn scan_security_with_compile_commands_resolves_relative_file_paths() -> Result<()> {
    let repo_tmp = TempDir::new()?;
    let repo_path = repo_tmp.path().to_path_buf();
    std::fs::create_dir_all(repo_path.join("lib"))?;
    std::fs::create_dir_all(repo_path.join("build"))?;
    std::fs::write(repo_path.join("lib/single_tu.c"), SINGLE_TU_C)?;

    let build_canonical = repo_path.join("build").canonicalize()?;
    let cc_json = format!(
        r#"[{{"directory": "{}", "command": "cc -c ../lib/single_tu.c", "file": "../lib/single_tu.c"}}]"#,
        build_canonical.display()
    );
    std::fs::write(repo_path.join("build/compile_commands.json"), cc_json)?;

    let opts = EngineOptions {
        use_compile_commands: true,
        ..Default::default()
    };
    let (engine, _index_tmp) = build_engine_with(repo_path.clone(), opts).await?;
    let repo_name = repo_path.to_str().unwrap();

    let report = engine
        .scan_security(repo_name, SecurityScanOptions::default())
        .await?;

    let scanned_zero = report.contains("**Files Scanned**: 0\n");
    assert!(
        !scanned_zero,
        "scan_security reported zero files scanned — compile_commands filter \
         dropped every C source. Full report:\n{report}"
    );

    let mentions_single_tu = report.contains("single_tu.c");
    let mentions_cwe = report.contains("CWE-476-002") || report.contains("CWE-122");
    assert!(
        mentions_single_tu && mentions_cwe,
        "expected a CWE finding referencing single_tu.c.\n\
         single_tu.c mentioned: {mentions_single_tu}\n\
         CWE-122 or CWE-476-002 present: {mentions_cwe}\n\
         Full report:\n{report}"
    );

    Ok(())
}
