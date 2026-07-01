use narsil_mcp::index::CodeIntelEngine;
use std::fs;
use tempfile::TempDir;

/// Test that read_resource rejects paths outside indexed repositories
#[tokio::test]
async fn test_read_resource_path_traversal_protection() {
    // Create a temporary directory with a test repo
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();

    // Create a safe file inside the repo
    let safe_file = repo_path.join("safe.txt");
    fs::write(&safe_file, "safe content").unwrap();

    // Create a sensitive file outside the repo (in parent directory)
    let sensitive_file = temp_dir.path().join("sensitive.txt");
    fs::write(&sensitive_file, "sensitive data").unwrap();

    // Initialize the code intelligence engine
    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();

    // Complete initialization to index the repository
    engine.complete_initialization().await.unwrap();

    // Test 1: Reading a file inside the repository should succeed
    let safe_uri = format!("file://{}", safe_file.to_str().unwrap());
    let result = engine.read_resource(&safe_uri).await;
    assert!(
        result.is_ok(),
        "Should allow reading files within indexed repository"
    );
    assert_eq!(result.unwrap(), "safe content");

    // Test 2: Reading a file outside the repository should fail
    let malicious_uri = format!("file://{}", sensitive_file.to_str().unwrap());
    let result = engine.read_resource(&malicious_uri).await;
    assert!(
        result.is_err(),
        "Should block reading files outside indexed repositories"
    );

    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("Access denied") || error_msg.contains("outside"),
        "Error message should indicate access denial, got: {}",
        error_msg
    );

    // Test 3: Path traversal attempt using ../ should fail
    let traversal_uri = format!(
        "file://{}",
        repo_path.join("../sensitive.txt").to_str().unwrap()
    );
    let result = engine.read_resource(&traversal_uri).await;
    assert!(
        result.is_err(),
        "Should block path traversal attempts with ../"
    );

    // Test 4: Absolute path outside repo should fail
    let abs_path_uri = "file:///etc/passwd";
    let result = engine.read_resource(abs_path_uri).await;
    assert!(
        result.is_err(),
        "Should block absolute paths to system files"
    );
}

/// Test that read_resource handles non-existent paths correctly
#[tokio::test]
async fn test_read_resource_nonexistent_path() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();

    // Complete initialization to index the repository
    engine.complete_initialization().await.unwrap();

    // Attempt to read a non-existent file
    let nonexistent = repo_path.join("nonexistent.txt");
    let uri = format!("file://{}", nonexistent.to_str().unwrap());
    let result = engine.read_resource(&uri).await;

    assert!(result.is_err(), "Should fail for non-existent paths");
    let error_msg = result.unwrap_err().to_string();
    assert!(
        error_msg.contains("does not exist") || error_msg.contains("cannot be accessed"),
        "Error should indicate path doesn't exist, got: {}",
        error_msg
    );
}

/// Test that read_resource works with relative URIs
#[tokio::test]
async fn test_read_resource_relative_uri() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();

    let test_file = repo_path.join("test.txt");
    fs::write(&test_file, "test content").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();

    // Complete initialization to index the repository
    engine.complete_initialization().await.unwrap();

    // Test with URI without file:// prefix
    let result = engine.read_resource(test_file.to_str().unwrap()).await;
    assert!(result.is_ok(), "Should handle URIs without file:// prefix");
    assert_eq!(result.unwrap(), "test content");
}

/// Test that resolve_repo rejects arbitrary filesystem paths not in indexed repos.
/// Uses get_project_structure, which routes through resolve_repo internally.
#[tokio::test]
async fn test_resolve_repo_rejects_arbitrary_paths() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();
    fs::write(repo_path.join("main.rs"), "fn main() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // Arbitrary filesystem paths should NOT resolve as repos.
    let result = engine.get_project_structure("/etc", 3).await;
    assert!(result.is_err(), "Should not allow /etc as a repo path");

    let result = engine.get_project_structure("/tmp", 3).await;
    assert!(result.is_err(), "Should not allow /tmp as a repo path");

    // The full indexed repo path must work.
    let result = engine
        .get_project_structure(repo_path.to_str().unwrap(), 3)
        .await;
    assert!(
        result.is_ok(),
        "Indexed repo path should work: {:?}",
        result.err()
    );
}

/// Test that resolve_repo accepts the actual indexed repo path.
#[tokio::test]
async fn test_resolve_repo_accepts_indexed_repo_path() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("my-project");
    fs::create_dir(&repo_path).unwrap();
    fs::write(repo_path.join("lib.rs"), "pub fn hello() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // The actual indexed path should work when passed directly.
    let result = engine
        .get_project_structure(repo_path.to_str().unwrap(), 3)
        .await;
    assert!(
        result.is_ok(),
        "Indexed repo path should work: {:?}",
        result.err()
    );
}

/// Test that resolve_repo rejects bare short names like "linux.git".
///
/// Short names cannot disambiguate between two indexed repos that share the
/// same basename (the original collision bug), so they are no longer accepted.
#[tokio::test]
async fn test_resolve_repo_rejects_bare_short_name() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("test-repo");
    fs::create_dir(&repo_path).unwrap();
    fs::write(repo_path.join("main.rs"), "fn main() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    let result = engine.get_project_structure("test-repo", 3).await;
    let err = result.expect_err("bare short name must be rejected");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("list_repos"),
        "Error should point at list_repos, got: {}",
        msg
    );
}

/// Test that two indexed repos sharing the same basename do not collide.
///
/// Before this refactor the basename was the map key, so the second clone
/// silently overwrote the first. With canonical absolute paths as keys, each
/// repo resolves independently by full path.
#[tokio::test]
async fn test_resolve_repo_two_repos_same_basename() {
    let temp_dir = TempDir::new().unwrap();
    let clone_a = temp_dir.path().join("a").join("linux.git");
    let clone_b = temp_dir.path().join("b").join("linux.git");
    fs::create_dir_all(&clone_a).unwrap();
    fs::create_dir_all(&clone_b).unwrap();
    fs::write(clone_a.join("a.rs"), "fn a() {}").unwrap();
    fs::write(clone_b.join("b.rs"), "fn b() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![clone_a.clone(), clone_b.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // Each path resolves to its own repo without collision.
    let result_a = engine
        .get_project_structure(clone_a.to_str().unwrap(), 3)
        .await
        .expect("clone A must resolve");
    let result_b = engine
        .get_project_structure(clone_b.to_str().unwrap(), 3)
        .await
        .expect("clone B must resolve");

    assert!(
        result_a.contains("a.rs"),
        "clone A's structure should contain its own file, got: {}",
        result_a
    );
    assert!(
        result_b.contains("b.rs"),
        "clone B's structure should contain its own file, got: {}",
        result_b
    );
}

/// Test that a subdirectory of an indexed repo resolves to that repo's root.
#[tokio::test]
async fn test_resolve_repo_subdirectory_resolves_to_root() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("my-project");
    let sub_path = repo_path.join("src").join("nested");
    fs::create_dir_all(&sub_path).unwrap();
    fs::write(repo_path.join("root.rs"), "fn root() {}").unwrap();
    fs::write(sub_path.join("inner.rs"), "fn inner() {}").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // Passing the subdirectory must resolve to the repo root, so the project
    // structure includes files outside the subdirectory.
    let result = engine
        .get_project_structure(sub_path.to_str().unwrap(), 3)
        .await
        .expect("subdirectory must resolve to repo root");
    assert!(
        result.contains("root.rs"),
        "subdirectory resolution must yield repo root, got: {}",
        result
    );
}

/// Test that a nested git checkout (e.g. a linked worktree) inside an
/// indexed repo does not silently resolve to the outer repo's index — it is
/// a distinct checkout with its own files and must not be merged in.
#[tokio::test]
async fn test_resolve_repo_nested_git_checkout_not_merged() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("my-project");
    fs::create_dir_all(&repo_path).unwrap();
    fs::write(repo_path.join("root.rs"), "fn root() {}").unwrap();

    // A nested directory that is itself a distinct git checkout, as a linked
    // worktree would be — not merely a subdirectory of the indexed repo.
    let nested_repo = repo_path.join(".claude").join("worktrees").join("agent-x");
    fs::create_dir_all(&nested_repo).unwrap();
    fs::write(nested_repo.join(".git"), "gitdir: /somewhere/else\n").unwrap();
    fs::write(
        nested_repo.join("worktree_only.rs"),
        "fn worktree_only() {}",
    )
    .unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    // The nested checkout was never indexed on its own, so it must not
    // silently resolve to the outer repo's index.
    let result = engine
        .get_project_structure(nested_repo.to_str().unwrap(), 3)
        .await;
    assert!(
        result.is_err(),
        "nested git checkout must not silently resolve to the outer repo, got: {:?}",
        result.ok()
    );
}

#[tokio::test]
async fn test_check_type_errors_accepts_directory_path() {
    let temp_dir = TempDir::new().unwrap();
    let repo_path = temp_dir.path().join("typed-project");
    let src_path = repo_path.join("src");
    fs::create_dir_all(&src_path).unwrap();
    fs::write(
        src_path.join("app.py"),
        "def add_one(value):\n    return value + 1\n",
    )
    .unwrap();
    fs::write(src_path.join("lib.rs"), "pub fn rust_file() {}\n").unwrap();

    let index_path = temp_dir.path().join("index");
    let engine = CodeIntelEngine::new(index_path, vec![repo_path.clone()])
        .await
        .unwrap();
    engine.complete_initialization().await.unwrap();

    let result = engine
        .check_type_errors(repo_path.to_str().unwrap(), "src", Some(true))
        .await
        .unwrap();

    assert!(result.contains("**Files analyzed**: 1"));
    assert!(result.contains("**Functions analyzed**: 1"));
}

/// End-to-end fixture for the CWE-680 integer-overflow-to-buffer
/// rules. CWE-680 detection in this engine is **partial** — patches
/// 21 and 22 cover literal-constant wraparound (CWE-680-001) and
/// the `var * sizeof(T)` shape (CWE-680-002), respectively. This
/// test asserts those two arms fire on the right call sites and
/// nothing else, and that the message carries the partial-coverage
/// caveat so AI callers reading the output see the limitation
/// without having to read source.
#[test]
fn test_heap_size_cwe680_shapes_fixture() {
    use narsil_mcp::security_rules::SecurityRulesEngine;

    let code = include_str!("fixtures/heap_size/cwe680_shapes.c");
    let engine = SecurityRulesEngine::new();
    let findings = engine.scan(code, "cwe680_shapes.c", "c");

    let cwe680_findings: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id.starts_with("CWE-680-"))
        .collect();

    let fired: Vec<(&str, &str)> = cwe680_findings
        .iter()
        .map(|finding| (finding.rule_id.as_str(), finding.snippet.as_str()))
        .collect();

    // Three WRAP cases must fire CWE-680-001.
    let wrap_calls = [
        "malloc(0xFFFFFFFFFFFFFFFF * 2)",
        "malloc(0xFFFFFFFFFFFFFFFF + 1)",
        "calloc(0xFFFFFFFFFFFFFFFF, 2)",
    ];
    for needle in wrap_calls {
        assert!(
            fired
                .iter()
                .any(|(id, snippet)| *id == "CWE-680-001" && snippet.contains(needle)),
            "expected CWE-680-001 finding containing {:?}; fired list: {:?}",
            needle,
            fired,
        );
    }

    // Three SIZEOF cases must fire CWE-680-002.
    let sizeof_calls = [
        "malloc(n * sizeof(struct record))",
        "malloc(sizeof(int) * n)",
        "calloc(n, sizeof(struct record))",
    ];
    for needle in sizeof_calls {
        assert!(
            fired
                .iter()
                .any(|(id, snippet)| *id == "CWE-680-002" && snippet.contains(needle)),
            "expected CWE-680-002 finding containing {:?}; fired list: {:?}",
            needle,
            fired,
        );
    }

    // CLEAN cases must not fire either CWE-680-001 or CWE-680-002.
    let forbidden = [
        "malloc(4 * sizeof(int))",
        "calloc(8, sizeof(int))",
        "malloc(n * 4)",
    ];
    for needle in forbidden {
        assert!(
            !fired.iter().any(|(_, snippet)| snippet.contains(needle)),
            "CWE-680 must not fire on {:?}; fired list: {:?}",
            needle,
            fired,
        );
    }

    // Every emitted finding must carry the partial-coverage caveat
    // — AI callers reading the message must see "PARTIAL check".
    for finding in &cwe680_findings {
        assert!(
            finding.message.contains("PARTIAL check"),
            "CWE-680 finding missing partial-coverage caveat; rule={} message={}",
            finding.rule_id,
            finding.message,
        );
    }

    // Total count guards against silent regressions adding a stray
    // finding elsewhere in the fixture.
    assert_eq!(
        cwe680_findings.len(),
        6,
        "expected 6 CWE-680 findings (3 WRAP + 3 SIZEOF); got {:?}",
        fired,
    );
}

/// End-to-end fixture exercising the CWE-122 heap-overflow rule.
///
/// Loads tests/fixtures/heap_size/canonical_overflows.c, runs the
/// security-rules engine over it, and asserts that every function
/// marked OVERFLOW emits a finding while every function marked CLEAN
/// does not. The fixture deliberately mixes allocator kinds (malloc,
/// asprintf, calloc, strdup, strndup, cross-function helper) and
/// writer kinds (sprintf, strcpy, strcat, memcpy, memset) so a
/// regression in any one path surfaces here.
#[test]
fn test_heap_size_canonical_overflows_fixture() {
    use narsil_mcp::security_rules::SecurityRulesEngine;

    let code = include_str!("fixtures/heap_size/canonical_overflows.c");
    let engine = SecurityRulesEngine::new();
    let findings = engine.scan(code, "canonical_overflows.c", "c");

    let overflow_findings: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id == "CWE-122-001")
        .collect();

    let fired_in_snippets: Vec<&str> = overflow_findings
        .iter()
        .map(|finding| finding.snippet.as_str())
        .collect();

    // Every OVERFLOW-marked function must produce exactly one finding,
    // identifiable by a substring of its write call.
    let expected_overflow_substrings = [
        ("overflow_malloc_strcpy", "very long literal"),
        ("overflow_asprintf_then_sprintf", "prefix, name"),
        ("overflow_calloc_memset", "memset(dst, 0, 40)"),
        ("overflow_strdup_then_sprintf", "name, name"),
        ("overflow_through_helper", "strcpy(dst, user_input)"),
    ];
    for (function_label, expected_substring) in expected_overflow_substrings {
        let count = fired_in_snippets
            .iter()
            .filter(|snippet| snippet.contains(expected_substring))
            .count();
        assert_eq!(
            count, 1,
            "expected exactly one CWE-122-001 finding for {} (looking for snippet containing {:?}); \
             got fired snippets {:?}",
            function_label, expected_substring, fired_in_snippets,
        );
    }

    // CLEAN functions must not fire. Match by substring from each
    // clean function's call site.
    let forbidden_substrings = [
        ("clean_malloc_strcpy", "strcpy(dst, name)"),
        ("clean_calloc_memcpy", "memcpy(dst, src, 16)"),
        ("clean_strndup_then_strcpy", "thirteen0000"),
    ];
    for (function_label, forbidden_substring) in forbidden_substrings {
        assert!(
            !fired_in_snippets
                .iter()
                .any(|snippet| snippet.contains(forbidden_substring)),
            "CWE-122-001 must not fire on the {} clean case; \
             saw a snippet containing {:?} in fired list {:?}",
            function_label,
            forbidden_substring,
            fired_in_snippets,
        );
    }

    // Total firing count must equal the OVERFLOW arm size — guards
    // against a future regression that adds a spurious finding
    // elsewhere in the fixture.
    assert_eq!(
        overflow_findings.len(),
        expected_overflow_substrings.len(),
        "unexpected total CWE-122-001 count; fired snippets: {:?}",
        fired_in_snippets,
    );
}
