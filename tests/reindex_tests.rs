//! `reindex` is the documented first move when a query returns nothing for
//! code that exists — including for a repository the server was never started
//! with, which it has to register before it can index.

use narsil_mcp::index::{CodeIntelEngine, EngineOptions};
use std::path::Path;

fn write_repo(root: &Path, function: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(root.join(".git"))?;
    std::fs::create_dir_all(root.join("src"))?;
    std::fs::write(
        root.join("src/lib.rs"),
        format!("pub fn {}() -> u32 {{ 1 }}\n", function),
    )
}

async fn engine_for(repo: &Path, index_dir: &Path) -> CodeIntelEngine {
    let engine = CodeIntelEngine::with_options(
        index_dir.to_path_buf(),
        vec![repo.to_path_buf()],
        EngineOptions::default(),
    )
    .await
    .expect("engine");
    engine
        .complete_initialization()
        .await
        .expect("initialization");
    engine
}

/// A repository absent at startup is registered and indexed, not rejected.
#[tokio::test]
async fn reindex_registers_a_repo_the_server_never_saw() {
    let started_with = tempfile::TempDir::new().unwrap();
    let unseen = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(started_with.path(), "known_fn").unwrap();
    write_repo(unseen.path(), "unseen_fn").unwrap();

    let engine = engine_for(started_with.path(), index_dir.path()).await;
    let unseen_arg = unseen.path().to_str().unwrap();

    // Before registration the repo is unknown, and says so.
    let before = engine
        .find_symbols(unseen_arg, None, Some("unseen_fn"), None, None, 10)
        .await;
    assert!(before.is_err(), "{:?}", before.map(|out| out.len()));

    let registered = engine.reindex(Some(unseen_arg)).await.expect("reindex");
    assert!(registered.contains("Registered"), "{}", registered);

    let after = engine
        .find_symbols(unseen_arg, None, Some("unseen_fn"), None, None, 10)
        .await
        .expect("find_symbols after registration");
    assert!(after.contains("unseen_fn"), "{}", after);

    // The repo the server started with is still answerable.
    let known = engine
        .find_symbols(
            started_with.path().to_str().unwrap(),
            None,
            Some("known_fn"),
            None,
            None,
            10,
        )
        .await
        .expect("find_symbols on the original repo");
    assert!(known.contains("known_fn"), "{}", known);
}

/// A path that is not a repository leaves the original "not found" error in
/// place rather than being adopted.
#[tokio::test]
async fn reindex_rejects_a_path_that_is_not_a_repo() {
    let started_with = tempfile::TempDir::new().unwrap();
    let bare_dir = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(started_with.path(), "known_fn").unwrap();
    std::fs::write(bare_dir.path().join("notes.txt"), "no vcs, no markers\n").unwrap();

    let engine = engine_for(started_with.path(), index_dir.path()).await;

    let error = engine
        .reindex(Some(bare_dir.path().to_str().unwrap()))
        .await
        .expect_err("a directory with no repository markers must not register");
    assert!(error.to_string().contains("not found"), "{}", error);
}

/// Registration mutates engine-wide state that every query reads, so a query
/// running against another repo at the same time must still be answered.
#[tokio::test]
async fn a_query_is_answered_while_a_repo_registers() {
    let started_with = tempfile::TempDir::new().unwrap();
    let unseen = tempfile::TempDir::new().unwrap();
    let index_dir = tempfile::TempDir::new().unwrap();
    write_repo(started_with.path(), "known_fn").unwrap();
    write_repo(unseen.path(), "unseen_fn").unwrap();

    let engine = std::sync::Arc::new(engine_for(started_with.path(), index_dir.path()).await);

    let registering = {
        let engine = engine.clone();
        let unseen_arg = unseen.path().to_str().unwrap().to_string();
        tokio::spawn(async move { engine.reindex(Some(&unseen_arg)).await })
    };
    let querying = {
        let engine = engine.clone();
        let known_arg = started_with.path().to_str().unwrap().to_string();
        tokio::spawn(async move {
            engine
                .find_symbols(&known_arg, None, Some("known_fn"), None, None, 10)
                .await
        })
    };

    let registered = registering.await.unwrap().expect("reindex");
    assert!(registered.contains("Registered"), "{}", registered);
    let queried = querying.await.unwrap().expect("find_symbols");
    assert!(queried.contains("known_fn"), "{}", queried);
}
