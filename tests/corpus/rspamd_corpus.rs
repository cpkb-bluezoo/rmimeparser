//! Opt-in harness against the external [rspamd-test-corpus](https://github.com/rspamd/rspamd-test-corpus).
//!
//! Run with:
//! ```bash
//! cargo test --features rspamd-corpus --test rspamd_corpus
//! ```
//!
//! Corpus root defaults to `$CARGO_MANIFEST_DIR/target/rspamd-test-corpus` and is
//! cloned on demand. Override with `RSPAMD_TEST_CORPUS`.

use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;

use rmimeparser::{MessageHandler, MessageParser, MimeHandler};

const CORPUS_REPO: &str = "https://github.com/rspamd/rspamd-test-corpus.git";
const MAX_ERROR_REPORTS: usize = 20;

struct Sink;

impl MimeHandler for Sink {}
impl MessageHandler for Sink {}

#[test]
fn rspamd_corpus_does_not_panic() {
    let root = ensure_corpus();
    let files = collect_emls(&root);
    assert!(
        !files.is_empty(),
        "no .eml files under {} (expected corpus/…)",
        root.display()
    );

    let mut ok = 0usize;
    let mut err = 0usize;
    let mut skipped = 0usize;
    let mut panics = Vec::new();
    let mut error_samples = Vec::new();

    for path in &files {
        let raw = match fs::read(path) {
            Ok(b) => b,
            Err(e) => panic!("failed to read {}: {e}", path.display()),
        };

        if !looks_like_email(&raw) {
            skipped += 1;
            continue;
        }

        let prepared = strip_mbox_from_in_headers(&raw);
        let path_display = path.display().to_string();

        let outcome = panic::catch_unwind(AssertUnwindSafe(|| parse_message(&prepared)));
        match outcome {
            Ok(Ok(())) => ok += 1,
            Ok(Err(e)) => {
                err += 1;
                if error_samples.len() < MAX_ERROR_REPORTS {
                    error_samples.push(format!("{path_display}: {e}"));
                }
            }
            Err(payload) => {
                let msg = panic_message(payload);
                panics.push(format!("{path_display}: {msg}"));
            }
        }
    }

    eprintln!(
        "rspamd corpus: total={} ok={} err={} skipped={} panics={}",
        files.len(),
        ok,
        err,
        skipped,
        panics.len()
    );
    for sample in &error_samples {
        eprintln!("  parse err: {sample}");
    }
    if error_samples.len() < err {
        eprintln!(
            "  … {} more parse errors omitted",
            err - error_samples.len()
        );
    }

    if !panics.is_empty() {
        for p in &panics {
            eprintln!("  panic: {p}");
        }
        panic!(
            "rmimeparser panicked on {} corpus message(s); see stderr",
            panics.len()
        );
    }
}

fn parse_message(raw: &[u8]) -> Result<(), String> {
    let mut handler = Sink;
    let mut parser = MessageParser::new(&mut handler);
    let mut input = raw;
    parser.receive(&mut input).map_err(|e| e.to_string())?;
    parser.close().map_err(|e| e.to_string())?;
    Ok(())
}

fn looks_like_email(bytes: &[u8]) -> bool {
    !bytes.starts_with(b"mv ")
}

/// Remove mbox `From_` separator lines in the header region (through the first blank line).
///
/// Matches lines that start with `From ` (space), not `From:`.
fn strip_mbox_from_in_headers(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut pos = 0;
    let mut in_headers = true;

    while pos < bytes.len() {
        let eol = bytes[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(bytes.len());
        let line = &bytes[pos..eol];
        let content = trim_line_ending(line);

        if in_headers {
            if content.is_empty() {
                in_headers = false;
                out.extend_from_slice(line);
            } else if content.starts_with(b"From ") {
                // drop mbox separator
            } else {
                out.extend_from_slice(line);
            }
        } else {
            out.extend_from_slice(line);
        }
        pos = eol;
    }

    out
}

fn trim_line_ending(line: &[u8]) -> &[u8] {
    let mut end = line.len();
    if end > 0 && line[end - 1] == b'\n' {
        end -= 1;
        if end > 0 && line[end - 1] == b'\r' {
            end -= 1;
        }
    } else if end > 0 && line[end - 1] == b'\r' {
        end -= 1;
    }
    &line[..end]
}

fn ensure_corpus() -> PathBuf {
    if let Ok(override_path) = std::env::var("RSPAMD_TEST_CORPUS") {
        let path = PathBuf::from(override_path);
        assert!(
            path.is_dir(),
            "RSPAMD_TEST_CORPUS={} is not a directory",
            path.display()
        );
        assert!(
            corpus_ready(&path),
            "RSPAMD_TEST_CORPUS={} has no .eml files under corpus/",
            path.display()
        );
        return path;
    }

    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target/rspamd-test-corpus");
    if corpus_ready(&path) {
        return path;
    }

    if path.exists() {
        fs::remove_dir_all(&path).unwrap_or_else(|e| {
            panic!(
                "incomplete corpus at {} could not be removed: {e}",
                path.display()
            )
        });
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|e| {
            panic!("failed to create {}: {e}", parent.display());
        });
    }

    let status = Command::new("git")
        .args(["clone", "--depth=1", CORPUS_REPO])
        .arg(&path)
        .status()
        .unwrap_or_else(|e| {
            panic!("failed to run git clone for rspamd-test-corpus: {e}");
        });
    assert!(
        status.success(),
        "git clone {CORPUS_REPO} failed with {status}"
    );
    assert!(
        corpus_ready(&path),
        "cloned {} but found no .eml files under corpus/",
        path.display()
    );
    path
}

fn corpus_ready(root: &Path) -> bool {
    let corpus = root.join("corpus");
    corpus.is_dir() && !collect_emls(root).is_empty()
}

fn collect_emls(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let corpus = root.join("corpus");
    if corpus.is_dir() {
        walk_emls(&corpus, &mut out);
    }
    // Also pick up regression/*.eml if present later
    let regression = root.join("regression");
    if regression.is_dir() {
        walk_emls(&regression, &mut out);
    }
    out.sort();
    out
}

fn walk_emls(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk_emls(&path, out);
        } else if path.extension().and_then(|s| s.to_str()) == Some("eml") {
            out.push(path);
        }
    }
}

fn panic_message(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else {
        "Box<dyn Any>".to_string()
    }
}
