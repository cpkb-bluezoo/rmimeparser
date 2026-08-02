//! Opt-in harness against the external [rspamd-test-corpus](https://github.com/rspamd/rspamd-test-corpus).
//!
//! One libtest trial per `.eml`. Run with:
//! ```bash
//! cargo test --features rspamd-corpus --test rspamd_corpus
//! ```
//!
//! Corpus root defaults to `$CARGO_MANIFEST_DIR/target/rspamd-test-corpus` and is
//! cloned on demand. Override with `RSPAMD_TEST_CORPUS`.
//!
//! Summary mapping:
//! - **passed** — parsed without error
//! - **ignored** — non-mail skip, or parse `Err` justified by a structural malformation check
//!   (reason shows the error). See `tests/corpus/expected_errors` for overrides.
//! - **failed** — panic, or parse `Err` on a message that does not appear malformed
//! - **filtered out** — excluded by a name filter (`cargo test … ham/0001`)
//! - **measured** — benchmark trials only; always 0 here

use std::collections::HashMap;
use std::fs;
use std::panic::{self, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use libtest_mimic::{Arguments, Completion, Failed, Trial};
use rmimeparser::{MessageHandler, MessageParser, MimeHandler};

const CORPUS_REPO: &str = "https://github.com/rspamd/rspamd-test-corpus.git";

/// Optional overrides: relative path → expected error substring.
///
/// Used when a message is known-bad but the automatic structural checks cannot
/// prove it. Format of [`EXPECTED_ERRORS_FILE`]: one `path<TAB>substring` per line.
const EXPECTED_ERRORS_FILE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/corpus/expected_errors");

static EXPECTED_ERRORS: OnceLock<HashMap<String, String>> = OnceLock::new();

fn expected_errors() -> &'static HashMap<String, String> {
    EXPECTED_ERRORS.get_or_init(load_expected_errors)
}

struct Sink;

impl MimeHandler for Sink {}
impl MessageHandler for Sink {}

fn main() {
    let args = Arguments::from_args();
    let root = ensure_corpus();
    let files = collect_emls(&root);
    assert!(
        !files.is_empty(),
        "no .eml files under {} (expected corpus/…)",
        root.display()
    );

    let trials: Vec<Trial> = files
        .into_iter()
        .map(|path| {
            let name = trial_name(&root, &path);
            let rel = name.clone();
            Trial::ignorable_test(name, move || run_one(&path, &rel))
        })
        .collect();

    libtest_mimic::run(&args, trials).exit();
}

fn trial_name(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/")
}

fn run_one(path: &Path, rel: &str) -> Result<Completion, Failed> {
    let raw = fs::read(path).map_err(|e| Failed::from(format!("read {}: {e}", path.display())))?;

    if !looks_like_email(&raw) {
        return Ok(Completion::ignored_with("not an email"));
    }

    let prepared = strip_mbox_from_in_headers(&raw);
    let outcome = panic::catch_unwind(AssertUnwindSafe(|| parse_message(&prepared)));
    match outcome {
        Ok(Ok(())) => {
            if let Some(substr) = expected_errors().get(rel) {
                Err(Failed::from(format!(
                    "expected parse error matching {substr:?} but parse succeeded"
                )))
            } else {
                Ok(Completion::Completed)
            }
        }
        Ok(Err(e)) => {
            if parse_error_is_justified(rel, &prepared, &e) {
                Ok(Completion::ignored_with(format!("malformed: {e}")))
            } else {
                Err(Failed::from(format!(
                    "unexpected parse error (message does not appear malformed): {e}"
                )))
            }
        }
        Err(payload) => Err(Failed::from(format!("panic: {}", panic_message(payload)))),
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

/// True when `err` is an expected / structurally justified failure for this message.
fn parse_error_is_justified(rel: &str, prepared: &[u8], err: &str) -> bool {
    if let Some(substr) = expected_errors().get(rel) {
        return err.contains(substr.as_str());
    }

    if let Some(boundary) = unclosed_boundary_from_error(err) {
        return !has_exact_close_delimiter_line(prepared, boundary);
    }

    false
}

fn unclosed_boundary_from_error(err: &str) -> Option<&str> {
    const PREFIX: &str = "Unclosed multipart boundary: ";
    let rest = err.strip_prefix(PREFIX)?;
    let boundary = rest.split(" (line ").next()?.trim();
    if boundary.is_empty() {
        None
    } else {
        Some(boundary)
    }
}

/// RFC 2046 close-delimiter is a line consisting entirely of `--boundary--`.
fn has_exact_close_delimiter_line(bytes: &[u8], boundary: &str) -> bool {
    let close = format!("--{boundary}--");
    let close = close.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let eol = bytes[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i + 1)
            .unwrap_or(bytes.len());
        if trim_line_ending(&bytes[pos..eol]) == close {
            return true;
        }
        pos = eol;
    }
    false
}

fn load_expected_errors() -> HashMap<String, String> {
    let path = Path::new(EXPECTED_ERRORS_FILE);
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };
    let mut map = HashMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((rel, substr)) = line.split_once('\t') else {
            panic!(
                "{}:{}: expected `path<TAB>error-substring`, got {line:?}",
                path.display(),
                lineno + 1
            );
        };
        map.insert(rel.trim().to_string(), substr.trim().to_string());
    }
    map
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
