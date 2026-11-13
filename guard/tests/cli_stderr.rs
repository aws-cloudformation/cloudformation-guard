//! What the built binary puts on the process's stderr, read from a child process.
//!
//! The in-process harness in `validate.rs` reads the command `Writer`'s stderr buffer, which is where
//! `validate` writes its warnings. It cannot see a write that bypasses the writer -- an `eprintln!` in
//! library code, a `dbg!` left behind, a dependency writing to fd 2 -- and it stayed green while the
//! loader still printed its tag warning that way. A grep for `eprintln!` under `src/rules` is a
//! secondary check and cannot see a write behind an alias or inside a dependency either. So these
//! tests run the binary as a child and read the child's whole stderr: exactly the lines the writer is
//! meant to print, in document order, and nothing else; and nothing at all for an untagged document.
//!
//! The child only reads the two fixtures named on its command line and writes to its own stdout and
//! stderr; `validate` has no other effect.

use std::path::Path;
use std::process::{Command, Output};

const CFN_GUARD: &str = env!("CARGO_BIN_EXE_cfn-guard");
const CRATE_DIR: &str = env!("CARGO_MANIFEST_DIR");

fn validate(rules: &str, data: &str) -> Output {
    Command::new(CFN_GUARD)
        .current_dir(CRATE_DIR)
        .args(["validate", "-r", rules, "-d", data, "--show-summary", "all"])
        .output()
        .expect("the cfn-guard binary runs")
}

/// `validate` names a data file by its absolute path, so the expected lines are built from the
/// fixture's canonical path rather than the relative one the child was given.
fn fixture_path(relative: &str) -> String {
    std::fs::canonicalize(Path::new(CRATE_DIR).join(relative))
        .unwrap_or_else(|e| panic!("{} is a fixture of this crate: {}", relative, e))
        .display()
        .to_string()
}

/// Three `!!` tags from another dialect, one warning line each with its own position, and nothing
/// else on the process's stderr. This is the pin for "no library code writes to stderr": a stray
/// write anywhere in the run would be a fourth line here.
#[test]
fn a_tag_read_past_is_the_only_thing_on_the_process_stderr() {
    let data = "resources/validate/tagged-scalars/three_foreign_tags.yaml";
    let output = validate(
        "resources/validate/tagged-scalars/a_is_a_string.guard",
        data,
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
    assert!(
        output.status.success(),
        "the tagged nodes load as if untagged, so the rule passes; status {:?}, stderr:\n{stderr}",
        output.status
    );

    let named = fixture_path(data);
    let expected: Vec<String> = [
        ("python/str", "L:1,C:4"),
        ("python/list", "L:3,C:3"),
        ("python/str", "L:4,C:5"),
    ]
    .iter()
    .map(|&(tag, at)| {
        format!(
            "Warning: cfn-guard does not read the YAML tag `!!{tag}` at {at} in data file {named}; \
             the node is read as if it had no tag."
        )
    })
    .collect();
    let lines: Vec<String> = stderr.lines().map(str::to_string).collect();

    assert_eq!(
        expected, lines,
        "the child's whole stderr, which must be exactly the three warnings:\n{stderr}"
    );
}

/// The control: a document with nothing to warn about puts nothing on stderr at all.
#[test]
fn an_untagged_document_puts_nothing_on_the_process_stderr() {
    let output = validate(
        "resources/validate/tagged-scalars/mode_is_493.guard",
        "resources/validate/tagged-scalars/plain_int_octal.yaml",
    );
    let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");

    assert!(
        output.status.success(),
        "the control passes; status {:?}, stderr:\n{stderr}",
        output.status
    );
    assert!(
        stderr.is_empty(),
        "nothing should reach stderr for an untagged document, got:\n{}",
        stderr
    );
}
