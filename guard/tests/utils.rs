// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
use pretty_assertions::assert_eq;
use std::env;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use cfn_guard::commands::CfnGuard;
use cfn_guard::utils::reader::ReadBuffer::File as ReadFile;
use cfn_guard::utils::reader::Reader;
use cfn_guard::utils::writer::WriteBuffer::File as WBFile;
use cfn_guard::utils::writer::WriteBuffer::Vec as WBVec;
use cfn_guard::utils::writer::Writer;
use cfn_guard::Error;
use clap::Parser;
use fancy_regex::Regex;

// By path, because this file is both a module of the test crates that declare `mod utils;` and a
// test target of its own, and a bare `mod` resolves beside the crate root in the second case. Not
// every crate that includes `utils` reads a loader-parity spec, hence the allow.
#[allow(dead_code)]
#[path = "utils/loader_parity_spec.rs"]
pub mod loader_parity_spec;

#[non_exhaustive]
pub struct StatusCode;

const GUARD_TEST_APP_NAME: &str = "cfn-guard-test";

#[allow(dead_code)]
pub enum Command {
    ParseTree,
    Validate,
    Test,
    Rulegen,
}

impl std::fmt::Display for Command {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Command::ParseTree => "parse-tree",
                Command::Validate => "validate",
                Command::Test => "test",
                Command::Rulegen => "rulegen",
            }
        )
    }
}

#[allow(dead_code)]
impl StatusCode {
    pub const SUCCESS: i32 = 0;
    pub const INTERNAL_FAILURE: i32 = -1;
    pub const COMMAND_MAPPING_ERROR: i32 = -2;
    pub const PREPROCESSOR_ERROR: i32 = -3;
    pub const INCORRECT_STATUS_ERROR: i32 = 1;
    pub const TEST_COMMAND_FAILURE: i32 = 7;
    pub const PARSING_ERROR: i32 = 5;
    pub const VALIDATION_ERROR: i32 = 19;
    /// A combination of arguments the command cannot honour, which is the caller's mistake to fix.
    ///
    /// clap's own code for a usage error, and now also the code `main` gives an
    /// `Error::IllegalArguments` raised after parsing. Both layers reject the same class of mistake,
    /// so both answer with the same number; see `guard/README.md`.
    pub const USAGE_ERROR: i32 = 2;
}

pub fn read_from_resource_file(path: &str) -> String {
    let mut resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resource.push(path);
    let mut content = String::new();
    let mut reader = BufReader::new(File::open(resource.as_path()).unwrap());
    reader.read_to_string(&mut content).unwrap();

    content
}

// NOTE: since junit records time elapsed we must mock the time we report
// otherwise this test will be extremely flakey since time will usually not be the same
#[allow(dead_code)]
pub fn sanitize_junit_writer(writer: Writer) -> Writer {
    let buf = writer.stripped().unwrap();

    let rgx = Regex::new(r#"time="\d+""#).unwrap();
    let res = rgx.replace_all(&buf, r#"time="0""#);

    let writer = Writer::new(WBVec(res.as_bytes().to_vec())).expect("Failed to create writer.");

    writer
}

#[allow(dead_code)]
pub fn sanitize_sarif_writer(writer: Writer) -> Writer {
    let buf = writer.stripped().unwrap();

    let rgx = Regex::new(r#"("uri": ".*")"#).unwrap();
    let res = rgx.replace_all(&buf, r#""uri": "some/path""#);

    let writer = Writer::new(WBVec(res.as_bytes().to_vec())).expect("Failed to create writer.");

    writer
}

pub fn get_full_path_for_resource_file(path: &str) -> String {
    let path = if cfg!(windows) {
        path.replace('/', r#"\"#)
    } else {
        path.to_string()
    };

    let mut resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resource.push(path);
    return resource.display().to_string();
}

/// Reduce resource paths in captured output to bare filenames, so expected-output fixtures do
/// not depend on where the repository is checked out.
///
/// Anchored on `CARGO_MANIFEST_DIR`. Every resource path that reaches test output is rooted
/// there, because `get_full_path_for_resource_file` builds them from it.
///
/// This replaced a `$HOME`-based version that first rewrote the home directory to `~` and then
/// matched `~/...`, which had two bugs:
///
/// - `$HOME` was substituted by plain substring match, so a checkout whose path merely
///   *contains* `$HOME` was corrupted rather than normalised. With `HOME=/home/u`, the path
///   `/local/home/u/repo/tests/resources/x.yaml` became `/local~/repo/tests/resources/x.yaml`,
///   and reducing the tail then left `/localx.yaml` welded together. `/local/home` is a real
///   layout rather than a hypothetical, and it failed 15 of the 96 `validate` tests while
///   leaving them looking like product failures.
/// - a checkout *outside* `$HOME` produced no `~` at all, so the reduction never fired and every
///   comparison saw a full absolute path.
///
/// Anchoring on the crate directory also leaves URLs alone by construction, which a regex over
/// bare absolute paths would not: the SARIF fixtures contain
/// `//docs.oasis-open.org/.../sarif-schema-2.1.0.json`, and reducing that to its basename would
/// break them. It is the only slash-bearing file reference in `guard/resources`, so the
/// distinction is load-bearing for exactly one fixture and easy to lose.
///
/// `guard` and `ruleset` are in the list because rules files reach output as the path they were
/// given, and the harness passes absolute paths built from `CARGO_MANIFEST_DIR`. `validate` does not
/// reduce a rules file to its basename itself: that reduction would make two rules files sharing a
/// basename indistinguishable, so the normalization lives where the machine-specific part actually
/// comes from -- the checkout location, which is the test harness's business and not the product's.
///
/// The four renderings this covers were all verified against the checked-in fixtures rather than
/// argued: `<rules>.guard/<rule>    FAIL`, `Evaluation of rules <rules>.guard against data <data>`,
/// `is not compliant with [<rules>.guard/<rule>]`, and `Location[file:<rules>.guard, line:N,
/// column:N]`. The pattern is unanchored at its end, so the `/<rule>` and `, line:N` tails survive
/// the substitution and only the directory prefix is dropped.
pub fn replace_path_with_filenames(text: String) -> String {
    let extensions = ["yaml", "yml", "json", "guard", "ruleset"];
    // Any path rooted at the crate directory, reduced to its final component.
    let pattern = format!(
        r#"{}[\w/.\-]*/([\w.\-]+\.(?:{}))"#,
        fancy_regex::escape(env!("CARGO_MANIFEST_DIR")),
        extensions.join("|")
    );
    let re = Regex::new(&pattern).unwrap();
    re.replace_all(&text, "$1").to_string()
}

pub fn sanitize_path(string_to_sanitize: String) -> String {
    replace_path_with_filenames(string_to_sanitize)
}

pub fn compare_write_buffer_with_file(
    expected_output_relative_file_path: &str,
    actual_output_writer: Writer,
) {
    if cfg!(windows) {
        return;
    }

    let expected_output_full_file_path =
        get_full_path_for_resource_file(expected_output_relative_file_path);
    let expected_output = read_from_resource_file(&expected_output_full_file_path);

    let actual_output = actual_output_writer.stripped().unwrap();

    assert_eq!(sanitize_path(actual_output), expected_output)
}

#[allow(dead_code)]
pub fn compare_write_buffer_with_string(expected_output: &str, actual_output_writer: Writer) {
    if cfg!(windows) {
        return;
    }

    let actual_output = actual_output_writer.stripped().unwrap();
    assert_eq!(expected_output, sanitize_path(actual_output))
}

pub trait CommandTestRunner {
    fn build_args(&self) -> Vec<String>;

    fn run(&self, writer: &mut Writer, reader: &mut Reader) -> i32 {
        let args = self.build_args();

        let command_options =
            args.iter()
                .fold(vec![String::from(GUARD_TEST_APP_NAME)], |mut res, arg| {
                    res.push(arg.to_string());
                    res
                });

        // `try_parse_from`, not `parse_from`. `parse_from` is the exiting entry point: a clap error
        // there calls `std::process::exit(2)` and takes the whole test binary with it, so no
        // clap-level rejection could be asserted at all, and a fix that made clap reject something a
        // test passes would abort the binary rather than fail the one test. `--no-fail-fast` does not
        // help with that, because the process is gone.
        //
        // `Error::exit_code()` is clap's own mapping and returns 2 for a usage error and 0 for
        // `--help`/`--version`, which is what the binary does, so a test reads the same number a
        // caller would.
        let cfn_guard = match CfnGuard::try_parse_from(command_options) {
            Ok(parsed) => parsed,
            Err(e) => {
                writer
                    .write_err(e.render().to_string())
                    .expect("failed to write to stderr");

                return e.exit_code();
            }
        };

        match cfn_guard.execute(writer, reader) {
            // Mirrors `main`: a combination the command cannot honour is the caller's mistake and
            // gets clap's usage code, not the code that means cfn-guard fell over. Keeping the two
            // mappings the same is the point -- a test that reads -1 where the binary exits 2 is
            // asserting a fiction.
            Err(Error::IllegalArguments(message)) => {
                writer
                    .write_err(format!("Error occurred {message}"))
                    .expect("failed to write to stderr");

                StatusCode::USAGE_ERROR
            }
            Err(e) => {
                writer
                    .write_err(format!("Error occurred {e}"))
                    .expect("failed to write to stderr");

                StatusCode::INTERNAL_FAILURE
            }
            Ok(code) => code,
        }
    }
}

#[macro_export]
macro_rules! assert_output_from_file_eq {
    ($expected_output_relative_file_path: expr, $actual_output_writer: expr) => {
        $crate::utils::compare_write_buffer_with_file(
            $expected_output_relative_file_path,
            $actual_output_writer,
        )
    };
}

#[macro_export]
macro_rules! assert_output_from_str_eq {
    ($expected_output: expr, $actual_output_writer: expr) => {
        $crate::utils::compare_write_buffer_with_string($expected_output, $actual_output_writer)
    };
}

#[allow(dead_code)]
pub fn get_reader(path: &str) -> Reader {
    let file = File::open(path).expect("failed to find mocked file");

    Reader::new(ReadFile(file))
}

// Helpers for the tests that hold `guard/README.md` to the binary's `--help` (`tests/readme.rs`).
// Prefixed `readme_` so they cannot collide with anything else appended to this file.

/// The width every help is rendered at by `readme_rendered_help`.
///
/// 100 is the width clap uses when its `wrap_help` feature is off, which it is in this crate: the
/// binary never probes the terminal, so it renders at 100 and nothing else. The width still shapes
/// the layout even without wrapping, because clap decides per argument whether the description
/// shares the flag's line or starts on the next one from the width; the `test` block flips to the
/// next-line layout at about 97. So the README matches the binary only when this is 100, and
/// `UPDATE_README=1` at any other width would write a layout the binary never prints.
#[allow(dead_code)]
pub const README_HELP_WIDTH: usize = 100;

#[allow(dead_code)]
pub fn readme_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("README.md")
}

/// The text of `guard/README.md`. Callers that may run beside a writer of the file serialize on a
/// lock of their own; this function takes none.
#[allow(dead_code)]
pub fn readme_read() -> String {
    std::fs::read_to_string(readme_path())
        .expect("guard/README.md must be readable from the crate directory")
}

/// What `cfn-guard <subcommand> --help` prints, through the same clap definitions the binary parses.
///
/// `--help` stops parsing with a `DisplayHelp` error whose rendering is the text `main`'s `parse()`
/// writes to stdout before exiting 0. The exit code is asserted so that a parse failure cannot be
/// mistaken for help.
#[allow(dead_code)]
pub fn readme_rendered_help(subcommand: &str) -> String {
    use clap::CommandFactory;

    let error = CfnGuard::command()
        .term_width(README_HELP_WIDTH)
        .try_get_matches_from(["cfn-guard", subcommand, "--help"])
        .expect_err("--help must stop parsing and render the help");
    assert_eq!(
        0,
        error.exit_code(),
        "--help is not a usage error: {}",
        error.render()
    );

    error.render().to_string()
}

/// Line-by-line text with trailing whitespace dropped and trailing blank lines removed, so the
/// trailing space clap prints at the end of a multi-line help string does not count as a difference
/// from a README that has none.
#[allow(dead_code)]
pub fn readme_trimmed(text: &str) -> String {
    let mut lines: Vec<&str> = text.lines().map(str::trim_end).collect();
    while lines.last() == Some(&"") {
        lines.pop();
    }

    lines.join("\n")
}

/// The byte range of the content inside the fenced code block that follows the `### <heading>` line
/// of `readme`.
///
/// Located by heading rather than by line number so that edits elsewhere in the README do not move
/// a comparison onto the wrong block. The range excludes both fence lines; an empty block gives an
/// empty range at the closing fence.
#[allow(dead_code)]
pub fn readme_usage_block(readme: &str, heading: &str) -> std::ops::Range<usize> {
    let heading_line = format!("### {}", heading);
    let mut offset = 0;
    let lines: Vec<(usize, &str)> = readme
        .split_inclusive('\n')
        .map(|line| {
            let start = offset;
            offset += line.len();
            (start, line)
        })
        .collect();

    let heading_at = lines
        .iter()
        .position(|(_, line)| line.trim_end() == heading_line)
        .unwrap_or_else(|| panic!("README.md has no `{}` heading", heading_line));
    let open = lines[heading_at + 1..]
        .iter()
        .position(|(_, line)| line.starts_with("```"))
        .map(|i| heading_at + 1 + i)
        .unwrap_or_else(|| panic!("no fenced block follows `{}`", heading_line));
    let close = lines[open + 1..]
        .iter()
        .position(|(_, line)| line.starts_with("```"))
        .map(|i| open + 1 + i)
        .unwrap_or_else(|| panic!("the fenced block after `{}` is not closed", heading_line));

    let start = lines[open].0 + lines[open].1.len();
    let end = lines[close].0;

    start..end
}

// Both streams of one in-process run, for every integration target that asserts on stderr beside
// stdout. Prefixed and named so that nothing else appended to this file collides with it.

/// The scratch directory one `capture_both_streams` run writes its two streams to.
///
/// One directory per call and process: the targets run their tests on many threads in one process,
/// and a shared path would let one run read, or remove, the file another run is writing. The name
/// carries the process id and a counter, so two runs never share one.
struct StreamsScratch {
    dir: PathBuf,
    stdout_path: PathBuf,
    stderr_path: PathBuf,
}

impl StreamsScratch {
    fn new() -> Self {
        static RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let run = RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = env::temp_dir().join(format!("cfn-guard-streams-{}-{run}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("Failed to create the scratch directory.");
        StreamsScratch {
            stdout_path: dir.join("stdout"),
            stderr_path: dir.join("stderr"),
            dir,
        }
    }
}

/// Removed when dropped, so a failing run cleans up too: a panic anywhere inside the run unwinds
/// through this `Drop`, where an end-of-body removal is never reached. Both removals ignore a
/// missing path, so a run that wrote nothing is fine.
impl Drop for StreamsScratch {
    fn drop(&mut self) {
        // Only what this run created, by name; nothing recursive.
        let _ = std::fs::remove_file(&self.stdout_path);
        let _ = std::fs::remove_file(&self.stderr_path);
        let _ = std::fs::remove_dir(&self.dir);
    }
}

/// One in-process run with both streams captured: `run` is given a `Writer` whose regular and error
/// buffers are two files in `scratch`, and what it returns comes back beside the two streams, each
/// with ANSI escape sequences removed.
fn capture_both_streams_in(
    scratch: &StreamsScratch,
    run: impl FnOnce(&mut Writer, &mut Reader) -> i32,
) -> (i32, String, String) {
    let mut reader = Reader::default();
    let mut writer = Writer::new_with_err(
        WBFile(File::create(&scratch.stdout_path).expect("Failed to create the stdout file.")),
        WBFile(File::create(&scratch.stderr_path).expect("Failed to create the stderr file.")),
    )
    .expect("Failed to create writer.");
    let status_code = run(&mut writer, &mut reader);
    drop(writer);

    // Reopened at offset zero: the handles the command wrote through are at the end.
    let stdout = Writer::new(WBFile(
        File::open(&scratch.stdout_path).expect("Failed to reopen the stdout file."),
    ))
    .expect("Failed to create writer.")
    .stripped()
    .expect("Failed to read stdout.");
    let stderr = Writer::new_with_err(
        WBVec(vec![]),
        WBFile(File::open(&scratch.stderr_path).expect("Failed to reopen the stderr file.")),
    )
    .expect("Failed to create writer.")
    .err_to_stripped()
    .expect("Failed to read stderr.");

    (status_code, stdout, stderr)
}

/// One in-process run with both streams captured: `run` is handed a `Writer` and a default `Reader`,
/// and what it returns comes back beside what the run wrote to stdout and to stderr, in that order,
/// each with ANSI escape sequences removed.
///
/// No public method hands both streams back from one `Writer`: `stripped` and `err_to_stripped`
/// each consume the writer they are called on, and this crate's series adds no public API. So the
/// two streams go to files, and each file is read back through a `Writer` of its own. Running the
/// command twice, once per stream, would double the cost of the heavy runs and read the two streams
/// from two executions rather than one.
///
/// The files live in a scratch directory under the system temp dir, one per call, owned by a guard
/// that removes it when dropped, on a panic inside the run as much as on return.
#[allow(dead_code)]
pub fn capture_both_streams(
    run: impl FnOnce(&mut Writer, &mut Reader) -> i32,
) -> (i32, String, String) {
    let scratch = StreamsScratch::new();
    capture_both_streams_in(&scratch, run)
}

#[cfg(test)]
mod capture_both_streams_tests {
    use super::{capture_both_streams, capture_both_streams_in, StreamsScratch};
    use pretty_assertions::assert_eq;
    use std::io::Write;

    #[test]
    fn both_streams_come_back_stripped_in_order() {
        let (status_code, stdout, stderr) = capture_both_streams(|writer, _reader| {
            write!(writer, "\u{1b}[1mdoc\u{1b}[0m\tend").unwrap();
            writer
                .write_err(String::from("\u{1b}[31merr\u{1b}[0m"))
                .unwrap();
            7
        });
        assert_eq!(7, status_code);
        assert_eq!("doc\tend", stdout);
        assert_eq!("err\n", stderr);
    }

    /// A panic anywhere inside the run unwinds through the guard that owns the directory, so a
    /// failing test leaves nothing behind under the temp dir. An end-of-body removal is never
    /// reached on that path.
    #[test]
    fn a_panic_inside_the_run_still_removes_the_scratch_directory() {
        let scratch = StreamsScratch::new();
        let dir = scratch.dir.clone();
        assert!(dir.is_dir(), "the scratch directory exists before the run");

        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let scratch = scratch;
            capture_both_streams_in(&scratch, |_writer, _reader| panic!("inside the run"))
        }));

        assert!(outcome.is_err(), "the run panicked");
        assert!(
            !dir.exists(),
            "the scratch directory is gone after the panic: {}",
            dir.display()
        );
    }
}
