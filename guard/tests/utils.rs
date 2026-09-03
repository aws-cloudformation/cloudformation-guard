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
use cfn_guard::utils::writer::WriteBuffer::Vec as WBVec;
use cfn_guard::utils::writer::Writer;
use cfn_guard::Error;
use clap::Parser;
use fancy_regex::Regex;

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
/// `guard` and `ruleset` are in the list because rules files now reach output as the path they were
/// given, and the harness passes absolute paths built from `CARGO_MANIFEST_DIR`. They used to be
/// absent for a reason that no longer holds: `validate` reduced every rules file to its basename
/// itself, so nothing rooted at the crate directory and ending in `.guard` could appear. That
/// reduction is what made two rules files sharing a basename indistinguishable, and removing it moves
/// the normalization to where the machine-specific part actually comes from -- the checkout location,
/// which is the test harness's business and not the product's.
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
