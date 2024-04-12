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

    let writer = match Writer::new(WBVec(res.as_bytes().to_vec())) {
        Ok(writer) => writer,
        Err(err) => {
            panic!("Error: {}", err);
        }
    };

    writer
}

#[allow(dead_code)]
pub fn sanitize_sarif_writer(writer: Writer) -> Writer {
    let buf = writer.stripped().unwrap();

    let rgx = Regex::new(r#"("uri": ".*")"#).unwrap();
    let res = rgx.replace_all(&buf, r#""uri": "some/path""#);

    let writer = match Writer::new(WBVec(res.as_bytes().to_vec())) {
        Ok(writer) => writer,
        Err(err) => {
            panic!("Error: {}", err);
        }
    };

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

pub fn replace_home_directory_with_tilde(text: String) -> String {
    let home_dir_string = match env::var("HOME") {
        Ok(home_path) => home_path,
        Err(_) => panic!("HOME variable required for tests!"),
    };

    text.replace(&home_dir_string, "~")
}

pub fn replace_path_with_filenames(text: String) -> String {
    let extensions = ["yaml", "yml", "json"];
    // pattern to match anything between "~/" and any of the extensions
    let pattern = format!(
        r#"~/(?:[\w/\-]+/)?([\w/\-]+\.(?:{}))"#,
        extensions.join("|")
    );
    let re = Regex::new(&pattern).unwrap();
    // replace the entire match with match group 1 (the file name)
    let replaced_filenames = re.replace_all(&text, "$1");

    replaced_filenames.to_string()
}

pub fn sanitize_path(string_to_sanitize: String) -> String {
    // replace the home directory to avoid regex issues with path matches beyond the
    // leading forward slash for example '[/Users/...' or 'name="/User...'
    let replaced_home_directory = replace_home_directory_with_tilde(string_to_sanitize);
    // return the blob of text with full path replaced with just the filename
    replace_path_with_filenames(replaced_home_directory)
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

        let cfn_guard = CfnGuard::parse_from(command_options);

        match cfn_guard.execute(writer, reader) {
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
