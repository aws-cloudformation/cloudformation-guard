// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;

use cfn_guard::utils;
use cfn_guard::utils::reader::ReadBuffer::File as ReadFile;
use cfn_guard::utils::reader::Reader;
use cfn_guard::utils::writer::Writer;

#[non_exhaustive]
pub struct StatusCode;

const GUARD_TEST_APP_NAME: &str = "cfn-guard-test";

#[allow(dead_code)]
impl StatusCode {
    pub const SUCCESS: i32 = 0;
    pub const INTERNAL_FAILURE: i32 = -1;
    pub const COMMAND_MAPPING_ERROR: i32 = -2;
    pub const PREPROCESSOR_ERROR: i32 = -3;
    pub const INCORRECT_STATUS_ERROR: i32 = 1;
    pub const TEST_COMMAND_FAILURE: i32 = 7;
    pub const PARSING_ERROR: i32 = 5;
    pub const VALIDATION_ERROR: i32 = 20;
}

pub fn read_from_resource_file(path: &str) -> String {
    let mut resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resource.push(path);
    let mut content = String::new();
    let mut reader = BufReader::new(File::open(resource.as_path()).unwrap());
    reader.read_to_string(&mut content).unwrap();

    content
}

pub fn get_full_path_for_resource_file(path: &str) -> String {
    let mut resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resource.push(path);
    return resource.display().to_string();
}

pub fn compare_write_buffer_with_file(
    expected_output_relative_file_path: &str,
    actual_output_writer: Writer,
) {
    let expected_output_full_file_path =
        get_full_path_for_resource_file(expected_output_relative_file_path);
    let expected_output = read_from_resource_file(&expected_output_full_file_path);
    let actual_output = actual_output_writer.stripped().unwrap();
    assert_eq!(expected_output, actual_output)
}

#[allow(dead_code)]
pub fn compare_write_buffer_with_string(expected_output: &str, actual_output_writer: Writer) {
    let actual_output = actual_output_writer.stripped().unwrap();
    assert_eq!(expected_output, actual_output)
}

pub trait CommandTestRunner {
    fn build_args(&self) -> Vec<String>;

    fn run(&self, writer: &mut Writer, reader: &mut Reader) -> i32 {
        let mut app = clap::Command::new(GUARD_TEST_APP_NAME);

        let args = self.build_args();

        let command_options =
            args.iter()
                .fold(vec![String::from(GUARD_TEST_APP_NAME)], |mut res, arg| {
                    res.push(arg.to_string());
                    res
                });

        let commands = utils::get_guard_commands();

        let mappings = commands.iter().map(|s| (s.name(), s)).fold(
            HashMap::with_capacity(commands.len()),
            |mut map, entry| {
                map.insert(entry.0, entry.1.as_ref());
                map
            },
        );

        for each in &commands {
            app = app.subcommand(each.command());
        }

        let app = app.get_matches_from(command_options);

        match app.subcommand() {
            Some((name, value)) => {
                if let Some(command) = mappings.get(name) {
                    match (*command).execute(value, writer, reader) {
                        Err(e) => {
                            writer
                                .write_err(format!("Error occurred {e}"))
                                .expect("failed to write to stderr");

                            StatusCode::INTERNAL_FAILURE
                        }
                        Ok(code) => code,
                    }
                } else {
                    StatusCode::PREPROCESSOR_ERROR
                }
            }

            None => StatusCode::PREPROCESSOR_ERROR,
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
