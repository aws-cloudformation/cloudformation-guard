// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, Read, stdout};
use std::path::PathBuf;

use clap::App;
use cfn_guard::command::Command;
use cfn_guard::utils::writer::{WriteBuffer, Writer};

pub fn read_from_resource_file(path: &str) -> String {
    let mut resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resource.push(path);
    let mut content = String::new();
    let mut reader = BufReader::new(File::open(resource.as_path()).unwrap());
    reader.read_to_string(&mut content).unwrap();
    return content;
}

pub fn get_full_path_for_resource_file(path: &str) -> String {
    let mut resource = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    resource.push(path);
    return resource.display().to_string();
}

pub(crate) fn compare_write_buffer_with_file(expected_output_relative_file_path: &str, actual_output_writer: Writer){
    let expected_output_full_file_path =
        get_full_path_for_resource_file(
            expected_output_relative_file_path
        );
    let expected_output = read_from_resource_file(
        &expected_output_full_file_path
    );
    let actual_output = actual_output_writer
        .from_utf8()
        .unwrap();
    assert_eq!(expected_output, actual_output)
}

pub(crate) fn compare_write_buffer_with_string(expected_output: &str, actual_output_writer: Writer){
    let actual_output = actual_output_writer
        .from_utf8()
        .unwrap();
    assert_eq!(expected_output, actual_output)
}

pub fn cfn_guard_test_command<T: Command>(command: T, args: Vec<&str>) -> i32 {
    let test_app_name = "cfn-guard-test";
    let mut app = App::new(test_app_name);
    let mut command_options = Vec::new();
    command_options.push(test_app_name);
    command_options.append(args.clone().as_mut());

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(command));

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
        (name, Some(value)) => {
            if let Some(command) = mappings.get(name) {
                match (*command).execute(value, &mut Writer::new(WriteBuffer::Stdout(stdout()))) {
                    Err(e) => {
                        println!("Error occurred {}", e);
                        -1
                    }
                    Ok(code) => code,
                }
            } else {
                -2
            }
        }

        (_, None) => -3,
    }
}

pub fn cfn_guard_test_command_verbose<T: Command>(command: T, args: Vec<&str>, mut writer: &mut Writer) -> i32 {
    let test_app_name = "cfn-guard-test";
    let mut app = App::new(test_app_name);
    let mut command_options = Vec::new();
    command_options.push(test_app_name);
    command_options.append(args.clone().as_mut());

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(command));

    let mappings = commands.iter()
        .map(|s| (s.name(), s)).fold(
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
        (name, Some(value)) => {
            if let Some(command) = mappings.get(name) {
                match (*command).execute(value, &mut writer) {
                    Err(e) => {
                        println!("Error occurred {}", e);
                        -1
                    }
                    Ok(code) => code,
                }
            } else {
                -2
            }
        }

        (_, None) => -3,
    }
}

#[macro_export]
macro_rules! assert_output_from_file_eq {
    ($expected_output_relative_file_path: expr, $actual_output_writer: expr) => {
        crate::utils::compare_write_buffer_with_file(
            $expected_output_relative_file_path,
            $actual_output_writer
        )
    }
}

#[macro_export]
macro_rules! assert_output_from_str_eq {
    ($expected_output: expr, $actual_output_writer: expr) => {
        crate::utils::compare_write_buffer_with_string(
            $expected_output,
            $actual_output_writer
        )
    }
}
