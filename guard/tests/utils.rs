// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fs::File;
use std::io::{BufReader, Read};
use std::path::PathBuf;
use cfn_guard::commands::validate::Validate;
use std::collections::HashMap;
use clap::App;
use cfn_guard::command::Command;
use cfn_guard::commands::{DATA, RULES};
use cfn_guard::commands::test::Test;

pub fn get_data_option() -> String {
    format!("-{}", DATA.1)
}

pub fn get_rules_option() -> String {
    format!("-{}", RULES.1)
}

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

pub fn cfn_guard_test_command<T: Command>(command: T, args: Vec<&str>) -> i32 {
    let TEST_APP_NAME = "cfn-guard-test";
    let mut app =
        App::new(TEST_APP_NAME);
    let mut command_options = Vec::new();
    command_options.push(TEST_APP_NAME);
    command_options.append(args.clone().as_mut());

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(command));

    let mappings = commands.iter()
        .map(|s| (s.name(), s)).fold(
        HashMap::with_capacity(commands.len()),
        |mut map, entry| {
            map.insert(entry.0, entry.1.as_ref());
            map
        }
    );

    for each in &commands {
        app = app.subcommand(each.command());
    }

    let app = app.get_matches_from(command_options);

     match app.subcommand() {
        (name, Some(value)) => {
            if let Some(command) = mappings.get(name) {
                match (*command).execute(value) {
                    Err(e) => {
                        println!("Error occurred {}", e);
                        -1
                    },
                    Ok(code) => {
                        code
                    }
                }
            } else {
                -2
            }
        },

        (_, None) => {
            -3
        }
    }
}