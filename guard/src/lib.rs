// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod rules;
pub mod commands;
pub mod command;
mod migrate;
mod utils;

pub extern "C" fn run_checks(
    data: &str,
    rules: &str,
    verbose: bool
) -> crate::rules::Result<String> {
    return  crate::commands::helper::validate_and_return_json(&data, &rules, verbose);
}
