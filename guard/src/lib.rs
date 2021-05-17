// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

mod rules;
mod commands;
mod command;
mod migrate;

pub extern "C" fn run_checks(
    data: &str,
    rules: &str,
) -> crate::rules::Result<String> {
    return  crate::commands::helper::validate_and_return_json(&data, &rules);
}
