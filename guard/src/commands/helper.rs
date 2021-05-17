// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::path_value::PathAwareValue;
use crate::commands::tracker::StackTracker;
use crate::commands::validate::ConsoleReporter;
use crate::rules::{Evaluate, Result};
use std::convert::TryFrom;

pub fn validate_and_return_json(
    data: &str,
    rules: &str,
) -> Result<String> {
    let input_data = match serde_json::from_str::<serde_json::Value>(&data) {
       Ok(value) => PathAwareValue::try_from(value),
       Err(e) => return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    };

    let span = crate::rules::parser::Span::new_extra(&rules, "lambda");

    match crate::rules::parser::rules_file(span) {

        Ok(rules) => {
            match input_data {
                Ok(root) => {
                    let root_context = RootScope::new(&rules, &root);
                    let stacker = StackTracker::new(&root_context);
                    let reporter = ConsoleReporter::new(stacker, true, true, false);
                    rules.evaluate(&root, &reporter)?;
                    let json_result = reporter.get_result_json();
                    return Ok(json_result);
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}
