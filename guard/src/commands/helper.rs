// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::path_value::PathAwareValue;
use crate::commands::tracker::StackTracker;
use crate::commands::validate::{ConsoleReporter, OutputFormatType, Reporter};
use crate::rules::{Evaluate, Result};
use std::convert::TryFrom;
use crate::commands::validate::generic_summary::GenericSummary;

pub fn validate_and_return_json(
    data: &str,
    rules: &str,
    verbose: bool
) -> Result<String> {
    let input_data = match serde_json::from_str::<serde_json::Value>(&data) {
       Ok(value) => PathAwareValue::try_from(value),
       Err(e) => {
           let value = serde_yaml::from_str::<serde_json::Value>(&data)?;
           PathAwareValue::try_from(value)
       }
    };

    let span = crate::rules::parser::Span::new_extra(&rules, "lambda");

    match crate::rules::parser::rules_file(span) {

        Ok(rules) => {
            match input_data {
                Ok(root) => {
                    let root_context = RootScope::new(&rules, &root);
                    let stacker = StackTracker::new(&root_context);
                    let data_file_name: &str = "lambda-payload";
                    let rules_file_name: &str = "lambda-run";
                    let renderer = &GenericSummary::new() as &dyn Reporter;
                    let renderers = vec![renderer];
                    let reporter = ConsoleReporter::new(stacker, &renderers, &rules_file_name, &data_file_name, verbose, true, false);
                    rules.evaluate(&root, &reporter)?;
                    let json_result = reporter.get_result_json(
                        &root, OutputFormatType::JSON)?;
                    return Ok(json_result);
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}
