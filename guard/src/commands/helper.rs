// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
                    // @TO-DO: Remove alternative code
                    // Option 1
                    // let mut root_scope = crate::rules::eval_context::root_scope(&rules, &root)?;
                    // //let mut tracker = crate::rules::eval_context::RecordTracker::new(&mut root_scope);
                    // let _status = crate::rules::eval::eval_rules_file(&rules, &mut root_scope)?;
                    // let event = root_scope.reset_recorder().extract();
                    // Ok(serde_json::to_string_pretty(&event)?)

                    // Option 2
                    let root_context = RootScope::new(&rules, &root);
                    let stacker = StackTracker::new(&root_context);
                    let data_file_name: &str = "lambda-payload";
                    let rules_file_name: &str = "lambda-run";
                    let reporters = vec![
                        Box::new(GenericSummary::new(&data_file_name, &rules_file_name, OutputFormatType::JSON)) as Box<dyn Reporter>
                    ];
                    let reporter = ConsoleReporter::new(stacker, &reporters, &rules_file_name, &data_file_name, verbose, true, false);
                    rules.evaluate(&root, &reporter)?;
                    let json_result = reporter.get_result_json()?;
                    return Ok(json_result);
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}
