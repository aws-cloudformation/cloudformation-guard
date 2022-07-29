// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::path_value::PathAwareValue;
use crate::commands::tracker::StackTracker;
use crate::commands::validate::{ConsoleReporter, OutputFormatType, Reporter};
use crate::rules::{Evaluate, Result};
use std::convert::TryFrom;
use std::io::BufWriter;
use crate::commands::validate::generic_summary::GenericSummary;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::root_scope;
use crate::rules::path_value::traversal::Traversal;

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
                    let data_file_name: &str = "lambda-payload";
                    let rules_file_name: &str = "lambda-run";

                    let mut write_output = BufWriter::new(Vec::new());

                    let traversal = Traversal::from(&root);
                    let mut root_scope = root_scope(&rules, &root)?;
                    let status = eval_rules_file(&rules, &mut root_scope)?;
                    let root_record = root_scope.reset_recorder().extract();

                    if verbose {
                        return Ok(serde_json::to_string_pretty(&root_record)?);
                    }

                    let reporter = &GenericSummary::new() as &dyn Reporter;

                    reporter.report_eval(
                        &mut write_output,
                        status,
                        &root_record,
                        rules_file_name,
                        data_file_name,
                        data,
                        &traversal,
                        OutputFormatType::JSON
                    )?;

                    match String::from_utf8(write_output.buffer().to_vec()) {
                        Ok(val) => return Ok(val),
                        Err(e) => return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
                    }
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}
