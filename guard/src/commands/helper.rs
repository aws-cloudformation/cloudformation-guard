// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::commands::validate::generic_summary::GenericSummary;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::errors::Error;
use crate::rules::eval::{eval_rules_file, FileData};
use crate::rules::eval_context::root_scope;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Result;
use std::convert::TryFrom;
use std::io::BufWriter;

pub struct ValidateInput<'a> {
    pub content: &'a str,
    pub file_name: &'a str,
}

pub fn validate_and_return_json(
    data: ValidateInput,
    rules: ValidateInput,
    verbose: bool,
) -> Result<String> {
    let input_data = match serde_json::from_str::<serde_json::Value>(&data.content) {
        Ok(value) => FileData {
            path_aware_value: PathAwareValue::try_from(value),
            file_name: data.file_name.to_owned(),
        },
        Err(_) => {
            let value = serde_yaml::from_str::<serde_yaml::Value>(&data.content)?;
            FileData {
                path_aware_value: PathAwareValue::try_from(value),
                file_name: data.file_name.to_owned(),
            }
        }
    };

    let span = crate::rules::parser::Span::new_extra(&rules.content, rules.file_name);

    let rules_file_name = rules.file_name;
    match crate::rules::parser::rules_file(span) {
        Ok(rules) => match input_data.path_aware_value {
            Ok(root) => {
                let mut write_output = BufWriter::new(Vec::new());

                let traversal = Traversal::from(&root);
                let mut root_scope = root_scope(&rules, &root)?;
                let status = eval_rules_file(&rules, &mut root_scope, Some(&input_data.file_name))?;
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
                    data.file_name,
                    data.content,
                    &traversal,
                    OutputFormatType::JSON,
                )?;

                match String::from_utf8(write_output.buffer().to_vec()) {
                    Ok(val) => return Ok(val),
                    Err(e) => return Err(Error::ParseError(e.to_string())),
                }
            }
            Err(e) => return Err(e),
        },
        Err(e) => return Err(Error::ParseError(e.to_string())),
    }
}
