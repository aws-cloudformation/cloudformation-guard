// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use enumflags2::BitFlags;

use crate::commands::reporters::validate::generic_summary::GenericSummary;
use crate::commands::validate::{DataFile, OutputFormatType, Reporter};
use crate::rules::errors::Error;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::root_scope;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Result;
use std::convert::TryFrom;
use std::io::BufWriter;
use std::rc::Rc;

#[allow(dead_code)]
pub struct ValidateInput<'a> {
    pub content: &'a str,
    pub file_name: &'a str,
}

#[allow(dead_code)]
pub fn validate_and_return_json(
    data: ValidateInput,
    rules: ValidateInput,
    verbose: bool,
) -> Result<String> {
    let path_value = match serde_json::from_str::<serde_json::Value>(data.content) {
        Ok(value) => PathAwareValue::try_from(value),
        Err(_) => {
            let value = serde_yaml::from_str::<serde_yaml::Value>(data.content)?;
            PathAwareValue::try_from(value)
        }
    }
    .map_err(|e| {
        Error::ParseError(format!(
            "Unable to process data in file {}, Error {e},",
            data.file_name,
        ))
    })?;

    let input_data = DataFile {
        content: "".to_string(), // not used later
        path_value,
        name: data.file_name.to_owned(),
    };

    let span = crate::rules::parser::Span::new_extra(rules.content, rules.file_name);

    let rules_file_name = rules.file_name;
    return match crate::rules::parser::rules_file(span) {
        Ok(Some(rules)) => {
            let mut write_output = BufWriter::new(Vec::new());
            let root = input_data.path_value;
            let traversal = Traversal::from(&root);
            let mut root_scope = root_scope(&rules, Rc::new(root.clone()));
            let status = eval_rules_file(&rules, &mut root_scope, Some(&input_data.name))?;
            let root_record = root_scope.reset_recorder().extract();

            if verbose {
                return Ok(serde_json::to_string_pretty(&root_record)?);
            }

            let reporter = &GenericSummary::new(BitFlags::empty()) as &dyn Reporter;

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
                Ok(val) => Ok(val),
                Err(e) => Err(Error::ParseError(e.to_string())),
            }
        }
        Ok(None) => Ok(String::default()),
        Err(e) => Err(Error::ParseError(e.to_string())),
    };
}
