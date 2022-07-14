// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use crate::rules::errors::{Error, ErrorKind};
use crate::rules::path_value::PathAwareValue;
use crate::commands::validate::{OutputFormatType, Reporter};
use crate::rules::{Result};
use std::convert::TryFrom;
use std::io::BufWriter;
use crate::commands::validate::generic_summary::GenericSummary;
use crate::commands::validate::tf::TfAware;
use crate::commands::validate::cfn::CfnAware;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::root_scope;

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
    let concat_rules = rules;

    match crate::rules::parser::rules_file(span) {

        Ok(rules) => {
            match input_data {
                Ok(root) => {
                    let data_file_name: &str = "lambda-payload";
                    let rules_file_name: &str = "lambda-run";

                    let traversal = Traversal::from(&root);
                    let mut root_scope = root_scope(&rules, &root)?;
                    let status = eval_rules_file(&rules, &mut root_scope)?;
                    let root_record = root_scope.reset_recorder().extract();

                    let mut write_output = BufWriter::new(Vec::new());
                    let generic: Box<dyn Reporter> = Box::new(GenericSummary::new()) as Box<dyn Reporter>;
                    let tf: Box<dyn Reporter> = Box::new(TfAware::new_with(generic.as_ref())) as Box<dyn Reporter>;
                    let cfn: Box<dyn Reporter> = Box::new(CfnAware::new_with(tf.as_ref())) as Box<dyn Reporter>;
                    let reporter: Box<dyn Reporter> = cfn;

                    reporter.report_eval(
                      &mut write_output,
                      status,
                      &root_record,
                      rules_file_name,
                      data_file_name,
                      concat_rules,
                      &traversal,
                      OutputFormatType::JSON
                    )?;

                    if verbose {
                      return Ok(serde_json::to_string_pretty(&root_record)?);
                    }

                    match String::from_utf8(write_output.buffer().to_vec()) {
                      Ok(val) => return Ok(val),
                      Err(e) => return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
                    }
                },
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}