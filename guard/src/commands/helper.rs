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

/// # Known gap: this path drops every deprecation notice, and it is the most machine-only one
///
/// The scope below is built, evaluated and handed to `reset_recorder()` without its recorded notices
/// ever being read (the other commands drain them through `Notices::absorb_deprecations`), so a
/// notice this run produced goes nowhere. That is the same omission fixed in
/// `CommonStructuredReporter`, `JunitReporter`, both test reporters and `validate`'s single-line path --
/// this is the one caller left, and by the argument those fixes were made on it is the worst place for
/// it: exported as `cfn_guard::run_checks` (`lib.rs:11`) and consumed by `cfn_guard_run_checks` in
/// `guard-ffi/src/lib.rs:54` and the Lambda handler in `guard-lambda/src/main.rs:43`. An FFI caller and
/// a Lambda have no terminal to print a warning to and no human reading one.
///
/// Not fixed here because it is not a one-line drain like the others were. This function returns
/// `Result<String>`, and that `String` is the report itself -- there is no second channel for
/// diagnostics, so a notice has nowhere to go that is not either inside the JSON document every FFI and
/// Lambda consumer parses, or a `stderr` write from library code that has no writer and should not
/// invent one. Both are API changes rather than a fix, and the callers are outside this crate.
///
/// What would resolve it: give the two `ValidateInput` entry points a return shape that carries
/// diagnostics beside the report -- a struct with `report` and `notices`, or an out-parameter matching
/// the one `get_test_case` uses -- and let `guard-ffi` and `guard-lambda` decide what to do with them.
/// Until then a rule author using the FFI or the Lambda gets no warning that a clause's answer changes
/// in a later release, which is exactly the audience the notice was written for.
#[allow(dead_code)]
pub fn validate_and_return_json(
    data: ValidateInput,
    rules: ValidateInput,
    verbose: bool,
) -> Result<String> {
    // Through the loader `validate` reads a data file with, for YAML and JSON text alike. This tried
    // `serde_json` first and fell back to `serde_yaml`, so the same bytes meant different things here
    // and under `validate`: `serde_yaml::Value` keeps no scalar style, so a quoted `"<<"` was merged
    // where YAML says it is an ordinary key; neither serde value keeps source text, so a float literal
    // that underflowed to zero was 0.0 and an integer wider than `u64` was a float; and the `serde_json`
    // conversion read an integer in `(i64::MAX, u64::MAX]` as a negative. A rule proven under this
    // entry point -- which is `guard-ffi` and `guard-lambda` -- then answered differently under the CLI.
    //
    // Two readings `serde_yaml` gave are kept, because a caller had them and lost nothing by them.
    // Aliases are resolved, as they are on every route, within one budget for the document, so a
    // document that shares a block through `&a` / `*a` evaluates here as it does under `validate`.
    // Text holding no document is
    // the null document, and the rules run against it as they did when `serde_yaml` read "" as null;
    // the loader reports it as a missing document, which is turned back here rather than wrapped as a
    // parse error.
    //
    // A key written twice keeps its last value, as under `validate`, and silently: the conversion's
    // duplicate list is dropped here, because this function has no terminal for `validate`'s warning;
    // the notice naming the key is `duplicate_key_warning`'s to carry once the FFI gains a channel for
    // diagnostics beside the report.
    //
    // Every loader failure is wrapped as a `ParseError` naming the file, as the conversion failures
    // already were, by the error's own text and not by its display, so a document the loader cannot
    // parse reads with one "Parser Error when parsing" prefix and no trailing punctuation. A document
    // the loader refuses that `serde_yaml` accepted is refused with the loader's own message, which
    // says what to change.
    let path_value = match crate::rules::values::read_from(data.content) {
        Err(Error::MissingDocument) => PathAwareValue::Null(crate::rules::path_value::Path::root()),
        read => read.and_then(PathAwareValue::try_from).map_err(|e| {
            let message = match e {
                Error::ParseError(message) => message,
                other => other.to_string(),
            };
            Error::ParseError(format!(
                "Unable to process data in file {}, Error {message}",
                data.file_name,
            ))
        })?,
    };

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
            // Built without the data file name because this path never reads the scope's notices:
            // a caller through this entry point gets the verdict and no deprecation or warning, a gap
            // that predates the notices themselves.
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

#[cfg(test)]
#[path = "helper_tests.rs"]
mod helper_tests;
