// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* require return types marked as must_use to be used (such as Result types) */
#![deny(unused_must_use)]

pub mod commands;
mod rules;
#[cfg(test)]
pub(crate) mod test_support;
pub mod utils;

pub use crate::commands::helper::{validate_and_return_json as run_checks, ValidateInput};
use crate::commands::parse_tree::ParseTree;
use crate::commands::rulegen::Rulegen;
use crate::commands::test::Test;
use crate::commands::validate::{OutputFormatType, ShowSummaryType, Validate};
use crate::commands::Executable;
pub use crate::rules::errors::Error;
/// The payload of `Error::InternalError`. Exported because that variant is public and its type
/// was not nameable outside this crate, so a consumer could match the variant but could neither
/// construct nor destructure what it carries. `cfn-guard-ffi` is one such consumer.
pub use crate::rules::errors::InternalError;
pub use crate::rules::errors::RefusalToken;

use crate::commands::ERROR_STATUS_CODE;
use crate::utils::reader::{ReadBuffer, Reader};
use crate::utils::writer::strip_escape_sequences;
use crate::utils::writer::WriteBuffer::Vec as WBVec;
use std::io::Cursor;

use wasm_bindgen::prelude::*;

pub trait CommandBuilder<T: Executable> {
    fn try_build(self) -> crate::rules::Result<T>;
}

#[derive(Default, Debug)]
/// .
/// A builder to help construct the `ParseTree` command
pub struct ParseTreeBuilder {
    rules: Option<String>,
    output: Option<String>,
    print_json: bool,
    print_yaml: bool,
}

impl CommandBuilder<ParseTree> for ParseTreeBuilder {
    /// .
    /// builds a parse tree command
    fn try_build(self) -> crate::rules::Result<ParseTree> {
        let ParseTreeBuilder {
            rules,
            output,
            print_json,
            print_yaml,
        } = self;

        Ok(ParseTree {
            rules,
            output,
            print_json,
            print_yaml,
        })
    }
}

impl ParseTreeBuilder {
    /// path to the rules file to be evaluated
    pub fn rules(mut self, rules: Option<String>) -> Self {
        self.rules = rules;

        self
    }

    /// path to the output file where the parse tree will be printed to
    pub fn output(mut self, output: Option<String>) -> Self {
        self.output = output;

        self
    }

    /// print parse tree in JSON format
    pub fn print_json(mut self, arg: bool) -> Self {
        self.print_json = arg;

        self
    }

    /// print parse tree in YAML format
    pub fn print_yaml(mut self, arg: bool) -> Self {
        self.print_yaml = arg;

        self
    }
}

#[derive(Default, Debug)]
#[wasm_bindgen]
/// .
/// A builder to help construct the `Validate` command
pub struct ValidateBuilder {
    rules: Vec<String>,
    data: Vec<String>,
    input_params: Vec<String>,
    template_type: Option<String>,
    output_format: OutputFormatType,
    // Unset until the caller sets it, and passed through as is; `Validate::show_summary_in_force`
    // applies the format's default. The rule is on `default_show_summary`.
    show_summary: Option<Vec<ShowSummaryType>>,
    alphabetical: bool,
    last_modified: bool,
    verbose: bool,
    print_json: bool,
    payload: bool,
    structured: bool,
}

impl CommandBuilder<Validate> for ValidateBuilder {
    /// .
    /// attempts to construct a `Validate` command
    ///
    /// This function will return an error if
    /// - conflicting attributes have been set
    /// - both rules is empty, and payload is false
    #[allow(deprecated)]
    fn try_build(self) -> crate::rules::Result<Validate> {
        // The policy for the texts this returns. The three checks below are the builder's own: they
        // are conflicts the command line cannot express, because clap rejects them at parse time
        // (`conflicts_with`, the required `--rules|--payload` group) before `validate_construct`
        // runs, so their texts are library API, returned to JavaScript callers through
        // `try_build_js_and_execute`, and `validate_builder_own_messages_are_stable` pins them. Every
        // conflict the command line also declares is refused by `validate_construct`, in that
        // function's words, so the builder and the command line never disagree; that text, and the
        // order (builder-own checks first), are a documented behavior change, recorded in the
        // commit body.
        if self.payload && (!self.rules.is_empty() || !self.data.is_empty()) {
            return Err(Error::IllegalArguments(String::from("cannot construct a validate command payload conflicts with both data and rules arguments")));
        }

        if !self.payload && self.rules.is_empty() {
            return Err(Error::IllegalArguments(String::from("cannot construct a validate command: either payload must be set to true, or rules must not be empty")));
        }

        if self.last_modified && self.alphabetical {
            return Err(Error::IllegalArguments(String::from(
                "cannot have both last modified, and alphabetical arguments set to true",
            )));
        }

        let ValidateBuilder {
            rules,
            data,
            input_params,
            template_type,
            output_format,
            show_summary,
            alphabetical,
            last_modified,
            verbose,
            print_json,
            payload,
            structured,
        } = self;

        // `show_summary` goes through unresolved, as clap leaves it; see `default_show_summary`.
        let cmd = Validate {
            rules,
            data,
            input_params,
            template_type,
            output_format,
            show_summary,
            alphabetical,
            last_modified,
            verbose,
            print_json,
            payload,
            structured,
        };

        // The format rules are `execute`'s, asked here through the same function so that nothing
        // this builds is rejected later; the policy note above says whose text each refusal carries.
        cmd.validate_construct()?;

        Ok(cmd)
    }
}

#[wasm_bindgen]
impl ValidateBuilder {
    /// Paths to rules files, or directories of them; a named file is read whatever its extension, and
    /// in a directory only .guard and .ruleset files are read.
    /// Conflicts with payload
    pub fn rules(mut self, rules: Vec<String>) -> Self {
        self.rules = rules;

        self
    }

    /// Paths to data files, or directories of them, for the rules to be evaluated against; a named
    /// file is read whatever its extension, and in a directory only JSON and YAML files are read.
    /// Conflicts with payload
    pub fn data(mut self, data: Vec<String>) -> Self {
        self.data = data;

        self
    }

    /// Controls if the summary table needs to be displayed. --show-summary fail or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)
    /// default is fail, or none when the output format is machine-readable (see `default_show_summary`)
    /// beside a machine-readable output format, or the structured flag, the list must select nothing: none, an empty list, or a list that none clears (fail,none)
    #[wasm_bindgen(js_name = showSummary)]
    pub fn show_summary(mut self, args: Vec<ShowSummaryType>) -> Self {
        self.show_summary = Some(args);

        self
    }

    /// Paths to JSON or YAML files, or directories of them, merged into one context that is merged
    /// into each data file before the rules run; a named file is read whatever its extension, and in
    /// a directory only JSON and YAML files are read.
    pub fn input_params(mut self, input_params: Vec<String>) -> Self {
        self.input_params = input_params;

        self
    }

    /// Specify the format in which the output should be displayed
    /// default is single-line-summary
    /// junit and sarif also require `structured` to be set to true
    #[wasm_bindgen(js_name = outputFormat)]
    pub fn output_format(mut self, output: OutputFormatType) -> Self {
        self.output_format = output;

        self
    }

    /// Tells the command that rules, and data will be passed via a reader, as a json payload.
    /// Conflicts with both rules, and data
    /// default is false
    pub fn payload(mut self, arg: bool) -> Self {
        self.payload = arg;

        self
    }

    /// Validate files in a directory ordered alphabetically, conflicts with `last_modified` field
    pub fn alphabetical(mut self, arg: bool) -> Self {
        self.alphabetical = arg;

        self
    }

    /// Validate files in a directory ordered by last modified times, conflicts with `alphabetical` field
    pub fn last_modified(mut self, arg: bool) -> Self {
        self.last_modified = arg;

        self
    }

    /// Output verbose logging, conflicts with `structured` field and with a machine-readable output format
    /// default is false
    pub fn verbose(mut self, arg: bool) -> Self {
        self.verbose = arg;

        self
    }

    /// Print the parse tree in a json format. This can be used to get more details on how the clauses were evaluated
    /// conflicts with the `structured` attribute and with a machine-readable output format
    /// default is false
    pub fn print_json(mut self, arg: bool) -> Self {
        self.print_json = arg;

        self
    }

    /// Print one structured JSON, YAML, JUnit or SARIF document; required for junit and sarif.
    /// Conflicts with `verbose`, `print_json`, the single-line-summary output format, and a
    /// `show_summary` that selects anything (a list that `None` clears, such as `[Fail, None]`, selects
    /// nothing and is allowed)
    /// default is false
    pub fn structured(mut self, arg: bool) -> Self {
        self.structured = arg;

        self
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(constructor)]
    pub fn new() -> ValidateBuilder {
        ValidateBuilder {
            ..Default::default()
        }
    }

    #[cfg(target_arch = "wasm32")]
    #[wasm_bindgen(js_name = tryBuildAndExecute)]
    pub fn try_build_js_and_execute(self, payload: &str) -> Result<JsValue, JsValue> {
        // Thrown as a JavaScript `Error` whose message is the diagnostic, so a caller's
        // `instanceof Error` check and `.message` read both work on the rejection.
        self.try_build_and_execute(payload)
            .map(JsValue::from)
            .map_err(|message| JsError::new(&message).into())
    }
}

/// Kept out of the `#[wasm_bindgen]` block above so that it is not exported to JavaScript, and
/// `pub(crate)` so that it is not part of the crate's API either; the exported `tryBuildAndExecute`
/// is a thin wrapper around it, and the native tests call it directly.
impl ValidateBuilder {
    /// What the exported `tryBuildAndExecute` hands to JavaScript, as one `Result<String, String>`,
    /// because neither the exit code nor the error stream crosses the wasm boundary.
    ///
    /// Two paths, chosen by the `structured` flag, which is what selects the structured reporters:
    ///
    /// - Structured output (json, yaml, junit, sarif): the document is returned whenever one was
    ///   written, including when the run ended with the error exit code, because those formats
    ///   record the failure inside the document (a sarif `invocations` entry for a rules file that
    ///   did not parse, an error-level result for a rule that names an undeclared variable). It is
    ///   an `Err` only when no document was written, which is what a data document that does not
    ///   parse, or a payload that is not the expected JSON, leaves behind.
    /// - Console output (the single-line summary): an `Err` whenever the run ended with the error
    ///   exit code, because the summary has no place for the failure and reads as complete
    ///   without it.
    ///
    /// On both paths a payload whose `rules` or `data` list is empty is an `Err`. Such a run checks
    /// nothing, says so only in a report on the error stream (the files a directory walk passed
    /// over, then the warning that none was evaluated), and exits 0, and none of the structured
    /// writers record that report in the document.
    ///
    /// The document is read back with terminal escape sequences removed and every other byte kept,
    /// since the console path underlines file names and colors verdicts, and JavaScript has no
    /// terminal to interpret either. The error stream is not read back as text at all: the writer
    /// records each failure and each notice as it is written, and the `Err` text is built from
    /// those records.
    ///
    /// For a run that ended with the error exit code it is the failure: the recorded failure texts,
    /// each stripped of escape sequences, without the console's `---` separators. For a run that
    /// checked nothing, which the command says by writing its nothing-checked report in whatever
    /// mode the builder is in (a payload with an empty list, or a `rules` directory with no rules
    /// file), it is that report with the warning first: `Warning: no rules files were evaluated`
    /// (or the data-side sentence) opens the `Err` whatever the directory held, and the files the
    /// walk passed over follow it, at most [`SKIPPED_FILES_NAMED`] of them named and the rest
    /// counted, each line stripped of escape sequences; unless the run also wrote a failure, which
    /// then is the message. So a caller that matches on the `Err`'s opening, or shows only its
    /// first line, reads the same sentence for every such run; the CLI's own stderr keeps its order,
    /// the names first and the warning last. When neither a failure nor a report is available the
    /// text is a fixed sentence, so it is never empty.
    /// Notices written by a run that returns `Ok` (a duplicate key in a data document, a
    /// deprecation notice) are dropped; this entry has no second channel for them, and the CLI
    /// remains where they are read.
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub(crate) fn try_build_and_execute(self, payload: &str) -> Result<String, String> {
        let structured = self.structured;

        let mut reader = Reader::new(ReadBuffer::Cursor(Cursor::new(Vec::from(
            payload.as_bytes(),
        ))));

        let mut writer = utils::writer::Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
            .map_err(|e| e.to_string())?;

        let cmd = self.try_build().map_err(|e| e.to_string())?;

        let code = cmd
            .execute(&mut writer, &mut reader)
            .map_err(|e| e.to_string())?;

        // Read before the writer is consumed for its document.
        let nothing_checked = nothing_checked_message(&writer);
        let failures = writer.failures().to_vec();
        let document = writer.stripped().map_err(|e| e.to_string())?;

        // A structured document written by a run that ended with the error exit code carries the
        // failure itself, as long as it has a per-file record to carry it in: a run with no data
        // file writes an empty document, which records nothing. Any other such run has to say so
        // here, and so does a run that checked nothing, whatever its exit code. All four structured
        // formats were measured to carry a rules-file error in the document they write for a data
        // file: json and yaml in `rule_file_errors`, junit as a test case in the `error` status,
        // sarif in the invocation's notifications. The tests below hold each of them to it, so a
        // document's emptiness is the one thing left to decide by.
        let failure_recorded_in_document = structured && !document.is_empty();
        if nothing_checked.is_some() || (code == ERROR_STATUS_CODE && !failure_recorded_in_document)
        {
            return Err(failure_message(&failures, nothing_checked.as_deref()));
        }

        Ok(document)
    }
}

/// The warnings a run wrote for the inputs it found none of, in the order it wrote them, as one text;
/// `None` when it checked something of both. Read from the writer's own record of those reports,
/// which the command fills when it writes one in whichever mode it ran, so the decision rests on an
/// entry being there and never on the warning's wording.
///
/// Each report opens with the warning that nothing was evaluated and names the files passed over
/// after it. The CLI prints the names first and the warning last, which reads well on a terminal;
/// a message thrown to a caller is read by its opening, by code that matches on it or by a reader
/// shown its first line, and that opening must not depend on what else the directory held. Two
/// more differences from the terminal: every line is stripped of escape sequences, as the failures
/// are, since a file name is whatever the file system holds; and at most [`SKIPPED_FILES_NAMED`]
/// files are named, with one line counting the rest, since a directory of unrelated files would
/// otherwise put one line per file into the error.
fn nothing_checked_message(writer: &utils::writer::Writer) -> Option<String> {
    let reports = writer.nothing_checked();
    if reports.is_empty() {
        return None;
    }

    let mut lines = Vec::new();
    for report in reports {
        lines.push(stripped(&report.warning));
        lines.extend(
            report
                .skipped
                .iter()
                .take(SKIPPED_FILES_NAMED)
                .map(|line| stripped(line)),
        );
        match report.skipped.len().saturating_sub(SKIPPED_FILES_NAMED) {
            0 => {}
            // Built through the writer's constructor, as every warning is, so the prefix is spelled
            // in one place; the line is a warning of this text's own making, not one the run wrote.
            1 => lines.push(utils::writer::warning(format_args!(
                "and 1 more file was not evaluated for the same reason"
            ))),
            rest => lines.push(utils::writer::warning(format_args!(
                "and {rest} more files were not evaluated for the same reason"
            ))),
        }
    }
    Some(lines.join("\n"))
}

/// How many of the files a nothing-checked run passed over are named in the entry point's error
/// before the rest are counted.
const SKIPPED_FILES_NAMED: usize = 20;

/// `text` with the escape sequences a terminal would interpret removed and every other byte kept.
fn stripped(text: &str) -> String {
    String::from_utf8_lossy(&strip_escape_sequences(text.as_bytes())).into_owned()
}

/// The text an `Err` carries when the run wrote nothing to its error stream, so that JavaScript is
/// never thrown an `Error` with an empty message.
const NO_DIAGNOSTIC: &str = "validate ended with its error exit code but wrote no diagnostic";

/// The message for a run that has to be reported as an error: the failure it wrote, if any; else,
/// for a run that checked nothing, its report as [`nothing_checked_message`] renders it (the
/// warning first, then the files the walk passed over, at most [`SKIPPED_FILES_NAMED`] named plus
/// a line counting the rest); else [`NO_DIAGNOSTIC`]. A notice is never the message: a run that ended with the
/// error exit code and wrote only notices wrote no diagnostic.
fn failure_message(failures: &[String], nothing_checked: Option<&str>) -> String {
    failure_in(failures)
        .or_else(|| nothing_checked.map(str::to_string))
        .unwrap_or_else(|| NO_DIAGNOSTIC.to_string())
}

/// The failure a run wrote, from the writer's record of its `write_err` texts.
///
/// The error stream holds notices on either side of the failure: a duplicate key in a data document
/// is reported when the document is read, before any rule runs, while a deprecation notice from a
/// rule that did run comes after the failure of the rules file before it. The record is what keeps
/// the two apart, because the stream's text does not: a notice can run over several lines, and an
/// escape sequence a notice opens and never terminates would, in a stripped stream, swallow the
/// text written after it. So each recorded failure is stripped on its own and loses the `---` the
/// console appends to its own record after a rules-file error, which is a `\n---` suffix on that
/// record and nowhere else; the lines inside a record are kept as written, so a `---` the failure
/// quotes from a document, and the trailing spaces of a quoted line, survive. The records are joined
/// by newlines and the whole is trimmed at its ends. `None` when nothing was written.
fn failure_in(failures: &[String]) -> Option<String> {
    let failure = failures
        .iter()
        .map(|text| {
            let mut text = stripped(text);
            let kept = text.strip_suffix("\n---").map_or(text.len(), str::len);
            text.truncate(kept);
            text
        })
        .collect::<Vec<_>>()
        .join("\n");
    let failure = failure.trim();

    if failure.is_empty() {
        None
    } else {
        Some(failure.to_string())
    }
}
/// .
/// A builder to help construct the `Test` command
#[derive(Default, Debug)]
pub struct TestBuilder {
    rules: Option<String>,
    test_data: Option<String>,
    directory: Option<String>,
    alphabetical: bool,
    last_modified: bool,
    verbose: bool,
    output_format: OutputFormatType,
}

impl CommandBuilder<Test> for TestBuilder {
    /// .
    /// attempts to construct a `Test` command
    ///
    /// This function will return an error if
    /// - conflicting attributes have been set
    /// - rules, test-data, and directory is set to None
    fn try_build(self) -> crate::rules::Result<Test> {
        if self.last_modified && self.alphabetical {
            return Err(Error::IllegalArguments(String::from("unable to construct a test command: cannot have both last modified, and alphabetical arguments set to true")));
        }

        if self.directory.is_some() && self.rules.is_some() {
            return Err(Error::IllegalArguments(String::from("unable to construct a test command: cannot pass both a directory argument, and a rules argument")));
        }

        if !matches!(self.output_format, OutputFormatType::SingleLineSummary) && self.verbose {
            return Err(Error::IllegalArguments(String::from("Cannot provide an output_type of JSON, YAML, or JUnit while the verbose flag is set")));
        }

        let TestBuilder {
            rules,
            test_data,
            directory,
            alphabetical,
            last_modified,
            verbose,
            output_format,
        } = self;

        Ok(Test {
            rules,
            test_data,
            directory,
            alphabetical,
            last_modified,
            verbose,
            output_format,
        })
    }
}

impl TestBuilder {
    // the path to the rule file
    // conflicts with directory
    pub fn rules(mut self, rules: Option<String>) -> Self {
        self.rules = rules;

        self
    }

    // the path to the test-data file
    // conflicts with directory
    pub fn test_data(mut self, test_data: Option<String>) -> Self {
        self.test_data = test_data;

        self
    }

    // A path to a directory containing rule file(s), and a subdirectory called tests containing
    // data input file(s)
    // conflicts with rules, and test_data
    pub fn directory(mut self, directory: Option<String>) -> Self {
        self.directory = directory;

        self
    }

    /// Test files in a directory ordered alphabetically, conflicts with `last_modified` field
    /// default is false
    pub fn alphabetical(mut self, arg: bool) -> Self {
        self.alphabetical = arg;

        self
    }

    /// Test files in a directory ordered by last modified times, conflicts with `alphabetical` field
    /// default is false
    pub fn last_modified(mut self, arg: bool) -> Self {
        self.last_modified = arg;

        self
    }

    /// Output verbose logging, conflicts with output_format if not single-line-summary
    /// default is false
    pub fn verbose(mut self, arg: bool) -> Self {
        self.verbose = arg;

        self
    }

    /// Specify the format in which the output should be displayed
    /// default is single-line-summary
    /// will conflict with verbose if set to something other than single-line-summary and verbose
    /// is set to true
    pub fn output_format(mut self, output: OutputFormatType) -> Self {
        self.output_format = output;

        self
    }
}

#[derive(Debug, Default)]
/// .
/// A builder to help construct the `Rulegen` command
pub struct RulegenBuilder {
    output: Option<String>,
    template: String,
}

impl CommandBuilder<Rulegen> for RulegenBuilder {
    /// construct a rulegen command
    fn try_build(self) -> crate::rules::Result<Rulegen> {
        let RulegenBuilder { output, template } = self;
        Ok(Rulegen { output, template })
    }
}

impl RulegenBuilder {
    /// path for the output file where the generated rules will be written to
    /// if no path is specified output will be printed to the stdout
    pub fn output(mut self, output: Option<String>) -> Self {
        self.output = output;

        self
    }

    /// path to the template which the rules will be autogenerated from
    pub fn template(mut self, template: String) -> Self {
        self.template = template;

        self
    }
}

#[cfg(test)]
mod cfn_guard_lib_tests {
    use crate::commands::validate::{
        default_show_summary, no_data_evaluated_warning, no_rules_evaluated_warning,
        OutputFormatType, ShowSummaryType, Validate,
    };
    use crate::commands::{CfnGuard, Executable, FAILURE_STATUS_CODE};
    use crate::test_support::ForcedColor;
    use crate::utils::reader::Reader;
    use crate::utils::writer::{
        WriteBuffer::Vec as WBVec, Writer, DEPRECATION_PREFIX, WARNING_PREFIX,
    };
    use crate::{
        failure_message, nothing_checked_message, CommandBuilder, Error, TestBuilder,
        ValidateBuilder, NO_DIAGNOSTIC, SKIPPED_FILES_NAMED,
    };
    use clap::Parser;

    const RULES_DIR: &str = "resources/validate/rules-dir";
    const DATA_DIR: &str = "resources/validate/data-dir";
    const FAILING_RULES: &str =
        "resources/validate/rules-dir/s3_bucket_public_read_prohibited.guard";
    const FAILING_DATA: &str =
        "resources/validate/data-dir/s3-public-read-prohibited-template-non-compliant.yaml";

    /// Runs a built command to its verdict, returning the outcome and what it wrote to stdout.
    fn execute(cmd: Validate) -> (crate::rules::Result<i32>, String) {
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let mut reader = Reader::default();
        let outcome = cmd.execute(&mut writer, &mut reader);

        (outcome, writer.stripped().expect("failed to read stdout"))
    }

    const SIZE_RULE: &str = "rule r { Resources.*.Properties.Size <= 1000 }\n";
    const UNPARSABLE_RULE: &str = "rule bad { Resources.*.Properties.Size <= }\n";
    const UNDECLARED_VARIABLE_RULE: &str = "rule broken { %undeclared == 1 }\n";
    const SMALL_TEMPLATE: &str = "Resources:\n  A:\n    Type: X\n    Properties:\n      Size: 5\n";
    const LARGE_TEMPLATE: &str =
        "Resources:\n  A:\n    Type: X\n    Properties:\n      Size: 2000\n";
    const UNTERMINATED_TEMPLATE: &str = "Resources: [unterminated\n";
    /// `Size` twice in one mapping: the loader keeps the last value and writes a warning about the
    /// duplicate to the error stream before any rule is evaluated.
    const DUPLICATE_KEY_TEMPLATE: &str =
        "Resources:\n  A:\n    Type: X\n    Properties:\n      Size: 5\n      Size: 6\n";
    /// `Str NOT IN [1, 3]` over a string `Str` compares the string with numbers, which no element
    /// matches, so the clause passes today as "not a member"; the evaluator reports that as a
    /// deprecation notice on the error stream once the rule has run, because a future release fails
    /// closed there. The tests that assert a notice is kept out of the entry's message use this rule,
    /// and first check through `notices_of` that the run did write the notice.
    const DEPRECATED_MEMBERSHIP_RULE: &str = "rule t { Str NOT IN [1, 3] }\n";
    const STRING_TEMPLATE: &str = "Str: a\n";
    /// Both at once: the duplicate key draws a warning when the document is read, and `Str` draws
    /// the deprecation notice once `DEPRECATED_MEMBERSHIP_RULE` has run.
    const DUPLICATE_KEY_AND_STRING_TEMPLATE: &str =
        "Str: a\nResources:\n  A:\n    Type: X\n    Properties:\n      Size: 5\n      Size: 6\n";

    fn payload(rules: &[&str], data: &[&str]) -> String {
        serde_json::json!({ "rules": rules, "data": data }).to_string()
    }

    /// The builder settings the TypeScript `validate()` wrapper uses before it calls
    /// `tryBuildAndExecute`.
    fn sarif_builder() -> ValidateBuilder {
        ValidateBuilder::default()
            .payload(true)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .output_format(OutputFormatType::Sarif)
    }

    /// The console format: the single-line summary, which has no place to record a failure.
    fn console_builder() -> ValidateBuilder {
        ValidateBuilder::default().payload(true)
    }

    /// A structured format with the settings the TypeScript wrapper uses, for the formats beside
    /// sarif.
    fn structured_builder(format: OutputFormatType) -> ValidateBuilder {
        ValidateBuilder::default()
            .payload(true)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .output_format(format)
    }

    /// A clause whose right-hand values are all markers (the map-key filter's right-hand side does not
    /// resolve for any of three maps) fails the rule closed, and the record the clause writes for it, the
    /// clause-error shape written by `eval_guard_access_clause`'s arm for a FAIL that rests on undecidable
    /// reads, reaches the structured report: the sentence "when handling clause" and the first map's
    /// reason are in the json, and `not check` over it fails closed with the record naming the causes of
    /// the other maps (`/Resources/Q2/`, `/Resources/Q3/`), which only the joined basis produces. This is
    /// the rendering path the recorded-explanations census asks for.
    ///
    /// Fails when the report lacks "FAIL", "when handling clause" or the first map's reason
    /// (the record was written and dropped); when no message in the parsed report carries the
    /// fail-closed phrase (the negation's record was not written); or when a message with the
    /// phrase omits `/Resources/Q2/` or `/Resources/Q3/` (the Err path named the first map
    /// alone, the joined basis was thrown away).
    #[test]
    fn a_clause_that_fails_closed_on_several_undecided_markers_reaches_the_structured_report() {
        const RULE: &str = "let missing = Resources.*.Properties.M[ keys == Missing ]\nrule check { Resources.Q1.Properties.M.PROD IN %missing }\nrule main { not check }\n";
        const TEMPLATE: &str = "Resources:\n  Q1:\n    Properties:\n      M:\n        PROD: 1\n  Q2:\n    Properties:\n      M:\n        PROD: 1\n  Q3:\n    Properties:\n      M:\n        PROD: 1\n";
        let document = structured_builder(OutputFormatType::JSON)
            .try_build_and_execute(&payload(&[RULE], &[TEMPLATE]))
            .unwrap();
        for expected in [
            "FAIL",
            "when handling clause",
            "the right-hand side of the key filter did not resolve at /Resources/Q1/Properties/M",
        ] {
            assert!(
                document.contains(expected),
                "the report must carry {:?}; got:\n{}",
                expected,
                document
            );
        }
        // Only the Ok path (the joined basis) produces the negation's record naming the causes beyond
        // the first; the Err path would name the first map alone. The let's key-filter records also
        // name Q2 and Q3, so the paths are asserted on the ONE message that carries the phrase, found
        // by parsing the report and not by searching the whole document.
        let parsed: serde_json::Value = serde_json::from_str(&document).unwrap();
        let mut closed = Vec::new();
        strings_containing(
            &parsed,
            "failed only on reads it could not decide",
            &mut closed,
        );
        assert!(
            !closed.is_empty(),
            "the report must carry a message with the phrase; got:\n{}",
            document
        );
        for message in &closed {
            for path in ["/Resources/Q2/", "/Resources/Q3/"] {
                assert!(
                    message.contains(path),
                    "the message with the phrase must name {:?}; it reads {:?}",
                    path,
                    message
                );
            }
        }
    }

    /// A rule that exits with the failure code is explained in the structured report: the rule's `checks`
    /// are not empty. The rule is a block over `Tags[*][ Key == 'Env' ]` whose body meets a converter's
    /// error (`parse_int` on a word) beside a map whose filter is refused, the shape of a refused
    /// one-object selection settled before the block exits; a report that lists the rule with empty
    /// `checks` and null messages (the run that found this: status FAIL, exit 19, nothing else) explains
    /// nothing. The report's walker falls back to a failing block's own record when its children report
    /// nothing. The rule is in the ASSERTION role, so the block leaves through the alone exit or the strict
    /// per-value record, which already carry the refusal's sentence: this cell pins that exit's output, not
    /// the gate and filter roles' block record (the cells after this one do).
    ///
    /// Fails when the rule is listed with empty `checks`, when the check lacks the refused
    /// map's path (the sentence is not carried) or is the generic fallback, or when the failure
    /// text prints the whole document.
    #[test]
    fn a_failing_rule_whose_block_children_report_nothing_still_lists_a_check() {
        const RULE: &str = "let kind = Resources.A.Kind\nrule check { Resources.*.Tags[*][ Key == 'Env' ] { Value == 'prod'\n let n = parse_int(%kind)\n %n == 1 } }\n";
        const TEMPLATE: &str = SILENT_BLOCK_TEMPLATE;
        let document = structured_builder(OutputFormatType::JSON)
            .try_build_and_execute(&payload(&[RULE], &[TEMPLATE]))
            .unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&document).expect("the document is JSON");
        let checks = report[0]["not_compliant"][0]["Rule"]["checks"]
            .as_array()
            .map(|checks| checks.len());
        assert!(
            checks.is_some_and(|count| count > 0),
            "the rule fails with exit 19 and must list a check; got:\n{}",
            document
        );
        // The check carries the refusal's SENTENCE (it names the refused map's path), not the reporter's
        // generic fallback, which is no refusal's and only stands for a record with no message.
        let listed = report[0]["not_compliant"][0]["Rule"]["checks"].to_string();
        assert!(
            listed.contains("/Resources/A/Tags"),
            "the listed check must carry the refusal's sentence; got:\n{}",
            document
        );
        assert!(
            !listed.contains("none of the checks recorded under it reports why"),
            "the generic fallback must not stand for a record that has a sentence; got:\n{}",
            document
        );
    }

    /// The template of the cells that run a block over a refused map beside a converter's error: `A` holds a
    /// scalar `Kind` and a `Tags` map whose `ENV` entry is a reference, `B` a `Tags` map the filter reads.
    const SILENT_BLOCK_TEMPLATE: &str = "Resources:\n  A:\n    Kind: 'abc'\n    Tags:\n      Env: 'dev'\n      ENV:\n        Ref: 'Stage'\n  B:\n    Tags:\n      Value: 'prod'\n      Other: 'o'\n";

    /// One run of `rule` over `template` through the structured JSON reporter: the parsed report and the
    /// document. The rules file must load: a fixture that did not parse would read as a count of none, so a
    /// load error fails here.
    fn run_json(rule: &str, template: &str) -> (serde_json::Value, String) {
        let document = structured_builder(OutputFormatType::JSON)
            .try_build_and_execute(&payload(&[rule], &[template]))
            .unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&document).expect("the document is JSON");
        let errors = &report[0]["rule_file_errors"];
        assert!(
            errors.is_null()
                || errors.as_array().is_some_and(|errors| errors.is_empty())
                || errors.as_object().is_some_and(|errors| errors.is_empty()),
            "the rules file must load; got:\n{}",
            document
        );
        (report, document)
    }

    /// The strings in `value` that contain `needle`, in document order.
    fn strings_containing<'a>(value: &'a serde_json::Value, needle: &str, out: &mut Vec<&'a str>) {
        match value {
            serde_json::Value::String(text) if text.contains(needle) => out.push(text),
            serde_json::Value::Array(items) => items
                .iter()
                .for_each(|item| strings_containing(item, needle, out)),
            serde_json::Value::Object(map) => map
                .values()
                .for_each(|item| strings_containing(item, needle, out)),
            _ => {}
        }
    }

    /// The messages in the `checks` of the failing rule named `rule_name` that name the refused map's path,
    /// for a rules file over the template of the cell above. The rules file must load: a fixture that did
    /// not parse would read as a count of none, so a load error fails here.
    fn refused_map_messages_in_checks(rule: &str, rule_name: &str) -> (Vec<String>, String) {
        const TEMPLATE: &str = SILENT_BLOCK_TEMPLATE;
        let (report, document) = run_json(rule, TEMPLATE);
        // One entry of `checks` is one listing for a reader. The strings that name the path are joined per
        // entry: one Unary entry carries the sentence in its message and again in the serialized marker's
        // `reason` (`UnaryCheck::UnResolved(ValueUnResolved { value, .. })`, `UnResolved` derives
        // `Serialize`), which is one listing, where two entries are two.
        let mut found = Vec::new();
        let mut seen = false;
        for failing in report[0]["not_compliant"].as_array().into_iter().flatten() {
            let rule = &failing["Rule"];
            if rule["name"] == rule_name {
                seen = true;
                for entry in rule["checks"].as_array().into_iter().flatten() {
                    let mut strings = Vec::new();
                    strings_containing(entry, "/Resources/A/Tags", &mut strings);
                    if !strings.is_empty() {
                        found.push(strings.join(" | "));
                    }
                }
            }
        }
        assert!(
            seen,
            "`not_compliant` must hold the rule {:?}; a rules file that did not load lists its error in `rule_file_errors` (`file_name`, `error`) and the file's status is SKIP; got:\n{}",
            rule_name, document
        );
        (found, document)
    }

    /// For the failing rule `rule_name`: how many message fields in its entry (its own message and every
    /// report beneath it) name the refused map's path, how many entries its `checks` holds, and the
    /// document.
    fn refused_map_strings_in_rule(rule: &str, rule_name: &str) -> (usize, usize, String) {
        const TEMPLATE: &str = SILENT_BLOCK_TEMPLATE;
        let (report, document) = run_json(rule, TEMPLATE);
        let mut count = 0;
        let mut checks = 0;
        let mut seen = false;
        for failing in report[0]["not_compliant"].as_array().into_iter().flatten() {
            if failing["Rule"]["name"] == rule_name {
                seen = true;
                count += reports_naming(&failing["Rule"], "/Resources/A/Tags");
                checks += failing["Rule"]["checks"].as_array().map_or(0, Vec::len);
            }
        }
        assert!(
            seen,
            "`not_compliant` must hold the rule {:?}; a rules file that did not load lists its error in `rule_file_errors` (`file_name`, `error`) and the file's status is SKIP; got:\n{}",
            rule_name, document
        );
        (count, checks, document)
    }

    /// How many times `needle` appears in the message fields (`error_message`, `custom_message`) of the
    /// reports in `value`, the rule's own among them, summed over every field and report.
    fn occurrences_naming(value: &serde_json::Value, needle: &str) -> usize {
        let own = value
            .get("messages")
            .and_then(serde_json::Value::as_object)
            .map_or(0, |messages| {
                ["error_message", "custom_message"]
                    .iter()
                    .filter_map(|field| messages.get(*field).and_then(serde_json::Value::as_str))
                    .map(|text| text.matches(needle).count())
                    .sum()
            });
        let below: usize = match value {
            serde_json::Value::Array(items) => items
                .iter()
                .map(|item| occurrences_naming(item, needle))
                .sum(),
            serde_json::Value::Object(map) => map
                .values()
                .map(|item| occurrences_naming(item, needle))
                .sum(),
            _ => 0,
        };
        own + below
    }

    /// How many message fields (`error_message`, `custom_message`) of the reports in `value`, the rule's
    /// own among them, name `needle`: every report object has a `messages` object, and each field counts
    /// on its own, so one sentence twice inside one report counts twice.
    fn reports_naming(value: &serde_json::Value, needle: &str) -> usize {
        let own = value
            .get("messages")
            .and_then(serde_json::Value::as_object)
            .map_or(0, |messages| {
                ["error_message", "custom_message"]
                    .iter()
                    .filter(|field| {
                        messages
                            .get(**field)
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|text| text.contains(needle))
                    })
                    .count()
            });
        let below: usize = match value {
            serde_json::Value::Array(items) => {
                items.iter().map(|item| reports_naming(item, needle)).sum()
            }
            serde_json::Value::Object(map) => {
                map.values().map(|item| reports_naming(item, needle)).sum()
            }
            _ => 0,
        };
        own + below
    }

    /// A refused one-object selection met by a block that is a `when` GATE reaches the structured report
    /// exactly once across the gated rule's whole entry, message included. The rule fails closed on its
    /// condition, and carries the condition's explanation, the refusal's sentence among it, as its own
    /// message; that message beats a silent block's generic sentence, so the walker does not descend into
    /// the failed condition and `checks` stays empty (the console names such a rule by its message when
    /// its checks are empty). The sentence is therefore in the message once and not in `checks`.
    ///
    /// The condition is a call of a parameterized rule whose body is the block (a block clause is not a
    /// condition clause itself: the first version of this fixture wrote one there and did not load), so the
    /// block runs in the gate role under the rule's `when` condition record.
    ///
    /// The count the cell reads is the number of strings in the rule's entry that name the refused map: 0
    /// means the rule's message does not carry it, 1 is the property, and 2 means the block's record is also
    /// walked into `checks`. The cell also fails when the count is one but `checks` is not empty (the sentence
    /// is in `checks` and the rule's message lacks it, which the console, naming such a rule by its message
    /// when its checks are empty, would not print), and when the rules file does not load. The fixture reaches
    /// the gate role's raising exit by reading, not by a run.
    #[test]
    fn a_when_gates_refused_block_reaches_the_structured_report_once() {
        const RULE: &str = "rule gate(r) { %r.*.Tags[*][ Key == 'Env' ] { Value == 'prod' } }\nrule check when gate(Resources) { Resources exists }\n";
        let (count, checks, document) = refused_map_strings_in_rule(RULE, "check");
        assert_eq!(
            1, count,
            "the refused map's sentence must appear once in the rule's entry (its message and its reports); got {} from:\n{}",
            count, document
        );
        // Once in the rule's MESSAGE, with `checks` empty: a count of one alone cannot tell that from the
        // message lacking the sentence and `checks` listing it.
        assert_eq!(
            0, checks,
            "the rule that failed on its condition lists no checks; got {} from:\n{}",
            checks, document
        );
    }

    /// The same selection refused inside a FILTER PREDICATE (the block is a clause of the predicate, so the
    /// fold raises it as the entry's undecided reason in the filter role) is listed in `checks` exactly
    /// once. A run of the first version counted two STRINGS: the bare sentence and the same sentence inside
    /// `Error = [..]`, both from the clause's own records (the block's record sits under the `Filter`
    /// record, which the walker does not visit). `Messages::parts` is not serialized, so the bare sentence
    /// does not come from it; the second string in one Unary entry is the serialized marker's `reason`
    /// (`UnaryCheck::UnResolved(ValueUnResolved { value, .. })`, `UnResolved` derives `Serialize`), which
    /// is one listing for a reader, so the count is of `checks` ENTRIES that name the path, not of strings.
    /// If the two strings are two entries, this reads 2 and the clause-error record and the per-value
    /// record both list the refusal: then one of them drops it.
    ///
    /// Fails when no entry of `checks` names the refused map, or when two entries do.
    #[test]
    fn a_filter_predicates_refused_block_reaches_the_structured_report_once() {
        const RULE: &str =
            "rule check { Resources.*[ Tags[*][ Key == 'Env' ] { Value == 'prod' } ] !empty }\n";
        let (messages, document) = refused_map_messages_in_checks(RULE, "check");
        assert_eq!(
            1,
            messages.len(),
            "the refused map's sentence must be listed once in `checks`; got {:?} from:\n{}",
            messages,
            document
        );
    }

    /// How many times each of `needles` appears in the message fields of the failing rule `rule_name`'s
    /// entry (its own message and every report beneath it, occurrences summed over the fields, so a
    /// sentence quoted twice inside one field counts twice), how many entries the rule's `checks` holds,
    /// and the document, over `template`. The rules file must load and `not_compliant` must hold the
    /// rule.
    fn refusals_named_in_rule(
        rule: &str,
        template: &str,
        rule_name: &str,
        needles: &[&str],
    ) -> (Vec<usize>, usize, String) {
        let (report, document) = run_json(rule, template);
        let mut counts = vec![0; needles.len()];
        let mut checks = 0;
        let mut seen = false;
        for failing in report[0]["not_compliant"].as_array().into_iter().flatten() {
            if failing["Rule"]["name"] == rule_name {
                seen = true;
                checks += failing["Rule"]["checks"].as_array().map_or(0, Vec::len);
                for (count, needle) in counts.iter_mut().zip(needles) {
                    *count += occurrences_naming(&failing["Rule"], needle);
                }
            }
        }
        assert!(
            seen,
            "`not_compliant` must hold the rule {:?} (a rules file that did not load lists its error in `rule_file_errors`); got:\n{}",
            rule_name, document
        );
        (counts, checks, document)
    }

    /// A type block whose `when` fails closed through a refused read lists that refusal once in the
    /// structured report. The type check closes with no message for a failed condition, so the refusal
    /// reaches the report only through the condition's records (the walker's `TypeCondition` arm). The
    /// count is of occurrences of the path in the message text (`occurrences_naming`), as in the cells below.
    ///
    /// Fails when the refusal is named nowhere in the rule's entry (the type check is listed
    /// with no explanation) or twice. The scalar `Tags` is a refused read by reading, not by a
    /// run, so a count of none may be the fixture.
    #[test]
    fn a_type_blocks_condition_that_fails_closed_lists_its_refusal_once() {
        const RULE: &str = "rule check { AWS::S3::Bucket when Properties.Tags[ Key == 'Env' ] !empty { Properties exists } }\n";
        const TEMPLATE: &str =
            "Resources:\n  A:\n    Type: 'AWS::S3::Bucket'\n    Properties:\n      Tags: 'x'\n";
        let (counts, _checks, document) =
            refusals_named_in_rule(RULE, TEMPLATE, "check", &["/Resources/A/Properties/Tags"]);
        assert_eq!(
            vec![1],
            counts,
            "the refusal must be named once in the rule's entry; got:\n{}",
            document
        );
    }

    /// A type block whose `when` is `A exists or B == %refused`, A a decided no and B a clause over a refused
    /// read, lists the refusal once and never the decided "A" as a finding: the real evaluation, read
    /// through `not_compliant`, not a hand-built tree. A decided answer in a condition is the type
    /// block's test of whether it applies, not a violation. Counted in occurrences in the message text
    /// (`occurrences_naming`).
    ///
    /// Fails when the decided answer about `A` is named in the rule's entry (the filter kept a
    /// decided per-value check under a disjunct's clause record), or when the refusal is named
    /// nowhere or twice.
    #[test]
    fn a_type_blocks_condition_lists_its_refusal_and_not_a_decided_disjunct() {
        const RULE: &str = "let refused = Resources.Q.Properties.Tags[ Key == 'Env' ]\nrule check { AWS::S3::Bucket when Properties.A exists or Properties.B == %refused { Properties exists } }\n";
        const TEMPLATE: &str = "Resources:\n  Bkt:\n    Type: 'AWS::S3::Bucket'\n    Properties:\n      B: 'x'\n  Q:\n    Type: 'AWS::SQS::Queue'\n    Properties:\n      Tags: 'x'\n";
        let (counts, _checks, document) = refusals_named_in_rule(
            RULE,
            TEMPLATE,
            "check",
            &["/Resources/Q/Properties/Tags", "property [A]"],
        );
        assert_eq!(
            vec![1, 0],
            counts,
            "the refusal once, the decided A never; got:\n{}",
            document
        );
    }

    /// A rule whose `when` condition has two disjuncts that each refuse reports BOTH refusals, each once:
    /// the condition's explanation carries the one error the conjunction held, and the other disjunct's
    /// refusal is added to the rule's message. The count is of occurrences in the message text, so the
    /// held refusal quoted a second time (inside the disjunction's own "could not be decided" wrapper)
    /// reads 2. The rule's `checks` stay empty.
    ///
    /// Fails when one of the two maps is named nowhere (the second refusal is dropped), when
    /// either is named twice (a wrapper that quotes the held refusal was appended beside it),
    /// or when the rule lists a check.
    #[test]
    fn a_when_of_two_refusing_disjuncts_reports_both_refusals_once() {
        const RULE: &str = "rule check when Resources.A.Tags[ Key == 'Env' ] exists or Resources.B.Tags[ Key == 'Env' ] exists { Resources exists }\n";
        const TEMPLATE: &str = "Resources:\n  A:\n    Tags: 'x'\n  B:\n    Tags: 'y'\n";
        let (counts, checks, document) = refusals_named_in_rule(
            RULE,
            TEMPLATE,
            "check",
            &["/Resources/A/Tags", "/Resources/B/Tags"],
        );
        assert_eq!(
            vec![1, 1],
            counts,
            "each refusal must be named once in the rule's entry; got:\n{}",
            document
        );
        assert_eq!(
            0, checks,
            "the rule that failed on its condition lists no checks; got:\n{}",
            document
        );
    }

    /// An inline `when` block whose condition has two disjuncts that each refuse reports BOTH refusals,
    /// each once: the `when` block's explanation carries the one error its condition held, and the other
    /// disjunct's refusal is appended to it by the same filter and the same append as a rule's own
    /// condition (`WhenCondition` beside `RuleCondition`). Counted in occurrences in the message text.
    ///
    /// Fails when one of the two maps is named nowhere (the inline `when`'s failed condition is not
    /// read) or when either is named twice.
    #[test]
    fn an_inline_when_of_two_refusing_disjuncts_reports_both_refusals_once() {
        const RULE: &str = "rule check { when Resources.A.Tags[ Key == 'Env' ] exists or Resources.B.Tags[ Key == 'Env' ] exists { Resources exists } }\n";
        const TEMPLATE: &str = "Resources:\n  A:\n    Tags: 'x'\n  B:\n    Tags: 'y'\n";
        let (counts, _checks, document) = refusals_named_in_rule(
            RULE,
            TEMPLATE,
            "check",
            &["/Resources/A/Tags", "/Resources/B/Tags"],
        );
        assert_eq!(
            vec![1, 1],
            counts,
            "each refusal must be named once in the rule's entry; got:\n{}",
            document
        );
    }

    /// A refusal inside a FILTER PREDICATE of a `when` condition is named once in the rule's sentence. The
    /// predicate's block body is refused over a statement written as one object (no `Principal`); the
    /// predicate's own records carry no sentence, so the refusal reaches the sentence through the enclosing
    /// clause's record, which fails on the marker the selection delivered. The walk of the failed condition
    /// descends through the filter's record, so a second source for the same refusal would show as a count
    /// of 2. Counted in occurrences of the predicate key the object lacks in the message text.
    ///
    /// Fails when the refusal is named nowhere (the predicate's refusal dropped out of the
    /// sentence) or twice.
    #[test]
    fn a_refusal_inside_a_predicate_of_a_when_condition_is_named_once() {
        const RULE: &str = "rule check when Resources.*[ Properties.PolicyDocument.Statement[*][ Principal == '*' ] { Condition exists } ] empty { Resources exists }\n";
        const TEMPLATE: &str = "Resources:\n  Role:\n    Type: 'AWS::IAM::Role'\n    Properties:\n      PolicyDocument:\n        Statement:\n          Effect: Allow\n          Action: 's3:GetObject'\n          Resource: '*'\n  Other:\n    Type: 'AWS::IAM::Role'\n    Properties:\n      PolicyDocument:\n        Statement:\n          - Principal: '*'\n            Effect: Deny\n            Action: 's3:GetObject'\n            Resource: '*'\n";
        let (counts, _checks, document) =
            refusals_named_in_rule(RULE, TEMPLATE, "check", &["no `Principal`"]);
        assert_eq!(
            vec![1],
            counts,
            "the predicate's refusal must be named once in the rule's entry; got:\n{}",
            document
        );
    }

    /// A rule that calls a gate rule whose read is refused names the reference's refusal once in its own
    /// sentence, read from a real evaluation: `gate` fails on a refused read, `check` opens on `gate` and
    /// fails closed on the reference's error. The failure the reference stores (`ReferenceFailure`) is what
    /// the walk of the failed condition reads, so a reverted extraction leaves the refusal unnamed here,
    /// where a hand-built record would keep it.
    ///
    /// Fails when the refusal is named nowhere in `check`'s entry (the reference's failure is
    /// not read) or twice (the reference's record and the callee's records both name it).
    #[test]
    fn a_rule_that_calls_a_gate_with_a_refused_read_names_the_refusal_once() {
        const RULE: &str = "rule gate { Resources.A.Tags[ Key == 'Env' ] exists }\nrule check when gate { Resources exists }\n";
        const TEMPLATE: &str = "Resources:\n  A:\n    Tags: 'x'\n";
        let (counts, _checks, document) =
            refusals_named_in_rule(RULE, TEMPLATE, "check", &["/Resources/A/Tags"]);
        assert_eq!(
            vec![1],
            counts,
            "the reference's refusal must be named once in the calling rule's entry; got:\n{}",
            document
        );
    }

    /// One gate block over THREE refused body values names each refusal once in the rule's sentence and
    /// lists no entry of its own for the rule: the gate role's marks (one per value) feed the sentence, not
    /// the entries. Read in `-o json` through the real evaluation.
    ///
    /// The variant with a run-ending error beside the marks, where the block is the one entry, is
    /// pinned by `a_refusal_a_mark_carries_beside_a_run_ending_error_is_told_once_by_the_block`.
    ///
    /// Fails when a path is named nowhere or twice, or when the rule lists a check (a mark
    /// became an entry).
    #[test]
    fn a_gate_block_over_three_refused_values_names_each_refusal_once_and_lists_no_check() {
        const RULE: &str = "rule gate(r) { %r.*.Tags[*][ Key == 'Env' ] { Value == 'prod' } }\nrule check when gate(Resources) { Resources exists }\n";
        const TEMPLATE: &str = "Resources:\n  A:\n    Tags:\n      Env: dev\n      ENV:\n        Ref: Stage\n  B:\n    Tags:\n      Env: dev\n      ENV:\n        Ref: Stage\n  C:\n    Tags:\n      Env: dev\n      ENV:\n        Ref: Stage\n";
        let (counts, checks, document) = refusals_named_in_rule(
            RULE,
            TEMPLATE,
            "check",
            &[
                "/Resources/A/Tags",
                "/Resources/B/Tags",
                "/Resources/C/Tags",
            ],
        );
        assert_eq!(
            (vec![1, 1, 1], 0),
            (counts, checks),
            "each refusal once in the rule's sentence and no check listed; got:\n{}",
            document
        );
    }

    /// An author's `<< >>` body on a failing call reaches the console whatever the called rule's
    /// children report. Read from a real console run, in the ASSERTION role (`rule outer` calls
    /// `inner(Resources)` with a body), over the three shapes of the records beneath the call:
    /// - a refused one-object map beside a one-object sibling whose body raises a converter's error: the
    ///   block exits before its fold and leaves a settled record with no message (the silent block);
    /// - the same refused map beside a LIST sibling: the loop completes and the fold writes the refusal's
    ///   record;
    /// - a refused map beside a map with no `Key`, whose selection is empty, so the converter never runs
    ///   (the shape the structured-report cell for a failing rule uses, here under a call with a body).
    /// A rule with a text of its own (a call's body) lists no generic "none of the checks recorded under it
    /// reports why" entry for a silent child (`rule_checks`), so its `checks` stay empty and the console
    /// names the rule by its message (`collect_unattributed_explanations` reads whether any block or clause
    /// beneath its checks is rendered per resource, and none is when `checks` is empty); the
    /// JUnit failure text is the body as well
    /// (`a_calls_body_over_a_silent_block_is_the_failure_text_and_the_generic_sentence_is_not`). Each row
    /// asserts the body is in the output (how many times the console prints it is read from the message
    /// when a row is red; the count is not pinned). A generic entry that filled `checks` would take the body's
    /// place in the console; if a row is red, the output printed in the message says which record the body
    /// is lost at.
    #[test]
    fn an_author_body_on_a_failing_call_over_a_silent_block_still_reaches_the_console() {
        const BODY: &str = "AUTHOR BODY SENTINEL";
        const BODY_RULES: &str = "rule inner(p) { %p.*.Tags[*][ Key == 'Env' ] { Value == 'prod'\n let n = parse_int(Value)\n %n == 1 } }\nrule outer { inner(Resources) << AUTHOR BODY SENTINEL >> }\n";
        const KIND_RULES: &str = "let kind = Resources.A.Kind\nrule inner(p) { %p.*.Tags[*][ Key == 'Env' ] { Value == 'prod'\n let n = parse_int(%kind)\n %n == 1 } }\nrule outer { inner(Resources) << AUTHOR BODY SENTINEL >> }\n";
        const ONE_OBJECT_SIBLING: &str = "Resources:\n  M:\n    Tags:\n      Env: 'dev'\n      ENV:\n        Ref: 'Stage'\n  N:\n    Tags:\n      Key: 'Env'\n      Value: 'prod'\n";
        const LIST_SIBLING: &str = "Resources:\n  M:\n    Tags:\n      Env: 'dev'\n      ENV:\n        Ref: 'Stage'\n  L:\n    Tags:\n      - Key: 'Env'\n        Value: 'prod'\n";
        for (label, rules, template) in [
            ("one-object sibling", BODY_RULES, ONE_OBJECT_SIBLING),
            ("list sibling", BODY_RULES, LIST_SIBLING),
            (
                "a map with no key beside it",
                KIND_RULES,
                SILENT_BLOCK_TEMPLATE,
            ),
        ] {
            let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![]))
                .expect("Failed to create writer.");
            let mut reader = Reader::new(crate::utils::reader::ReadBuffer::Cursor(
                std::io::Cursor::new(Vec::from(payload(&[rules], &[template]).as_bytes())),
            ));
            let _ = console_builder()
                .try_build()
                .expect("the console builder builds")
                .execute(&mut writer, &mut reader);
            let output = writer.stripped().expect("the console output reads back");
            assert!(
                output.matches(BODY).count() >= 1,
                "({}) the author's body must reach the console; got:\n{}",
                label,
                output
            );
        }
    }

    /// The notices a console run over `rules` and `data` records, read from the writer the run
    /// wrote through. A test that asserts a notice is absent from the entry's message first shows
    /// here that the run wrote one; otherwise the absence is not a measurement.
    fn notices_of(rules: &[&str], data: &[&str]) -> Vec<String> {
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let mut reader = Reader::new(crate::utils::reader::ReadBuffer::Cursor(
            std::io::Cursor::new(Vec::from(payload(rules, data).as_bytes())),
        ));
        console_builder()
            .try_build()
            .expect("the console builder builds")
            .execute(&mut writer, &mut reader)
            .expect("the run completes");
        writer.notices().to_vec()
    }

    fn wrote_a_deprecation(notices: &[String]) -> bool {
        notices
            .iter()
            .any(|notice| notice.starts_with(DEPRECATION_PREFIX))
    }

    #[test]
    fn structured_entry_records_an_unparsable_rules_file_beside_a_valid_one_in_json() {
        // The json document carries a rules-file error per data file, beside the valid rule's
        // finding, so the document is what the caller gets, as for sarif.
        let document = structured_builder(OutputFormatType::JSON)
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE, SIZE_RULE], &[LARGE_TEMPLATE]))
            .unwrap();
        let report: serde_json::Value =
            serde_json::from_str(&document).expect("the document is JSON");
        let file = &report[0];
        assert_eq!(file["name"], "DATA_STDIN[1]", "{}", document);
        assert_eq!(
            file["rule_file_errors"][0]["file_name"], "RULES_STDIN[1]",
            "{}",
            document
        );
        assert!(
            file["rule_file_errors"][0]["error"]
                .as_str()
                .unwrap_or_default()
                .contains("Parser Error"),
            "{}",
            document
        );
        assert_eq!(
            file["not_compliant"][0]["Rule"]["name"], "r",
            "{}",
            document
        );
    }

    #[test]
    fn structured_entry_records_an_unparsable_rules_file_beside_a_valid_one_in_yaml() {
        let document = structured_builder(OutputFormatType::YAML)
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE, SIZE_RULE], &[LARGE_TEMPLATE]))
            .unwrap();
        assert!(document.contains("rule_file_errors:\n"), "{}", document);
        assert!(
            document.contains("file_name: RULES_STDIN[1]\n"),
            "{}",
            document
        );
        assert!(document.contains("Parser Error"), "{}", document);
        assert!(document.contains("not_compliant:\n"), "{}", document);
        assert!(document.contains("name: r\n"), "{}", document);
    }

    #[test]
    fn structured_entry_records_an_unparsable_rules_file_beside_a_valid_one_in_junit() {
        // junit carries the rules-file error as a test case in the `error` status beside the valid
        // rule's failure, and counts both on the suite.
        let document = structured_builder(OutputFormatType::Junit)
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE, SIZE_RULE], &[LARGE_TEMPLATE]))
            .unwrap();
        assert!(
            document.contains("<testcase name=\"RULES_STDIN[1]\" time=\"0\" status=\"error\">"),
            "{}",
            document
        );
        assert!(document.contains("<error>Parser Error"), "{}", document);
        assert!(document.contains("<failure message=\"r\">"), "{}", document);
        assert!(
            document.contains("errors=\"1\" failures=\"1\""),
            "{}",
            document
        );
    }

    #[test]
    fn failure_message_keeps_a_quoted_document_separator_and_trailing_spaces() {
        // A failure that quotes the text it could not read may quote a YAML document marker, and a
        // quoted line may end in spaces. Neither is the console's separator, which is the `---` the
        // console appends to its own record after a rules-file error, so both are kept.
        let recorded = String::from(
            "Error parsing file DATA_STDIN[1] at line 3\n  quoted:  \n---\nResources: x\n---",
        );
        assert_eq!(
            failure_message(&[recorded], None),
            "Error parsing file DATA_STDIN[1] at line 3\n  quoted:  \n---\nResources: x"
        );
    }

    #[test]
    fn failure_message_drops_the_console_separator_after_each_rules_file_error() {
        // What the console records for a rules file that did not parse ends in its separator; two
        // such records make two lines of message with neither separator.
        let first =
            String::from("Parsing error handling rule file = RULES_STDIN[1], Error = one\n---");
        let second = String::from("Error handling rule file = RULES_STDIN[2], Error = two\n---");
        assert_eq!(
            failure_message(&[first, second], None),
            "Parsing error handling rule file = RULES_STDIN[1], Error = one\n\
             Error handling rule file = RULES_STDIN[2], Error = two"
        );
    }

    /// A duplicate key whose name holds an ESC followed by `]`, the opening of a terminal OSC
    /// sequence, written twice. The ESC is spelled as the JSON escape `\u001b` here because this text
    /// travels inside the payload's JSON, which admits no raw control byte; the payload parser turns
    /// it into the raw byte, and the data document's loader reads that byte in the key's name.
    const DUPLICATE_KEY_WITH_ESC_TEMPLATE: &str =
        "{\"Resources\": {\"A\": {\"Type\": \"X\", \"Properties\": {\"Size\": 5}}}, \"a\\u001b]b\": 1, \"a\\u001b]b\": 2}";
    /// A duplicate key whose name holds a line feed, and one whose name holds the two characters `\`
    /// `n`: two different keys that an escaping without the backslash would print alike.
    const DUPLICATE_KEY_WITH_NEWLINE_TEMPLATE: &str =
        "{\"Resources\": {\"A\": {\"Type\": \"X\", \"Properties\": {\"Size\": 5}}}, \"a\\nb\": 1, \"a\\nb\": 2}";
    const DUPLICATE_KEY_WITH_LITERAL_BACKSLASH_N_TEMPLATE: &str =
        "{\"Resources\": {\"A\": {\"Type\": \"X\", \"Properties\": {\"Size\": 5}}}, \"a\\\\nb\": 1, \"a\\\\nb\": 2}";

    /// Runs the console command over `payload` with both streams captured and returns the exit code,
    /// the writer's record of notices and of failures, and the error stream as the entry would strip
    /// it, so a test can read the stream and the record side by side.
    fn console_run_recorded(payload: &str) -> (i32, Vec<String>, Vec<String>, String) {
        let mut reader = Reader::new(crate::utils::reader::ReadBuffer::Cursor(
            std::io::Cursor::new(Vec::from(payload.as_bytes())),
        ));
        let mut writer =
            Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
        let cmd = console_builder()
            .try_build()
            .expect("the console builder builds");
        let code = cmd
            .execute(&mut writer, &mut reader)
            .expect("the run reports its failure by exit code, not by Err");
        let notices = writer.notices().to_vec();
        let failures = writer.failures().to_vec();
        let stripped = writer.err_to_stripped().expect("failed to read stderr");
        (code, notices, failures, stripped)
    }

    /// A control character the data document puts into a warning is written as its escape, so the
    /// warning on the error stream is one line of printable text. Before this, an ESC from a key
    /// named `a<ESC>]b` reached stderr raw: on a terminal `ESC ]` opens an OSC sequence that hides
    /// what follows and that some terminals act on, and the stream's own escape stripping swallowed
    /// everything from it to the end, the parse failure written after the warning included. The
    /// entry's Error text was never affected, because it reads the failure from the writer's record
    /// and not from the stream; that is asserted too, as the control.
    #[test]
    fn a_control_character_in_a_duplicate_key_is_escaped_in_the_warning() {
        let payload = payload(&[UNPARSABLE_RULE], &[DUPLICATE_KEY_WITH_ESC_TEMPLATE]);
        let (code, notices, failures, stripped) = console_run_recorded(&payload);
        assert_eq!(crate::commands::ERROR_STATUS_CODE, code);
        let warning = notices
            .iter()
            .find(|n| n.contains("duplicate key"))
            .unwrap_or_else(|| panic!("no duplicate-key warning recorded: {:?}", notices));
        assert!(
            !warning.contains('\u{1b}') && warning.contains("/a\\u{1b}]b in data file"),
            "the ESC is written as its escape: {:?}",
            warning
        );
        assert!(
            stripped.contains("/a\\u{1b}]b in data file")
                && stripped.contains("Parsing error handling rule file = RULES_STDIN[1]"),
            "the stream keeps both the warning and the failure that follows it: {:?}",
            stripped
        );
        assert_eq!(1, failures.len(), "{:?}", failures);
        let entry = console_builder()
            .try_build_and_execute(&payload)
            .expect_err("an unparsable rules file must be an error");
        assert!(
            entry.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = ")
                && !entry.contains("duplicate key"),
            "{}",
            entry
        );
    }

    /// A key named `a<LF>b` and a key named with the two characters `\` `n` are two keys, and their
    /// warnings print apart: the line feed as `\n` and the backslash as `\\`, so the escaped form maps
    /// back to one name. Both warnings are one line.
    #[test]
    fn a_line_feed_and_a_literal_backslash_n_in_a_duplicate_key_print_apart() {
        let (_, with_newline, _, _) = console_run_recorded(&payload(
            &[SIZE_RULE],
            &[DUPLICATE_KEY_WITH_NEWLINE_TEMPLATE],
        ));
        let (_, with_literal, _, _) = console_run_recorded(&payload(
            &[SIZE_RULE],
            &[DUPLICATE_KEY_WITH_LITERAL_BACKSLASH_N_TEMPLATE],
        ));
        let newline = with_newline
            .iter()
            .find(|n| n.contains("duplicate key"))
            .unwrap_or_else(|| panic!("{:?}", with_newline));
        let literal = with_literal
            .iter()
            .find(|n| n.contains("duplicate key"))
            .unwrap_or_else(|| panic!("{:?}", with_literal));
        assert_eq!(1, newline.lines().count(), "{:?}", newline);
        assert!(newline.contains("/a\\nb in data file"), "{:?}", newline);
        assert!(literal.contains("/a\\\\nb in data file"), "{:?}", literal);
        assert_ne!(newline, literal);
    }

    fn sarif_run(document: &str) -> serde_json::Value {
        let mut sarif: serde_json::Value =
            serde_json::from_str(document).expect("the document is JSON");
        sarif["runs"][0].take()
    }

    fn rule_ids(run: &serde_json::Value) -> Vec<String> {
        run["results"]
            .as_array()
            .expect("results is an array")
            .iter()
            .map(|result| result["ruleId"].as_str().unwrap().to_string())
            .collect()
    }

    /// The text of the one tool-configuration notification the run's invocation records, or a
    /// panic naming what the run had instead.
    fn invocation_notice(run: &serde_json::Value) -> String {
        let invocations = run["invocations"]
            .as_array()
            .unwrap_or_else(|| panic!("no invocations in {}", run));
        assert_eq!(invocations.len(), 1, "{run}");
        assert_eq!(invocations[0]["executionSuccessful"], false, "{run}");
        let notices = invocations[0]["toolConfigurationNotifications"]
            .as_array()
            .unwrap_or_else(|| panic!("no notifications in {}", run));
        assert_eq!(notices.len(), 1, "{run}");
        assert_eq!(notices[0]["level"], "error", "{run}");
        notices[0]["message"]["text"].as_str().unwrap().to_string()
    }

    #[test]
    fn structured_entry_errs_with_the_parser_message_for_an_unreadable_data_document() {
        // A data document that does not parse is reported on the error stream with the error exit
        // code and no document is written. The entry has no exit code to hand back, so the
        // diagnostic must come back as the error; an empty success string would make the caller
        // believe a document was produced.
        let err = sarif_builder()
            .try_build_and_execute(&payload(&[SIZE_RULE], &[UNTERMINATED_TEMPLATE]))
            .expect_err("an unreadable data document must not look like a written document");
        assert!(
            err.contains("Error encountered while parsing data file: DATA_STDIN[1]"),
            "{}",
            err
        );
    }

    #[test]
    fn structured_entry_returns_a_sarif_document_for_a_compliant_template() {
        let document = sarif_builder()
            .try_build_and_execute(&payload(&[SIZE_RULE], &[SMALL_TEMPLATE]))
            .unwrap();
        let run = sarif_run(&document);
        assert_eq!(rule_ids(&run), Vec::<String>::new(), "{}", run);
        assert!(run["invocations"].is_null(), "{}", run);
    }

    #[test]
    fn structured_entry_returns_a_sarif_document_for_a_non_compliant_template() {
        let document = sarif_builder()
            .try_build_and_execute(&payload(&[SIZE_RULE], &[LARGE_TEMPLATE]))
            .unwrap();
        let run = sarif_run(&document);
        assert_eq!(rule_ids(&run), vec!["r"], "{}", run);
        assert_eq!(run["results"][0]["level"], "error", "{}", run);
    }

    #[test]
    fn structured_entry_records_an_unparsable_rules_file_in_the_sarif_invocations() {
        // The run ends with the error exit code, but the document it wrote carries the failure, so
        // the document is what the caller gets; an `Err` here would hide the invocation record the
        // TypeScript side reads.
        let document = sarif_builder()
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE], &[SMALL_TEMPLATE]))
            .unwrap();
        let run = sarif_run(&document);
        assert!(
            invocation_notice(&run).contains("RULES_STDIN[1]"),
            "{}",
            run
        );
        assert_eq!(rule_ids(&run), Vec::<String>::new(), "{}", run);
    }

    #[test]
    fn structured_entry_keeps_the_valid_rules_findings_beside_an_unparsable_rules_file() {
        let document = sarif_builder()
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE, SIZE_RULE], &[LARGE_TEMPLATE]))
            .unwrap();
        let run = sarif_run(&document);
        assert!(
            invocation_notice(&run).contains("RULES_STDIN[1]"),
            "{}",
            run
        );
        assert_eq!(rule_ids(&run), vec!["r"], "{}", run);
    }

    #[test]
    fn structured_entry_keeps_a_failing_rules_finding_beside_an_undeclared_variable() {
        // An undeclared name is the author's mistake and ends the run with the error exit code, but
        // the document records it as an error-level result for that rule and still carries the
        // other rule's finding, so the document is returned.
        let document = sarif_builder()
            .try_build_and_execute(&payload(
                &[UNDECLARED_VARIABLE_RULE, SIZE_RULE],
                &[LARGE_TEMPLATE],
            ))
            .unwrap();
        let run = sarif_run(&document);
        let mut ids = rule_ids(&run);
        ids.sort();
        assert_eq!(ids, vec!["broken", "r"], "{}", run);
        let broken = run["results"]
            .as_array()
            .unwrap()
            .iter()
            .find(|result| result["ruleId"] == "broken")
            .unwrap();
        assert_eq!(broken["level"], "error", "{}", run);
        assert!(
            broken["message"]["text"]
                .as_str()
                .unwrap()
                .contains("undeclared"),
            "{}",
            run
        );
    }

    #[test]
    fn console_entry_errs_when_a_rules_file_beside_a_valid_one_does_not_parse() {
        // The single-line summary of the valid rule is all the console run writes to its output,
        // and it reads as a complete run. The summary has no place for the failure, so it has to be
        // the error; the file name is written underlined on the console and the escapes must not
        // reach JavaScript.
        let err = console_builder()
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE, SIZE_RULE], &[LARGE_TEMPLATE]))
            .expect_err("a console run that ended with the error exit code must not look complete");
        assert!(
            err.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
        assert!(!err.contains('\u{1b}'), "{:?}", err);
    }

    #[test]
    fn console_entry_returns_the_summary_for_a_compliant_template() {
        // The default summary reports failures only, so a compliant run writes nothing; asking for
        // passes too makes the control observable.
        //
        // Color is forced on so the verdict is written wrapped in escapes whatever the runner is:
        // without forcing, a runner with no terminal writes none, and a document strip that went
        // missing from the entry would stay green here while colored verdicts reached JavaScript. The
        // guard also keeps the forced window from overlapping the other forcing test. The stripped
        // text is asserted whole, and the escapes are asserted gone.
        let _forced = ForcedColor::new();
        let summary = console_builder()
            .show_summary(vec![ShowSummaryType::Pass])
            .try_build_and_execute(&payload(&[SIZE_RULE], &[SMALL_TEMPLATE]))
            .unwrap();
        assert!(summary.contains("Status = PASS"), "{}", summary);
        assert!(!summary.contains('\u{1b}'), "{:?}", summary);
    }

    #[test]
    fn console_entry_message_is_the_failure_not_the_deprecation_written_after_it() {
        // The unparsable rules file is reported when it is parsed; the deprecation notice comes from
        // the valid rule that runs after it, so the stream ends with a notice rather than opening
        // with one.
        let notices = notices_of(
            &[UNPARSABLE_RULE, DEPRECATED_MEMBERSHIP_RULE],
            &[STRING_TEMPLATE],
        );
        assert!(
            wrote_a_deprecation(&notices),
            "the run wrote a deprecation notice, or the absence below measures nothing: {:?}",
            notices
        );
        let err = console_builder()
            .try_build_and_execute(&payload(
                &[UNPARSABLE_RULE, DEPRECATED_MEMBERSHIP_RULE],
                &[STRING_TEMPLATE],
            ))
            .expect_err("an unparsable rules file must be an error");
        assert!(
            err.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
        assert!(!err.contains("DEPRECATION"), "{}", err);
    }

    #[test]
    fn console_entry_message_is_the_failure_between_a_warning_and_a_deprecation() {
        // The stream is: the duplicate-key warning (written when the document is read), the
        // rules-file failure, its `---` separator, then the deprecation notice from the rule that
        // ran afterwards. Neither notice is the failure, and a message that keeps only what follows
        // the last notice would hold nothing of it.
        let notices = notices_of(
            &[UNPARSABLE_RULE, DEPRECATED_MEMBERSHIP_RULE],
            &[DUPLICATE_KEY_AND_STRING_TEMPLATE],
        );
        assert!(
            wrote_a_deprecation(&notices),
            "the run wrote a deprecation notice, or the absence below measures nothing: {:?}",
            notices
        );
        assert!(
            notices
                .iter()
                .any(|notice| notice.starts_with(WARNING_PREFIX)),
            "the run wrote the duplicate-key warning: {:?}",
            notices
        );
        let err = console_builder()
            .try_build_and_execute(&payload(
                &[UNPARSABLE_RULE, DEPRECATED_MEMBERSHIP_RULE],
                &[DUPLICATE_KEY_AND_STRING_TEMPLATE],
            ))
            .expect_err("an unparsable rules file must be an error");
        assert!(
            err.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
        assert!(!err.contains("Warning:"), "{}", err);
        assert!(!err.contains("DEPRECATION"), "{}", err);
    }

    #[test]
    fn console_entry_message_is_the_undeclared_variable_not_the_deprecation_written_after_it() {
        let notices = notices_of(
            &[UNDECLARED_VARIABLE_RULE, DEPRECATED_MEMBERSHIP_RULE],
            &[STRING_TEMPLATE],
        );
        assert!(
            wrote_a_deprecation(&notices),
            "the run wrote a deprecation notice, or the absence below measures nothing: {:?}",
            notices
        );
        let err = console_builder()
            .try_build_and_execute(&payload(
                &[UNDECLARED_VARIABLE_RULE, DEPRECATED_MEMBERSHIP_RULE],
                &[STRING_TEMPLATE],
            ))
            .expect_err("an undeclared variable must be an error");
        assert!(
            err.starts_with("Error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
        assert!(err.contains("undeclared"), "{}", err);
        assert!(!err.contains("DEPRECATION"), "{}", err);
    }

    #[test]
    fn console_entry_message_carries_no_color_escapes_when_color_is_forced() {
        // `colored` writes escapes only on a tty or when forced, so without forcing, the strip has
        // nothing to remove and a missing strip goes unnoticed. The override is process-wide, so it
        // is forced through the guard, which keeps two forced windows from overlapping and puts the
        // flag back when it drops, so a panic here cannot leave color forced on for the tests that
        // run afterwards. The siblings that run meanwhile are not kept out: they are safe because
        // they read stripped text. A test that asserts on unstripped text takes a `ForcedColor` too.
        let _forced = ForcedColor::new();
        let err = console_builder()
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE, SIZE_RULE], &[LARGE_TEMPLATE]))
            .expect_err("an unparsable rules file must be an error");
        assert!(
            err.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
        assert!(!err.contains('\u{1b}'), "{:?}", err);
    }

    #[test]
    fn console_entry_message_is_the_failure_not_the_warning_written_before_it() {
        // The duplicate key is reported when the data document is read, before the rules file is
        // parsed, so the error stream opens with a warning about something other than the failure.
        let err = console_builder()
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE], &[DUPLICATE_KEY_TEMPLATE]))
            .expect_err("an unparsable rules file must be an error");
        assert!(
            err.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
        assert!(!err.contains("duplicate key"), "{}", err);
        assert!(!err.contains('\u{1b}'), "{:?}", err);
    }

    #[test]
    fn entry_errs_with_the_payload_parse_message_for_malformed_payload_json() {
        let err = sarif_builder()
            .try_build_and_execute("{not json")
            .expect_err("a payload that is not JSON must be an error");
        assert!(
            err.contains("Unable to parse the --payload JSON read from stdin"),
            "{}",
            err
        );
    }

    #[test]
    fn entry_errs_when_the_rules_list_is_empty() {
        // Such a run checks nothing, warns so only on the error stream and exits 0, and no writer
        // records the warning in its document; on either path a returned document would read as a
        // pass of a policy nobody applied.
        for builder in [sarif_builder(), console_builder()] {
            let err = builder
                .try_build_and_execute(&payload(&[], &[SMALL_TEMPLATE]))
                .expect_err("a run with no rules must be an error");
            assert!(
                err.starts_with("Warning: no rules files were evaluated. Nothing was checked"),
                "{}",
                err
            );
        }
    }

    #[test]
    fn entry_errs_when_the_data_list_is_empty() {
        for builder in [sarif_builder(), console_builder()] {
            let err = builder
                .try_build_and_execute(&payload(&[SIZE_RULE], &[]))
                .expect_err("a run with no data must be an error");
            assert!(
                err.starts_with("Warning: no data files were evaluated. Nothing was checked"),
                "{}",
                err
            );
        }
    }

    const DUPLICATE_KEY_NOTICE: &str =
        "Warning: duplicate key /Resources/A/Properties/Size in data file DATA_STDIN[1], first at \
         L:5,C:7 and again at L:6,C:7. The last value is the one evaluated.";
    /// A notice over three lines, the way a deprecation notice reads when it quotes a clause written
    /// over several.
    const MULTI_LINE_NOTICE: &str =
        "DEPRECATION: the clause\n  Sizes == 50\npassed because the value could not be compared \
         with any element of the list.";

    /// A writer whose error stream is read back, so it keeps the records the entry point reads.
    fn recording_writer() -> Writer {
        Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).unwrap()
    }

    #[test]
    fn failure_message_of_an_error_run_that_wrote_only_notices_is_not_a_notice() {
        // Two notices and nothing else, as a run that ended with the error exit code without writing
        // its failure would leave the stream. Neither notice is the failure, and no part of one may
        // be reported as it: such a run wrote no diagnostic.
        let mut writer = recording_writer();
        writer
            .write_notice(DUPLICATE_KEY_NOTICE.to_string())
            .unwrap();
        writer.write_notice(MULTI_LINE_NOTICE.to_string()).unwrap();

        let message = failure_message(writer.failures(), None);

        assert_eq!(message, NO_DIAGNOSTIC);
        let (_, stream) = writer.into_stripped_parts().unwrap();
        assert!(stream.contains("Sizes == 50"), "{:?}", stream);
    }

    #[test]
    fn failure_message_keeps_a_failure_written_between_a_multi_line_notice_and_another() {
        // The failure sits between the notices and runs over two lines of its own, followed by the
        // console's separator. Every line of the notices goes, every line of the failure stays.
        let failure =
            "Parsing error handling rule file = RULES_STDIN[1], Error =\n  unexpected end";
        let mut writer = recording_writer();
        writer.write_notice(MULTI_LINE_NOTICE.to_string()).unwrap();
        writer.write_err(format!("{failure}\n---")).unwrap();
        writer
            .write_notice(DUPLICATE_KEY_NOTICE.to_string())
            .unwrap();

        let message = failure_message(writer.failures(), None);

        assert_eq!(message, failure);
    }

    #[test]
    fn failure_message_of_a_run_that_checked_nothing_is_its_report_and_nothing_written_after_it() {
        // The run that checked nothing is known from the report the command recorded, not from the
        // stream's shape. The message is the report with the warning first, then the files the
        // command passed over. A notice written afterwards about something else is not part of it.
        let skipped =
            "Warning: notes.txt was not evaluated because its extension is not one of: guard, ruleset";
        let warning = no_rules_evaluated_warning();
        let mut writer = recording_writer();
        writer
            .write_nothing_checked([skipped.to_string()], warning.clone())
            .unwrap();
        writer
            .write_notice(DUPLICATE_KEY_NOTICE.to_string())
            .unwrap();

        let found = nothing_checked_message(&writer);
        let message = failure_message(writer.failures(), found.as_deref());

        assert_eq!(message, format!("{warning}\n{skipped}"));
    }

    #[test]
    fn failure_message_prefers_a_written_failure_to_the_nothing_checked_warning() {
        // A run with no data file that still ended with the error exit code wrote a failure, and
        // that is what it is reported by; the warning is the fallback for when it wrote none.
        let nothing_checked = no_data_evaluated_warning();
        let failure = "Parsing error handling rule file = RULES_STDIN[1], Error = unexpected end";
        let mut writer = recording_writer();
        writer.write_notice(nothing_checked.clone()).unwrap();
        writer.write_err(format!("{failure}\n---")).unwrap();

        let message = failure_message(writer.failures(), Some(&nothing_checked));

        assert_eq!(message, failure);
    }

    #[test]
    fn a_notice_written_through_the_writer_is_kept_out_of_the_failure_message() {
        // The writer's records are what the message is built from, so a notice written through
        // `write_notice` with the shared prefix never reaches the message whatever its spelling, and
        // a failure written through `write_err` beside it does.
        let mut writer = recording_writer();
        writer
            .write_notice(format!(
                "{WARNING_PREFIX} something the run went on from\n  over a second line"
            ))
            .unwrap();
        writer
            .write_notice(format!(
                "{DEPRECATION_PREFIX} something a future release changes"
            ))
            .unwrap();
        assert_eq!(writer.notices().len(), 2, "{:?}", writer.notices());
        assert_eq!(failure_message(writer.failures(), None), NO_DIAGNOSTIC);

        writer.write_err("the failure".to_string()).unwrap();
        assert_eq!(failure_message(writer.failures(), None), "the failure");
    }

    #[test]
    fn a_run_that_checked_nothing_is_recognized_whatever_its_warning_says() {
        // The command says it checked nothing as a fact of its own, not through the wording of the
        // warning it writes, so a reworded warning leaves the entry's decision where it was.
        let reworded = "Warning: no rules file was found under the directory given";
        let mut writer = recording_writer();
        writer
            .write_nothing_checked(Vec::new(), reworded.to_string())
            .unwrap();

        let message = nothing_checked_message(&writer);

        assert_eq!(message.as_deref(), Some(reworded));
        assert_eq!(writer.notices(), [reworded]);
    }

    #[test]
    fn nothing_checked_message_reads_the_recorded_warnings_in_the_order_written() {
        let rules = no_rules_evaluated_warning();
        let data = no_data_evaluated_warning();

        let writer = recording_writer();
        assert_eq!(nothing_checked_message(&writer), None);

        let mut writer = recording_writer();
        writer
            .write_notice(DUPLICATE_KEY_NOTICE.to_string())
            .unwrap();
        assert_eq!(nothing_checked_message(&writer), None);
        writer
            .write_nothing_checked(Vec::new(), rules.clone())
            .unwrap();
        assert_eq!(nothing_checked_message(&writer), Some(rules.clone()));

        let mut writer = recording_writer();
        writer
            .write_nothing_checked(Vec::new(), data.clone())
            .unwrap();
        writer
            .write_nothing_checked(Vec::new(), rules.clone())
            .unwrap();
        assert_eq!(
            nothing_checked_message(&writer),
            Some(format!("{data}\n{rules}"))
        );
        let warnings: Vec<&str> = writer
            .nothing_checked()
            .iter()
            .map(|report| report.warning.as_str())
            .collect();
        assert_eq!(warnings, [data.as_str(), rules.as_str()]);
    }

    #[test]
    fn entry_errs_with_both_warnings_when_both_lists_are_empty() {
        for builder in [sarif_builder(), console_builder()] {
            let err = builder
                .try_build_and_execute(&payload(&[], &[]))
                .expect_err("a run with nothing to check must be an error");
            assert!(
                err.starts_with("Warning: no rules files were evaluated. Nothing was checked"),
                "{}",
                err
            );
            assert!(
                err.contains("\nWarning: no data files were evaluated. Nothing was checked"),
                "{}",
                err
            );
        }
    }

    #[test]
    fn structured_entry_reports_the_parse_error_when_the_data_list_is_empty() {
        // With no data file there is no per-file record for the rules-file error to live in, so the
        // document the run wrote is an empty one (`[]`, an empty sarif run, a zero-test junit suite)
        // that records no failure. The parse error on the error stream is the message, not the
        // nothing-checked warning.
        let err = sarif_builder()
            .try_build_and_execute(&payload(&[UNPARSABLE_RULE], &[]))
            .expect_err("an unparsable rules file must be an error");
        assert!(
            err.starts_with("Parsing error handling rule file = RULES_STDIN[1], Error = "),
            "{}",
            err
        );
    }

    #[test]
    fn builder_mode_entry_does_not_read_the_data_document_as_a_payload() {
        // With `rules` set, what the entry is handed is the data document itself, read from stdin.
        // A document that happens to carry a top-level `rules: []` names nothing to check: the
        // rules in the directory ran.
        let result = ValidateBuilder::default()
            .rules(vec![RULES_DIR.to_string()])
            .try_build_and_execute(r#"{"rules": [], "data": [], "Resources": {}}"#);
        assert!(result.is_ok(), "{:?}", result);
    }

    #[test]
    fn builder_mode_entry_errs_when_the_rules_directory_holds_no_rules_file() {
        // The directory has no `.guard` or `.ruleset` file, so the command warns that no rules
        // file was evaluated and exits 0; the entry must not hand that back as a pass.
        let err = ValidateBuilder::default()
            .rules(vec![
                "resources/validate/only-unrelated-files-dir".to_string()
            ])
            .try_build_and_execute("Resources: {}\n")
            .expect_err("a run with no rules file must be an error");
        assert!(
            err.contains("Warning: no rules files were evaluated. Nothing was checked"),
            "{}",
            err
        );
    }

    /// The structure of a nothing-checked error, asserted without counting its lines: the warning
    /// opens it; every later line is a warning, naming a file the walk passed over or, as the last
    /// line, counting the files past [`SKIPPED_FILES_NAMED`]; and when no line counts, so every
    /// file is named, one of them names `name`. A count would break on any file added to the
    /// fixture directory with no change of behavior, and a check for the name would break once the
    /// directory holds more files than the message names.
    fn assert_nothing_checked_error(err: &str, warning: &str, name: &str) {
        let lines: Vec<&str> = err.lines().collect();
        assert!(!lines.is_empty(), "{}", err);
        assert_eq!(lines[0], warning, "the warning opens the error:\n{}", err);
        let later = &lines[1..];
        assert!(
            later.iter().all(|line| line.starts_with(WARNING_PREFIX)),
            "every later line is a warning:\n{}",
            err
        );
        let counts_the_rest = |line: &&str| line.contains(" more file");
        assert!(
            later.iter().enumerate().all(|(i, line)| {
                line.contains("was not evaluated")
                    || (i + 1 == later.len() && counts_the_rest(line))
            }),
            "every later line names a file passed over, or the last counts the rest:\n{}",
            err
        );
        if !later.last().is_some_and(counts_the_rest) {
            assert!(
                later.iter().any(|line| line.contains(name)),
                "one of them names {name}:\n{}",
                err
            );
        }
    }

    #[test]
    fn builder_mode_entry_opens_with_the_warning_and_then_names_the_files_it_passed_over() {
        // The error a caller is thrown opens with the sentence that says nothing was checked, so a
        // caller that matches on its opening, or shows its first line, sees the same opening whatever
        // the directory held; the files the walk passed over follow it, because the names are what
        // tell the reader why. The CLI's own stderr keeps its order, names first and the warning last.
        // The fixture directory holds README.md and no rules file; the directory for the test
        // command's orphaned-file cell exists beside it.
        let err = ValidateBuilder::default()
            .rules(vec![
                "resources/validate/only-unrelated-files-dir".to_string()
            ])
            .try_build_and_execute("Resources: {}\n")
            .expect_err("a run with no rules file must be an error");
        assert_nothing_checked_error(&err, &no_rules_evaluated_warning(), "README.md");
    }

    #[test]
    fn builder_mode_entry_opens_with_the_data_warning_when_the_data_directory_holds_no_data_file() {
        // The data side of the same shape: a `data` directory that holds only a README.
        let err = ValidateBuilder::default()
            .rules(vec![RULES_DIR.to_string()])
            .data(vec![
                "resources/validate/only-unrelated-files-dir".to_string()
            ])
            .try_build_and_execute("")
            .expect_err("a run with no data file must be an error");
        assert_nothing_checked_error(&err, &no_data_evaluated_warning(), "README.md");
    }

    #[test]
    fn the_structure_check_holds_when_the_passed_over_files_outnumber_the_cap() {
        // A rules directory holding two more unrelated files than the message names: the error
        // then ends with the line counting the rest, in the plural, and the last name the walk met
        // may be among the counted rather than the named. The structure check reads that error as
        // it reads a two-line one, since the directory's size is not a change of behavior.
        // The directory is this process's own and is removed on every exit from the test, pass,
        // failure or panic, by the guard below; a leftover from an earlier run, which could hold
        // other files and move the line count, is removed before it is filled.
        struct RemoveOnDrop(std::path::PathBuf);
        impl Drop for RemoveOnDrop {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
        let dir =
            std::env::temp_dir().join(format!("cfn-guard-lib-counted-rest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let _guard = RemoveOnDrop(dir.clone());
        for n in 1..=SKIPPED_FILES_NAMED + 2 {
            std::fs::write(dir.join(format!("file-{n:02}.txt")), "").unwrap();
        }

        let err = ValidateBuilder::default()
            .rules(vec![dir.to_string_lossy().into_owned()])
            .try_build_and_execute("Resources: {}\n")
            .expect_err("a run with no rules file must be an error");

        assert_nothing_checked_error(&err, &no_rules_evaluated_warning(), "file-01.txt");
        let lines: Vec<&str> = err.lines().collect();
        assert_eq!(lines.len(), SKIPPED_FILES_NAMED + 2, "{}", err);
        assert!(
            lines[SKIPPED_FILES_NAMED + 1]
                .ends_with("2 more files were not evaluated for the same reason"),
            "{}",
            err
        );
    }

    #[test]
    fn an_unterminated_escape_inside_a_notice_does_not_swallow_the_failure_after_it() {
        // Quoted clause text can carry a lone `ESC ]`, which opens an OSC sequence that nothing
        // terminates. Stripping the stream as one text would run that sequence past the notice's
        // newline into the failure written after it, so the failure must be recovered from what was
        // written, not from the stripped stream.
        let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).unwrap();
        writer
            .write_notice(format!(
                "{DEPRECATION_PREFIX} the clause `Name == \"\u{1b}]title\"` passed"
            ))
            .unwrap();
        writer.write_err("the failure".to_string()).unwrap();

        assert_eq!(failure_message(writer.failures(), None), "the failure");
    }

    #[test]
    fn a_nothing_checked_report_without_skipped_files_is_still_the_warning() {
        // The message for a run that checked nothing is never empty: the warning is part of every
        // report, whether or not the directory walk passed over any file.
        let warning = no_data_evaluated_warning();
        let mut writer = recording_writer();
        writer
            .write_nothing_checked(Vec::new(), warning.clone())
            .unwrap();

        let message = failure_message(
            writer.failures(),
            nothing_checked_message(&writer).as_deref(),
        );

        assert_eq!(message, warning);
    }

    #[test]
    fn skipped_file_names_in_the_message_are_stripped_of_escape_sequences() {
        // A file name is whatever the file system holds, escape sequences included, and the names
        // reach the message the way failures do: with the sequences a terminal would interpret
        // removed and every other byte kept.
        let skipped = format!(
            "{WARNING_PREFIX} \u{1b}[31mnotes\u{1b}[0m.txt was not evaluated because its extension \
             is not one of: guard, ruleset"
        );
        let warning = no_rules_evaluated_warning();
        let mut writer = recording_writer();
        writer
            .write_nothing_checked([skipped], warning.clone())
            .unwrap();

        let message = failure_message(
            writer.failures(),
            nothing_checked_message(&writer).as_deref(),
        );

        assert!(!message.contains('\u{1b}'), "{:?}", message);
        assert!(
            message.contains("notes.txt was not evaluated"),
            "{:?}",
            message
        );
        assert!(message.starts_with(&warning), "{:?}", message);
    }

    #[test]
    fn the_message_names_a_bounded_number_of_skipped_files_and_counts_the_rest() {
        // A directory of unrelated files would otherwise put one line per file into the error a
        // caller is thrown. The warning comes first, the first names are kept, the rest are counted.
        let skipped: Vec<String> = (1..=25)
            .map(|n| {
                format!(
                    "{WARNING_PREFIX} file-{n:02}.txt was not evaluated because its extension is \
                     not one of: guard, ruleset"
                )
            })
            .collect();
        let warning = no_rules_evaluated_warning();
        let mut writer = recording_writer();
        writer
            .write_nothing_checked(skipped.clone(), warning.clone())
            .unwrap();

        let message = failure_message(
            writer.failures(),
            nothing_checked_message(&writer).as_deref(),
        );
        let lines: Vec<&str> = message.lines().collect();

        let named = SKIPPED_FILES_NAMED;
        assert_eq!(lines.len(), named + 2, "{}", message);
        assert_eq!(lines[0], warning, "{}", message);
        assert_eq!(lines[1], skipped[0], "{}", message);
        assert_eq!(lines[named], skipped[named - 1], "{}", message);
        assert!(
            lines[named + 1].starts_with("Warning: ")
                && lines[named + 1].contains(&format!("{} more", 25 - named)),
            "{}",
            message
        );
        // The CLI's own stderr is not capped: every file is named there.
        assert_eq!(writer.notices().len(), 25 + 1, "{:?}", writer.notices());
    }

    #[test]
    fn the_count_of_the_rest_is_worded_for_one_file_as_for_many() {
        // One file past the cap is counted in the singular; the plural form is the other cell's.
        let skipped: Vec<String> = (1..=SKIPPED_FILES_NAMED + 1)
            .map(|n| {
                format!(
                    "{WARNING_PREFIX} file-{n:02}.txt was not evaluated because its extension is \
                     not one of: guard, ruleset"
                )
            })
            .collect();
        let warning = no_rules_evaluated_warning();
        let mut writer = recording_writer();
        writer
            .write_nothing_checked(skipped, warning.clone())
            .unwrap();

        let message = failure_message(
            writer.failures(),
            nothing_checked_message(&writer).as_deref(),
        );
        let lines: Vec<&str> = message.lines().collect();

        assert_eq!(lines.len(), SKIPPED_FILES_NAMED + 2, "{}", message);
        assert_eq!(lines[0], warning, "{}", message);
        assert_eq!(
            lines[SKIPPED_FILES_NAMED + 1],
            format!("{WARNING_PREFIX} and 1 more file was not evaluated for the same reason"),
            "{}",
            message
        );
    }

    #[test]
    fn validate_with_errors() {
        // fails cause structured, but show_summary fail. Spelled out: the default follows the format
        // and is `none` here, so only an explicit summary type is a conflict.
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .rules(vec![String::from("resources/validate/rules-dir")])
            .structured(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .show_summary(vec![ShowSummaryType::Fail])
            .try_build();
        assert!(cmd.is_err());

        // fails cause structured, but single-line-summary
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .rules(vec![String::from("resources/validate/rules-dir")])
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();
        assert!(cmd.is_err());

        // fails cause structured, but verbose
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .rules(vec![String::from("resources/validate/rules-dir")])
            .structured(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .verbose(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();
        assert!(cmd.is_err());

        // fails cause structured, but print_json
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .rules(vec![String::from("resources/validate/rules-dir")])
            .structured(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .print_json(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();
        assert!(cmd.is_err());

        // fails cause junit or sarif, but not structured
        vec![
            crate::commands::validate::OutputFormatType::Junit,
            crate::commands::validate::OutputFormatType::Sarif,
        ]
        .into_iter()
        .for_each(|output_format| {
            let cmd = ValidateBuilder::default()
                .data(vec![String::from("resources/validate/data-dir")])
                .rules(vec![String::from("resources/validate/rules-dir")])
                .output_format(output_format)
                .show_summary(vec![ShowSummaryType::None])
                .try_build();

            assert!(cmd.is_err());
        });

        // fails cause no payload, or rules
        let cmd = ValidateBuilder::default()
            .output_format(crate::commands::validate::OutputFormatType::Junit)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_err());

        // fails cause payload, and rules conflict
        let cmd = ValidateBuilder::default()
            .rules(vec![String::from("resources/validate/rules-dir")])
            .payload(true)
            .output_format(crate::commands::validate::OutputFormatType::Junit)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_err());

        // fails cause payload, and data conflict
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .payload(true)
            .output_format(crate::commands::validate::OutputFormatType::Junit)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_err());

        // fails cause last_modified, and alphabetical conflict
        let cmd = ValidateBuilder::default()
            .payload(true)
            .alphabetical(true)
            .last_modified(true)
            .output_format(crate::commands::validate::OutputFormatType::Junit)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_err());
    }

    /// Every case `try_build` accepts is one `execute` runs to a verdict rather than rejecting as a
    /// bad combination of arguments, so each built command is also executed here, on the one
    /// rules-file/data-file pair this module uses for a known FAIL verdict, and the exact exit code
    /// is asserted. A directory-on-directory run would make this test answer for every fixture in
    /// the tree instead of for the builder.
    ///
    /// The JSON rows also check that stdout is one JSON document, and for the plain JSON report
    /// that its status is FAIL: the first row sets only rules, data and the format, so the summary
    /// default in force is the format's and the report is the whole of stdout; the last sets
    /// `[Fail, None]`, which `None` clears, so it builds and runs as `-S fail,none` does on the
    /// command line rather than being refused as a list that holds `Fail`. The structured JSON row
    /// is a different document shape, checked only to be one JSON document.
    #[test]
    fn validate_happy_path() {
        enum Stdout {
            Unchecked,
            OneJsonDocument,
            OneJsonReportThatFailed,
        }

        let data = vec![String::from(FAILING_DATA)];
        let rules = vec![String::from(FAILING_RULES)];
        let cases = vec![
            (
                ValidateBuilder::default()
                    .output_format(OutputFormatType::JSON)
                    .data(data.clone())
                    .rules(rules.clone()),
                FAILURE_STATUS_CODE,
                Stdout::OneJsonReportThatFailed,
            ),
            (
                ValidateBuilder::default()
                    .verbose(true)
                    .show_summary(vec![
                        ShowSummaryType::Pass,
                        ShowSummaryType::Fail,
                        ShowSummaryType::Skip,
                    ])
                    .data(data.clone())
                    .rules(rules.clone()),
                FAILURE_STATUS_CODE,
                Stdout::Unchecked,
            ),
            (
                ValidateBuilder::default()
                    .verbose(true)
                    .data(data.clone())
                    .rules(rules.clone()),
                FAILURE_STATUS_CODE,
                Stdout::Unchecked,
            ),
            (
                ValidateBuilder::default()
                    .data(data.clone())
                    .rules(rules.clone())
                    .structured(true)
                    .output_format(OutputFormatType::JSON)
                    .show_summary(vec![ShowSummaryType::None]),
                FAILURE_STATUS_CODE,
                Stdout::OneJsonDocument,
            ),
            (
                ValidateBuilder::default()
                    .data(data.clone())
                    .rules(rules.clone())
                    .output_format(OutputFormatType::Junit)
                    .structured(true)
                    .show_summary(vec![ShowSummaryType::None]),
                FAILURE_STATUS_CODE,
                Stdout::Unchecked,
            ),
            (
                ValidateBuilder::default()
                    .data(data.clone())
                    .rules(rules.clone())
                    .show_summary(vec![ShowSummaryType::Fail, ShowSummaryType::None])
                    .output_format(OutputFormatType::JSON),
                FAILURE_STATUS_CODE,
                Stdout::OneJsonReportThatFailed,
            ),
        ];

        for (builder, expected_code, stdout) in cases {
            let description = format!("{:?}", builder);
            let cmd = builder
                .try_build()
                .unwrap_or_else(|e| panic!("{} must build: {}", description, e));
            let (outcome, document) = execute(cmd);
            assert!(
                matches!(outcome, Ok(code) if code == expected_code),
                "{} must exit {}, got {:?}",
                description,
                expected_code,
                outcome
            );
            if matches!(stdout, Stdout::Unchecked) {
                continue;
            }
            let report: serde_json::Value = serde_json::from_str(&document).unwrap_or_else(|e| {
                panic!(
                    "{}: stdout is not one JSON document: {}\n{}",
                    description, e, document
                )
            });
            if matches!(stdout, Stdout::OneJsonReportThatFailed) {
                assert_eq!(Some("FAIL"), report["status"].as_str(), "{}", description);
            }
        }
    }

    #[test]
    fn build_test_command_happy_path() {
        let data = String::from("resources/validate/data-dir");
        let rules = String::from("resources/validate/rules-dir");
        let cmd = TestBuilder::default()
            .test_data(Option::from(data.clone()))
            .rules(Option::from(rules.clone()))
            .try_build();

        assert!(cmd.is_ok());

        let cmd = TestBuilder::default()
            .directory(Option::from(data.clone()))
            .try_build();
        assert!(cmd.is_ok());

        let cmd = TestBuilder::default()
            .directory(Option::from(data.clone()))
            .alphabetical(true)
            .try_build();

        assert!(cmd.is_ok())
    }

    #[test]
    fn build_test_command_with_errors() {
        let data = String::from("resources/validate/data-dir");
        let rules = String::from("resources/validate/rules-dir");

        // fails cause rules and dir
        let cmd = TestBuilder::default()
            .rules(Option::from(rules.clone()))
            .directory(Option::from(data.clone()))
            .try_build();

        assert!(cmd.is_err());

        // fails cause alphabetical and last_modified
        let cmd = TestBuilder::default()
            .directory(Option::from(data.clone()))
            .last_modified(true)
            .alphabetical(true)
            .try_build();

        assert!(cmd.is_err());
    }

    /// The builder and the command line refuse the same combinations of arguments.
    ///
    /// Three rows are format conflicts that reach `execute`, a second document on stdout beside a
    /// machine-readable report whether or not `structured` is set (gating the checks on `structured`
    /// alone let `verbose(true)` beside `output_format(JSON)` build and then fail at `execute`; an
    /// explicit `show_summary` other than `None` is a second document too, as `-o json -S fail` is).
    /// clap parses them, both paths then ask `Validate::validate_construct`, and the two messages
    /// are asserted equal and to name the format. The equality is what makes a second copy of the
    /// shared rule impossible to introduce unnoticed: a check added to `try_build` with its own
    /// wording for one of these rows fails here. Two rows are conflicts clap declares itself
    /// (`--rules` beside `--payload` through `conflicts_with`, `-a` beside `-m`) and rejects at
    /// parse time as an `ArgumentConflict`, which the builder refuses in `try_build` with its own
    /// text, library and wasm API text that `try_build_js_and_execute` returns to JavaScript callers
    /// as is. For those two only the refusal is asserted on each side, never the wording, and the
    /// clap error kind is checked so that a parse failure of another kind (an unknown short flag,
    /// say) does not pass as the conflict under test.
    #[test]
    fn validate_builder_and_cli_refuse_the_same_combinations() {
        fn builder_message(builder: ValidateBuilder) -> String {
            let description = format!("{:?}", builder);
            match builder.try_build() {
                Err(Error::IllegalArguments(message)) => message,
                other => panic!("the builder must refuse {}, got {:?}", description, other),
            }
        }

        fn parse(args: &[&str]) -> Result<CfnGuard, clap::Error> {
            let mut argv = vec!["cfn-guard", "validate"];
            argv.extend_from_slice(args);
            CfnGuard::try_parse_from(argv)
        }

        let rules = vec![String::from(RULES_DIR)];
        let data = vec![String::from(DATA_DIR)];

        // Reach `execute`; both sides read `validate_construct`'s message, which names the format.
        let shared_rule = vec![
            (
                ValidateBuilder::default()
                    .rules(rules.clone())
                    .data(data.clone())
                    .verbose(true)
                    .output_format(OutputFormatType::JSON),
                vec!["-r", RULES_DIR, "-d", DATA_DIR, "-o", "json", "-v"],
                "JSON",
            ),
            (
                ValidateBuilder::default()
                    .rules(rules.clone())
                    .data(data.clone())
                    .print_json(true)
                    .output_format(OutputFormatType::YAML),
                vec!["-r", RULES_DIR, "-d", DATA_DIR, "-o", "yaml", "-p"],
                "YAML",
            ),
            (
                ValidateBuilder::default()
                    .rules(rules.clone())
                    .data(data.clone())
                    .show_summary(vec![ShowSummaryType::Fail])
                    .output_format(OutputFormatType::JSON),
                vec!["-r", RULES_DIR, "-d", DATA_DIR, "-o", "json", "-S", "fail"],
                "JSON",
            ),
        ];
        for (builder, args, format) in shared_rule {
            let from_builder = builder_message(builder);
            assert!(
                from_builder.contains(format),
                "{:?}: the message must name the format, got {:?}",
                args,
                from_builder
            );

            let cmd = parse(&args).unwrap_or_else(|e| panic!("clap accepts {:?}: {}", args, e));
            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let mut reader = Reader::default();
            let from_cli = match cmd.execute(&mut writer, &mut reader) {
                Err(Error::IllegalArguments(message)) => message,
                other => panic!(
                    "the command line must refuse {:?} at execute, got {:?}",
                    args, other
                ),
            };

            assert_eq!(from_cli, from_builder, "{:?}", args);
        }

        // clap's own conflicts, rejected at parse time; the builder's own checks and texts.
        let clap_rule = vec![
            (
                ValidateBuilder::default()
                    .rules(rules.clone())
                    .payload(true),
                vec!["-P", "-r", RULES_DIR],
            ),
            (
                ValidateBuilder::default()
                    .rules(rules.clone())
                    .data(data.clone())
                    .alphabetical(true)
                    .last_modified(true),
                vec!["-r", RULES_DIR, "-d", DATA_DIR, "-a", "-m"],
            ),
        ];
        for (builder, args) in clap_rule {
            builder_message(builder);

            match parse(&args) {
                Err(e) if e.kind() == clap::error::ErrorKind::ArgumentConflict => {}
                Err(e) => panic!(
                    "clap must reject {:?} as an argument conflict, got {:?}",
                    args,
                    e.kind()
                ),
                Ok(_) => panic!(
                    "clap must reject {:?} as an argument conflict, but it parsed",
                    args
                ),
            }
        }
    }

    /// `try_build`'s own messages are the library's API text and do not move.
    ///
    /// Three conflicts never reach `validate_construct` because the command line rejects them at
    /// parse time, so the builder states them itself. `try_build_js_and_execute` hands the text to
    /// JavaScript callers as is, so it is pinned here word for word.
    #[test]
    fn validate_builder_own_messages_are_stable() {
        let cases = vec![
            (
                ValidateBuilder::default()
                    .rules(vec![String::from(RULES_DIR)])
                    .payload(true),
                "cannot construct a validate command payload conflicts with both data and rules arguments",
            ),
            (
                ValidateBuilder::default().data(vec![String::from(DATA_DIR)]),
                "cannot construct a validate command: either payload must be set to true, or rules must not be empty",
            ),
            (
                ValidateBuilder::default()
                    .rules(vec![String::from(RULES_DIR)])
                    .alphabetical(true)
                    .last_modified(true),
                "cannot have both last modified, and alphabetical arguments set to true",
            ),
        ];

        for (builder, expected) in cases {
            let description = format!("{:?}", builder);
            match builder.try_build() {
                Err(Error::IllegalArguments(message)) => {
                    assert_eq!(expected, message, "{}", description)
                }
                other => panic!("{} must not build, got {:?}", description, other),
            }
        }
    }

    /// An explicit empty summary list means "no table", for every output format, and is not the
    /// same thing as an unset one.
    ///
    /// `show_summary(vec![])` is how a Rust or wasm caller asks for no summary table without naming
    /// `None`. It folds to no flags and prints nothing; a resolution that read an empty list as
    /// "unset" would turn it into the format's default and print the fail table on the single-line
    /// format. The summary table is the only output that carries the `FAILED rules` heading.
    #[test]
    fn validate_explicit_empty_summary_prints_no_table() {
        use clap::ValueEnum;

        for format in OutputFormatType::value_variants() {
            let needs_structured =
                matches!(format, OutputFormatType::Junit | OutputFormatType::Sarif);
            let cmd = ValidateBuilder::default()
                .rules(vec![String::from(FAILING_RULES)])
                .data(vec![String::from(FAILING_DATA)])
                .show_summary(vec![])
                .structured(needs_structured)
                .output_format(*format)
                .try_build()
                .unwrap_or_else(|e| {
                    panic!("{:?} with an empty summary list must build: {}", format, e)
                });

            let (outcome, document) = execute(cmd);
            assert!(
                matches!(outcome, Ok(FAILURE_STATUS_CODE)),
                "{:?}: must run to its FAIL verdict, got {:?}",
                format,
                outcome
            );
            assert!(
                !document.contains("FAILED rules"),
                "{:?}: an explicit empty summary list must print no summary table:\n{}",
                format,
                document
            );
        }
    }

    /// The command line and the builder build one and the same `Validate` for the same command.
    ///
    /// Derived `PartialEq` over the whole struct, for every output format, so the two entry points
    /// cannot leave a field in different states for an equivalent command (an absent `-S` and an
    /// unset `show_summary` in particular), and code that reads a field directly instead of through
    /// its resolving accessor sees the same value from both.
    #[test]
    fn validate_cli_and_builder_build_the_same_command() {
        use clap::ValueEnum;

        for format in OutputFormatType::value_variants() {
            let name = format
                .to_possible_value()
                .expect("every output format is a command-line value")
                .get_name()
                .to_owned();
            let needs_structured =
                matches!(format, OutputFormatType::Junit | OutputFormatType::Sarif);

            let mut argv = vec![
                "cfn-guard",
                "validate",
                "-r",
                RULES_DIR,
                "-d",
                DATA_DIR,
                "-o",
                &name,
            ];
            if needs_structured {
                argv.push("-z");
            }
            let from_cli = match CfnGuard::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("-o {} must parse: {}", name, e))
                .command
            {
                crate::commands::Commands::Validate(validate) => validate,
                _ => panic!("-o {} parsed as something other than validate", name),
            };

            let from_builder = ValidateBuilder::default()
                .rules(vec![String::from(RULES_DIR)])
                .data(vec![String::from(DATA_DIR)])
                .structured(needs_structured)
                .output_format(*format)
                .try_build()
                .unwrap_or_else(|e| panic!("{:?} must build: {}", format, e));

            assert_eq!(from_cli, from_builder, "-o {}", name);
        }
    }

    /// The summary default per output format, as `default_show_summary` answers it and as a built
    /// command resolves it: `[Fail]` for the single-line summary, `[None]` for each machine-readable
    /// format. The rows are spelled out rather than derived from `is_structured`, so a change to
    /// either side shows up here. A value the caller sets is kept as given.
    ///
    /// The enum's `Default` is pinned beside the table: `ShowSummaryType` keeps `#[default] Fail`
    /// (the enum is wasm API, and `Fail` is the single-line summary's default, which is why the
    /// enum default looked right), while the defect this table guards against was a builder default
    /// of `vec![Default::default()]` whatever the format, which built and then failed at `execute`
    /// beside a JSON report. So every machine-readable row also asserts that the default in force
    /// is not what `ShowSummaryType::default()` gives.
    #[test]
    fn validate_summary_default_follows_output_format() {
        assert_eq!(ShowSummaryType::Fail, ShowSummaryType::default());
        assert_eq!(
            vec![ShowSummaryType::default()],
            default_show_summary(OutputFormatType::SingleLineSummary)
        );

        let rules = vec![String::from(RULES_DIR)];
        let data = vec![String::from(DATA_DIR)];
        let table = [
            (
                OutputFormatType::SingleLineSummary,
                false,
                vec![ShowSummaryType::Fail],
            ),
            (OutputFormatType::JSON, false, vec![ShowSummaryType::None]),
            (OutputFormatType::YAML, false, vec![ShowSummaryType::None]),
            (OutputFormatType::Junit, true, vec![ShowSummaryType::None]),
            (OutputFormatType::Sarif, true, vec![ShowSummaryType::None]),
        ];
        for (format, needs_structured, expected) in table {
            assert_eq!(expected, default_show_summary(format), "{:?}", format);

            let cmd = ValidateBuilder::default()
                .rules(rules.clone())
                .data(data.clone())
                .structured(needs_structured)
                .output_format(format)
                .try_build()
                .unwrap_or_else(|e| panic!("{:?} with no summary set must build: {}", format, e));
            assert_eq!(None, cmd.show_summary, "{:?}: unset stays unset", format);
            let in_force = cmd.show_summary_in_force();
            assert_eq!(expected, in_force, "{:?}", format);
            if format.is_structured() {
                assert_ne!(
                    vec![ShowSummaryType::default()],
                    in_force,
                    "{:?}: the enum default is not the default in effect",
                    format
                );
            }
        }

        let explicit = ValidateBuilder::default()
            .rules(rules.clone())
            .data(data.clone())
            .show_summary(vec![ShowSummaryType::Pass, ShowSummaryType::Skip])
            .try_build()
            .expect("an explicit summary with the single-line format builds");
        assert_eq!(
            Some(vec![ShowSummaryType::Pass, ShowSummaryType::Skip]),
            explicit.show_summary
        );
    }
}
