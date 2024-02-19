// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* require return types marked as must_use to be used (such as Result types) */
#![deny(unused_must_use)]

pub mod commands;
mod rules;
pub mod utils;

pub use crate::commands::helper::{validate_and_return_json as run_checks, ValidateInput};
use crate::commands::parse_tree::ParseTree;
use crate::commands::rulegen::Rulegen;
use crate::commands::test::Test;
use crate::commands::validate::{OutputFormatType, ShowSummaryType, Validate};
use crate::commands::Executable;
pub use crate::rules::errors::Error;

pub trait CommandBuilder<T: Executable> {
    fn try_build(self) -> crate::rules::Result<T>;
}

#[derive(Default, Debug)]
pub struct ParseTreeBuilder {
    rules: Option<String>,
    output: Option<String>,
    print_json: bool,
    print_yaml: bool,
}

impl CommandBuilder<ParseTree> for ParseTreeBuilder {
    fn try_build(self) -> crate::rules::Result<ParseTree> {
        if self.print_json && self.print_yaml {
            return Err(Error::IllegalArguments(String::from("cannot construct a ParseTree command when both print_json and print_yaml are set to true")));
        }

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
    pub fn rules(mut self, rules: Option<String>) -> Self {
        self.rules = rules;

        self
    }

    pub fn output(mut self, output: Option<String>) -> Self {
        self.output = output;

        self
    }

    pub fn print_json(mut self, arg: bool) -> Self {
        self.print_json = arg;

        self
    }

    pub fn print_yaml(mut self, arg: bool) -> Self {
        self.print_yaml = arg;

        self
    }
}

#[derive(Debug)]
/// .
/// A builder to help construct the `Validate` command for
pub struct ValidateBuilder {
    rules: Vec<String>,
    data: Vec<String>,
    input_params: Vec<String>,
    template_type: Option<String>,
    output_format: OutputFormatType,
    show_summary: Vec<ShowSummaryType>,
    alphabetical: bool,
    last_modified: bool,
    verbose: bool,
    print_json: bool,
    payload: bool,
    structured: bool,
}

impl Default for ValidateBuilder {
    fn default() -> Self {
        Self {
            rules: Default::default(),
            data: Default::default(),
            input_params: Default::default(),
            template_type: Default::default(),
            output_format: Default::default(),
            show_summary: vec![Default::default()],
            alphabetical: Default::default(),
            last_modified: false,
            verbose: false,
            print_json: false,
            payload: false,
            structured: false,
        }
    }
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
        if self.structured {
            if self.output_format == OutputFormatType::SingleLineSummary {
                return Err(Error::IllegalArguments(String::from(
                        "single-line-summary is not able to be used when the `structured` flag is present",
                    )));
            }

            if self.print_json {
                return Err(Error::IllegalArguments(String::from("unable to construct validate command when both structured and print_json are set to true")));
            }

            if self.verbose {
                return Err(Error::IllegalArguments(String::from("unable to construct validate command when both structured and verbose are set to true")));
            }

            if self.show_summary.iter().any(|st| {
                matches!(
                    st,
                    ShowSummaryType::Pass
                        | ShowSummaryType::Fail
                        | ShowSummaryType::Skip
                        | ShowSummaryType::All
                )
            }) {
                return Err(Error::IllegalArguments(String::from(
                    "Cannot provide a summary-type other than `none` when the `structured` flag is present",
                )));
            }
        } else if matches!(self.output_format, OutputFormatType::Junit) {
            return Err(Error::IllegalArguments(String::from(
                "the structured flag must be set when output is set to junit",
            )));
        }

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

        Ok(Validate {
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
        })
    }
}

impl ValidateBuilder {
    /// a list of paths that point to rule files, or a directory containing rule files on a local machine. Only files that end with .guard or .ruleset will be evaluated
    /// conflicts with payload
    pub fn rules(mut self, rules: Vec<String>) -> Self {
        self.rules = rules;

        self
    }

    /// a list of paths that point to data files, or a directory containing data files  for the rules to be evaluated against. Only JSON, or YAML files will be used
    /// conflicts with payload
    pub fn data(mut self, data: Vec<String>) -> Self {
        self.data = data;

        self
    }

    /// Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)
    /// default is failed
    /// must be set to none if used together with the structured flag
    pub fn show_summary(mut self, args: Vec<ShowSummaryType>) -> Self {
        self.show_summary = args;

        self
    }

    /// a list of paths that point to data files, or a directory containing data files to be merged with the data argument and then the  rules will be evaluated against them. Only JSON, or YAML files will be used
    pub fn input_params(mut self, input_params: Vec<String>) -> Self {
        self.input_params = input_params;

        self
    }

    /// Specify the format in which the output should be displayed
    /// default is single-line-summary
    /// if junit is used, `structured` attributed must be set to true
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

    /// Output verbose logging, conflicts with `structured` field
    /// default is false
    pub fn verbose(mut self, arg: bool) -> Self {
        self.verbose = arg;

        self
    }

    /// Print the parse tree in a json format. This can be used to get more details on how the clauses were evaluated
    /// conflicts with the `structured` attribute
    /// default is false
    pub fn print_json(mut self, arg: bool) -> Self {
        self.print_json = arg;

        self
    }

    /// Prints the output which must be specified to JSON/YAML/JUnit in a structured format
    /// Conflicts with the following attributes `verbose`, `print-json`, `output-format` when set
    /// to "single-line-summary", show-summary when set to anything other than "none"
    /// default is false
    pub fn structured(mut self, arg: bool) -> Self {
        self.structured = arg;

        self
    }
}

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
    /// will conflict with verbose if set to something other thatn single-line-summary and verbose
    /// is set to true
    pub fn output_format(mut self, output: OutputFormatType) -> Self {
        self.output_format = output;

        self
    }
}

#[derive(Debug, Default)]
pub struct RulegenBuilder {
    output: Option<String>,
    template: String,
}

impl CommandBuilder<Rulegen> for RulegenBuilder {
    fn try_build(self) -> crate::rules::Result<Rulegen> {
        let RulegenBuilder { output, template } = self;
        Ok(Rulegen { output, template })
    }
}

impl RulegenBuilder {
    pub fn output(mut self, output: Option<String>) -> Self {
        self.output = output;

        self
    }

    pub fn template(mut self, template: String) -> Self {
        self.template = template;

        self
    }
}

#[cfg(test)]
mod cfn_guard_lib_tests {
    use crate::{
        commands::validate::ShowSummaryType, CommandBuilder, TestBuilder, ValidateBuilder,
    };

    #[test]
    fn validate_with_errors() {
        // fails cause structured, but show_summary fail
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .rules(vec![String::from("resources/validate/rules-dir")])
            .structured(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
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

        // fails cause junit, but not structured
        let cmd = ValidateBuilder::default()
            .data(vec![String::from("resources/validate/data-dir")])
            .rules(vec![String::from("resources/validate/rules-dir")])
            .output_format(crate::commands::validate::OutputFormatType::Junit)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_err());

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

    #[test]
    fn validate_happy_path() {
        let data = vec![String::from("resources/validate/data-dir")];
        let rules = vec![String::from("resources/validate/rules-dir")];
        let cmd = ValidateBuilder::default()
            .verbose(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .data(data.clone())
            .rules(rules.clone())
            .try_build();

        assert!(cmd.is_ok());

        let cmd = ValidateBuilder::default()
            .verbose(true)
            .show_summary(vec![
                ShowSummaryType::Pass,
                ShowSummaryType::Fail,
                ShowSummaryType::Skip,
            ])
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .data(data.clone())
            .rules(rules.clone())
            .try_build();

        assert!(cmd.is_ok());

        let cmd = ValidateBuilder::default()
            .verbose(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .data(data.clone())
            .rules(rules.clone())
            .try_build();

        assert!(cmd.is_ok());

        let cmd = ValidateBuilder::default()
            .data(data.clone())
            .rules(rules.clone())
            .structured(true)
            .output_format(crate::commands::validate::OutputFormatType::JSON)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_ok());

        let cmd = ValidateBuilder::default()
            .data(data.clone())
            .rules(rules.clone())
            .output_format(crate::commands::validate::OutputFormatType::Junit)
            .structured(true)
            .show_summary(vec![ShowSummaryType::None])
            .try_build();

        assert!(cmd.is_ok());
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
}
