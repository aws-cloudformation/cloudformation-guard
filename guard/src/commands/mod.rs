use clap::{Parser, Subcommand};

use crate::{
    commands::{
        completions::Completions, parse_tree::ParseTree, rulegen::Rulegen, test::Test,
        validate::Validate,
    },
    utils::{reader::Reader, writer::Writer},
};

pub(crate) mod files;
pub(crate) mod helper;
pub mod parse_tree;
pub mod rulegen;
pub mod test;
pub mod validate;

mod aws_meta_appender;
mod common_test_helpers;
pub mod completions;
pub mod reporters;
mod tracker;

//
// Constants
//
// Application metadata
pub const APP_NAME: &str = "cfn-guard";

// Arguments for validate
pub const ALPHABETICAL: (&str, char) = ("alphabetical", 'a');
#[allow(dead_code)]
pub const DATA: (&str, char) = ("data", 'd');
pub const LAST_MODIFIED: (&str, char) = ("last-modified", 'm');
#[allow(dead_code)]
pub const OUTPUT_FORMAT: (&str, char) = ("output-format", 'o');
#[allow(dead_code)]
pub const INPUT_PARAMETERS: (&str, char) = ("input-parameters", 'i');
pub const PAYLOAD: (&str, char) = ("payload", 'P');
pub const PRINT_JSON: (&str, char) = ("print-json", 'p');
pub const SHOW_SUMMARY: (&str, char) = ("show-summary", 'S');
pub const TYPE: (&str, char) = ("type", 't');
pub const VERBOSE: (&str, char) = ("verbose", 'v');
// Arguments for validate, parse tree
pub const RULES: (&str, char) = ("rules", 'r');
// Arguments for parse-tree, rulegen
#[allow(dead_code)]
pub const OUTPUT: (&str, char) = ("output", 'o');
// Arguments for parse-tree
pub const PRINT_YAML: (&str, char) = ("print-yaml", 'y');
// Arguments for test
pub const RULES_FILE: (&str, char) = ("rules-file", 'r');
pub const TEST_DATA: (&str, char) = ("test-data", 't');
pub const DIRECTORY: (&str, char) = ("dir", 'd');
// Arguments for rulegen
#[allow(dead_code)]
pub const TEMPLATE: (&str, char) = ("template", 't');
// Arg group for validate
pub(crate) const REQUIRED_FLAGS: &str = "required_flags";
// Arg group for test
pub const RULES_AND_TEST_FILE: &str = "rules-and-test-file";
pub const DIRECTORY_ONLY: &str = "directory-only";
pub const STRUCTURED: (&str, char) = ("structured", 'z');

pub(crate) const DATA_FILE_SUPPORTED_EXTENSIONS: [&str; 5] =
    [".yaml", ".yml", ".json", ".jsn", ".template"];
pub(crate) const RULE_FILE_SUPPORTED_EXTENSIONS: [&str; 2] = [".guard", ".ruleset"];

pub const FAILURE_STATUS_CODE: i32 = 19;
pub const SUCCESS_STATUS_CODE: i32 = 0;
pub const ERROR_STATUS_CODE: i32 = 5;
pub const TEST_ERROR_STATUS_CODE: i32 = 1;
pub const TEST_FAILURE_STATUS_CODE: i32 = 7;

const ABOUT: &str = r#"
Guard is a general-purpose tool that provides a simple declarative syntax to define
policy-as-code as rules to validate against any structured hierarchical data (like JSON/YAML).
Rules are composed of clauses expressed using Conjunctive Normal Form
(fancy way of saying it is a logical AND of OR clauses). Guard has deep
integration with CloudFormation templates for evaluation but is a general tool
that equally works for any JSON- and YAML- data."#;

#[derive(Debug, Parser)]
#[command(name=APP_NAME)]
#[command(about=ABOUT)]
#[command(version)]
pub struct CfnGuard {
    #[command(subcommand)]
    pub(crate) command: Commands,
}

impl CfnGuard {
    pub fn execute(&self, writer: &mut Writer, reader: &mut Reader) -> crate::rules::Result<i32> {
        self.command.execute(writer, reader)
    }
}

#[derive(Debug, Subcommand)]
pub(crate) enum Commands {
    Validate(Validate),
    Test(Test),
    ParseTree(ParseTree),
    Rulegen(Rulegen),
    Completions(Completions),
}

pub trait Executable {
    fn execute(&self, writer: &mut Writer, reader: &mut Reader) -> crate::rules::Result<i32>;
}

impl Executable for Commands {
    fn execute(&self, writer: &mut Writer, reader: &mut Reader) -> crate::rules::Result<i32> {
        match self {
            Commands::Validate(cmd) => cmd.execute(writer, reader),
            Commands::Test(cmd) => cmd.execute(writer, reader),
            Commands::ParseTree(cmd) => cmd.execute(writer, reader),
            Commands::Rulegen(cmd) => cmd.execute(writer, reader),
            Commands::Completions(cmd) => cmd.execute(),
        }
    }
}
