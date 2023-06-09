pub(crate) mod files;
pub(crate) mod helper;
pub mod migrate;
pub mod parse_tree;
pub mod rulegen;
pub mod test;
pub mod validate;

mod aws_meta_appender;
mod common_test_helpers;
mod tracker;

//
// Constants
//
// Application metadata
pub const APP_NAME: &str = "cfn-guard";
pub const APP_VERSION: &'static str = env!("CARGO_PKG_VERSION");
// Commands
pub const MIGRATE: &str = "migrate";
pub const PARSE_TREE: &str = "parse-tree";
pub const RULEGEN: &str = "rulegen";
pub const TEST: &str = "test";
pub const VALIDATE: &str = "validate";
// Arguments for validate
pub const ALPHABETICAL: (&str, char) = ("alphabetical", 'a');
pub const DATA: (&str, char) = ("data", 'd');
pub const LAST_MODIFIED: (&str, char) = ("last-modified", 'm');
pub const OUTPUT_FORMAT: (&str, char) = ("output-format", 'o');
pub const INPUT_PARAMETERS: (&str, char) = ("input-parameters", 'i');
pub const PAYLOAD: (&str, char) = ("payload", 'P');
pub const PREVIOUS_ENGINE: (&str, char) = ("previous-engine", 'E');
pub const PRINT_JSON: (&str, char) = ("print-json", 'p');
pub const PRINT_JSON_DEPRECATED: char = 'j';
pub const SHOW_CLAUSE_FAILURES: (&str, char) = ("show-clause-failures", 's');
pub const SHOW_SUMMARY: (&str, char) = ("show-summary", 'S');
pub const TYPE: (&str, char) = ("type", 't');
pub const VERBOSE: (&str, char) = ("verbose", 'v');
// Arguments for validate, migrate, parse tree
pub const RULES: (&str, char) = ("rules", 'r');
// Arguments for migrate, parse-tree, rulegen
pub const OUTPUT: (&str, char) = ("output", 'o');
// Arguments for parse-tree
pub const PRINT_YAML: (&str, char) = ("print-yaml", 'y');
// Arguments for test
pub const RULES_FILE: (&str, char) = ("rules-file", 'r');
pub const TEST_DATA: (&str, char) = ("test-data", 't');
pub const DIRECTORY: (&str, char) = ("dir", 'd');
// Arguments for rulegen
pub const TEMPLATE: (&str, char) = ("template", 't');
// Arg group for validate
pub(crate) const REQUIRED_FLAGS: &str = "required_flags";
// Arg group for test
pub const RULES_AND_TEST_FILE: &str = "rules-and-test-file";
pub const DIRECTORY_ONLY: &str = "directory-only";

pub(crate) const DATA_FILE_SUPPORTED_EXTENSIONS: [&'static str; 5] =
    [".yaml", ".yml", ".json", ".jsn", ".template"];
pub(crate) const RULE_FILE_SUPPORTED_EXTENSIONS: [&'static str; 2] = [".guard", ".ruleset"];
