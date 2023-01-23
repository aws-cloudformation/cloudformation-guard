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
pub const ALPHABETICAL: (&str, &str) = ("alphabetical", "a");
pub const DATA: (&str, &str) = ("data", "d");
pub const LAST_MODIFIED: (&str, &str) = ("last-modified", "m");
pub const OUTPUT_FORMAT: (&str, &str) = ("output-format", "o");
pub const INPUT_PARAMETERS: (&str, &str) = ("input-parameters", "i");
pub const PAYLOAD: (&str, &str) = ("payload", "P");
pub const PREVIOUS_ENGINE: (&str, &str) = ("previous-engine", "E");
pub const PRINT_JSON: (&str, &str) = ("print-json", "p");
pub const SHOW_CLAUSE_FAILURES: (&str, &str) = ("show-clause-failures", "s");
pub const SHOW_SUMMARY: (&str, &str) = ("show-summary", "S");
pub const TYPE: (&str, &str) = ("type", "t");
pub const VERBOSE: (&str, &str) = ("verbose", "v");
// Arguments for validate, migrate, parse tree
pub const RULES: (&str, &str) = ("rules", "r");
// Arguments for migrate, parse-tree, rulegen
pub const OUTPUT: (&str, &str) = ("output", "o");
// Arguments for parse-tree
pub const PRINT_YAML: (&str, &str) = ("print-yaml", "y");
// Arguments for test
pub const RULES_FILE: (&str, &str) = ("rules-file", "r");
pub const TEST_DATA: (&str, &str) = ("test-data", "t");
pub const DIRECTORY: (&str, &str) = ("dir", "d");
// Arguments for rulegen
pub(crate) const TEMPLATE: (&str, &str) = ("template", "t");
// Arg group for validate
pub(crate) const REQUIRED_FLAGS: &str = "required_flags";
// Arg group for test
pub const RULES_AND_TEST_FILE: &str = "rules-and-test-file";
pub const DIRECTORY_ONLY: &str = "directory-only";

pub(crate) const DATA_FILE_SUPPORTED_EXTENSIONS: [&'static str; 5] =
    [".yaml", ".yml", ".json", ".jsn", ".template"];
pub(crate) const RULE_FILE_SUPPORTED_EXTENSIONS: [&'static str; 2] = [".guard", ".ruleset"];
