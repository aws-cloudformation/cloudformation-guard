pub(crate) mod files;
pub mod validate;
pub(crate) mod rulegen;
pub(crate) mod test;
pub(crate) mod helper;
pub(crate) mod parse_tree;
pub(crate) mod migrate;
pub(crate) mod github_pull;
pub(crate) mod authenticated_source;
pub(crate) mod util;

mod tracker;
mod aws_meta_appender;
mod common_test_helpers;

//
// Constants
//
// Application metadata
pub const APP_NAME: &str = "cfn-guard";
pub const APP_VERSION: &'static str = env!("CARGO_PKG_VERSION");
// Commands
pub(crate)  const MIGRATE: &str = "migrate";
pub(crate)  const PARSE_TREE: &str = "parse-tree";
pub(crate) const RULEGEN: &str = "rulegen";
pub(crate)  const TEST: &str = "test";
pub const VALIDATE: &str = "validate";
// Arguments for validate
pub(crate) const ALPHABETICAL: (&str, &str) = ("alphabetical", "a");
pub const DATA: (&str, &str) = ("data", "d");
pub(crate) const LAST_MODIFIED: (&str, &str) = ("last-modified", "m");
pub(crate) const OUTPUT_FORMAT: (&str, &str) = ("output-format", "o");
pub const INPUT_PARAMETERS: (&str, &str) = ("input-parameters", "i");
pub(crate) const PAYLOAD: (&str, &str) = ("payload", "P");
pub(crate) const PREVIOUS_ENGINE: (&str, &str) = ("previous-engine","E");
pub(crate) const PRINT_JSON: (&str, &str) = ("print-json", "p");
pub(crate) const SHOW_CLAUSE_FAILURES: (&str, &str) = ("show-clause-failures", "s");
pub(crate) const SHOW_SUMMARY: (&str, &str) = ("show-summary", "S");
pub(crate) const TYPE: (&str, &str) = ("type", "t");
pub(crate) const VERBOSE: (&str, &str) = ("verbose", "v");
// Arguments for validate, migrate, parse tree
pub const RULES: (&str, &str) = ("rules", "r");
// Arguments for migrate, parse-tree, rulegen
pub(crate) const OUTPUT: (&str, &str) = ("output", "o");
// Arguments for parse-tree
pub(crate) const PRINT_YAML: (&str, &str) = ("print-yaml", "y");
// Arguments for test
pub(crate) const RULES_FILE: (&str, &str) = ("rules-file", "r");
pub(crate) const TEST_DATA: (&str, &str) = ("test-data", "t");
pub(crate) const DIRECTORY: (&str, &str) = ("dir", "d");
// Arguments for rulegen
pub(crate) const TEMPLATE: (&str, &str) = ("template", "t");
// Arg group for validate
pub(crate)  const REQUIRED_FLAGS: &str = "required_flags";
// Arg group for test
pub(crate)  const RULES_AND_TEST_FILE: &str = "rules-and-test-file";
pub(crate)  const DIRECTORY_ONLY: &str =  "directory-only";


pub(crate) const  DATA_FILE_SUPPORTED_EXTENSIONS: [&'static str; 5] = [".yaml",
                                                                      ".yml",
                                                                      ".json",
                                                                      ".jsn",
                                                                      ".template"];
pub(crate) const  RULE_FILE_SUPPORTED_EXTENSIONS: [&'static str; 2] = [".guard",
                                                                     ".ruleset"];

pub(crate) const SEMANTIC_VERSION_NAMING: &'static str = r"^(\d+\.)?(\d+\.)?(\*|\d+)$";
pub(crate) const GITHUB_URL: &'static str = r"(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/)?(raw.githubusercontent.com)?(\/.*)?$";
