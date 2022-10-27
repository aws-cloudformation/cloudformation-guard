pub(crate) mod files;
pub mod validate;
pub(crate) mod rulegen;
pub(crate) mod test;
pub(crate) mod helper;
pub(crate) mod parse_tree;
pub(crate) mod migrate;

mod tracker;
mod aws_meta_appender;
mod common_test_helpers;

//
// Constants
//
// Application metadata
pub const APP_NAME: &str = "cfn-guard";
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");
// Commands
pub(crate)  const MIGRATE: &str = "migrate";
pub(crate)  const PARSE_TREE: &str = "parse-tree";
pub(crate) const RULEGEN: &str = "rulegen";
pub(crate)  const TEST: &str = "test";
pub const VALIDATE: &str = "validate";
// Arguments for validate
pub(crate) const ALPHABETICAL: (&str,char) = ("alphabetical", 'a');
pub const DATA: (&str,char) = ("data", 'd');
pub(crate) const LAST_MODIFIED: (&str,char) = ("last-modified", 'm');
pub(crate) const OUTPUT_FORMAT: (&str,char) = ("output-format", 'o');
pub const INPUT_PARAMETERS: (&str,char) = ("input-parameters", 'i');
pub(crate) const PAYLOAD: (&str,char) = ("payload", 'P');
pub(crate) const PREVIOUS_ENGINE: (&str,char) = ("previous-engine",'E');
pub(crate) const PRINT_JSON: (&str,char) = ("print-json", 'p');
pub(crate) const SHOW_CLAUSE_FAILURES: (&str,char) = ("show-clause-failures", 's');
pub(crate) const SHOW_SUMMARY: (&str,char) = ("show-summary", 'S');
pub(crate) const TYPE: (&str,char) = ("type", 't');
pub(crate) const VERBOSE: (&str,char) = ("verbose", 'v');
// Arguments for validate, migrate, parse tree
pub const RULES: (&str, char) = ("rules", 'r');
// Arguments for migrate, parse-tree, rulegen
pub(crate) const OUTPUT: (&str,char) = ("output", 'o');
// Arguments for parse-tree
pub(crate) const PRINT_YAML: (&str,char) = ("print-yaml", 'y');
// Arguments for test
pub(crate) const RULES_FILE: (&str,char) = ("rules-file", 'r');
pub(crate) const TEST_DATA: (&str,char) = ("test-data", 't');
pub(crate) const DIRECTORY: (&str,char) = ("dir", 'd');
// Arguments for rulegen
pub(crate) const TEMPLATE: (&str,char) = ("template", 'a');
// Arg group for validate
pub(crate)  const REQUIRED_FLAGS: &str = "required_flags";
// Arg group for test
pub(crate)  const RULES_AND_TEST_FILE: &str = "rules-and-test-file";
pub(crate)  const DIRECTORY_ONLY: &str =  "directory-only";


pub(crate) const  DATA_FILE_SUPPORTED_EXTENSIONS: [&str; 5] = [".yaml",
                                                                      ".yml",
                                                                      ".json",
                                                                      ".jsn",
                                                                      ".template"];
pub(crate) const  RULE_FILE_SUPPORTED_EXTENSIONS: [&str; 2] = [".guard",
                                                                     ".ruleset"];
