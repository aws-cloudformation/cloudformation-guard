pub(crate) mod files;
pub(crate) mod validate;
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
// Commands
pub(crate)  const MIGRATE: &str = "migrate";
pub(crate)  const PARSE_TREE: &str = "parse-tree";
pub(crate)  const TEST: &str = "test";
pub(crate)  const VALIDATE: &str = "validate";
// Arguments for validate
pub(crate) const ALPHABETICAL: (&str, &str) = ("alphabetical", "a");
pub(crate) const DATA: (&str, &str) = ("data", "d");
pub(crate) const LAST_MODIFIED: (&str, &str) = ("last-modified", "m");
pub(crate) const OUTPUT_FORMAT: (&str, &str) = ("output-format", "o");
pub(crate) const INPUT_PARAMETERS: (&str, &str) = ("input-parameters", "i");
pub(crate) const PAYLOAD: (&str, &str) = ("payload", "P");
pub(crate) const PREVIOUS_ENGINE: (&str, &str) = ("previous-engine","E");
pub(crate) const PRINT_JSON: (&str, &str) = ("print-json", "p");
pub(crate) const SHOW_CLAUSE_FAILURES: (&str, &str) = ("show-clause-failures", "s");
pub(crate) const SHOW_SUMMARY: (&str, &str) = ("show-summary", "S");
pub(crate) const TYPE: (&str, &str) = ("type", "t");
pub(crate) const VERBOSE: (&str, &str) = ("verbose", "v");
// Arguments for validate, migrate, parse tree
pub(crate) const RULES: (&str, &str) = ("rules", "r");
// Arguments for migrate, parse-tree
pub(crate) const OUTPUT: (&str, &str) = ("output", "o");
// Arguments for parse-tree
pub(crate) const PRINT_YAML: (&str, &str) = ("print-yaml", "y");
// Arguments for test
pub(crate) const RULES_FILE: (&str, &str) = ("rules-file", "r");
pub(crate) const TEST_DATA: (&str, &str) = ("test-data", "t");
pub(crate) const DIRECTORY: (&str, &str) = ("dir", "d");
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
