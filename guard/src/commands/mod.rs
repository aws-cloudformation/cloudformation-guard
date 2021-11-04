pub(crate) mod files;
pub(crate) mod helper;
pub(crate) mod migrate;
pub(crate) mod parse_tree;
pub(crate) mod rulegen;
pub(crate) mod test;
pub(crate) mod validate;

mod aws_meta_appender;
mod common_test_helpers;
mod tracker;

//
// Constants for arguments
//
pub(crate) const ALPHABETICAL: (&str, &str) = ("alphabetical", "a");
pub(crate) const LAST_MODIFIED: (&str, &str) = ("last-modified", "l");
pub(crate) const RULES: (&str, &str) = ("rules", "r");
pub(crate) const DATA: (&str, &str) = ("data", "d");
