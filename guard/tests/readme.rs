// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
//! The `--help` text, and `guard/README.md`'s copies of it.
//!
//! Each usage block in the README is a paste of `cfn-guard <subcommand> --help`, and nothing but a
//! test keeps a paste in step with its source: a flag can be removed or renamed, or a description
//! reworded, without the block following. These tests compare every block with the help clap renders
//! for the binary under test, so any hunk between the two fails here.
//!
//! To regenerate the blocks after a change to the help text or a clap upgrade, run
//! `UPDATE_README=1 cargo test --test readme`: each block case then rewrites its fenced block in
//! place before comparing, and the diff of `guard/README.md` is the review.
//!
//! The help is rendered at `utils::README_HELP_WIDTH`, the one width the binary renders at; its
//! doc says why no other value matches the binary. The helpers live in `tests/utils.rs` under a
//! `readme_` prefix.

#[allow(dead_code)]
pub(crate) mod utils;

use std::fs;
use std::sync::Mutex;

use cfn_guard::commands::{
    CfnGuard, ERROR_STATUS_CODE, INPUT_PARAMETERS, PAYLOAD, SUCCESS_STATUS_CODE,
};
use cfn_guard::utils::reader::{ReadBuffer, Reader};
use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
use clap::{CommandFactory, Parser};
use pretty_assertions::assert_eq;

use crate::utils::{
    get_full_path_for_resource_file, readme_path, readme_read, readme_rendered_help,
    readme_trimmed, readme_usage_block,
};

/// `UPDATE_README=1` rewrites a drifted block instead of only reporting it.
const UPDATE_README: &str = "UPDATE_README";

/// Serializes every read and the read-modify-write of `README.md` across the tests, which run in
/// parallel. A test that fails its assertion while holding the lock poisons it; the others still
/// have their own comparison to report, so takers recover the poison rather than propagate it.
static README_LOCK: Mutex<()> = Mutex::new(());

/// The README's four usage blocks are the live `--help` of their subcommands.
///
/// One case per block, so that a block added or removed later is one line here. A failure names
/// the block and the command to regenerate it.
#[rstest::rstest]
#[case("Validate", "validate")]
#[case("Rulegen", "rulegen")]
#[case("Parse Tree", "parse-tree")]
#[case("Test", "test")]
fn usage_block_matches_help(#[case] heading: &str, #[case] subcommand: &str) {
    let _serialized = README_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let expected = readme_trimmed(&readme_rendered_help(subcommand));
    let mut readme = readme_read();
    let mut block = readme_usage_block(&readme, heading);

    if std::env::var_os(UPDATE_README).is_some()
        && readme_trimmed(&readme[block.clone()]) != expected
    {
        let mut updated = String::with_capacity(readme.len() + expected.len());
        updated.push_str(&readme[..block.start]);
        updated.push_str(&expected);
        updated.push('\n');
        updated.push_str(&readme[block.end..]);
        fs::write(readme_path(), updated)
            .expect("guard/README.md must be writable to regenerate it");

        readme = readme_read();
        block = readme_usage_block(&readme, heading);
    }

    assert_eq!(
        expected,
        readme_trimmed(&readme[block]),
        "guard/README.md's `{}` usage block differs from `cfn-guard {} --help`; \
         run `UPDATE_README=1 cargo test --test readme` to regenerate it",
        heading,
        subcommand
    );
}

/// Both spellings of the input-parameters flag are accepted: the one the public `INPUT_PARAMETERS`
/// constant defines the flag with, and the one the documentation carried for years.
///
/// The constants in `commands` are how a caller spells a flag without hard-coding it, so `.0` is
/// what the argument is declared with, and the old `--input-parameters` stays an alias so that
/// every script written from the old README keeps working. A constant that spelled a name clap did
/// not accept gave such a command line exit 2, and so did the documented spelling once the help was
/// corrected. The trio is the known-good combination from the validate tests.
#[rstest::rstest]
#[case::constant(INPUT_PARAMETERS.0)]
#[case::documented_alias("input-parameters")]
fn input_params_flag_spellings_are_accepted(#[case] long_flag: &str) {
    let cmd = CfnGuard::try_parse_from([
        String::from("cfn-guard"),
        String::from("validate"),
        String::from("-r"),
        get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard"),
        String::from("-d"),
        get_full_path_for_resource_file("resources/validate/db_resource.yaml"),
        format!("--{}", long_flag),
        get_full_path_for_resource_file("resources/validate/input-parameters-dir/"),
    ])
    .unwrap_or_else(|e| panic!("--{} must be accepted: {}", long_flag, e));
    let mut writer =
        Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
    let mut reader = Reader::default();

    let code = cmd
        .execute(&mut writer, &mut reader)
        .expect("a known-good rules/data/input-parameters trio runs to a verdict");
    assert_eq!(SUCCESS_STATUS_CODE, code, "--{}", long_flag);
}

/// Flags of other programs that the repository README quotes in its install, container and
/// pre-commit instructions, and that are not cfn-guard's to accept: curl (`--proto`, `--tlsv1.2`),
/// cargo (`--bin`), docker (`--mount`) and the pre-commit hook's own arguments (`--tag-prefix`,
/// `--operation`). A flag added here has to belong to a program the sentence names.
const OTHER_PROGRAMS_FLAGS: &[&str] =
    &["proto", "tlsv1", "bin", "mount", "tag-prefix", "operation"];

/// Every `--flag` either README mentions, in prose or in a block, is a long flag of the subcommand
/// the line names before it (`cfn-guard <subcommand>`), or, on a line that names none, of some
/// cfn-guard subcommand; the other programs' flags listed above and the top-level flags (`--help`,
/// `--version`) are accepted anywhere.
///
/// The usage-block tests hold the four fenced blocks to the live help, and the help tests hold the
/// help strings to clap, but a stale flag can also sit in a sentence: the repository README told
/// readers to use a spelling the binary rejected, in prose no block test reads. The accepted sets
/// are read from the built clap definition, so a flag renamed in code fails here until every
/// sentence follows. Only long names and visible aliases count: a hidden alias is a spelling
/// `--help` never shows, so a README that uses one sends readers to a flag they cannot find in the
/// help, and `--input-parameters`, the exact spelling this test exists to catch, is such an alias.
/// Checking against the named subcommand is what catches a flag that exists, but on another
/// subcommand (`cfn-guard validate --dir`, say).
///
/// Takes `README_LOCK`, because under `UPDATE_README` a block case may be rewriting the crate
/// README while this reads it. The repository README sits one directory above the crate and is not
/// part of a packaged crate, so that case is skipped, with a line on stderr, only when the crate is
/// clearly outside a checkout: no `.git` and no workspace `Cargo.toml` one directory up (a
/// `cargo package` or vendored copy). Inside a checkout, which is what CI runs, a missing
/// `../README.md` fails, so a moved or renamed repository README cannot pass unread; a missing
/// crate README fails whatever the layout.
#[rstest::rstest]
#[case::crate_readme("README.md")]
#[case::repository_readme("../README.md")]
fn readme_names_only_flags_cfn_guard_accepts(#[case] relative: &str) {
    let _serialized = README_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let crate_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let path = crate_dir.join(relative);
    if !path.exists() {
        let parent = crate_dir.join("..");
        let in_checkout = parent.join(".git").exists() || parent.join("Cargo.toml").exists();
        assert!(
            relative == "../README.md" && !in_checkout,
            "{} must exist: this is a repository checkout, so the README it ships is read",
            path.display()
        );
        eprintln!(
            "skipping {}: {} is not inside a repository checkout, so there is no repository README",
            relative,
            crate_dir.display()
        );
        return;
    }

    let mut command = CfnGuard::command();
    command.build();
    let mut anywhere: Vec<String> = command
        .get_arguments()
        .filter_map(|arg| arg.get_long().map(str::to_owned))
        .collect();
    anywhere.extend(OTHER_PROGRAMS_FLAGS.iter().map(|flag| (*flag).to_owned()));
    let per_subcommand: Vec<(String, Vec<String>)> = command
        .get_subcommands()
        .map(|subcommand| {
            let flags = subcommand
                .get_arguments()
                .flat_map(|arg| {
                    arg.get_long()
                        .into_iter()
                        .chain(arg.get_visible_aliases().unwrap_or_default())
                        .map(str::to_owned)
                })
                .collect();
            (subcommand.get_name().to_owned(), flags)
        })
        .collect();

    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{} must be readable: {}", path.display(), e));
    let mut unknown: Vec<String> = Vec::new();
    for (index, line) in text.lines().enumerate() {
        for (at, flag) in long_flags_mentioned_at(line) {
            if anywhere.iter().any(|a| a == flag) {
                continue;
            }
            match subcommand_named_before(line, at, &per_subcommand) {
                Some((name, flags)) => {
                    if !flags.iter().any(|a| a == flag) {
                        unknown.push(format!(
                            "line {}: --{} is not a flag of `cfn-guard {}`",
                            index + 1,
                            flag,
                            name
                        ));
                    }
                }
                None => {
                    if !per_subcommand
                        .iter()
                        .any(|(_, flags)| flags.iter().any(|a| a == flag))
                    {
                        unknown.push(format!(
                            "line {}: --{} is not a flag of any cfn-guard subcommand",
                            index + 1,
                            flag
                        ));
                    }
                }
            }
        }
    }

    assert!(
        unknown.is_empty(),
        "{} names flags cfn-guard does not accept:\n{}",
        relative,
        unknown.join("\n")
    );
}

/// The subcommand that a `cfn-guard <subcommand>` mention names in `line` before byte offset `at`,
/// with its accepted flags; the nearest such mention when there are several, none when the line
/// names no subcommand before that point.
fn subcommand_named_before<'a>(
    line: &str,
    at: usize,
    subcommands: &'a [(String, Vec<String>)],
) -> Option<&'a (String, Vec<String>)> {
    subcommands
        .iter()
        .filter_map(|entry| {
            let needle = format!("cfn-guard {}", entry.0);
            line[..at]
                .match_indices(&needle)
                .map(|(start, _)| start)
                .filter(|start| {
                    // A whole word: `cfn-guard test` must not match `cfn-guard tests`.
                    line[start + needle.len()..]
                        .chars()
                        .next()
                        .map_or(true, |c| !c.is_ascii_alphanumeric() && c != '-')
                })
                .last()
                .map(|start| (start, entry))
        })
        .max_by_key(|(start, _)| *start)
        .map(|(_, entry)| entry)
}

/// Every `--flag` a subcommand's help mentions is a long flag that subcommand accepts.
///
/// A help string is prose clap does not check: an example can name a flag that was renamed, and a
/// reader who copies it gets a usage error (exit 2). The accepted set is read from the built clap
/// definition, so it includes clap's own `--help`.
#[rstest::rstest]
#[case("validate")]
#[case("rulegen")]
#[case("parse-tree")]
#[case("test")]
fn help_text_names_only_flags_the_subcommand_accepts(#[case] subcommand: &str) {
    let mut command = CfnGuard::command();
    command.build();
    let accepted: Vec<&str> = command
        .find_subcommand(subcommand)
        .unwrap_or_else(|| panic!("cfn-guard has a `{}` subcommand", subcommand))
        .get_arguments()
        .filter_map(|arg| arg.get_long())
        .collect();

    let help = readme_rendered_help(subcommand);
    let unknown: Vec<&str> = long_flags_mentioned(&help)
        .into_iter()
        .filter(|flag| !accepted.contains(flag))
        .collect();

    assert!(
        unknown.is_empty(),
        "`cfn-guard {} --help` names flags the subcommand does not accept: {:?}\n{}",
        subcommand,
        unknown,
        help
    );
}

/// The distinct `--long-flag` tokens in `text`, in order of first appearance: a `--` at the start or
/// after a non-word character, followed by a letter or digit and then any run of letters, digits and
/// hyphens. A `---` rule or a `--` dash on its own is not a flag.
fn long_flags_mentioned(text: &str) -> Vec<&str> {
    let mut flags: Vec<&str> = Vec::new();
    for (_, flag) in long_flags_mentioned_at(text) {
        if !flags.contains(&flag) {
            flags.push(flag);
        }
    }

    flags
}

/// Every `--flag` mention in `text`, with the byte offset of its `--`, in order and with repeats.
fn long_flags_mentioned_at(text: &str) -> Vec<(usize, &str)> {
    let mut flags: Vec<(usize, &str)> = Vec::new();
    for (at, _) in text.match_indices("--") {
        let starts_a_word = text[..at]
            .chars()
            .next_back()
            .map_or(true, |c| !c.is_ascii_alphanumeric() && c != '-');
        let rest = &text[at + 2..];
        if !starts_a_word || !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
            continue;
        }
        let len = rest
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .unwrap_or(rest.len());
        flags.push((at, &rest[..len]));
    }

    flags
}

/// The exit-code section names the three commands that answer these codes, and its row for 5 names
/// each command and the `validate` inputs that the behavior tests below run to a 5.
///
/// Tokens, not sentences: the lead-in before the table has to carry `validate`, `parse-tree` and
/// `rulegen` as backticked names, and the row for 5 has to carry the same three names plus the two
/// flags (`--input-params`, `--payload`, spelled from the constants that declare them), so a copy
/// edit that keeps the meaning passes and a row that drops a command or an input fails.
///
/// Takes `README_LOCK` because under `UPDATE_README` a block case may be rewriting the file.
#[test]
fn exit_code_table_names_the_inputs_each_command_rejects_with_five() {
    let _serialized = README_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let readme = readme_read();
    let exit_codes = readme
        .split("## Exit codes")
        .nth(1)
        .expect("README.md has an `## Exit codes` section")
        .split("\n## ")
        .next()
        .expect("the exit-code section has a body");
    let lead_in = exit_codes
        .split("\n|")
        .next()
        .expect("the exit-code section has text before its table");
    let five = exit_codes
        .lines()
        .find(|line| line.starts_with("| `5` |"))
        .expect("the exit-code table has a row for 5");

    let commands = ["`validate`", "`parse-tree`", "`rulegen`"];
    for command in commands {
        assert!(
            lead_in.contains(command),
            "the table's lead-in must name {} among the commands that use it:\n{}",
            command,
            lead_in
        );
    }
    let inputs = [
        format!("`--{}`", INPUT_PARAMETERS.0),
        format!("`--{}`", PAYLOAD.0),
    ];
    for token in commands
        .iter()
        .map(|command| (*command).to_owned())
        .chain(inputs)
    {
        assert!(
            five.contains(&token),
            "the row for exit code 5 must name {}: {}",
            token,
            five
        );
    }
}

/// `validate` answers `ERROR_STATUS_CODE` for each input the README row names: a data file, an
/// `--input-params` file and a `--payload` document that are not valid JSON or YAML. The rules file
/// and the data file are the pair `input_params_flag_spellings_are_accepted` runs to exit 0, so the
/// 5 here is the malformed input's, and the fixture is the one `rulegen` cannot read either.
#[rstest::rstest]
#[case::data_file("data")]
#[case::input_params_file("input-params")]
#[case::payload("payload")]
fn validate_exits_five_for_each_input_the_readme_names(#[case] input: &str) {
    let rules = get_full_path_for_resource_file("resources/validate/db_param_port_rule.guard");
    let data = get_full_path_for_resource_file("resources/validate/db_resource.yaml");
    let unparsable =
        get_full_path_for_resource_file("resources/readme/rulegen-exit-five/unparsable.yaml");
    let (arguments, stdin): (Vec<String>, &str) = match input {
        "data" => (
            vec!["-r".to_owned(), rules, "-d".to_owned(), unparsable],
            "",
        ),
        "input-params" => (
            vec![
                "-r".to_owned(),
                rules,
                "-d".to_owned(),
                data,
                format!("--{}", INPUT_PARAMETERS.0),
                unparsable,
            ],
            "",
        ),
        "payload" => (vec![format!("--{}", PAYLOAD.0)], "not a json document"),
        other => panic!("no such case: {}", other),
    };
    let mut argv = vec!["cfn-guard".to_owned(), "validate".to_owned()];
    argv.extend(arguments);
    let cmd =
        CfnGuard::try_parse_from(&argv).unwrap_or_else(|e| panic!("{:?} parses: {}", argv, e));
    let mut writer =
        Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
    let mut reader = Reader::new(ReadBuffer::Cursor(std::io::Cursor::new(
        stdin.as_bytes().to_vec(),
    )));

    let code = cmd.execute(&mut writer, &mut reader).unwrap_or_else(|e| {
        panic!(
            "{}: a malformed input is reported through the exit code, not an error: {}",
            input, e
        )
    });
    assert_eq!(ERROR_STATUS_CODE, code, "{}", input);
}

/// `rulegen` answers `ERROR_STATUS_CODE` for each reason the README row names and a fixture can
/// show: a template that is not JSON or YAML, one with no `Resources` mapping, and one from which no
/// rule is generated. The fourth reason, generated rules that fail to parse back, has no fixture
/// here because no template is known to produce one.
#[rstest::rstest]
#[case::unparsable("resources/readme/rulegen-exit-five/unparsable.yaml")]
#[case::no_resources("resources/readme/rulegen-exit-five/no-resources.yaml")]
#[case::no_rules("resources/readme/rulegen-exit-five/no-rules.yaml")]
fn rulegen_exits_five_for_each_reason_the_readme_names(#[case] template: &str) {
    let cmd = CfnGuard::try_parse_from([
        String::from("cfn-guard"),
        String::from("rulegen"),
        String::from("-t"),
        get_full_path_for_resource_file(template),
    ])
    .expect("rulegen -t <file> parses");
    let mut writer =
        Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).expect("Failed to create writer.");
    let mut reader = Reader::default();

    let code = cmd
        .execute(&mut writer, &mut reader)
        .expect("an unusable template is reported through the exit code, not an error");
    assert_eq!(ERROR_STATUS_CODE, code, "{}", template);
}
