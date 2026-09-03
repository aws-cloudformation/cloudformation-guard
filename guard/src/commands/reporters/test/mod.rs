use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

use crate::rules::errors::Error;
use crate::rules::exprs::RulesFile;
use crate::rules::{NamedStatus, RecordType, Status};
use crate::utils::writer::Writer;

pub mod generic;
pub mod structured;

/// Messages a test run writes to stderr instead of into the report.
///
/// Two kinds so far -- deprecation notices from the evaluator, and expectations that match no rule
/// -- and one set for both, because they are the same thing from a consumer's point of view: a
/// problem with the rules or the test file rather than a result of running them. Stderr keeps stdout
/// parseable, which matters because `--output-format json` is.
///
/// A set, because a rule file is evaluated once per test case, so every message it produces is
/// produced again for each case. Six identical lines from three cases is how a warning is trained to
/// be ignored.
pub(crate) type Diagnostics = BTreeSet<String>;

/// The expectations no evaluated rule answered, by name and in sorted order.
///
/// Names, not reasons: whether the file declares the name at all is a separate question, asked by
/// [`unchecked_expectation_message`]. What this decides is only that nothing was compared against it.
///
/// An expectation for `S3_BUCKET_ENCRYPTED` in a file whose rule is `S3_BUCKET_ENCRYPTION` was
/// silently ignored: expectations are read per evaluated rule, so one with no rule to attach to is
/// never consulted, and the run exited 0. A test asserting FAIL on a misspelled name passed while
/// asserting nothing -- the same shape as the evaluator defects this branch fixes, one layer out.
///
/// Sorted, because `expectations` is a `HashMap` and its key order is reseeded every process. The
/// messages built from these land in a `BTreeSet` and were ordered by that; the structured reporters
/// carry the names into a `Vec` in the report itself, where nothing sorts them later.
pub(crate) fn unmatched_expectation_names(
    expectations: &HashMap<String, String>,
    evaluated: &BTreeSet<&str>,
) -> Vec<String> {
    let mut names = expectations
        .keys()
        .filter(|name| !evaluated.contains(name.as_str()))
        .cloned()
        .collect::<Vec<String>>();

    names.sort();
    names
}

/// The one place these sentences are written, so the note on stderr, the structured reports and the
/// junit `<error>` cannot drift apart.
///
/// A failure, and not the message it was when it was first written. The reasoning then was that
/// failing would break suites that pass today; the answer is that a suite passing because an
/// assertion was dropped is the defect and not a property worth preserving. The mirror case the
/// reporters print, `No Test expectation was set for Rule`, stays a message for a reason that does
/// not apply here: a rule with no expectation is a gap in coverage the author can see in the report,
/// while an expectation with no rule reads exactly like coverage the author does not have.
///
/// The suites this breaks are the ones that were not testing what they claimed. One was in this
/// repo: `test_data_file_with_shorthand_reference` paired a logging test file against the encryption
/// rules file, and its recorded output was five cases of `No Test expectation was set for Rule`
/// with no PASS or FAIL section anywhere in it.
///
/// Two sentences, because there are two ways an expectation goes unchecked and only one of them is a
/// name the file does not have. Both are decided from the rules file itself rather than from what
/// ran, since the two questions are different: which names the file declares, and which of them
/// produced a top-level verdict.
///
/// - Declared as a parameterized rule. It is in the file, so the first sentence would be a lie.
///   `eval_rules_file` walks `guard_rules` only, and a parameterized rule is evaluated where a
///   clause invokes it, which records it as a child of that clause's rule rather than of the file --
///   so it never appears among the rules an expectation can be matched against.
/// - Declared nowhere. A renamed or misspelled rule, which is the case worth naming plainly.
///
/// Not among these: a rule that exists and could not be evaluated. `eval_rule` closes that rule's
/// record as a failure before the error leaves `eval_rules_file`, so it has a verdict and its
/// expectation is checked against it. Measured, because keying on what ran would otherwise report a
/// rule that is plainly in the file as missing from it.
pub(crate) fn unchecked_expectation_message(rules: &RulesFile<'_>, name: &str) -> String {
    if rules
        .parameterized_rules
        .iter()
        .any(|each| each.rule.rule_name == name)
    {
        return format!(
            "{name} is a parameterized rule, which only gets a verdict where a clause invokes it, so its expectation was not checked"
        );
    }

    format!("No rule named {name} is in this file, so its expectation was not checked")
}

/// The third way an expectation goes unchecked: the rules file declares no rules at all.
///
/// Separate from [`unchecked_expectation_message`] because that one needs a `RulesFile` to tell a
/// parameterized rule from a name the file does not have, and a file with no rules in it does not
/// produce one -- `rules_file` returns `Ok(None)` for an empty, comment-only or whitespace-only file.
/// So this case could not reach that function, and it was the one of the three that said nothing:
/// `test -r empty.guard -t tests.yaml` exited **0** having checked no expectation at all, while the
/// other two exit `TEST_ERROR_STATUS_CODE` and name the rule. A suite asserting `MAIN: PASS` against
/// a rules file with no `MAIN` in it read as success.
///
/// Names the rules file by its final component only, not the path as given.
///
/// The reason recorded here was that the test-side path reducer normalized `.yaml`, `.yml` and `.json`
/// and not `.guard`, so a full path would have made any expected-output fixture hold only for the
/// checkout that produced it. That is no longer true -- the reducer covers `.guard` and `.ruleset` now
/// -- so this is a plain choice rather than a constraint, and it is left alone because this sentence is
/// about a file that declares no rules at all. There is no clause to locate in it, so the directory
/// adds nothing a reader would use. `parse_tree` records the same stale reason on the same footing.
pub(crate) fn no_rules_declared_message(rules_file: &str, expectation: &str) -> String {
    format!("{rules_file} declares no rules, so the expectation for {expectation} was not checked")
}

/// The one place the sentence for a test data file that is neither YAML nor JSON is written.
///
/// Three copies of it existed inside the test command and one of them had already drifted: the generic
/// reporter and `parse_test_specs` ended it with a comma and the structured reporter did not, so the
/// same file that will not parse read as `... at column 2,` in `single-line-summary` and `... at column 2` in
/// the three structured formats. That is the drift the note on [`unchecked_expectation_message`] exists
/// to prevent, on a sentence that had never been given the same treatment. The comma is what goes:
/// nothing ever followed it.
///
/// `validate`'s copy in `commands/helper.rs` is deliberately left where it is. That is a different
/// command's input path and this module is the test command's, so the sentence is now one place per
/// command rather than one place outright, and those two can still drift from each other. Said here
/// because the omission is a boundary rather than an oversight.
pub(crate) fn test_file_parse_error(path: &Path, error: impl std::fmt::Display) -> Error {
    Error::ParseError(format!(
        "Unable to process data in file {}, Error {}",
        path.display(),
        error
    ))
}

/// One message per test file that no rules file claimed.
///
/// The mirror of the line the report already prints for a rules file with no test files. That one
/// reads as benign, because a rules file legitimately may have no tests; a test file that nothing
/// runs is what a rules file rename leaves behind, and nothing named it.
///
/// A message and not a failure, for the reason above plus one of its own: a `tests/` directory may
/// hold a yaml or json file that is not a suite at all, and the walker cannot tell one from the
/// other by name, so failing would break setups that work.
pub(crate) fn unmatched_test_file_message(path: &Path) -> String {
    format!(
        "{} did not match any rules file, so it was not run",
        path.display()
    )
}

/// Write what a run collected. Sorted by the set, so two runs over the same input agree.
pub(crate) fn write_diagnostics(
    diagnostics: &Diagnostics,
    writer: &mut Writer,
) -> crate::rules::Result<()> {
    for line in diagnostics {
        writer.write_err(line.clone())?;
    }

    Ok(())
}

pub(crate) fn get_by_rules<'top>(
    top: &'top crate::rules::eval_context::EventRecord<'_>,
) -> BTreeMap<&'top str, Vec<&'top Option<RecordType<'top>>>> {
    top.children.iter().fold(BTreeMap::new(), |mut acc, rule| {
        if let Some(RecordType::RuleCheck(NamedStatus { name, .. })) = rule.container {
            acc.entry(name).or_default().push(&rule.container)
        }

        acc
    })
}

pub(crate) fn get_status_result(
    expected: Status,
    rule: Vec<&Option<RecordType<'_>>>,
) -> (Option<Status>, Vec<Status>) {
    let mut statuses: Vec<Status> = Vec::with_capacity(rule.len());
    let mut all_skipped = 0;

    for each in rule.iter().copied().flatten() {
        if let RecordType::RuleCheck(NamedStatus {
            status: got_status, ..
        }) = each
        {
            match expected {
                Status::SKIP => {
                    if *got_status == Status::SKIP {
                        all_skipped += 1;
                    }
                }

                rest => {
                    if *got_status == rest {
                        return (Some(expected), statuses);
                    }
                }
            }
            statuses.push(*got_status)
        }
    }

    if expected == Status::SKIP && all_skipped == rule.len() {
        return (Some(expected), statuses);
    }

    (None, statuses)
}
