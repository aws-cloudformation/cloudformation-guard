use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::Path;

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

/// The expectations that name a rule the file does not contain, by name and in sorted order.
///
/// An expectation for `S3_BUCKET_ENCRYPTED` in a file whose rule is `S3_BUCKET_ENCRYPTION` was
/// silently ignored: expectations are read per evaluated rule, so one with no rule to attach to is
/// never consulted, and the run exits 0. A test asserting FAIL on a misspelled name passed while
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

/// The one place this sentence is written, so the note on stderr and the structured reports cannot
/// drift apart.
///
/// A message, not a failure. Making it a failure would break suites that pass today, and the useful
/// half is knowing; the reporters already print the mirror case, `No Test expectation was set for
/// Rule`, when a rule has no expectation. The structured reporters carry it as a skip for the same
/// reason.
pub(crate) fn unchecked_expectation_message(name: &str) -> String {
    format!("No rule named {name} is in this file, so its expectation was not checked")
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

/// The messages, for the plaintext reporter, which writes them and keeps no structured record.
pub(crate) fn unmatched_expectations(
    expectations: &HashMap<String, String>,
    evaluated: &BTreeSet<&str>,
) -> Vec<String> {
    unmatched_expectation_names(expectations, evaluated)
        .iter()
        .map(|name| unchecked_expectation_message(name))
        .collect()
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
