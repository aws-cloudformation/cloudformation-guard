use std::collections::{BTreeMap, BTreeSet, HashMap};

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

/// Messages for expectations that name a rule the file does not contain.
///
/// An expectation for `S3_BUCKET_ENCRYPTED` in a file whose rule is `S3_BUCKET_ENCRYPTION` was
/// silently ignored: expectations are read per evaluated rule, so one with no rule to attach to is
/// never consulted, and the run exits 0. A test asserting FAIL on a misspelled name passed while
/// asserting nothing -- the same shape as the evaluator defects this branch fixes, one layer out.
///
/// A message, not a failure. Making it a failure would break suites that pass today, and the useful
/// half is knowing; the reporters already print the mirror case, `No Test expectation was set for
/// Rule`, when a rule has no expectation.
pub(crate) fn unmatched_expectations(
    expectations: &HashMap<String, String>,
    evaluated: &BTreeSet<&str>,
) -> Vec<String> {
    expectations
        .keys()
        .filter(|name| !evaluated.contains(name.as_str()))
        .map(|name| {
            format!("No rule named {name} is in this file, so its expectation was not checked")
        })
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
