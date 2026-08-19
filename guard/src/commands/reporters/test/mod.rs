use std::collections::BTreeMap;

use crate::rules::{NamedStatus, RecordType, Status};

pub mod generic;
pub mod structured;

/// Rules a test case evaluated, keyed by name.
///
/// `BTreeMap` rather than `HashMap` because both test reporters iterate this map to build their
/// output, so its key order is the order rule names appear in the report. With a `HashMap` that
/// order came from `RandomState`, which is seeded per process: the same command over the same files
/// printed the same rules in a different sequence on consecutive runs. Anything diffing two reports
/// saw churn that was not there, and a golden-file test over more than one rule in a result group
/// could not be written at all.
///
/// The generic reporter already sorted the PASS/FAIL headings for this reason. This is the layer
/// underneath, which was missed because every fixture in `resources/test-command` has exactly one
/// rule per group, where hash order and sorted order cannot differ.
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
