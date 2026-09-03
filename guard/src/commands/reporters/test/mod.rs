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
///
/// Says "in this file" and does not name it, so every stderr caller wraps it in
/// [`located_diagnostic`]. The report does not, because the enclosing `UncheckedExpectation` sits in an
/// entry whose `rule_file` already answers it.
///
/// This was recorded here as a known gap and deferred, on the premise that the identity was always
/// recoverable from the document on stdout. That premise was wrong, and wrong in the format that matters
/// most. It was checked against `json` -- where the entry does carry `rule_file` -- and generalized
/// without checking `single-line-summary`, which is the default. Measured over two sibling directories
/// each holding a `y.guard` and a suite expecting an `absent_rule`:
///
/// ```text
/// single-line-summary   2 stderr lines, byte-identical   0 records on stdout
/// json                  1 stderr line                    2 records on stdout, each with rule_file
/// yaml                  1 stderr line                    2 records on stdout, each with rule_file
/// junit                 1 stderr line                    2 records on stdout, each under its testsuite
/// ```
///
/// So in the default format the two lines were the whole account of two dropped expectations and named
/// neither file. The deferral rested on a field that format does not have.
///
/// The other half of the old note was right and is why the sentence itself is unchanged: it reaches the
/// report as an `UncheckedExpectation::reason`, four golden files carry it verbatim
/// (`unchecked_expectation_{json,yaml,junit}.out` and
/// `no_expectation_beside_unchecked_expectation_json.out`), and moving the file inside it would change
/// documents consumers parse in order to repeat what the entry already says. The locator goes on the
/// stream that has no field for it.
///
/// The junit field is `<testsuite name=...>`, not `rule_file`; an earlier note here said otherwise.
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
/// Names the rules file by the path it was given, which `report_expectations_against_no_rules` now
/// passes in.
///
/// It used to be the final component only, on two reasons that were both wrong by the time they were
/// load-bearing.
///
/// The first was that the test-side path reducer normalized `.yaml`, `.yml` and `.json` and not
/// `.guard`, so a full path would have pinned an expected-output fixture to the checkout that produced
/// it. The reducer covers `.guard` and `.ruleset` now, so that constraint is gone.
///
/// The second was that a file declaring no rules has no clause to locate, so a directory "adds nothing
/// a reader would use". That reads as a judgment about legibility and it is really a claim about
/// identity, which is false here: this arm pushes no `TestResult`, so the structured document is `[]`
/// and carries no `rule_file` field. The sentence is the only record that exists, and the walk keeps one
/// `Diagnostics` set, so two files named alike produced one line naming neither -- one dropped
/// expectation reported, one lost outright.
///
/// `parse_tree` keeps its basename and is *not* the same footing, which is the third thing recorded
/// here wrongly. Its `rules` field is `Option<String>` where `validate`'s is `Vec<String>`, and
/// `parse-tree -r <dir>` is refused outright -- measured, exit 5, "a directory is not a rules file". So
/// parse-tree can never hold two rules files in one run and its basename cannot collide with anything.
/// This sentence reaches a directory walk, where it can and did.
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

/// A diagnostic with the rules file it is about in front of it.
///
/// Some of these sentences identify their own subject -- [`no_rules_declared_message`] and
/// [`unmatched_test_file_message`] both open with the path. [`unchecked_expectation_message`] does not:
/// it says "in this file", which has no referent once two rules files in one walk both produce it. Two
/// sibling directories each dropping the same expectation gave two byte-identical lines, and in
/// `single-line-summary` -- the default format -- that pair was the entire record. Measured: zero
/// entries on stdout pairing an unchecked expectation with a file, against two in `json` and `yaml`,
/// where the enclosing entry's `rule_file` answers it. So the format a caller gets without asking was
/// the one where the identity was recoverable from nowhere.
///
/// Applied here rather than inside the sentence, which is what keeps every expected-output fixture
/// untouched. The sentence also reaches the structured report as an `UncheckedExpectation::reason`, and
/// four golden files carry it verbatim; putting the file inside it would move bytes in documents that
/// consumers parse in order to say something the entry's own `rule_file` already says. `stderr` has no
/// such field, so this is where the locator belongs.
///
/// Both stderr call sites go through this one function. Prefixing only the plaintext one would leave the
/// same fact rendered two ways on the same stream depending on `--output-format`, which is the drift the
/// note on [`unchecked_expectation_message`] exists to prevent.
///
/// `path: message`, so it lines up with the sentences that already open with their path and reads the way
/// a diagnostic is expected to.
pub(crate) fn located_diagnostic(rules_file: &str, message: &str) -> String {
    format!("{rules_file}: {message}")
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
