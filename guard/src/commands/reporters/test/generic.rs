use std::{
    collections::{BTreeSet, HashMap},
    convert::TryFrom,
    path::{Path, PathBuf},
    rc::Rc,
};

use crate::{
    commands::{
        files::iterate_over,
        reporters::test::{
            get_by_rules, get_status_result, joined_rule_reasons, located_diagnostic,
            unchecked_expectation_message, unmatched_expectation_names, write_diagnostics, Notices,
            ReasonForm, StderrLineKind,
        },
        test::{
            convert_input, duplicate_case_names, parse_test_specs, specs_noting_tags, TestSpec,
        },
        validate, SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE,
    },
    rules::{eval::eval_rules_file, exprs::RulesFile, Status},
};
use std::io::Write;

/// The expectations a test case could decide, keyed by `PASS`/`FAIL`; what stopped it deciding the
/// rest; and the expectations that had no rule to be decided against at all.
///
/// The second element is `None` for the ordinary case. It is `Some` when a rule in the file could not be
/// evaluated at all, which costs that rule its verdict and leaves every other rule's verdict intact --
/// so both halves are wanted, and returning only the first is what discarded a whole file's expectations
/// over one unresolvable variable.
///
/// The third is the names, so the caller can set an exit code from them. The messages go to stderr from
/// inside, where the rest of the diagnostics are collected; only the fact that there were any has to
/// come back out.
type DecidedExpectations = (
    HashMap<String, indexmap::IndexSet<String>>,
    Option<String>,
    Vec<String>,
);

pub struct GenericReporter<'report> {
    pub(crate) test_data: &'report [PathBuf],
    pub(crate) verbose: bool,
    pub(crate) rules: RulesFile<'report>,
    /// The rules file being tested, as the caller named it, for the diagnostics that do not identify
    /// their own subject. `rules` is the parsed file and carries no path, and this reporter is built once
    /// per rules file by both plaintext handlers, which each already hold it.
    pub(crate) rules_file: &'report str,
    pub(crate) writer: &'report mut crate::utils::writer::Writer,
}

impl<'report> GenericReporter<'report> {
    pub fn report(&mut self) -> crate::rules::Result<i32> {
        let mut exit_code = SUCCESS_STATUS_CODE;
        let mut test_counter = 1;
        // Accumulated across cases and written once at the end: these describe the rules or the
        // test file, not a case, so a per-case write repeats each line for every case.
        let mut diagnostics = Notices::new();

        // Zipped with the paths, as the structured reporter does, so a warning about a case's input
        // can name the file it came from.
        let specs_by_file = iterate_over(self.test_data, |data, path| {
            Ok(parse_test_specs(&data, path))
        });
        for (test_file, read) in self.test_data.iter().zip(specs_by_file) {
            // The `!!` tags the loader read past in this file are noted first, whether or not the
            // file then loaded, and printed with the other diagnostics at the end of the run.
            match specs_noting_tags(read, &mut diagnostics) {
                Err(e) => {
                    writeln!(&mut self.writer, "Error processing {e}")?;
                    exit_code = TEST_ERROR_STATUS_CODE;
                }
                Ok(specs) => {
                    diagnostics.extend_in_order(
                        StderrLineKind::Notice,
                        duplicate_case_names(&specs, test_file),
                    );
                    // Numbered twice, on purpose. `test_counter` runs across every spec file of the
                    // run and is the `Test Case #N` header, as it always was. `index` is the case's
                    // position in ITS file, from 1, which is what the case's scope names an unnamed
                    // case by, as the structured reporter does: passing the run-wide counter there
                    // made the moved-reading warning say "case 3 of `b_tests.yaml`" on this output and
                    // "case 1" on json for the same case, and could name a case the file does not have.
                    for (index, each) in specs.into_iter().enumerate() {
                        writeln!(self.writer, "Test Case #{test_counter}")?;

                        if let Some(name) = &each.name {
                            writeln!(self.writer, "Name: {name}")?;
                        }

                        // Not `?` on the evaluation. Propagating a rule that could not be evaluated out
                        // of the whole run would make a rules file with one unresolvable variable print
                        // the case number, the case name, one error line and nothing else — none of the
                        // *other* rules' expectations checked or reported, in a file where they were all
                        // decidable.
                        //
                        // `get_by_result` hands back both what it could decide and what stopped it:
                        // `eval_rules_file` evaluates every rule before returning an error, so the record
                        // holds the other rules' verdicts and there is no reason to throw them away.
                        // Not `?` either, and for the reason the loop above already applies to a test
                        // file it cannot parse at all. What is left that can fail here is the case's
                        // `input:` and its expectation strings, both of which are the test file's
                        // content: `TEST_ERROR_STATUS_CODE` is the answer to those, and it is what the
                        // `Err` arm twenty lines up gives a file that is not YAML. Propagating reached
                        // `main`'s catch-all and exited 255 -- `INTERNAL_FAILURE`, the code reserved for
                        // the tool breaking -- and abandoned every later case in the file, so one
                        // unreadable `input:` cost the verdicts of every good case behind it. The
                        // structured reporter propagated the same conversion with `?` and reached the
                        // same catch-all, so all four output formats exited 255 on these bytes: the
                        // defect was in every one of them, not a disagreement between two of them.
                        let (by_result, eval_error, unchecked) = match self.get_by_result(
                            each,
                            test_file,
                            index + 1,
                            &mut diagnostics,
                        ) {
                            Ok(decided) => decided,
                            Err(e) => {
                                writeln!(self.writer, "Error processing {e}")?;
                                exit_code = TEST_ERROR_STATUS_CODE;
                                test_counter += 1;
                                continue;
                            }
                        };

                        // Guarded, rather than assigned outright: an expectation that could not be
                        // evaluated outranks one that was not met, and the two can come from different
                        // cases of the same file. Without the guard a later failing case demoted an
                        // earlier case's error to a failure.
                        if by_result.get("FAIL").is_some() && exit_code != TEST_ERROR_STATUS_CODE {
                            exit_code = TEST_FAILURE_STATUS_CODE;
                        }

                        // After the FAIL check, so it wins: an expectation that could not be evaluated is
                        // a different and worse answer than an expectation that was not met, and
                        // `TEST_ERROR_STATUS_CODE` rather than `TEST_FAILURE_STATUS_CODE` is what says so.
                        if let Some(e) = eval_error {
                            writeln!(self.writer, "  Error: {e}")?;
                            exit_code = TEST_ERROR_STATUS_CODE;
                        }

                        // An expectation naming a rule that produced no verdict is the same answer by the
                        // same argument: there was nothing to compare it against, so it was not met or
                        // unmet, it was not evaluated. A note on stderr with exit 0 is how a rule renamed
                        // without its test file would keep a suite green.
                        //
                        // The names are already on stderr with the reason for each. What is added here is
                        // only that the run says so in its exit code.
                        if !unchecked.is_empty() {
                            exit_code = TEST_ERROR_STATUS_CODE;
                        }

                        self.print_test_case_report(&by_result);
                        test_counter += 1;
                    }
                }
            }
        }

        write_diagnostics(&diagnostics, self.writer)?;

        Ok(exit_code)
    }

    /// Returns what could be decided, and what stopped the rest from being decided.
    ///
    /// The second half exists because a rules file can be partly evaluable: `eval_rules_file` runs every
    /// rule and returns the first error afterwards, so a rule reading a variable that does not exist in
    /// it costs its own verdict and no other. Propagating instead discarded every expectation in the
    /// file, decidable or not.
    fn get_by_result(
        &mut self,
        spec: TestSpec,
        test_file: &Path,
        case_number: usize,
        diagnostics: &mut Notices,
    ) -> crate::rules::Result<DecidedExpectations> {
        let mut by_result = HashMap::new();

        // A case whose field the command could not read is this case's error, as an `input:` that
        // cannot be converted is: the reason goes where the conversion's error would, and the loop
        // above reports it and moves on to the next case.
        if let Some(reason) = spec.unreadable {
            return Err(crate::rules::errors::Error::ParseError(reason));
        }
        let root = convert_input(spec.input, &spec.collisions, test_file, diagnostics)?;
        // Built for the case, so a notice that cites a position in its input can say which case of
        // which spec file the position is in; the command reads no data file to name instead.
        let mut root_scope = crate::rules::eval_context::root_scope_for_case(
            &self.rules,
            Rc::new(root),
            test_file,
            spec.name.as_deref(),
            case_number,
        );
        let eval_error = eval_rules_file(&self.rules, &mut root_scope, None)
            .err()
            .map(|e| e.to_string());

        // Read before `reset_recorder` consumes the scope, as in `validate`: both notice kinds.
        diagnostics.absorb_deprecations(&root_scope);
        diagnostics.absorb_warnings(&root_scope);

        let top = root_scope.reset_recorder().extract();

        let by_rules = get_by_rules(&top);
        let evaluated = by_rules.keys().copied().collect::<BTreeSet<&str>>();

        // Decided once and used twice, as in the structured reporter: the note on stderr and the exit
        // code have to be answering the same question.
        //
        // Before the rule loop, and that is the whole of the fix. The loop below returns early on an
        // expectation that is not a status -- deliberately, because the case is then abandoned and the
        // structured reporter abandons it the same way -- and this was computed after the loop, so the
        // early return took it with it. The structured reporter computes it before its own rule loop,
        // so a case carrying both a bad expectation string and an expectation naming a rule that does
        // not exist reported the stale name in `json`, `yaml` and `junit` and not in
        // `single-line-summary`. Both formats already exited 1 on those bytes; the sentence saying
        // *which* expectation named nothing was the half that went missing, and a stale rule name
        // reads as coverage the author does not have, which is the reason the sentence exists.
        let unchecked = unmatched_expectation_names(&spec.expectations.rules, &evaluated);
        // Located, because this sentence says "in this file" and this is the format where nothing else
        // says which. See `located_diagnostic`.
        diagnostics.extend_sorted(
            StderrLineKind::Failure,
            unchecked.iter().map(|name| {
                located_diagnostic(
                    self.rules_file,
                    &unchecked_expectation_message(&self.rules, name),
                )
            }),
        );

        // The rule's sentence where its failed condition met refusals beside the error that decided it
        // (`Messages::parts`): `test` prints per-rule statuses and no messages, and the refused-read line
        // that used to name such a refusal is not written for this shape, so an unmet expectation on such a
        // rule says why here, with the refusal in it.
        // Built on the first unmet expectation and not before: a case whose expectations all matched
        // never needs the report walk.
        let mut joined_reasons: Option<HashMap<String, String>> = None;

        for (rule_name, rule) in by_rules {
            let expected = match spec.expectations.rules.get(rule_name) {
                Some(exp) => Status::try_from(exp.as_str())?,
                None => {
                    writeln!(
                        self.writer,
                        "  No Test expectation was set for Rule {rule_name}"
                    )?;
                    continue;
                }
            };

            let (matched, statues) = get_status_result(expected, rule);

            match matched {
                Some(status) => {
                    by_result
                        .entry(String::from("PASS"))
                        .or_insert_with(indexmap::IndexSet::new)
                        .insert(format!("{rule_name}: Expected = {status}"));
                }

                None => {
                    let reasons = joined_reasons
                        .get_or_insert_with(|| joined_rule_reasons(&top, ReasonForm::Console));
                    by_result
                        .entry(String::from("FAIL"))
                        .or_insert_with(indexmap::IndexSet::new)
                        .insert(match reasons.get(rule_name) {
                            Some(reason) => format!(
                                "{rule_name}: Expected = {expected}, Evaluated = {statues:?}, Reason = {reason}"
                            ),
                            None => format!(
                                "{rule_name}: Expected = {expected}, Evaluated = {statues:?}"
                            ),
                        });
                }
            }
        }

        if self.verbose {
            validate::print_verbose_tree(&top, self.writer);
        }

        Ok((by_result, eval_error, unchecked))
    }

    fn print_test_case_report(&mut self, by_result: &HashMap<String, indexmap::IndexSet<String>>) {
        use itertools::Itertools;
        let mut results = by_result.keys().cloned().collect_vec();

        results.sort(); // Deterministic order of results

        for result in &results {
            writeln!(self.writer, "  {result} Rules:").expect("Unable to write to the output");
            for each_case in by_result.get(result).unwrap() {
                writeln!(self.writer, "    {}", *each_case).expect("Unable to write to the output");
            }
        }

        writeln!(self.writer).expect("Unable to write to the output");
    }
}
