use std::{
    collections::{BTreeSet, HashMap},
    convert::TryFrom,
    path::PathBuf,
    rc::Rc,
};

use crate::{
    commands::{
        files::iterate_over,
        reporters::test::{
            get_by_rules, get_status_result, unchecked_expectation_message,
            unmatched_expectation_names, write_diagnostics, Diagnostics,
        },
        test::TestSpec,
        validate, SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE,
    },
    rules::{
        errors::Error, eval::eval_rules_file, exprs::RulesFile, path_value::PathAwareValue, Status,
    },
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
    pub(crate) writer: &'report mut crate::utils::writer::Writer,
}

impl<'report> GenericReporter<'report> {
    pub fn report(&mut self) -> crate::rules::Result<i32> {
        let mut exit_code = SUCCESS_STATUS_CODE;
        let mut test_counter = 1;
        // Accumulated across cases and written once at the end: these describe the rules or the
        // test file, not a case, so a per-case write repeats each line for every case.
        let mut diagnostics = Diagnostics::new();

        for specs in iterate_over(self.test_data, |data, path| {
            match serde_yaml::from_str::<Vec<TestSpec>>(&data) {
                Ok(spec) => Ok(spec),
                Err(_) => match serde_json::from_str::<Vec<TestSpec>>(&data) {
                    Ok(specs) => Ok(specs),
                    Err(e) => Err(Error::ParseError(format!(
                        "Unable to process data in file {}, Error {},",
                        path.display(),
                        e
                    ))),
                },
            }
        }) {
            match specs {
                Err(e) => {
                    writeln!(&mut self.writer, "Error processing {e}")?;
                    exit_code = TEST_ERROR_STATUS_CODE;
                }
                Ok(specs) => {
                    for each in specs {
                        writeln!(self.writer, "Test Case #{test_counter}")?;

                        if let Some(name) = &each.name {
                            writeln!(self.writer, "Name: {name}")?;
                        }

                        // Not `?` on the evaluation. A rule that could not be evaluated used to propagate
                        // out of the whole run, so a rules file with one unresolvable variable printed
                        // the case number, the case name, one error line and nothing else — none of the
                        // *other* rules' expectations checked or reported, in a file where they were all
                        // decidable.
                        //
                        // `get_by_result` now hands back both what it could decide and what stopped it,
                        // because since `eval_rules_file` evaluates every rule before returning an error,
                        // the record holds the other rules' verdicts and there is no reason to throw them
                        // away.
                        let (by_result, eval_error, unchecked) =
                            self.get_by_result(each, &mut diagnostics)?;

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
                        // unmet, it was not evaluated. It used to be a note on stderr and exit 0, which
                        // is how a rule renamed without its test file kept a suite green.
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
        diagnostics: &mut Diagnostics,
    ) -> crate::rules::Result<DecidedExpectations> {
        let mut by_result = HashMap::new();

        let root = PathAwareValue::try_from(spec.input)?;
        let mut root_scope = crate::rules::eval_context::root_scope(&self.rules, Rc::new(root));
        let eval_error = eval_rules_file(&self.rules, &mut root_scope, None)
            .err()
            .map(|e| e.to_string());

        // Read before `reset_recorder` consumes the scope, as in `validate`.
        diagnostics.extend(root_scope.diagnostics().cloned());

        let top = root_scope.reset_recorder().extract();

        let by_rules = get_by_rules(&top);
        let evaluated = by_rules.keys().copied().collect::<BTreeSet<&str>>();

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
                    by_result
                        .entry(String::from("FAIL"))
                        .or_insert_with(indexmap::IndexSet::new)
                        .insert(format!(
                            "{rule_name}: Expected = {expected}, Evaluated = {statues:?}"
                        ));
                }
            }
        }

        // Decided once and used twice, as in the structured reporter: the note on stderr and the exit
        // code have to be answering the same question.
        let unchecked = unmatched_expectation_names(&spec.expectations.rules, &evaluated);
        diagnostics.extend(
            unchecked
                .iter()
                .map(|name| unchecked_expectation_message(&self.rules, name)),
        );

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
