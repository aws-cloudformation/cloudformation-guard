use std::{collections::HashMap, convert::TryFrom, path::PathBuf, rc::Rc};

use crate::{
    commands::{
        files::iterate_over,
        reporters::test::{get_by_rules, get_status_result},
        test::TestSpec,
        validate, SUCCESS_STATUS_CODE, TEST_ERROR_STATUS_CODE, TEST_FAILURE_STATUS_CODE,
    },
    rules::{
        errors::Error, eval::eval_rules_file, exprs::RulesFile, path_value::PathAwareValue, Status,
    },
};
use std::io::Write;

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

                        let by_result = self.get_by_result(each)?;

                        if by_result.get("FAIL").is_some() {
                            exit_code = TEST_FAILURE_STATUS_CODE;
                        }

                        self.print_test_case_report(&by_result);
                        test_counter += 1;
                    }
                }
            }
        }

        Ok(exit_code)
    }

    fn get_by_result(
        &mut self,
        spec: TestSpec,
    ) -> crate::rules::Result<HashMap<String, indexmap::IndexSet<String>>> {
        let mut by_result = HashMap::new();

        let root = PathAwareValue::try_from(spec.input)?;
        let mut root_scope = crate::rules::eval_context::root_scope(&self.rules, Rc::new(root));
        eval_rules_file(&self.rules, &mut root_scope, None)?;
        let top = root_scope.reset_recorder().extract();

        let by_rules = get_by_rules(&top);

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

        if self.verbose {
            validate::print_verbose_tree(&top, self.writer);
        }

        Ok(by_result)
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
