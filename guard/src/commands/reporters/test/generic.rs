use std::{collections::HashMap, convert::TryFrom, path::PathBuf, rc::Rc};

use crate::{
    commands::{
        files::iterate_over, test::TestSpec, validate, TEST_ERROR_STATUS_CODE,
        TEST_FAILURE_STATUS_CODE,
    },
    rules::{
        errors::Error, eval::eval_rules_file, exprs::RulesFile, path_value::PathAwareValue,
        NamedStatus, RecordType, Status,
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
    #![allow(clippy::never_loop)]
    pub fn report(&mut self) -> crate::rules::Result<i32> {
        let mut exit_code = 0;
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
                        if each.name.is_some() {
                            writeln!(self.writer, "Name: {}", each.name.unwrap_or_default())?;
                        }

                        let by_result = {
                            let mut by_result = HashMap::new();
                            let root = PathAwareValue::try_from(each.input)?;

                            let mut root_scope =
                                crate::rules::eval_context::root_scope(&self.rules, Rc::new(root));

                            eval_rules_file(&self.rules, &mut root_scope, None)?; // we never use data file name in the output

                            let top = root_scope.reset_recorder().extract();

                            let by_rules: HashMap<&str, Vec<&Option<RecordType<'_>>>> =
                                top.children.iter().fold(HashMap::new(), |mut acc, rule| {
                                    if let Some(RecordType::RuleCheck(NamedStatus {
                                        name, ..
                                    })) = rule.container
                                    {
                                        acc.entry(name).or_default().push(&rule.container)
                                    }
                                    acc
                                });

                            for (rule_name, rule) in by_rules {
                                let expected = match each.expectations.rules.get(rule_name) {
                                    Some(exp) => Status::try_from(exp.as_str())?,
                                    None => {
                                        writeln!(
                                            self.writer,
                                            "  No Test expectation was set for Rule {rule_name}"
                                        )?;
                                        continue;
                                    }
                                };

                                let mut statues: Vec<Status> = Vec::with_capacity(rule.len());
                                let matched = 'matched: loop {
                                    let mut all_skipped = 0;

                                    for each in rule.iter().copied().flatten() {
                                        if let RecordType::RuleCheck(NamedStatus {
                                            status: got_status,
                                            ..
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
                                                        break 'matched Some(expected);
                                                    }
                                                }
                                            }
                                            statues.push(*got_status)
                                        }
                                    }
                                    if expected == Status::SKIP && all_skipped == rule.len() {
                                        break 'matched Some(expected);
                                    }
                                    break 'matched None;
                                };

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
                                        exit_code = TEST_FAILURE_STATUS_CODE;
                                    }
                                }
                            }

                            if self.verbose {
                                validate::print_verbose_tree(&top, self.writer);
                            }
                            by_result
                        };
                        self.print_test_case_report(&by_result);
                        test_counter += 1;
                    }
                }
            }
        }
        Ok(exit_code)
    }

    pub(crate) fn print_test_case_report(
        &mut self,
        by_result: &HashMap<String, indexmap::IndexSet<String>>,
    ) {
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
