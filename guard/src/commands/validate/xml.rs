use std::{rc::Rc, time::Instant};

use colored::Colorize;
use quick_xml::{
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
    Writer,
};

use crate::{
    commands::validate::{parse_rules, DataFile, RuleFileInfo},
    rules::{
        self,
        eval::eval_rules_file,
        eval_context::{root_scope, simplifed_json_from_root, FileReport, Messages},
        exprs::RulesFile,
        path_value::PathAwareValue,
        Status,
    },
};

pub struct JunitReport<'report> {
    pub(crate) name: String,
    pub(crate) test_suites: Vec<TestSuite<'report>>,
    pub(crate) failures: usize,
    pub(crate) errors: usize,
    pub(crate) tests: usize,
    pub(crate) duration: f32,
}

impl<'report> JunitReport<'report> {
    pub fn serialize(
        &self,
        writer: &'report mut crate::utils::writer::Writer,
    ) -> crate::rules::Result<()> {
        let mut writer = Writer::new_with_indent(writer, b' ', 4);
        let decl = BytesDecl::new("1.0", Some("UTF-8"), None);

        writer.write_event(Event::Decl(decl))?;
        self.serialize_test_suites(&mut writer)?;

        Ok(writer.write_indent()?)
    }

    fn serialize_test_suites(
        &self,
        writer: &mut Writer<impl std::io::Write>,
    ) -> crate::rules::Result<()> {
        let mut suite_tag = BytesStart::new("testsuites");

        suite_tag.extend_attributes([
            ("name", self.name.as_str()),
            ("tests", self.tests.to_string().as_str()),
            ("failures", self.failures.to_string().as_str()),
            ("errors", self.errors.to_string().as_str()),
        ]);
        serialize_time(&mut suite_tag, self.duration);
        writer.write_event(Event::Start(suite_tag))?;

        for test_suite in &self.test_suites {
            test_suite.serialize(writer)?;
        }

        serialize_end_event("testsuites", writer)?;

        Ok(writer.write_event(Event::Eof)?)
    }
}

impl<'test> TestSuite<'test> {
    fn serialize(&self, writer: &mut Writer<impl std::io::Write>) -> crate::rules::Result<()> {
        let mut suite_tag = BytesStart::new("testsuite");
        suite_tag.extend_attributes([
            ("name", self.name.as_str()),
            ("errors", self.errors.to_string().as_str()),
            ("failures", self.failures.to_string().as_str()),
        ]);

        serialize_time(&mut suite_tag, self.time);
        writer.write_event(Event::Start(suite_tag))?;

        for test_case in &self.test_cases {
            test_case.serialize(writer)?;
        }

        let end_tag = BytesEnd::new("testsuite");

        Ok(writer.write_event(Event::End(end_tag))?)
    }
}

impl<'test> TestCase<'test> {
    fn serialize(&self, writer: &mut Writer<impl std::io::Write>) -> crate::rules::Result<()> {
        let mut suite_tag = BytesStart::new("testcase");
        suite_tag.extend_attributes([("name", self.name)]);

        serialize_time(&mut suite_tag, self.time);
        match &self.status {
            TestCaseStatus::Fail(failure) => {
                writer.write_event(Event::Start(suite_tag))?;
                serialize_failure(failure, writer)?;
                serialize_end_event("testcase", writer)
            }
            TestCaseStatus::Error { error } => {
                writer.write_event(Event::Start(suite_tag))?;
                let error_tag = BytesStart::new("error");
                writer.write_event(Event::Start(error_tag))?;
                serialize_text_event(&error.to_string(), writer)?;
                serialize_end_event("error", writer)?;
                serialize_end_event("testcase", writer)
            }
            _ => {
                let status = match self.status {
                    TestCaseStatus::Skip => "skip",
                    TestCaseStatus::Pass => "pass",
                    _ => unreachable!(),
                };
                suite_tag.extend_attributes([("status", status)]);
                serialize_empty_event(suite_tag, writer)
            }
        }
    }
}

pub struct JunitReporter<'reporter> {
    pub(crate) rule_info: &'reporter [RuleFileInfo],
    pub(crate) input_params: &'reporter Option<PathAwareValue>,
    pub(crate) data: &'reporter Vec<DataFile>,
    pub(crate) writer: &'reporter mut crate::utils::writer::Writer,
}

impl<'reporter> JunitReporter<'reporter> {
    fn get_rules(&mut self) -> rules::Result<Vec<(RulesFile<'reporter>, &'reporter str)>> {
        self.rule_info.iter().try_fold(
            vec![],
            |mut rules,
             RuleFileInfo { file_name, content }|
             -> rules::Result<Vec<(RulesFile<'reporter>, &'reporter str)>> {
                match parse_rules(content, file_name) {
                    Err(e) => {
                        self.writer.write_err(format!(
                            "Parsing error handling rule file = {}, Error = {e}\n---",
                            file_name.underline()
                        ))?;
                    }
                    Ok(Some(rule)) => rules.push((rule, file_name)),
                    Ok(None) => {}
                }
                Ok(rules)
            },
        )
    }

    fn merge_input_params_with_data(&mut self) -> Vec<DataFile> {
        self.data.iter().fold(vec![], |mut res, file| {
            let each = match &self.input_params {
                Some(data) => data.clone().merge(file.path_value.clone()).unwrap(),
                None => file.path_value.clone(),
            };

            let merged_file_data = DataFile {
                path_value: each,
                name: file.name.to_owned(),
                content: "".to_string(), // not used later on
            };

            res.push(merged_file_data);
            res
        })
    }

    pub fn generate_junit_report(&mut self) -> crate::rules::Result<i32> {
        let now = Instant::now();
        let rules = self.get_rules()?;
        let merged_data = self.merge_input_params_with_data();
        let mut suites = vec![];
        let mut total_errors = 0;
        let mut total_failures = 0;
        let mut tests = 0;

        for each in merged_data {
            let file_report = FileReport {
                name: &each.name,
                ..Default::default()
            };

            let mut failures = 0;
            let mut errors = 0;
            let mut test_cases = vec![];
            for (rule, name) in &rules {
                let now = Instant::now();
                let tc = match root_scope(rule, Rc::new(each.path_value.clone())) {
                    Ok(mut root_scope) => {
                        let status = eval_rules_file(rule, &mut root_scope, Some(&each.name))?;
                        let root_record = root_scope.reset_recorder().extract();
                        let time = now.elapsed().as_secs_f32();
                        match simplifed_json_from_root(&root_record) {
                            Ok(report) => match status {
                                Status::FAIL => {
                                    failures += 1;

                                    let status = report.not_compliant.iter().fold(
                                        FailingTestCase {
                                            name: None,
                                            messages: vec![],
                                        },
                                        |mut test_case, failure| {
                                            failure.get_message().into_iter().for_each(|e| {
                                                if let rules::eval_context::ClauseReport::Rule(
                                                    rule,
                                                ) = failure
                                                {
                                                    let name = match rule.name.contains(".guard/") {
                                                        true => rule
                                                            .name
                                                            .split(".guard/")
                                                            .collect::<Vec<&str>>()[1],
                                                        false => rule.name,
                                                    };
                                                    test_case.name = Some(name.to_string());
                                                };
                                                test_case.messages.push(e);
                                            });
                                            test_case
                                        },
                                    );

                                    TestCase {
                                        name,
                                        time,
                                        status: TestCaseStatus::Fail(status),
                                    }
                                }
                                _ => TestCase {
                                    name,
                                    time,
                                    status: match status {
                                        Status::PASS => TestCaseStatus::Pass,
                                        Status::SKIP => TestCaseStatus::Skip,
                                        _ => unreachable!(),
                                    },
                                },
                            },

                            Err(error) => {
                                errors += 1;
                                TestCase {
                                    name,
                                    time,
                                    status: TestCaseStatus::Error { error },
                                }
                            }
                        }
                    }
                    Err(error) => {
                        errors += 1;
                        TestCase {
                            name,
                            time: now.elapsed().as_secs_f32(),
                            status: TestCaseStatus::Error { error },
                        }
                    }
                };
                test_cases.push(tc);
            }

            tests += test_cases.len();

            let suite = TestSuite {
                name: file_report.name.to_string(),
                test_cases,
                time: now.elapsed().as_secs_f32(),
                errors,
                failures,
            };

            total_errors += errors;
            total_failures += failures;

            suites.push(suite);
        }

        let exit_code = if total_errors > 0 {
            5
        } else if total_failures > 0 {
            19
        } else {
            0
        };

        let report = JunitReport {
            name: String::from("cfn-guard validate report"),
            test_suites: suites,
            failures: total_failures,
            errors: total_errors,
            tests,
            duration: std::time::Instant::now().elapsed().as_secs_f32(),
        };

        report.serialize(self.writer)?;

        Ok(exit_code)
    }
}

pub struct TestCase<'test> {
    pub name: &'test str,
    pub time: f32,
    pub(crate) status: TestCaseStatus,
}

pub(crate) enum TestCaseStatus {
    Pass,
    Skip,
    Fail(FailingTestCase),
    Error { error: crate::rules::errors::Error },
}

pub struct TestSuite<'suite> {
    pub name: String,
    pub(crate) test_cases: Vec<TestCase<'suite>>,
    pub time: f32,
    pub errors: usize,
    pub failures: usize,
}

pub(crate) struct FailingTestCase {
    pub(crate) name: Option<String>,
    pub(crate) messages: Vec<Messages>,
}

fn serialize_end_event(
    title: &str,
    writer: &mut Writer<impl std::io::Write>,
) -> crate::rules::Result<()> {
    let tag = BytesEnd::new(title);
    Ok(writer.write_event(Event::End(tag))?)
}

fn serialize_text_event(
    content: &str,
    writer: &mut Writer<impl std::io::Write>,
) -> crate::rules::Result<()> {
    Ok(writer.write_event(Event::Text(BytesText::new(content)))?)
}

fn serialize_failure(
    failure: &FailingTestCase,
    writer: &mut Writer<impl std::io::Write>,
) -> crate::rules::Result<()> {
    let mut failure_tag = BytesStart::new("failure");
    if let Some(rule_name) = &failure.name {
        failure_tag.extend_attributes([("message", rule_name.as_str())]);
    }
    match failure.messages.is_empty() {
        false => {
            writer.write_event(Event::Start(failure_tag))?;

            for failures in &failure.messages {
                if let Some(ref custom_message) = failures.custom_message {
                    serialize_text_event(custom_message, writer)?;
                }

                if let Some(ref error_message) = failures.error_message {
                    serialize_text_event(error_message, writer)?;
                }
            }
            serialize_end_event("failure", writer)
        }
        true => serialize_empty_event(failure_tag, writer),
    }
}

fn serialize_empty_event(
    tag: BytesStart,
    writer: &mut Writer<impl std::io::Write>,
) -> crate::rules::Result<()> {
    Ok(writer.write_event(Event::Empty(tag))?)
}

fn serialize_time(tag: &mut BytesStart<'_>, time: f32) {
    tag.push_attribute(("time", format!("{:.3}", time).as_str()))
}
