pub mod test;
pub mod validate;

use std::{fmt::Display, rc::Rc, time::Instant};

use quick_xml::{
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
    Writer,
};
use serde::{Deserialize, Serialize};

use crate::{
    commands::{
        reporters::test::structured::TestResult, validate::DataFile, ERROR_STATUS_CODE,
        FAILURE_STATUS_CODE,
    },
    rules::{
        self,
        eval::eval_rules_file,
        eval_context::{root_scope, simplified_json_from_root, Messages},
        exprs::RulesFile,
        Status,
    },
};

pub struct JunitReport<'report> {
    pub name: &'report str,
    pub test_suites: Vec<TestSuite<'report>>,
    pub failures: usize,
    pub errors: usize,
    pub tests: usize,
    pub duration: u128,
}

impl<'report> From<&'report Vec<TestResult>> for JunitReport<'report> {
    fn from(value: &'report Vec<TestResult>) -> Self {
        let mut errors = 0;
        let mut failures = 0;
        let mut tests = 0;
        let mut time = 0;

        let test_suites = value.iter().fold(vec![], |mut acc, result| {
            let suite = result.build_test_suite();

            time += suite.time;
            errors += suite.errors;
            failures += suite.failures;
            tests += suite.test_cases.len();

            acc.push(suite);
            acc
        });

        JunitReport {
            name: "cfn-guard test report",
            test_suites,
            failures,
            errors,
            tests,
            duration: time,
        }
    }
}

impl<'report> JunitReport<'report> {
    pub fn serialize(
        &self,
        writer: &'report mut crate::utils::writer::Writer,
    ) -> crate::rules::Result<()> {
        let mut writer = quick_xml::Writer::new_with_indent(writer, b' ', 4);
        let decl = BytesDecl::new("1.0", Some("UTF-8"), None);

        writer.write_event(Event::Decl(decl))?;
        let suites = EventType::TestSuites(TestSuites {
            name: self.name,
            tests: self.tests,
            failures: self.failures,
            errors: self.errors,
            time: self.duration,
            test_suites: &self.test_suites,
        });

        suites.serialize(&mut writer)?;
        Ok(writer.write_indent()?)
    }
}

struct JunitReporter<'reporter> {
    rules: Vec<(RulesFile<'reporter>, &'reporter str)>,
    data: Vec<DataFile>,
    writer: &'reporter mut crate::utils::writer::Writer,
    exit_code: i32,
}

impl<'reporter> JunitReporter<'reporter> {
    /// Update exit code only if code takes more presedence than current exit code
    fn update_exit_code(&mut self, code: i32) {
        if code == ERROR_STATUS_CODE
            || code == FAILURE_STATUS_CODE && self.exit_code != ERROR_STATUS_CODE
        {
            self.exit_code = code;
        }
    }
}

fn get_test_case<'rule>(
    data: &DataFile,
    rule: &RulesFile<'_>,
    name: &'rule str,
) -> crate::rules::Result<TestCase<'rule>> {
    let now = Instant::now();
    let mut root_scope = root_scope(rule, Rc::new(data.path_value.clone()));
    let status = eval_rules_file(rule, &mut root_scope, Some(&data.name))?;
    let root_record = root_scope.reset_recorder().extract();
    let time = now.elapsed().as_millis();

    let tc = match simplified_json_from_root(&root_record) {
        Ok(report) => match status {
            Status::FAIL => {
                let status = report.not_compliant.iter().fold(
                    FailingTestCase {
                        name: None,
                        messages: vec![],
                    },
                    |mut test_case, failure| {
                        failure.get_message().into_iter().for_each(|e| {
                            if let rules::eval_context::ClauseReport::Rule(rule) = failure {
                                let name = match rule.name.contains(".guard/") {
                                    true => rule.name.split(".guard/").collect::<Vec<&str>>()[1],
                                    false => rule.name,
                                };
                                test_case.name = Some(String::from(name));
                            };
                            test_case.messages.push(e);
                        });
                        test_case
                    },
                );

                TestCase {
                    id: None,
                    name,
                    time,
                    status: TestCaseStatus::Fail(status),
                }
            }
            _ => TestCase {
                id: None,
                name,
                time,
                status: match status {
                    Status::PASS => TestCaseStatus::Pass,
                    Status::SKIP => TestCaseStatus::Skip,
                    _ => unreachable!(),
                },
            },
        },

        Err(error) => TestCase {
            id: None,
            name,
            time,
            status: TestCaseStatus::Error {
                error: error.to_string(),
            },
        },
    };

    Ok(tc)
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct TestCase<'test> {
    pub id: Option<&'test str>,
    pub name: &'test str,
    pub time: u128,
    pub(crate) status: TestCaseStatus,
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) enum TestCaseStatus {
    Pass,
    Skip,
    Fail(FailingTestCase),
    Error { error: String },
}

#[derive(Debug, Clone)]
pub struct TestSuite<'suite> {
    pub name: String,
    pub test_cases: Vec<TestCase<'suite>>,
    pub time: u128,
    pub errors: usize,
    pub failures: usize,
}

impl<'suite> TestSuite<'suite> {
    pub fn new(
        name: String,
        test_cases: Vec<TestCase<'suite>>,
        time: u128,
        errors: usize,
        failures: usize,
    ) -> Self {
        Self {
            name,
            test_cases,
            time,
            errors,
            failures,
        }
    }
}

#[derive(Deserialize, Serialize, Debug, Clone)]
pub(crate) struct FailingTestCase {
    pub(crate) name: Option<String>,
    pub(crate) messages: Vec<Messages>,
}

#[derive(Default, Debug)]
struct Failure<'report> {
    name: Option<&'report String>,
    messages: Vec<&'report String>,
}

#[derive(Default, Debug)]
pub struct TestSuites<'report, 'se: 'report> {
    pub name: &'report str,
    pub tests: usize,
    pub failures: usize,
    pub errors: usize,
    pub time: u128,
    pub test_suites: &'se [TestSuite<'report>],
}

#[derive(Debug)]
enum EventType<'report, 'se: 'report> {
    Failure(Failure<'report>),
    Error(&'report str),
    TestCase(&'se TestCase<'report>),
    TestSuite(&'se TestSuite<'report>),
    TestSuites(TestSuites<'report, 'se>),
}

impl<'report, 'se: 'report> EventType<'report, 'se> {
    fn serialize_start_event(
        &self,
        writer: &mut Writer<impl std::io::Write>,
        tag: BytesStart<'_>,
    ) -> crate::rules::Result<()> {
        Ok(writer.write_event(Event::Start(tag))?)
    }
    fn start_tag(&self) -> BytesStart<'_> {
        BytesStart::new(self.to_string())
    }
    fn serialize_end_event(
        &self,
        writer: &mut Writer<impl std::io::Write>,
    ) -> crate::rules::Result<()> {
        Ok(writer.write_event(Event::End(BytesEnd::new(self.to_string())))?)
    }
    fn extend_attributes(&self, tag: &mut BytesStart<'_>) {
        match self {
            EventType::Failure(failure) => {
                if let Some(name) = &failure.name {
                    tag.push_attribute(("message", name.as_str()));
                }
            }
            EventType::TestCase(test_case) => {
                if let Some(id) = test_case.id {
                    tag.push_attribute(("id", id));
                }
                tag.extend_attributes([
                    ("name", test_case.name),
                    ("time", format!("{:.3}", test_case.time).as_str()),
                ]);
                match &test_case.status {
                    TestCaseStatus::Fail(..) => {}
                    status => {
                        let status = match status {
                            TestCaseStatus::Skip => "skip",
                            TestCaseStatus::Pass => "pass",
                            TestCaseStatus::Error { .. } => "error",
                            _ => unreachable!(),
                        };
                        tag.extend_attributes([("status", status)]);
                    }
                }
            }
            EventType::TestSuite(test_suite) => {
                tag.extend_attributes([
                    ("name", test_suite.name.as_str()),
                    ("errors", test_suite.errors.to_string().as_str()),
                    ("failures", test_suite.failures.to_string().as_str()),
                    ("time", format!("{:.3}", test_suite.time).as_str()),
                ]);
            }
            EventType::Error(..) => {}
            EventType::TestSuites(suites) => {
                tag.extend_attributes([
                    ("name", suites.name),
                    ("tests", suites.tests.to_string().as_str()),
                    ("failures", suites.failures.to_string().as_str()),
                    ("errors", suites.errors.to_string().as_str()),
                    ("time", format!("{:.3}", suites.time).as_str()),
                ]);
            }
        }
    }

    fn serialize(&self, writer: &mut Writer<impl std::io::Write>) -> crate::rules::Result<()> {
        let mut tag = self.start_tag();
        self.extend_attributes(&mut tag);
        match self {
            EventType::Failure(failure) => {
                if !failure.messages.is_empty() {
                    self.serialize_start_event(writer, tag)?;
                    self.serialize_text_events(writer)?;
                    self.serialize_end_event(writer)?;
                } else {
                    writer.write_event(Event::Empty(tag))?;
                }
            }
            EventType::TestCase(test_case) => match &test_case.status {
                TestCaseStatus::Fail(failure) => {
                    self.serialize_start_event(writer, tag)?;
                    let name = failure.name.as_ref();
                    let event = match failure.messages.is_empty() {
                        false => {
                            let messages = failure.messages.iter().fold(vec![], |mut acc, msg| {
                                if let Some(custom_message) = &msg.custom_message {
                                    acc.push(custom_message);
                                }
                                if let Some(error_message) = &msg.error_message {
                                    acc.push(error_message);
                                }
                                acc
                            });
                            EventType::Failure(Failure { name, messages })
                        }
                        true => EventType::Failure(Failure {
                            name,
                            messages: vec![],
                        }),
                    };
                    event.serialize(writer)?;
                    self.serialize_end_event(writer)?;
                }
                TestCaseStatus::Error { ref error } => {
                    self.serialize_start_event(writer, tag)?;
                    EventType::Error(error).serialize(writer)?;
                    self.serialize_end_event(writer)?;
                }
                _ => {
                    writer.write_event(Event::Empty(tag))?;
                }
            },
            EventType::Error(..) => {
                self.serialize_start_event(writer, tag)?;
                self.serialize_text_events(writer)?;
                self.serialize_end_event(writer)?;
            }
            EventType::TestSuite(test_suite) => {
                self.serialize_start_event(writer, tag)?;

                for test_case in &test_suite.test_cases {
                    EventType::TestCase(test_case).serialize(writer)?;
                }

                self.serialize_end_event(writer)?;
            }
            EventType::TestSuites(suites) => {
                self.serialize_start_event(writer, tag)?;
                for test_suite in suites.test_suites {
                    EventType::TestSuite(test_suite).serialize(writer)?;
                }

                self.serialize_end_event(writer)?;
                writer.write_event(Event::Eof)?;
            }
        }

        Ok(())
    }

    fn serialize_text_events(
        &self,
        writer: &mut Writer<impl std::io::Write>,
    ) -> crate::rules::Result<()> {
        match self {
            EventType::Failure(Failure { messages, .. }) => {
                for message in messages {
                    writer.write_event(Event::Text(BytesText::new(message)))?;
                }
            }
            EventType::Error(err) => {
                writer.write_event(Event::Text(BytesText::new(err)))?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}

impl<'report, 'se: 'report> Display for EventType<'report, 'se> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            EventType::Failure(..) => "failure",
            EventType::Error(..) => "error",
            EventType::TestCase(..) => "testcase",
            EventType::TestSuite(..) => "testsuite",
            EventType::TestSuites(..) => "testsuites",
        };

        f.write_str(text)
    }
}
