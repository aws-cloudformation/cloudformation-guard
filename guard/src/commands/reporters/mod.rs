pub mod test;
pub mod validate;

use std::{collections::BTreeSet, fmt::Display, rc::Rc, time::Instant};

use quick_xml::{
    events::{BytesDecl, BytesEnd, BytesStart, BytesText, Event},
    Writer,
};
use serde::{Deserialize, Serialize};

use crate::{
    commands::{
        reporters::test::structured::TestResult,
        validate::{more_severe, DataFile},
    },
    rules::{
        self,
        eval::eval_rules_file,
        eval_context::{root_scope, simplified_json_from_root, Messages, RuleFileError},
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
    /// Rules files the parser rejected, which never reach `rules` and so would otherwise produce no
    /// test case at all. Borrowed rather than owned so the names can be lent to `TestCase` without
    /// tying those borrows to `&self`, which `update_exit_code` needs mutably.
    rule_file_errors: &'reporter [RuleFileError],
    writer: &'reporter mut crate::utils::writer::Writer,
    exit_code: i32,
}

impl<'reporter> JunitReporter<'reporter> {
    /// Update exit code only if code takes more precedence than current exit code.
    ///
    /// The precedence rule itself lives in `validate::more_severe`, which the single-line path also
    /// uses. It was stated in both places; this reporter was the only one that had it right, so the
    /// shared version is this one, moved rather than rewritten.
    fn update_exit_code(&mut self, code: i32) {
        self.exit_code = more_severe(self.exit_code, code);
    }
}

/// Builds one junit test case, and hands back the deprecation notices the evaluation produced.
///
/// The notices are an out-parameter rather than part of the return value because the early return
/// below has to carry them too: a rule that could not be evaluated may still have produced a notice
/// from a clause that was evaluated before the error, and returning `TestCase` alone gave that arm
/// nowhere to put it.
///
/// They leave through this function at all because the scope they live on is created and consumed
/// here. `-o junit` therefore lost every notice by a route of its own, separate from the one the other
/// three structured formats shared, and it is the format most likely to be the only thing a CI job
/// reads.
fn get_test_case<'rule>(
    data: &DataFile,
    rule: &RulesFile<'_>,
    name: &'rule str,
    deprecations: &mut BTreeSet<String>,
) -> crate::rules::Result<TestCase<'rule>> {
    let now = Instant::now();
    let mut root_scope = root_scope(rule, Rc::new(data.path_value.clone()));
    // A rule that cannot be evaluated is a test case in the `Error` state, not a reason to discard the
    // whole report.
    //
    // Everything needed for that was already here: `TestCaseStatus::Error` exists, `xml.rs` counts it
    // into the suite's `errors` total, and that total already sets `ERROR_STATUS_CODE`. Only this `?`
    // stood in the way, so a junit run against a rules file with one unresolvable variable emitted no
    // XML at all — and junit is a CI format, where "no report" means the job reports nothing rather
    // than reports a problem.
    //
    // The arm further down builds this same variant for a report that could not be *rendered*. This one
    // covers a rule that could not be *evaluated*, which is the case a reader actually hits.
    let status = match eval_rules_file(rule, &mut root_scope, Some(&data.name)) {
        Ok(status) => status,
        Err(error) => {
            // Drained on this arm as well as the one below. `eval_rules_file` evaluates every rule
            // before returning an error, so a clause that reached a notice already recorded it, and
            // returning here without reading the scope would drop it for the one input where the
            // author most needs everything the run had to say.
            deprecations.extend(root_scope.deprecations().cloned());

            return Ok(TestCase {
                id: None,
                name,
                time: now.elapsed().as_millis(),
                status: TestCaseStatus::Error {
                    error: error.to_string(),
                },
            });
        }
    };

    // Read before `reset_recorder` consumes the scope, which is the only window there is.
    deprecations.extend(root_scope.deprecations().cloned());

    let root_record = root_scope.reset_recorder().extract();
    let time = now.elapsed().as_millis();

    let tc = match simplified_json_from_root(&root_record) {
        Ok(report) => match status {
            Status::FAIL => {
                // The failing rule names are accumulated, not assigned. `message` holds one value and
                // the element body holds every rule's messages, so assigning once per message left the
                // attribute naming whichever rule happened to be visited last: `message="gamma_fails"`
                // on a body whose first message belongs to `alpha_fails`, so a reader who trusted the
                // attribute attributed alpha's and beta's violations to gamma.
                //
                // The golden fixtures could not show this. Every rules file in the golden directory
                // declares at most one rule, and last-rule-wins is always right when there is only one
                // rule to win.
                //
                // A rule contributes its name once per message, hence the containment check. Guard rule
                // names are identifiers, so order-preserving deduplication by equality is enough, and
                // the order is the order the reader meets the messages in.
                let mut rule_names: Vec<&str> = vec![];
                let mut messages = vec![];

                for failure in report.not_compliant.iter() {
                    for message in failure.get_message() {
                        if let rules::eval_context::ClauseReport::Rule(rule) = failure {
                            let name = match rule.name.contains(".guard/") {
                                true => rule.name.split(".guard/").collect::<Vec<&str>>()[1],
                                false => rule.name,
                            };
                            if !rule_names.contains(&name) {
                                rule_names.push(name);
                            }
                        };
                        messages.push(message);
                    }
                }

                let status = FailingTestCase {
                    name: (!rule_names.is_empty()).then(|| rule_names.join(", ")),
                    messages,
                };

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
                    // The evaluator records why a rule did not apply; carry those reasons through so
                    // junit says as much as the console does. Without this a skipped run reports
                    // `status="skip"` and nothing else, which is indistinguishable from a rule that
                    // was simply not selected.
                    Status::SKIP => TestCaseStatus::Skip {
                        reasons: report
                            .not_applicable_reasons
                            .iter()
                            .map(|(rule, reason)| format!("{}: {}", rule, reason))
                            .collect(),
                    },
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
    /// `reasons` holds one `rule: why` line per inapplicable rule that the evaluator could explain,
    /// and is empty when it could not explain any -- which is the shape every consumer saw before,
    /// since a skip previously carried nothing at all.
    Skip {
        reasons: Vec<String>,
    },
    Fail(FailingTestCase),
    Error {
        error: String,
    },
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
    /// The `<skipped>` child of a test case, carrying one line per rule that did not apply.
    Skipped(&'report [String]),
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
            // The reasons go in the element body rather than a `message` attribute, because there is
            // one per inapplicable rule and an attribute holds a single value.
            EventType::Skipped(..) => {}
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
                            TestCaseStatus::Skip { .. } => "skip",
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
                            // `custom_message` is `Some("")` rather than `None` for a clause with no
                            // custom message, which is most of them. That was invisible while each
                            // message was written as its own XML text event, because an empty event
                            // writes nothing; once the messages are joined with a separator an empty
                            // one becomes a blank line, and a leading empty one puts a newline
                            // immediately after the `<failure>` tag. Dropping them here rather than at
                            // the join also makes the emptiness test above mean what it says.
                            let messages = failure.messages.iter().fold(vec![], |mut acc, msg| {
                                if let Some(custom_message) = &msg.custom_message {
                                    if !custom_message.is_empty() {
                                        acc.push(custom_message);
                                    }
                                }
                                if let Some(error_message) = &msg.error_message {
                                    if !error_message.is_empty() {
                                        acc.push(error_message);
                                    }
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
                // An unexplained skip stays an empty element, so output only grows where there is
                // something to say.
                TestCaseStatus::Skip { reasons } if !reasons.is_empty() => {
                    self.serialize_start_event(writer, tag)?;
                    EventType::Skipped(reasons).serialize(writer)?;
                    self.serialize_end_event(writer)?;
                }
                _ => {
                    writer.write_event(Event::Empty(tag))?;
                }
            },
            EventType::Skipped(..) | EventType::Error(..) => {
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
                // One text event with explicit separators, for the reason the `Skipped` arm below
                // gives: adjacent text events concatenate with nothing between them. A custom message
                // and the error message that follows it ran together into a non-word, so
                // `...must be Enabled` plus `Check was not compliant...` read as `must be
                // EnabledCheck was not compliant`, and the committed junit golden carried `].Check`
                // five times over. With several failing rules in one test case there was also no
                // boundary a consumer could split on to recover which message belonged to which.
                let joined = messages
                    .iter()
                    .map(|message| message.as_str())
                    .collect::<Vec<&str>>()
                    .join("\n");
                writer.write_event(Event::Text(BytesText::new(&joined)))?;
            }
            EventType::Skipped(reasons) => {
                // One text event with explicit separators, not one event per reason. Adjacent text
                // events are concatenated with nothing between them, so two rules came out as
                // `...nothing to checkb: no AWS::S3::Bucket...` and the second reason was unreadable.
                // Some reasons happen to end in whitespace, which hid this in the fixtures that had
                // only one rule to explain.
                writer.write_event(Event::Text(BytesText::new(&reasons.join("\n"))))?;
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
            EventType::Skipped(..) => "skipped",
            EventType::Error(..) => "error",
            EventType::TestCase(..) => "testcase",
            EventType::TestSuite(..) => "testsuite",
            EventType::TestSuites(..) => "testsuites",
        };

        f.write_str(text)
    }
}
