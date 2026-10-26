pub mod test;
pub mod validate;

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
    rc::Rc,
    time::Instant,
};

use indexmap::{IndexMap, IndexSet};
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
        eval_context::{
            root_scope_for, simplified_json_from_root, Messages, RootScope, RuleFileError,
            UnraisedCounts, WarningKind, WarningSite,
        },
        exprs::RulesFile,
        DeprecationKind, Status,
    },
};

/// Messages a run writes to stderr instead of into the report, as the commands collect them.
///
/// Three kinds -- deprecation notices from the evaluator, for the test command the expectations that
/// match no rule, and the warnings about a spec file's text (its `!!` tags, keys written twice, cases
/// named alike, cases that could not be read) -- in one collection, because they are the same thing
/// from a consumer's point of view: a problem with the rules or the test file rather than a result of
/// running them. Stderr keeps stdout parseable, which matters because `--output-format json` is.
///
/// Three buckets. The sorted set holds the lines with no position of their own, once per distinct text,
/// because one rules file is evaluated more than once per run -- once per test case by the test
/// command, once per data file by a structured validate report -- so every message it produces is
/// produced again for each evaluation. Six identical lines from three cases is how a warning is trained
/// to be ignored. A notice the evaluator records once per site carries the value it is about in its
/// text, so two cases, or two data files, whose matching resource has a different logical id would
/// print two lines for one filter. The `(kind, site)` keys are therefore carried alongside the lines,
/// and such a notice is kept only when its site is new: one line per site across the evaluations, the
/// first one's text.
///
/// The ordered set holds the lines that carry a position in a file, in the order they were added,
/// each once. Sorted by text, `L:10` comes before `L:2`, so two such lines from one file came out in
/// the opposite order from the one a reader fixing the file works in, while `validate` prints the same
/// lines for a data file in document order. The order they are added in is grouped by kind, each kind
/// in document order: files are read in order, and within one file every `!!` tag line comes first,
/// then the file's refusal if the loader refused it, then the alike-name lines, then the duplicate-key
/// or unreadable-case lines case by case. The kinds are not interleaved by position, on purpose: that
/// is the order `validate` writes the same lines in for a data file, every tag line as the file is
/// read and the duplicate-key lines after them. An `IndexSet` rather than a `Vec` checked with
/// `contains`, because a directory walk folds every file's lines into one collection and a scan per
/// line grows with the square of the line count. The ordered lines are written before the sorted set.
///
/// The third bucket holds the evaluator's warnings: positioned lines too, each ending with the position
/// of the clause it is about, in the order the scopes recorded them, once per call site and argument,
/// through `absorb_warnings`. Written after the sorted set, so that every output writes the deprecation notices
/// first and then the warnings in recorded order, which is the order the single-line `validate` output
/// writes the two kinds in as it reads the scope directly (its deprecations, then its warnings).
/// Sorted in with the notices, as these lines were, "line:13" came before "line:3"; in the first bucket
/// they would have come before the deprecation notices, where the single-line output puts them after.
///
/// Each method names its bucket, and there is no `Extend` or `FromIterator`: a call that could pick the
/// sorted set without saying so is how a positioned line goes back to text order unnoticed.
///
/// Shared by the test reporters and the structured validate reporters (json, yaml, sarif, junit), which
/// write one document for several evaluations, and by the single-line validate output, which writes
/// each data file's notices beside that file's report and carries one of these across its data files
/// so that a site announced beside the first file is not announced again beside the next. The test
/// command's public reporter keeps upstream's `diagnostics` field, a plain sorted set, beside this: see
/// `StructuredTestReporter::evaluate`.
#[derive(Debug, Default)]
pub(crate) struct Notices {
    in_order: IndexSet<Line>,
    sorted: BTreeSet<Line>,
    /// The evaluator's warnings, one line per key (`WarningSite`: the call site, the argument, and the
    /// input file), in the order the keys were first recorded; written after the sorted set, so that
    /// the deprecation notices come first and the warnings after them, which is the order the
    /// single-line `validate` output writes the two kinds in. A map rather than a set so that a later
    /// case of the same spec file, which shares its key, can re-render the line in place with a count
    /// that covers its maps too; see `absorb_warnings`.
    warnings: IndexMap<WarningSite, Line>,
    /// What each warning line counts: the first text recorded for its key and every (case, map) pair
    /// recorded for it, keyed by the case's position in its file because two cases' maps share their
    /// paths and are not one map, and two cases' names may be one name while the cases are not.
    warning_tallies: BTreeMap<WarningSite, WarningTally>,
    sites: BTreeSet<(DeprecationKind, String)>,
}

/// The readings one warning line stands for, across the scopes absorbed under its key: the maps of
/// every input for a moved reading, the inputs alone for an unbound capture, which has no maps, and for
/// an unraised refusal the cases with what each case's line was rendered from, so the multi-case line is
/// rendered again from all of them (`unraised_refusal_notice`) and a later case's refusal text or
/// verdict is named, not reduced to a count.
#[derive(Debug)]
struct WarningTally {
    kind: WarningKind,
    /// The head the multi-case line is built on: the first text recorded for the key
    /// (`SiteWarning::first`). For a moved reading and an unbound capture that is a rendered `Warning:`
    /// line, which the count is appended to; for an unraised refusal it is the clause as written, the
    /// context the line is rendered from with the summed counts, the joined texts and the position below.
    first: String,
    /// Every (case position, map path) recorded for the key: the maps a moved reading counts.
    readings: BTreeSet<(usize, String)>,
    /// Every case position recorded for the key, the K of "across K cases in this file", with the
    /// evaluations that case's scope counted under each verdict of an unraised refusal (all zero for the
    /// other kinds). Keyed by case so a scope absorbed twice counts once.
    cases: BTreeMap<usize, UnraisedCounts>,
    /// For an unraised refusal: the distinct refusal texts in the order the cases met them, and the
    /// clause's position, which ends the line unless an entry went unrecorded, when a closing sentence
    /// asking for a report follows it.
    met: Vec<String>,
    position: String,
}

/// What a line collected for stderr is, decided where the line is made, and named for the writer's
/// path it takes. The writer has one path per kind: a notice goes through its notice path, which
/// records it as a notice and holds it to one of the two shared prefixes; a failure goes through its
/// failure path and is recorded as one; an informational line, which is neither, is written and
/// recorded as neither. Carrying the kind with the line is what lets the writing end route without
/// reading the text, so a misspelled prefix is caught where the line is written rather than passed
/// through as something else; the routing lives in [`Line::write_to`], the one place a collected
/// line is written from, whether on its own or as part of a collection ([`Notices::write_to`]).
///
/// Warnings and deprecation notices are one kind here, the writer's notice, as they are one path
/// there. They are told apart by their prefix alone, and the evaluator's notice channel carries both
/// (a filter that selected nothing is a warning, a clause that passes by default a deprecation) as
/// plain text with no kind of its own; a kind that separated them would be guessed at the point of
/// collection, which is what this type exists to avoid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum StderrLineKind {
    /// A condition the run noticed and went on from, which the writer records as a notice: under the
    /// warning prefix (a tag the loader read past, a key written twice, two cases named alike, a
    /// filter that selected nothing) or the deprecation prefix (a notice from the evaluator about a
    /// future release).
    Notice,
    /// Information that is neither a problem with the run nor a notice, which the writer's message
    /// path writes and records nowhere: a test file no rules file claimed.
    Message,
    /// Something the run could not do or an expectation it could not meet: a file or case it could
    /// not read, an expectation no rule answered.
    Failure,
}

/// One line collected for stderr, with its kind. Ordered and hashed by the text first, so the sorted
/// set stays sorted by text and a line is held once per text and kind.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Line {
    pub(crate) text: String,
    pub(crate) kind: StderrLineKind,
}

impl Line {
    pub(crate) fn new(kind: StderrLineKind, text: String) -> Self {
        Self { text, kind }
    }

    /// Writes the line to the error stream down the writer's path for its kind: a notice through
    /// the notice path, which records it as a notice and holds it to the shared prefixes; a failure
    /// through the failure path; an informational line through the message path, which records
    /// nothing. The one place a collected line is written from, so no caller reads a line's text to
    /// route it and no caller can drop its kind: a collection writes each of its lines through here
    /// ([`Notices::write_to`]), and the single-line validate output, which writes each data file's
    /// new lines as it goes, writes them one at a time through here.
    pub(crate) fn write_to(
        &self,
        writer: &mut crate::utils::writer::Writer,
    ) -> crate::rules::Result<()> {
        match self.kind {
            StderrLineKind::Notice => writer.write_notice(self.text.clone())?,
            StderrLineKind::Message => writer.write_message(self.text.clone())?,
            StderrLineKind::Failure => writer.write_err(self.text.clone())?,
        }
        Ok(())
    }
}

impl Notices {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A message with no position of its own: kept once per distinct text and kind, in the sorted
    /// set.
    pub(crate) fn insert_sorted(&mut self, kind: StderrLineKind, line: String) -> bool {
        self.sorted.insert(Line::new(kind, line))
    }

    /// Messages with no position of their own, into the sorted set.
    pub(crate) fn extend_sorted<I: IntoIterator<Item = String>>(
        &mut self,
        kind: StderrLineKind,
        lines: I,
    ) {
        self.sorted
            .extend(lines.into_iter().map(|line| Line::new(kind, line)));
    }

    /// One positioned line, after the ones already held, once.
    pub(crate) fn push_in_order(&mut self, kind: StderrLineKind, line: String) {
        self.in_order.insert(Line::new(kind, line));
    }

    /// Positioned lines that keep their order, after the ones already held, each once.
    pub(crate) fn extend_in_order<I: IntoIterator<Item = String>>(
        &mut self,
        kind: StderrLineKind,
        lines: I,
    ) {
        self.in_order
            .extend(lines.into_iter().map(|line| Line::new(kind, line)));
    }

    /// Every notice a scope collected: the plain ones once per text, the once-per-site ones once per
    /// site across every scope absorbed so far.
    ///
    /// Returns the lines this scope added, in text order and with their kind, for a path that writes
    /// each evaluation's notices as it goes rather than the whole set at the end: the single-line
    /// validate output writes a data file's notices beside that file's report, reads from here which
    /// of them are new to the run, and writes each through [`Line::write_to`]. A caller that writes
    /// the set once ignores the return. Every line absorbed here is a deprecation notice, so it is
    /// collected as [`StderrLineKind::Notice`], the writer's notice path.
    pub(crate) fn absorb_deprecations(&mut self, root_scope: &RootScope<'_, '_>) -> Vec<Line> {
        let mut added = BTreeSet::new();
        for notice in root_scope.plain_deprecations() {
            let line = Line::new(StderrLineKind::Notice, notice.clone());
            if self.sorted.insert(line.clone()) {
                added.insert(line);
            }
        }
        for (site, notice) in root_scope.deprecations_once() {
            let line = Line::new(StderrLineKind::Notice, notice.clone());
            if self.sites.insert(site.clone()) && self.sorted.insert(line.clone()) {
                added.insert(line);
            }
        }
        added.into_iter().collect()
    }

    /// Whether a once-per-site notice at `site` has already been absorbed from an earlier scope, for a
    /// caller that wants to say, after the fact, which later evaluations hit a site the run announced
    /// once. Read before the scope that holds the site is absorbed, or the answer is about that scope.
    pub(crate) fn holds_site(&self, site: &(DeprecationKind, String)) -> bool {
        self.sites.contains(site)
    }

    /// Whether a notice with no site and this text has already been absorbed from an earlier scope: the
    /// plain counterpart of [`Self::holds_site`], read before the scope that holds the text is absorbed.
    /// The sorted set holds the once-per-site notices' texts too, so this answers for any text; a caller
    /// asks it about the plain notices a scope recorded. Every notice absorbed into the sorted set carries
    /// the notice kind, so the text is looked up under it.
    pub(crate) fn holds_plain(&self, text: &str) -> bool {
        self.sorted
            .contains(&Line::new(StderrLineKind::Notice, text.to_owned()))
    }

    /// Every moved-reading warning a scope collected (`RootScope::warnings_by_site`), once per key
    /// (`WarningSite`: the call site, the argument, and the input, the data file under `validate` or the
    /// spec file under `test`) across every scope absorbed so far: the `test` command builds a scope per
    /// case, and each case's line names that case's positions, so a drain by exact text printed one line
    /// per case for one call. The input file is in the key so that a run over several spec files, or
    /// over several data files, prints each file's line for the call, naming the file, rather than the
    /// first file's alone. Within one spec file the line is the first case's, and its count covers every
    /// case of the file that recorded the key: a later case's maps are counted into the line, keyed by
    /// the case's position in the file because two cases' maps share their paths (and two cases may
    /// share a name, which a spec file is free to repeat), and the line is re-rendered in place, worded
    /// "across K cases in this file", since the first case's own count ("in this case") named a case
    /// that may have passed and said nothing of a later case that failed on the moved reading. The lines
    /// go into the bucket written last, in the order the keys were first recorded: positioned lines,
    /// each ending with the position of the clause it is about. The one place the bucket for this kind
    /// is chosen; every reporter that reads a scope's warnings calls this, so that none of them puts a
    /// positioned line back into text order on its own. Returns the lines this scope added or
    /// re-rendered, in that order and with their kind, as `absorb_deprecations` does, for the path that
    /// writes as it goes through [`Line::write_to`] (under `validate` every key is one data file's, so a
    /// line is never re-rendered there). The unbound-capture warning (`WarningKind::UnboundCapture`)
    /// is collapsed by the same key and re-rendered with its own words across the cases of one spec
    /// file, counting the further cases that refuse the capture: it has no maps and no differing value,
    /// and while it rode the moved reading's key its line across two cases said "1 more map under this
    /// call read a differing value for this argument".
    pub(crate) fn absorb_warnings(&mut self, root_scope: &RootScope<'_, '_>) -> Vec<Line> {
        let mut added = Vec::new();
        for (key, reading) in root_scope.warnings_by_site() {
            let tally = self
                .warning_tallies
                .entry(key.clone())
                .or_insert_with(|| WarningTally {
                    kind: reading.kind,
                    first: reading.first.to_owned(),
                    readings: BTreeSet::new(),
                    cases: BTreeMap::new(),
                    met: Vec::new(),
                    position: reading.position.to_owned(),
                });
            tally.cases.insert(reading.case, reading.verdicts);
            tally
                .readings
                .extend(reading.maps.iter().map(|map| (reading.case, map.clone())));
            for text in reading.met {
                if !tally.met.contains(text) {
                    tally.met.push(text.clone());
                }
            }
            let text = if tally.cases.len() == 1 {
                reading.line.to_owned()
            } else {
                match tally.kind {
                    WarningKind::MovedReading => {
                        let more = tally.readings.len() - 1;
                        format!(
                            "{} {} more map{} under this call read a differing value for this \
                             argument across {} cases in this file; only the first is shown.",
                            tally.first,
                            more,
                            if more == 1 { "" } else { "s" },
                            tally.cases.len()
                        )
                    }
                    WarningKind::UnboundCapture => {
                        let more = tally.cases.len() - 1;
                        format!(
                            "{} The same capture is refused in {} more case{} of this file; only the \
                             first is shown.",
                            tally.first,
                            more,
                            if more == 1 { "" } else { "s" }
                        )
                    }
                    // An unraised refusal has no maps either: what each case's scope counted is the
                    // evaluations under each verdict and the refusal texts the site met, so across the
                    // cases of one spec file the line is RENDERED AGAIN from the cases' summed counts
                    // and every text any case met, in case order, with the case count and the spec
                    // file in place of the one case's name; a count appended to the first case's line
                    // left a later case's different refusal text, or its different verdict, unsaid.
                    WarningKind::UnraisedRefusal => {
                        let verdicts = tally
                            .cases
                            .values()
                            .fold(UnraisedCounts::default(), |sum, case| sum + *case);
                        let across = rules::eval_context::WhereFound::Cases {
                            count: tally.cases.len(),
                            spec_file: key.spec_file().map(str::to_string),
                        };
                        rules::eval_context::unraised_refusal_notice(
                            &tally.first,
                            verdicts,
                            &tally.met,
                            &tally.position,
                            &across,
                        )
                    }
                }
            };
            // Every line the evaluator records here is a notice under one of the two shared prefixes,
            // so the kind is fixed here, as `absorb_deprecations` fixes it, and no caller chooses it.
            let line = Line::new(StderrLineKind::Notice, text);
            if self.warnings.get(&key) != Some(&line) {
                self.warnings.insert(key, line.clone());
                added.push(line);
            }
        }
        added
    }

    /// Every line in the order it is written: the ordered lines, then the sorted set, then the
    /// evaluator's warnings.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &Line> {
        self.in_order
            .iter()
            .chain(self.sorted.iter())
            .chain(self.warnings.values())
    }

    /// Writes every line to the error stream in the order [`iter`](Self::iter) gives, each through
    /// [`Line::write_to`], the writer's path for its kind. The one way a collection is written, so
    /// no caller reads a line's text to route it and no caller can drop its kind.
    pub(crate) fn write_to(
        &self,
        writer: &mut crate::utils::writer::Writer,
    ) -> crate::rules::Result<()> {
        for line in self.iter() {
            line.write_to(writer)?;
        }
        Ok(())
    }
}

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
    deprecations: &mut Notices,
) -> crate::rules::Result<TestCase<'rule>> {
    let now = Instant::now();
    let mut root_scope = root_scope_for(rule, Rc::new(data.path_value.clone()), Some(&data.name));
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
            deprecations.absorb_deprecations(&root_scope);
            deprecations.absorb_warnings(&root_scope);

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
    deprecations.absorb_deprecations(&root_scope);
    deprecations.absorb_warnings(&root_scope);

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
                    for message in failure.get_message_with_rule_records() {
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
    messages: Vec<FailureText<'report>>,
}

/// One text of a failure element and whose it is: the rule author's `<< >>` prose (a `custom_message`),
/// written under the relaxed set, or the evaluator's (an `error_message`), written under the strict one.
#[derive(Debug)]
struct FailureText<'report> {
    author: bool,
    text: &'report str,
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
                    push_text_attribute(tag, "message", name);
                }
            }
            // The reasons go in the element body rather than a `message` attribute, because there is
            // one per inapplicable rule and an attribute holds a single value.
            EventType::Skipped(..) => {}
            EventType::TestCase(test_case) => {
                if let Some(id) = test_case.id {
                    push_text_attribute(tag, "id", id);
                }
                push_text_attribute(tag, "name", test_case.name);
                tag.extend_attributes([("time", format!("{:.3}", test_case.time).as_str())]);
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
                push_text_attribute(tag, "name", test_suite.name.as_str());
                tag.extend_attributes([
                    ("errors", test_suite.errors.to_string().as_str()),
                    ("failures", test_suite.failures.to_string().as_str()),
                    ("time", format!("{:.3}", test_suite.time).as_str()),
                ]);
            }
            EventType::Error(..) => {}
            EventType::TestSuites(suites) => {
                push_text_attribute(tag, "name", suites.name);
                tag.extend_attributes([
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
                                // A text of blanks says nothing (`rules::non_blank`, the one test for it).
                                if let Some(custom_message) =
                                    crate::rules::non_blank(&msg.custom_message)
                                {
                                    acc.push(FailureText {
                                        author: true,
                                        text: custom_message,
                                    });
                                }
                                if let Some(error_message) =
                                    crate::rules::non_blank(&msg.error_message)
                                {
                                    acc.push(FailureText {
                                        author: false,
                                        text: error_message,
                                    });
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
                    .map(|message| match message.author {
                        true => xml_text_with_escaped_controls_by(
                            message.text,
                            crate::utils::writer::escaped_controls_for_xml_author_text,
                        ),
                        false => xml_text_with_escaped_controls(message.text),
                    })
                    .collect::<Vec<String>>()
                    .join("\n");
                writer.write_event(Event::Text(BytesText::new(&joined)))?;
            }
            EventType::Skipped(reasons) => {
                // One text event with explicit separators, not one event per reason. Adjacent text
                // events are concatenated with nothing between them, so two rules came out as
                // `...nothing to checkb: no AWS::S3::Bucket...` and the second reason was unreadable.
                // Some reasons happen to end in whitespace, which hid this in the fixtures that had
                // only one rule to explain.
                let joined = reasons
                    .iter()
                    .map(|reason| xml_text_with_escaped_controls(reason))
                    .collect::<Vec<String>>()
                    .join("\n");
                writer.write_event(Event::Text(BytesText::new(&joined)))?;
            }
            EventType::Error(err) => {
                writer.write_event(Event::Text(BytesText::new(
                    &xml_text_with_escaped_controls(err),
                )))?;
            }
            _ => unreachable!(),
        }

        Ok(())
    }
}

/// `text` for an XML text node, with every control that breaks or hides a line written as its escape
/// (`escaped_controls_for_xml_text`) except the line feed and the tab, which the text keeps: the messages
/// of a failing case are joined by line feeds on purpose, a message's own line feeds are legal XML, and a
/// tab is legal XML that neither ends nor hides a line. XML escaping alone leaves an ESC or another C0
/// control as the byte itself, which XML 1.0 does not allow in a document at all (a conforming parser
/// rejects the file) and which a terminal reading the report acts on; U+FFFE and U+FFFF, which XML 1.0
/// forbids as well and which the JSON reader keeps, are written as their escapes too. A carriage return
/// and line feed pair is one line feed, since a parser reads the pair as one; a carriage return alone is
/// escaped, since a parser reads one as a line feed.
fn xml_text_with_escaped_controls(text: &str) -> String {
    xml_text_with_escaped_controls_by(text, crate::utils::writer::escaped_controls_for_xml_text)
}

/// [`xml_text_with_escaped_controls`] under the escape `escape` names: the strict set for the evaluator's
/// text, the relaxed one for a rule author's prose (`escaped_controls_for_xml_author_text`), which keeps a
/// zero-width joiner and the direction marks as typed, as the console does.
fn xml_text_with_escaped_controls_by(text: &str, escape: fn(&str) -> String) -> String {
    text.replace("\r\n", "\n")
        .split('\n')
        .map(escape)
        .collect::<Vec<String>>()
        .join("\n")
}

/// Adds the attribute `key` with the value `text` written by `xml_attribute_value` (`utils::writer`): a
/// tab and a line feed as character references (a parser keeps a reference and turns a literal one into a
/// space), a carriage return and every other control as its escape (a reference to a carriage return
/// decodes to a raw one for every consumer), the markup characters as entities. A name that holds a
/// zero-width joiner or a bidirectional mark prints it as an escape too: a name is an identifier compared
/// by eye against another, which differs from the rule author's prose on the console. A backslash is
/// written as it is, so a file name reads back as it was typed; a name holding a control and a name
/// holding the typed characters of its escape read alike (`xml_attribute_value` says why that is
/// accepted). The value is handed to the
/// writer as bytes (`Attribute::from` for byte slices applies no transformation), so the character
/// references are not escaped a second time.
fn push_text_attribute(tag: &mut BytesStart<'_>, key: &str, text: &str) {
    tag.push_attribute((
        key.as_bytes(),
        crate::utils::writer::xml_attribute_value(text).as_bytes(),
    ));
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

/// The text nodes and the attribute values of the JUnit report: a message, a skip reason, an error and a
/// name that hold a raw ESC are written with the control as its escape, and the document stays
/// well-formed (the two code points XML 1.0 forbids beside the controls are escapes too). A tab and a line
/// feed stay in a text node and are written as character references in an attribute value; a carriage
/// return is written as its escape `\r` in both, since a reference to it decodes to a raw one for every
/// consumer. The ESC is built with `char::from`, since the source holds no raw control.
#[cfg(test)]
mod junit_escape_tests {
    use super::{
        xml_text_with_escaped_controls, EventType, FailingTestCase, TestCase, TestCaseStatus,
        TestSuite, TestSuites,
    };
    use crate::rules::eval_context::Messages;
    use quick_xml::{events::Event, Reader, Writer};

    fn esc() -> char {
        char::from(0x1b)
    }

    /// The report for one suite holding one case with `status`.
    fn report_of(status: TestCaseStatus) -> String {
        report_named("all", "suite", "case", status)
    }

    /// The report for one suite holding one case with `status`, with the names of the three elements
    /// as given.
    fn report_named(
        suites_name: &str,
        suite_name: &str,
        case_name: &str,
        status: TestCaseStatus,
    ) -> String {
        let case = TestCase {
            id: None,
            name: case_name,
            time: 0,
            status,
        };
        let suite = TestSuite::new(suite_name.to_string(), vec![case], 0, 0, 1);
        let suites = [suite];
        let mut writer = Writer::new(Vec::new());
        EventType::TestSuites(TestSuites {
            name: suites_name,
            tests: 1,
            failures: 1,
            errors: 0,
            time: 0,
            test_suites: &suites,
        })
        .serialize(&mut writer)
        .expect("writing to a Vec cannot fail");
        String::from_utf8(writer.into_inner()).expect("the report is UTF-8")
    }

    /// The text of the report's text nodes only, joined with nothing between them, read back by an XML
    /// parser; a parse error fails the cell, so the document is well-formed wherever this returns.
    /// Attribute values are not in it: the cells that read them look at the document itself.
    fn text_nodes(xml: &str) -> String {
        let mut reader = Reader::from_str(xml);
        let mut text = String::new();
        loop {
            match reader.read_event().expect("the report is well-formed XML") {
                Event::Text(node) => {
                    text.push_str(&node.unescape().expect("a text node unescapes"))
                }
                Event::Eof => return text,
                _ => {}
            }
        }
    }

    /// A control other than a line feed or a tab, in the document: XML 1.0 allows a tab, a line feed and
    /// a carriage return below U+0020 and nothing else, and the report writes a carriage return raw
    /// nowhere; the tab and the line feed of a text node are written as they are.
    fn has_a_raw_control(xml: &str) -> bool {
        xml.chars()
            .any(|c| c.is_control() && c != '\n' && c != '\t')
    }

    /// Fails when a failing case's message or error carries the ESC byte, so the document holds a
    /// character XML 1.0 does not allow, when a message's line feed is escaped and the joined
    /// messages lose their separator, or when the tab is written as `\t` where the text keeps it.
    #[test]
    fn a_failing_cases_messages_are_written_with_escaped_controls() {
        let xml = report_of(TestCaseStatus::Fail(FailingTestCase {
            name: Some("n".to_string()),
            messages: vec![Messages {
                custom_message: Some(format!("{}[2J\tfirst\nsecond", esc())),
                error_message: Some(format!("bad {}[1mvalue", esc())),
                location: None,
                refusal: false,
                parts: None,
            }],
        }));
        assert!(
            !has_a_raw_control(&xml),
            "no raw control in the report:\n{:?}",
            xml
        );
        assert_eq!(
            "\\u{1b}[2J\tfirst\nsecond\nbad \\u{1b}[1mvalue",
            text_nodes(&xml),
            "the ESCs are escapes, the tab and the line feeds stay"
        );
    }

    /// A rule that fails with no check under it (its own `when` could not be evaluated, or a call that
    /// carries a `<< >>` body over a rule whose clauses reported nothing) reaches the failure element with
    /// the rule record's own message, and the escape set follows the record's slot
    /// (`RuleReport::custom_slot`): the author's body keeps a zero-width joiner as typed, the evaluator's
    /// sentence and a refusal's write it as an escape. One row per slot, through
    /// `get_message_with_rule_records` and the writer.
    ///
    /// Fails when the failure element is empty for a row (the rule's own record is not read),
    /// when the author's row writes the joiner as an escape, or when an evaluator's or a
    /// refusal's row keeps it raw.
    #[test]
    fn a_rule_with_no_check_reports_its_own_message_under_its_slots_escape_set() {
        use crate::rules::eval_context::{ClauseReport, RuleReport};
        use crate::rules::CustomSlot;
        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let typed = format!("owner{}tag", joiner);
        let escaped = "owner\\u{200d}tag";
        for (slot, expected) in [
            (CustomSlot::Author, typed.clone()),
            (CustomSlot::Evaluator, escaped.to_string()),
            (CustomSlot::Refusal, escaped.to_string()),
        ] {
            let report = ClauseReport::Rule(RuleReport {
                name: "check",
                messages: Messages {
                    custom_message: Some(typed.clone()),
                    error_message: None,
                    location: None,
                    refusal: slot == CustomSlot::Refusal,
                    parts: None,
                },
                custom_slot: slot,
                ..Default::default()
            });
            let xml = report_of(TestCaseStatus::Fail(FailingTestCase {
                name: Some("check".to_string()),
                messages: report.get_message_with_rule_records(),
            }));
            assert_eq!(
                expected,
                text_nodes(&xml),
                "the failure text of a rule record marked {:?}:\n{}",
                slot,
                xml
            );
        }
    }

    /// Fails when a skip reason carries the ESC byte.
    #[test]
    fn a_skip_reason_is_written_with_escaped_controls() {
        let xml = report_of(TestCaseStatus::Skip {
            reasons: vec![format!("rule: {}[1mnothing to check", esc())],
        });
        assert!(
            !has_a_raw_control(&xml),
            "no raw control in the report:\n{:?}",
            xml
        );
        assert_eq!("rule: \\u{1b}[1mnothing to check", text_nodes(&xml));
    }

    /// Fails when an error text carries the ESC byte.
    #[test]
    fn an_error_text_is_written_with_escaped_controls() {
        let xml = report_of(TestCaseStatus::Error {
            error: format!("failed {}[1mhere", esc()),
        });
        assert!(
            !has_a_raw_control(&xml),
            "no raw control in the report:\n{:?}",
            xml
        );
        assert_eq!("failed \\u{1b}[1mhere", text_nodes(&xml));
    }

    /// A text that is already escaped, and one with no control, are written as they are.
    #[test]
    fn an_escaped_or_plain_text_is_unchanged() {
        assert_eq!(
            "a\\u{1b}[1m\nb",
            xml_text_with_escaped_controls("a\\u{1b}[1m\nb")
        );
        assert_eq!("plain; text", xml_text_with_escaped_controls("plain; text"));
    }

    /// A carriage return and line feed pair is one line feed in a text node, a carriage return alone is
    /// written as its escape, and a tab stays.
    ///
    /// Fails when the pair is written as `\r` followed by a line feed.
    #[test]
    fn a_crlf_pair_is_one_line_feed_in_a_text_node() {
        assert_eq!("a\nb", xml_text_with_escaped_controls("a\r\nb"));
        assert_eq!("a\\rb", xml_text_with_escaped_controls("a\rb"));
        assert_eq!("a\tb", xml_text_with_escaped_controls("a\tb"));
    }

    /// The `name` attribute values of the `testcase` elements, read back by an XML parser: the character
    /// references are decoded, as a consumer of the report decodes them.
    fn case_names(xml: &str) -> Vec<String> {
        let mut reader = Reader::from_str(xml);
        let mut names = Vec::new();
        loop {
            match reader.read_event().expect("the report is well-formed XML") {
                Event::Start(tag) | Event::Empty(tag) if tag.name().as_ref() == b"testcase" => {
                    for attribute in tag.attributes() {
                        let attribute = attribute.expect("an attribute parses");
                        if attribute.key.as_ref() == b"name" {
                            names.push(
                                attribute
                                    .unescape_value()
                                    .expect("a value unescapes")
                                    .into_owned(),
                            );
                        }
                    }
                }
                Event::Eof => return names,
                _ => {}
            }
        }
    }

    /// The raw bytes of every attribute value in the document, as written and not unescaped: what a
    /// consumer's parser normalizes before it hands a value over, so a raw tab, line feed or carriage
    /// return in one is read here though the unescaped read-back (`case_names`) would not show it.
    fn raw_attribute_values(xml: &str) -> Vec<Vec<u8>> {
        let mut reader = Reader::from_str(xml);
        let mut values = Vec::new();
        loop {
            match reader.read_event().expect("the report is well-formed XML") {
                Event::Start(tag) | Event::Empty(tag) => {
                    for attribute in tag.attributes() {
                        values.push(attribute.expect("an attribute parses").value.to_vec());
                    }
                }
                Event::Eof => return values,
                _ => {}
            }
        }
    }

    /// The names of the three elements are attribute values: a tab and a line feed are written as
    /// character references, which a parser reads back as the character (a literal one would be
    /// normalized to a space), a carriage return and every other control as its escape (a reference to a
    /// carriage return decodes to a raw one for every consumer), and no attribute holds a raw tab, line
    /// feed or carriage return, which the unescaped read-back cannot show and the written bytes do.
    ///
    /// Fails when an attribute carries the ESC byte, a raw tab, line feed or carriage return, a
    /// carriage return written as a reference, or a tab or line feed written as the two
    /// characters `\t`, `\n`.
    #[test]
    fn a_name_is_written_as_an_attribute_with_escaped_controls() {
        let xml = report_named(
            &format!("all{}[1m", esc()),
            "suite\tone",
            "case\ntwo\rthree\tfour",
            TestCaseStatus::Pass,
        );
        assert!(
            !has_a_raw_control(&xml) && !xml.contains('\t'),
            "no raw control in the report:\n{:?}",
            xml
        );
        assert!(
            raw_attribute_values(&xml)
                .iter()
                .all(|value| !value.iter().any(|b| matches!(b, b'\t' | b'\n' | b'\r'))),
            "no attribute holds a raw tab, line feed or carriage return:\n{:?}",
            xml
        );
        assert!(xml.contains("name=\"all\\u{1b}[1m\""), "{}", xml);
        assert!(xml.contains("name=\"suite&#9;one\""), "{}", xml);
        assert!(
            xml.contains("name=\"case&#10;two\\rthree&#9;four\""),
            "{}",
            xml
        );
        assert!(
            !xml.contains("&#13;"),
            "no reference to a carriage return, which every consumer decodes to a raw one:\n{}",
            xml
        );
        assert_eq!(
            vec!["case\ntwo\\rthree\tfour".to_string()],
            case_names(&xml),
            "a parser reads a tab and a line feed back as the characters they were, and a carriage return as its escape"
        );
    }

    /// A name reads back from the report as typed, except that a carriage return reads as its escape. A
    /// name that holds a tab and a name that holds a backslash and a `t` are two names; a carriage return
    /// and a backslash and an `r` read ALIKE (`a\rb`, the escape's two characters), the collision the
    /// design accepts, as it does for an ESC and the typed characters of its escape; a carriage return and
    /// line feed pair is written as the escape and a line feed, and a name with the characters XML needs
    /// escaped comes back as written. A backslash is written as it is, so a Windows path keeps its
    /// separators. The written bytes of each control are pinned beside the read-back, which does not
    /// normalize and so cannot show a raw control.
    ///
    /// Fails when the tab and the backslash and `t` read back alike, a backslash reads back
    /// doubled, a carriage return is written as a reference or raw, the pair is folded to a
    /// line feed, or the markup characters come back changed.
    #[test]
    fn a_tab_and_a_backslash_t_are_two_distinct_names() {
        let written = |name: &str| report_named("all", "suite", name, TestCaseStatus::Pass);
        let tab = case_names(&written("a\tb"));
        let slash = case_names(&written("a\\tb"));
        assert_eq!(vec!["a\tb".to_string()], tab);
        assert_eq!(vec!["a\\tb".to_string()], slash);
        assert_ne!(tab, slash, "the two names stay distinct");
        let carriage = case_names(&written("a\rb"));
        let backslash_r = case_names(&written("a\\rb"));
        assert_eq!(vec!["a\\rb".to_string()], carriage);
        assert_eq!(vec!["a\\rb".to_string()], backslash_r);
        assert_eq!(
            carriage, backslash_r,
            "a carriage return and a backslash and an `r` read alike: the accepted collision"
        );
        assert_eq!(
            vec!["a\\r\nb".to_string()],
            case_names(&written("a\r\nb")),
            "a carriage return and line feed pair reads back as the escape and a line feed"
        );
        for (name, bytes) in [
            ("a\tb", "name=\"a&#9;b\""),
            ("a\nb", "name=\"a&#10;b\""),
            ("a\rb", "name=\"a\\rb\""),
            ("a\r\nb", "name=\"a\\r&#10;b\""),
            ("a\\tb", "name=\"a\\tb\""),
        ] {
            let xml = written(name);
            assert!(
                xml.contains(bytes),
                "{:?} is written as {}:\n{}",
                name,
                bytes,
                xml
            );
            assert!(
                !xml.contains("&#13;"),
                "{:?}: no reference to a carriage return:\n{}",
                name,
                xml
            );
        }
        let windows = "templates\\a.yaml";
        assert_eq!(
            vec![windows.to_string()],
            case_names(&report_named("all", "suite", windows, TestCaseStatus::Pass)),
            "a backslash in a file name is kept as written"
        );
        let markup = "a&b<c>\"d'";
        assert_eq!(
            vec![markup.to_string()],
            case_names(&report_named("all", "suite", markup, TestCaseStatus::Pass)),
            "the markup characters survive"
        );
    }

    /// U+FFFE and U+FFFF, which XML 1.0 forbids and the JSON reader keeps, are written as their escapes
    /// in a text node and in an attribute value, so the report stays well-formed and a parser that rejects
    /// them reads it. A joiner and a bidirectional mark in a name are written as escapes too: a name is an
    /// identifier read against other names.
    ///
    /// Fails when the report holds either code point raw (a strict parser rejects it), or when the
    /// joiner or the mark is kept as typed in a name.
    #[test]
    fn the_two_noncharacters_xml_forbids_are_written_as_escapes() {
        let forbidden = ['\u{FFFE}', '\u{FFFF}'];
        let xml = report_named(
            "all",
            "suite",
            &format!("n{}{}x{}\u{200D}\u{200F}", forbidden[0], forbidden[1], 'y'),
            TestCaseStatus::Error {
                error: format!("bad {}{} text", forbidden[0], forbidden[1]),
            },
        );
        assert!(
            !xml.contains(forbidden[0]) && !xml.contains(forbidden[1]),
            "no forbidden code point in the report:\n{:?}",
            xml
        );
        assert_eq!("bad \\u{fffe}\\u{ffff} text", text_nodes(&xml));
        assert_eq!(
            vec!["n\\u{fffe}\\u{ffff}xy\\u{200d}\\u{200f}".to_string()],
            case_names(&xml)
        );
        assert_eq!(
            "\\u{fffe}\\u{ffff}",
            xml_text_with_escaped_controls("\u{FFFE}\u{FFFF}")
        );
    }
}
