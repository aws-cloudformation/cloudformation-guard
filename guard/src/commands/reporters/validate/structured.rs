use std::rc::Rc;

use crate::commands::reporters::validate::sarif::SarifReport;
use crate::commands::reporters::{JunitReporter, Notices};
use crate::commands::validate::{parse_rules, DataFile, OutputFormatType, RuleFileInfo};
use crate::commands::{ERROR_STATUS_CODE, FAILURE_STATUS_CODE};
use crate::rules;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{
    root_scope_for, simplified_json_from_root, FileReport, RuleFileError,
};
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::Status;
use crate::utils::writer::Writer;
use colored::Colorize;

pub(crate) trait StructuredReporter {
    fn report(&mut self) -> rules::Result<i32>;
}

pub struct StructuredEvaluator<'eval> {
    pub(crate) rule_info: &'eval [RuleFileInfo],
    pub(crate) input_params: Option<PathAwareValue>,
    pub(crate) data: Vec<DataFile>,
    pub(crate) output: OutputFormatType,
    pub(crate) writer: &'eval mut Writer,
    pub(crate) exit_code: i32,
}

impl<'eval> StructuredEvaluator<'eval> {
    pub(crate) fn evaluate(&mut self) -> rules::Result<i32> {
        // A rules file the parser rejects is dropped from `rules`, so no reporter ever sees it and
        // nothing it would have reported becomes a finding. That left every format emitting the
        // document a clean run emits: three empty verdict lists in json and yaml, `tests="0"
        // failures="0" errors="0"` in junit, an empty `results` array in sarif. Exit 5 and the
        // stderr text were the only signals, and the CI steps that consume these files -- a junit
        // test reporter, `upload-sarif` under `if: always()` -- run regardless of exit status. An
        // empty sarif `results` array does not read as "no news" either: uploading it resolves the
        // alerts the previous run raised, so a typo in a rules file reads as "all policies pass".
        //
        // Collecting the failures here is what lets each reporter say so in its own vocabulary.
        // The stderr write and the exit code are unchanged; this only adds to stdout.
        let mut rule_file_errors: Vec<RuleFileError> = vec![];

        let rules = self.rule_info.iter().try_fold(
            vec![],
            |mut rules,
             RuleFileInfo { file_name, content }|
             -> rules::Result<Vec<(RulesFile, &str)>> {
                match parse_rules(content, file_name) {
                    Err(e) => {
                        self.writer.write_err(format!(
                            "Parsing error handling rule file = {}, Error = {e}\n---",
                            file_name.underline()
                        ))?;
                        self.exit_code = ERROR_STATUS_CODE;
                        rule_file_errors.push(RuleFileError {
                            file_name: file_name.to_owned(),
                            error: e.to_string(),
                        });
                    }
                    Ok(Some(rule)) => rules.push((rule, file_name)),
                    Ok(None) => {}
                }
                Ok(rules)
            },
        )?;

        let merged_data = self.data.iter().fold(vec![], |mut res, file| {
            let each = match &self.input_params {
                Some(data) => data.clone().merge(file.path_value.clone()).unwrap(),
                None => file.path_value.clone(),
            };

            let merged_file_data = DataFile {
                path_value: each,
                name: file.name.to_owned(),
                content: String::default(),
            };

            res.push(merged_file_data);
            res
        });

        let mut reporter = match self.output {
            OutputFormatType::Junit => Box::new(JunitReporter {
                data: merged_data,
                rules,
                rule_file_errors: &rule_file_errors,
                writer: self.writer,
                exit_code: self.exit_code,
            }) as Box<dyn StructuredReporter>,
            OutputFormatType::JSON | OutputFormatType::YAML | OutputFormatType::Sarif => {
                Box::new(CommonStructuredReporter {
                    rules,
                    data: merged_data,
                    rule_file_errors: &rule_file_errors,
                    writer: self.writer,
                    exit_code: self.exit_code,
                    output: self.output,
                }) as Box<dyn StructuredReporter>
            }
            OutputFormatType::SingleLineSummary => unreachable!(),
        };

        reporter.report()
    }
}

struct CommonStructuredReporter<'reporter> {
    rules: Vec<(RulesFile<'reporter>, &'reporter str)>,
    data: Vec<DataFile>,
    rule_file_errors: &'reporter [RuleFileError],
    writer: &'reporter mut crate::utils::writer::Writer,
    exit_code: i32,
    output: OutputFormatType,
}

impl<'reporter> StructuredReporter for CommonStructuredReporter<'reporter> {
    fn report(&mut self) -> rules::Result<i32> {
        let mut records = vec![];
        let mut first_error = None;
        // Collected across the whole run and written once, below.
        //
        // One set for the document: one line per filter site and one per plain notice text across the
        // data files of one run, because a notice is aimed at the rule author and describes the rule,
        // not the data. The single-line path keeps the same two collapses across its data-file loop
        // (`validate.rs`, `evaluate_against_data_input`), writing beside each file's report only the
        // lines that file adds to the run's set. The two paths part on what the later files keep. Here
        // nothing: a second file whose verdict moved for the same reason shows that move with no notice
        // beside it, and the reader finds the once-written notice above; the document is one report for
        // the run, so which files hit a notice is not a question its reader puts to the notice list. The
        // single-line path, whose stream is read file by file, ends with a `NOTE:` trailer naming the
        // later files that drew a notice the run announced once. What both reject, N copies of one sentence
        // attached to nothing that distinguishes them, is a warning trained to be skipped.
        //
        // The set spans rules files too, not only data files, and that is what makes a notice count a
        // real signal on this path. The opposite reading -- that each rules file gets its own
        // `RootScope` and so its own `BTreeSet`, so two notices are written either way -- is only half
        // right, and this is where the halves are separated. Across rules files
        // it still holds for the single-line path, whose set is one per rules file. Within one rules
        // file it holds for neither path now; it did for the single-line path until that path took a
        // set across its data files. json, yaml and sarif share this set, and junit has one of its own
        // on the same footing in `xml.rs`. Two byte-identical notices dedupe in all four.
        //
        // Measured with only the validate-side locator returned to a basename, so that two rules files
        // sharing a name produce byte-identical notices:
        //
        //     single-line   2 notices, 1 distinct locator
        //     -o json       1 notice
        //     -o yaml       1 notice
        //     -o sarif      1 notice
        //     -o junit      1 notice
        //
        // against 2 notices and 2 distinct locators in all five once the locator is the path. So for
        // these four formats the count *was* a symptom, and the drain fixed one commit earlier was
        // silently dropping one of two files' notices until the locator followed it.
        //
        // Keyed by site as well as by text, for the reason given on `Notices`: a once-per-site
        // notice names the value it is about, so two data files whose matching resource has a different
        // logical id give one filter two texts, and a text-keyed set wrote two lines for it.
        let mut deprecations = Notices::new();
        for each in &self.data {
            let mut file_report: FileReport = FileReport {
                name: &each.name,
                rule_file_errors: self.rule_file_errors.to_vec(),
                ..Default::default()
            };

            for (rule, _) in &self.rules {
                let mut root_scope =
                    root_scope_for(rule, Rc::new(each.path_value.clone()), Some(&each.name));

                // Not `?`. By the time an error comes back the rules that *could* be evaluated have
                // their findings in the record, and returning here discarded the whole document: a JSON,
                // YAML or SARIF consumer got one error line for a file whose other rules had real
                // findings. The same defect as the single-line path had, in the path that machines read.
                //
                // The error is returned after the document is written, so the exit code still says the
                // ruleset is broken rather than the template being non-compliant.
                match eval_rules_file(rule, &mut root_scope, Some(&each.name)) {
                    Ok(Status::FAIL) => self.exit_code = FAILURE_STATUS_CODE,
                    Ok(_) => {}
                    Err(e) => {
                        if first_error.is_none() {
                            first_error = Some(e);
                        }
                    }
                }

                // Read before `reset_recorder` consumes the scope, which is the only window there is.
                //
                // This line was missing, and its absence had no signal: the scope was built, evaluated
                // and discarded, so every deprecation notice this run produced went nowhere. Exit code
                // and document were both correct, stderr was empty, and an empty stderr is also what a
                // run with nothing to warn about leaves -- so the mode a pipeline runs was the one mode
                // that never carried the warning written for the pipeline's author.
                deprecations.absorb_deprecations(&root_scope);
                deprecations.absorb_warnings(&root_scope);

                let root_record = root_scope.reset_recorder().extract();
                let report = simplified_json_from_root(&root_record)?;
                file_report.combine(report);
            }

            records.push(file_report);
        }

        // Before the document and on stderr, both for the reason `validate`'s single-line path gives:
        // stdout is what pipelines parse, and a notice about a future release is not part of this run's
        // result. Writing it into the report would change the document for every consumer in order to
        // announce something that has not happened yet.
        deprecations.write_to(self.writer)?;

        match self.output {
            OutputFormatType::YAML => serde_yaml::to_writer(&mut self.writer, &records)?,
            OutputFormatType::JSON => serde_json::to_writer_pretty(&mut self.writer, &records)?,
            OutputFormatType::Sarif => {
                let report = SarifReport::new(&records);
                serde_json::to_writer_pretty(&mut self.writer, &report)?
            }
            _ => unreachable!(),
        };

        match first_error {
            // Classified the way the single-line path classifies it, and for the same reason: a name
            // the rules file never declares, or an operation the rules file wrote against a value it
            // also wrote, is the author's mistake, not cfn-guard's. The document is already written
            // above, so this only decides the code.
            //
            // `-o junit` reached `ERROR_STATUS_CODE` for this input already, because `JunitReporter`
            // folds an eval error into the suite's `errors` total instead of returning `Err`. json,
            // yaml and sarif came through here and exited -1. So one binary gave two answers about one
            // rules file depending only on `-o`, and the format that disagreed with the other three
            // was the one that had been looked at.
            Some(e) if e.is_rules_file_mistake() => {
                self.writer
                    .write_err(format!("Error handling rule file, Error = {e}\n---"))?;

                Ok(ERROR_STATUS_CODE)
            }
            Some(e) => Err(e),
            None => Ok(self.exit_code),
        }
    }
}
