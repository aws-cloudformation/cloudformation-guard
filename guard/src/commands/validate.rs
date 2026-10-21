use std::cmp;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

use clap::{Args, ValueEnum};
use colored::*;
use enumflags2::BitFlags;
use serde::{Deserialize, Serialize};

use crate::commands::files::{alphabetical, iterate_over, last_modified, walk_dir};
use crate::commands::reporters::validate::structured::StructuredEvaluator;
use crate::commands::reporters::validate::summary_table::{self, SummaryType};
use crate::commands::reporters::validate::tf::TfAware;
use crate::commands::reporters::validate::{cfn, generic_summary};
use crate::commands::reporters::Notices;
use crate::commands::tracker::StatusContext;
use crate::commands::{
    Executable, ALPHABETICAL, DATA_FILE_SUPPORTED_EXTENSIONS, ERROR_STATUS_CODE,
    FAILURE_STATUS_CODE, INPUT_PARAMETERS, LAST_MODIFIED, PAYLOAD, PRINT_JSON, REQUIRED_FLAGS,
    RULES, RULE_FILE_SUPPORTED_EXTENSIONS, SHOW_SUMMARY, STRUCTURED, SUCCESS_STATUS_CODE, TYPE,
    VERBOSE,
};
use crate::rules::errors::{Error, InternalError};
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{root_scope_for, EventRecord};
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::{DuplicateKey, PathAwareValue};
use crate::rules::values::UnreadTag;
use crate::rules::{Result, Status};
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use wasm_bindgen::prelude::*;

#[derive(Eq, Clone, Debug, PartialEq)]
pub(crate) struct DataFile {
    pub(crate) content: String,
    pub(crate) path_value: PathAwareValue,
    pub(crate) name: String,
}

#[derive(Copy, Eq, Clone, Debug, PartialEq)]
pub(crate) enum Type {
    CFNTemplate,
    Generic,
}

impl From<&str> for Type {
    fn from(value: &str) -> Self {
        match value {
            "CFNTemplate" => Type::CFNTemplate,
            _ => Type::Generic,
        }
    }
}

#[wasm_bindgen]
#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Eq, Clone, Debug, PartialEq, ValueEnum, Serialize, Default, Deserialize)]
pub enum OutputFormatType {
    #[default]
    SingleLineSummary,
    JSON,
    YAML,
    Junit,
    Sarif,
}

#[wasm_bindgen]
#[derive(Copy, Eq, Clone, Debug, PartialEq, ValueEnum, Serialize, Default, Deserialize)]
pub enum ShowSummaryType {
    All,
    Pass,
    // Not the `--show-summary` default in effect, which depends on the output format: see
    // `default_show_summary`. The derive stays because the enum is wasm API. A plain comment, not a
    // doc comment: clap turns a variant's doc into help text for the value.
    #[default]
    Fail,
    Skip,
    None,
}

impl From<&str> for ShowSummaryType {
    fn from(value: &str) -> Self {
        match value {
            "all" => ShowSummaryType::All,
            "fail" => ShowSummaryType::Fail,
            "pass" => ShowSummaryType::Pass,
            "none" => ShowSummaryType::None,
            "skip" => ShowSummaryType::Skip,
            _ => unreachable!(),
        }
    }
}

impl OutputFormatType {
    /// Whether the format puts one machine-readable document on stdout, so that nothing else (a
    /// summary table, the verbose tree, the parse tree) may share it.
    pub(crate) fn is_structured(&self) -> bool {
        !matches!(self, Self::SingleLineSummary)
    }
}

/// The `--show-summary` default for an output format: `[Fail]` for the single-line summary, `[None]`
/// for a machine-readable format, which has nowhere to put a summary table beside its document.
///
/// This is the one statement of the unset-summary rule; the other places that touch it point here.
///
/// - `Validate::show_summary` is an `Option`, `None` when `-S` was not given and when a
///   `ValidateBuilder` caller never set one, and `Validate::show_summary_in_force` is the only place
///   the default is applied, so a `Validate` from either entry point compares equal and resolves the
///   same. An explicit empty list is `Some(vec![])`, a setting of its own (no table), not an absence.
/// - clap carries no default for `-S`: a `default_value` would be one value for every format, and a
///   `default_value_ifs` list would be a second statement of which formats are machine-readable,
///   spelled as literal names that `is_structured` does not read, so a format added to the enum
///   would default one way on the command line and another in the builder. The help text names
///   both defaults itself, since clap prints no `[default: ...]` annotation for it.
/// - The default is not what `ShowSummaryType::default()` answers: that derive is wasm API and gives
///   `Fail`, which is right only for the single-line summary.
/// - What a set list means is `summary_flags`'s business: `None` clears whatever precedes it, so
///   `[Fail, None]` and `[]` select nothing and are allowed beside a machine-readable format, as
///   `-S fail,none` is; `validate_construct` reads the list through the same fold before deciding.
pub(crate) fn default_show_summary(output_format: OutputFormatType) -> Vec<ShowSummaryType> {
    if output_format.is_structured() {
        vec![ShowSummaryType::None]
    } else {
        vec![ShowSummaryType::Fail]
    }
}

/// Folds a `--show-summary` list into the summary flags the reporters read.
///
/// `None` clears everything selected so far, so `fail,none` is the same as `none`, and `All` selects
/// the three kinds at once. `validate_construct` reads the list through this before deciding whether
/// it is allowed, and the reporters read it through this to know what to print, so the two cannot
/// disagree about what a list means; a check that reasoned about the list itself would reject
/// `[Fail, None]` beside a machine-readable format while the command line accepts `-S fail,none`.
fn summary_flags(show_summary: &[ShowSummaryType]) -> BitFlags<SummaryType, u8> {
    show_summary.iter().fold(BitFlags::empty(), |mut st, elem| {
        match elem {
            ShowSummaryType::Pass => st.insert(SummaryType::PASS),
            ShowSummaryType::Fail => st.insert(SummaryType::FAIL),
            ShowSummaryType::Skip => st.insert(SummaryType::SKIP),
            ShowSummaryType::None => return BitFlags::empty(),
            ShowSummaryType::All => {
                st.insert(SummaryType::PASS | SummaryType::FAIL | SummaryType::SKIP)
            }
        };
        st
    })
}

impl From<&str> for OutputFormatType {
    fn from(value: &str) -> Self {
        match value {
            "single-line-summary" => OutputFormatType::SingleLineSummary,
            "json" => OutputFormatType::JSON,
            "junit" => OutputFormatType::Junit,
            "sarif" => OutputFormatType::Sarif,
            _ => OutputFormatType::YAML,
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) trait Reporter: Debug {
    fn report(
        &self,
        writer: &mut dyn Write,
        status: Option<Status>,
        failed_rules: &[&StatusContext],
        passed_or_skipped: &[&StatusContext],
        longest_rule_name: usize,
        rules_file: &str,
        data_file: &str,
        data: &Traversal<'_>,
        output_type: OutputFormatType,
    ) -> Result<()>;

    fn report_eval<'value>(
        &self,
        _write: &mut dyn Write,
        _status: Status,
        _root_record: &EventRecord<'value>,
        _rules_file: &str,
        _data_file: &str,
        _data_file_bytes: &str,
        _data: &Traversal<'value>,
        _output_type: OutputFormatType,
    ) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Args)]
#[clap(group=clap::ArgGroup::new(REQUIRED_FLAGS).args([RULES.0, PAYLOAD.0]).required(true))]
#[clap(about=ABOUT)]
#[clap(arg_required_else_help = true)]
/// .
/// The Validate command evaluates rules against data files to determine success or failure
// Field notes below are `//` comments, not `///`: `help=` carries the text users see, and a doc
// comment on a clap-derived field becomes help text the moment `help=` is dropped, so a stale one
// would reach users. The `help=` constants at the end of this file are the only user-facing words.
pub struct Validate {
    // `num_args=1..`, not `0..`. `--rules` is a member of the required `REQUIRED_FLAGS` group, so a
    // bare `--rules` with no values *satisfied* that group while leaving `self.rules` empty, and
    // `execute` then took neither branch and hit its `unreachable!()` -- exit 101 on
    // `cfn-guard validate --rules`. `num_args=0..` had widened what the argument can hold without the
    // `else` arm being widened to match.
    //
    // One value is also the smallest number that can mean anything: there is no reading of `--rules`
    // with nothing after it. `ValidateBuilder::try_build` already rejects the same state for library
    // callers, so this makes the two agree rather than inventing a rule.
    //
    // `--data` keeps `num_args=0..` on purpose: an empty `data` is a supported state that means "read
    // the data from stdin", which is what an absent `--data` also means.
    #[arg(short, long, help=RULES_HELP, num_args=1.., conflicts_with=PAYLOAD.0)]
    // Paths to rules files, or directories of them; in a directory only .guard and .ruleset files
    // are read. Conflicts with `payload`.
    pub(crate) rules: Vec<String>,
    #[arg(short, long, help=DATA_HELP, num_args=0.., conflicts_with=PAYLOAD.0)]
    // Paths to data files, or directories of them; in a directory only JSON and YAML files are
    // read. Conflicts with `payload`.
    pub(crate) data: Vec<String>,
    // Declared from the public constant, so a command line built from `INPUT_PARAMETERS.0` is the
    // flag clap accepts. `--input-parameters` is a hidden alias: it was the spelling the
    // documentation carried for years while the flag clap accepted was `--input-params`, so a script
    // written from the documentation exited 2; the alias makes such a script run.
    #[arg(short=INPUT_PARAMETERS.1, long=INPUT_PARAMETERS.0, alias="input-parameters", help=INPUT_PARAMETERS_HELP, num_args=0..)]
    // Paths to JSON or YAML files, or directories of them, merged into one context that is merged
    // into each data file before the rules run.
    pub(crate) input_params: Vec<String>,
    #[arg(name=TYPE.0, short, long, help=TEMPLATE_TYPE_HELP, value_parser=TEMPLATE_TYPE)]
    #[deprecated(since = "3.0.0", note = "this field does not get evaluated")]
    pub(crate) template_type: Option<String>,
    #[arg(short, long, help=OUTPUT_FORMAT_HELP, value_enum, default_value_t=OutputFormatType::SingleLineSummary)]
    // The report's format. Default is single-line-summary; junit and sarif also require
    // `structured`.
    pub(crate) output_format: OutputFormatType,
    // Which rules the summary table lists (see SHOW_SUMMARY_HELP). `None` when `-S` was not given;
    // the default, and why clap declares none here, are on `default_show_summary`.
    #[arg(short=SHOW_SUMMARY.1, long, help=SHOW_SUMMARY_HELP, value_enum, value_delimiter=',')]
    pub(crate) show_summary: Option<Vec<ShowSummaryType>>,
    #[arg(short, long, help=ALPHABETICAL_HELP, conflicts_with=LAST_MODIFIED.0)]
    // Validate the files of a directory in alphabetical order. Conflicts with `last_modified`.
    pub(crate) alphabetical: bool,
    #[arg(name="last-modified", short=LAST_MODIFIED.1, long, help=LAST_MODIFIED_HELP, conflicts_with=ALPHABETICAL.0)]
    // Validate the files of a directory by last-modified time. Conflicts with `alphabetical`.
    pub(crate) last_modified: bool,
    #[arg(short, long, help=VERBOSE_HELP)]
    // Output verbose logging. Conflicts with `structured` and with a machine-readable output format,
    // because the verbose tree and the report would share stdout. Default is false.
    pub(crate) verbose: bool,
    #[arg(name="print-json", short=PRINT_JSON.1, long, help=PRINT_JSON_HELP)]
    // Print the parse tree in a json format, for more detail on how the clauses were evaluated.
    // Conflicts with `structured` and with a machine-readable output format, because the parse tree
    // and the report would share stdout. Default is false.
    pub(crate) print_json: bool,
    #[arg(short=PAYLOAD.1, long, help=PAYLOAD_HELP)]
    // Rules and data arrive on the reader as one JSON document (see PAYLOAD_SCHEMA). Conflicts with
    // `rules` and `data`. Default is false.
    pub(crate) payload: bool,
    #[arg(short=STRUCTURED.1, long, help=STRUCTURED_HELP, conflicts_with_all=vec![PRINT_JSON.0, VERBOSE.0])]
    // Print one structured JSON, YAML, JUnit or SARIF document; required for junit and sarif.
    // Conflicts with `verbose`, `print_json`, the single-line-summary format, and a `show_summary`
    // other than none. Default is false.
    pub(crate) structured: bool,
}

impl Validate {
    /// The summary selection in force: what the caller set, or `default_show_summary` for the output
    /// format when nothing was set. The only place the default is applied; the rule is documented
    /// there.
    pub(crate) fn show_summary_in_force(&self) -> Vec<ShowSummaryType> {
        self.show_summary
            .clone()
            .unwrap_or_else(|| default_show_summary(self.output_format))
    }

    /// A machine-readable `--output-format` means stdout carries exactly one document, and nothing
    /// else.
    ///
    /// One rule, replacing two half-rules that between them let stdout be corrupted and made `-z`
    /// unusable on its own:
    ///
    /// - The summary table was suppressed only when `--structured` was passed, not when the output
    ///   format was machine-readable. `--show-summary` defaults to `fail`, and the table goes to the
    ///   same stdout the document does, so `validate ... -o json` emitted clean JSON while everything
    ///   passed and a table welded to the front of the JSON the moment a rule failed -- that is,
    ///   exactly when a consumer needs to read it. `-o json > out.json` produced a valid file or an
    ///   invalid one depending on the verdict.
    /// - The check keyed on `self.structured` fired against `--show-summary`'s own *default*, so every
    ///   `-z` invocation that did not spell out `-S none` exited with a complaint about a flag the
    ///   caller never passed. The `-z` help text lists `show-summary: all/fail/pass/skip` among its
    ///   conflicts without noting that `fail` is the default, so following the help produced the
    ///   error.
    ///
    /// Keying both on the format rather than on the flag fixes the pair, because `--structured`
    /// already requires a machine-readable format (the arm below rejects `-z -o single-line-summary`),
    /// so the format is the more general condition and subsumes the flag.
    ///
    /// `--verbose` and `--print-json` are rejected for the same reason and are not merely suppressed:
    /// both append a second document to stdout after the first, unseparated -- `-o json -v` put the
    /// closing brace and the tree's first line on one line. `test` already refuses
    /// "an output_type of JSON, YAML, or JUnit while the verbose flag is set", clap already refuses
    /// `-z -v` and `-z -p`, and `ValidateBuilder::try_build` asks this function. This is the fourth
    /// statement of a rule the codebase had already made three times, applied to the case that was
    /// missed.
    ///
    /// `pub(crate)` so that `ValidateBuilder::try_build` calls this rather than keeping a copy of
    /// it: one rule with one set of messages, so that for a conflict clap does not reject first a
    /// library caller and a command-line caller are told the same thing. It reads `show_summary`
    /// itself rather than taking flags from the caller, so no caller can pass it a summary setting
    /// other than the command's own.
    pub(crate) fn validate_construct(&self) -> crate::rules::Result<()> {
        let summary_type = summary_flags(&self.show_summary_in_force());

        if self.output_format.is_structured() && !summary_type.is_empty() {
            return Err(Error::IllegalArguments(format!(
                "Cannot provide a summary-type other than `none` when the output format is {:?}, \
                 because the summary table and the report share stdout",
                self.output_format
            )));
        } else if self.output_format.is_structured() && self.verbose {
            return Err(Error::IllegalArguments(format!(
                "Cannot provide an output format of {:?} while the verbose flag is set, \
                 because the verbose tree and the report share stdout",
                self.output_format
            )));
        } else if self.output_format.is_structured() && self.print_json {
            return Err(Error::IllegalArguments(format!(
                "Cannot provide an output format of {:?} while the print-json flag is set, \
                 because the parse tree and the report share stdout",
                self.output_format
            )));
        } else if self.structured
            && matches!(self.output_format, OutputFormatType::SingleLineSummary)
        {
            return Err(Error::IllegalArguments(String::from(
                "single-line-summary is not able to be used when the `structured` flag is present",
            )));
        }

        if matches!(self.output_format, OutputFormatType::Junit) && !self.structured {
            return Err(Error::IllegalArguments(String::from(
                "the structured flag must be set when output is set to junit",
            )));
        }

        if matches!(self.output_format, OutputFormatType::Sarif) && !self.structured {
            return Err(Error::IllegalArguments(String::from(
                "the structured flag must be set when output is set to sarif",
            )));
        }

        Ok(())
    }

    fn get_comparator(&self) -> fn(&walkdir::DirEntry, &walkdir::DirEntry) -> cmp::Ordering {
        match self.last_modified {
            true => last_modified,
            false => alphabetical,
        }
    }
}

impl Executable for Validate {
    /// .
    /// evaluates the given rules, against the given data files.
    ///
    /// This function will return an error if
    /// - conflicting attributes have been set
    /// - any of the specified paths do not exist
    /// - parse errors occur in the rule file
    /// - illegal json or yaml syntax present in any of the data/input parameter files
    /// - both rules is empty, and payload is false
    fn execute(&self, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        match self.evaluate(writer, reader) {
            // Input cfn-guard cannot read is the user's mistake, not cfn-guard breaking, and the exit
            // code has to say which. An `Err` escaping here reaches `main`'s catch-all, which prints
            // "Error occurred" and exits -1 -- the code `guard/tests/utils.rs` names
            // `INTERNAL_FAILURE`. So a template with an unquoted `~` key, an empty data file, or a
            // file that is not YAML all reported that cfn-guard had broken.
            //
            // `ERROR_STATUS_CODE` is 5, the code this repository gives a ruleset it cannot use, and
            // rules-file mistakes report it for the same reason: 5 is not 19, so a CI gate still
            // distinguishes it from a violation, and unlike -1 it does not additionally claim the tool
            // is at fault.
            //
            // `ParseError` is the discriminator because every one of its ~20 producers is about the
            // user's input -- the rules parser, the libyaml loader, the test-spec readers, the payload
            // deserializer -- and none is an internal failure. `guard-ffi`'s error table had already
            // reached the same judgement, mapping `ParseError` to its code 5.
            //
            // A *missing* file keeps -1 deliberately. `File::open` returns `IoError`, not
            // `ParseError`, so it is untouched here, and that is the same line the parse-tree commit
            // drew: validate, test and parse-tree already agree on -1 for a path that does not exist.
            Err(e @ Error::ParseError(..)) => {
                // Reported here rather than left to `main`, because once this function has decided the
                // failure is not internal, "Error occurred" no longer describes it.
                writer.write_err(format!("{e}"))?;

                Ok(ERROR_STATUS_CODE)
            }
            outcome => outcome,
        }
    }
}

impl Validate {
    #[allow(deprecated)]
    fn evaluate(&self, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        self.validate_construct()?;

        let summary_type = summary_flags(&self.show_summary_in_force());

        let cmp = self.get_comparator();

        let data_files = match self.data.is_empty() {
            false => {
                let mut streams = Vec::new();
                let mut skipped = PassedOver::new();

                for file_or_dir in &self.data {
                    validate_path(file_or_dir)?;
                    let base = resolve_path(file_or_dir)?;

                    // A file the user named is read whatever it is called. The extension list is
                    // how a directory walk decides which of the files it found look like data, and
                    // an argument naming one file is not a discovery problem -- `--data` documents
                    // the filter as applying to directory arguments, and the `--rules` handling
                    // below already draws this distinction. Filtering here dropped the file, left
                    // nothing to evaluate, and reported PASS.
                    if base.is_file() {
                        let name = canonical_name(&base)?;
                        streams.push(read_data_file(&base, name, writer)?);
                        skipped.found();
                        continue;
                    }

                    for file in walk_dir(base, cmp) {
                        if file.path().is_file() {
                            let name = canonical_name(file.path())?;
                            if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS) {
                                streams.push(read_data_file(file.path(), name, writer)?);
                                skipped.found();
                            } else {
                                skipped.skip(name);
                            }
                        }
                    }
                }

                if streams.is_empty() {
                    report_no_data_evaluated(writer, skipped.names())?;
                }

                streams
            }
            true => {
                if !self.rules.is_empty() {
                    let mut content = String::new();
                    reader.read_to_string(&mut content)?;

                    let data_file = build_data_file(content, "STDIN".to_string(), writer)?;

                    vec![data_file]
                } else {
                    vec![]
                } // expect Payload, since rules aren't specified
            }
        };

        let extra_data = match self.input_params.is_empty() {
            false => {
                let mut primary_path_value: Option<PathAwareValue> = None;

                for file_or_dir in &self.input_params {
                    validate_path(file_or_dir)?;
                    let base = resolve_path(file_or_dir)?;

                    // Named explicitly, read whatever the extension, for the reason given for
                    // `--data` above. `--input-params` documents the filter as applying to
                    // directory arguments too, and a parameter file dropped by it changes what
                    // every rule sees without saying so.
                    let files: Vec<PathBuf> = if base.is_file() {
                        vec![base]
                    } else {
                        walk_dir(base, cmp)
                            .filter(|file| file.path().is_file())
                            .map(|file| file.path().to_path_buf())
                            .filter(|path| {
                                has_a_supported_extension(
                                    &file_name_of(path),
                                    &DATA_FILE_SUPPORTED_EXTENSIONS,
                                )
                            })
                            .collect()
                    };

                    for path in files {
                        let DataFile { path_value, .. } =
                            read_data_file(&path, file_name_of(&path), writer)?;

                        primary_path_value = match primary_path_value {
                            Some(current) => Some(current.merge(path_value)?),
                            None => Some(path_value),
                        };
                    }
                }
                primary_path_value
            }
            true => None,
        };

        let mut exit_code = SUCCESS_STATUS_CODE;

        let data_type = self
            .template_type
            .as_ref()
            .map_or(Type::Generic, |t| Type::from(t.as_str()));

        let cmp = if self.last_modified {
            last_modified
        } else {
            alphabetical
        };

        if !self.rules.is_empty() {
            let mut rules = Vec::new();
            let mut skipped = PassedOver::new();

            for file_or_dir in &self.rules {
                validate_path(file_or_dir)?;
                let base = resolve_path(file_or_dir)?;

                if base.is_file() {
                    rules.push(base.clone());
                    skipped.found();
                } else {
                    for entry in walk_dir(base, cmp) {
                        if entry.path().is_file() {
                            let name = file_name_of(entry.path());
                            if has_a_supported_extension(&name, &RULE_FILE_SUPPORTED_EXTENSIONS) {
                                rules.push(entry.path().to_path_buf());
                                skipped.found();
                            } else {
                                skipped.skip(name);
                            }
                        }
                    }
                }
            }

            // The counterpart of `report_no_data_evaluated`, which the `--data` side has had and this
            // side has not. A `--rules` directory holding no `.guard` or `.ruleset` file left `rules`
            // empty, the loop below ran zero times, and the run exited 0 having printed nothing --
            // indistinguishable from a run in which every rule passed. That is a green build for a
            // policy nobody applied, which is worse on this side than on the data side: the data side
            // at least named the files its walk passed over.
            if rules.is_empty() {
                report_no_rules_evaluated(writer, skipped.names())?;
            }

            exit_code = match self.structured {
                true => {
                    let rule_info = get_rule_info(&rules, writer)?;
                    let mut evaluator = StructuredEvaluator {
                        rule_info: &rule_info,
                        input_params: extra_data,
                        data: data_files,
                        output: self.output_format,
                        writer,
                        exit_code,
                    };
                    evaluator.evaluate()?
                }

                false => {
                    for each_file_content in iterate_over(&rules, |content, file| {
                        Ok(RuleFileInfo {
                            content,
                            file_name: rules_file_locator(file),
                        })
                    }) {
                        match each_file_content {
                            Err(e) => {
                                writer.write_err(format!("Unable read content from file {e}"))?
                            }
                            Ok(rule) => {
                                let status = evaluate_rule(
                                    data_type,
                                    self.output_format,
                                    &extra_data,
                                    &data_files,
                                    rule,
                                    self.verbose,
                                    self.print_json,
                                    summary_type,
                                    writer,
                                )?;

                                exit_code = more_severe(exit_code, status);
                            }
                        }
                    }
                    exit_code
                }
            };
        } else if self.payload {
            let mut context = String::new();
            reader.read_to_string(&mut context)?;
            let payload = deserialize_payload(&context)?;

            let data_collection = payload.list_of_data.iter().enumerate().try_fold(
                vec![],
                |mut data_collection, (i, data)| -> Result<Vec<DataFile>> {
                    let content = data.to_string();
                    let name = format!("DATA_STDIN[{}]", i + 1);
                    let data_file = build_data_file(content, name, writer)?;

                    data_collection.push(data_file);

                    Ok(data_collection)
                },
            )?;

            let rule_info = payload
                .list_of_rules
                .iter()
                .enumerate()
                .map(|(i, rules)| RuleFileInfo {
                    content: rules.to_string(),
                    file_name: format!("RULES_STDIN[{}]", i + 1),
                })
                .collect::<Vec<_>>();

            // The payload branch had no equivalent of the two warnings above, which are reached only
            // from the `--data` and `--rules` branches. A payload whose `rules` or `data` list was
            // empty parsed cleanly, evaluated nothing, printed nothing and exited 0 -- the same
            // false green, arrived at through the one input that is most likely to be machine-built
            // and so least likely to be eyeballed.
            if rule_info.is_empty() {
                report_no_rules_evaluated(writer, &[])?;
            }

            if data_collection.is_empty() {
                report_no_data_evaluated(writer, &[])?;
            }

            exit_code = match self.structured {
                true => {
                    let mut evaluator = StructuredEvaluator {
                        rule_info: &rule_info,
                        input_params: extra_data,
                        data: data_collection,
                        output: self.output_format,
                        writer,
                        exit_code,
                    };
                    evaluator.evaluate()?
                }
                false => {
                    for rule in rule_info {
                        // `&extra_data`, not `&None`. The structured branch above merges
                        // `--input-params` into every payload document; this one discarded them,
                        // so `validate -P -i params.yaml` gave opposite verdicts depending on whether
                        // `-z` was passed -- PASS structured, FAIL not -- with nothing saying a file
                        // the caller named had not been read.
                        //
                        // Merging is the side that matches what `--input-params` documents: the
                        // parameter files "get merged and this combined context is again merged with
                        // each file passed as an argument for `data`". Nothing in that says the merge
                        // is conditional on the reporter.
                        //
                        // Rejecting `-P` with `-i` was the alternative, by giving `--input-params`
                        // the `conflicts_with=PAYLOAD` that `--rules` and `--data` carry. It was not
                        // taken because the structured path makes the combination work today, so
                        // banning it would break a caller to fix a caller that is already served.
                        let status = evaluate_rule(
                            data_type,
                            self.output_format,
                            &extra_data,
                            &data_collection,
                            rule,
                            self.verbose,
                            self.print_json,
                            summary_type,
                            writer,
                        )?;

                        exit_code = more_severe(exit_code, status);
                    }
                    exit_code
                }
            };
        } else {
            // Genuinely unreachable, and by construction rather than by hope. Two enforcement points
            // stand between a caller and this arm, and both are needed because there are two ways in:
            //
            // - CLI: the `REQUIRED_FLAGS` group (`--rules` or `--payload`) is `required(true)`, and
            //   `--rules` takes `num_args=1..`, so `self.rules` cannot be empty while `--payload` is
            //   absent. Widening either back would make this a panic again -- it was one, at exit 101,
            //   while `--rules` took `num_args=0..`.
            // - Library: `ValidateBuilder::try_build` rejects `!payload && rules.is_empty()`.
            unreachable!(
                "validate requires --rules with at least one value or --payload; \
                 the clap argument group and ValidateBuilder::try_build both enforce it"
            )
        }

        Ok(exit_code)
    }
}

#[derive(Deserialize, Debug)]
pub(crate) struct Payload {
    #[serde(rename = "rules")]
    list_of_rules: Vec<String>,
    #[serde(rename = "data")]
    list_of_data: Vec<String>,
}

const ABOUT: &str = r#"Evaluates rules against the data files to determine success or failure.
You can point rules flag to a rules directory and point data flag to a data directory.
When pointed to a directory it will read all rules in the directory file and evaluate
them against the data files found in the directory. The command can also point to a
single file and it would work as well.
Note - When pointing the command to a directory, the directory may not contain a mix of
rules and data files. The directory being pointed to must contain only data files,
or rules files.
"#;

// const SHOW_SUMMARY_VALUE_TYPE: [&str; 5] = ["none", "all", "pass", "fail", "skip"];
const TEMPLATE_TYPE: [&str; 1] = ["CFNTemplate"];
const RULES_HELP: &str = "Provide a rules file or a directory of rules files. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --rules rule1.guard --rules ./rules-dir1 --rules rule2.guard\
                          \nFor directory arguments such as `rules-dir1` above, scanning is only supported for files with following extensions: .guard, .ruleset";
const DATA_HELP: &str = "Provide a data file or directory of data files in JSON or YAML. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --data template1.yaml --data ./data-dir1 --data template2.yaml\
                          \nFor directory arguments such as `data-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template";
const INPUT_PARAMETERS_HELP: &str = "Provide a parameter file or directory of parameter files in JSON or YAML that specifies any additional parameters to use along with data files to be used as a combined context. \
                           All the parameter files passed as input get merged and this combined context is again merged with each file passed as an argument for `data`. Due to this, every file is \
                           expected to contain mutually exclusive properties, without any overlap. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --input-params param1.yaml --input-params ./param-dir1 --input-params param2.yaml\
                          \nFor directory arguments such as `param-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template";
const TEMPLATE_TYPE_HELP: &str =
    "Specify the type of data file used for improved messaging - ex: CFNTemplate";
pub(crate) const OUTPUT_FORMAT_HELP: &str =
    "Specify the format in which the output should be displayed";
/// Names both defaults itself, because the argument declares none to clap (see
/// `default_show_summary`) and so carries no `[default: ...]` annotation. The list of machine-readable
/// formats is a literal, held to `OutputFormatType::is_structured` by `show_summary_help_tests`.
const SHOW_SUMMARY_HELP: &str = "Controls if the summary table needs to be displayed. The default is fail, or none when --output-format is json, yaml, junit or sarif, because the summary table and the report share stdout. The list is applied left to right and none clears the kinds listed before it, so fail,none means none. --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)";

/// Holds `SHOW_SUMMARY_HELP` to the code it describes.
#[cfg(test)]
mod show_summary_help_tests {
    use super::OutputFormatType;
    use crate::commands::CfnGuard;
    use clap::{CommandFactory, ValueEnum};

    /// The `-S` entry of the rendered `validate --help`, joined into one line.
    fn show_summary_entry() -> String {
        let error = CfnGuard::command()
            .term_width(100)
            .try_get_matches_from(["cfn-guard", "validate", "--help"])
            .expect_err("--help must stop parsing and render the help");
        let help = error.render().to_string();
        let mut lines = help.lines();
        lines
            .by_ref()
            .find(|line| line.trim_start().starts_with("-S, --show-summary"))
            .expect("the validate help has a -S entry");
        lines
            .take_while(|line| !line.trim_start().starts_with('-'))
            .map(str::trim)
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// The entry's list of machine-readable formats is the set `OutputFormatType::is_structured`
    /// answers, no more and no less.
    ///
    /// The help text is a literal (clap's `help=` wants a `&'static str`, and assembling one at run
    /// time buys nothing over this check), so this is what keeps it in step: a format added to the
    /// enum shows up in `value_variants()` and fails here until the sentence names it; a format
    /// that stops being machine-readable fails here until the sentence drops it. Only the `-S` entry
    /// is read, not the whole help, where `-o` lists every format, and only whole tokens count, so
    /// a format name inside another word ("json" inside "jsonl", say) is not a mention.
    #[test]
    fn names_exactly_the_machine_readable_formats() {
        let entry = show_summary_entry();
        let tokens: Vec<&str> = entry
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '-')
            .filter(|token| !token.is_empty())
            .collect();

        for format in OutputFormatType::value_variants() {
            let name = format
                .to_possible_value()
                .expect("every output format is a command-line value")
                .get_name()
                .to_owned();
            assert_eq!(
                format.is_structured(),
                tokens.contains(&name.as_str()),
                "the -S help must name `{}` exactly when it is machine-readable:\n{}",
                name,
                entry
            );
        }
    }

    /// The entry does not call one kind the default unconditionally.
    ///
    /// "(default)" is how clap's own default annotation puts it, and a reader who spells that default
    /// out beside `-o json` gets exit 2 (measured with the release binary): the default is `none` for
    /// a machine-readable format, so no single kind may be marked as the default.
    #[test]
    fn marks_no_kind_as_the_unconditional_default() {
        let entry = show_summary_entry();
        assert!(
            !entry.contains("(default)"),
            "the -S help must not call one kind the default unconditionally:\n{}",
            entry
        );
    }
}

const ALPHABETICAL_HELP: &str = "Validate files in a directory ordered alphabetically";
const LAST_MODIFIED_HELP: &str = "Validate files in a directory ordered by last modified times";
const VERBOSE_HELP: &str = "Verbose logging";
const PRINT_JSON_HELP: &str = "Print the parse tree in a json format. This can be used to get more details on how the clauses were evaluated";
/// The shape `--payload` expects, named in both the help text and the parse error, from here, so the
/// two cannot describe different shapes.
const PAYLOAD_SCHEMA: &str =
    "{\"rules\":[\"<rules 1>\", \"<rules 2>\", ...], \"data\":[\"<data 1>\", \"<data 2>\", ...]}";
const PAYLOAD_HELP: &str = "Provide rules and data in the following JSON format via STDIN,\n{\"rules\":[\"<rules 1>\", \"<rules 2>\", ...], \"data\":[\"<data 1>\", \"<data 2>\", ...]}, where,\n- \"rules\" takes a list of string \
                version of rules files as its value and\n- \"data\" takes a list of string version of data files as it value.\nWhen --payload is specified --rules and --data cannot be specified.";
const STRUCTURED_HELP: &str = "Print out a list of structured and valid JSON/YAML. This argument conflicts with the following arguments: \nverbose \n print-json \n show-summary: all/fail/pass/skip \noutput-format: single-line-summary";

/// Fold one rules file's exit code into the code for the run so far, keeping the more severe of the
/// two.
///
/// `ERROR_STATUS_CODE` outranks `FAILURE_STATUS_CODE`: a ruleset that could not be evaluated is a
/// different and worse answer than a template that failed a rule which *was* evaluated, and a
/// consumer that treats the two alike will read a broken ruleset as a policy violation it can waive.
/// `SUCCESS_STATUS_CODE` never lowers a code already set.
///
/// Saying this out loud became necessary when an undeclared name stopped returning `Err`. While it
/// did, the first unevaluatable file ended the whole run, so no later file could overwrite its code
/// and `exit_code = status` was sufficient. Now that such a file yields a code and the run continues
/// to the remaining files, a later `FAILURE_STATUS_CODE` would have silently replaced it.
///
/// `JunitReporter::update_exit_code` applies the same rule; it delegates here so the two cannot drift.
pub(crate) fn more_severe(current: i32, candidate: i32) -> i32 {
    if candidate == ERROR_STATUS_CODE
        || (candidate == FAILURE_STATUS_CODE && current != ERROR_STATUS_CODE)
    {
        candidate
    } else {
        current
    }
}

#[allow(clippy::too_many_arguments)]
fn evaluate_rule(
    data_type: Type,
    output: OutputFormatType,
    extra_data: &Option<PathAwareValue>,
    data_files: &Vec<DataFile>,
    rule: RuleFileInfo,
    verbose: bool,
    print_json: bool,
    summary_type: BitFlags<SummaryType>,
    writer: &mut Writer,
) -> Result<i32> {
    let RuleFileInfo { content, file_name } = &rule;
    match parse_rules(content, file_name) {
        Err(e) => {
            writer.write_err(format!(
                "Parsing error handling rule file = {}, Error = {e}\n---",
                file_name.underline(),
            ))?;

            return Ok(ERROR_STATUS_CODE);
        }

        Ok(Some(rule)) => {
            let evaluated = evaluate_against_data_input(
                data_type,
                output,
                extra_data,
                data_files,
                &rule,
                file_name,
                verbose,
                print_json,
                summary_type,
                writer,
            );

            let status = match evaluated {
                Ok(status) => status,
                // A rules file naming something it never declares -- a variable used without a `let`,
                // most often -- is the author's mistake, and `ERROR_STATUS_CODE` is already what this
                // function returns for the sibling case of a file the parser rejects, a few lines up.
                // `?` here instead carried the error to `main` and exited -1, so forgetting a `let`
                // reported that cfn-guard had broken. Forgetting a `let` is a common mistake, and the
                // message does not name the variable as the thing to fix, so the exit code was the only
                // signal and it pointed at the wrong party.
                //
                // The same holds for an operation written in the rules file that can never succeed on
                // the value written beside it (`let numeric = 5` with `%numeric empty`, `parse_int("abc")`,
                // a query shape interpolation does not support): `Error::is_rules_file_mistake` names
                // the variants, and `guard/README.md` documents 5 as "your rules need fixing, not your
                // template".
                //
                // Whatever the other rules found is already on stdout: `evaluate_against_data_input`
                // reports before propagating, which is deliberate and explained there.
                Err(e) if e.is_rules_file_mistake() => {
                    writer.write_err(format!(
                        "Error handling rule file = {}, Error = {e}\n---",
                        file_name.underline(),
                    ))?;

                    return Ok(ERROR_STATUS_CODE);
                }
                Err(e) => return Err(e),
            };

            if status == Status::FAIL {
                return Ok(FAILURE_STATUS_CODE);
            }
        }
        Ok(None) => return Ok(SUCCESS_STATUS_CODE),
    }

    Ok(SUCCESS_STATUS_CODE)
}

pub(crate) fn validate_path(base: &str) -> Result<()> {
    #[cfg(target_arch = "wasm32")]
    {
        path_exists(base).map_err(Error::from).and_then(|exists| {
            if exists {
                Ok(())
            } else {
                Err(Error::FileNotFoundError(base.to_string()))
            }
        })
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        if Path::new(base).exists() {
            Ok(())
        } else {
            Err(Error::FileNotFoundError(base.to_string()))
        }
    }
}

#[wasm_bindgen]
extern "C" {
    type Buffer;
}

#[wasm_bindgen(module = "fs")]
extern "C" {
    #[wasm_bindgen(js_name = existsSync, catch)]
    fn path_exists(path: &str) -> Result<bool>;
    #[wasm_bindgen(js_name = readDirSync, catch)]
    fn read_dir(path: &str) -> Result<String>;
}

#[wasm_bindgen(module = "path")]
extern "C" {
    #[wasm_bindgen(js_name = resolve, catch)]
    fn path_resolve(path: &str) -> Result<String>;
}

pub fn resolve_path(file_or_dir: &str) -> Result<PathBuf> {
    #[cfg(target_arch = "wasm32")]
    {
        Ok(PathBuf::from_str(&path_resolve(file_or_dir)?)?)
    }

    #[cfg(not(target_arch = "wasm32"))]
    {
        Ok(PathBuf::from_str(file_or_dir)?)
    }
}

/// Reads the `--payload` JSON from stdin.
///
/// The message says where the text came from, which flag asked for it, and what shape was expected.
/// Serde's bare text -- `EOF while parsing a value at line 1 column 0` for no stdin at all -- names
/// none of the three, even though this function knows all three and `PAYLOAD_HELP` already carries
/// the schema. "line 1 column 0" is especially unhelpful when the real answer is that
/// nothing was piped in, which is the shape this takes in CI with no stdin attached.
fn deserialize_payload(payload: &str) -> Result<Payload> {
    match serde_json::from_str::<Payload>(payload) {
        Ok(value) => Ok(value),
        Err(e) => Err(Error::ParseError(format!(
            "Unable to parse the --payload JSON read from stdin: {e}. Expected {}",
            PAYLOAD_SCHEMA
        ))),
    }
}

pub fn parse_rules<'r>(
    rules_file_content: &'r str,
    rules_file_name: &'r str,
) -> Result<Option<RulesFile<'r>>> {
    let span = crate::rules::parser::Span::new_extra(rules_file_content, rules_file_name);
    crate::rules::parser::rules_file(span)
}

//
// https://vallentin.dev/2019/05/14/pretty-print-tree
//
#[allow(clippy::uninlined_format_args)]
fn pprint_tree(current: &EventRecord<'_>, prefix: String, last: bool, writer: &mut Writer) {
    let prefix_current = if last { "`- " } else { "|- " };
    writeln!(writer, "{}{}{}", prefix, prefix_current, current)
        .expect("Unable to write to the output");

    let prefix_child = if last { "   " } else { "|  " };
    let prefix = prefix + prefix_child;
    if !current.children.is_empty() {
        let last_child = current.children.len() - 1;
        for (i, child) in current.children.iter().enumerate() {
            pprint_tree(child, prefix.clone(), i == last_child, writer);
        }
    }
}

pub(crate) fn print_verbose_tree(root: &EventRecord<'_>, writer: &mut Writer) {
    pprint_tree(root, "".to_string(), true, writer);
}

#[allow(clippy::too_many_arguments)]
fn evaluate_against_data_input<'r>(
    _data_type: Type,
    output: OutputFormatType,
    extra_data: &Option<PathAwareValue>,
    data_files: &'r Vec<DataFile>,
    rules: &RulesFile<'_>,
    rules_file_name: &'r str,
    verbose: bool,
    print_json: bool,
    summary_table: BitFlags<SummaryType>,
    mut write_output: &mut Writer,
) -> Result<Status> {
    let mut overall = Status::PASS;
    let generic: Box<dyn Reporter> =
        Box::new(generic_summary::GenericSummary::new(summary_table)) as Box<dyn Reporter>;
    let tf: Box<dyn Reporter> = Box::new(TfAware::new_with(generic.as_ref())) as Box<dyn Reporter>;
    let cfn: Box<dyn Reporter> =
        Box::new(cfn::CfnAware::new_with(tf.as_ref())) as Box<dyn Reporter>;

    let reporter: Box<dyn Reporter> = if summary_table.is_empty() {
        cfn
    } else {
        Box::new(summary_table::SummaryTable::new(
            summary_table,
            cfn.as_ref(),
        )) as Box<dyn Reporter>
    };

    // One set across the data files, with the two collapses `Notices` makes: a notice the
    // evaluator records once per site is written once per site for the run, and a plain notice (one
    // with no site) once per distinct text for the run, not once per file. Both for the same reason: a
    // deprecation describes the rule, not the data, so one line per run is what the rule author needs,
    // and a line repeated beside every template is a line trained to be skipped. The once-per-site
    // collapse is what the text alone cannot give: the notice names the map that lost its selection,
    // which differs between two templates with different logical ids, so a set keyed by text wrote a
    // near-identical line per template for one filter in the rules file. The once-per-text collapse is
    // the same reading applied to a notice whose text does not vary with the template, which would
    // otherwise be written beside each file that drew it.
    //
    // What the later files keep is a trailer: a notice drawn by more than one data file, of either
    // collapse, is named once more after the loop beside the files after the first that drew it, so a
    // reader of a multi-file run can still tell which files hit a notice the run announced once,
    // without the notice repeated beside each of them. One trailer line per distinct list of later
    // files, naming at most a few of them and counting the rest (`repeated_notice_trailer`), so the run
    // the trailer exists for, a directory of templates over one `let`, does not end in the line the
    // collapse removed; two lists that would read the same shortened are told apart by the first name
    // where they differ, so the line stays bounded (`repeated_notice_trailers`). Each notice is
    // named by what tells it from its neighbors: a once-per-site notice by its kind and site, since one
    // `when` site holds a notice per direction, and a plain notice by its opening words and the position
    // it ends with, since it has no site and two clauses can draw one text (`describe_apart`). A notice
    // one file drew gets no trailer. The trailers are part of what this function reports, so they are
    // written on the exits that end the loop early too, before the error goes back: a data file whose
    // merge with the input parameters fails, whose evaluation errs, or whose report fails to write. A
    // failed notice write is the error stream itself failing, and is returned at once.
    let mut deprecations = Notices::new();
    let mut repeated: std::collections::BTreeMap<RepeatedNotice, Vec<String>> =
        std::collections::BTreeMap::new();
    let mut first_error = None;
    for file in data_files {
        let each = match &extra_data {
            Some(data) => match data.clone().merge(file.path_value.clone()) {
                Ok(each) => each,
                Err(error) => {
                    first_error = Some(error);
                    break;
                }
            },
            None => file.path_value.clone(),
        };
        let traversal = Traversal::from(&each);
        let mut root_scope = root_scope_for(rules, Rc::new(each.clone()), Some(&file.name));
        // Not `?`. A rules file with one unevaluatable rule still has findings from the others, and
        // they are in the record by the time the error comes back -- `eval_rules_file` evaluates every
        // rule before returning it. Reporting first and propagating afterwards keeps the exit code
        // saying "the ruleset is broken" while letting the reader see what the rest of it found.
        let evaluated = eval_rules_file(rules, &mut root_scope, Some(&file.name));
        let status = match &evaluated {
            Ok(status) => *status,
            Err(_) => Status::FAIL,
        };

        // Notices, the deprecations and then the warnings, written to stderr and read before
        // `reset_recorder` consumes the scope. Stderr rather than the report because the report on
        // stdout is what pipelines parse, and a notice about how a reading moved, or will move, is not
        // part of this run's result -- adding it there would change the document for every consumer in
        // order to tell them something that is not a verdict. Of both kinds, only the lines this file
        // adds to the run's set are written, beside this file's report: a deprecation once per site
        // across the data files, and a moved-reading warning once per call site, argument and data
        // file, so each file whose reading moved gets its line beside its own report and no trailer
        // names it: the trailer below is for the deprecations the collapse kept to one line.
        // The notices this file draws that an earlier file already announced, of either collapse, read
        // before this scope is absorbed: the trailer after the loop names this file for each of them.
        // The file's name is recorded as given; the trailer escapes its control characters when it
        // prints it (`repeated_notice_trailers`), as every notice naming a file does. The moved-reading
        // warnings need no trailer, since their key carries the data file and each file that moved a
        // reading gets its own line beside its own report. Each line goes down the writer's path for
        // its kind, as a collection's lines do, so nothing here reads a line's text to route it.
        for (site, _) in root_scope.deprecations_once() {
            if deprecations.holds_site(site) {
                repeated
                    .entry(RepeatedNotice::Site(site.clone()))
                    .or_default()
                    .push(file.name.clone());
            }
        }
        for text in root_scope.plain_deprecations() {
            if deprecations.holds_plain(text) {
                repeated
                    .entry(RepeatedNotice::Plain(text.clone()))
                    .or_default()
                    .push(file.name.clone());
            }
        }
        let added_deprecations = deprecations.absorb_deprecations(&root_scope);
        let added_warnings = deprecations.absorb_warnings(&root_scope);
        for line in added_deprecations.into_iter().chain(added_warnings) {
            line.write_to(write_output)?;
        }

        let root_record = root_scope.reset_recorder().extract();

        if let Err(error) = reporter.report_eval(
            &mut write_output,
            status,
            &root_record,
            rules_file_name,
            &file.name,
            &file.content,
            &traversal,
            output,
        ) {
            first_error = Some(error);
            break;
        }

        if verbose {
            print_verbose_tree(&root_record, write_output);
        }

        if print_json {
            writeln!(
                write_output,
                "{}",
                serde_json::to_string_pretty(&root_record)?
            )
            .expect("Unable to write to the output");
        }

        if status == Status::FAIL {
            overall = Status::FAIL
        }

        // The error ends the loop rather than the function: the trailers below are owed for the files
        // evaluated so far, under the rule above that this path reports first and propagates after. A
        // `?` here left them unwritten whenever a later file's evaluation failed.
        if let Err(error) = evaluated {
            first_error = Some(error);
            break;
        }
    }

    // The trailers, after every file's report and before the error, if any, goes back; see the comment
    // above the loop and `repeated_notice_trailers`. Notes, so the library entry drops them from a
    // failure text as it drops the notices while a reader counting deprecations does not count them.
    for trailer in repeated_notice_trailers(&repeated) {
        write_output.write_notice(trailer)?;
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(overall),
    }
}

/// The trailer lines for the notices later data files drew, from the map of each such notice to the
/// files after the first that drew it (in run order, since each file pushed its name as it was
/// reached). Grouped by that list, so the notices the same files drew share one line, and each line
/// names at most a few of the files and counts the rest (`trailer_file_list`), always: a directory of
/// templates over one `let` must not end in a line listing every template. Two groups whose shortened
/// lists would read the same (the same first names and the same count, as for two sites each missed by
/// one different template) are told apart by the first name where their lists differ, one phrase per
/// such neighbor (`not t60`: a file the neighbor's list holds and this one lacks), so the line stays
/// bounded by the number of such neighbors and never grows with the number of files. Each notice on a
/// line is described so it is told from the others (`describe_apart`).
fn repeated_notice_trailers(
    repeated: &std::collections::BTreeMap<RepeatedNotice, Vec<String>>,
) -> Vec<String> {
    let mut by_later_files: std::collections::BTreeMap<&Vec<String>, Vec<&RepeatedNotice>> =
        std::collections::BTreeMap::new();
    for (notice, later_files) in repeated {
        by_later_files.entry(later_files).or_default().push(notice);
    }
    // Each group's shortened reading and the set of its names, built once per group: a run over a
    // directory of templates can hold thousands of names per list, and the neighbor check below reads
    // the names of one list against another, so a linear `contains` per name made the pass over one pair
    // of lists grow with the square of the directory.
    let groups: Vec<(&Vec<String>, String, std::collections::HashSet<&str>)> = by_later_files
        .keys()
        .map(|later_files| {
            (
                *later_files,
                crate::utils::writer::trailer_file_list(later_files, &[]),
                later_files.iter().map(String::as_str).collect(),
            )
        })
        .collect();
    groups
        .iter()
        .map(|(later_files, shortened, names)| {
            let notices = &by_later_files[*later_files];
            let mut apart: Vec<String> = Vec::new();
            for (other, other_shortened, _) in &groups {
                if *other == *later_files || other_shortened != shortened {
                    continue;
                }
                // The two lists have the same length and differ, so each holds a name the other lacks;
                // the first such name of the neighbor's is what this line says it did not have.
                if let Some(missing) = other.iter().find(|name| !names.contains(name.as_str())) {
                    let phrase = format!(
                        "not {}",
                        crate::utils::writer::escaped_controls_for_display(missing)
                    );
                    if !apart.contains(&phrase) {
                        apart.push(phrase);
                    }
                }
            }
            // The names are the data files as given on the command line, kept raw above so the lists
            // compare and group by the names themselves; the trailer prints them as every notice prints
            // a file name, with each control character written as its escape, so a line feed in a path
            // cannot split the one trailer line and an ESC in one cannot reach the terminal raw.
            let named: Vec<String> = later_files
                .iter()
                .map(|name| crate::utils::writer::escaped_controls_for_display(name))
                .collect();
            crate::utils::writer::repeated_notice_trailer(&describe_apart(notices), &named, &apart)
        })
        .collect()
}

/// A notice the single-line output announced once that a later data file drew too, as the trailer after
/// the data-file loop names it (`evaluate_against_data_input`): a once-per-site notice by its kind and
/// site, the key the evaluator records it under, and a plain notice by its text, the only key it has.
/// Ordered so the trailer lists sites before plain notices, and each group in key order.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
enum RepeatedNotice {
    Site((crate::rules::DeprecationKind, String)),
    Plain(String),
}

impl RepeatedNotice {
    /// The words the trailer refers to the notice by: the kind and site for one recorded per site, since
    /// one site can hold notices of two kinds; the first `words` words and the position for a plain one.
    fn described(&self, words: usize) -> String {
        match self {
            // The key holds the position's `Display` as recorded, so the rules path in it is escaped
            // here, as `location_for_notice` escapes it for the notice the trailer refers back to.
            RepeatedNotice::Site((kind, site)) => format!(
                "{} for the site at {}",
                kind.described(),
                crate::utils::writer::escaped_controls_for_display(site)
            ),
            RepeatedNotice::Plain(text) => crate::utils::writer::notice_opening(text, words),
        }
    }
}

/// How many words of a plain notice a trailer quotes before trying more.
const OPENING_WORDS: usize = 8;

/// The descriptions of one trailer's notices, each telling its notice from the others on the line. A
/// once-per-site notice carries its kind and site, the key the evaluator records it under, so two never
/// read the same. A plain notice is quoted by its opening words and the position it ends with, and when
/// two still read the same (two notices of one kind whose texts differ only further in) every plain one
/// on the line is quoted at more words until they differ, or until the longest is quoted whole, which
/// tells them apart because the set holds each text once.
fn describe_apart(notices: &[&RepeatedNotice]) -> Vec<String> {
    let longest = notices
        .iter()
        .filter_map(|notice| match notice {
            RepeatedNotice::Plain(text) => Some(text.split_whitespace().count()),
            RepeatedNotice::Site(_) => None,
        })
        .max()
        .unwrap_or(0);
    let mut words = OPENING_WORDS;
    loop {
        let described: Vec<String> = notices
            .iter()
            .map(|notice| notice.described(words))
            .collect();
        let distinct = described
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == described.len();
        if distinct || words >= longest {
            return described;
        }
        words += OPENING_WORDS;
    }
}

fn data_file_is_empty(name: &str) -> Error {
    Error::ParseError(format!(
        "Unable to parse a template from data file: {name} is empty"
    ))
}

/// Reports each key the document declared twice inside one mapping, on the same stderr channel the
/// empty-file message uses.
///
/// The verdict is left alone: the last value still wins and the exit code does not move. The YAML
/// 1.2 spec makes a duplicate key a loading failure, so rejecting the document would be defensible
/// on it, but every template that carries one passes today and that is a maintainer's call. Saying
/// so is not.
///
/// One line per duplicated key, written once when the file is read. Data files are built before any
/// rule is evaluated, so the count does not scale with the number of rules.
fn report_duplicate_keys(writer: &mut Writer, name: &str, duplicates: &[DuplicateKey]) {
    for duplicate in duplicates {
        // Which value stands is the record's to say: the last for a key written twice, the first for
        // a merged key that collided with an earlier source's key, and a third site when an alias
        // wrote the standing value at a line the pair does not name (see
        // `DuplicateKey::evaluated_sentence`).
        writer
            .write_notice(crate::utils::writer::warning(format_args!(
                "duplicate key {} in data file {}, first at {} and again at {}. {}",
                crate::utils::writer::escaped_for_display(&duplicate.path),
                crate::utils::writer::escaped_controls_for_display(name),
                duplicate.first,
                duplicate.repeated,
                duplicate.evaluated_sentence()
            )))
            .expect("Unable to write to stderr");
    }
}

/// One line per `!!` tag the loader read past, written once when the file is read, beside the
/// duplicate-key lines above. The loader collects them rather than printing them because library code
/// writes nothing to stderr: a library caller gets the same list in its result and reports it its own
/// way.
fn report_unread_tags(writer: &mut Writer, name: &str, warnings: &[UnreadTag]) {
    for warning in warnings {
        writer
            .write_notice(warning.in_file(&format!("data file {name}")))
            .expect("Unable to write to stderr");
    }
}

fn build_data_file(content: String, name: String, writer: &mut Writer) -> Result<DataFile> {
    if content.trim().is_empty() {
        return Err(data_file_is_empty(&name));
    }

    let mut duplicates = vec![];
    // The `!!` tags the loader read past are reported whether or not the load succeeded: a tag read
    // before the loader refused the document was still read past.
    let mut warnings = vec![];
    let loaded = crate::rules::values::read_from_reporting(&content, &mut warnings);
    report_unread_tags(writer, &name, &warnings);
    let path_value = match loaded {
        Ok((value, collisions)) => {
            // `collisions` are the merged keys the loader dropped against a held key of another form,
            // by the position of the mapping that merged and the held key's position; the conversion
            // reports each where the value lands in that mapping, beside the pairs it finds itself.
            let converted = PathAwareValue::try_from_marked_reporting(
                (value, crate::rules::path_value::Path::root()),
                &collisions,
                &mut duplicates,
            )?;
            report_duplicate_keys(writer, &name, &duplicates);
            converted
        }
        // A file that parses but holds no document -- one that is all comments, say -- has nothing
        // more in it to validate than a file of no bytes, and is reported the same way. The check
        // above cannot answer this on the text alone, so the loader is what decides it.
        Err(Error::MissingDocument) => return Err(data_file_is_empty(&name)),
        Err(e) => {
            // These two say what is wrong and where, so they keep their own wording. The file name
            // is prepended because neither message can know it, and without it a run over a
            // directory reports a position in an unnamed file: `L:2,C:4` identifies nothing when
            // there are N templates to choose from.
            if matches!(
                e,
                Error::InternalError(InternalError::InvalidKeyType(..))
                    | Error::UnsupportedDocument(..)
            ) {
                return Err(Error::ParseError(format!("in data file {name}: {e}")));
            }

            // libyaml's own failure names what the parser expected and the line and the column it
            // stopped at, so it is reported under the file's name and nothing else. The excerpt of
            // the file's first hundred bytes below was written for the time that failure read "error
            // parsing file" and nothing more, to give the reader some text to go on; it is kept for
            // that bare text alone, which the parser wrapper falls back to when libyaml records a
            // failure without describing it.
            let message = match e {
                Error::ParseError(message) => message,
                other => other.to_string(),
            };
            if message != "error parsing file" {
                return Err(Error::ParseError(format!(
                    "Error encountered while parsing data file: {name}: {message}"
                )));
            }
            let str_len: usize = cmp::min(content.len(), 100);
            return Err(Error::ParseError(format!(
                "Error encountered while parsing data file: {name}, data beginning with \n{}\n ...",
                &content[..str_len]
            )));
        }
    };

    Ok(DataFile {
        name,
        path_value,
        content,
    })
}

/// Whether a name ends in one of the extensions a directory walk recognises.
///
/// The comparison is a plain suffix match, so it is case sensitive: `.yaml` is recognised and
/// `.YAML` is not. This decides only what a directory walk picks up. A file named as an argument is
/// read without consulting it.
fn has_a_supported_extension(name: &str, extensions: &[&str]) -> bool {
    extensions.iter().any(|extension| name.ends_with(extension))
}

/// The canonical path of a data file, which is the name its findings are reported under.
///
/// Canonicalising is what keeps doubled separators out of the report: `walkdir` output occasionally
/// includes '//', and this name is printed verbatim.
fn canonical_name(path: &Path) -> Result<String> {
    Ok(path
        .canonicalize()?
        .to_str()
        .map_or("".to_string(), String::from))
}

/// The final component of a path, or an empty string if it has none.
pub(crate) fn file_name_of(path: &Path) -> String {
    path.file_name()
        .and_then(|name| name.to_str())
        .map_or_else(String::new, String::from)
}

/// Reads one data file under the name its findings will be reported against.
fn read_data_file(path: &Path, name: String, writer: &mut Writer) -> Result<DataFile> {
    let mut content = String::new();
    let mut reader = BufReader::new(File::open(path)?);
    reader.read_to_string(&mut content)?;

    build_data_file(content, name, writer)
}

/// The names a directory walk passed over, kept only while the walk has found nothing it can use.
/// They are printed in one case, by [`report_no_data_evaluated`] or [`report_no_rules_evaluated`]
/// when the whole walk found no file, so once a file is found they can never be printed: the
/// names held so far are dropped, their memory with them, and no later name is kept. Without this
/// every run held one `String` per unrelated file in every directory it walked, the README, the
/// lockfile and the rest, for the length of the walk, and threw them away at its end.
#[derive(Debug, Default)]
pub(crate) struct PassedOver {
    names: Vec<String>,
    found: bool,
}

impl PassedOver {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// A file the walk passed over. Kept only while nothing has been found.
    pub(crate) fn skip(&mut self, name: String) {
        if !self.found {
            self.names.push(name);
        }
    }

    /// The walk found a file it can use: the names kept so far are dropped and no more are kept.
    pub(crate) fn found(&mut self) {
        self.found = true;
        self.names = Vec::new();
    }

    /// The names kept: every file passed over when nothing was found, none once a file was.
    pub(crate) fn names(&self) -> &[String] {
        &self.names
    }
}

/// Reports on stderr that the run had no data to evaluate, and names the files a directory walk
/// passed over on the way to finding none.
///
/// A run that checked nothing is otherwise indistinguishable from a run in which everything
/// complied: both print nothing to stdout and exit 0. In a pipeline that is a green build for data
/// nobody looked at.
///
/// This fires only when the run evaluated nothing at all. Reporting every skipped file would emit a
/// line for the README, the licence and the lockfile in any real directory, and a warning that
/// fires on every run stops being read. What that leaves uncovered is a directory yielding some
/// templates while skipping one the user expected to be checked; such a run does print findings, so
/// it is not silent about having run, only about the omission.
///
/// The exit code is left alone. A run that evaluated nothing still returns PASS, because moving it
/// would change the result for everyone pointing `--data` at a directory of mixed content, and that
/// is a separate argument to make.
fn report_no_data_evaluated(writer: &mut Writer, skipped: &[String]) -> Result<()> {
    let passed_over = skipped.iter().map(|name| {
        crate::utils::writer::warning(format_args!(
            "{} was not evaluated because its extension is not one of: {}",
            crate::utils::writer::escaped_controls_for_display(name),
            DATA_FILE_SUPPORTED_EXTENSIONS.join(", ")
        ))
    });
    writer.write_nothing_checked(passed_over, no_data_evaluated_warning())?;

    Ok(())
}

/// The warning [`report_no_data_evaluated`] ends with: the one line that says the run checked
/// nothing. Written through `Writer::write_nothing_checked`, which records the fact beside the text,
/// so the entry point that has to report such a run as an error (`ValidateBuilder::try_build_and_execute`)
/// branches on the fact and shows this text as the command wrote it, whatever it says.
pub(crate) fn no_data_evaluated_warning() -> String {
    crate::utils::writer::warning(format_args!(
        "no data files were evaluated. Nothing was checked, and the absence of findings does not \
         mean the data complied."
    ))
}

/// Reports on stderr that the run had no rules to apply, and names the files a directory walk passed
/// over on the way to finding none.
///
/// The mirror of [`report_no_data_evaluated`], written for the same reason and reached the same way:
/// a run that applied no rule prints nothing to stdout and exits 0, which is what a run in which
/// everything complied also does. `--rules some-empty-dir` therefore reported success for a policy
/// that was never applied.
///
/// Like the data side, this fires only when the run found no rules at all, and leaves the exit code
/// alone. Moving the code would change the result for every caller pointing `--rules` at a directory
/// that happens to hold no rules file, which is a separate argument to make; and a warning that fires
/// on runs which *did* apply rules stops being read.
fn report_no_rules_evaluated(writer: &mut Writer, skipped: &[String]) -> Result<()> {
    let passed_over = skipped.iter().map(|name| {
        crate::utils::writer::warning(format_args!(
            "{} was not evaluated because its extension is not one of: {}",
            crate::utils::writer::escaped_controls_for_display(name),
            RULE_FILE_SUPPORTED_EXTENSIONS.join(", ")
        ))
    });
    writer.write_nothing_checked(passed_over, no_rules_evaluated_warning())?;

    Ok(())
}

/// The warning [`report_no_rules_evaluated`] ends with, the mirror of
/// [`no_data_evaluated_warning`] and shared with the same entry point for the same reason.
pub(crate) fn no_rules_evaluated_warning() -> String {
    crate::utils::writer::warning(format_args!(
        "no rules files were evaluated. Nothing was checked, and the absence of findings does not \
         mean the data complied."
    ))
}

/// The name a rules file is reported and located under: the path as it was given.
///
/// This replaced `get_file_name(file, base)`, which every caller invoked as `get_file_name(file, file)`.
/// `strip_prefix` against itself yields the empty path, so the function always took its
/// `file_name()` branch and every rules file was known by its basename alone -- two arguments spent
/// arriving at a value that needed neither. Two files named `same.guard` in different directories then
/// produced byte-identical output everywhere the name appears, including the source position a
/// deprecation notice ends with, which exists so a reader can go to the clause.
///
/// The path as given rather than a path derived from it, for three reasons.
///
/// It is reproducible. `resolve_path` is `PathBuf::from_str` on every non-wasm target and does not
/// canonicalize, so a relative argument stays relative and the locator is the caller's own string.
/// An absolute argument yields an absolute locator, which is the caller's choice and not this
/// function's to rewrite; deriving a path relative to the process's working directory would make the
/// same file report differently depending on where the command was run from.
///
/// It is what the data file already does. `Property [...] in data [...]` prints the data file exactly
/// as it was passed, so the rules file was the asymmetric one.
///
/// And `test --rules-file` already does it -- `path.to_str()` -- so three of the four paths that name
/// a rules file now agree on one rule instead of holding three spellings between them.
///
/// Rejected: relative to the `--rules` argument that produced the file, which is what the two-argument
/// shape was reaching for. It distinguishes files found by walking a directory, but a caller naming two
/// files explicitly makes each one its own base, which is the collapse above again.
fn rules_file_locator(file: &Path) -> String {
    file.display().to_string()
}

fn get_rule_info(rules: &[PathBuf], writer: &mut Writer) -> Result<Vec<RuleFileInfo>> {
    iterate_over(rules, |content, file| {
        Ok(RuleFileInfo {
            content,
            file_name: rules_file_locator(file),
        })
    })
    .try_fold(vec![], |mut res, rule| -> Result<Vec<RuleFileInfo>> {
        if let Err(e) = rule {
            writer.write_err(format!("Unable to read content from file {e}"))?;
            return Err(e);
        }

        res.push(rule?);
        Ok(res)
    })
}

pub(crate) struct RuleFileInfo {
    pub(crate) content: String,
    pub(crate) file_name: String,
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod validate_tests;
