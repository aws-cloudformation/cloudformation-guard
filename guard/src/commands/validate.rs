use std::cmp;
use std::convert::TryFrom;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::str::FromStr;

use clap::{Arg, ArgAction, ArgGroup, ArgMatches};
use colored::*;
use enumflags2::BitFlags;
use serde::Deserialize;

use crate::command::Command;
use crate::commands::aws_meta_appender::MetadataAppender;
use crate::commands::files::{alpabetical, iterate_over, last_modified};
use crate::commands::tracker::{StackTracker, StatusContext};
use crate::commands::validate::structured::StructuredEvaluator;
use crate::commands::validate::summary_table::SummaryType;
use crate::commands::validate::tf::TfAware;
use crate::commands::{
    ALPHABETICAL, DATA, DATA_FILE_SUPPORTED_EXTENSIONS, INPUT_PARAMETERS, LAST_MODIFIED,
    OUTPUT_FORMAT, PAYLOAD, PREVIOUS_ENGINE, PRINT_JSON, REQUIRED_FLAGS, RULES,
    RULE_FILE_SUPPORTED_EXTENSIONS, SHOW_CLAUSE_FAILURES, SHOW_SUMMARY, STRUCTURED, TYPE, VALIDATE,
    VERBOSE,
};
use crate::rules::errors::Error;
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{root_scope, EventRecord};
use crate::rules::evaluate::RootScope;
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use crate::rules::{Evaluate, EvaluationContext, EvaluationType, Result, Status};
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;

mod cfn;
mod cfn_reporter;
mod common;
mod console_reporter;
pub(crate) mod generic_summary;
mod structured;
mod summary_table;
mod tf;

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

#[allow(clippy::upper_case_acronyms)]
#[derive(Copy, Eq, Clone, Debug, PartialEq)]
pub(crate) enum OutputFormatType {
    SingleLineSummary,
    JSON,
    YAML,
}

impl From<&str> for OutputFormatType {
    fn from(value: &str) -> Self {
        match value {
            "single-line-summary" => OutputFormatType::SingleLineSummary,
            "json" => OutputFormatType::JSON,
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

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Validate {}

#[derive(Deserialize, Debug)]
pub(crate) struct Payload {
    #[serde(rename = "rules")]
    list_of_rules: Vec<String>,
    #[serde(rename = "data")]
    list_of_data: Vec<String>,
}

#[allow(clippy::new_without_default)]
impl Validate {
    pub fn new() -> Self {
        Validate {}
    }
}

const OUTPUT_FORMAT_VALUE_TYPE: [&str; 3] = ["json", "yaml", "single-line-summary"];
const SHOW_SUMMARY_VALUE_TYPE: [&str; 5] = ["none", "all", "pass", "fail", "skip"];
const TEMPLATE_TYPE: [&str; 1] = ["CFNTemplate"];

impl Command for Validate {
    fn name(&self) -> &'static str {
        VALIDATE
    }

    fn command(&self) -> clap::Command {
        clap::Command::new(VALIDATE)
            .about(r#"Evaluates rules against the data files to determine success or failure.
You can point rules flag to a rules directory and point data flag to a data directory.
When pointed to a directory it will read all rules in the directory file and evaluate
them against the data files found in the directory. The command can also point to a
single file and it would work as well.
Note - When pointing the command to a directory, the directory may not contain a mix of
rules and data files. The directory being pointed to must contain only data files,
or rules files.
"#)
            .arg(Arg::new(RULES.0)
                .long(RULES.0)
                .short(RULES.1)
                .num_args(0..)
                .action(ArgAction::Append)
                .help("Provide a rules file or a directory of rules files. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --rules rule1.guard --rules ./rules-dir1 --rules rule2.guard\
                          \nFor directory arguments such as `rules-dir1` above, scanning is only supported for files with following extensions: .guard, .ruleset")
                .conflicts_with("payload"))
            .arg(Arg::new(DATA.0)
                .long(DATA.0)
                .short(DATA.1)
                .num_args(0..)
                .action(ArgAction::Append)
                .help("Provide a data file or directory of data files in JSON or YAML. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --data template1.yaml --data ./data-dir1 --data template2.yaml\
                          \nFor directory arguments such as `data-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template")
                .conflicts_with("payload"))
            .arg(Arg::new(INPUT_PARAMETERS.0)
                .long(INPUT_PARAMETERS.0)
                .short(INPUT_PARAMETERS.1)
                .num_args(0..)
                .action(ArgAction::Append)
                .help("Provide a data file or directory of data files in JSON or YAML that specifies any additional parameters to use along with data files to be used as a combined context. \
                           All the parameter files passed as input get merged and this combined context is again merged with each file passed as an argument for `data`. Due to this, every file is \
                           expected to contain mutually exclusive properties, without any overlap. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --input-parameters param1.yaml --input-parameters ./param-dir1 --input-parameters param2.yaml\
                          \nFor directory arguments such as `param-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template"))
            .arg(Arg::new(TYPE.0)
                .long(TYPE.0)
                .short(TYPE.1)
                .action(ArgAction::Set)
                .required(false)
                .value_parser(TEMPLATE_TYPE)
                .help("Specify the type of data file used for improved messaging - ex: CFNTemplate"))
            .arg(Arg::new(OUTPUT_FORMAT.0).long(OUTPUT_FORMAT.0).short(OUTPUT_FORMAT.1)
                .value_parser(OUTPUT_FORMAT_VALUE_TYPE)
                .default_value("single-line-summary")
                .action(ArgAction::Set)
                .help("Specify the format in which the output should be displayed"))
            .arg(Arg::new(PREVIOUS_ENGINE.0).long(PREVIOUS_ENGINE.0).short(PREVIOUS_ENGINE.1)
                .action(ArgAction::SetTrue)
                .help("Uses the old engine for evaluation. This parameter will allow customers to evaluate old changes before migrating"))
            .arg(Arg::new(SHOW_SUMMARY.0)
                .long(SHOW_SUMMARY.0)
                .short(SHOW_SUMMARY.1)
                .use_value_delimiter(true)
                .action(ArgAction::Append)
                .value_parser(SHOW_SUMMARY_VALUE_TYPE)
                .default_value("fail")
                .help("Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)"))
            .arg(Arg::new(SHOW_CLAUSE_FAILURES.0)
                .long(SHOW_CLAUSE_FAILURES.0)
                .short(SHOW_CLAUSE_FAILURES.1)
                .action(ArgAction::SetTrue)
                .help("Show clause failure along with summary"))
            .arg(Arg::new(ALPHABETICAL.0)
                .long(ALPHABETICAL.0)
                .short(ALPHABETICAL.1)
                .action(ArgAction::SetTrue)
                .help("Validate files in a directory ordered alphabetically"))
            .arg(Arg::new(LAST_MODIFIED.0)
                .long(LAST_MODIFIED.0)
                .short(LAST_MODIFIED.1)
                .action(ArgAction::SetTrue)
                .conflicts_with(ALPHABETICAL.0)
                .help("Validate files in a directory ordered by last modified times"))
            .arg(Arg::new(VERBOSE.0)
                .long(VERBOSE.0)
                .short(VERBOSE.1)
                .action(ArgAction::SetTrue)
                .help("Verbose logging"))
            .arg(Arg::new(PRINT_JSON.0)
                .long(PRINT_JSON.0)
                .short(PRINT_JSON.1)
                .action(ArgAction::SetTrue)
                .help("Print output in json format"))
            .arg(Arg::new(PAYLOAD.0)
                .long(PAYLOAD.0)
                .short(PAYLOAD.1)
                .action(ArgAction::SetTrue)
                .required(false)
                .help("Provide rules and data in the following JSON format via STDIN,\n{\"rules\":[\"<rules 1>\", \"<rules 2>\", ...], \"data\":[\"<data 1>\", \"<data 2>\", ...]}, where,\n- \"rules\" takes a list of string \
                version of rules files as its value and\n- \"data\" takes a list of string version of data files as it value.\nWhen --payload is specified --rules and --data cannot be specified."))
            .arg(Arg::new(STRUCTURED.0)
                .long(STRUCTURED.0)
                .short(STRUCTURED.1)
                .help("Print out a list of structured and valid JSON/YAML. This argument conflicts with the following arguments: \nverbose \n print-json \n previous-engine \n show-summary: all/fail/pass/skip \noutput-format: single-line-summary")
                .conflicts_with_all(vec![PRINT_JSON.0, VERBOSE.0, PREVIOUS_ENGINE.0])
                .action(ArgAction::SetTrue))
            .group(ArgGroup::new(REQUIRED_FLAGS)
                .args([RULES.0, PAYLOAD.0])
                .required(true))
            .arg_required_else_help(true)
    }

    fn execute(&self, app: &ArgMatches, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        let cmp = if app.get_flag(LAST_MODIFIED.0) {
            last_modified
        } else {
            alpabetical
        };

        let summary_type: BitFlags<SummaryType> =
            app.get_many::<String>(SHOW_SUMMARY.0)
                .map_or(SummaryType::FAIL.into(), |v| {
                    v.fold(BitFlags::empty(), |mut st, elem| {
                        match elem.as_str() {
                            "pass" => st.insert(SummaryType::PASS),
                            "fail" => st.insert(SummaryType::FAIL),
                            "skip" => st.insert(SummaryType::SKIP),
                            "none" => return BitFlags::empty(),
                            "all" => {
                                st.insert(SummaryType::PASS | SummaryType::FAIL | SummaryType::SKIP)
                            }
                            _ => unreachable!(),
                        };
                        st
                    })
                });

        let output_type = match app.get_one::<String>(OUTPUT_FORMAT.0) {
            Some(o) => OutputFormatType::from(o.as_str()),
            None => OutputFormatType::SingleLineSummary,
        };

        let structured = app.get_flag(STRUCTURED.0);
        if structured && !summary_type.is_empty() {
            return Err(Error::IllegalArguments(String::from(
                "Cannot provide a summary-type other than `none` when the `structured` flag is present",
            )));
        } else if structured && output_type == OutputFormatType::SingleLineSummary {
            return Err(Error::IllegalArguments(String::from(
                "single-line-summary is not able to be used when the `structured` flag is present",
            )));
        }

        let mut streams = Vec::new();

        let data_files = match app.get_many::<String>(DATA.0) {
            Some(list_of_file_or_dir) => {
                for file_or_dir in list_of_file_or_dir {
                    validate_path(file_or_dir)?;
                    let base = PathBuf::from_str(file_or_dir)?;
                    for file in walkdir::WalkDir::new(base.clone()).into_iter().flatten() {
                        if file.path().is_file() {
                            let name = file
                                .file_name()
                                .to_str()
                                .map_or("".to_string(), String::from);

                            if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS) {
                                let mut content = String::new();
                                let mut reader = BufReader::new(File::open(file.path())?);
                                reader.read_to_string(&mut content)?;

                                let path = file.path();

                                let file_name = get_file_name(path, &base);

                                let path_value = match get_path_aware_value_from_data(&content) {
                                    Ok(t) => t,
                                    Err(e) => return Err(e),
                                };

                                streams.push(DataFile {
                                    name: file_name,
                                    path_value,
                                    content,
                                });
                            }
                        }
                    }
                }
                streams
            }
            None => {
                if app.contains_id(RULES.0) {
                    let mut content = String::new();
                    reader.read_to_string(&mut content)?;
                    let path_value = match get_path_aware_value_from_data(&content) {
                        Ok(t) => t,
                        Err(e) => return Err(e),
                    };
                    streams.push(DataFile {
                        name: "STDIN".to_string(),
                        path_value,
                        content,
                    });
                    streams
                } else {
                    vec![]
                } // expect Payload, since rules aren't specified
            }
        };

        let extra_data = match app.get_many::<String>(INPUT_PARAMETERS.0) {
            Some(list_of_file_or_dir) => {
                let mut primary_path_value: Option<PathAwareValue> = None;
                for file_or_dir in list_of_file_or_dir {
                    validate_path(file_or_dir)?;
                    let base = PathBuf::from_str(file_or_dir)?;

                    for file in walkdir::WalkDir::new(base.clone()).into_iter().flatten() {
                        if file.path().is_file() {
                            let name = file
                                .file_name()
                                .to_str()
                                .map_or("".to_string(), String::from);

                            if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS) {
                                let mut content = String::new();
                                let mut reader = BufReader::new(File::open(file.path())?);
                                reader.read_to_string(&mut content)?;

                                let path_value = get_path_aware_value_from_data(&content)?;

                                primary_path_value = match primary_path_value {
                                    Some(current) => Some(current.merge(path_value)?),
                                    None => Some(path_value),
                                };
                            }
                        }
                    }
                }
                primary_path_value
            }
            None => None,
        };

        let verbose = app.get_flag(VERBOSE.0);

        let data_type = match app.get_one::<String>(TYPE.0) {
            Some(t) => Type::from(t.as_str()),
            None => Type::Generic,
        };

        let print_json = app.get_flag(PRINT_JSON.0);
        let show_clause_failures = app.get_flag(SHOW_CLAUSE_FAILURES.0);
        let new_version_eval_engine = !app.get_flag(PREVIOUS_ENGINE.0);

        let mut exit_code = 0;

        if app.contains_id(RULES.0) {
            let list_of_file_or_dir = app.get_many::<String>(RULES.0).unwrap();
            let mut rules = Vec::new();
            for file_or_dir in list_of_file_or_dir {
                validate_path(file_or_dir)?;
                let base = PathBuf::from_str(file_or_dir)?;
                if base.is_file() {
                    rules.push(base.clone())
                } else {
                    for entry in walkdir::WalkDir::new(base.clone())
                        .sort_by(cmp)
                        .into_iter()
                        .flatten()
                    {
                        if entry.path().is_file()
                            && entry
                                .path()
                                .file_name()
                                .and_then(|s| s.to_str())
                                .map_or(false, |s| {
                                    has_a_supported_extension(s, &RULE_FILE_SUPPORTED_EXTENSIONS)
                                })
                        {
                            rules.push(entry.path().to_path_buf());
                        }
                    }
                }
            }

            exit_code = match structured {
                true => {
                    let rule_info = get_rule_info(&rules, writer)?;
                    let mut evaluator = StructuredEvaluator {
                        rule_info: &rule_info,
                        input_params: extra_data,
                        data: data_files,
                        output: output_type,
                        writer,
                        exit_code: 0,
                    };
                    evaluator.evaluate()?
                }

                false => {
                    for each_file_content in iterate_over(&rules, |content, file| {
                        Ok(RuleFileInfo {
                            content,
                            file_name: get_file_name(file, file),
                        })
                    }) {
                        match each_file_content {
                            Err(e) => {
                                writer.write_err(format!("Unable read content from file {e}"))?
                            }
                            Ok(rule) => {
                                let status = evaluate_rule(
                                    data_type,
                                    output_type,
                                    &extra_data,
                                    &data_files,
                                    rule,
                                    verbose,
                                    print_json,
                                    show_clause_failures,
                                    new_version_eval_engine,
                                    summary_type,
                                    writer,
                                )?;

                                if status == 5 {
                                    exit_code = 5
                                }
                            }
                        }
                    }
                    exit_code
                }
            };
        } else if app.contains_id(PAYLOAD.0) {
            let mut context = String::new();
            reader.read_to_string(&mut context)?;
            let payload = deserialize_payload(&context)?;

            let data_collection = payload.list_of_data.iter().enumerate().try_fold(
                vec![],
                |mut data_collection, (i, data)| -> Result<Vec<DataFile>> {
                    let content = data.to_string();
                    let path_value = get_path_aware_value_from_data(&content)?;

                    data_collection.push(DataFile {
                        name: format!("DATA_STDIN[{}]", i + 1),
                        path_value,
                        content,
                    });

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

            exit_code = match structured {
                true => {
                    let mut evaluator = StructuredEvaluator {
                        rule_info: &rule_info,
                        input_params: extra_data,
                        data: data_collection,
                        output: output_type,
                        writer,
                        exit_code: 0,
                    };
                    evaluator.evaluate()?
                }
                false => {
                    for rule in rule_info {
                        let status = evaluate_rule(
                            data_type,
                            output_type,
                            &None,
                            &data_collection,
                            rule,
                            verbose,
                            print_json,
                            show_clause_failures,
                            new_version_eval_engine,
                            summary_type,
                            writer,
                        )?;

                        if status == 5 {
                            exit_code = 5;
                        }
                    }
                    exit_code
                }
            };
        } else {
            unreachable!()
        }

        Ok(exit_code)
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
    show_clause_failures: bool,
    new_version_eval_engine: bool,
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

            return Ok(5);
        }

        Ok(rule) => {
            let status = evaluate_against_data_input(
                data_type,
                output,
                extra_data,
                data_files,
                &rule,
                file_name,
                verbose,
                print_json,
                show_clause_failures,
                new_version_eval_engine,
                summary_type,
                writer,
            )?;

            if status == Status::FAIL {
                return Ok(5);
            }
        }
    }

    Ok(0)
}

pub(crate) fn validate_path(base: &str) -> Result<()> {
    match Path::new(base).exists() {
        true => Ok(()),
        false => Err(Error::FileNotFoundError(base.to_string())),
    }
}

fn deserialize_payload(payload: &str) -> Result<Payload> {
    match serde_json::from_str::<Payload>(payload) {
        Ok(value) => Ok(value),
        Err(e) => Err(Error::ParseError(e.to_string())),
    }
}

fn parse_rules<'r>(rules_file_content: &'r str, rules_file_name: &'r str) -> Result<RulesFile<'r>> {
    let span = crate::rules::parser::Span::new_extra(rules_file_content, rules_file_name);
    crate::rules::parser::rules_file(span)
}

#[derive(Debug)]
pub(crate) struct ConsoleReporter<'r> {
    root_context: StackTracker<'r>,
    reporters: &'r Vec<&'r dyn Reporter>,
    rules_file_name: &'r str,
    data_file_name: &'r str,
    verbose: bool,
    print_json: bool,
    show_clause_failures: bool,
    writer: &'r mut Writer,
}

fn indent_spaces(indent: usize, writer: &mut Writer) {
    for _idx in 0..indent {
        write!(writer, "{INDENT}").expect("Unable to write to the output");
    }
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

pub(super) fn print_context(cxt: &StatusContext, depth: usize, writer: &mut Writer) {
    let header = format!(
        "{}({}, {})",
        cxt.eval_type,
        cxt.context,
        common::colored_string(cxt.status)
    )
    .underline();
    //let depth = cxt.indent;
    let _sub_indent = depth + 1;
    indent_spaces(depth - 1, writer);
    writeln!(writer, "{header}").expect("Unable to write to the output");
    match &cxt.from {
        Some(v) => {
            indent_spaces(depth, writer);
            write!(writer, "|  ").expect("Unable to write to the output");
            writeln!(writer, "From: {v:?}").expect("Unable to write to the output");
        }
        None => {}
    }
    match &cxt.to {
        Some(v) => {
            indent_spaces(depth, writer);
            write!(writer, "|  ").expect("Unable to write to the output");
            writeln!(writer, "To: {v:?}").expect("Unable to write to the output");
        }
        None => {}
    }
    match &cxt.msg {
        Some(message) => {
            indent_spaces(depth, writer);
            write!(writer, "|  ").expect("Unable to write to the output");
            writeln!(writer, "Message: {message}").expect("Unable to write to the output");
        }
        None => {}
    }

    for child in &cxt.children {
        print_context(child, depth + 1, writer)
    }
}

#[allow(clippy::uninlined_format_args)]
fn print_failing_clause(
    rules_file_name: &str,
    rule: &StatusContext,
    longest: usize,
    writer: &mut Writer,
) {
    write!(
        writer,
        "{file}/{rule:<0$}",
        longest + 4,
        file = rules_file_name,
        rule = rule.context
    )
    .expect("Unable to write to the output");
    let longest = rules_file_name.len() + longest;
    let mut first = true;
    for (index, matched) in common::find_all_failing_clauses(rule).iter().enumerate() {
        let matched = *matched;
        let header = format!(
            "{}({})",
            common::colored_string(matched.status),
            matched.context
        )
        .underline();
        if !first {
            write!(
                writer,
                "{space:>longest$}",
                space = " ",
                longest = longest + 4
            )
            .expect("Unable to write to the output");
        }
        let clause = format!("Clause #{}", index + 1).bold();
        writeln!(
            writer,
            "{header:<20}{content}",
            header = clause,
            content = header
        )
        .expect("Unable to write to the output");
        match &matched.from {
            Some(from) => {
                write!(
                    writer,
                    "{space:>longest$}",
                    space = " ",
                    longest = longest + 4
                )
                .expect("Unable to write to the output");
                let content = format!("Comparing {:?}", from);
                write!(
                    writer,
                    "{header:<20}{content}",
                    header = " ",
                    content = content
                )
                .expect("Unable to write to the output");
            }
            None => {}
        }
        match &matched.to {
            Some(to) => {
                writeln!(writer, " with {:?} failed", to).expect("Unable to write to the output");
            }
            None => {
                writeln!(writer).expect("Unable to write to the output");
            }
        }
        match &matched.msg {
            Some(m) => {
                for each in m.split('\n') {
                    write!(
                        writer,
                        "{space:>longest$}",
                        space = " ",
                        longest = longest + 4 + 20
                    )
                    .expect("Unable to write to the output");
                    writeln!(writer, "{}", each).expect("Unable to write to the output");
                }
            }
            None => {
                writeln!(writer).expect("Unable to write to the output");
            }
        }
        if first {
            first = false;
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl<'r> ConsoleReporter<'r> {
    pub(crate) fn new(
        root: StackTracker<'r>,
        renderers: &'r Vec<&'r dyn Reporter>,
        rules_file_name: &'r str,
        data_file_name: &'r str,
        verbose: bool,
        print_json: bool,
        show_clause_failures: bool,
        writer: &'r mut Writer,
    ) -> ConsoleReporter<'r> {
        ConsoleReporter {
            root_context: root,
            reporters: renderers,
            rules_file_name,
            data_file_name,
            verbose,
            print_json,
            show_clause_failures,
            writer,
        }
    }

    fn report(mut self, root: &PathAwareValue, output_format_type: OutputFormatType) -> Result<()> {
        let stack = self.root_context.stack();
        let top = stack.first().unwrap();

        if self.verbose && self.print_json {
            let serialized_user = serde_json::to_string_pretty(&top.children).unwrap();
            writeln!(self.writer, "{serialized_user}").expect("Unable to write to the output");
        } else {
            let longest = get_longest(top);

            let (failed, rest): (Vec<&StatusContext>, Vec<&StatusContext>) =
                partition_failed_and_rest(top);

            let traversal = Traversal::from(root);

            for each_reporter in self.reporters {
                each_reporter.report(
                    &mut self.writer,
                    top.status,
                    &failed,
                    &rest,
                    longest,
                    self.rules_file_name,
                    self.data_file_name,
                    &traversal,
                    output_format_type,
                )?;
            }

            if self.show_clause_failures {
                writeln!(self.writer, "{}", "Clause Failure Summary".bold())
                    .expect("Unable to write to the output");
                for each in failed {
                    print_failing_clause(self.rules_file_name, each, longest, self.writer);
                }
            }

            if self.verbose {
                writeln!(self.writer, "Evaluation Tree").expect("Unable to write to the output");
                for each in &top.children {
                    print_context(each, 1, self.writer);
                }
            }
        }

        Ok(())
    }
}

const INDENT: &str = "    ";

impl<'r> EvaluationContext for ConsoleReporter<'r> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        self.root_context.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.root_context.rule_status(rule_name)
    }

    fn end_evaluation(
        &self,
        eval_type: EvaluationType,
        context: &str,
        msg: String,
        from: Option<PathAwareValue>,
        to: Option<PathAwareValue>,
        status: Option<Status>,
        cmp: Option<(CmpOperator, bool)>,
    ) {
        self.root_context
            .end_evaluation(eval_type, context, msg, from, to, status, cmp);
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        self.root_context.start_evaluation(eval_type, context);
    }
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
    show_clause_failures: bool,
    new_engine_version: bool,
    summary_table: BitFlags<SummaryType>,
    mut write_output: &mut Writer,
) -> Result<Status> {
    let mut overall = Status::PASS;
    let generic: Box<dyn Reporter> =
        Box::new(generic_summary::GenericSummary::new()) as Box<dyn Reporter>;
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

    for file in data_files {
        if new_engine_version {
            let each = match &extra_data {
                Some(data) => data.clone().merge(file.path_value.clone())?,
                None => file.path_value.clone(),
            };
            let traversal = Traversal::from(&each);
            let mut root_scope = root_scope(rules, Rc::new(each.clone()))?;
            let status = eval_rules_file(rules, &mut root_scope, Some(&file.name))?;

            let root_record = root_scope.reset_recorder().extract();

            reporter.report_eval(
                &mut write_output,
                status,
                &root_record,
                rules_file_name,
                &file.name,
                &file.content,
                &traversal,
                output,
            )?;

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
        } else {
            let each = &file.path_value;
            let root_context = RootScope::new(rules, each)?;
            let stacker = StackTracker::new(&root_context);
            let renderers = vec![reporter.as_ref()];

            let reporter = ConsoleReporter::new(
                stacker,
                &renderers,
                rules_file_name,
                &file.name,
                verbose,
                print_json,
                show_clause_failures,
                write_output,
            );

            let appender = MetadataAppender {
                delegate: &reporter,
                root_context: each,
            };
            let status = rules.evaluate(each, &appender)?;
            reporter.report(each, output)?;
            if status == Status::FAIL {
                overall = Status::FAIL
            }
        }
    }
    Ok(overall)
}

fn get_path_aware_value_from_data(content: &String) -> Result<PathAwareValue> {
    if content.trim().is_empty() {
        Err(Error::ParseError("blank data".to_string()))
    } else {
        let path_value = match crate::rules::values::read_from(content) {
            Ok(value) => PathAwareValue::try_from(value)?,
            Err(_) => {
                let str_len: usize = cmp::min(content.len(), 100);
                return Err(Error::ParseError(format!(
                    "data beginning with \n{}\n ...",
                    &content[..str_len]
                )));
            }
        };
        Ok(path_value)
    }
}

fn has_a_supported_extension(name: &str, extensions: &[&str]) -> bool {
    extensions.iter().any(|extension| name.ends_with(extension))
}

fn partition_failed_and_rest(top: &StatusContext) -> (Vec<&StatusContext>, Vec<&StatusContext>) {
    top.children
        .iter()
        .partition(|ctx| matches!(ctx.status, Some(Status::FAIL)))
}

fn get_longest(top: &StatusContext) -> usize {
    top.children
        .iter()
        .max_by(|f, s| f.context.len().cmp(&s.context.len()))
        .map(|elem| elem.context.len())
        .unwrap_or(20)
}

fn get_file_name(file: &Path, base: &Path) -> String {
    let empty_path = Path::new("");
    match file.strip_prefix(base) {
        Ok(path) => {
            if path == empty_path {
                file.file_name().unwrap().to_str().unwrap().to_string()
            } else {
                format!("{}", path.display())
            }
        }
        Err(_) => format!("{}", file.display()),
    }
}

fn get_rule_info(rules: &[PathBuf], writer: &mut Writer) -> Result<Vec<RuleFileInfo>> {
    iterate_over(rules, |content, file| {
        Ok(RuleFileInfo {
            content,
            file_name: get_file_name(file, file),
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
