use std::cmp;
use std::convert::TryFrom;
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
use crate::commands::tracker::StatusContext;
use crate::commands::{
    Executable, ALPHABETICAL, DATA_FILE_SUPPORTED_EXTENSIONS, ERROR_STATUS_CODE,
    FAILURE_STATUS_CODE, INPUT_PARAMETERS, LAST_MODIFIED, PAYLOAD, PRINT_JSON, REQUIRED_FLAGS,
    RULES, RULE_FILE_SUPPORTED_EXTENSIONS, SHOW_SUMMARY, STRUCTURED, SUCCESS_STATUS_CODE, TYPE,
    VERBOSE,
};
use crate::rules::errors::{Error, InternalError};
use crate::rules::eval::eval_rules_file;
use crate::rules::eval_context::{root_scope, EventRecord};
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::{Result, Status};
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;

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
#[derive(Copy, Eq, Clone, Debug, PartialEq, ValueEnum, Serialize, Default, Deserialize)]
pub enum OutputFormatType {
    #[default]
    SingleLineSummary,
    JSON,
    YAML,
    Junit,
}

#[derive(Copy, Eq, Clone, Debug, PartialEq, ValueEnum, Serialize, Default, Deserialize)]
pub enum ShowSummaryType {
    All,
    Pass,
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
    pub(crate) fn is_structured(&self) -> bool {
        !matches!(self, Self::SingleLineSummary)
    }
}

impl From<&str> for OutputFormatType {
    fn from(value: &str) -> Self {
        match value {
            "single-line-summary" => OutputFormatType::SingleLineSummary,
            "json" => OutputFormatType::JSON,
            "junit" => OutputFormatType::Junit,
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
pub(crate) struct Validate {
    #[arg(short, long, help=RULES_HELP, num_args=0.., conflicts_with=PAYLOAD.0)]
    pub(crate) rules: Vec<String>,
    #[arg(short, long, help=DATA_HELP, num_args=0.., conflicts_with=PAYLOAD.0)]
    pub(crate) data: Vec<String>,
    #[arg(short, long, help=INPUT_PARAMETERS_HELP, num_args=0..)]
    pub(crate) input_params: Vec<String>,
    #[arg(name=TYPE.0, short, long, help=TEMPLATE_TYPE_HELP, value_parser=TEMPLATE_TYPE)]
    pub(crate) template_type: Option<String>,
    #[arg(short, long, help=OUTPUT_FORMAT_HELP, value_enum, default_value_t=OutputFormatType::SingleLineSummary)]
    pub(crate) output_format: OutputFormatType,
    #[arg(short=SHOW_SUMMARY.1, long, help=SHOW_SUMMARY_HELP, value_enum, default_values_t=vec![ShowSummaryType::Fail])]
    pub(crate) show_summary: Vec<ShowSummaryType>,
    #[arg(short, long, help=ALPHABETICAL_HELP, conflicts_with=LAST_MODIFIED.0)]
    pub(crate) alphabetical: bool,
    #[arg(name="last-modified", short=LAST_MODIFIED.1, long, help=LAST_MODIFIED_HELP, conflicts_with=ALPHABETICAL.0)]
    pub(crate) last_modified: bool,
    #[arg(short, long, help=VERBOSE_HELP)]
    pub(crate) verbose: bool,
    #[arg(name="print-json", short=PRINT_JSON.1, long, help=PRINT_JSON_HELP)]
    pub(crate) print_json: bool,
    #[arg(short=PAYLOAD.1, long, help=PAYLOAD_HELP)]
    pub(crate) payload: bool,
    #[arg(short=STRUCTURED.1, long, help=STRUCTURED_HELP, conflicts_with_all=vec![PRINT_JSON.0, VERBOSE.0])]
    pub(crate) structured: bool,
}

impl Executable for Validate {
    fn execute(&self, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        let summary_type = self
            .show_summary
            .iter()
            .fold(BitFlags::empty(), |mut st, elem| {
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
            });

        let cmp = if self.last_modified {
            last_modified
        } else {
            alphabetical
        };

        if self.structured && !summary_type.is_empty() {
            return Err(Error::IllegalArguments(String::from(
                "Cannot provide a summary-type other than `none` when the `structured` flag is present",
            )));
        } else if self.structured && self.output_format == OutputFormatType::SingleLineSummary {
            return Err(Error::IllegalArguments(String::from(
                "single-line-summary is not able to be used when the `structured` flag is present",
            )));
        }

        if matches!(self.output_format, OutputFormatType::Junit) && !self.structured {
            return Err(Error::IllegalArguments(String::from(
                "the structured flag must be set when output is set to junit",
            )));
        }

        let data_files = match self.data.is_empty() {
            false => {
                let mut streams = Vec::new();

                for file_or_dir in &self.data {
                    validate_path(file_or_dir)?;
                    let base = PathBuf::from_str(file_or_dir)?;
                    for file in walk_dir(base, cmp) {
                        if file.path().is_file() {
                            let name = file
                                .path()
                                // path output occasionally includes double slashes '//'
                                // without calling canonicalize()
                                .canonicalize()?
                                .to_str()
                                .map_or("".to_string(), String::from);

                            if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS) {
                                let mut content = String::new();
                                let mut reader = BufReader::new(File::open(file.path())?);
                                reader.read_to_string(&mut content)?;

                                let data_file = build_data_file(content, name)?;

                                streams.push(data_file);
                            }
                        }
                    }
                }
                streams
            }
            true => {
                if !self.rules.is_empty() {
                    let mut content = String::new();
                    reader.read_to_string(&mut content)?;

                    let data_file = build_data_file(content, "STDIN".to_string())?;

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
                    let base = PathBuf::from_str(file_or_dir)?;

                    for file in walk_dir(base, cmp) {
                        if file.path().is_file() {
                            let name = file
                                .file_name()
                                .to_str()
                                .map_or("".to_string(), String::from);

                            if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS) {
                                let mut content = String::new();
                                let mut reader = BufReader::new(File::open(file.path())?);
                                reader.read_to_string(&mut content)?;

                                let DataFile { path_value, .. } = build_data_file(content, name)?;

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

            for file_or_dir in &self.rules {
                validate_path(file_or_dir)?;
                let base = PathBuf::from_str(file_or_dir)?;

                if base.is_file() {
                    rules.push(base.clone())
                } else {
                    for entry in walk_dir(base, cmp) {
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
                                    self.output_format,
                                    &extra_data,
                                    &data_files,
                                    rule,
                                    self.verbose,
                                    self.print_json,
                                    summary_type,
                                    writer,
                                )?;

                                if status != SUCCESS_STATUS_CODE {
                                    exit_code = status
                                }
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
                    let data_file = build_data_file(content, name)?;

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
                        let status = evaluate_rule(
                            data_type,
                            self.output_format,
                            &None,
                            &data_collection,
                            rule,
                            self.verbose,
                            self.print_json,
                            summary_type,
                            writer,
                        )?;

                        if status != SUCCESS_STATUS_CODE {
                            exit_code = status;
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
const INPUT_PARAMETERS_HELP: &str = "Provide a data file or directory of data files in JSON or YAML that specifies any additional parameters to use along with data files to be used as a combined context. \
                           All the parameter files passed as input get merged and this combined context is again merged with each file passed as an argument for `data`. Due to this, every file is \
                           expected to contain mutually exclusive properties, without any overlap. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --input-parameters param1.yaml --input-parameters ./param-dir1 --input-parameters param2.yaml\
                          \nFor directory arguments such as `param-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template";
const TEMPLATE_TYPE_HELP: &str =
    "Specify the type of data file used for improved messaging - ex: CFNTemplate";
pub(crate) const OUTPUT_FORMAT_HELP: &str =
    "Specify the format in which the output should be displayed";
const SHOW_SUMMARY_HELP: &str = "Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)";
const ALPHABETICAL_HELP: &str = "Validate files in a directory ordered alphabetically";
const LAST_MODIFIED_HELP: &str = "Validate files in a directory ordered by last modified times";
const VERBOSE_HELP: &str = "Verbose logging";
const PRINT_JSON_HELP: &str = "Print the parse tree in a json format. This can be used to get more details on how the clauses were evaluated";
const PAYLOAD_HELP: &str = "Provide rules and data in the following JSON format via STDIN,\n{\"rules\":[\"<rules 1>\", \"<rules 2>\", ...], \"data\":[\"<data 1>\", \"<data 2>\", ...]}, where,\n- \"rules\" takes a list of string \
                version of rules files as its value and\n- \"data\" takes a list of string version of data files as it value.\nWhen --payload is specified --rules and --data cannot be specified.";
const STRUCTURED_HELP: &str = "Print out a list of structured and valid JSON/YAML. This argument conflicts with the following arguments: \nverbose \n print-json \n show-summary: all/fail/pass/skip \noutput-format: single-line-summary";

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
            let status = evaluate_against_data_input(
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
            )?;

            if status == Status::FAIL {
                return Ok(FAILURE_STATUS_CODE);
            }
        }
        Ok(None) => return Ok(SUCCESS_STATUS_CODE),
    }

    Ok(SUCCESS_STATUS_CODE)
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

    for file in data_files {
        let each = match &extra_data {
            Some(data) => data.clone().merge(file.path_value.clone())?,
            None => file.path_value.clone(),
        };
        let traversal = Traversal::from(&each);
        let mut root_scope = root_scope(rules, Rc::new(each.clone()));
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
    }
    Ok(overall)
}
fn build_data_file(content: String, name: String) -> Result<DataFile> {
    if content.trim().is_empty() {
        return Err(Error::ParseError(format!(
            "Unable to parse a template from data file: {name} is empty"
        )));
    }

    let path_value = match crate::rules::values::read_from(&content) {
        Ok(value) => PathAwareValue::try_from(value)?,
        Err(e) => {
            if matches!(e, Error::InternalError(InternalError::InvalidKeyType(..))) {
                return Err(Error::ParseError(e.to_string()));
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

fn has_a_supported_extension(name: &str, extensions: &[&str]) -> bool {
    extensions.iter().any(|extension| name.ends_with(extension))
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
