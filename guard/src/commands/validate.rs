use std::convert::TryFrom;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read, Write};
use std::cmp;

use clap::{App, Arg, ArgMatches, ArgGroup};
use colored::*;

use crate::command::Command;
use crate::commands::aws_meta_appender::MetadataAppender;
use crate::commands::files::{alpabetical, iterate_over, last_modified};
use crate::commands::tracker::{StackTracker, StatusContext};
use crate::rules::{Evaluate, EvaluationContext, EvaluationType, Result, Status};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use crate::commands::validate::summary_table::SummaryType;
use enumflags2::BitFlags;
use serde::Deserialize;
use std::path::{PathBuf, Path};
use std::str::FromStr;
use Type::CFNTemplate;
use crate::commands::{ALPHABETICAL, DATA, DATA_FILE_SUPPORTED_EXTENSIONS, INPUT_PARAMETERS, LAST_MODIFIED, OUTPUT_FORMAT, PAYLOAD, PREVIOUS_ENGINE, PRINT_JSON, REQUIRED_FLAGS, RULE_FILE_SUPPORTED_EXTENSIONS, RULES, SHOW_CLAUSE_FAILURES, SHOW_SUMMARY, TYPE, VALIDATE, VERBOSE};
use crate::rules::eval_context::{EventRecord, root_scope, simplifed_json_from_root};
use crate::rules::eval::eval_rules_file;
use crate::rules::path_value::traversal::Traversal;
use crate::commands::validate::tf::TfAware;

pub(crate) mod generic_summary;
mod common;
mod summary_table;
mod cfn_reporter;
mod cfn;
mod console_reporter;
mod tf;

#[derive(Eq, Clone, Debug, PartialEq)]
pub(crate) struct DataFile {
    content: String,
    path_value: PathAwareValue,
    name: String
}

#[derive(Copy, Eq, Clone, Debug, PartialEq)]
pub(crate) enum Type {
    CFNTemplate,
    Generic
}

#[derive(Copy, Eq, Clone, Debug, PartialEq)]
pub(crate) enum OutputFormatType {
    SingleLineSummary,
    JSON,
    YAML
}

pub(crate) trait Reporter : Debug {
    fn report(&self,
              writer: &mut dyn Write,
              status: Option<Status>,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize,
              rules_file: &str,
              data_file: &str,
              data: &Traversal<'_>,
              output_type: OutputFormatType
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
        _output_type: OutputFormatType
    ) -> Result<()> { Ok(()) }
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

impl Validate {
    pub fn new() -> Self {
        Validate{}
    }
}

impl Command for Validate {
    fn name(&self) -> &'static str {
        VALIDATE
    }


    fn command(&self) -> App<'static, 'static> {
        App::new(VALIDATE)
            .about(r#"Evaluates rules against the data files to determine success or failure. 
You can point rules flag to a rules directory and point data flag to a data directory. 
When pointed to a directory it will read all rules in the directory file and evaluate 
them against the data files found in the directory. The command can also point to a
single file and it would work as well.
Note - When pointing the command to a directory, the directory may not contain a mix of 
rules and data files. The directory being pointed to must contain only data files,
or rules files.
"#)
            .arg(Arg::with_name(RULES.0).long(RULES.0).short(RULES.1).takes_value(true)
                .help("Provide a rules file or a directory of rules files. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --rules rule1.guard --rules ./rules-dir1 --rules rule2.guard\
                          \nFor directory arguments such as `rules-dir1` above, scanning is only supported for files with following extensions: .guard, .ruleset")
                .multiple(true).conflicts_with("payload"))
            .arg(Arg::with_name(DATA.0).long(DATA.0).short(DATA.1).takes_value(true)
                .help("Provide a data file or directory of data files in JSON or YAML. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --data template1.yaml --data ./data-dir1 --data template2.yaml\
                          \nFor directory arguments such as `data-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template")
                .multiple(true).conflicts_with("payload"))
            .arg(Arg::with_name(INPUT_PARAMETERS.0).long(INPUT_PARAMETERS.0).short(INPUT_PARAMETERS.1).takes_value(true)
                     .help("Provide a data file or directory of data files in JSON or YAML that specifies any additional parameters to use along with data files to be used as a combined context. \
                           All the parameter files passed as input get merged and this combined context is again merged with each file passed as an argument for `data`. Due to this, every file is \
                           expected to contain mutually exclusive properties, without any overlap. Supports passing multiple values by using this option repeatedly.\
                          \nExample:\n --input-parameters param1.yaml --input-parameters ./param-dir1 --input-parameters param2.yaml\
                          \nFor directory arguments such as `param-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template")
                     .multiple(true))
            .arg(Arg::with_name(TYPE.0).long(TYPE.0).short(TYPE.1).takes_value(true).possible_values(&["CFNTemplate"])
                .help("Specify the type of data file used for improved messaging"))
            .arg(Arg::with_name(OUTPUT_FORMAT.0).long(OUTPUT_FORMAT.0).short(OUTPUT_FORMAT.1).takes_value(true)
                .possible_values(&["json","yaml","single-line-summary"])
                .default_value("single-line-summary")
                .help("Specify the format in which the output should be displayed"))
            .arg(Arg::with_name(PREVIOUS_ENGINE.0).long(PREVIOUS_ENGINE.0).short(PREVIOUS_ENGINE.1).takes_value(false)
                .help("Uses the old engine for evaluation. This parameter will allow customers to evaluate old changes before migrating"))
            .arg(Arg::with_name(SHOW_SUMMARY.0).long(SHOW_SUMMARY.0).short(SHOW_SUMMARY.1).takes_value(true).use_delimiter(true).multiple(true)
                .possible_values(&["none", "all", "pass", "fail", "skip"])
                .default_value("fail")
                .help("Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip)"))
            .arg(Arg::with_name(SHOW_CLAUSE_FAILURES.0).long(SHOW_CLAUSE_FAILURES.0).short(SHOW_CLAUSE_FAILURES.1).takes_value(false).required(false)
                .help("Show clause failure along with summary"))
            .arg(Arg::with_name(ALPHABETICAL.0).long(ALPHABETICAL.0).short(ALPHABETICAL.1).required(false).help("Validate files in a directory ordered alphabetically"))
            .arg(Arg::with_name(LAST_MODIFIED.0).long(LAST_MODIFIED.0).short(LAST_MODIFIED.1).required(false).conflicts_with(ALPHABETICAL.0)
                .help("Validate files in a directory ordered by last modified times"))
            .arg(Arg::with_name(VERBOSE.0).long(VERBOSE.0).short(VERBOSE.1).required(false)
                .help("Verbose logging"))
            .arg(Arg::with_name(PRINT_JSON.0).long(PRINT_JSON.0).short(PRINT_JSON.1).required(false)
                .help("Print output in json format"))
            .arg(Arg::with_name(PAYLOAD.0).long(PAYLOAD.0).short(PAYLOAD.1)
                .help("Provide rules and data in the following JSON format via STDIN,\n{\"rules\":[\"<rules 1>\", \"<rules 2>\", ...], \"data\":[\"<data 1>\", \"<data 2>\", ...]}, where,\n- \"rules\" takes a list of string \
                version of rules files as its value and\n- \"data\" takes a list of string version of data files as it value.\nWhen --payload is specified --rules and --data cannot be specified."))
            .group(ArgGroup::with_name(REQUIRED_FLAGS)
                .args(&[RULES.0, PAYLOAD.0])
                .required(true))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<i32> {
        let cmp = if app.is_present(LAST_MODIFIED.0) {
            last_modified
        } else {
            alpabetical
        };

        let empty_path = Path::new("");
        let mut streams: Vec<DataFile> = Vec::new();
        let data_files: Vec<DataFile> = match app.values_of(DATA.0) {
            Some(list_of_file_or_dir) => {
                for file_or_dir in list_of_file_or_dir {
                    let base = PathBuf::from_str(file_or_dir)?;
                    for each_entry in walkdir::WalkDir::new(base.clone()) {
                        if let Ok(file) = each_entry {
                            if file.path().is_file() {
                                let name = file.file_name().to_str().map_or("".to_string(), String::from);
                                if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS)
                                {
                                    let mut content = String::new();
                                    let mut reader = BufReader::new(File::open(file.path())?);
                                    reader.read_to_string(&mut content)?;
                                    let path = file.path();
                                    let relative = match path.strip_prefix(base.as_path()) {
                                        Ok(p) => if p != empty_path {
                                            format!("{}", p.display())
                                        } else { format!("{}", path.file_name().unwrap().to_str().unwrap()) },
                                        Err(_) => format!("{}", path.display()),
                                    };
                                    let path_value = match get_path_aware_value_from_data(&content) {
                                        Ok(T) => T,
                                        Err(E) => return Err(E)
                                    };
                                    streams.push(DataFile {
                                        name: relative,
                                        path_value,
                                        content
                                    });
                                }
                            }
                        }
                    }
                }
                streams
            },
            None => {
                if app.is_present(RULES.0) {
                    let mut content = String::new();
                    let mut reader = BufReader::new(std::io::stdin());
                    reader.read_to_string(&mut content)?;
                    let path_value = match get_path_aware_value_from_data(&content) {
                        Ok(T) => T,
                        Err(E) => return Err(E)
                    };
                    streams.push(DataFile {
                        name: "STDIN".to_string(),
                        path_value,
                        content
                    });
                    streams
                }
                else { vec![] } // expect Payload, since rules aren't specified
            }
        };

        let extra_data = match app.values_of(INPUT_PARAMETERS.0) {
            Some(list_of_file_or_dir) => {
                let mut primary_path_value: Option<PathAwareValue> = None;
                for file_or_dir in list_of_file_or_dir {
                    let base = PathBuf::from_str(file_or_dir)?;
                    for each_entry in walkdir::WalkDir::new(base.clone()) {
                        if let Ok(file) = each_entry {
                            if file.path().is_file() {
                                let name = file.file_name().to_str().map_or("".to_string(), String::from);
                                if has_a_supported_extension(&name, &DATA_FILE_SUPPORTED_EXTENSIONS)
                                {
                                    let mut content = String::new();
                                    let mut reader = BufReader::new(File::open(file.path())?);
                                    reader.read_to_string(&mut content)?;
                                    let path_value = match get_path_aware_value_from_data(&content) {
                                        Ok(T) => T,
                                        Err(E) => return Err(E)
                                    };
                                    primary_path_value = match primary_path_value {
                                        Some(mut current) => {
                                            Some(current.merge(path_value)?)
                                        },
                                        None => Some(path_value)
                                    };
                                }
                            }
                        }
                    }
                }
                primary_path_value
            }
            None => None
        };

        let verbose = if app.is_present(VERBOSE.0) {
            true
        } else {
            false
        };

        let data_type = match app.value_of(TYPE.0) {
            Some(t) =>
                if t == "CFNTemplate" {
                    CFNTemplate
                }
                else {
                    Type::Generic
                },
            None => Type::Generic
        };

        let output_type = match app.value_of(OUTPUT_FORMAT.0) {
            Some(o) =>
                if o == "single-line-summary" {
                    OutputFormatType::SingleLineSummary
                }
                else if o == "json" {
                    OutputFormatType::JSON
                }
                else {
                    OutputFormatType::YAML
                }
            None => OutputFormatType::SingleLineSummary
        };

        let summary_type: BitFlags<SummaryType> = app.values_of(SHOW_SUMMARY.0).map_or(
            SummaryType::FAIL.into(),
            |v| {
                v.fold(BitFlags::empty(), |mut st, elem| {
                    match elem {
                        "pass" => st.insert(SummaryType::PASS),
                        "fail" => st.insert(SummaryType::FAIL),
                        "skip" => st.insert(SummaryType::SKIP),
                        "none" => return BitFlags::empty(),
                        "all"  => st.insert(SummaryType::PASS | SummaryType::FAIL | SummaryType::SKIP),
                        _ => unreachable!()
                    };
                    st
                })
            });

        let print_json = app.is_present(PRINT_JSON.0);
        let show_clause_failures = app.is_present(SHOW_CLAUSE_FAILURES.0);
        let new_version_eval_engine = !app.is_present(PREVIOUS_ENGINE.0);

        let mut exit_code = 0;
        if app.is_present(RULES.0) {
            let list_of_file_or_dir = app.values_of(RULES.0).unwrap();
            let mut rules = Vec::new();
            for file_or_dir in list_of_file_or_dir {
            let base = PathBuf::from_str(file_or_dir)?;
            if base.is_file() {
                rules.push(base.clone())
            } else {
                    for each in walkdir::WalkDir::new(base.clone()).sort_by(cmp) {
                        if let Ok(entry) = each {
                            if entry.path().is_file() &&
                                entry.path().file_name().map(|s| s.to_str()).flatten()
                                    .map_or(false, |s|
                                        has_a_supported_extension(&s.to_string(),
                                                                  &RULE_FILE_SUPPORTED_EXTENSIONS)
                                    )
                            {
                                rules.push(entry.path().to_path_buf());
                            }
                        }
                    }
                }
            }
            for each_file_content in iterate_over(&rules, |content, file|
                Ok((content, match file.strip_prefix(&file) {
                    Ok(path) => if path == empty_path {
                        format!("{}", file.file_name().unwrap().to_str().unwrap())
                    } else { format!("{}", path.display()) },
                    Err(_) => format!("{}", file.display()),
                }))) {
                match each_file_content {
                    Err(e) => println!("Unable read content from file {}", e),
                    Ok((file_content, rule_file_name)) => {
                        let span = crate::rules::parser::Span::new_extra(&file_content, &rule_file_name);
                        match crate::rules::parser::rules_file(span) {
                            Err(e) => {
                                println!("Parsing error handling rule file = {}, Error = {}",
                                         rule_file_name.underline(), e);
                                println!("---");
                                exit_code = 5;
                                continue;
                            },

                            Ok(rules) => {
                                match evaluate_against_data_input(
                                    data_type,
                                    output_type,
                                    extra_data.clone(),
                                    &data_files,
                                    &rules,
                                    &rule_file_name,
                                    verbose,
                                    print_json,
                                    show_clause_failures,
                                    new_version_eval_engine,
                                    summary_type.clone())? {
                                    Status::SKIP | Status::PASS => continue,
                                    Status::FAIL => {
                                        exit_code = 5;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        } else {
            let mut context = String::new();
            let mut reader = BufReader::new(std::io::stdin());
            reader.read_to_string(&mut context);
            let payload: Payload = deserialize_payload(&context)?;
            let mut data_collection: Vec<DataFile> = Vec::new();
            for (i, data) in payload.list_of_data.iter().enumerate() {
                let mut content = data.to_string();
                let path_value = match get_path_aware_value_from_data(&content) {
                    Ok(T) => T,
                    Err(E) => return Err(E)
                };
                data_collection.push(DataFile {
                    name: format!("DATA_STDIN[{}]", i + 1),
                    path_value,
                    content
                });
            }
            let rules_collection: Vec<(String, String)> = payload.list_of_rules.iter().enumerate().map(|(i, rules)|(rules.to_string(), format!("RULES_STDIN[{}]", i + 1))).collect();

            for (each_rules, location) in rules_collection {
               match parse_rules(&each_rules, &location) {
                    Err(e) => {
                        println!("Parsing error handling rules = {}, Error = {}",
                                 location.underline(), e);
                        println!("---");
                        exit_code = 5;
                        continue;
                    },

                    Ok(rules) => {
                        match evaluate_against_data_input(
                            data_type,
                            output_type,
                            None,
                            &data_collection,
                            &rules,
                            &location,
                            verbose,
                            print_json,
                            show_clause_failures,
                            new_version_eval_engine,
                            summary_type.clone())? {
                            Status::SKIP | Status::PASS => continue,
                            Status::FAIL => {
                                exit_code = 5;
                            }
                        }
                    }
                }
            }
        }
        Ok(exit_code)
    }
}

pub fn validate_and_return_json(
    data: &str,
    rules: &str,
) -> Result<String> {
    let input_data = match serde_json::from_str::<serde_json::Value>(&data) {
       Ok(value) => PathAwareValue::try_from(value),
       Err(e) => return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    };

    let span = crate::rules::parser::Span::new_extra(&rules, "lambda");

    match crate::rules::parser::rules_file(span) {
        Ok(rules) => {
            match input_data {
                Ok(root) => {
                    let mut root_scope = crate::rules::eval_context::root_scope(&rules, &root)?;
                    //let mut tracker = crate::rules::eval_context::RecordTracker::new(&mut root_scope);
                    let _status = crate::rules::eval::eval_rules_file(&rules, &mut root_scope)?;
                    let mut tracker = root_scope.reset_recorder();
                    let event = tracker.final_event.unwrap();
                    let file_report = simplifed_json_from_root(&event)?;
                    Ok(serde_json::to_string_pretty(&file_report)?)

                }
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}

fn deserialize_payload(payload: &str) -> Result<Payload> {
    match serde_json::from_str::<Payload>(payload) {
        Ok(value) => Ok(value),
        Err(e) => return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
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
}

fn indent_spaces(indent: usize) {
    for _idx in 0..indent {
        print!("{}", INDENT)
    }
}

//
// https://vallentin.dev/2019/05/14/pretty-print-tree
//
fn pprint_tree(current: &EventRecord<'_>, prefix: String, last: bool)
{
    let prefix_current = if last { "`- " } else { "|- " };
    println!(
        "{}{}{}",
        prefix,
        prefix_current,
        current);

    let prefix_child = if last { "   " } else { "|  " };
    let prefix = prefix + prefix_child;
    if !current.children.is_empty() {
        let last_child = current.children.len() - 1;
        for (i, child) in current.children.iter().enumerate() {
            pprint_tree(child, prefix.clone(), i == last_child);
        }
    }
}

pub(crate) fn print_verbose_tree(root: &EventRecord<'_>) {
    pprint_tree(root, "".to_string(), true);
}

pub(super) fn print_context(cxt: &StatusContext, depth: usize) {
    let header = format!("{}({}, {})", cxt.eval_type, cxt.context, common::colored_string(cxt.status)).underline();
    //let depth = cxt.indent;
    let _sub_indent = depth + 1;
    indent_spaces(depth - 1);
    println!("{}", header);
    match &cxt.from {
        Some(v) => {
            indent_spaces(depth);
            print!("|  ");
            println!("From: {:?}", v);
        },
        None => {}
    }
    match &cxt.to {
        Some(v) => {
            indent_spaces(depth);
            print!("|  ");
            println!("To: {:?}", v);
        },
        None => {}
    }
    match &cxt.msg {
        Some(message) => {
            indent_spaces(depth);
            print!("|  ");
            println!("Message: {}", message);

        },
        None => {}
    }

    for child in &cxt.children {
        print_context(child, depth+1)
    }
}

fn print_failing_clause(rules_file_name: &str, rule: &StatusContext, longest: usize) {
    print!("{file}/{rule:<0$}", longest+4, file=rules_file_name, rule=rule.context);
    let longest = rules_file_name.len() + longest;
    let mut first = true;
    for (index, matched) in common::find_all_failing_clauses(rule).iter().enumerate() {
        let matched = *matched;
        let header = format!("{}({})", common::colored_string(matched.status), matched.context).underline();
        if !first {
            print!("{space:>longest$}", space=" ", longest=longest+4)
        }
        let clause = format!("Clause #{}", index+1).bold();
        println!("{header:<20}{content}", header=clause, content=header);
        match &matched.from {
            Some(from) => {
                print!("{space:>longest$}", space=" ", longest=longest+4);
                let content = format!("Comparing {:?}", from);
                print!("{header:<20}{content}", header=" ", content=content);
            },
            None => {}
        }
        match &matched.to {
            Some(to) => {
                println!(" with {:?} failed", to);
            },
            None => { print!("\n") }
        }
        match &matched.msg {
            Some(m) => {
                for each in m.split('\n') {
                    print!("{space:>longest$}", space=" ", longest=longest+4+20);
                    println!("{}", each);
                }
            },
            None => { print!("\n"); }
        }
        if first { first = false; }
    }
}

impl<'r, 'loc> ConsoleReporter<'r> {
    pub(crate) fn new(root: StackTracker<'r>, renderers: &'r Vec<&'r dyn Reporter>, rules_file_name: &'r str, data_file_name: &'r str, verbose: bool, print_json: bool, show_clause_failures: bool) -> Self {
        ConsoleReporter {
            root_context: root,
            reporters: renderers,
            rules_file_name,
            data_file_name,
            verbose,
            print_json,
            show_clause_failures,
        }
    }

    pub fn get_result_json(self, root: &PathAwareValue, output_format_type: OutputFormatType) -> Result<String> {
        let stack = self.root_context.stack();
        let top = stack.first().unwrap();
        if self.verbose {
            Ok(format!("{}", serde_json::to_string_pretty(&top.children).unwrap()))
        }
        else {
            let mut output = Vec::new();
            let longest = top.children.iter()
                .max_by(|f, s| {
                    (*f).context.len().cmp(&(*s).context.len())
                })
                .map(|elem| elem.context.len())
                .unwrap_or(20);
            let (failed, rest): (Vec<&StatusContext>, Vec<&StatusContext>) =
                top.children.iter().partition(|ctx|
                    match (*ctx).status {
                        Some(Status::FAIL) => true,
                        _ => false
                    });

            let traversal = Traversal::from(root);

            for each_reporter in self.reporters {
                each_reporter.report(
                    &mut output,
                    top.status.clone(),
                    &failed,
                    &rest,
                    longest,
                    self.rules_file_name,
                    self.data_file_name,
                    &traversal,
                    output_format_type)?;
            }

            match String::from_utf8(output) {
                Ok(s) => Ok(s),
                Err(e) => Err(Error::new(ErrorKind::ParseError(e.to_string())))
            }
        }
    }

    fn report(self, root: &PathAwareValue, output_format_type: OutputFormatType) -> crate::rules::Result<()> {
        let stack = self.root_context.stack();
        let top = stack.first().unwrap();
        let mut output = Box::new(std::io::stdout()) as Box<dyn std::io::Write>;

        if self.verbose && self.print_json {
            let serialized_user = serde_json::to_string_pretty(&top.children).unwrap();
            println!("{}", serialized_user);
        } else {
            let longest = top.children.iter()
                .max_by(|f, s| {
                    (*f).context.len().cmp(&(*s).context.len())
                })
                .map(|elem| elem.context.len())
                .unwrap_or(20);

            let (failed, rest): (Vec<&StatusContext>, Vec<&StatusContext>) =
                top.children.iter().partition(|ctx|
                    match (*ctx).status {
                        Some(Status::FAIL) => true,
                        _ => false
                    });

            let traversal = Traversal::from(root);

            for each_reporter in self.reporters {
                each_reporter.report(
                    &mut output,
                    top.status.clone(),
                    &failed,
                    &rest,
                    longest,
                    self.rules_file_name,
                    self.data_file_name,
                    &traversal,
                    output_format_type)?;
            }

            if self.show_clause_failures {
                println!("{}", "Clause Failure Summary".bold());
                for each in failed {
                    print_failing_clause(self.rules_file_name, each, longest);
                }
            }

            if self.verbose {
                println!("Evaluation Tree");
                for each in &top.children {
                    print_context(each, 1);
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

    fn end_evaluation(&self,
                      eval_type: EvaluationType,
                      context: &str,
                      msg: String,
                      from: Option<PathAwareValue>,
                      to: Option<PathAwareValue>,
                      status: Option<Status>,
                      cmp: Option<(CmpOperator, bool)>) {
        self.root_context.end_evaluation(eval_type, context, msg, from, to, status, cmp);
    }

    fn start_evaluation(&self,
                        eval_type: EvaluationType,
                        context: &str) {
        self.root_context.start_evaluation(eval_type, context);
    }

}

fn evaluate_against_data_input<'r>(data_type: Type,
                                   output: OutputFormatType,
                                   extra_data: Option<PathAwareValue>,
                                   data_files: &'r Vec<DataFile>,
                                   rules: &RulesFile<'_>,
                                   rules_file_name: &'r str,
                                   verbose: bool,
                                   print_json: bool,
                                   show_clause_failures: bool,
                                   new_engine_version: bool,
                                   summary_table: BitFlags<SummaryType>) -> Result<Status> {
    let mut overall = Status::PASS;
    let mut write_output = Box::new(std::io::stdout()) as Box<dyn std::io::Write>;
    let generic: Box<dyn Reporter> = Box::new(generic_summary::GenericSummary::new()) as Box<dyn Reporter>;
    let tf: Box<dyn Reporter> = Box::new(TfAware::new_with(generic.as_ref())) as Box<dyn Reporter>;
    let cfn: Box<dyn Reporter> = Box::new(cfn::CfnAware::new_with(tf.as_ref())) as Box<dyn Reporter>;
    let reporter: Box<dyn Reporter> = if summary_table.is_empty() {
        cfn
    } else {
        Box::new(summary_table::SummaryTable::new(summary_table.clone(), cfn.as_ref()))
            as Box<dyn Reporter>
    };
    for file in data_files {
        if new_engine_version {
            let each = match &extra_data {
                Some(data) => data.clone().merge(file.path_value.clone())?,
                None => file.path_value.clone()
            };
            let traversal = Traversal::from(&each);
            let mut root_scope = root_scope(rules, &each)?;
            let status = eval_rules_file(rules, &mut root_scope)?;
            let root_record = root_scope.reset_recorder().extract();
            reporter.report_eval(
                &mut write_output,
                status,
                &root_record,
                rules_file_name,
                &file.name,
                &file.content,
                &traversal,
                output
            )?;
            if verbose {
                print_verbose_tree(&root_record);
            }
            if print_json {
                println!("{}", serde_json::to_string_pretty(&root_record)?)
            }
            if status == Status::FAIL {
                overall = Status::FAIL
            }
        } else {
            let each = &file.path_value;
            let root_context = RootScope::new(rules, each);
            let stacker = StackTracker::new(&root_context);
            let renderers = vec![reporter.as_ref()];
            let reporter = ConsoleReporter::new(stacker, &renderers, rules_file_name, &file.name, verbose, print_json, show_clause_failures);
            let appender = MetadataAppender { delegate: &reporter, root_context: &each };
            let status = rules.evaluate(&each, &appender)?;
            reporter.report(&each, output)?;
            if status == Status::FAIL {
                overall = Status::FAIL
            }
        }
    }
    Ok(overall)
}

fn get_path_aware_value_from_data(content: &String) -> Result<PathAwareValue> {
    let path_value = match crate::rules::values::read_from(content) {
        Ok(value) => PathAwareValue::try_from(value)?,
        Err(_) => {
            let value = match serde_json::from_str::<serde_json::Value>(content) {
                Ok(value) => PathAwareValue::try_from(value)?,
                Err(_) => {
                    let value = match serde_yaml::from_str::<serde_json::Value>(content) {
                        Ok(value) => PathAwareValue::try_from(value)?,
                        Err(_) => {
                            let str_len: usize =  cmp::min(content.len(), 100);
                            return Err(Error::new(ErrorKind::ParseError(
                                format!("Unable to parse data beginning with \n{}\n ...", &content[..str_len]))
                            ))
                        }

                    };
                    value
                }
            };
            value
        }
    };
    Ok(path_value)
}

fn has_a_supported_extension(name: &String, extensions: &[&str]) -> bool {
    extensions.into_iter().any(|extension| name.ends_with(extension))
}

#[cfg(test)]
#[path = "validate_tests.rs"]
mod validate_tests;