use std::convert::TryFrom;
use std::fmt::Debug;
use std::fs::File;
use std::io::{BufReader, Read, Write};

use clap::{App, Arg, ArgMatches};
use colored::*;

use crate::command::Command;
use crate::commands::{ALPHABETICAL, LAST_MODIFIED};
use crate::commands::aws_meta_appender::MetadataAppender;
use crate::commands::files::{alpabetical, get_files, iterate_over, last_modified, regular_ordering};
use crate::commands::tracker::{StackTracker, StatusContext};
use crate::rules::{Evaluate, EvaluationContext, EvaluationType, Result, Status};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::evaluate::RootScope;
use crate::rules::exprs::RulesFile;
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use crate::commands::validate::summary_table::SummaryType;
use enumflags2::{BitFlag, BitFlags};

mod cfn_renderer;
mod generic_summary;
mod common;
mod summary_table;

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

pub(crate) trait Renderer: Debug {
    fn render(&self,
              writer: &mut Write,
              failed_rules: &[&StatusContext],
              passed_or_skipped: &[&StatusContext],
              longest_rule_name: usize,
    ) -> Result<()>;
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Validate {}

impl Validate {
    pub(crate) fn new() -> Self {
        Validate{}
    }
}

impl Command for Validate {
    fn name(&self) -> &'static str {
        "validate"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("validate")
            .about(r#"Evaluates rules against the data files to determine success or failure. 
You can point rules flag to a rules directory and point data flag to a data directory. 
When pointed to a directory it will read all rules in the directory file and evaluate 
them against the data files found in the directory. The command can also point to a
single file and it would work as well.
Note - When pointing the command to a directory, the directory may not contain a mix of 
rules and data files. The directory being pointed to must contain only data files,
or rules files.
"#)
            .arg(Arg::with_name("rules").long("rules").short("r").takes_value(true).help("Provide a rules file or a directory of rules files").required(true))
            .arg(Arg::with_name("data").long("data").short("d").takes_value(true).help("Provide a file or dir for data files in JSON or YAML"))
            .arg(Arg::with_name("type").long("type").short("t").takes_value(true).possible_values(&["CFNTemplate"])
                .help("Specify the type of data file used for improved messaging"))
            .arg(Arg::with_name("output-format").long("output-format").short("o").takes_value(true)
                .possible_values(&["json","yaml","single-line-summary"])
                .help("Specify the type of data file used for improved messaging"))
            .arg(Arg::with_name("show-summary-table").long("show-summary-table").takes_value(true).use_delimiter(true).multiple(true)
                .possible_values(&["none", "all", "pass", "fail", "skip"])
                .default_value("all")
                .help("control if the summary table needs to be displayed. --show-summary-table all (default) or --show-summary-table pass,fail (only show rules that did pass/fail) or --show-summary-table none (to turn it off)")
            )
            .arg(Arg::with_name("show-clause-failures").long("show-clause-failures").short("s").takes_value(false).required(false)
                .help("Show clause failure along with summary"))
            .arg(Arg::with_name("alphabetical").long("alphabetical").short("a").required(false).help("Validate files in a directory ordered alphabetically"))
            .arg(Arg::with_name("last-modified").long("last-modified").short("m").required(false).conflicts_with("alphabetical")
                .help("Validate files in a directory ordered by last modified times"))
            .arg(Arg::with_name("verbose").long("verbose").short("v").required(false)
                .help("Verbose logging"))
            .arg(Arg::with_name("print-json").long("print-json").short("p").required(false)
                .help("Print output in json format"))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<i32> {
        let file = app.value_of("rules").unwrap();
        let cmp = if app.is_present("last-modified") {
            last_modified
        } else {
            alpabetical
        };

        let data_files = match app.value_of("data") {
            Some(file_or_dir) => {
                let selected = get_files(file_or_dir, cmp)?;
                let mut streams = Vec::with_capacity(selected.len());
                for each in selected {
                    let mut context = String::new();
                    let mut reader = BufReader::new(File::open(each.as_path())?);
                    reader.read_to_string(&mut context)?;
                    streams.push((context, each.to_str().map_or("".to_string(), |p| p.to_string())));
                }
                streams
            },
            None => {
                let mut context = String::new();
                let mut reader = BufReader::new(std::io::stdin());
                reader.read_to_string(&mut context);
                vec![(context, "STDIN".to_string())]
            }
        };

        let verbose = if app.is_present("verbose") {
            true
        } else {
            false
        };

        let data_type = match app.value_of("type")  {
            Some(t) =>
                if t == "CFNTemplate" {
                    Type::CFNTemplate
                }
                else {
                    Type::Generic
                },
            None => Type::Generic
        };

        let output_type = match app.value_of("output-format") {
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

        let summary_type: BitFlags<SummaryType> = app.values_of("show-summary-table").map_or(
            SummaryType::PASS | SummaryType::FAIL | SummaryType::SKIP,
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

        let print_json = app.is_present("print-json");
        let show_clause_failures = app.is_present("show-clause-failures");

        let files = get_files(file, cmp)?;
        let mut exit_code = 0;
        for each_file_content in iterate_over(&files, |content, file| Ok((content, file.to_str().unwrap_or("").to_string()))) {
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
                                &data_files,
                                &rules,
                                &rule_file_name,
                                verbose,
                                print_json,
                                show_clause_failures,
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
                    let root_context = RootScope::new(&rules, &root);
                    let stacker = StackTracker::new(&root_context);
                    let reporters = vec![];
                    let reporter = ConsoleReporter::new(stacker, &reporters, "lambda-function", "input-payload", true, true, false);
                    rules.evaluate(&root, &reporter)?;
                    let json_result = reporter.get_result_json();
                    return Ok(json_result);
                }
                Err(e) => return Err(e),
            }
        }
        Err(e) =>  return Err(Error::new(ErrorKind::ParseError(e.to_string()))),
    }
}

#[derive(Debug)]
pub(crate) struct ConsoleReporter<'r> {
    root_context: StackTracker<'r>,
    reporters: &'r Vec<Box<dyn Renderer + 'r>>,
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
    pub(crate) fn new(root: StackTracker<'r>, renderers: &'r Vec<Box<dyn Renderer + 'r>>, rules_file_name: &'r str, data_file_name: &'r str, verbose: bool, print_json: bool, show_clause_failures: bool) -> Self {
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

    pub fn get_result_json(self) -> String {
        let stack = self.root_context.stack();
        let top = stack.first().unwrap();
        return format!("{}", serde_json::to_string_pretty(&top.children).unwrap());
    }

    fn report(self) -> crate::rules::Result<()> {
        let stack = self.root_context.stack();
        let top = stack.first().unwrap();
        let mut output = Box::new(std::io::stdout()) as Box<dyn std::io::Write>;

        if self.verbose && self.print_json {
            let serialized_user = serde_json::to_string_pretty(&top.children).unwrap();
            println!("{}", serialized_user);
        }
        else {
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

            for each_renderer in self.reporters {
                each_renderer.render(
                    &mut output,
                    &failed,
                    &rest,
                    longest
                )?;
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
                                   data_files: &'r [(String, String)],
                                   rules: &RulesFile<'_>,
                                   rules_file_name: &'r str,
                                   verbose: bool,
                                   print_json: bool,
                                   show_clause_failures: bool,
                                   summary_table: BitFlags<SummaryType>) -> Result<Status> {
    let iterator: Result<Vec<(PathAwareValue, &str)>> = data_files.iter().map(|(content, name)|
        match serde_json::from_str::<serde_json::Value>(content) {
            Ok(value) => Ok((PathAwareValue::try_from(value)?, name.as_str())),
            Err(_) => {
                let value = serde_yaml::from_str::<serde_json::Value>(content)?;
                Ok((PathAwareValue::try_from(value)?, name.as_str()))
            }
        }
    ).collect();

    let mut overall = Status::PASS;
    for (each, data_file_name) in iterator? {
        let mut reporters= match data_type {
            Type::CFNTemplate =>
                vec![
                    Box::new(cfn_renderer::CfnRender::new(data_file_name, rules_file_name, output)) as Box<dyn Renderer>],
            Type::Generic =>
                vec![
                    Box::new(generic_summary::GenericSummary::new(data_file_name, rules_file_name, output)) as Box<dyn Renderer>],
        };
        if !summary_table.is_empty() {
            reporters.insert(
                0, Box::new(
                    summary_table::SummaryTable::new(rules_file_name, data_file_name, summary_table.clone())) as Box<dyn Renderer>);
        }
        let root_context = RootScope::new(rules, &each);
        let stacker = StackTracker::new(&root_context);
        let reporter = ConsoleReporter::new(stacker, &reporters, rules_file_name, data_file_name, verbose, print_json, show_clause_failures);
        let appender = MetadataAppender{delegate: &reporter, root_context: &each};
        let status = rules.evaluate(&each, &appender)?;
        reporter.report();
        if status == Status::FAIL {
            overall = Status::FAIL
        }
    }
    Ok(overall)
}
