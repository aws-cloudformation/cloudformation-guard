use std::fs::File;

use clap::{App, Arg, ArgMatches};
use colored::*;

use crate::command::Command;
use crate::commands::{ALPHABETICAL, LAST_MODIFIED, RULES};
use crate::commands::files::{alpabetical, get_files, last_modified, read_file_content, regular_ordering};
use crate::rules;
use crate::rules::dependency;
use crate::rules::expr::*;
use crate::rules::parser::Span;
use crate::rules::clean::errors::{Error, ErrorKind};

use super::files;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct ParseTreeView {}

impl ParseTreeView {
    pub(crate) fn new() -> ParseTreeView {
        ParseTreeView {}
    }
}

impl Command for ParseTreeView {
    fn name(&self) -> &'static str {
        "parse-tree-view"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new(self.name())
            .about(r#"
             parse-tree-view provides a simeple tree like view for
             your ruleset file post parsing the tree to understand
             the overall evalutation for easy preview
        "#)
            .arg(Arg::with_name(RULES.0).long(RULES.0).short(RULES.1).takes_value(true).help("provide a rules file or a directory").required(true))
            .arg(Arg::with_name(ALPHABETICAL.0).long(ALPHABETICAL.0).short(ALPHABETICAL.1).help("sort alphabetically inside a directory").required(false))
            .arg(Arg::with_name(LAST_MODIFIED.0).long(LAST_MODIFIED.0).short(LAST_MODIFIED.1).required(false).conflicts_with("alphabetical")
                .help("sort by last modified times within a directory"))
    }


    fn execute(&self, args: &ArgMatches) -> Result<(), Error> {
        let file = args.value_of("rules").unwrap();
        let cmp = if let Some(_ignored) = args.value_of(ALPHABETICAL.0) {
            alpabetical
        } else if let Some(_ignored) = args.value_of(LAST_MODIFIED.0) {
            last_modified
        } else {
            regular_ordering
        };
        let files = get_files(file, cmp)?;
        for each in files {
            let content = read_file_content(File::open(each.as_path())?)?;
            let file_name = each.to_str().unwrap();
            let rules = parse_rule_file(&content, &file_name)?;
            print_expr_tree(&rules);
        }
        Ok(())
    }

}

pub(super) fn parse_rule_file<'a>(content: &'a str, file_name: &'a str) -> Result<Rules<'a>, Error> {
    let (_span, rules) = rules::parser::parse_rules(Span::new_extra(content, file_name))?;
    Ok(rules)
}

fn print_expr_tree(rules: &Rules) -> Result<(), Error>{
//    let mut non_default = Vec::with_capacity(rules.len());
//    let mut defaults = Vec::with_capacity(rules.len());
//    for each in rules {
//        if let Expr::NamedRule(rule) = each {
//            if rule.rule_name == "default" {
//                defaults.push(each);
//            } else {
//                non_default.push(each);
//            }
//        }
//    }
//
//    let non_defaults_size = non_default.len();
//    let dependency_order = dependency::rules_execution_order_itr(non_default)?;
//    let summary = "Basic Summary Stats".yellow().underline();
//    println!("{}", summary);
//    println!("Total Number of Statements = {}", rules.len());
//    println!("Number of {} rules = {}", "Default".bright_yellow(), defaults.len());
//    println!("Number of {} rules = {}", "Named".bright_blue(), non_defaults_size);
//    println!("{}{}", "             ".underline(), "\n");
//
//    let order = dependency_order.iter().fold(String::new(), |mut str, entry| {
//        str.push_str((*entry).0);
//        str
//    });
//    println!("Order of execution of rules {}", order.truecolor(241, 250, 238));
    Ok(())
}


