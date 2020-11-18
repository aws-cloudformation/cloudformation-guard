mod rules;
mod commands;
pub mod errors;
pub mod command;

use clap::{App, Arg};
use std::fs::{File, read_dir};
use rules::expr::Rules;
use rules::parser::Span;
use walkdir::{DirEntry, WalkDir};
use colored::*;

use std::io::{BufReader, Read, Error};
use std::path::{Path, PathBuf};
use nom::error::ErrorKind;
use std::ffi::OsStr;
use nom::lib::std::collections::HashMap;
use std::str::FromStr;
use std::cmp::Ordering;
use crate::rules::EvalStatus;
use crate::rules::expr::Evaluate;
use crate::command::Command;

fn read_rules_content(file: File) -> Result<String, std::io::Error> {
    let mut file_content = String::new();
    let mut buf_reader = BufReader::new(file);
    buf_reader.read_to_string(&mut file_content)?;
    Ok(file_content)
}

fn parse_rule_file<'a>(content: &'a str, file_name: &'a str) -> Result<Rules<'a>, errors::Error> {
    let (_span, rules) = rules::parser::parse_rules(Span::new_extra(content, file_name))?;
    Ok(rules)
}

fn get_files<F>(file: &str, sort: F) -> Result<Vec<PathBuf>, errors::Error>
    where F: FnMut(&walkdir::DirEntry, &walkdir::DirEntry) -> Ordering + Send + Sync + 'static
{
    let path = PathBuf::from_str(file)?;
    let file = File::open(file)?;
    let metatdata = file.metadata()?;
    Ok(if metatdata.is_file() {
        vec![path]
    }
    else {
        let walkdir = WalkDir::new(path).follow_links(true)
            .sort_by(sort);
        let mut result = Vec::with_capacity(10);
        for file in walkdir {
            if let Ok(entry) = file {
                let path = entry.into_path();
                result.push(path);
            }
        }
        result
    })
}

fn evalute_rules(file_name: &str, content: &str, files: &Vec<PathBuf>)
    -> Result<HashMap<String, Result<rules::expr::Resolutions, errors::Error>>, errors::Error> {

    let result = parse_rule_file(content, file_name)?;
    let mut per_ruleset = HashMap::with_capacity(files.len());
    for each in files {
        let opened = File::open(each);
        if let Ok(file) = opened {
            let reader = BufReader::new(file);
            let context: serde_json::Value = serde_json::from_reader(reader)?;
            let resolutions = result.evaluate(&context);
            per_ruleset.insert(each.to_str().unwrap().to_string(), resolutions);
        }
        else {
            let error = opened.map_err(|e| errors::Error::from(e))
                .err().unwrap();
            per_ruleset.insert(each.to_str().unwrap().to_string(), Err(error));
        }
    }
    Ok(per_ruleset)
}

fn main() -> Result<(), errors::Error>{
    let mut app =
        App::new("cfn-guard")
            .version("1.1")
            .about(r#"
             Gaurd Rules provides a simple declerative syntax
             based on Conjuctive Normal Form (fancy way of saying
             it is a logical AND of OR clauses). It evaluates
             incoming structured payload (JSON/YAML) against
             the rules specified."#);

    let mut commands: Vec<Box<dyn Command>> = Vec::with_capacity(2);
    commands.push(Box::new(crate::commands::evaluate::EvaluateRules::new()));
    commands.push(Box::new(crate::commands::parse_tree::ParseTreeView::new()));

    let mappings = commands.iter()
        .map(|s| (s.name(), s)).fold(
        HashMap::with_capacity(commands.len()),
        |mut map, entry| {
            map.insert(entry.0, entry.1.as_ref());
            map
        }
    );

    for each in &commands {
        app = app.subcommand(each.command());
    }

    let app = app.get_matches();
    match app.subcommand() {
        (name, Some(value)) => {
            if let Some(command) = mappings.get(name) {
                (*command).execute(value);
            }
            else {
                println!("{}", app.usage());
            }
        },

        (_, None) => {
            println!("{}", app.usage());
        }
    }
    Ok(())
}

