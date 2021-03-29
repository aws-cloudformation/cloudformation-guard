use clap::{App, Arg, ArgMatches};


use crate::command::Command;
use crate::commands::files::read_file_content;
use crate::rules::Result;
use crate::migrate::parser::{parse_rules_file, RuleLineType, Rule};
use std::fs::File;
use std::fmt::Write as FmtWrite;
use std::io::Write as IoWrite;
use std::collections::HashSet;
use crate::rules::errors::{Error, ErrorKind};
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod migrate_tests;



#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Migrate {}

impl Migrate {
    pub(crate) fn new() -> Self {
        Migrate{}
    }
}

impl Command for Migrate {
    fn name(&self) -> &'static str {
        "migrate"
    }


    fn command(&self) -> App<'static, 'static> {
        App::new("migrate")
            .about(r#"
            Migrates 1.0 rulesets to 2.0 compatible rulesets.
        "#)
            .arg(Arg::with_name("rules").long("rules").short("r").takes_value(true).help("provide a rules file").required(true))
            .arg(Arg::with_name("output").long("output").short("o").takes_value(true).help("write migrated rules to output file").required(false))
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<()> {
        let file_input = app.value_of("rules").unwrap();
        let path = PathBuf::from_str(file_input).unwrap();
        let file_name = path.to_str().unwrap_or("").to_string();
        let file = File::open(file_input)?;

        let mut out= match app.value_of("output") {
            Some(file) => Box::new(File::create(file)?) as Box<dyn std::io::Write>,
            None => Box::new(std::io::stdout()) as Box<dyn std::io::Write>
        };
        match read_file_content(file) {
            Err(e) => {
                println!("Unable read content from file {}", e);
                Err(Error::new(ErrorKind::IoError(e)))
            },
            Ok(file_content) => {
                match parse_rules_file(&file_content, &file_name) {
                    Err(e) => {
                        println!("Could not parse 1.0 rule file: {}. Please ensure the file is valid with the old version of the tool and try again.", file_name);
                        Err(e)
                    },
                    Ok(rules) => {
                        let migrated_rules = migrate_rules(rules)?;
                        let span = crate::rules::parser::Span::new_extra(&migrated_rules, "");
                        match crate::rules::parser::rules_file(span) {
                            Ok(_rules) => {
                                write!(out,"{}", migrated_rules);
                                Ok(())
                            },
                            Err(e) => {
                                println!("Could not parse migrated ruleset for file: '{}': {}", &file_name, e);
                                Err(e)
                            }
                        }
                    }
                }
            }
        }
    }
}

pub (crate) fn get_resource_types_in_ruleset(rules: &Vec<RuleLineType>) -> Result<Vec<String>> {
    let mut resource_types = HashSet::new();
    for rule in rules {
        if let RuleLineType::Clause(clause) = rule.clone() {
            clause.rules.into_iter().for_each(|rule|
                match rule {
                    Rule::Basic(basic_rule) => { resource_types.insert(basic_rule.type_name); },
                    Rule::Conditional(conditional_rule) => { resource_types.insert(conditional_rule.type_name); }
                }
            );
        }
    }
    let mut resource_types_list = resource_types.into_iter().collect::<Vec<_>>();
    resource_types_list.sort();
    Ok(resource_types_list)
}

pub (crate) fn migrate_rules(rules: Vec<RuleLineType>) -> Result<String> {
    let mut migrated_rules = String::new();
    let resource_types = get_resource_types_in_ruleset(&rules).unwrap();
    // write assignments for every resource type
    writeln!(&mut migrated_rules, "rule migrated_rules {{");
    for resource_type in resource_types {
        writeln!(&mut migrated_rules, "\tlet {} = Resources.*[ Type == \"{}\" ]", resource_type.to_lowercase().replace("::", "_"), resource_type);
    }
    for rule in rules {
        writeln!(&mut migrated_rules, "\t{}", rule);
    }
    writeln!(&mut migrated_rules, "}}");
    Ok(migrated_rules)
}
