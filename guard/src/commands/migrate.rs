use clap::{App, Arg, ArgMatches};

use crate::command::Command;
use crate::commands::files::read_file_content;
use crate::commands::{MIGRATE, OUTPUT, RULES};
use crate::migrate::parser::{parse_rules_file, Clause, Rule, RuleLineType, TypeName};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::Result;
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write as IoWrite;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod migrate_tests;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct Migrate {}

impl Migrate {
    pub(crate) fn new() -> Self {
        Migrate {}
    }
}

impl Command for Migrate {
    fn name(&self) -> &'static str {
        MIGRATE
    }

    fn command(&self) -> App<'static, 'static> {
        App::new(MIGRATE)
            .about(
                r#"Migrates 1.0 rules to 2.0 compatible rules.
"#,
            )
            .arg(
                Arg::with_name(RULES.0)
                    .long(RULES.0)
                    .short(RULES.1)
                    .takes_value(true)
                    .help("Provide a rules file")
                    .required(true),
            )
            .arg(
                Arg::with_name(OUTPUT.0)
                    .long(OUTPUT.0)
                    .short(OUTPUT.1)
                    .takes_value(true)
                    .help("Write migrated rules to output file")
                    .required(false),
            )
    }

    fn execute(&self, app: &ArgMatches<'_>) -> Result<i32> {
        let file_input = app.value_of(RULES.0).unwrap();
        let path = PathBuf::from_str(file_input).unwrap();
        let file_name = path.to_str().unwrap_or("").to_string();
        let file = File::open(file_input)?;

        let mut out = match app.value_of(OUTPUT.0) {
            Some(file) => Box::new(File::create(file)?) as Box<dyn std::io::Write>,
            None => Box::new(std::io::stdout()) as Box<dyn std::io::Write>,
        };
        match read_file_content(file) {
            Err(e) => {
                println!("Unable read content from file {}", e);
                Err(Error::new(ErrorKind::IoError(e)))
            }
            Ok(file_content) => match parse_rules_file(&file_content, &file_name) {
                Err(e) => {
                    println!("Could not parse 1.0 rule file: {}. Please ensure the file is valid with the old version of the tool and try again.", file_name);
                    Err(e)
                }
                Ok(rules) => {
                    let migrated_rules = migrate_rules(rules)?;
                    let span = crate::rules::parser::Span::new_extra(&migrated_rules, "");
                    match crate::rules::parser::rules_file(span) {
                        Ok(_rules) => {
                            write!(out, "{}", migrated_rules)?;
                            Ok(0 as i32)
                        }
                        Err(e) => {
                            println!(
                                "Could not parse migrated ruleset for file: '{}': {}",
                                &file_name, e
                            );
                            Err(e)
                        }
                    }
                }
            },
        }
    }
}

pub(crate) fn migrated_rules_by_type(
    rules: &[RuleLineType],
    by_type: &HashMap<TypeName, indexmap::IndexSet<&Clause>>,
) -> Result<String> {
    let mut migrated = String::new();
    for rule in rules {
        if let RuleLineType::Assignment(assignment) = rule {
            writeln!(&mut migrated, "{}", assignment)?;
        }
    }

    let mut types = by_type.keys().map(|elem| elem.clone()).collect_vec();
    types.sort();
    for each_type in &types {
        writeln!(
            &mut migrated,
            "let {} = Resources.*[ Type == \"{}\" ]",
            each_type, each_type.type_name
        )?;
        writeln!(
            &mut migrated,
            "rule {name}_checks WHEN %{name} NOT EMPTY {{",
            name = each_type
        )?;
        writeln!(&mut migrated, "    %{} {{", each_type)?;
        for each_clause in by_type.get(each_type).unwrap() {
            writeln!(&mut migrated, "        {}", *each_clause)?;
        }
        writeln!(&mut migrated, "    }}\n}}\n")?;
    }
    Ok(migrated)
}

pub(crate) fn aggregate_by_type(
    rules: &Vec<RuleLineType>,
) -> HashMap<TypeName, indexmap::IndexSet<&Clause>> {
    let mut by_type = HashMap::with_capacity(rules.len());
    for rule in rules {
        if let RuleLineType::Clause(clause) = rule {
            for each in &clause.rules {
                match each {
                    Rule::Basic(br) => {
                        by_type
                            .entry(br.type_name.clone())
                            .or_insert(indexmap::IndexSet::new())
                            .insert(clause);
                    }
                    Rule::Conditional(br) => {
                        by_type
                            .entry(br.type_name.clone())
                            .or_insert(indexmap::IndexSet::new())
                            .insert(clause);
                    }
                }
            }
        }
    }
    by_type
}

pub(crate) fn get_resource_types_in_ruleset(rules: &Vec<RuleLineType>) -> Result<Vec<TypeName>> {
    let mut resource_types = HashSet::new();
    for rule in rules {
        if let RuleLineType::Clause(clause) = rule.clone() {
            clause.rules.into_iter().for_each(|rule| match rule {
                Rule::Basic(basic_rule) => {
                    resource_types.insert(basic_rule.type_name);
                }
                Rule::Conditional(conditional_rule) => {
                    resource_types.insert(conditional_rule.type_name);
                }
            });
        }
    }
    let mut resource_types_list = resource_types.into_iter().collect::<Vec<_>>();
    resource_types_list.sort();
    Ok(resource_types_list)
}

pub(crate) fn migrate_rules(rules: Vec<RuleLineType>) -> Result<String> {
    let aggr_by_type = aggregate_by_type(&rules);
    let migrated_rules = migrated_rules_by_type(&rules, &aggr_by_type)?;

    Ok(migrated_rules)
}
