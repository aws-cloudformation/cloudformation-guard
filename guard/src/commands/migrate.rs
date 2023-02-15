use clap::{Arg, ArgMatches};

use crate::command::Command;
use crate::commands::files::read_file_content;
use crate::commands::{MIGRATE, OUTPUT, RULES};
use crate::migrate::parser::{parse_rules_file, Clause, Rule, RuleLineType, TypeName};
use crate::rules::errors::Error;
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use itertools::Itertools;
use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::str::FromStr;

#[cfg(test)]
#[path = "migrate_tests.rs"]
mod migrate_tests;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Migrate {}

#[allow(clippy::new_without_default)]
impl Migrate {
    pub fn new() -> Self {
        Migrate {}
    }
}

impl Command for Migrate {
    fn name(&self) -> &'static str {
        MIGRATE
    }

    fn command(&self) -> clap::Command {
        clap::Command::new(MIGRATE)
            .about("Migrates 1.0 rules to 2.0 compatible rules.")
            .arg(
                Arg::new(RULES.0)
                    .long(RULES.0)
                    .short(RULES.1)
                    .help("Provide a rules file")
                    .required(true),
            )
            .arg(
                Arg::new(OUTPUT.0)
                    .long(OUTPUT.0)
                    .short(OUTPUT.1)
                    .help("Write migrated rules to output file")
                    .required(false),
            )
    }

    fn execute(&self, app: &ArgMatches, writer: &mut Writer, reader: &mut Reader) -> Result<i32> {
        let file_input = match app.get_one::<String>(RULES.0) {
            Some(file_input) => file_input,
            None => return Err(Error::ParseError(String::from("rip"))),
        };

        let path = PathBuf::from_str(file_input).unwrap();
        let file_name = path.to_str().unwrap_or("").to_string();
        let file = File::open(file_input)?;

        match read_file_content(file) {
            Err(e) => {
                writer.write_err(format!("Unable read content from file {e}"))?;
                Err(Error::IoError(e))
            }
            Ok(file_content) => match parse_rules_file(&file_content, &file_name) {
                Err(e) => {
                    writer.write_err(format!("Could not parse 1.0 rule file: {file_name}. Please ensure the file is valid with the old version of the tool and try again."))?;
                    Err(e)
                }
                Ok(rules) => {
                    let migrated_rules = migrate_rules(rules)?;
                    let span = crate::rules::parser::Span::new_extra(&migrated_rules, "");
                    match crate::rules::parser::rules_file(span) {
                        Ok(_rules) => {
                            write!(writer, "{migrated_rules}")?;
                            Ok(0_i32)
                        }
                        Err(e) => {
                            writer.write_err(format!(
                                "Could not parse migrated ruleset for file: '{file_name}': {e}"
                            ))?;
                            Err(e)
                        }
                    }
                }
            },
        }
    }
}

#[allow(clippy::uninlined_format_args)]
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

    let mut types = by_type.keys().cloned().collect_vec();
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
