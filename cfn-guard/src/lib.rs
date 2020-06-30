// © Amazon Web Services, Inc. or its affiliates. All Rights Reserved. This AWS Content is provided subject to the terms of the AWS Customer Agreement available at http://aws.amazon.com/agreement or other written agreement between Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

use log::{self, debug, error, info, trace};
use serde_json::Value;

use regex::Regex;
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fs;

mod guard_types;
mod parser;
pub mod util;

pub use crate::guard_types::{enums, structs};
use crate::util::fix_stringified_bools;

pub fn run(
    template_file: &str,
    rules_file: &str,
    strict_checks: bool,
) -> Result<(Vec<String>, usize), Box<dyn Error>> {
    debug!("Entered run");
    let template_contents = fs::read_to_string(template_file)?;
    let rules_file_contents = fs::read_to_string(rules_file)?;

    trace!(
        "Template file is '{}' and its contents are:\n'{}'",
        template_file,
        template_contents
    );
    trace!(
        "Rules file is '{}' and its contents are: {}",
        rules_file,
        rules_file_contents.to_string()
    );

    let (outcome, exit_code) = run_check(&template_contents, &rules_file_contents, strict_checks);
    debug!("Outcome was: '{:#?}'", &outcome);
    Ok((outcome, exit_code))
}

pub fn run_check(
    template_file_contents: &str,
    rules_file_contents: &str,
    strict_checks: bool,
) -> (Vec<String>, usize) {
    info!("Loading CloudFormation Template and Rule Set");
    debug!("Entered run_check");

    trace!("Normalizing booleans in inputs");
    let cleaned_template_file_contents = fix_stringified_bools(template_file_contents);
    trace!(
        "Cleaned template contents are:\n'{}'",
        cleaned_template_file_contents
    );

    let cleaned_rules_file_contents = fix_stringified_bools(rules_file_contents);
    trace!(
        "Cleaned rules file contents are:\n'{}'",
        cleaned_rules_file_contents
    );

    debug!("Deserializing CloudFormation template");
    let cfn_template: HashMap<String, Value> =
        match serde_json::from_str(&cleaned_template_file_contents) {
            Ok(s) => s,
            Err(_) => match serde_yaml::from_str(&cleaned_template_file_contents) {
                Ok(y) => y,
                Err(e) => {
                    return (
                        vec![format!(
                            "ERROR:  Template file format was unreadable as json or yaml: {}",
                            e
                        )],
                        1,
                    );
                }
            },
        };
    trace!("CFN Template is '{:#?}'", &cfn_template);

    let cfn_resources: HashMap<String, Value> = match cfn_template.get("Resources") {
        Some(r) => serde_json::from_value(r.clone()).unwrap(),
        None => {
            return (
                vec![
                    "ERROR:  Template file does not contain a [Resources] section to check"
                        .to_string(),
                ],
                1,
            );
        }
    };

    trace!("CFN resources are: {:?}", cfn_resources);

    info!("Parsing rule set");
    let parsed_rule_set = parser::parse_rules(&cleaned_rules_file_contents, &cfn_resources);

    let mut outcome = check_resources(&cfn_resources, &parsed_rule_set, strict_checks);
    outcome.sort();

    let exit_code = match outcome.len() {
        0 => 0,
        _ => 2,
    };
    (outcome, exit_code)
}

fn check_resources(
    cfn_resources: &HashMap<String, Value>,
    parsed_rule_set: &structs::ParsedRuleSet,
    strict_checks: bool,
) -> Vec<String> {
    info!("Checking resources");
    let mut result: Vec<String> = vec![];
    for c_rule in parsed_rule_set.rule_set.iter() {
        info!("Applying rule '{:#?}'", &c_rule);
        match c_rule.compound_type {
            enums::CompoundType::OR => {
                for (name, cfn_resource) in cfn_resources {
                    trace!("OR'ing [{}] against {:?}", name, c_rule);
                    let mut pass_fail = HashSet::new();
                    let mut temp_results: Vec<String> = vec![];
                    let mut cfn_resource_map: HashMap<String, Value> = HashMap::new();
                    cfn_resource_map.insert(name.clone(), cfn_resource.clone());
                    for rule in &c_rule.rule_list {
                        match apply_rule(
                            &cfn_resource_map,
                            &rule,
                            &parsed_rule_set.variables,
                            strict_checks,
                        ) {
                            Some(rule_result) => {
                                pass_fail.insert("fail");
                                temp_results.extend(rule_result);
                            }
                            None => {
                                pass_fail.insert("pass");
                            }
                        }
                    }
                    trace! {"pass_fail set is {:?}", &pass_fail};
                    trace! {"temp_results are {:?}", &temp_results};
                    if !pass_fail.contains("pass") {
                        result.extend(temp_results);
                    }
                }
            }
            enums::CompoundType::AND => {
                for rule in &c_rule.rule_list {
                    if let Some(rule_result) = apply_rule(
                        &cfn_resources,
                        &rule,
                        &parsed_rule_set.variables,
                        strict_checks,
                    ) {
                        result.extend(rule_result);
                    }
                }
            }
        }
    }
    if result.is_empty() {
        info!("All CloudFormation resources passed");
    }
    result
}

fn apply_rule(
    cfn_resources: &HashMap<String, Value>,
    rule: &structs::Rule,
    variables: &HashMap<String, String>,
    strict_checks: bool,
) -> Option<Vec<String>> {
    debug!("Applying rule '{:?}'", &rule);
    let mut rule_result: Vec<String> = vec![];
    for (name, cfn_resource) in cfn_resources {
        if cfn_resource["Type"] == rule.resource_type {
            info!(
                "Checking [{}] which is of type {}",
                &name, &cfn_resource["Type"]
            );
            let target_field: Vec<&str> = rule.field.split('.').collect();
            match util::get_resource_prop_value(&cfn_resource["Properties"], &target_field) {
                Err(e) => {
                    if strict_checks {
                        rule_result.push(match &rule.custom_msg {
                            Some(c) => format!("[{}] failed because {}", name, c),
                            None => format!(
                        "[{}] failed because it does not contain the required property of [{}]",
                        name, e
                    ),
                        })
                    }
                }
                Ok(val) => {
                    debug!("Template val is {:?}", val);
                    match util::deref_rule_value(rule, variables) {
                        Ok(v) => {
                            debug!("rule_val is {} and val is {}", &v, &val);
                            if let Some(r) = apply_rule_operation(name, rule, v, &val) {
                                rule_result.push(r)
                            }
                        }
                        Err(_) => rule_result.push(
                            format!("[{}] failed because there is no value defined for [{}] to check [{}] against",
                                    name,
                                    rule.value,
                                    rule.field)),
                    };
                }
            };
        } else {
            info!(
                "Rule does not apply to {} which is of type {}",
                &name, cfn_resource["Type"]
            );
        };
    }
    if !rule_result.is_empty() {
        Some(rule_result)
    } else {
        None
    }
}

fn apply_rule_operation(
    res_name: &str,
    rule: &structs::Rule,
    rule_val: &str,
    val: &Value,
) -> Option<String> {
    debug!(
        "OpCode::{:?} with rule_val as {} and val as {} of RValueType::{:?}",
        &rule.operation, &rule_val, &val, &rule.rule_vtype
    );
    match rule.operation {
        enums::OpCode::Require => {
            match rule.rule_vtype {
                enums::RValueType::Value | enums::RValueType::Variable => {
                    if util::format_value(&val) == util::strip_ws_nl(rule_val.to_string()) {
                        info!("Result: PASS");
                        None
                    } else {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c
                            ),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the permitted value is [{}]",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            ),
                        })
                    }
                }
                enums::RValueType::Regex => {
                    let re = Regex::new(rule_val).unwrap();
                    if re.is_match(&val.to_string()) {
                        info!("Result: PASS");
                        None
                    } else {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the permitted pattern is [{}]",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            )
                        })
                    }
                }
                _ => {
                    error!("REQUIRE rule type that doesn't match RValueType of Regex, Variable or Value");
                    None
                }
            }
        }
        enums::OpCode::RequireNot => {
            match rule.rule_vtype {
                enums::RValueType::Value | enums::RValueType::Variable => {
                    if util::format_value(&val) != util::strip_ws_nl(rule_val.to_string()) {
                        info!("Result: PASS");
                        None
                    } else {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c
                            ),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and that value is not permitted",
                                res_name,
                                &rule.field,
                                util::format_value(&val)
                            ),
                        })
                    }
                }
                enums::RValueType::Regex => {
                    let re = Regex::new(rule_val).unwrap();
                    if !re.is_match(&val.to_string()) {
                        info!("Result: PASS");
                        None
                    } else {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the pattern [{}] is not permitted",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            )
                        })
                    }
                }
                _ => {
                    error!("REQUIRE rule type that doesn't match RValueType of Regex, Variable or Value");
                    None
                }
            }
        }
        enums::OpCode::In => {
            let value_vec = util::convert_list_var_to_vec(rule_val);
            let val_as_string = match val.as_str() {
                Some(s) => s.to_string(),
                None => serde_json::to_string(val).unwrap(),
            };
            if value_vec.contains(&util::strip_ws_nl(val_as_string)) {
                info!("Result: PASS");
                None
            } else {
                info!("Result: FAIL");
                Some(match &rule.custom_msg {
                    Some(c) => format!(
                        "[{}] failed because [{}] is [{}] and {}",
                        res_name,
                        &rule.field,
                        util::format_value(&val),
                        c
                    ),
                    None => format!(
                        "[{}] failed because [{}] is not in {} for [{}]",
                        res_name,
                        util::format_value(&val),
                        rule_val.to_string(),
                        &rule.field
                    ),
                })
            }
        }
        enums::OpCode::NotIn => {
            let value_vec = util::convert_list_var_to_vec(rule_val);
            let val_as_string = match val.as_str() {
                Some(s) => s.to_string(),
                None => serde_json::to_string(val).unwrap(),
            };
            if !value_vec.contains(&util::strip_ws_nl(val_as_string)) {
                info!("Result: PASS");
                None
            } else {
                info!("Result: FAIL");
                Some(match &rule.custom_msg {
                    Some(c) => format!(
                        "[{}] failed because [{}] is [{}] and {}",
                        res_name,
                        &rule.field,
                        util::format_value(&val),
                        c
                    ),
                    None => format!(
                        "[{}] failed because [{}] is in {} which is not permitted for [{}]",
                        res_name,
                        util::format_value(&val),
                        rule_val.to_string(),
                        &rule.field
                    ),
                })
            }
        }
        enums::OpCode::LessThan => {
            match rule.rule_vtype {
                enums::RValueType::Value | enums::RValueType::Variable => {
                    if util::format_value(&val).parse::<f32>().unwrap() > util::strip_ws_nl(rule_val.to_string()).parse::<f32>().unwrap() ||
                    util::format_value(&val).parse::<f32>().unwrap() == util::strip_ws_nl(rule_val.to_string()).parse::<f32>().unwrap() {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the permitted value is [< {}]",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            )
                        }
                        )
                    } else {
                        info!("Result: PASS");
                        None
                    }
                }
                _ => {
                    error!("REQUIRE rule type that doesn't match RValueType of Regex, Variable or Value");
                    None
                }
            }
        }
        enums::OpCode::GreaterThan => {
            match rule.rule_vtype {
                enums::RValueType::Value | enums::RValueType::Variable => {
                    if util::format_value(&val).parse::<f32>().unwrap() < util::strip_ws_nl(rule_val.to_string()).parse::<f32>().unwrap() ||
                       util::format_value(&val).parse::<f32>().unwrap() == util::strip_ws_nl(rule_val.to_string()).parse::<f32>().unwrap() {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the permitted value is [> {}]",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            )
                        }
                        )
                    } else {
                        info!("Result: PASS");
                        None
                    }
                }
                _ => {
                    error!("REQUIRE rule type that doesn't match RValueType of Regex, Variable or Value");
                    None
                }
            }
        }
        enums::OpCode::LessThanOrEqualTo => {
            match rule.rule_vtype {
                enums::RValueType::Value | enums::RValueType::Variable => {
                    if util::format_value(&val).parse::<f32>().unwrap() > util::strip_ws_nl(rule_val.to_string()).parse::<f32>().unwrap() {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the permitted value is [<= {}]",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            )
                        }
                        )
                    } else {
                        info!("Result: PASS");
                        None
                    }
                }
                _ => {
                    error!("REQUIRE rule type that doesn't match RValueType of Regex, Variable or Value");
                    None
                }
            }
        }
        enums::OpCode::GreaterThanOrEqualTo => {
            match rule.rule_vtype {
                enums::RValueType::Value | enums::RValueType::Variable => {
                    if util::format_value(&val).parse::<f32>().unwrap() < util::strip_ws_nl(rule_val.to_string()).parse::<f32>().unwrap() {
                        info!("Result: FAIL");
                        Some(match &rule.custom_msg {
                            Some(c) => format!(
                                "[{}] failed because [{}] is [{}] and {}",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                c),
                            None => format!(
                                "[{}] failed because [{}] is [{}] and the permitted value is [>= {}]",
                                res_name,
                                &rule.field,
                                util::format_value(&val),
                                rule_val.to_string()
                            )
                        }
                        )
                    } else {
                        info!("Result: PASS");
                        None
                    }
                }
                _ => {
                    error!("REQUIRE rule type that doesn't match RValueType of Regex, Variable or Value");
                    None
                }
            }
        }
    }
}
