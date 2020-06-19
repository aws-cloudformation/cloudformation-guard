// © Amazon Web Services, Inc. or its affiliates. All Rights Reserved. This AWS Content is provided subject to the terms of the AWS Customer Agreement available at http://aws.amazon.com/agreement or other written agreement between Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

use std::collections::{HashMap, HashSet};
use std::env;

use log::{self, debug, trace};
use regex::{Captures, Regex};
use serde_json::Value;

use crate::guard_types::enums::{CompoundType, LineType, OpCode, RValueType};
use crate::guard_types::structs::{CompoundRule, ParsedRuleSet, Rule};
use crate::util::expand_wildcard_props;
use lazy_static::lazy_static;

// This sets it up so the regexen only get compiled once
// See: https://docs.rs/regex/1.3.9/regex/#example-avoid-compiling-the-same-regex-in-a-loop
lazy_static! {
    static ref ASSIGN_REG: Regex = Regex::new(r"let (?P<var_name>\w+) *= *(?P<var_value>.*)").unwrap();
    static ref RULE_REG: Regex = Regex::new(r"(?P<resource_type>\S+) +(?P<resource_property>[\w\.\*]+) +(?P<operator>\S+) +(?P<rule_value>[^\n\r]+)").unwrap();
    static ref COMMENT_REG: Regex = Regex::new(r#"#(?P<comment>.*)"#).unwrap();
    static ref WILDCARD_OR_RULE_REG: Regex = Regex::new(r"(\S+) (\S+\*\S+) (==) (.+)").unwrap();
    static ref RULE_WITH_OPTIONAL_MESSAGE_REG: Regex = Regex::new(
        r"(?P<resource_type>\S+) +(?P<resource_property>[\w\.\*]+) +(?P<operator>\S+) +(?P<rule_value>[^\n\r]+) +<{2} *(?P<custom_msg>.*)").unwrap();
}

pub(crate) fn parse_rules(
    rules_file_contents: &str,
    cfn_resources: &HashMap<String, Value>,
) -> ParsedRuleSet {
    debug!("Entered parse_rules");
    trace!(
        "Parse rules entered with rules_file_contents: {:#?}",
        &rules_file_contents
    );
    trace!(
        "Parse rules entered with cfn_resources: {:#?}",
        &cfn_resources
    );

    let mut rule_set: Vec<CompoundRule> = vec![];
    let mut variables = HashMap::new();

    let lines = rules_file_contents.lines();
    trace!("Rules file lines: {:#?}", &lines);

    for l in lines {
        debug!("Parsing '{}'", &l);
        if l.is_empty() {
            continue;
        };
        let line_type = find_line_type(l);
        debug!("line_type is {:#?}", line_type);
        match line_type {
            LineType::Assignment => {
                let caps = process_assignment(l);
                trace!("Parsed assignment's captures are: {:?}", &caps);
                variables.insert(caps["var_name"].to_string(), caps["var_value"].to_string());
            }
            LineType::Comment => (),
            LineType::Rule => {
                let compound_rule: CompoundRule = if is_or_rule(l) {
                    debug!("Line is an |OR| rule");
                    process_or_rule(l, &cfn_resources)
                } else {
                    debug!("Line is an 'AND' rule");
                    process_and_rule(l, &cfn_resources)
                };
                debug!("Parsed rule is: {:#?}", &compound_rule);
                rule_set.push(compound_rule);
            }
        }
    }
    for (key, value) in env::vars() {
        let key_name = format!("ENV_{}", key);
        variables.insert(key_name, value);
    }
    debug!("Variables dictionary is {:?}", &variables);
    debug!("Rule Set is {:#?}", &rule_set);
    ParsedRuleSet {
        variables,
        rule_set,
    }
}

fn find_line_type(line: &str) -> LineType {
    if COMMENT_REG.is_match(line) {
        return LineType::Comment;
    };
    if ASSIGN_REG.is_match(line) {
        return LineType::Assignment;
    };
    if RULE_REG.is_match(line) {
        return LineType::Rule;
    };
    panic!("BAD RULE: {:?}", line)
}

fn process_assignment(line: &str) -> Captures {
    ASSIGN_REG.captures(line).unwrap()
}

fn is_or_rule(line: &str) -> bool {
    line.contains("|OR|") || WILDCARD_OR_RULE_REG.is_match(line)
}

fn process_or_rule(line: &str, cfn_resources: &HashMap<String, Value>) -> CompoundRule {
    trace!("Entered process_or_rule");
    let branches = line.split("|OR|");
    debug!("Rule branches are: {:#?}", &branches);
    let mut rules: Vec<Rule> = vec![];
    for b in branches {
        rules.append(destructure_rule(b.trim(), cfn_resources).as_mut());
    }
    CompoundRule {
        compound_type: CompoundType::OR,
        rule_list: rules,
    }
}

fn process_and_rule(line: &str, cfn_resources: &HashMap<String, Value>) -> CompoundRule {
    CompoundRule {
        compound_type: CompoundType::AND,
        rule_list: destructure_rule(line, cfn_resources),
    }
}

fn destructure_rule(rule_text: &str, cfn_resources: &HashMap<String, Value>) -> Vec<Rule> {
    trace!("Entered destructure_rule");
    let mut rules_hash: HashSet<Rule> = HashSet::new();
    let caps = match RULE_WITH_OPTIONAL_MESSAGE_REG.captures(rule_text) {
        Some(c) => c,
        None => RULE_REG.captures(rule_text).unwrap(),
    };

    trace!("Parsed rule's captures are: {:#?}", &caps);
    let mut props: Vec<String> = vec![];
    if caps["resource_property"].contains('*') {
        for (_name, value) in cfn_resources {
            if caps["resource_type"] == value["Type"] {
                if let Some(p) = expand_wildcard_props(
                    &value["Properties"],
                    caps["resource_property"].to_string(),
                    String::from(""),
                ) {
                    props.append(&mut p.clone());
                    trace!("Expanded props are {:#?}", &props);
                }
            }
        }
    } else {
        props.push(caps["resource_property"].to_string());
    };

    for p in props {
        rules_hash.insert(Rule {
            resource_type: caps["resource_type"].to_string(),
            field: p.to_string(),
            operation: {
                match &caps["operator"] {
                    "==" => OpCode::Require,
                    "!=" => OpCode::RequireNot,
                    "IN" => OpCode::In,
                    "NOT_IN" => OpCode::NotIn,
                    _ => panic!(format!("Bad Rule Operator: {}", &caps["operator"])),
                }
            },
            rule_vtype: {
                let rv = caps["rule_value"].chars().next().unwrap();
                match rv {
                    '[' => match &caps["operator"] {
                        "==" | "!=" => RValueType::Value,
                        "IN" | "NOT_IN" => RValueType::List,
                        _ => panic!(format!("Bad Rule Operator: {}", &caps["operator"])),
                    },
                    '/' => RValueType::Regex,
                    '%' => RValueType::Variable,
                    _ => RValueType::Value,
                }
            },
            value: {
                let rv = caps["rule_value"].chars().next().unwrap();
                match rv {
                    '/' => caps["rule_value"].trim_matches('/').to_string(),
                    _ => caps["rule_value"].to_string().trim().to_string(),
                }
            },
            custom_msg: match caps.name("custom_msg") {
                Some(s) => Some(s.as_str().to_string()),
                None => None,
            },
        });
    }

    let rules = rules_hash.into_iter().collect::<Vec<Rule>>();
    trace!("Destructured rules are: {:#?}", &rules);
    rules
}

mod tests {
    #[cfg(test)]
    use crate::parser::find_line_type;

    #[test]
    fn test_find_line_type() {
        let comment = find_line_type("# This is a comment");
        let assignment = find_line_type("let x = assignment");
        let rule = find_line_type("AWS::EC2::Volume Encryption == true");
        assert_eq!(comment, crate::enums::LineType::Comment);
        assert_eq!(assignment, crate::enums::LineType::Assignment);
        assert_eq!(rule, crate::enums::LineType::Rule);
    }
}
