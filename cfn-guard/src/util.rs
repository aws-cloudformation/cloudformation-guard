// © Amazon Web Services, Inc. or its affiliates. All Rights Reserved. This AWS Content is provided subject to the terms of the AWS Customer Agreement available at http://aws.amazon.com/agreement or other written agreement between Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

use crate::{enums, structs};
use lazy_static::lazy_static;
use log::{self, debug, error, trace};
use regex::{Captures, Regex};
use serde_json::Value;
use std::collections::HashMap;

// This sets it up so the regex only gets compiled once
// See: https://docs.rs/regex/1.3.9/regex/#example-avoid-compiling-the-same-regex-in-a-loop
lazy_static! {
    static ref STRINGIFIED_BOOLS: Regex =
        Regex::new(r"[:=]\s*([fF]alse|[tT]rue)\s*([,}]+|$)").unwrap();
}
pub fn fix_stringified_bools(fstr: &str) -> String {
    let after = STRINGIFIED_BOOLS.replace_all(fstr, |caps: &Captures| caps[0].to_lowercase());
    after.to_string()
}

pub fn format_value(v: &Value) -> String {
    let formatted_value = if v.is_string() {
        strip_ws_nl(String::from(v.as_str().unwrap()))
    } else {
        strip_ws_nl(v.to_string())
    };
    trace!("formatted_value is '{}'", formatted_value);
    formatted_value
}

pub fn strip_ws_nl(v: String) -> String {
    trace!("Removing spaces and newline characters from '{}'", &v);
    v.trim().replace("\n", "")
}

pub fn convert_list_var_to_vec(rule_val: &str) -> Vec<String> {
    let value_string: String = rule_val
        .trim_start_matches('[')
        .trim_end_matches(']')
        .replace(" ", "");

    let mut value_vec: Vec<String> = vec![];

    for vs in value_string.split(',') {
        value_vec.push(String::from(vs));
    }
    debug!("Rule value_vec is {:?}", &value_vec);
    value_vec
}

fn match_props<'a>(props: &'a Value, n: &'a dyn serde_json::value::Index) -> Result<&'a Value, ()> {
    trace!("props are {:#?}", props);
    match props.get(n) {
        Some(v) => Ok(v),
        None => Err(()),
    }
}

pub fn get_resource_prop_value(props: &Value, field: &[&str]) -> Result<Value, String> {
    trace!("Getting {:?} from {}", &field, &props);
    let mut field_list = field.to_owned();
    trace!("field_list len is {}", field_list.len());
    let next_field = field_list.remove(0);
    match next_field.parse::<usize>() {
        Ok(n) => {
            trace!(
                "next_field is {:?} and field_list is now {:?}",
                &n,
                &field_list
            );
            match match_props(props, &n) {
                Ok(v) => {
                    if !field_list.is_empty() {
                        get_resource_prop_value(&v, &field_list)
                    } else {
                        Ok(v.clone())
                    }
                }
                Err(_) => Err(n.to_string()),
            }
        }
        Err(_) => {
            trace!(
                "next_field is {:?} and field_list is now {:?}",
                &next_field,
                &field_list
            );
            match match_props(props, &next_field) {
                Ok(v) => {
                    if !field_list.is_empty() {
                        get_resource_prop_value(&v, &field_list)
                    } else {
                        Ok(v.clone())
                    }
                }
                Err(_) => Err(next_field.to_string()),
            }
        }
    }
}

pub fn deref_rule_value<'a>(
    rule: &'a structs::Rule,
    vars: &'a HashMap<String, String>,
) -> Result<&'a str, String> {
    trace!(
        "Entered dereference_rule_value() with '{:#?}' and Variables '{:#?}'",
        rule,
        &vars
    );
    match rule.rule_vtype {
        enums::RValueType::Variable => {
            let target_value: &str = rule.value.split('%').collect::<Vec<&str>>()[1];
            let first_char = target_value.chars().collect::<Vec<char>>()[0];
            let final_target = match first_char {
                // Environment variable lookup
                '{' => format!(
                    "ENV_{}",
                    target_value.trim_start_matches('{').trim_end_matches('}')
                ),
                _ => target_value.to_string(),
            };
            trace!(
                "Dereferencing variable {:?} in '{:#?}'",
                final_target,
                &vars
            );
            match &vars.get(&final_target) {
                Some(v) => Ok(v),
                None => {
                    error!(
                        "Undefined Variable:  [{}] does not exist in {:?}",
                        final_target, &vars
                    );
                    Err(format!("[{}] does not exist in {:?}", rule.value, &vars))
                }
            }
        }
        _ => Ok(&rule.value),
    }
}

pub fn expand_wildcard_props(
    props: &Value,
    address: String,
    accumulator: String,
) -> Option<Vec<String>> {
    trace!(
        "Entering expand_wildcard_props() with props: {:#?} , address: {:#?} , accumulator: {:#?}",
        &props,
        &address,
        &accumulator
    );
    let mut segments = address.split('*').collect::<Vec<&str>>();
    trace!("Segments are {:#?}", &segments);
    let segment = segments.remove(0);
    trace!("Processing segment {:#?}", &segment);
    if segment != "" {
        let mut expanded_props: Vec<String> = vec![];
        let s = segment.trim_end_matches('.').trim_start_matches('.');
        let steps = s.split('.').collect::<Vec<&str>>();
        match get_resource_prop_value(props, &steps) {
            Ok(v) => match v.as_array() {
                Some(result_array) => {
                    trace!("Value is an array");
                    for (counter, r) in result_array.iter().enumerate() {
                        trace!("Counter is {:#?}", counter);
                        let next_segment = segments.join("*");
                        trace!("next_segment is {:#?}", &next_segment);
                        let temp_address = format!("{}{}{}", accumulator, segment, counter);
                        trace!("temp_address is {:#?}", &temp_address);
                        match expand_wildcard_props(&r, next_segment, temp_address) {
                            Some(result) => expanded_props.append(&mut result.clone()),
                            None => return None,
                        }
                    }
                }
                None => expanded_props.push(format!("{}{}", accumulator, segment)),
            },
            Err(_) => return None,
        }
        Some(expanded_props)
    } else {
        trace!("Segment is empty");
        Some(vec![accumulator])
    }
}

mod tests {
    #[cfg(test)]
    use crate::util::expand_wildcard_props;
    #[cfg(test)]
    use std::collections::HashMap;

    #[test]
    fn test_wildcard_expansion() {
        let iam_template: &'static str = r#"
Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
                - lambda.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
                - ec2.amazonaws.com
            Action:
              - 'sts:AssumeRole'
"#;
        let cfn_template: HashMap<String, serde_json::Value> =
            serde_yaml::from_str(&iam_template).unwrap();
        let mut wildcard = String::from("AssumeRolePolicyDocument.Statement.*.Effect");
        let root = &cfn_template["Resources"]["LambdaRoleHelper"]["Properties"];
        let mut expanded_wildcards =
            expand_wildcard_props(&root, wildcard, String::from("")).unwrap();
        assert_eq!(
            expanded_wildcards,
            vec![
                String::from("AssumeRolePolicyDocument.Statement.0.Effect"),
                String::from("AssumeRolePolicyDocument.Statement.1.Effect"),
                String::from("AssumeRolePolicyDocument.Statement.2.Effect"),
            ]
        );
        wildcard = String::from("AssumeRolePolicyDocument.Statement.*.Action.*");
        expanded_wildcards = expand_wildcard_props(&root, wildcard, String::from("")).unwrap();
        assert_eq!(
            expanded_wildcards,
            vec![
                String::from("AssumeRolePolicyDocument.Statement.0.Action.0"),
                String::from("AssumeRolePolicyDocument.Statement.1.Action.0"),
                String::from("AssumeRolePolicyDocument.Statement.2.Action.0"),
            ]
        );
    }
}
