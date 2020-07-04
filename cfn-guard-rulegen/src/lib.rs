// © Amazon Web Services, Inc. or its affiliates. All Rights Reserved. This AWS Content is provided subject to the terms of the AWS Customer Agreement available at http://aws.amazon.com/agreement or other written agreement between Customer and either Amazon Web Services, Inc. or Amazon Web Services EMEA SARL or both.

use log::{self, debug, error, info, trace};
use serde_json::Value;
use std::collections::HashMap;
use std::collections::HashSet;
use std::error::Error;
use std::fs;

pub fn run(template_file: &str) -> Result<Vec<String>, Box<dyn Error>> {
    let template_contents = fs::read_to_string(template_file)?;

    trace!(
        "Template file is '{}' and its contents are:\n'{}'",
        template_file,
        template_contents
    );

    Ok(run_gen(&template_contents))
}

pub fn run_gen(template_file_contents: &str) -> Vec<String> {
    info!("Loading CloudFormation Template");
    debug!("Entered run_gen");

    debug!("Deserializing CloudFormation template");
    let cfn_template: HashMap<String, Value> = match serde_json::from_str(template_file_contents) {
        Ok(s) => s,
        Err(_) => match serde_yaml::from_str(template_file_contents) {
            Ok(y) => y,
            Err(e) => {
                let msg_string = format!("Template file format was unreadable as json or yaml: {}", e);
                error!("{}", &msg_string);
                return vec![msg_string]
            },
        },
    };
    trace!("CFN Template is {:#?}", &cfn_template);
    let cfn_resources_clone = match cfn_template.get("Resources") {
        Some(y) => y.clone(),
        None => {
            let msg_string = format!("Template lacks a Resources section");
            error!("{}", &msg_string);
            return vec![msg_string]
        },
    };
    let cfn_resources: HashMap<String, Value> =
        match serde_json::from_value(cfn_resources_clone) {
            Ok(y) => y,
            Err(e) => {
                let msg_string = format!("Template Resources section has an invalid structure: {}", e);
                error!("{}", &msg_string);
                return vec![msg_string]
            },
        };
    trace!("CFN resources are: {:?}", cfn_resources);
    gen_rules(cfn_resources)
}

fn gen_rules(cfn_resources: HashMap<String, Value>) -> Vec<String> {
    let mut rule_set: HashSet<String> = HashSet::new();
    let mut rule_map: HashMap<String, HashSet<String>> = HashMap::new();
    for (name, cfn_resource) in cfn_resources {
        trace!("{} is {:?}", name, &cfn_resource);
        let props: HashMap<String, Value> =
            match serde_json::from_value(cfn_resource["Properties"].clone()) {
                Ok(s) => s,
                Err(_) => continue
            };
        for (prop_name, prop_val) in props {
            let stripped_val = match prop_val.as_str() {
                Some(v) => String::from(v),
                None => prop_val.to_string(),
            };
            let no_newline_stripped_val = stripped_val.trim().replace("\n", "");
            let key_name = format!("{} {}", &cfn_resource["Type"].as_str().unwrap(), prop_name);
            // If the key doesn't exist, create it and set its value to a new HashSet with the rule value in it
            if !rule_map.contains_key(&key_name) {
                let value_set: HashSet<String> = vec![no_newline_stripped_val].into_iter().collect();
                rule_map.insert(key_name, value_set);
            } else {
                // If the key does exist, add the item to the HashSet
                let value_set = rule_map.get_mut(&key_name).unwrap();
                value_set.insert(no_newline_stripped_val);
            };
        }
    }
    for (key, val_set) in rule_map {
        let mut rule_string: String = String::from("");
        let mut count = 0;
        for r in val_set {
            let temp_rule_string = format!("{} == {}", key, r);
            if count > 0 {
                rule_string = format!("{} |OR| {}", rule_string, temp_rule_string);
            } else {
                rule_string = temp_rule_string;
            }
            count += 1;
        }
        rule_set.insert(rule_string);
    }
    rule_set.into_iter().collect()
}

