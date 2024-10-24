use std::fs;
use std::process;

use crate::commands::Executable;
use crate::commands::SUCCESS_STATUS_CODE;
use crate::rules::Result;
use crate::utils::reader::Reader;
use crate::utils::writer::Writer;
use clap::Args;
use itertools::Itertools;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::Write;
use string_builder::Builder;

const ABOUT: &str = "Autogenerate rules from an existing JSON- or YAML- formatted data. (Currently works with only CloudFormation templates)";
const TEMPLATE_HELP: &str = "Provide path to a CloudFormation template file in JSON or YAML";
const OUTPUT_HELP: &str = "Write to output file";

#[derive(Debug, Clone, Eq, PartialEq, Args)]
#[clap(arg_required_else_help = true)]
#[clap(about=ABOUT)]
/// .
/// The Rulegen command auto generates rules from an existing CloudFormation template
/// Please note this currently only works on CloudFormation templates
pub struct Rulegen {
    /// the path to the file which the generated rules will be outputted to
    /// default None
    /// if set to None rules will be outputted to the stdout
    #[arg(short, long, help=OUTPUT_HELP)]
    pub(crate) output: Option<String>,
    /// the path to the CloudFormation template
    #[arg(short, long, help=TEMPLATE_HELP)]
    pub(crate) template: String,
}

impl Executable for Rulegen {
    /// .
    /// autogenerate rules from an existing CloudFormation template
    ///
    /// This function will return an error if
    /// - any of the specified paths do not exist
    /// - illegal json or yaml syntax present in any of the data/input parameter files
    fn execute(&self, writer: &mut Writer, _: &mut Reader) -> Result<i32> {
        let template_contents = fs::read_to_string(&self.template)?;

        let result = parse_template_and_call_gen(&template_contents, writer);
        print_rules(result, writer)?;

        Ok(SUCCESS_STATUS_CODE)
    }
}

pub fn parse_template_and_call_gen(
    template_contents: &str,
    writer: &mut Writer,
) -> HashMap<String, HashMap<String, HashSet<String>>> {
    let cfn_template: HashMap<String, Value> = match serde_yaml::from_str(template_contents) {
        Ok(s) => s,
        Err(e) => {
            writer
                .write_err(format!("Parsing error handling template file, Error = {e}"))
                .expect("failed to write to stderr");
            process::exit(1);
        }
    };

    let cfn_resources_clone = match cfn_template.get("Resources") {
        Some(y) => y.clone(),
        None => {
            writer
                .write_err(String::from("Template lacks a Resources section"))
                .expect("failed to write to stderr");
            process::exit(1);
        }
    };

    let cfn_resources: HashMap<String, Value> = match serde_json::from_value(cfn_resources_clone) {
        Ok(y) => y,
        Err(e) => {
            writer
                .write_err(format!(
                    "Template Resources section has an invalid structure: {e}"
                ))
                .expect("failed to write to stderr");
            process::exit(1);
        }
    };

    gen_rules(cfn_resources)
}

#[allow(clippy::map_entry)]
fn gen_rules(
    cfn_resources: HashMap<String, Value>,
) -> HashMap<String, HashMap<String, HashSet<String>>> {
    // Create hashmap of resource name, property name and property values
    // For example, the following template:
    //
    //        {
    //            "Resources": {
    //                "NewVolume" : {
    //                    "Type" : "AWS::EC2::Volume",
    //                    "Properties" : {
    //                        "Size" : 500,
    //                        "Encrypted": false,
    //                        "AvailabilityZone" : "us-west-2b"
    //                    }
    //                },
    //                "NewVolume2" : {
    //                    "Type" : "AWS::EC2::Volume",
    //                    "Properties" : {
    //                        "Size" : 50,
    //                        "Encrypted": false,
    //                        "AvailabilityZone" : "us-west-2c"
    //                    }
    //                }
    //            }
    //        }
    //
    //
    // The data structure would contain:
    // <AWS::EC2::Volume> <Encrypted> <false>
    //                    <Size> <500, 50>
    //                    <AvailabilityZone> <us-west-2c, us-west-2b>
    //
    //
    //
    let mut rule_map: HashMap<String, HashMap<String, HashSet<String>>> = HashMap::new();
    for (_name, cfn_resource) in cfn_resources {
        let props: HashMap<String, Value> =
            match serde_json::from_value(cfn_resource["Properties"].clone()) {
                Ok(s) => s,
                Err(_) => continue,
            };

        for (prop_name, prop_val) in props {
            let stripped_val = match prop_val.as_str() {
                Some(v) => String::from(v),
                None => prop_val.to_string(),
            };

            let mut no_newline_stripped_val = stripped_val.trim().replace('\n', "");

            // Preserve double quotes for strings.
            if prop_val.is_string() {
                let test_str = format!("{}{}{}", "\"", no_newline_stripped_val, "\"");
                no_newline_stripped_val = test_str;
            }
            let resource_name = (&cfn_resource["Type"].as_str().unwrap()).to_string();

            if !rule_map.contains_key(&resource_name) {
                let value_set: HashSet<String> =
                    vec![no_newline_stripped_val].into_iter().collect();

                let mut property_map = HashMap::new();
                property_map.insert(prop_name, value_set);
                rule_map.insert(resource_name, property_map);
            } else {
                let property_map = rule_map.get_mut(&resource_name).unwrap();

                if !property_map.contains_key(&prop_name) {
                    let value_set: HashSet<String> =
                        vec![no_newline_stripped_val].into_iter().collect();
                    property_map.insert(prop_name, value_set);
                } else {
                    let value_set = property_map.get_mut(&prop_name).unwrap();
                    value_set.insert(no_newline_stripped_val);
                }
            };
        }
    }

    rule_map
}

// Prints the generated rules data structure to stdout. If there are properties mapping to
// multiple values in the template, the rules are put in one statement using the IN keyword so that
// the generated rules are interpreted as ALL by default.
// Using the same example in the comment above, the rules printed for the template will be:
//     let aws_ec2_volume_resources = Resources.*[ Type == 'AWS::EC2::Volume' ]
//     rule aws_ec2_volume when %aws_ec2_volume_resources !empty {
//          %aws_ec2_volume_resources.Properties.Size IN [500, 50]
//          %aws_ec2_volume_resources.Properties.AvailabilityZone IN ["us-west-2b", "us-west-2c"]
//          %aws_ec2_volume_resources.Properties.Encrypted == false
//     }
fn print_rules(
    rule_map: HashMap<String, HashMap<String, HashSet<String>>>,
    writer: &mut Writer,
) -> Result<()> {
    let mut str = Builder::default();

    for (resource, properties) in &rule_map {
        let resource_name_underscore = resource.replace("::", "_").to_lowercase();
        let variable_name = format!("{}_resources", resource_name_underscore);

        str.append(format!(
            "let {} = Resources.*[ Type == '{}' ]\n",
            variable_name, resource
        ));
        str.append(format!(
            "rule {} when %{} !empty {{\n",
            resource_name_underscore, variable_name
        ));

        for (property, values) in properties {
            if values.len() > 1 {
                str.append(format!(
                    "  %{}.Properties.{} IN [{}]\n",
                    variable_name,
                    property,
                    values.iter().join(", ")
                ));
            } else {
                str.append(format!(
                    "  %{}.Properties.{} == {}\n",
                    variable_name,
                    property,
                    values.iter().next().unwrap()
                ));
            }
        }

        str.append("}\n");
    }

    // validate rules generated
    let generated_rules = str.string().unwrap();

    let span = crate::rules::parser::Span::new_extra(&generated_rules, "");
    match crate::rules::parser::rules_file(span) {
        Ok(_rules) => {
            //
            // TODO fix with Error return
            //
            write!(writer, "{}", generated_rules)?;
        }
        Err(e) => {
            writer.write_err(format!(
                "Parsing error with generated rules file, Error = {e}"
            ))?;
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "rulegen_tests.rs"]
mod rulegen_tests;
