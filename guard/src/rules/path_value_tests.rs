use super::*;
use std::convert::TryInto;

const SAMPLE_SINGLE: &str = r#"{
            "Resources": {
                "vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/12"
                    }
                }
            }
        }"#;


const SAMPLE_MULTIPLE : &str = r#"{
            "Resources": {
                "vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": "10.0.0.0/12"
                    }
                },
                "routing": {
                    "Type": "AWS::EC2::Route",
                    "Properties": {
                        "Acls": [
                            {
                                "From": 0,
                                "To": 22,
                                "Allow": false
                            },
                            {
                                "From": 0,
                                "To": 23,
                                "Allow": false
                            }
                        ]
                    }
                }
            }
        }
        "#;

#[test]
fn path_value_equivalent() -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        SAMPLE_SINGLE
    )?;

    let resources_path  = Path::try_from("/Resources")?;
    let vpc_path        = resources_path.extend_str("vpc");
    let vpc_type        = vpc_path.extend_str("Type");
    let vpc_props       = vpc_path.extend_str("Properties");
    let cidr_path       = vpc_props.extend_str("CidrBlock");

    let mut vpc_properties = indexmap::IndexMap::new();
    vpc_properties.insert(
        String::from("CidrBlock"),
        PathAwareValue::String((cidr_path.clone(), String::from("10.0.0.0/12")))
    );
    let vpc_properties = PathAwareValue::Map((vpc_props.clone(), MapValue {
        keys: vec![
            PathAwareValue::String(( cidr_path.clone(), String::from("CidrBlock")))
        ],
        values: vpc_properties
    }));
    let vpc_type_prop = PathAwareValue::String((vpc_type.clone(), String::from("AWS::EC2::VPC")));

    let mut vpc_block = indexmap::IndexMap::new();
    vpc_block.insert(String::from("Type"), vpc_type_prop);
    vpc_block.insert(String::from("Properties"), vpc_properties);

    let vpc = PathAwareValue::Map((
        vpc_path.clone(),
        MapValue {
            keys: vec![
                PathAwareValue::String((vpc_type.clone(), String::from("Type"))),
                PathAwareValue::String((vpc_props.clone(), String::from("Properties"))),
            ],
            values: vpc_block
        }));

    let mut resources = indexmap::IndexMap::new();
    resources.insert(String::from("vpc"), vpc);
    let resources = PathAwareValue::Map((
        resources_path.clone(),
        MapValue {
            keys: vec![
                PathAwareValue::String((vpc_path.clone(), String::from("vpc")))
            ],
            values: resources
        }));

    let mut top = indexmap::IndexMap::new();
    top.insert("Resources".to_string(), resources);
    let top = PathAwareValue::Map((
        Path::root(),
        MapValue {
            keys: vec![
                PathAwareValue::String((resources_path.clone(), "Resources".to_string()))
            ],
            values: top
        }));

    assert_eq!(top, value);
    Ok(())
}

#[test]
fn path_value_queries() -> Result<(), Error> {

    Ok(())
}