use super::*;
use std::convert::TryInto;
use crate::rules::parser::AccessQueryWrapper;

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

struct DummyEval{}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, variable: &str) -> crate::rules::Result<Vec<&PathAwareValue>> {
        unimplemented!()
    }

    fn rule_status(&self, rule_name: &str) -> crate::rules::Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>) {
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
    }
}

#[test]
fn path_value_queries() -> Result<(), Error> {
    let resources = r#"{
      "Resources": {
       "NewSecurityGroupACA21D0A": {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
              "GroupDescription": "Allow ssh access to ec2 instances",
              "SecurityGroupEgress": [
                {
                  "CidrIp": "0.0.0.0/0",
                  "Description": "Allow all outbound traffic by default",
                  "IpProtocol": "-1"
                }
              ],
              "SecurityGroupIngress": [
                {
                  "CidrIp": "0.0.0.0/0",
                  "Description": "allow ssh access from the world",
                  "FromPort": 22,
                  "IpProtocol": "tcp",
                  "ToPort": 22
                }
              ],
              "VpcId": {
                "Ref": "TheVPC92636AB0"
              }
            },
            "Metadata": {
              "aws:cdk:path": "FtCdkSecurityGroupStack/NewSecurityGroup/Resource"
            }
        },
        "myInstanceUsingNewSG": {
          "Type": "AWS::EC2::Instance",
          "Properties": {
            "ImageId": " ami-0f5dbc86dd9cbf7a8",
            "InstanceType": "t2.micro",
            "NetworkInterfaces": [
              {
                "DeviceIndex": "0",
                "SubnetId": {
                  "Ref": "TheVPCapplicationSubnet1Subnet2149DB21"
                }
              }
            ],
            "SecurityGroupIds": [
              {
                "Fn::GetAtt": [
                  "NewSecurityGroupACA21D0A",
                  "GroupId"
                ]
              }
            ],
            "Tags": [
              {
                "Key": "Name",
                "Value": "my-new-ec2-myInstanceUsingNewSG"
              }
            ]
          },
          "Metadata": {
            "aws:cdk:path": "FtCdkSecurityGroupStack/myInstanceUsingNewSG"
          }
        }
      }
    }
    "#;

    let incoming = PathAwareValue::try_from(resources)?;
    let eval = DummyEval{};
    //
    // Select all resources that have security groups present as a property
    //
    let resources_with_sgs = AccessQueryWrapper::try_from(
        "Resources.*[ Properties.SecurityGroups EXISTS ]")?.0;
    let selected = incoming.select(true, &resources_with_sgs, &eval)?;
    assert_eq!(selected.is_empty(), true);

    let resources_with_sgs = AccessQueryWrapper::try_from(
        "Resources.*[ Properties.SecurityGroupIds EXISTS ]")?.0;
    let selected = incoming.select(true, &resources_with_sgs, &eval)?;
    assert_eq!(selected.is_empty(), false);

    let get_att_refs =
        r#"Resources.*[ Properties.SecurityGroupIds EXISTS ].Properties.SecurityGroupIds[ 'Fn::GetAtt' EXISTS ].*"#;
    let resources_with_sgs = AccessQueryWrapper::try_from(get_att_refs)?.0;
    let selected = incoming.select(true, &resources_with_sgs, &eval)?;
    assert_eq!(selected.len(), 1);

    let get_att_refs =
        r#"Resources.*.Properties.SecurityGroupIds[*].'Fn::GetAtt'.*"#;
    let resources_with_sgs = AccessQueryWrapper::try_from(get_att_refs)?.0;
    let selected = incoming.select(false, &resources_with_sgs, &eval)?;
    assert_eq!(selected.len(), 1);
    println!("{:?}", selected);

    Ok(())
}