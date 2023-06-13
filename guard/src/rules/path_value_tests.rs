use crate::rules::exprs::{
    AccessClause, AccessQuery, FileLocation, GuardAccessClause, GuardClause, LetExpr, LetValue,
};

use super::*;

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

// const SAMPLE_MULTIPLE: &str = r#"{
//             "Resources": {
//                 "vpc": {
//                     "Type": "AWS::EC2::VPC",
//                     "Properties": {
//                         "CidrBlock": "10.0.0.0/12"
//                     }
//                 },
//                 "routing": {
//                     "Type": "AWS::EC2::Route",
//                     "Properties": {
//                         "Acls": [
//                             {
//                                 "From": 0,
//                                 "To": 22,
//                                 "Allow": false
//                             },
//                             {
//                                 "From": 0,
//                                 "To": 23,
//                                 "Allow": false
//                             }
//                         ]
//                     }
//                 }
//             }
//         }
// "#;

#[test]
fn path_value_equivalent() -> Result<(), Error> {
    let value = PathAwareValue::try_from(SAMPLE_SINGLE)?;

    let resources_path = Path::try_from("/Resources")?;
    let vpc_path = resources_path.extend_str("vpc");
    let vpc_type = vpc_path.extend_str("Type");
    let vpc_props = vpc_path.extend_str("Properties");
    let cidr_path = vpc_props.extend_str("CidrBlock");

    let mut vpc_properties = indexmap::IndexMap::new();
    vpc_properties.insert(
        String::from("CidrBlock"),
        PathAwareValue::String((cidr_path.clone(), String::from("10.0.0.0/12"))),
    );
    let vpc_properties = PathAwareValue::Map((
        vpc_props.clone(),
        MapValue {
            keys: vec![PathAwareValue::String((
                cidr_path,
                String::from("CidrBlock"),
            ))],
            values: vpc_properties,
        },
    ));
    let vpc_type_prop = PathAwareValue::String((vpc_type.clone(), String::from("AWS::EC2::VPC")));

    let mut vpc_block = indexmap::IndexMap::new();
    vpc_block.insert(String::from("Type"), vpc_type_prop);
    vpc_block.insert(String::from("Properties"), vpc_properties);

    let vpc = PathAwareValue::Map((
        vpc_path.clone(),
        MapValue {
            keys: vec![
                PathAwareValue::String((vpc_type, String::from("Type"))),
                PathAwareValue::String((vpc_props, String::from("Properties"))),
            ],
            values: vpc_block,
        },
    ));

    let mut resources = indexmap::IndexMap::new();
    resources.insert(String::from("vpc"), vpc);
    let resources = PathAwareValue::Map((
        resources_path.clone(),
        MapValue {
            keys: vec![PathAwareValue::String((vpc_path, String::from("vpc")))],
            values: resources,
        },
    ));

    let mut top = indexmap::IndexMap::new();
    top.insert("Resources".to_string(), resources);
    let top = PathAwareValue::Map((
        Path::root(),
        MapValue {
            keys: vec![PathAwareValue::String((
                resources_path,
                "Resources".to_string(),
            ))],
            values: top,
        },
    ));

    assert_eq!(top, value);
    Ok(())
}

struct DummyEval {}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, _variable: &str) -> crate::rules::Result<Vec<&PathAwareValue>> {
        unimplemented!()
    }

    fn rule_status(&self, _rule_name: &str) -> crate::rules::Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(
        &self,
        _eval_type: EvaluationType,
        _context: &str,
        _msg: String,
        _from: Option<PathAwareValue>,
        _to: Option<PathAwareValue>,
        _status: Option<Status>,
        _cmp: Option<(CmpOperator, bool)>,
    ) {
    }

    fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {}
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
    let eval = DummyEval {};
    //
    // Select all resources that have security groups present as a property
    //
    let resources_with_sgs =
        AccessQuery::try_from("Resources.*[ Properties.SecurityGroups EXISTS ]")?;
    let selected = incoming.select(
        resources_with_sgs.match_all,
        &resources_with_sgs.query,
        &eval,
    )?;
    assert!(selected.is_empty());

    let resources_with_sgs =
        AccessQuery::try_from("Resources.*[ Properties.SecurityGroupIds EXISTS ]")?;
    let selected = incoming.select(
        resources_with_sgs.match_all,
        &resources_with_sgs.query,
        &eval,
    )?;
    assert!(!selected.is_empty());

    let get_att_refs = r#"Resources.*[ Properties.SecurityGroupIds EXISTS ].Properties.SecurityGroupIds[ 'Fn::GetAtt' EXISTS ].'Fn::GetAtt'.*"#;
    let resources_with_sgs = AccessQuery::try_from(get_att_refs)?;
    let selected = incoming.select(
        resources_with_sgs.match_all,
        &resources_with_sgs.query,
        &eval,
    )?;
    assert_eq!(selected.len(), 2);

    let get_att_refs = r#"SOME Resources.*.Properties.SecurityGroupIds[*].'Fn::GetAtt'.*"#;
    let resources_with_sgs = AccessQuery::try_from(get_att_refs)?;
    let selected = incoming.select(
        resources_with_sgs.match_all,
        &resources_with_sgs.query,
        &eval,
    )?;
    assert_eq!(selected.len(), 2);
    println!("{:?}", selected);

    //
    // Assignments
    //
    let assignment = r#"let var = ANY Resources.*.Properties.SecurityGroupIds[*].'Fn::GetAtt'.*"#;
    let let_statement = LetExpr::try_from(assignment)?;
    println!("{:?}", let_statement);

    //
    // Clauses
    //
    let clause =
        "SOME Resources.*.Properties.SecurityGroupIds[*].'Fn::GetAtt'.* IN [/aa/, /bb/] #;";
    let clause_statement = GuardClause::try_from(clause)?;
    println!("{:?}", clause_statement);
    let expected = GuardClause::Clause(GuardAccessClause {
        negation: false,
        access_clause: AccessClause {
            query: AccessQuery {
                query: vec![
                    QueryPart::Key(String::from("Resources")),
                    QueryPart::AllValues(None),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("SecurityGroupIds".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("Fn::GetAtt".to_string()),
                    QueryPart::AllValues(None),
                ],
                match_all: false,
            },
            compare_with: Some(LetValue::Value(PathAwareValue::try_from("[/aa/, /bb/]")?)),
            location: FileLocation {
                line: 1,
                column: 1,
                file_name: "",
            },
            comparator: (CmpOperator::In, false),
            custom_message: None,
        },
    });
    assert_eq!(expected, clause_statement);

    Ok(())
}

#[test]
fn some_filter_tests() -> Result<(), Error> {
    let query_str = r#"some Resources.*.Properties.SecurityGroups[*].'Fn::GetAtt'"#;
    let resources_str = r#"{
        Resources: {
            ec2: {
                Properties: {
                    SecurityGroups: ["sg-1234"]
                }
            },
            ec22: {
                Properties: {
                    SecurityGroups: [{ 'Fn::GetAtt': ["sg", "GroupId"] }]
                }
            }
        }
    }"#;
    let query = AccessQuery::try_from(query_str)?;
    let resources = PathAwareValue::try_from(resources_str)?;
    let dummy = DummyEval {};
    let selected = resources.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 1);
    Ok(())
}

#[test]
fn it_support_evaluation_tests() -> Result<(), Error> {
    let tags = r#"Tags[ this == { Key: "Hi", Value: "There" } ]"#;
    let parsed_tags = AccessQuery::try_from(tags)?;
    let values = r#"{
        Tags: [
            { Key: "Hi", Value: "There" },
            { Key: "NotHi", Value: "NotThere" }
        ]
    }"#;
    let parsed_values = PathAwareValue::try_from(values)?;
    let dummy = DummyEval {};
    let selected = parsed_values.select(parsed_tags.match_all, &parsed_tags.query, &dummy)?;
    println!("Selected = {:?}", selected);
    assert_eq!(selected.len(), 1);
    match selected[0] {
        PathAwareValue::Map((p, _map)) => {
            assert_eq!(p, &Path::try_from("/Tags/0")?);
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[test]
fn map_keys_filter_test() -> Result<(), Error> {
    let condition_str = r#"{
        Condition: {
            'aws:SourceVpc': ['vpc-123454'],
            'aws:IsSecure': false
        }
    }"#;
    let value = PathAwareValue::try_from(condition_str)?;
    let selection_str = r#"Condition[ keys == /aws:[Ss]ource(Vpc|VPC|VpcE|VPCE)/ ]"#;
    let access = AccessQuery::try_from(selection_str)?;
    let dummy = DummyEval {};
    let selected = value.select(access.match_all, &access.query, &dummy)?;
    println!("Selected = {:?}", selected);
    assert_eq!(selected.len(), 1);
    let inner = selected[0];
    if let PathAwareValue::List((p, l)) = inner {
        assert_eq!(p, &Path::try_from("/Condition/aws:SourceVpc")?);
        assert_eq!(l.len(), 1);
        let inner = &l[0];
        if let PathAwareValue::String((p, v)) = inner {
            assert_eq!(p, &Path::try_from("/Condition/aws:SourceVpc/0")?);
            assert_eq!(v, "vpc-123454");
        }
    }
    Ok(())
}

#[test]
fn merge_values_test() -> Result<(), Error> {
    let resources = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
        "#,
    )?)?;

    let parameters = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        PARAMETERS:
            ORG_IDS: ["o-2324/"]
        "#,
    )?)?;

    let resources = resources.merge(parameters)?;
    assert!(matches!(resources, PathAwareValue::Map(_)));
    let resources_map = match &resources {
        PathAwareValue::Map((_, map)) => map,
        _ => unreachable!(),
    };
    assert_eq!(resources_map.values.len(), 2);
    assert!(matches!(resources_map.values.get("PARAMETERS"), Some(_)),);

    let parameters = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        PARAMETERS:
            ORG_IDS: ["o-2324/"]
        "#,
    )?)?;
    let resources = resources.merge(parameters);
    assert!(resources.is_err());

    Ok(())
}
