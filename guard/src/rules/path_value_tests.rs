use crate::rules::exprs::{
    AccessClause, AccessQuery, FileLocation, GuardAccessClause, GuardClause, LetExpr, LetValue,
};
use pretty_assertions::assert_eq;

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
    assert!(resources_map.values.get("PARAMETERS").is_some());

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

/// Mixed integer and float operands order numerically, and exactly.
///
/// `compare_values` matched Int/Int and Float/Float and nothing in between, so every mixed
/// numeric comparison reached the `NotComparable` catch-all. `Size > 10` against a template
/// carrying `Size: 50.5` reported "PathAwareValues are not comparable float, int" and FAILed a
/// compliant volume. Worse in a `when` condition, where the non-PASS became a SKIP and dropped
/// the guarded body at exit 0 -- see `a_float_valued_gate_condition_still_guards_its_body` in
/// eval_tests.rs.
///
/// The precision cases below are the reason this is not `(i as f64).partial_cmp(f)`. `i64` values
/// above 2^53 do not survive a round trip through `f64`: `9007199254740993i64` (2^53 + 1) casts to
/// `9007199254740992.0`, so the lossy spelling reports `Equal` for two values that differ by one.
#[test]
fn mixed_int_and_float_operands_compare_numerically() {
    fn int(i: i64) -> PathAwareValue {
        PathAwareValue::Int((Path::root(), i))
    }
    fn flt(f: f64) -> PathAwareValue {
        PathAwareValue::Float((Path::root(), f))
    }

    // (int operand, float operand, how the int orders against the float)
    let cases: [(i64, f64, Ordering); 12] = [
        (50, 10.0, Ordering::Greater),
        (10, 50.5, Ordering::Less),
        (50, 50.0, Ordering::Equal),
        (50, 50.5, Ordering::Less), // same floor, float carries the fraction
        (51, 50.5, Ordering::Greater),
        (-1, -0.5, Ordering::Less), // floor(-0.5) is -1, and -0.5 is the larger
        (-1, -1.0, Ordering::Equal),
        (0, -0.0, Ordering::Equal),
        // 2^53 + 1 against 2^53: exact here, Equal under an `as f64` cast on the integer.
        (
            9_007_199_254_740_993,
            9_007_199_254_740_992.0,
            Ordering::Greater,
        ),
        // Out of i64 range in both directions: no cast, no saturation.
        (i64::MAX, 1.0e300, Ordering::Less),
        (i64::MIN, -1.0e300, Ordering::Greater),
        // i64::MIN is exactly -2^63, which f64 represents exactly.
        (i64::MIN, -9_223_372_036_854_775_808.0, Ordering::Equal),
    ];

    for (i, f, expected) in cases {
        assert_eq!(
            compare_values(&int(i), &flt(f)).unwrap(),
            expected,
            "comparing int {} against float {}",
            i,
            f
        );
        assert_eq!(
            compare_values(&flt(f), &int(i)).unwrap(),
            expected.reverse(),
            "comparing float {} against int {} (reversed operands)",
            f,
            i
        );
    }

    // The operators built on compare_values, so the fix reaches the surface the rules use.
    assert!(compare_gt(&flt(50.5), &int(10)).unwrap());
    assert!(compare_ge(&flt(50.5), &int(10)).unwrap());
    assert!(compare_lt(&int(10), &flt(50.5)).unwrap());
    assert!(compare_le(&int(10), &flt(50.5)).unwrap());
    assert!(compare_eq(&flt(50.0), &int(50)).unwrap());
    assert!(!compare_eq(&flt(50.5), &int(50)).unwrap());

    // NaN stays not-comparable, the same answer Float/Float already gave.
    assert!(matches!(
        compare_values(&int(1), &flt(f64::NAN)),
        Err(Error::NotComparable(_))
    ));
    assert!(matches!(
        compare_values(&flt(f64::NAN), &int(1)),
        Err(Error::NotComparable(_))
    ));
}

/// A number is inside a range of the other numeric kind, or outside it, but never incomparable.
///
/// `WithinRange` is generic over one type, so `i64` has an impl for `RangeType<i64>` and `f64` for
/// `RangeType<f64>`, and the two mixed pairings had none. The range table fell through to
/// `compare_values`, which reports `int` against `range(float, float)` as incomparable. So
/// `Size IN r[5.0, 100.0]` failed a `Size: 50` that sits inside the range: a wrong verdict, not a
/// wrong skip.
///
/// This is the same defect as `mixed_int_and_float_operands_compare_numerically` and was left behind
/// by that fix -- the widening landed on the scalar arms and stopped there.
///
/// Asserted against `compare_eq` only, because that is the table the evaluator consults. `PartialEq`
/// carries a second, partial copy of the same semantics; see the note on `impl Eq for PathAwareValue`
/// for why range membership does not belong there.
///
/// Boundaries are asserted in both polarities because the inclusivity flags are the part a lossy
/// conversion would break invisibly: a bound that rounds moves the edge without changing any
/// interior answer, so a test over interior values alone would pass against a broken implementation.
#[test]
fn mixed_numeric_range_membership_is_decided() {
    fn int(i: i64) -> PathAwareValue {
        PathAwareValue::Int((Path::root(), i))
    }
    fn flt(f: f64) -> PathAwareValue {
        PathAwareValue::Float((Path::root(), f))
    }
    fn range_f(lower: f64, upper: f64, inclusive: u8) -> PathAwareValue {
        PathAwareValue::RangeFloat((
            Path::root(),
            RangeType {
                lower,
                upper,
                inclusive,
            },
        ))
    }
    fn range_i(lower: i64, upper: i64, inclusive: u8) -> PathAwareValue {
        PathAwareValue::RangeInt((
            Path::root(),
            RangeType {
                lower,
                upper,
                inclusive,
            },
        ))
    }
    const BOTH: u8 = LOWER_INCLUSIVE | UPPER_INCLUSIVE;

    // (label, value, range, expected)
    let cases: [(&str, PathAwareValue, PathAwareValue, bool); 12] = [
        (
            "int inside a float range",
            int(50),
            range_f(5.0, 100.0, BOTH),
            true,
        ),
        (
            "int below a float range",
            int(1),
            range_f(5.0, 100.0, BOTH),
            false,
        ),
        (
            "int above a float range",
            int(500),
            range_f(5.0, 100.0, BOTH),
            false,
        ),
        (
            "float inside an int range",
            flt(50.5),
            range_i(5, 100, BOTH),
            true,
        ),
        (
            "float below an int range",
            flt(0.5),
            range_i(5, 100, BOTH),
            false,
        ),
        (
            "float above an int range",
            flt(500.5),
            range_i(5, 100, BOTH),
            false,
        ),
        // Edges, both polarities. An implementation that rounds a bound gets these wrong while
        // answering every interior case correctly.
        (
            "int on an inclusive float lower bound",
            int(5),
            range_f(5.0, 100.0, BOTH),
            true,
        ),
        (
            "int on an exclusive float lower bound",
            int(5),
            range_f(5.0, 100.0, UPPER_INCLUSIVE),
            false,
        ),
        (
            "int on an inclusive float upper bound",
            int(100),
            range_f(5.0, 100.0, BOTH),
            true,
        ),
        (
            "int on an exclusive float upper bound",
            int(100),
            range_f(5.0, 100.0, LOWER_INCLUSIVE),
            false,
        ),
        // 2^53 + 1 against a float bound of 2^53: the integer is the larger, so it is outside an
        // upper bound there. Casting it to f64 would round it down to equal and admit it.
        (
            "an integer above 2^53 against a float upper bound",
            int(9_007_199_254_740_993),
            range_f(0.0, 9_007_199_254_740_992.0, BOTH),
            false,
        ),
        // The mirror: the same integer as an inclusive lower bound accepts itself.
        (
            "an integer above 2^53 on its own float lower bound",
            int(9_007_199_254_740_993),
            range_f(9_007_199_254_740_993.0, 1.0e300, BOTH),
            true,
        ),
    ];

    for (label, value, range, expected) in cases {
        assert_eq!(
            compare_eq(&value, &range).unwrap(),
            expected,
            "compare_eq: {}",
            label
        );
    }
}
