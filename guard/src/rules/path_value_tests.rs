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

/// Values that compare equal hash equally, which is what `Eq` promises and what a `HashMap` keyed on
/// `PathAwareValue` relies on -- `report_at_least_one` keys one.
///
/// The break was narrow and easy to miss: `Float` hashed via `*f as u64`. That cast saturates, so
/// every negative float hashed as 0 while `Int(-1)` hashed as -1, and the two are equal since
/// integers and floats compare numerically. Nothing in the evaluator noticed, because the one live
/// consumer keys on map keys, which are strings. It was a latent unsoundness, not a wrong verdict --
/// worth pinning precisely because a future `HashSet<PathAwareValue>` would inherit it silently.
///
/// Asserted as the implication `eq => same hash`, not as specific hash values, since the hasher's
/// output is not part of the contract.
#[test]
fn equal_values_hash_equally() {
    fn hash_of(v: &PathAwareValue) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        v.hash(&mut hasher);
        hasher.finish()
    }
    fn int(i: i64) -> PathAwareValue {
        PathAwareValue::Int((Path::root(), i))
    }
    fn flt(f: f64) -> PathAwareValue {
        PathAwareValue::Float((Path::root(), f))
    }

    let equal_pairs = [
        (
            "negative, the case the saturating cast lost",
            int(-1),
            flt(-1.0),
        ),
        ("positive", int(1), flt(1.0)),
        ("zero", int(0), flt(0.0)),
        ("signed zero against its integer", int(0), flt(-0.0)),
        (
            "large but exactly representable",
            int(1 << 53),
            flt(9_007_199_254_740_992.0),
        ),
        (
            "most negative i64",
            int(i64::MIN),
            flt(-9_223_372_036_854_775_808.0),
        ),
    ];
    for (label, a, b) in equal_pairs {
        assert_eq!(a, b, "precondition, these must be equal: {}", label);
        assert_eq!(
            hash_of(&a),
            hash_of(&b),
            "equal but hashed differently: {}",
            label
        );
    }

    // The two spellings of zero are equal to each other, not only to the integer.
    assert_eq!(flt(0.0), flt(-0.0));
    assert_eq!(hash_of(&flt(0.0)), hash_of(&flt(-0.0)));

    // A float with a fraction is not equal to any integer, and must not be folded onto one by the
    // truncation the old cast performed.
    assert_ne!(flt(1.5), int(1));
    assert_ne!(hash_of(&flt(1.5)), hash_of(&int(1)));

    // Out of i64 range on both ends: no exact integer exists, so these hash their bits. Distinct
    // values must not collapse the way saturation collapsed them.
    assert_ne!(
        hash_of(&flt(f64::INFINITY)),
        hash_of(&flt(f64::NEG_INFINITY))
    );
    assert_ne!(hash_of(&flt(1.0e300)), hash_of(&flt(-1.0e300)));

    // A map's entries in two different orders. `eq` for a map is order-independent because it is a
    // lookup per key, so the hash has to be too -- and it was not, because `IndexMap` iterates in
    // insertion order. The `Int`/`Float` pairs above all sit in the scalar arms, so none of them
    // reached this one.
    fn map_of(entries: &[(&str, i64)]) -> PathAwareValue {
        let mut values = indexmap::IndexMap::new();
        let mut keys = vec![];
        for (key, value) in entries {
            values.insert((*key).to_string(), int(*value));
            keys.push(PathAwareValue::String((Path::root(), (*key).to_string())));
        }
        PathAwareValue::Map((Path::root(), MapValue { keys, values }))
    }

    let forward = map_of(&[("alpha", 1), ("beta", 2)]);
    let reversed = map_of(&[("beta", 2), ("alpha", 1)]);
    assert_eq!(
        forward, reversed,
        "precondition, a map's entry order does not affect equality"
    );
    assert_eq!(
        hash_of(&forward),
        hash_of(&reversed),
        "equal maps hashed differently because the entries were written in a different order"
    );

    // The sort must not flatten a real difference: same keys, one value changed.
    let changed = map_of(&[("alpha", 1), ("beta", 3)]);
    assert_ne!(forward, changed);
    assert_ne!(hash_of(&forward), hash_of(&changed));

    // Nor may it confuse a key with a value: `{alpha: 1, beta: 2}` against the pair swapped onto the
    // other key. Both hash the same four items, so hashing entries without their order would.
    let swapped = map_of(&[("alpha", 2), ("beta", 1)]);
    assert_ne!(forward, swapped);
    assert_ne!(hash_of(&forward), hash_of(&swapped));

    // A list, by contrast, is order-sensitive in `eq`, so it must stay order-sensitive in `hash`.
    let ordered = PathAwareValue::List((Path::root(), vec![int(1), int(2)]));
    let unordered = PathAwareValue::List((Path::root(), vec![int(2), int(1)]));
    assert_ne!(ordered, unordered);
    assert_ne!(hash_of(&ordered), hash_of(&unordered));
}

/// `eq` is symmetric, which `Eq` requires and range membership violated.
///
/// `Int(50) == RangeInt(5..100)` answered "is it inside", while the reverse pairing had no arm and
/// answered false. Membership is `compare_eq`'s job; this asserts it is no longer also `eq`'s.
#[test]
fn equality_is_symmetric_for_ranges() {
    let value = PathAwareValue::Int((Path::root(), 50));
    let range = PathAwareValue::RangeInt((
        Path::root(),
        RangeType {
            lower: 5,
            upper: 100,
            inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE,
        },
    ));

    assert_eq!(value == range, range == value, "eq must be symmetric");
    assert!(!(value == range), "a scalar is not equal to a range");

    // The membership answer still exists, in the table the evaluator consults.
    assert!(compare_eq(&value, &range).unwrap());
}

/// `==` answers a scalar against a range the same way whichever side the range is on, and `compare_eq`
/// on its own deliberately does not.
///
/// All five membership arms are written scalar-on-the-left and `compare_values` has none, so asked
/// directly with the range on the left the pair reaches the incomparable catch-all: `A == r[80,90]` was
/// PASS and `%l == A` for the same two values refused with `not comparable range(int, int), int`. `==`
/// is a symmetric relation -- the `Eq` comment on this type calls the identical shape in `PartialEq` a
/// symmetry bug -- so `compare_eq_symmetric` puts the operands in the order the table expects, and the
/// `==` operator asks that instead.
///
/// The one-directional table is asserted too, in the same test and on purpose. Mirroring it was tried
/// and reaches four other callers; three of them then answer a different question than the one written,
/// and six `IN`/`NOT IN` cells of the operator matrix moved. Anyone who "fixes" the asymmetry by adding
/// the five reverse arms has to delete an assertion that says why not.
///
/// Both bound types on both sides, because the mixed int/float pairings go through
/// `int_within_float_range` and `float_within_int_range` rather than `WithinRange`, and covering only
/// the same-type pairs would leave two of the four numeric cells asymmetric.
#[test]
fn range_membership_is_answered_in_both_operand_orders() {
    const BOTH: u8 = LOWER_INCLUSIVE | UPPER_INCLUSIVE;
    fn int(i: i64) -> PathAwareValue {
        PathAwareValue::Int((Path::root(), i))
    }
    fn flt(f: f64) -> PathAwareValue {
        PathAwareValue::Float((Path::root(), f))
    }
    fn chr(c: char) -> PathAwareValue {
        PathAwareValue::Char((Path::root(), c))
    }
    let range_i = PathAwareValue::RangeInt((
        Path::root(),
        RangeType {
            lower: 80i64,
            upper: 90i64,
            inclusive: BOTH,
        },
    ));
    let range_f = PathAwareValue::RangeFloat((
        Path::root(),
        RangeType {
            lower: 80.0f64,
            upper: 90.0f64,
            inclusive: BOTH,
        },
    ));
    let range_c = PathAwareValue::RangeChar((
        Path::root(),
        RangeType {
            lower: 'a',
            upper: 'z',
            inclusive: BOTH,
        },
    ));

    // (label, scalar, range, inside)
    let cases = [
        ("int in int range", int(85), &range_i, true),
        ("int outside int range", int(95), &range_i, false),
        ("float in float range", flt(85.5), &range_f, true),
        ("float outside float range", flt(95.5), &range_f, false),
        ("int in float range", int(85), &range_f, true),
        ("int outside float range", int(95), &range_f, false),
        ("float in int range", flt(85.5), &range_i, true),
        ("float outside int range", flt(95.5), &range_i, false),
        ("char in char range", chr('b'), &range_c, true),
        ("char outside char range", chr('1'), &range_c, false),
    ];

    for (label, scalar, range, inside) in cases {
        // Explicit format arguments: this crate is edition 2018, where `panic!` with a single string
        // literal passes it through unformatted, so an implicit capture would print the braces.
        let forward = compare_eq(&scalar, range).unwrap_or_else(|e| {
            panic!(
                "scalar on the left refused, which it never did: {}: {}",
                label, e
            )
        });
        assert_eq!(forward, inside, "scalar on the left: {}", label);

        // What `==` asks. Both orders, so this is symmetry rather than a second spelling of the
        // forward case.
        let sym_forward = compare_eq_symmetric(&scalar, range)
            .unwrap_or_else(|e| panic!("symmetric, scalar on the left: {}: {}", label, e));
        let sym_reversed = compare_eq_symmetric(range, &scalar)
            .unwrap_or_else(|e| panic!("symmetric, range on the left: {}: {}", label, e));
        assert_eq!(sym_forward, inside, "symmetric, scalar first: {}", label);
        assert_eq!(sym_reversed, inside, "symmetric, range first: {}", label);

        // And the table itself stays one-directional, which is what keeps `IN` reading `%range in
        // [15]` as "the range is one of these elements" rather than "15 is inside the range".
        assert!(
            compare_eq(range, &scalar).is_err(),
            "compare_eq answered a range on the left, which would leak into IN: {}",
            label
        );
    }

    // The swap is by pairing, not a blanket "a range is comparable with anything". A range against a
    // scalar of a kind its bounds are not still refuses, through the symmetric wrapper as well.
    let text = PathAwareValue::String((Path::root(), "85".to_string()));
    assert!(compare_eq(&text, &range_i).is_err());
    assert!(compare_eq_symmetric(&text, &range_i).is_err());
    assert!(compare_eq_symmetric(&range_i, &text).is_err());
    assert!(compare_eq_symmetric(&int(85), &range_c).is_err());
    assert!(compare_eq_symmetric(&range_c, &int(85)).is_err());

    // And a pair with no reverse arm keeps the operand order it arrived in, so the reason reads in the
    // order the clause is written. Swapping unconditionally is the obvious spelling of this function and
    // it reworded forty refusals into naming the right-hand kind first -- the same wrong-operand defect
    // as F10, introduced while fixing an asymmetry.
    let reason = compare_eq_symmetric(&range_i, &text)
        .unwrap_err()
        .to_string();
    assert!(
        reason.contains("range(int, int), String"),
        "the refusal named the operands in the opposite order to the clause: {}",
        reason
    );

    // Two ranges are already symmetric, so the wrapper must leave that pair alone rather than swapping
    // it and changing which one is read as the range.
    assert!(compare_eq_symmetric(&range_i, &range_i.clone()).unwrap());
    assert!(compare_eq_symmetric(&range_i, &range_f).is_err());
}

/// A range equals itself, which `impl Eq for PathAwareValue` promises and none of the three range
/// variants delivered.
///
/// `PartialEq` had no range-against-range arm at all, so the fall-through asked `compare_values`,
/// which reports two ranges as incomparable -- and a value was therefore not equal to itself. The
/// commit that removed the scalar-against-range membership arms closed a symmetry hole and left this
/// reflexivity one open; a reviewer found it by writing exactly this assertion.
///
/// All three variants, because the defect was in the missing arm rather than in any one type: the
/// report named two of them and the third was broken identically.
#[test]
fn a_range_is_equal_to_itself() {
    fn hash_of(v: &PathAwareValue) -> u64 {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        v.hash(&mut hasher);
        hasher.finish()
    }
    const BOTH: u8 = LOWER_INCLUSIVE | UPPER_INCLUSIVE;

    let ranges = [
        (
            "RangeInt",
            PathAwareValue::RangeInt((
                Path::root(),
                RangeType {
                    lower: 5i64,
                    upper: 100i64,
                    inclusive: BOTH,
                },
            )),
        ),
        (
            "RangeFloat",
            PathAwareValue::RangeFloat((
                Path::root(),
                RangeType {
                    lower: 5.0f64,
                    upper: 100.0f64,
                    inclusive: BOTH,
                },
            )),
        ),
        (
            "RangeFloat with negative bounds",
            PathAwareValue::RangeFloat((
                Path::root(),
                RangeType {
                    lower: -100.5f64,
                    upper: -5.5f64,
                    inclusive: BOTH,
                },
            )),
        ),
        (
            "RangeChar",
            PathAwareValue::RangeChar((
                Path::root(),
                RangeType {
                    lower: 'a',
                    upper: 'z',
                    inclusive: BOTH,
                },
            )),
        ),
    ];

    for (label, range) in &ranges {
        assert_eq!(range, &range.clone(), "{} is not equal to itself", label);
        assert_eq!(
            hash_of(range),
            hash_of(&range.clone()),
            "{} hashes differently from itself",
            label
        );
        // The same question asked of the other equality function, which is the one `==` actually
        // reaches: `EqOperation` hands `compare_eq` to `match_value`. It had no range-against-range
        // arm either, so `%allowed == r[80,90]` refused with `not comparable range(int, int),
        // range(int, int)` and reported `Value=[80,90] not equal to value [80,90]`, while
        // `in [r[80,90]]` passed on the same pair because `contained_in` consults `PartialEq` first.
        // One entry point being reflexive is not enough when the operator uses the other.
        assert!(
            compare_eq(range, &range.clone()).unwrap(),
            "compare_eq: {} is not equal to itself",
            label
        );
    }

    // Different ranges of the same kind stay unequal, so reflexivity was not bought by making every
    // range equal to every other.
    let five_to_100 = &ranges[0].1;
    let six_to_100 = PathAwareValue::RangeInt((
        Path::root(),
        RangeType {
            lower: 6i64,
            upper: 100i64,
            inclusive: BOTH,
        },
    ));
    assert_ne!(five_to_100, &six_to_100);
    assert!(!compare_eq(five_to_100, &six_to_100).unwrap());

    // Inclusivity is part of the range, not decoration: two ranges over the same bounds that differ
    // only in whether an endpoint is included are different ranges.
    let five_to_100_exclusive = PathAwareValue::RangeInt((
        Path::root(),
        RangeType {
            lower: 5i64,
            upper: 100i64,
            inclusive: LOWER_INCLUSIVE,
        },
    ));
    assert_ne!(five_to_100, &five_to_100_exclusive);
    assert!(!compare_eq(five_to_100, &five_to_100_exclusive).unwrap());

    // Ranges of different kinds are not equal, and must not error either.
    assert_ne!(&ranges[0].1, &ranges[1].1);

    // Through `compare_eq` the same pair refuses rather than answering false, and that difference is
    // deliberate on both sides. `compare_eq` returns the error so the clause can name the reason;
    // `PartialEq` cannot return one and swallows it, which `docs/KNOWN_ISSUES.md` records. A
    // `RangeInt` and a `RangeFloat` are two kinds, not two ranges, so refusing is the honest answer
    // and the arms added for the same-kind case must not widen to this one.
    assert!(compare_eq(&ranges[0].1, &ranges[1].1).is_err());

    // The collection arms recurse, so a range nested in one inherits whichever answer the range
    // itself gets. This is the `{p: r[80,90]} == {p: r[80,90]}` case, which refused before the arms
    // existed even though `PartialEq` on the same two maps answered true.
    let map_with_range = |range: &PathAwareValue| {
        let mut values = indexmap::IndexMap::new();
        values.insert("p".to_string(), range.clone());
        PathAwareValue::Map((
            Path::root(),
            MapValue {
                keys: vec![PathAwareValue::String((Path::root(), "p".to_string()))],
                values,
            },
        ))
    };
    assert!(compare_eq(&map_with_range(five_to_100), &map_with_range(five_to_100)).unwrap());
    assert!(!compare_eq(&map_with_range(five_to_100), &map_with_range(&six_to_100)).unwrap());

    let list_with_range =
        |range: &PathAwareValue| PathAwareValue::List((Path::root(), vec![range.clone()]));
    assert!(compare_eq(&list_with_range(five_to_100), &list_with_range(five_to_100)).unwrap());
    assert!(!compare_eq(&list_with_range(five_to_100), &list_with_range(&six_to_100)).unwrap());
}

/// An index refers to one element or to none, and never silently to the wrong one.
///
/// Two defects met in `index_offset`, both of which ran without complaint and answered wrongly.
///
/// The parser narrowed an index literal with `as i32` at both parse sites, so an out-of-range index
/// wrapped onto a valid element: on `["safe", "other"]`, `Items[4294967296]` became `Items[0]` and a
/// clause comparing it against `"safe"` passed. Reported by a reviewer with five worked cases, all
/// covered below.
///
/// And a negative index was taken as its own magnitude rather than counted from the end, so on
/// `[a, b, c]`, `Items[-1]` was `b` and `Items[-3]` was out of bounds. Undocumented and unasserted in
/// either direction, which is how it survived; `docs/CLAUSES.md` now states the behaviour.
#[test]
fn an_index_names_one_element_or_none() {
    // (index, len, expected offset)
    let cases: [(i64, usize, Option<usize>); 16] = [
        // Ordinary positive indexing.
        (0, 3, Some(0)),
        (1, 3, Some(1)),
        (2, 3, Some(2)),
        (3, 3, None),
        // Negative counts back from the end, so -1 is the last element and -len is the first.
        (-1, 3, Some(2)),
        (-2, 3, Some(1)),
        (-3, 3, Some(0)),
        (-4, 3, None),
        // The reviewer's cases. Each of these used to wrap onto a real element through `as i32`.
        (4_294_967_295, 2, None),
        (4_294_967_296, 2, None),
        (4_294_967_297, 2, None),
        (i64::MAX, 2, None),
        (-4_294_967_296, 2, None),
        // `i64::MIN` has no positive counterpart, which is why the magnitude is taken with
        // `unsigned_abs` rather than by negating.
        (i64::MIN, 2, None),
        // An empty collection has no offsets at all, in either direction.
        (0, 0, None),
        (-1, 0, None),
    ];

    for (index, len, expected) in cases {
        assert_eq!(
            index_offset(index, len),
            expected,
            "index {} into {} elements",
            index,
            len
        );
    }
}
