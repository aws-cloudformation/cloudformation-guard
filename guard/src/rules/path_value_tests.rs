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
/// `PathAwareValue` relies on -- `report_by_lhs` keys one.
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
    fn chr(c: char) -> PathAwareValue {
        PathAwareValue::Char((Path::root(), c))
    }
    fn string(s: &str) -> PathAwareValue {
        PathAwareValue::String((Path::root(), s.to_string()))
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
        // The second widening `compare_values` reaches, and the one this test did not cover when the
        // arms for it were added: `Char` hashed through `Hash for char` (`write_u32`) while the equal
        // `String` hashed through `Hash for str` (`write` then a `0xff` terminator).
        (
            "a char against the string that spells it",
            chr('b'),
            string("b"),
        ),
        // Multi-byte, so the `encode_utf8` buffer is exercised past one byte. `'é'` is two bytes in
        // UTF-8 and a `to_string()` would have hidden a buffer that was too small.
        ("a multi-byte char", chr('é'), string("é")),
        // Four bytes, the widest `encode_utf8` can produce.
        (
            "an astral-plane char",
            chr('\u{1F600}'),
            string("\u{1F600}"),
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

    // A `Char` nested in a list. `eq` for a list is element-wise `eq`, so the widening reaches through
    // the collection arms; the hash has to reach through them the same way, and the `List` arm hashing
    // each element is what makes it. The same holds inside a map value.
    let char_in_list = PathAwareValue::List((Path::root(), vec![chr('b'), int(1)]));
    let string_in_list = PathAwareValue::List((Path::root(), vec![string("b"), int(1)]));
    assert_eq!(
        char_in_list, string_in_list,
        "precondition, element-wise eq"
    );
    assert_eq!(hash_of(&char_in_list), hash_of(&string_in_list));

    // The widening does not flatten a real difference: a char is not the two-character string that
    // starts with it, and must not hash as one.
    assert_ne!(chr('b'), string("bc"));
    assert_ne!(hash_of(&chr('b')), hash_of(&string("bc")));
    // Nor is it a different character.
    assert_ne!(chr('b'), string("c"));
    assert_ne!(hash_of(&chr('b')), hash_of(&string("c")));
    // And the empty string, which no char spells.
    assert_ne!(chr('b'), string(""));
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

/// No comparison against a NaN answers, the four range-membership ones included.
///
/// `libyaml/loader.rs` keeps `Float(NaN)` out of the value space and states why: the type asserts `Eq`
/// and hashes its own contents, and a NaN is not equal to itself. The `serde_yaml` conversion, which is
/// what `cfn-guard test` and the library entry point read a document through, has no such gate, so a
/// NaN is reachable and the comparison layer has to behave.
///
/// Ordering and scalar equality already refused, through `compare_values` and `compare_int_to_float`.
/// Range membership did not: `is_within` is `le`/`lt`/`ge`/`gt`, all false for a NaN, and
/// `float_within_int_range` reads `compare_int_to_float`'s `None` through a `_ => false` arm. Both
/// answered "not in the range", which is a decision -- and `!=` and `NOT IN` invert a decision, so
/// `A not in r[-1,1]` *passed* for a NaN and a denylist admitted a value that is not a number.
///
/// Asserted as "every operator refuses", not as a verdict, because a refusal is what fails both
/// polarities and so cannot be inverted into a pass.
#[test]
fn nothing_compares_against_a_nan() {
    const BOTH: u8 = LOWER_INCLUSIVE | UPPER_INCLUSIVE;
    let nan = PathAwareValue::Float((Path::root(), f64::NAN));
    let range_f = PathAwareValue::RangeFloat((
        Path::root(),
        RangeType {
            lower: -1.0f64,
            upper: 1.0f64,
            inclusive: BOTH,
        },
    ));
    let range_i = PathAwareValue::RangeInt((
        Path::root(),
        RangeType {
            lower: -1i64,
            upper: 1i64,
            inclusive: BOTH,
        },
    ));

    let others = [
        (
            "another NaN",
            PathAwareValue::Float((Path::root(), f64::NAN)),
        ),
        ("a float", PathAwareValue::Float((Path::root(), 0.0))),
        ("an integer", PathAwareValue::Int((Path::root(), 0))),
        ("a float range", range_f),
        ("an integer range", range_i),
    ];

    for (label, other) in &others {
        assert!(
            compare_eq(&nan, other).is_err(),
            "compare_eq answered a NaN against {}",
            label
        );
        assert!(
            compare_eq_symmetric(&nan, other).is_err(),
            "compare_eq_symmetric answered a NaN against {}",
            label
        );
    }

    // The ordering comparators take no range, so they are checked against the scalars only. All four,
    // because each reads `compare_values`'s `Ordering` through its own match and a missing arm in any
    // one of them would answer.
    for (label, other) in others.iter().take(3) {
        for (name, cmp) in [
            (
                "lt",
                compare_lt as fn(&PathAwareValue, &PathAwareValue) -> crate::rules::Result<bool>,
            ),
            ("le", compare_le),
            ("gt", compare_gt),
            ("ge", compare_ge),
        ] {
            assert!(
                cmp(&nan, other).is_err(),
                "compare_{} answered a NaN against {}",
                name,
                label
            );
        }
    }

    // A finite float in the same ranges still decides, so the gate is on the value and not on the arm.
    let inside = PathAwareValue::Float((Path::root(), 0.5));
    let outside = PathAwareValue::Float((Path::root(), 5.5));
    for (label, range) in [
        ("a float range", &others[3].1),
        ("an integer range", &others[4].1),
    ] {
        assert!(
            compare_eq(&inside, range).unwrap(),
            "a float inside {} stopped matching",
            label
        );
        assert!(
            !compare_eq(&outside, range).unwrap(),
            "a float outside {} started matching",
            label
        );
    }
}

/// A `Char` compares with a string, which is the only spelling the rules language has for a character.
///
/// `parse_char` is a shipped guard-language function and its documented example is
/// `let converted = parse_char(%sg.Properties.Char)` then `%converted == '1'`. That failed for every
/// input with `not comparable char, String`, blaming the template's type for a comparison the language
/// cannot express any other way: `parse_scalar_value` has no `Char` alternative, so `'1'` and `"1"` are
/// both `Value::String` and the single-quote spelling is not a character literal. `parse_char` was the
/// only one of the five converters whose result could not be checked against a literal.
///
/// In `compare_values`, so ordering and equality agree. Asserted through all five comparison functions
/// for that reason -- a fix in `compare_eq` alone would leave `%c == "b"` deciding and `%c < "c"`
/// refusing.
#[test]
fn a_char_compares_with_a_one_character_string() {
    fn chr(c: char) -> PathAwareValue {
        PathAwareValue::Char((Path::root(), c))
    }
    fn txt(s: &str) -> PathAwareValue {
        PathAwareValue::String((Path::root(), s.to_string()))
    }

    // The documented example, both quotings, which reach the same `Value::String`.
    assert!(compare_eq(&chr('1'), &txt("1")).unwrap());
    assert!(compare_eq(&txt("1"), &chr('1')).unwrap());
    assert!(!compare_eq(&chr('1'), &txt("2")).unwrap());
    assert!(!compare_eq(&txt("2"), &chr('1')).unwrap());

    // Ordering, in both operand positions, and consistent with equality rather than separate from it.
    assert!(compare_lt(&chr('b'), &txt("c")).unwrap());
    assert!(!compare_lt(&chr('b'), &txt("a")).unwrap());
    assert!(compare_gt(&txt("c"), &chr('b')).unwrap());
    assert!(compare_le(&chr('b'), &txt("b")).unwrap());
    assert!(compare_ge(&chr('b'), &txt("b")).unwrap());

    // A longer string is not equal to a character and still orders against it, rather than the
    // comparison refusing on a length the types do not carry.
    assert!(!compare_eq(&chr('b'), &txt("bc")).unwrap());
    assert!(compare_lt(&chr('b'), &txt("bc")).unwrap());
    assert!(compare_gt(&chr('b'), &txt("")).unwrap());

    // The answer a `Char` gets is the answer the same value gets before conversion. That equivalence is
    // the reason to compare as strings: applying `parse_char` must not change a verdict the language
    // could already reach.
    for other in ["1", "2", "b", "bc", ""] {
        assert_eq!(
            compare_values(&chr('b'), &txt(other)).unwrap(),
            compare_values(&txt("b"), &txt(other)).unwrap(),
            "a Char ordered differently from the same one-character string against {:?}",
            other
        );
    }

    // Same-kind comparison is untouched, and a kind with no arm still refuses -- the new arms are a
    // pair of types, not a general loosening.
    assert!(compare_eq(&chr('b'), &chr('b')).unwrap());
    assert!(compare_lt(&chr('b'), &chr('c')).unwrap());
    assert!(compare_eq(&chr('b'), &PathAwareValue::Int((Path::root(), 15))).is_err());
    assert!(compare_eq(&chr('b'), &PathAwareValue::Bool((Path::root(), true))).is_err());
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
/// Without a range-against-range arm in `PartialEq`, the fall-through asks `compare_values`, which
/// reports two ranges as incomparable -- and a value is then not equal to itself. Removing the
/// scalar-against-range membership arms closes a symmetry hole and leaves this reflexivity one open
/// unless an arm answers it; exactly this assertion exposes it.
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
/// An index literal narrowed with `as i32` at either parse site would wrap an out-of-range index onto a
/// valid element: on `["safe", "other"]`, `Items[4294967296]` would become `Items[0]` and a clause
/// comparing it against `"safe"` would pass.
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
        // Indices wider than 32 bits: an `as i32` cast would wrap each of these onto a real element.
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

/// Two lists are decided on length first, and on equal lengths whatever an element raises is the answer.
///
/// The `(List, List)` arm has two exits and the difference between them is load-bearing for comments in
/// two other files. On unequal lengths it answers `false` without asking an element anything. On equal
/// lengths it zips and calls itself with `?`, so a pair that refuses refuses for the whole comparison.
///
/// Unasserted until now, and the gap cost two wrong comments. `incomparable_membership` in `eval.rs`
/// said this arm "always returns `Ok` -- `false` on a length mismatch, never a refusal", and the
/// `(List, Regex)` note beneath it concluded from that premise that a whole-list left-hand side can never
/// reach the regex engine. The second case below is the counterexample: it is the pair
/// `Cat NOT IN [[/re/]]` builds, and the zip walks straight into `(String, Regex)`.
///
/// The first case is the length exit alone, which the false-alarm discriminator in that same comment
/// would rest on if the predicate compared whole values: `Strs NOT IN ["x","y",["p"]]` would stay silent,
/// because a two-element `Strs` against a one-element `["p"]` mismatches on length and answers before any
/// element is looked at. The predicate compares elements, so that clause is noticed and the discriminator
/// does not turn on this exit -- but the exit itself is still what `compare_eq` does with an unequal
/// pair, and `contained_in`'s whole-list membership reading still asks it. The case holds a refusing
/// element on purpose, so that a future change making the length exit compare eagerly cannot pass this
/// test.
#[test]
fn two_equal_length_lists_propagate_what_their_elements_raise() {
    let list = |elems: Vec<PathAwareValue>| PathAwareValue::List((Path::root(), elems));
    let txt = |s: &str| PathAwareValue::String((Path::root(), s.to_string()));

    // Thirty `a` characters is the length at which `(?!x)((a+)+)b` exhausts `fancy_regex`'s backtracking
    // budget, the same subject the eval tests use. The pattern is stored without its slashes, which is
    // what `parse_regex_inner` hands the value.
    let catastrophic = PathAwareValue::Regex((Path::root(), "(?!x)((a+)+)b".to_string()));
    let thirty_a = txt(&"a".repeat(30));

    assert!(
        !compare_eq(
            &list(vec![thirty_a.clone(), txt("b")]),
            &list(vec![catastrophic.clone()])
        )
        .unwrap(),
        "lists of different lengths must answer false without asking their elements, even when one \
         element pair would have refused"
    );

    let spent = compare_eq(&list(vec![thirty_a]), &list(vec![catastrophic])).expect_err(
        "a String zipped against a Regex must reach the engine, not answer structurally",
    );
    assert!(
        matches!(spent, Error::RegexError(_)),
        "expected the spent backtracking budget to propagate out of the zip, got {:?}",
        spent
    );

    // Not a property of regexes. Any element pair the function cannot decide propagates the same way,
    // which is why the arm cannot be described as always answering.
    let refused = compare_eq(
        &list(vec![PathAwareValue::Int((Path::root(), 1))]),
        &list(vec![txt("1")]),
    )
    .expect_err("an Int against a String has no arm, so the pair of lists must refuse");
    assert!(
        matches!(refused, Error::NotComparable(_)),
        "expected NotComparable to propagate out of the zip, got {:?}",
        refused
    );
}

/// A passing `Filter` over a list steps over an `AllIndices` that follows it.
///
/// THE CENSUS OF SLOT-SKIPPING SITES LIVES HERE, and
/// `a_variable_rooted_query_skips_its_reserved_slot_one` in `evaluate_tests.rs` points at this one.
/// Two sites skip a slot on its shape alone rather than evaluating it:
/// this one, and `evaluate.rs`'s `resolve_variable_query`. `eval_context`'s root-variable arm was
/// counted a third and is not one: `query_retrieval_with_converter` decides whether to consume the
/// reserved slot, asking `query_projects` and `expansion_at`. That arm's own comment is the account of
/// why, and `access_query`'s variable branch carries what it means for the reservation. Changing this
/// one's `QueryPart::AllIndices(_) => 2` to `=> 1` left the entire workspace green -- 3241 passed, 0
/// failed, 16 targets -- so the behavior was load-bearing and unpinned at once. A panic probe in this
/// branch reddened 11 tests, so the line does run; the silence was missing assertions, not dead code.
///
/// What hid the mutation is what a careless witness would trip over. `AllIndices` is a pass-through
/// no-op on anything that is not a `List`: the `AllIndices` arm above sends a `Map` or a scalar
/// straight on with `rest.select(all, &query[1..], resolver)`. A filter over a list of maps -- the
/// ordinary shape, `Resources.*[ Type == 'X' ]` -- therefore cannot tell skipping from applying, and
/// that is every filter in the existing corpus. The elements have to be lists themselves, which is why
/// this test filters a list of lists.
///
/// A DIFFERENT INVARIANT WITH THE SAME SHAPE, AND IT IS WRONG HERE. The other skipping site,
/// `resolve_variable_query`, is protected by the parser: `access_query` guarantees that slot 1 of a
/// `%var`-rooted query is `AllIndices(None)`, inserting one when the author wrote something else, so
/// matching `AllIndices(_)` there can only ever match the reserved no-op. This site has no such
/// guarantee. `query[0]` is a `Filter` reached by recursion, and `query[1]` is whatever the author
/// wrote next. `dotted_access` needs no separator between bracket forms, and `all_indices` reads
/// `[ name ]` as `AllIndices(Some(name))` -- a key capture, real work rather than a no-op -- so
/// `<list>[ <filter> ][ name ].<rest>` parses today and this line silently drops the capture. A digit
/// in the brackets would be `Index` and not affected; the defective spelling needs an identifier.
///
/// WHY THAT IS NOT A USER-VISIBLE BUG. `PathAwareValue::select` is not reachable from any command.
/// Every subcommand that evaluates -- `validate` and `test`, in both plain and structured form, plus
/// the library and FFI entry `run_checks` -- goes through `eval_context::root_scope` paired with
/// `eval_rules_file`: `commands/validate.rs:966` and `:971`,
/// `commands/reporters/validate/structured.rs:165` and `:174`, `commands/reporters/mod.rs:128` and
/// `:140`, `commands/reporters/test/generic.rs:166` and `:167`,
/// `commands/reporters/test/structured.rs:393` and `:400`, `commands/helper.rs:79` and `:80`. The other
/// three subcommands never evaluate at all: `parse-tree`, `rulegen`, and `completions`. Nothing under
/// `guard/src/commands/` so much as names `rules::evaluate`. Sharper still, the legacy engine has no
/// root context outside tests -- `RootScope::new` is itself behind `#[cfg(test)]` at
/// `evaluate.rs:1084` -- so `RulesFile::evaluate` cannot be entered in a release build even in
/// principle. `MetadataAppender` at `commands/aws_meta_appender.rs:7` is the only other
/// `EvaluationContext` that calls `select`, and its single construction site is
/// `aws_meta_appender_tests.rs:70`, in a file included only under `#[cfg(test)]`. `StackTracker` at
/// `commands/tracker.rs:33` implements the same trait and is constructed nowhere in the repository.
///
/// So the wrong answer for `[ name ]` after a filter is latent, not live. It would become live the
/// moment anything routes a command through this engine -- a new reporter reaching for `select`, or a
/// non-test `RootScope::new` -- and the fix at that point is to narrow this match to
/// `AllIndices(None)`, which is what the parser already guarantees at the one skipping site that is
/// protected, `resolve_variable_query`.
#[test]
fn a_filter_skips_an_all_indices_that_follows_it() -> Result<(), Error> {
    let value = PathAwareValue::try_from(r#"{ "Groups": [ [1, 2], [3, 4] ] }"#)?;
    let dummy = DummyEval {};

    let query = AccessQuery::try_from("Groups[ this !empty ][*]")?;
    assert_eq!(
        query.query.len(),
        3,
        "expected Key, Filter, AllIndices, got {:?}",
        query.query
    );
    assert!(
        matches!(query.query[1], QueryPart::Filter(..)),
        "the filter must sit at slot 1 so that select recurses with it at query[0], got {:?}",
        query.query[1]
    );
    assert!(
        matches!(query.query[2], QueryPart::AllIndices(None)),
        "the part this site skips must be an AllIndices, got {:?}",
        query.query[2]
    );

    let selected = value.select(query.match_all, &query.query, &dummy)?;

    assert_eq!(
        selected.len(),
        2,
        "the filter passes both groups and the AllIndices after it is skipped, so the two groups \
         themselves are selected; applying it instead would flatten them to four scalars, got {:?}",
        selected
    );
    for each in &selected {
        assert!(
            matches!(each, PathAwareValue::List(_)),
            "each selection is a whole group, not one of its members, got {:?}",
            each
        );
    }

    Ok(())
}

/// A null against a non-null value is a decided inequality, not a refusal.
///
/// `compare_eq` had arms for every like-typed pair and a `(Null, Null)` arm through `compare_values`,
/// but nothing for a null on one side only. That pair fell through to `compare_values`'s catch-all and
/// came back `NotComparable`. A refusal fails both polarities -- the negation wrapper passes it through
/// untouched, correctly, since "could not be answered" must not become a pass -- so `X != null` could
/// never PASS on any input, and `X == null` on a present value failed for the reason "not comparable
/// String, null" rather than "not equal". A `when X != null { ... }` gate, which the rules parser's own
/// documentation offers as the idiom for "X is set", therefore never opened: the guarded body was
/// skipped at exit 0 for every template, present or not.
///
/// Equality only. Ordering a value against null has no sensible answer and `compare_lt` and friends
/// keep refusing it; the arm is in `compare_eq`, after the typed pairs and before the fallthrough, so
/// the ordering operators never see it.
#[test]
fn a_null_against_a_non_null_value_is_not_equal() -> Result<(), Error> {
    let null = PathAwareValue::Null(Path::root());
    let text =
        PathAwareValue::String((Path::root(), "arn:aws:kms:us-east-1:1:key/abc".to_string()));
    let number = PathAwareValue::Int((Path::root(), 7));
    let flag = PathAwareValue::Bool((Path::root(), true));
    let map = PathAwareValue::try_from(r#"{ "Encrypted": false }"#)?;
    let list = PathAwareValue::try_from(r#"[1, 2]"#)?;

    for other in [&text, &number, &flag, &map, &list] {
        assert!(
            !compare_eq(other, &null)?,
            "{} == null must answer false, not refuse",
            other.type_info()
        );
        assert!(
            !compare_eq(&null, other)?,
            "null == {} must answer false, not refuse",
            other.type_info()
        );
    }

    // The pair that always worked keeps working.
    assert!(compare_eq(
        &null,
        &PathAwareValue::Null(Path::new("/x".to_string(), 3, 1))
    )?);

    // A range or a regex against null stays a refusal. "Is null inside r[0,1023]" and "does null
    // match /^public-/" have no answer, and answering false would let `Port != r[0,1023]` and
    // `Name != /^public-/` PASS on a property that is present and null -- a port rule and a naming
    // rule both satisfied by a value that is not a port and not a name. The arm names the kinds that
    // do answer and leaves these four to the fallthrough.
    const BOTH: u8 = LOWER_INCLUSIVE | UPPER_INCLUSIVE;
    let unordered = [
        PathAwareValue::RangeInt((
            Path::root(),
            RangeType {
                lower: 0,
                upper: 1023,
                inclusive: BOTH,
            },
        )),
        PathAwareValue::RangeFloat((
            Path::root(),
            RangeType {
                lower: 0.0,
                upper: 1.0,
                inclusive: BOTH,
            },
        )),
        PathAwareValue::RangeChar((
            Path::root(),
            RangeType {
                lower: 'a',
                upper: 'z',
                inclusive: BOTH,
            },
        )),
        PathAwareValue::Regex((Path::root(), "^public-".to_string())),
    ];
    for other in &unordered {
        for (first, second) in [(other, &null), (&null, other)] {
            match compare_eq(first, second) {
                Err(Error::NotComparable(_)) => {}
                other => panic!(
                    "{} against {} must refuse as not comparable, got {:?}",
                    first.type_info(),
                    second.type_info(),
                    other
                ),
            }
        }
    }

    // Ordering against null still has no answer.
    assert!(compare_lt(&text, &null).is_err());
    assert!(compare_gt(&null, &number).is_err());

    Ok(())
}

/// A map key's path names the key, whichever constructor built the map.
///
/// The two constructors disagreed. `TryFrom<(&Value, Path)>`, the serde route, pushed each key with
/// `path.extend_string(key)`, so the key `Bad` under `Resources` was pathed `/Resources/Bad`;
/// `try_from_marked`, the libyaml route every `validate` run takes, pushed it with
/// `path.with_location(loc)`, the mapping's own path, so the same key was pathed `/Resources`. A
/// failing comparison on a captured key -- `Resources[ nm | ... ]` then `%nm == "Good"` -- reported
/// `from.path` as `/Resources/Bad` under `test` and `run_checks` and as bare `/Resources` under
/// `validate -o json`, the one route a template author actually uses, and that is the field that
/// loses the resource name. `merge` already agreed with the serde shape.
///
/// The keyed path wins because it is the one that names the resource, and the libyaml location stays
/// on it: the line and column are the key's, which is where the author will look.
#[test]
fn a_map_key_is_pathed_to_itself_under_both_constructors() -> Result<(), Error> {
    const TEMPLATE: &str = "Resources:
  Good:
    Type: X
    Properties:
      Public: true
  Bad:
    Type: X
    Properties:
      Public: true
";

    // (key, its path, its line, its column), in document order.
    fn resource_keys(value: &PathAwareValue) -> Vec<(String, String, usize, usize)> {
        let PathAwareValue::Map((_, root)) = value else {
            panic!("the document is a map, got {:?}", value);
        };
        let Some(PathAwareValue::Map((_, resources))) = root.values.get("Resources") else {
            panic!("Resources is a map, got {:?}", root.values.get("Resources"));
        };
        resources
            .keys
            .iter()
            .map(|key| match key {
                PathAwareValue::String((path, name)) => {
                    (name.clone(), path.0.clone(), path.1.line, path.1.col)
                }
                other => panic!("a map key is a string, got {:?}", other),
            })
            .collect()
    }

    fn value_path(value: &PathAwareValue, key: &str) -> String {
        let PathAwareValue::Map((_, root)) = value else {
            unreachable!()
        };
        let Some(PathAwareValue::Map((_, resources))) = root.values.get("Resources") else {
            unreachable!()
        };
        resources.values.get(key).unwrap().self_path().0.clone()
    }

    let libyaml = PathAwareValue::try_from(read_from(TEMPLATE)?)?;
    let serde = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(TEMPLATE)?)?;

    assert_eq!(
        resource_keys(&libyaml),
        vec![
            ("Good".to_string(), "/Resources/Good".to_string(), 2, 3),
            ("Bad".to_string(), "/Resources/Bad".to_string(), 6, 3),
        ],
        "the libyaml route keys each key by name and keeps the key's own line and column"
    );
    assert_eq!(
        resource_keys(&serde),
        vec![
            ("Good".to_string(), "/Resources/Good".to_string(), 0, 0),
            ("Bad".to_string(), "/Resources/Bad".to_string(), 0, 0),
        ],
        "the serde route has no locations and keys each key by name"
    );

    // Controls: the values were pathed by name under both routes before, and still are.
    for value in [&libyaml, &serde] {
        assert_eq!(value_path(value, "Bad"), "/Resources/Bad");
    }

    // `merge` agreed with the keyed shape already and keeps doing so.
    let merged = PathAwareValue::try_from(r#"{ "A": 1 }"#)?
        .merge(PathAwareValue::try_from(r#"{ "B": 2 }"#)?)?;
    let PathAwareValue::Map((_, merged)) = &merged else {
        unreachable!()
    };
    let merged_keys: Vec<&str> = merged
        .keys
        .iter()
        .map(|key| key.self_path().0.as_str())
        .collect();
    assert_eq!(merged_keys, vec!["/A", "/B"]);

    Ok(())
}

/// An `EvaluationContext` that answers `%names` with a fixed list of key names, for the legacy
/// resolver's variable-interpolation arm.
struct NamesResolver {
    names: Vec<PathAwareValue>,
}

impl EvaluationContext for NamesResolver {
    fn resolve_variable(&self, variable: &str) -> crate::rules::Result<Vec<&PathAwareValue>> {
        assert_eq!(
            variable, "names",
            "only %names is interpolated in these tests"
        );
        Ok(self.names.iter().collect())
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

fn selected_strings(selected: &[&PathAwareValue]) -> Vec<String> {
    selected
        .iter()
        .map(|each| match each {
            PathAwareValue::String((_, s)) => s.clone(),
            other => format!("{:?}", other),
        })
        .collect()
}

/// An index after an interpolated key selects the key, and is then not applied to the value as well.
///
/// The variable-interpolation arm of `select` peeks at `query[1]`: an `Index` there says which of the
/// resolved key names to use, and the arm narrowed `keys` to that one. It then recursed with
/// `&query[1..]` for every shape of `query[1]`, so the index it had just consumed was walked a second
/// time, on the value the key selected. `Resources.%names[0].Type` picked `A` and then tried to index
/// into A's map: an empty selection with `all` false, an `IncompatibleRetrievalError` naming
/// `Remaining Query = 0.Type` with `all` true, and `Type` never read. The form without an index always
/// worked, which is what let it hide.
///
/// Latent. This resolver is reached from no command: every subcommand evaluates through
/// `eval_context::root_scope`, whose own interpolation path has had this fix since it was found there,
/// and `RootScope::new` is behind `#[cfg(test)]`. The census of callers is in the comment on
/// `a_filter_skips_an_all_indices_that_follows_it` above. Fixed anyway, because the two engines
/// answering the same query differently is the condition that lets a future caller inherit the wrong
/// answer.
#[test]
fn an_index_after_an_interpolated_key_is_consumed_once() -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        r#"{ "Resources": { "A": { "Type": "TA" }, "B": { "Type": "TB" } } }"#,
    )?;
    let resolver = NamesResolver {
        names: vec![
            PathAwareValue::String((Path::root(), "A".to_string())),
            PathAwareValue::String((Path::root(), "B".to_string())),
        ],
    };

    // Control: no index, every named key.
    let without_index = AccessQuery::try_from("Resources.%names.Type")?;
    assert_eq!(
        selected_strings(&value.select(
            without_index.match_all,
            &without_index.query,
            &resolver
        )?),
        vec!["TA".to_string(), "TB".to_string()]
    );

    let first = AccessQuery::try_from("Resources.%names[0].Type")?;
    assert!(
        matches!(first.query[2], QueryPart::Index(0)),
        "the index sits at slot 2, after the interpolated key, got {:?}",
        first.query
    );
    for all in [false, true] {
        assert_eq!(
            selected_strings(&value.select(all, &first.query, &resolver)?),
            vec!["TA".to_string()],
            "all = {all}: the first named resource's Type"
        );
    }

    let second = AccessQuery::try_from("Resources.%names[1].Type")?;
    assert_eq!(
        selected_strings(&value.select(true, &second.query, &resolver)?),
        vec!["TB".to_string()]
    );

    // Out of bounds still selects nothing with `all` false and still refuses with `all` true.
    let beyond = AccessQuery::try_from("Resources.%names[5].Type")?;
    assert!(value.select(false, &beyond.query, &resolver)?.is_empty());
    assert!(value.select(true, &beyond.query, &resolver).is_err());

    Ok(())
}

/// A map key filter selects by the comparator it was written with.
///
/// The `MapKeyFilter` arm of the legacy `select` matched on `filter.compare_with` alone and never read
/// `filter.comparator`. Every spelling was evaluated as equality: `keys != 'a'` selected exactly the
/// key `a`, the same set `keys == 'a'` selects, and `keys not in ['a', 'b']` selected nothing, because
/// a key is never equal to a list. The parser had recorded `NotEq` and `NotIn` all along.
///
/// The arm now resolves the right-hand side to a flat list of values, widens `==` and `!=` against
/// a set to membership through the live engine's own `key_filter::key_comparator`, asks
/// `compare_eq` per pair, and folds by comparator: `==` and `in` select a key that matches one value,
/// `!=` and `not in` select a key that matches none. A pair `compare_eq` cannot answer selects the key
/// under neither polarity, which is how the live engine treats a key comparison with no answer.
///
/// Latent, by the same reachability argument as `an_index_after_an_interpolated_key_is_consumed_once`:
/// no command reaches this resolver, and the live engine's key filter already honors the comparator.
#[test]
fn a_map_key_filter_honors_its_comparator() -> Result<(), Error> {
    let value = PathAwareValue::try_from(r#"{ "Resources": { "a": 1, "b": 2, "c": 3 } }"#)?;
    let dummy = DummyEval {};

    let cases: [(&str, &[&str]); 11] = [
        // A string key is equal to a string, not to a string that contains it. `ab` contains `a`,
        // and `a` is still not in `['ab']`.
        ("Resources[ keys in ['ab'] ]", &[]),
        // Nothing to compare against is the empty set: no key is in it, and every key is outside it,
        // so `!=` selects every key, as the live engine answers before it compares.
        (
            "Resources[ keys != [] ]",
            &["/Resources/a", "/Resources/b", "/Resources/c"],
        ),
        // A key compared with a kind it cannot be compared with has no answer, and a key with no answer
        // is selected under neither polarity.
        ("Resources[ keys != 1 ]", &[]),
        ("Resources[ keys == 'a' ]", &["/Resources/a"]),
        (
            "Resources[ keys != 'a' ]",
            &["/Resources/b", "/Resources/c"],
        ),
        (
            "Resources[ keys in ['a', 'b'] ]",
            &["/Resources/a", "/Resources/b"],
        ),
        ("Resources[ keys not in ['a', 'b'] ]", &["/Resources/c"]),
        // Equality against several values is membership, as in the live engine.
        (
            "Resources[ keys == ['a', 'b'] ]",
            &["/Resources/a", "/Resources/b"],
        ),
        ("Resources[ keys != ['a', 'b'] ]", &["/Resources/c"]),
        // A regex goes through `compare_eq`'s string-against-pattern arm under both polarities.
        (
            "Resources[ keys == /^[ab]$/ ]",
            &["/Resources/a", "/Resources/b"],
        ),
        (
            "Resources[ keys != /^a/ ]",
            &["/Resources/b", "/Resources/c"],
        ),
    ];

    let mut disagreed = Vec::new();
    for (query_text, expected) in cases {
        let query = AccessQuery::try_from(query_text)?;
        assert!(
            matches!(query.query[1], QueryPart::MapKeyFilter(..)),
            "{query_text}: expected a map key filter at slot 1, got {:?}",
            query.query
        );
        let selected: Vec<String> = value
            .select(query.match_all, &query.query, &dummy)?
            .iter()
            .map(|each| each.self_path().0.clone())
            .collect();
        let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        if selected != expected {
            disagreed.push(format!(
                "{query_text}: wanted {expected:?}, got {selected:?}"
            ));
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of 11 cells disagree:\n  {}",
        disagreed.len(),
        disagreed.join("\n  ")
    );

    Ok(())
}

/// The legacy arm widens `==` by the shape of the right-hand side, as the live engine does.
///
/// The rows are the live engine's `a_key_filter_widens_equality_by_the_shape_of_its_right_hand_side`,
/// run through this resolver: a list on the right, of any length, makes `==` membership and `!=` its
/// negation, so a one-element list holding a char range selects the one-character keys the range
/// covers; a bare range under `==` or `!=` is refused; and `IN` and `NOT IN` against a range select by
/// the character in both polarities. The evaluator and the legacy resolver read the shape through the
/// one `key_comparator`, so a row that passes here and fails there is a drift to look for.
///
/// The `%names` rows bind the list through a variable, bare and enumerated with `[*]`: an enumerating
/// right-hand side is a set at any length, so `%names[*]` over a one-element binding selects what
/// `%names` does. This arm has no retrieval notes, so it reads the enumeration off the query's parts.
/// The two-character key `ab` is selected by no row.
#[rstest::rstest]
#[case::in_a_bare_range("Tags[ keys IN r[a,f] ]", "[]", &["/Tags/a", "/Tags/b"])]
#[case::not_in_a_bare_range("Tags[ keys NOT IN r[a,f] ]", "[]", &["/Tags/g", "/Tags/y"])]
#[case::in_a_bracketed_range("Tags[ keys IN [r[a,f]] ]", "[]", &["/Tags/a", "/Tags/b"])]
#[case::equal_to_a_one_element_list_holding_a_range(
    "Tags[ keys == [r[a,f]] ]",
    "[]",
    &["/Tags/a", "/Tags/b"]
)]
#[case::not_equal_to_a_one_element_list_holding_a_range(
    "Tags[ keys != [r[a,f]] ]",
    "[]",
    &["/Tags/g", "/Tags/y"]
)]
#[case::equal_to_a_two_element_list_of_ranges(
    "Tags[ keys == [r[a,f], r[x,z]] ]",
    "[]",
    &["/Tags/a", "/Tags/b", "/Tags/y"]
)]
#[case::equal_to_a_bare_range_is_refused("Tags[ keys == r[a,f] ]", "[]", &[])]
#[case::not_equal_to_a_bare_range_is_refused("Tags[ keys != r[a,f] ]", "[]", &[])]
#[case::equal_to_a_one_element_binding(
    "Tags[ keys == %names ]",
    "[r[a,f]]",
    &["/Tags/a", "/Tags/b"]
)]
#[case::equal_to_a_one_element_binding_enumerated(
    "Tags[ keys == %names[*] ]",
    "[r[a,f]]",
    &["/Tags/a", "/Tags/b"]
)]
#[case::not_equal_to_a_one_element_binding_enumerated(
    "Tags[ keys != %names[*] ]",
    "[r[a,f]]",
    &["/Tags/g", "/Tags/y"]
)]
#[case::equal_to_a_two_element_binding_enumerated(
    "Tags[ keys == %names[*] ]",
    "[r[a,f], r[x,z]]",
    &["/Tags/a", "/Tags/b", "/Tags/y"]
)]
#[case::a_text_pattern_is_the_check_that_reaches_a_longer_key(
    "Tags[ keys != /^[a-f]$/ ]",
    "[]",
    &["/Tags/ab", "/Tags/g", "/Tags/y"]
)]
#[case::an_indexed_binding_names_one_value_and_is_not_a_set(
    "Tags[ keys == %names[0] ]",
    "[r[a,f]]",
    &[]
)]
#[case::a_key_under_a_binding_names_its_list_which_is_a_set(
    "Tags[ keys == %names.k ]",
    r#"{"k": ["a", "b"]}"#,
    &["/Tags/a", "/Tags/b"]
)]
// KNOWN DRIFT from the live engine. A binding whose own query enumerated to one value, `let s = %r[*]`
// over `let r = [r[a,f]]`, read through a bare `%s`: the live engine folds the binding's shape into the
// read and widens `==` to membership, selecting `a` and `b`. This resolver has no way to ask what shape
// a binding resolved with -- its `EvaluationContext` hands back values and nothing else -- so it reads
// the one range it is given as one value, keeps `==`, and selects nothing. The live table's
// `a_binding_whose_own_query_enumerated_is_a_set_through_a_bare_name` row is the other answer. No
// command path reaches this resolver, which is why the drift is recorded here rather than closed.
#[case::known_drift_a_bare_name_bound_to_an_enumerating_query_is_one_value_here(
    "Tags[ keys == %names ]",
    "r[a,f]",
    &[]
)]
fn a_map_key_filter_widens_equality_by_the_shape_of_its_right_hand_side(
    #[case] query_text: &str,
    #[case] binding: &str,
    #[case] expected: &[&str],
) -> Result<(), Error> {
    // A list of ranges is rules syntax, not document syntax, so it is read out of a parsed key filter
    // rather than through `PathAwareValue::try_from`; a map binding is document syntax and parses
    // directly.
    let names = if binding.starts_with('{') {
        vec![PathAwareValue::try_from(binding)?]
    } else {
        let bound_text = format!("X[ keys == {binding} ]");
        let bound = AccessQuery::try_from(bound_text.as_str())?;
        match &bound.query[1] {
            QueryPart::MapKeyFilter(_, filter) => match &filter.compare_with {
                LetValue::Value(list) => vec![list.clone()],
                other => panic!("the binding must parse as a value; got {:?}", other),
            },
            other => panic!("expected a key filter; got {:?}", other),
        }
    };
    let resolver = NamesResolver { names };

    let value =
        PathAwareValue::try_from(r#"{ "Tags": { "a": 1, "b": 2, "g": 3, "y": 4, "ab": 5 } }"#)?;
    let query = AccessQuery::try_from(query_text)?;
    let mut selected: Vec<String> = value
        .select(query.match_all, &query.query, &resolver)?
        .iter()
        .map(|each| each.self_path().0.clone())
        .collect();
    selected.sort();
    let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
    assert_eq!(expected, selected, "query: {}", query_text);
    Ok(())
}

/// A key filter whose right-hand query enumerates an empty collection selects by polarity on this
/// engine too: no key under `==` and `in`, every key under `!=` and `not in`.
///
/// The live engine reads the marker the retrieval leaves for `Names[*]` over `Names: []` (and `.*`
/// over `{}`) as a right-hand side with nothing in it, and decides the filter by polarity before it
/// compares. This resolver resolves the right-hand query itself, against the map being filtered and
/// nothing else (it has no parent scope to fall back to, so a right-hand query rooted at the document
/// is a key it cannot locate), and when that resolution fails it has only the error in hand. So what it
/// hands `select_key` for the same query is measured here, with the exemption list held inside the
/// filtered map where this resolver can reach it: the evaluator and the legacy resolver ask the one
/// module, and the module's answer has to be the same whatever the engine handed it. A bare `Nulls:`
/// (YAML null) is the same empty set, and a key the map lacks (`Missing[*]`) is still an unresolved
/// right-hand side, refused under every comparator rather than decided by polarity.
#[test]
fn a_map_key_filter_over_an_empty_right_hand_collection_selects_by_polarity() -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        r#"{
            "Resources": {
                "Exempt": { "Names": [], "Groups": {}, "Nulls": null },
                "a": 1,
                "b": 2
            }
        }"#,
    )?;
    let dummy = DummyEval {};
    const EVERY: &[&str] = &["/Resources/Exempt", "/Resources/a", "/Resources/b"];
    const NONE: &[&str] = &[];

    // The last four rows enumerate twice. The empty collection is the FIRST enumeration's (`Names[*]`
    // over `Names: []`, `Groups.*` over `Groups: {}`): nothing reached the second, and the right-hand
    // side is still the empty set, as the live engine reads it. A probe that asked only whether the
    // query up to its LAST enumeration resolves to empty collections erred on the prefix
    // `Exempt.Names[*].Inner` (a query remains after the empty `Names`), read the right-hand side as
    // one the document lacks, and failed the filter closed where the live engine decided it.
    // The five rows after the double enumerations are the right-hand sides that RESOLVE to an empty
    // collection rather than enumerating one: `[*]` over a map is a pass-through on this walker too
    // (`Groups[*]` hands the empty map on), and a bare key names the collection itself. Each is the
    // empty set, dropped by `normalize_rhs` before the fold; arriving at the fold as a value, it would
    // be one a string key cannot be compared with and would select no key under either polarity.
    let cases: [(&str, &[&str]); 19] = [
        ("Resources[ keys == Exempt.Names[*] ]", NONE),
        ("Resources[ keys != Exempt.Names[*] ]", EVERY),
        ("Resources[ keys in Exempt.Names[*] ]", NONE),
        ("Resources[ keys not in Exempt.Names[*] ]", EVERY),
        ("Resources[ keys == Exempt.Groups.* ]", NONE),
        ("Resources[ keys != Exempt.Groups.* ]", EVERY),
        ("Resources[ keys not in Exempt.Names.* ]", EVERY),
        ("Resources[ keys == Exempt.Nulls[*] ]", NONE),
        ("Resources[ keys != Exempt.Nulls[*] ]", EVERY),
        ("Resources[ keys not in Exempt.Nulls ]", EVERY),
        ("Resources[ keys == Exempt.Names[*].Inner[*] ]", NONE),
        ("Resources[ keys != Exempt.Names[*].Inner[*] ]", EVERY),
        ("Resources[ keys not in Exempt.Groups.*.Inner[*] ]", EVERY),
        ("Resources[ keys in Exempt.Groups.*.Inner.* ]", NONE),
        ("Resources[ keys == Exempt.Groups[*] ]", NONE),
        ("Resources[ keys != Exempt.Groups[*] ]", EVERY),
        ("Resources[ keys not in Exempt.Names ]", EVERY),
        ("Resources[ keys not in Exempt.Groups ]", EVERY),
        ("Resources[ keys in Exempt.Groups ]", NONE),
    ];

    let mut disagreed = Vec::new();
    for (query_text, expected) in cases {
        let query = AccessQuery::try_from(query_text)?;
        let selected = match value.select(query.match_all, &query.query, &dummy) {
            Ok(selected) => selected
                .iter()
                .map(|each| each.self_path().0.clone())
                .collect::<Vec<String>>(),
            Err(error) => {
                disagreed.push(format!(
                    "{query_text}: wanted {expected:?}, got Err({error})"
                ));
                continue;
            }
        };
        let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        if selected != expected {
            disagreed.push(format!(
                "{query_text}: wanted {expected:?}, got {selected:?}"
            ));
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of 19 cells disagree:\n  {}",
        disagreed.len(),
        disagreed.join("\n  ")
    );

    // The control: a right-hand query the document cannot answer is not an empty set, and is not
    // decided by polarity. The keys such a filter selects cannot be decided, so it fails closed under
    // every comparator with the refusal the unreachable-value test below reads, as the live engine
    // fails it, rather than selecting every key under `not in` or none under `in`.
    for query_text in [
        "Resources[ keys not in Exempt.Missing[*] ]",
        "Resources[ keys in Exempt.Missing[*] ]",
    ] {
        let query = AccessQuery::try_from(query_text)?;
        match value.select(query.match_all, &query.query, &dummy) {
            Err(Error::UndecidableComparison(reason)) => assert!(
                reason.contains("did not resolve") && reason.contains("Exempt.Missing[*]"),
                "{}: the refusal names the query the retrieval could not walk, got {}",
                query_text,
                reason
            ),
            other => panic!(
                "{}: a key the document lacks fails the filter closed, got {:?}",
                query_text, other
            ),
        }
    }

    Ok(())
}

/// A map on the right-hand side is its key set when the query NAMES it and a member when the query
/// ENUMERATED to it, on this engine as on the live one.
///
/// The same `{ Name: BucketA }` is reached three ways: by name as `Exempt.Keyed`, which is the key set
/// `{ Name }` and selects the key `Name` under `in` and `==` (a one-key set widens `==` as a two-key
/// one does) and every other key under `not in` and `!=`; through the enumeration `Exempt.*`, which
/// produces the map `Keyed` and the list `Entries` as members, so a string key against either has no
/// answer and no key is selected under either polarity; and as an element of `Exempt.Entries[*]`, a
/// member too. The bare `Exempt.Entries` arrives as the list and is expanded to the same map member, so
/// the two spellings of the list agree. This resolver's own `rhs_enumerated` flag is what tells the
/// readings apart, as the live engine's shape notes do; the parity table for the live engine is
/// `a_map_on_the_right_is_a_member_or_its_key_set_by_how_the_query_reached_it` in `eval_tests.rs`.
#[test]
fn a_map_key_filter_reads_a_named_map_as_its_key_set_and_an_enumerated_one_as_a_member(
) -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        r#"{
            "Resources": {
                "Exempt": { "Entries": [ { "Name": "BucketA" } ], "Keyed": { "Name": "BucketA" } },
                "Name": 1,
                "BucketA": 2
            }
        }"#,
    )?;
    let dummy = DummyEval {};
    const NAME: &[&str] = &["/Resources/Name"];
    const OTHERS: &[&str] = &["/Resources/Exempt", "/Resources/BucketA"];
    const BUCKET_A: &[&str] = &["/Resources/BucketA"];
    const NAME_AND_EXEMPT: &[&str] = &["/Resources/Exempt", "/Resources/Name"];
    const NONE: &[&str] = &[];

    let cases: &[(&str, &[&str])] = &[
        ("Resources[ keys in Exempt.Keyed ]", NAME),
        ("Resources[ keys == Exempt.Keyed ]", NAME),
        ("Resources[ keys not in Exempt.Keyed ]", OTHERS),
        ("Resources[ keys != Exempt.Keyed ]", OTHERS),
        ("Resources[ keys in Exempt.* ]", NONE),
        ("Resources[ keys not in Exempt.* ]", NONE),
        ("Resources[ keys in Exempt.Entries[*] ]", NONE),
        ("Resources[ keys not in Exempt.Entries[*] ]", NONE),
        ("Resources[ keys in Exempt.Entries ]", NONE),
        ("Resources[ keys not in Exempt.Entries ]", NONE),
        ("Resources[ keys in Exempt.Entries[*].Name ]", BUCKET_A),
        (
            "Resources[ keys not in Exempt.Entries[*].Name ]",
            NAME_AND_EXEMPT,
        ),
    ];

    let mut disagreed = Vec::new();
    for (query_text, expected) in cases {
        let query = AccessQuery::try_from(*query_text)?;
        let selected = match value.select(query.match_all, &query.query, &dummy) {
            Ok(selected) => selected
                .iter()
                .map(|each| each.self_path().0.clone())
                .collect::<Vec<String>>(),
            Err(error) => {
                disagreed.push(format!(
                    "{query_text}: wanted {expected:?}, got Err({error})"
                ));
                continue;
            }
        };
        let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        if selected != expected {
            disagreed.push(format!(
                "{query_text}: wanted {expected:?}, got {selected:?}"
            ));
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of {} cells disagree:\n  {}",
        disagreed.len(),
        cases.len(),
        disagreed.join("\n  ")
    );

    Ok(())
}

/// KNOWN DISAGREEMENT between the two engines, pinned so that it is read rather than rediscovered: a
/// right-hand enumeration that is empty on SOME branches and not on others.
///
/// `Groups.*.Inner[*].N` over `Groups: { a: { Inner: [] }, b: { Inner: [ { N: x } ] } }`. The live
/// engine walks each branch and leaves one empty-enumeration marker for `a` beside the value `x` for
/// `b`; `normalize_rhs` drops the marker, and the filter is decided on `x` (the sibling test in
/// `eval_tests.rs`, `a_partially_empty_enumeration_is_decided_by_the_live_engine`). This resolver has
/// only the retrieval error in hand and asks `enumerates_an_empty_collection` whether the query up to
/// some enumeration resolves to nothing but empty collections: `Groups` is one non-empty map and
/// `Groups.*.Inner` is `[[], [{N: x}]]`, so no prefix qualifies, the entry is typed as a value the document
/// lacks, and the filter fails closed under every comparator. Per-branch markers would close it, which is
/// a change to this walker and not to the shared fold; no command path reaches this arm, so no verdict a
/// user sees moves. The row pins both the refusal and the reason it names, so a later change to either
/// engine turns this red and the disagreement is re-read before it is moved.
#[test]
fn a_partially_empty_enumeration_is_refused_by_the_legacy_resolver() -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        r#"{
            "Resources": {
                "Exempt": { "Groups": { "a": { "Inner": [] }, "b": { "Inner": [ { "N": "x" } ] } } },
                "x": 1,
                "y": 2
            }
        }"#,
    )?;
    let dummy = DummyEval {};
    for query_text in [
        "Resources[ keys == Exempt.Groups.*.Inner[*].N ]",
        "Resources[ keys not in Exempt.Groups.*.Inner[*].N ]",
    ] {
        let query = AccessQuery::try_from(query_text)?;
        match value.select(query.match_all, &query.query, &dummy) {
            Err(Error::UndecidableComparison(reason)) => assert!(
                reason.contains("did not resolve") && reason.contains("Exempt.Groups.*.Inner[*].N"),
                "{}: the refusal names the query the retrieval could not walk, got {}",
                query_text,
                reason
            ),
            other => panic!(
                "{}: this resolver fails a partially empty enumeration closed (known disagreement with \
                 the live engine, which decides it on the branch that has a value), got {:?}",
                query_text, other
            ),
        }
    }
    Ok(())
}

/// A map a key step reaches after an earlier enumeration is its key set in this arm too, as the live
/// engine reads it (`key_step_after_dot_star_*` and the `Groups.*.Buckets` rows of
/// `a_map_on_the_right_is_a_member_or_its_key_set_by_how_the_query_reached_it` in `eval_tests.rs`).
///
/// This arm read any enumeration anywhere in the right-hand query as `LastPart`, so `Groups.*.Buckets`
/// kept each group's `Buckets` map whole, a value no key is equal to, and selected no key under either
/// `IN` or `NOT IN`; the live engine, reading the walk's own notes, named the shape `EarlierPart` and
/// read the map as its key set. The arm now reads the shape off the parts through
/// `RhsEnumeration::of_parts`, whose rule for one part is the live engine's `part_projects`, so the two
/// engines agree: `IN` selects the key the group's map holds and `NOT IN` the others. The arm's own two
/// copies of that rule had drifted from it on one part: a variable-interpolated key projects live
/// (`Groups.%names` reaches the member named, kept whole) and did not here, where each named group was
/// read as its key set; the `%names` rows pin the shared rule. The last-part shapes are the controls: a
/// map the author's `[*]` passed on unchanged (`Passed[*]`) is its key set through the passed-on
/// record, so is one under a key that holds a `/` (`Slash.'a/b'[*]`, where splitting the path on `/`
/// matched the key against neither half), a named map (`Named`) through `Names`, and a map a filter
/// enumerated to (`Groups.*[ Buckets exists ]`) or a variable named is a member: a string key against a
/// map is a pairing with no answer, which selects the key under neither `IN` nor `NOT IN`
/// (`key_selected_from`: a key with no answer is not equal to one value, and not equal to none either).
/// The right-hand queries are relative to the filtered map, which is where this arm resolves them. A
/// row that errors is recorded as a disagreement, so every row stays visible.
#[test]
fn a_map_a_key_step_reaches_after_an_earlier_enumeration_is_its_key_set_in_the_legacy_arm(
) -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        r#"{
            "M": {
                "k1": 1,
                "k2": 2,
                "Groups": { "G1": { "Buckets": { "k1": true }, "k2": 0 } },
                "Named": { "k2": true },
                "Passed": { "k1": true },
                "Slash": { "a/b": { "k1": true } }
            }
        }"#,
    )?;
    let resolver = NamesResolver {
        names: vec![PathAwareValue::try_from(r#""G1""#)?],
    };
    const ALL_BUT_K1: &[&str] = &["/M/Groups", "/M/Named", "/M/Passed", "/M/Slash", "/M/k2"];
    let cases: [(&str, &[&str]); 9] = [
        ("M[ keys IN Groups.*.Buckets ]", &["/M/k1"]),
        ("M[ keys NOT IN Groups.*.Buckets ]", ALL_BUT_K1),
        ("M[ keys IN Passed[*] ]", &["/M/k1"]),
        ("M[ keys IN Slash.'a/b'[*] ]", &["/M/k1"]),
        ("M[ keys IN Named ]", &["/M/k2"]),
        ("M[ keys IN Groups.*[ Buckets exists ] ]", &[]),
        ("M[ keys NOT IN Groups.*[ Buckets exists ] ]", &[]),
        // `%names` is `G1`: the member named, kept whole, not its key set (`k2` is one of its keys).
        ("M[ keys IN Groups.%names ]", &[]),
        ("M[ keys NOT IN Groups.%names ]", &[]),
    ];
    let mut disagreed = Vec::new();
    for (query_text, expected) in cases {
        let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        let query = match AccessQuery::try_from(query_text) {
            Ok(query) => query,
            Err(error) => {
                disagreed.push(format!(
                    "{query_text}: wanted {expected:?}, did not parse: {error}"
                ));
                continue;
            }
        };
        let mut selected: Vec<String> = match value.select(query.match_all, &query.query, &resolver)
        {
            Ok(selected) => selected
                .iter()
                .map(|each| each.self_path().0.clone())
                .collect(),
            Err(error) => {
                disagreed.push(format!(
                    "{query_text}: wanted {expected:?}, got Err({error})"
                ));
                continue;
            }
        };
        selected.sort();
        if selected != expected {
            disagreed.push(format!(
                "{query_text}: wanted {expected:?}, got {selected:?}"
            ));
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of {} cells disagree:\n  {}",
        disagreed.len(),
        cases.len(),
        disagreed.join("\n  ")
    );
    Ok(())
}

/// A key filter whose right-hand side is a query binding one list expands the list, one level.
///
/// `let names = Cfg.KeyList` over `KeyList: [a, b]` resolves to a single value holding both names.
/// Counting that as one right-hand value kept `keys == %names` at strict equality, where every key
/// against a list has no answer, and `keys in %names` compared each key against the list itself. The
/// live engine expands such a binding one level (`interpolated_keys`) before counting or comparing;
/// the legacy arm does the same, through the one function the evaluator and the legacy resolver both
/// ask.
#[test]
fn a_map_key_filter_expands_a_list_valued_binding() -> Result<(), Error> {
    let value = PathAwareValue::try_from(r#"{ "Resources": { "a": 1, "b": 2, "c": 3 } }"#)?;
    let resolver = NamesResolver {
        names: vec![PathAwareValue::try_from(r#"["a", "b"]"#)?],
    };

    let cases: [(&str, &[&str]); 4] = [
        (
            "Resources[ keys in %names ]",
            &["/Resources/a", "/Resources/b"],
        ),
        ("Resources[ keys not in %names ]", &["/Resources/c"]),
        // Equality against two values widens to membership, exactly as a two-element list literal does.
        (
            "Resources[ keys == %names ]",
            &["/Resources/a", "/Resources/b"],
        ),
        ("Resources[ keys != %names ]", &["/Resources/c"]),
    ];

    let mut disagreed = Vec::new();
    for (query_text, expected) in cases {
        let query = AccessQuery::try_from(query_text)?;
        let selected: Vec<String> = value
            .select(query.match_all, &query.query, &resolver)?
            .iter()
            .map(|each| each.self_path().0.clone())
            .collect();
        let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        if selected != expected {
            disagreed.push(format!(
                "{query_text}: wanted {expected:?}, got {selected:?}"
            ));
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of 4 cells disagree:\n  {}",
        disagreed.len(),
        disagreed.join("\n  ")
    );

    Ok(())
}

/// A right-hand value the filter's query could not reach fails the selection closed here too.
///
/// The legacy arm resolves a right-hand query relative to the map being filtered, and a value the query
/// cannot reach is reported rather than dropped. Resolving with `all` off would let a path missing on
/// one element yield nothing, and the fold would see a shorter list:
/// `Tags[ keys not in Allowed[*].Key ]` over an `Allowed` whose second element has no `Key` would ask
/// only "differs from `Name`?" and select every other key. Reading the unreachable value as a pairing
/// nobody decided would keep a key out under `not in` and `!=` and leave `in` to select the match
/// beside it. It is a comparison nobody can finish: the set the keys are tested against cannot be read
/// in full, so the selection is undecided under every comparator and the arm returns the error the
/// live engine returns, with a reason naming the path. The evaluator and the legacy resolver reach that
/// answer through the one key-filter entry point.
///
/// The nested one-element list row is the other agreement: `[['a']]` expands to `['a']`, a string key
/// against a list has no answer, and neither engine unwraps a second time.
#[test]
fn a_map_key_filter_fails_closed_on_an_unreachable_right_hand_value() -> Result<(), Error> {
    let value = PathAwareValue::try_from(
        r#"{ "Tags": { "Name": 1, "Other": 2, "Allowed": [ { "Key": "Name" }, { "NoKey": 1 } ] },
             "Resources": { "a": 1 } }"#,
    )?;
    let dummy = DummyEval {};

    for query_text in [
        "Tags[ keys not in Allowed[*].Key ]",
        "Tags[ keys != Allowed[*].Key ]",
        "Tags[ keys in Allowed[*].Key ]",
    ] {
        let query = AccessQuery::try_from(query_text)?;
        match value.select(query.match_all, &query.query, &dummy) {
            // This resolver hands the whole right-hand query back as unresolved at the map it was
            // begun from, so the reason names `/Tags` and the query `Allowed[*].Key` it could not walk.
            Err(Error::UndecidableComparison(reason)) => assert!(
                reason.contains("did not resolve")
                    && reason.contains("/Tags")
                    && reason.contains("Allowed[*].Key"),
                "{}: the reason names where the retrieval stopped and the query it could not walk, got {}",
                query_text,
                reason
            ),
            other => panic!(
                "{}: an unreachable right-hand value fails the selection closed, got {:?}",
                query_text,
                other.map(|selected| {
                    selected
                        .iter()
                        .map(|each| each.self_path().0.clone())
                        .collect::<Vec<_>>()
                })
            ),
        }
    }

    let cases: [(&str, &[&str]); 2] = [
        ("Resources[ keys == [['a']] ]", &[]),
        ("Resources[ keys == ['a'] ]", &["/Resources/a"]),
    ];
    let mut disagreed = Vec::new();
    for (query_text, expected) in cases {
        let query = AccessQuery::try_from(query_text)?;
        let selected: Vec<String> = value
            .select(query.match_all, &query.query, &dummy)?
            .iter()
            .map(|each| each.self_path().0.clone())
            .collect();
        let expected: Vec<String> = expected.iter().map(|s| s.to_string()).collect();
        if selected != expected {
            disagreed.push(format!(
                "{query_text}: wanted {expected:?}, got {selected:?}"
            ));
        }
    }
    assert!(
        disagreed.is_empty(),
        "{} of 2 cells disagree:\n  {}",
        disagreed.len(),
        disagreed.join("\n  ")
    );

    Ok(())
}

/// A key comparison the engine could not finish fails the selection closed instead of shrinking it.
///
/// `compare_eq` can fail two ways. A kind mismatch is `NotComparable`, which is a refusal with a known
/// shape: the key is selected under neither polarity and the rest of the map is still decided. A regex
/// that exhausts its backtracking budget is not that. Nothing was decided about the key, and reading
/// the error as "did not match" would select the complement under `!=` on the strength of a comparison
/// that never finished. The live engine's `real_binary_operation` fails such a filter closed as
/// `UndecidableComparison`, and the legacy arm does the same; folding every error into "no answer"
/// would return a smaller selection with nothing to say about it.
///
/// Eighteen `a` characters is where `(?!x)((a+)+)b` gives up on this path, the same key the validate
/// fixtures use for the live engine.
#[test]
fn a_map_key_filter_that_cannot_be_evaluated_fails_closed() -> Result<(), Error> {
    let value = PathAwareValue::try_from(r#"{ "Cfg": { "aaaaaaaaaaaaaaaaaa": 1, "other": 2 } }"#)?;
    let dummy = DummyEval {};

    for spelling in [
        "Cfg[ keys == /(?!x)((a+)+)b/ ]",
        "Cfg[ keys != /(?!x)((a+)+)b/ ]",
        "Cfg[ keys in [/(?!x)((a+)+)b/] ]",
        "Cfg[ keys not in [/(?!x)((a+)+)b/] ]",
    ] {
        let query = AccessQuery::try_from(spelling)?;
        for all in [false, true] {
            // Arguments spelled out rather than captured inline: under edition 2018 a lone literal
            // handed to `panic!` becomes the payload verbatim.
            match value.select(all, &query.query, &dummy) {
                Err(Error::UndecidableComparison(reason)) => assert!(
                    reason.contains("could not be evaluated"),
                    "{}, all = {}: the reason must say the comparison was not finished, got {:?}",
                    spelling,
                    all,
                    reason
                ),
                other => panic!(
                    "{}, all = {}: an unfinished key comparison must fail the selection closed, got {:?}",
                    spelling, all, other
                ),
            }
        }
    }

    // Control: a pattern that finishes still selects.
    let query = AccessQuery::try_from("Cfg[ keys == /^other$/ ]")?;
    let selected: Vec<String> = value
        .select(query.match_all, &query.query, &dummy)?
        .iter()
        .map(|each| each.self_path().0.clone())
        .collect();
    assert_eq!(selected, vec!["/Cfg/other".to_string()]);

    Ok(())
}

/// A repeat of a key position is an alias's write: the position was already in the mapping's map, so
/// the second write is a copy that kept its anchor's position, which only an alias makes, and the
/// record names the alias's own site for it. The count and the sites are one record written by one
/// call. The plain first write of a key records nothing at all; an alias's write, repeat or not, records
/// its site beside the count; and a repeat that arrives with NO site is recorded at the key's own
/// position, so the conversion still emits its notice, naming that position as both the first write
/// and the repeat. The same assertions hold in a release build, where no `debug_assert!` runs: a
/// writer that refused the site-less repeat in debug builds only would, in a release build, record a
/// count with no site, which the conversion, finding nothing to name, would report as nothing.
#[test]
fn a_repeat_of_a_key_position_with_no_alias_site_is_recorded_at_the_key() {
    let mut collisions = KeyCollisions::new();
    let mapping_at = Location::new(1, 1);
    let key_at = Location::new(2, 3);
    collisions.add_key_write(mapping_at, key_at, None, false);
    assert!(collisions.is_empty(), "a plain first write records nothing");
    collisions.add_key_write(mapping_at, key_at, Some(Location::new(3, 3)), true);
    assert_eq!(
        collisions.writes_at(mapping_at, key_at),
        Some(&KeyWrites {
            repeats: 1,
            alias_sites: vec![Location::new(3, 3)],
        }),
        "an alias's repeat is one count and one site in one record"
    );

    // The site-less repeat, on its own record: counted, and sited at the key.
    let mut siteless = KeyCollisions::new();
    siteless.add_key_write(mapping_at, key_at, None, true);
    assert_eq!(
        siteless.writes_at(mapping_at, key_at),
        Some(&KeyWrites {
            repeats: 1,
            alias_sites: vec![key_at],
        }),
        "a repeat with no site is recorded at the key's own position, never as a bare count"
    );

    // The conversion emits the notice for it, at the key's position twice, with that position standing.
    let mut entries: indexmap::IndexMap<(String, Location), crate::rules::values::MarkedValue> =
        indexmap::IndexMap::new();
    entries.insert(
        (String::from("x"), key_at),
        crate::rules::values::MarkedValue::Int(2, Location::new(2, 6)),
    );
    let mapping = crate::rules::values::MarkedValue::Map(entries, mapping_at);
    let mut duplicates = vec![];
    let converted = PathAwareValue::try_from_marked_reporting(
        (mapping, Path::root()),
        &siteless,
        &mut duplicates,
    )
    .expect("one scalar entry converts");
    assert!(matches!(converted, PathAwareValue::Map(_)));
    assert_eq!(
        duplicates,
        vec![DuplicateKey {
            path: String::from("/x"),
            first: key_at,
            repeated: key_at,
            evaluated: key_at,
        }],
        "the write beyond the first is reported even when no alias site was recorded for it"
    );
}
