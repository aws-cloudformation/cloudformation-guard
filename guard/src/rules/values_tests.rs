use super::*;
use crate::rules::exprs::{AccessQuery, GuardClause};
use crate::rules::exprs::{Rule, TypeBlock};
use pretty_assertions::assert_eq;
use std::collections::HashMap;
use std::convert::{TryFrom, TryInto};
use std::fs::read_to_string;

use crate::rules::path_value::traversal::{Traversal, TraversalResult};
use crate::rules::path_value::{PathAwareValue, QueryResolver};
use crate::rules::{Error, Evaluate, EvaluationContext, EvaluationType, Result, Status};

#[test]
fn test_convert_from_to_value() -> Result<()> {
    let val = r#"
        {
            "first": {
                "block": [{
                    "number": 10,
                    "hi": "there"
                }, {
                    "number": 20,
                    "hi": "hello"
                }],
                "simple": "desserts"
            },
            "second": 50
        }
        "#;
    let json: serde_json::Value = serde_json::from_str(val)?;
    let value = Value::try_from(&json)?;
    //
    // serde_json uses a BTree for the value which preserves alphabetical
    // order for the keys
    //
    assert_eq!(
        value,
        Value::Map(make_linked_hashmap(vec![
            (
                "first",
                Value::Map(make_linked_hashmap(vec![
                    (
                        "block",
                        Value::List(vec![
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("there".to_string())),
                                ("number", Value::Int(10)),
                            ])),
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("hello".to_string())),
                                ("number", Value::Int(20)),
                            ]))
                        ])
                    ),
                    ("simple", Value::String("desserts".to_string())),
                ]))
            ),
            ("second", Value::Int(50))
        ]))
    );
    Ok(())
}

#[test]
fn test_convert_into_json() -> Result<()> {
    let value = r#"
        {
             first: {
                 block: [{
                     hi: "there",
                     number: 10
                 }, {
                     hi: "hello",
                     # comments in here for the value
                     number: 20
                 }],
                 simple: "desserts"
             }, # now for second value
             second: 50
        }
        "#;

    let value_str = r#"
        {
            "first": {
                "block": [{
                    "number": 10,
                    "hi": "there"
                }, {
                    "number": 20,
                    "hi": "hello"
                }],
                "simple": "desserts"
            },
            "second": 50
        }
        "#;

    let json: serde_json::Value = serde_json::from_str(value_str)?;
    let type_value = Value::try_from(value)?;
    assert_eq!(
        type_value,
        Value::Map(make_linked_hashmap(vec![
            (
                "first",
                Value::Map(make_linked_hashmap(vec![
                    (
                        "block",
                        Value::List(vec![
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("there".to_string())),
                                ("number", Value::Int(10)),
                            ])),
                            Value::Map(make_linked_hashmap(vec![
                                ("hi", Value::String("hello".to_string())),
                                ("number", Value::Int(20)),
                            ]))
                        ])
                    ),
                    ("simple", Value::String("desserts".to_string())),
                ]))
            ),
            ("second", Value::Int(50))
        ]))
    );

    let converted: Value = (&json).try_into()?;
    assert_eq!(converted, type_value);
    Ok(())
}

#[test]
fn test_query_on_value() -> Result<()> {
    let content = read_to_string("assets/cfn-template.json")?;
    let value = PathAwareValue::try_from(content.as_str())?;

    struct DummyResolver<'a> {
        cache: HashMap<&'a str, Vec<&'a PathAwareValue>>,
    }
    impl<'a> EvaluationContext for DummyResolver<'a> {
        fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
            if let Some(v) = self.cache.get(variable) {
                return Ok(v.clone());
            }
            Err(Error::MissingVariable(format!("Not found {}", variable)))
        }

        fn rule_status(&self, _rule_name: &str) -> Result<Status> {
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
    let dummy = DummyResolver {
        cache: HashMap::new(),
    };

    //
    // Select all resources inside a template
    //
    let query = AccessQuery::try_from("Resources.*")?;
    let selected = value.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 17);
    for each in selected {
        if let PathAwareValue::Map(_index) = each {
            continue;
        }
        unreachable!()
    }

    //
    // Select all IAM::Role resources inside the template
    //
    let query = AccessQuery::try_from("Resources.*[ Type == \"AWS::IAM::Role\" ]")?;
    let selected = value.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 1);

    println!("{:?}", selected[0]);
    let iam_role = selected[0];

    //
    // Select all policies that has Effect "allow"
    //
    let query = AccessQuery::try_from(
        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ]",
    )?;
    let selected = iam_role.select(query.match_all, &query.query, &dummy)?;
    assert_eq!(selected.len(), 2);

    //
    // This is the case with IAM roles where Action can be either a single value or array
    //
    //    let clause = GuardClause::try_from(
    //        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ].Action != \"*\"")?;
    //    let status = clause.evaluate(iam_role, &dummy)?;
    //    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(
        "Properties.Policies.*.PolicyDocument.Statement[ Effect == \"Allow\" ].Action.* != \"*\"",
    )?;
    let status = clause.evaluate(iam_role, &dummy)?;
    assert_eq!(status, Status::FAIL);

    //
    // Making it work with variable references
    //
    let block = r#"
    AWS::IAM::Role {
        let statements = Properties.Policies.*.PolicyDocument.Statement[ Effect == "Allow" ]

        # %statements.Action != "*" OR
        %statements.Action.* != "*"

        %statements.Resource != "*" # OR
        # %statements.Resource.* != "*"
    }
    "#;
    let type_block = TypeBlock::try_from(block)?;
    let status = type_block.evaluate(&value, &dummy)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_type_block_with_var_query_evaluation() -> Result<()> {
    let content = read_to_string("assets/cfn-template.json")?;
    let value = PathAwareValue::try_from(content.as_str())?;

    struct DummyResolver {}
    impl EvaluationContext for DummyResolver {
        fn resolve_variable(&self, _variable: &str) -> Result<Vec<&PathAwareValue>> {
            unimplemented!()
        }

        fn rule_status(&self, _rule_name: &str) -> Result<Status> {
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
    let dummy = DummyResolver {};

    let block = r#"
    rule check_subnets when Resources.*[ Type == "AWS::EC2::VPC" ] !EMPTY {
        # Ensure that Zone is always set
        AWS::EC2::Subnet Properties.AvailabilityZone NOT EMPTY

        # Check if either IPv6 is correctly on or IPv4
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation EXISTS
            Properties.AssignIpv6AddressOnCreation == true
            Properties.Ipv6CidrBlock EXISTS
            Properties.CidrBlock NOT EXISTS
        } OR
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation !EXISTS or
            Properties.AssignIpv6AddressOnCreation == false
            Properties.CidrBlock EXISTS
            Properties.Ipv6CidrBlock NOT EXISTS
        }
    }
    "#;
    let rule = Rule::try_from(block)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);

    let block = r###"
    rule check_subnets {
        # Ensure that Zone is always set
        AWS::EC2::Subnet Properties.AvailabilityZone NOT EMPTY

        # Check if either IPv6 is correctly on or IPv4
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation EXISTS
            Properties.AssignIpv6AddressOnCreation == true
            Properties.Ipv6CidrBlock EXISTS
            Properties.CidrBlock NOT EXISTS
        } OR
        AWS::EC2::Subnet {
            Properties.AssignIpv6AddressOnCreation !EXISTS or
            Properties.AssignIpv6AddressOnCreation == false
            Properties.CidrBlock EXISTS
            Properties.Ipv6CidrBlock NOT EXISTS
        }
    }
    "###;
    let rule = Rule::try_from(block)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);

    let content = r#"
    {
       "Resources": {
           "subnet": {
              "Type": "AWS::EC2::Subnet",
              "Properties": {
                  "AvailabilityZone": "us-east-2a",
                  "AssignIpv6AddressOnCreation": true,
                  "CidrBlock": "10.0.0.0/12"
              }
           }
       }
    }
    "#;
    let value = PathAwareValue::try_from(content)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::FAIL);

    let content = r#"
    {
       "Resources": {
           "subnet": {
              "Type": "AWS::EC2::Subnet",
              "Properties": {
                  "AvailabilityZone": "us-east-2a",
                  "CidrBlock": "10.0.0.0/12"
              }
           }
       }
    }
    "#;
    let value = PathAwareValue::try_from(content)?;
    let status = rule.evaluate(&value, &dummy)?;
    println!("Status = {:?}", status);
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_parse_string_with_colon() -> Result<()> {
    // let s = r#"'aws:AssumeRole'"#;
    let s = r#""aws:AssumeRole""#;
    let _value = Value::try_from(s)?;
    Ok(())
}

#[test]
fn test_yaml_json_mapping() -> Result<()> {
    let resources = r###"
    apiVersion: v1
    spec:
      containers:
        - image: docker/httpd
          cpu: 2
          memory: 10
    "###;

    let resources_json = r#"{
        "Resources": {
            "s3": {
               "Type": "AWS::S3::Bucket",
               "Properties": {
                  "AccessControl": "PublicRead"
               }
            }
        }
    }
    "#;

    let value = super::read_from(resources)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    println!("{:?}", path_value);

    let value = super::read_from(resources_json)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    println!("{:?}", path_value);
    Ok(())
}

#[test]
fn test_yaml_json_mapping_2() -> Result<()> {
    let resources = r#"
MyNotCondition:
    !Not [!Equals [!Ref EnvironmentType, prod]]
Resources:
  myEC2Instance:
    Type: "AWS::EC2::Instance"
    Properties:
      ImageId: !FindInMap
        - RegionMap
        - !Ref 'AWS::Region'
        - HVM64
      InstanceType: m1.small
  s3:
    Type: AWS::S3::Bucket
    Properties:
      AccessControl: !Sub
        - /${a}/works
        - a: this

      Others: !Select [ "1", [ "apples", "grapes", "oranges", "mangoes" ] ]
      TestJoin: !Join [ ":", [ a, b, c ] ]
      TestJoinWithRef: !Join [ ":", [ !Ref A, b, c ] ]
      "#;

    let value = super::read_from(resources)?;
    println!("{:?}", value);
    let path_value = PathAwareValue::try_from((value, super::super::path_value::Path::root()))?;
    let traversal = Traversal::from(&path_value);
    let root = traversal.root().unwrap();
    let test_join = traversal.at(
        "/Resources/s3/Properties/TestJoinWithRef/Fn::Join/1/0",
        root,
    )?;
    assert!(matches!(test_join, TraversalResult::Value(_)));
    let condition = traversal.at("/MyNotCondition/Fn::Not/0/Fn::Equals/0/Ref", root)?;
    assert!(matches!(condition, TraversalResult::Value(_)));
    match condition {
        TraversalResult::Value(val) => {
            assert!(val.value().is_scalar());
            match val.value() {
                PathAwareValue::String((_, v)) => {
                    assert_eq!(v, "EnvironmentType");
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }

    let ec2_image = match traversal.at(
        "/Resources/myEC2Instance/Properties/ImageId/Fn::FindInMap",
        root,
    )? {
        TraversalResult::Value(n) => n,
        _ => unreachable!(),
    };
    match traversal.at("0/0", ec2_image)?.as_value().unwrap().value() {
        PathAwareValue::String((_, region)) => {
            assert_eq!("RegionMap", region);
        }
        _ => unreachable!(),
    }

    match traversal
        .at("0/1/Ref", ec2_image)?
        .as_value()
        .unwrap()
        .value()
    {
        PathAwareValue::String((_, region)) => {
            assert_eq!("AWS::Region", region);
        }
        _ => unreachable!(),
    }

    match traversal.at("0/2", ec2_image)?.as_value().unwrap().value() {
        PathAwareValue::String((_, region)) => {
            assert_eq!("HVM64", region);
        }
        _ => unreachable!(),
    }

    println!("{:?}", path_value);
    Ok(())
}

/// cfn-guard has two document loaders, and they must give the same document the same value.
///
/// `values::read_from` -- the libyaml loader -- is reached only by `validate`'s `build_data_file`.
/// Everything else goes through serde: `commands::helper::validate_and_return_json`, which is the
/// public `run_checks`; the `test` command's spec `input:` blocks; and `rulegen`. So a scalar the two
/// resolve differently means one file means two things depending on which command read it.
///
/// The measured divergences were: the YAML 1.1-only booleans, hex and `0o` integers, a decimal with a
/// leading zero, the empty scalar, and the dotted `!GetAtt` short form. They showed up as
/// `rulegen` emitting a rule that `validate` then rejected on the very template it was generated
/// from, and as a rule whose `guard test` suite was green failing under `validate` on byte-identical
/// input -- so the harness a rule author uses to prove a rule correct did not exercise the loader the
/// rule would run against.
///
/// This compares the two through `serde_json`, which is the only form both reach, because the libyaml
/// value carries source locations and the serde one has none.
///
/// The cases left out are below, and the list is exhaustive: everything else this document can be
/// extended with belongs in it. They divide into two kinds, and the difference decides whether the
/// next reader should try to close one.
///
/// **Closable, and left open with a reason.**
///
///   - `0b101`. YAML 1.2 core has no binary form -- it is 1.1's -- so following `serde_yaml`'s
///     extension would re-add a 1.1-ism the boolean set dropped. A choice, not a limit.
///
/// **Not closable at this boundary.** `serde_yaml::Value` is a *resolved* value model: it has already
/// discarded how each scalar was written, and anchors with it, before this conversion sees anything. So
/// no amount of work in `values.rs` can close a divergence whose correct answer depends on the source
/// text or the scalar style. Closing these means one loader rather than two -- for the entry points
/// that read a whole file, moving `validate_and_return_json` onto `read_from` the way `rulegen` moved,
/// which costs the YAML aliases that `run_checks` accepts today; for `guard test` it means more, since
/// a spec's `input:` is a `serde_yaml::Value` by the time the `test` command has it.
///
///   - a float literal that underflows to zero, such as `1e-400`. The libyaml loader keeps its text,
///     because it can see that the mantissa holds a non-zero digit. `serde_yaml::Number` is
///     `enum N { PosInt(u64), NegInt(i64), Float(f64) }` and retains no source text, so an underflowed
///     `1e-400` arrives as `Float(0.0)`, indistinguishable from a literal `0`. Refusing every
///     `Float(0.0)` would refuse a legitimate `0.0`, which is worse. Checked against the pinned crate
///     source (0.9.34), not assumed. This one's direction is a silent wrong PASS: `underflow == 0`
///     holds here and fails under `validate`.
///   - a **quoted** `"<<"`. YAML resolves the merge key from a plain scalar only, so `"<<"` is an
///     ordinary key; `libyaml::loader` records which scalars were plain to tell them apart, and a
///     `serde_yaml::Value::Mapping` key is `String("<<")` either way.
///   - a YAML **alias**. `serde_yaml` resolves anchors and aliases; the libyaml loader refuses them,
///     loudly, because it is a parser wrapper with no composer. So `run_checks` reads an aliased file
///     that `validate` will not.
///   - a **duplicate key**. `serde_yaml::from_str` refuses one outright ("duplicate entry with key
///     ..."); the libyaml loader keeps the last value and warns.
///
/// An integer wider than `i64` and a non-finite float *were* on that list and are now in the document:
/// keeping the digits and the canonical `.nan`/`.inf` spelling closed both. So are the merge key and
/// the non-string scalar keys, which the round that added this test fixed on the libyaml loader only.
/// The document with those two blocks in it fails this assertion against `values.rs` as it stood then,
/// which is measured, and each of the two was measured diverging on its own through `guard test`.
#[test]
fn both_loaders_resolve_the_same_document_to_the_same_value() -> Result<()> {
    let document = r#"
Mappings:
  NonStringKeys:
    123456789012: an account id
    0755: a file mode
    0x1F: a bitmask
    1.0: a whole float
    2.5: a fractional float
    true: a boolean
    18446744073709551615: past i64
    .nan: not a number
Resources:
  Probe:
    Merged:
      <<: { from_merge: yes_really, overridden: from_merge }
      overridden: explicit
    MergedSequence:
      <<: [{ a: first, shared: from_first }, { b: second, shared: from_second }]
    Properties:
      bool_true: true
      bool_TRUE: TRUE
      bool_mixed: tRuE
      not_a_bool_yes: yes
      not_a_bool_n: N
      not_a_bool_off: off
      hex: 0x1F
      octal: 0o17
      leading_zero: 0755
      plain_int: 42
      signed_int: +42
      i64_max: 9223372036854775807
      float: 1.5
      exponent: 1e5
      time: 12:30:45
      sexagesimal: 1:30
      underscored: 1_000
      empty_node:
      quoted_empty: ""
      tilde: ~
      spelled_null: null
      u64_max: 18446744073709551615
      just_past_i64_max: 9223372036854775808
      not_a_number: .nan
      infinity: .inf
      negative_infinity: -.inf
      getatt_dotted: !GetAtt Other.Arn
      getatt_multi_dot: !GetAtt myELB.SourceSecurityGroup.OwnerAlias
      getatt_list: !GetAtt [Other, Arn]
      ref: !Ref Param
      unlisted_intrinsic: !Length [1, 2, 3]
      tagged_mapping: !ToJsonString { a: 1 }
"#;

    let via_libyaml = PathAwareValue::try_from(crate::rules::values::read_from(document)?)?;
    let via_serde = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;

    let (_, libyaml_json): (String, serde_json::Value) = (&via_libyaml).try_into()?;
    let (_, serde_json_value): (String, serde_json::Value) = (&via_serde).try_into()?;

    assert_eq!(
        serde_json_value, libyaml_json,
        "the two loaders read the same bytes as different values, so which command read a file \
         decides what it means"
    );

    Ok(())
}

/// The serde-backed conversion does not read a positive integer as negative, and does not admit a
/// non-finite float.
///
/// `num.as_u64().unwrap() as i64` reinterpreted the bit pattern rather than losing precision, as its
/// comment claimed: `u64::MAX` became exactly -1 and `i64::MAX + 1` exactly `i64::MIN`. Every numeric
/// guard in the language inverts for such a value, so `A < 0` passed and `MaxSize <= 1000` passed for
/// an input of 18446744073709551615, at exit 0.
///
/// The float half is the `Eq` violation: `PathAwareValue` asserts `Eq` and `Float(NaN)` is not equal
/// to itself, so `A == A` reported FAIL through this conversion on a document that PASSed through the
/// libyaml one. The libyaml loader has had the finiteness gate all along; this conversion did not,
/// and it is what `guard test` and the public `run_checks` read documents with.
#[rstest::rstest]
#[case::u64_max("18446744073709551615", Value::String("18446744073709551615".to_string()))]
#[case::just_past_i64_max("9223372036854775808", Value::String("9223372036854775808".to_string()))]
#[case::i64_max("9223372036854775807", Value::Int(i64::MAX))]
#[case::i64_min("-9223372036854775808", Value::Int(i64::MIN))]
#[case::negative("-1", Value::Int(-1))]
#[case::ordinary("42", Value::Int(42))]
#[case::nan(".nan", Value::String(".nan".to_string()))]
#[case::infinity(".inf", Value::String(".inf".to_string()))]
#[case::negative_infinity("-.inf", Value::String("-.inf".to_string()))]
#[case::ordinary_float("1.5", Value::Float(1.5))]
fn the_serde_conversion_never_changes_a_number_s_sign_or_admits_a_non_finite(
    #[case] scalar: &str,
    #[case] expected: Value,
) -> Result<()> {
    let yaml: serde_yaml::Value = serde_yaml::from_str(&format!("v: {scalar}"))?;
    let converted = Value::try_from(&yaml)?;

    let map = match converted {
        Value::Map(m) => m,
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    };
    let value = map.get("v").expect("v is present");

    assert_eq!(&expected, value, "for the scalar {}", scalar);

    Ok(())
}
