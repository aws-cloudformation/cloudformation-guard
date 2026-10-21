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
/// `values::read_from` -- the libyaml loader -- is what every entry point that reads a document from
/// text uses now: `validate`'s `build_data_file`, `commands::helper::validate_and_return_json` (the
/// public `run_checks`), the `test` command's spec files (through `read_spec_from`, the same loader
/// with the spec file's settings), and `rulegen`. The serde-backed conversion still has one production caller:
/// the `json_parse` function in `rules/functions/strings.rs` parses a string taken out of the document
/// with `serde_yaml` and converts it through `Value::try_from_json`, which is `convert_yaml` with the
/// merge key read literally. So every divergence listed below is live on the text a template embeds
/// as a string, and this pin is not a record of a retired route. `rules` is a private module, so the
/// `TryFrom<serde_yaml::Value>` and `TryFrom<serde_json::Value>` impls themselves are reached only by
/// in-crate tests building fixtures, and by this pin. When the two were both live on whole documents,
/// a scalar they resolved differently meant one file meant two things depending on which command
/// read it, and this test is what caught each one; it stays so that a route added back onto serde
/// would be caught the same way.
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
/// The cases left out are below. They are the ones found so far, not a proof that no other spelling
/// divides the two readers; a spelling that turns out to divide them is added to this list, not to the
/// document. They divide into two kinds, and the difference decides whether the next reader should try
/// to close one.
///
/// **Closable, and left open with a reason.**
///
///   - `0b101`. YAML 1.2 core has no binary form -- it is 1.1's -- so following `serde_yaml`'s
///     extension would re-add a 1.1-ism the boolean set dropped. A choice, not a limit.
///
/// **Not closable at this boundary.** `serde_yaml::Value` is a *resolved* value model: it has already
/// discarded how each scalar was written, and anchors with it, before this conversion sees anything. So
/// no amount of work in `values.rs` can close a divergence whose correct answer depends on the source
/// text or the scalar style. Closing these for documents meant one loader rather than two, and that is
/// what was done: `validate_and_return_json` and the `test` command's `parse_test_specs` read through
/// the libyaml loader the way `rulegen` moved. The four below still divide the two *conversions*,
/// which is what this test compares. No whole document reaches the serde one any more; a string
/// `json_parse` reads out of a document does, so each of the four is still a way an embedded JSON
/// string can mean something other than the same text would as a file.
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
///   - a YAML **alias**. `serde_yaml` resolves anchors and aliases without a bound. The libyaml loader
///     resolves them on every route within an expansion budget
///     (`libyaml::loader::MAX_ALIAS_EXPANSION_NODES`), so an alias chain that `serde_yaml` would
///     expand without limit is refused there.
///   - a **duplicate key**. `serde_yaml::from_str` refuses one outright ("duplicate entry with key
///     ..."); the libyaml loader keeps the last value and warns.
///
/// An integer wider than `i64` and a lower-case non-finite float *were* on that list and are now in
/// the document: keeping the digits and the canonical `.nan`/`.inf` spelling made the two agree on the
/// spellings the document holds. Only those: `.Inf` and `.INF` still divide them (the serde side
/// resolves the three core casings to two floats, so `.Inf` is ".inf" there and ".Inf" on the libyaml
/// side, while `.iNf` is a plain string on both),
/// `0b101` is 5 on the serde side and the string "0b101" on the libyaml side, and a `1e-400` key is
/// the key "0.0" on the serde side and "1e-400" on the libyaml side; `values::scalar_key_name` records
/// those as the documented divergences of `json_parse`, and they are kept out of this document on
/// purpose. The merge key and the non-string scalar keys are in the document too, which the round that
/// added this test fixed on the libyaml loader only. The document with those two blocks in it fails
/// this assertion against `values.rs` as it stood then, which is measured, and each of the two was
/// measured diverging on its own through `guard test`.
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
/// libyaml one. The libyaml loader has the finiteness gate, and this conversion carries the same one:
/// `guard test` and the public `run_checks` read documents through the libyaml loader, and `json_parse`
/// is the one production route left through here.
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

/// The `serde_json` conversion keeps the digits of an integer above `i64::MAX`, as the `serde_yaml`
/// one and the libyaml loader do.
///
/// It read `num.as_u64().unwrap() as i64`, which reinterprets the bit pattern: `u64::MAX` became
/// exactly -1 and `i64::MAX + 1` exactly `i64::MIN`, so `A < 0` passed for a positive input wherever a
/// JSON document reached this conversion. The other two readers had already been moved to the digits.
///
/// Every route that reads a document from text goes through the libyaml loader now, so this
/// conversion is reached only by in-crate tests building fixtures from JSON; it is kept in step with
/// the loader so a fixture and a document holding the same integer mean the same thing.
#[rstest::rstest]
#[case::u64_max(serde_json::json!({"A": 18446744073709551615u64}), "18446744073709551615")]
#[case::just_past_i64_max(serde_json::json!({"A": 9223372036854775808u64}), "9223372036854775808")]
fn the_serde_json_conversion_keeps_the_digits_of_an_integer_past_i64(
    #[case] document: serde_json::Value,
    #[case] digits: &str,
) -> Result<()> {
    let converted = PathAwareValue::try_from(document)?;

    let map = match &converted {
        PathAwareValue::Map((_, map)) => map,
        other => unreachable!("an object converts to a map, got {:?}", other),
    };

    match map.values.get("A").expect("A is present") {
        PathAwareValue::String((_, text)) => assert_eq!(digits, text),
        other => panic!(
            "an integer above i64::MAX should keep its digits, got {:?}",
            other
        ),
    }

    // The ordinary case is unchanged: an integer that fits is still an integer.
    let small = PathAwareValue::try_from(serde_json::json!({"A": 42}))?;
    match &small {
        PathAwareValue::Map((_, map)) => assert!(
            matches!(map.values.get("A"), Some(PathAwareValue::Int((_, 42)))),
            "42 should still be an integer, got {:?}",
            map.values.get("A")
        ),
        other => unreachable!("an object converts to a map, got {:?}", other),
    }

    Ok(())
}

/// `read_from` reads valid JSON whose strings spell a character outside the BMP as a surrogate pair,
/// the way Python's `json.dumps` writes one.
///
/// libyaml refuses a surrogate escape inside a double-quoted scalar, which is right for YAML and
/// wrong for JSON, where the pair is the only spelling of that character. So a JSON document the
/// loader refuses is parsed once more as JSON, and if it is valid JSON its surrogate pairs are
/// decoded in place before the loader reads it again. The same six characters inside a YAML
/// double-quoted scalar are not valid JSON and stay refused: the decoding is a JSON rule, applied
/// only to JSON text.
#[test]
fn read_from_decodes_a_json_surrogate_pair_escape() -> Result<()> {
    let json = "{\"Label\": \"\\ud83d\\ude00\", \"Plain\": \"\\u0041\"}";

    let loaded = PathAwareValue::try_from(crate::rules::values::read_from(json)?)?;
    let map = match &loaded {
        PathAwareValue::Map((_, map)) => map,
        other => unreachable!("an object converts to a map, got {:?}", other),
    };
    match map.values.get("Label").expect("Label is present") {
        PathAwareValue::String((_, text)) => assert_eq!("😀", text),
        other => panic!("the pair should decode to one character, got {:?}", other),
    }
    match map.values.get("Plain").expect("Plain is present") {
        PathAwareValue::String((_, text)) => assert_eq!("A", text),
        other => panic!("an ordinary escape still decodes, got {:?}", other),
    }

    let yaml = "Label: \"\\ud83d\\ude00\"\n";
    assert!(
        crate::rules::values::read_from(yaml).is_err(),
        "the same escape in YAML text is not valid JSON and stays refused"
    );

    Ok(())
}

/// Positions after a rewritten surrogate pair are the source text's, not the rewritten text's.
///
/// The YAML escape a pair is rewritten as is two characters shorter than the pair, so the loader's
/// columns for everything after it on the line are too small by two per pair. The rewrite records
/// where it shortened each line and the loaded positions are corrected afterwards, so a finding, a
/// duplicate-key warning or a SARIF region on such a line names the column the author can see. Two
/// pairs on one line pin that the correction accumulates; a second line pins that it is confined to
/// the lines that held a pair.
#[test]
fn read_from_keeps_source_columns_after_surrogate_pairs() -> Result<()> {
    let json = "{\"Label\": \"\\ud83d\\ude00\\ud83d\\ude01\", \"After\": 1,\n \"Other\": 2}";

    let loaded = PathAwareValue::try_from(crate::rules::values::read_from(json)?)?;
    let map = match &loaded {
        PathAwareValue::Map((_, map)) => map,
        other => unreachable!("an object converts to a map, got {:?}", other),
    };

    let location_of = |name: &str| match map.values.get(name).expect("the member is present") {
        PathAwareValue::Int((path, _)) => path.1,
        PathAwareValue::String((path, _)) => path.1,
        other => unreachable!("a scalar member, got {:?}", other),
    };
    assert_eq!(
        Location::new(1, 11),
        location_of("Label"),
        "a position before the pairs is untouched"
    );
    assert_eq!(
        Location::new(1, 48),
        location_of("After"),
        "a position after two pairs is the source column, four past the loader's"
    );
    assert_eq!(
        Location::new(2, 11),
        location_of("Other"),
        "a position on a line holding no pair is untouched"
    );

    let key_columns: Vec<usize> = map
        .keys
        .iter()
        .map(|key| match key {
            PathAwareValue::String((path, _)) => path.1.col,
            other => unreachable!("a key is a string, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![2, 39, 2],
        key_columns,
        "the key positions are corrected too"
    );

    Ok(())
}

/// Valid JSON that libyaml's scanner refuses is rewritten the way a YAML emitter would write it, and
/// read, with every position put back on the source.
///
/// JSON is read as the YAML it is, and three shapes JSON permits fall outside what libyaml's scanner
/// accepts: a member name that spans more than 1024 bytes from its opening quote to its colon, a line
/// break between a member name and its colon, and a raw U+007F-U+009F (other than U+0085), U+FFFE or
/// U+FFFF inside a string. All three were refused with a message naming the limit, and all three
/// read through `serde_json` before the readers were made one, so the refusal was a regression on
/// valid documents. Each is rewritten before the loader reads the text: a long member name becomes
/// an explicit `? "name"` key, which the scanner does not measure; the break is replaced by a space;
/// the raw character becomes its `\u` escape. The positions are the source's: the member after a
/// break is on the next line, and the long name's position is its opening quote.
#[rstest::rstest]
#[case::a_member_name_past_the_limit(
    format!("{{\"{}\": 1, \"B\": 2}}", "k".repeat(1100)),
    "k".repeat(1100),
    Location::new(1, 2),
    Location::new(1, 1106)
)]
#[case::a_line_break_before_the_colon(
    "{\"A\"\n: 1, \"B\": 2}".to_string(),
    "A".to_string(),
    Location::new(1, 2),
    Location::new(2, 3)
)]
// A bare CR is a line break to libyaml, so a member name followed by one is rewritten like one
// followed by LF. CRLF is one break, so a member name on the second line of a CRLF file is at line 2.
#[case::a_bare_carriage_return_before_the_colon(
    "{\"A\"\r: 1, \"B\": 2}".to_string(),
    "A".to_string(),
    Location::new(1, 2),
    Location::new(2, 3)
)]
#[case::a_member_name_after_a_crlf(
    "{\r\n\"A\"\r\n: 1, \"B\": 2}".to_string(),
    "A".to_string(),
    Location::new(2, 1),
    Location::new(3, 3)
)]
fn read_from_reads_the_json_member_names_libyaml_cannot_scan(
    #[case] json: String,
    #[case] name: String,
    #[case] name_location: Location,
    #[case] value_location: Location,
) -> Result<()> {
    let loaded = PathAwareValue::try_from(crate::rules::values::read_from(&json)?)?;
    let map = match &loaded {
        PathAwareValue::Map((_, map)) => map,
        other => unreachable!("an object converts to a map, got {:?}", other),
    };
    match map.values.get(&name) {
        Some(PathAwareValue::Int((path, 1))) => assert_eq!(
            value_location, path.1,
            "the member's value is where the source has it"
        ),
        other => panic!(
            "the member `{}` should be the integer 1, got {:?}",
            &name[..1],
            other
        ),
    }
    match map.keys.first() {
        Some(PathAwareValue::String((path, key))) => {
            assert_eq!(&name, key, "the member name is read whole");
            assert_eq!(
                name_location, path.1,
                "the member name is at its opening quote in the source"
            );
        }
        other => panic!("the first key is the member name, got {:?}", other),
    }
    assert!(
        matches!(map.values.get("B"), Some(PathAwareValue::Int((_, 2)))),
        "the member after it is read as well"
    );

    Ok(())
}

/// A raw character JSON permits inside a string and libyaml's reader refuses as a control character
/// is read as that character.
///
/// libyaml accepts U+0085 and the printable ranges and refuses U+007F-U+009F, U+FFFE and U+FFFF,
/// where JSON requires only U+0000-U+001F to be escaped. Each is rewritten as its `\u` escape before
/// the loader reads the text, as the three raw line breaks are, and the loader reads the escape back
/// as the character; the escape is five characters longer than the character, so a position after it
/// on the same line is put back where the source has it. None of the three is a line break, so
/// nothing moves to the next line.
#[rstest::rstest]
#[case::a_delete("a\u{007F}b")]
#[case::a_c1_control("a\u{0080}b")]
#[case::the_last_c1_control("a\u{009F}b")]
#[case::a_noncharacter("a\u{FFFE}b")]
#[case::the_last_noncharacter("a\u{FFFF}b")]
fn read_from_reads_a_raw_control_character_inside_a_json_string_as_the_character(
    #[case] label: &str,
) -> Result<()> {
    let json = format!("{{\"Label\":\"{label}\",\"After\":1}}");

    let loaded = PathAwareValue::try_from(crate::rules::values::read_from(&json)?)?;
    let map = match &loaded {
        PathAwareValue::Map((_, map)) => map,
        other => unreachable!("an object converts to a map, got {:?}", other),
    };
    match map.values.get("Label").expect("Label is present") {
        PathAwareValue::String((_, text)) => assert_eq!(label, text, "the character is kept"),
        other => panic!("Label should be a string, got {:?}", other),
    }
    match map.values.get("After").expect("After is present") {
        // `{` 1, `"Label"` 2 to 8, `:` 9, the string 10 to 14, `,` 15, `"After"` 16 to 22, `:` 23.
        PathAwareValue::Int((path, 1)) => assert_eq!(
            Location::new(1, 24),
            path.1,
            "the member after the character is where the source has it, on the same line"
        ),
        other => panic!("After should be the integer 1, got {:?}", other),
    }

    Ok(())
}

/// A raw NEL, LS or PS inside a JSON string is read as that character, and the positions after it
/// are the ones the loader gives the source.
///
/// JSON permits all three unescaped, and libyaml reads each as a line break: inside a double-quoted
/// scalar a break is folded, so `"a<NEL>b"` loaded as `a b` and `"a <LS> b"` as `a<LS>b` (NEL
/// becomes a space, LS and PS are kept and the blanks beside them dropped), the load succeeded, and
/// nothing said the value had changed. The character is rewritten as its `\u` escape before the
/// loader reads the text, and the loader reads the escape back as the character. Positions are
/// numbered as the loader numbers the source: the raw character ends a line, so `After` on the same
/// physical line is on line 2 -- for `"a<NEL>b"` at column 12, `b` 1, `"` 2, `,` 3, `"After"` 4 to
/// 10, `:` 11, `1` 12; for the five-character strings one further along -- and the mapping key before
/// it is untouched. The YAML control pins that the loader itself still folds: this is a JSON reading,
/// applied to JSON text only.
#[rstest::rstest]
#[case::a_next_line("a\u{0085}b", 12)]
#[case::a_line_separator("a \u{2028} b", 13)]
#[case::a_paragraph_separator("a \u{2029} b", 13)]
fn read_from_reads_a_raw_line_break_inside_a_json_string_as_the_character(
    #[case] label: &str,
    #[case] column_after_the_break: usize,
) -> Result<()> {
    let json = format!("{{\"Label\":\"{label}\",\"After\":1}}");

    let loaded = PathAwareValue::try_from(crate::rules::values::read_from(&json)?)?;
    let map = match &loaded {
        PathAwareValue::Map((_, map)) => map,
        other => unreachable!("an object converts to a map, got {:?}", other),
    };
    match map.values.get("Label").expect("Label is present") {
        PathAwareValue::String((path, text)) => {
            assert_eq!(label, text, "the character is kept, not folded");
            assert_eq!(Location::new(1, 10), path.1, "the string's opening quote");
        }
        other => panic!("Label should be a string, got {:?}", other),
    }
    match map.values.get("After").expect("After is present") {
        PathAwareValue::Int((path, 1)) => assert_eq!(
            Location::new(2, column_after_the_break),
            path.1,
            "the member after the break is on the next line, as the loader numbers the source"
        ),
        other => panic!("After should be the integer 1, got {:?}", other),
    }
    let key_positions: Vec<Location> = map
        .keys
        .iter()
        .map(|key| match key {
            PathAwareValue::String((path, _)) => path.1,
            other => unreachable!("a key is a string, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![
            Location::new(1, 2),
            Location::new(2, column_after_the_break - 8)
        ],
        key_positions,
        "the key before the break is untouched and the key after it is on line 2"
    );

    let yaml = format!("Label: \"{label}\"\n");
    let folded = PathAwareValue::try_from(crate::rules::values::read_from(&yaml)?)?;
    match &folded {
        PathAwareValue::Map((_, map)) => match map.values.get("Label") {
            Some(PathAwareValue::String((_, text))) => assert_ne!(
                label, text,
                "in YAML text the loader still folds the break; the rewrite is a JSON reading"
            ),
            other => panic!("Label should be a string, got {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }

    Ok(())
}

/// When the rewritten text is refused for one of the loader's own reasons, that refusal is what comes
/// back, with the positions it names put back on the source.
///
/// The only refusal of the loader's own that JSON text can earn is the depth bound (JSON has no
/// aliases, no second document and no key but a string). The depth refusal names the container's
/// position, which the loader read off the rewritten text, two columns left of where the source has
/// it; the position is restored before the message is returned. The JSON gate follows the text to the
/// loader's bound and one level past it, independent of `serde_json`'s own recursion limit, so the
/// refusal is reached end to end through `read_from`, and the same text one container shallower, 128
/// deep, is rewritten and loads with the pair decoded.
#[test]
fn load_rewritten_returns_the_loaders_own_refusal_at_the_source_position() {
    let prefix = "{\"Label\":\"\\ud83d\\ude00\",\"deep\":";
    // The object is the first container, so the 128th `[` is the 129th and is refused.
    let json = format!("{prefix}{}1{}}}", "[".repeat(128), "]".repeat(128));
    let source_col = prefix.chars().count() + 128;
    let rewritten_col = source_col - 2;

    match crate::rules::values::read_from(&json) {
        Err(Error::UnsupportedDocument(message)) => {
            assert!(
                message.contains("nested at most") && message.contains("level 129"),
                "the loader's depth refusal is returned, not a generic one:\n{}",
                message
            );
            assert!(
                message.contains(&format!("L:1,C:{source_col}"))
                    && !message.contains(&format!("L:1,C:{rewritten_col}")),
                "the position is the source's column {source_col}, not the rewritten text's \
                 {rewritten_col}:\n{}",
                message
            );
        }
        other => panic!(
            "the depth refusal should come back, got {:?}",
            other.map(|_| "a loaded document")
        ),
    }

    let at_the_bound = format!("{prefix}{}1{}}}", "[".repeat(127), "]".repeat(127));
    let loaded = crate::rules::values::read_from(&at_the_bound)
        .expect("128 nested containers are inside the loader's bound and load");
    let MarkedValue::Map(entries, _) = loaded else {
        panic!("a JSON object loads as a mapping");
    };
    assert!(
        entries.iter().any(|((key, _), value)| key == "Label"
            && matches!(value, MarkedValue::String(s, _) if s == "\u{1F600}")),
        "the surrogate pair is decoded at the bound: {:?}",
        entries.keys().collect::<Vec<_>>()
    );
}

/// The limits are measured on the text libyaml read, which after a rewrite is the rewritten text.
///
/// The simple-key limit counts bytes, and a rewritten surrogate pair is two bytes shorter than the
/// pair. A member name of 1,026 bytes from quote to colon in the source is 1,024 in the rewritten
/// text, which libyaml accepts; a check measured on the source would blame it for a refusal whose cause
/// is the lone surrogate two members later. The check runs on the rewritten text and names the lone
/// surrogate, and the position it names is the source's.
#[test]
fn read_from_measures_the_member_name_limit_on_the_text_the_reader_read() {
    let name = format!("{}\\ud83d\\ude00", "k".repeat(1012));
    let json = format!("{{\"{name}\": 1, \"B\": \"\\ud800\"}}");
    // The lone surrogate's position in the source: `{` 1, the name's opening quote 2, its 1,024
    // characters 3 to 1026, its closing quote 1027, `:` 1028, space 1029, `1` 1030, `,` 1031, space
    // 1032, `"B"` 1033 to 1035, `:` 1036, space 1037, `"` 1038, `\` 1039.
    let lone_surrogate_col = 1039;

    let refused = crate::rules::values::read_from(&json);
    match refused {
        Err(Error::UnsupportedDocument(message)) => {
            assert!(
                message.contains("lone surrogate") && !message.contains("member name"),
                "the lone surrogate is the cause, not the member name libyaml accepted:\n{}",
                message
            );
            assert!(
                message.contains(&format!("L:1,C:{lone_surrogate_col}")),
                "the position is the source's:\n{}",
                message
            );
        }
        other => panic!(
            "valid JSON libyaml refuses is UnsupportedDocument, got {:?}",
            other
        ),
    }
}

/// `read_from` hands the loader's error variants to its caller apart, rather than folding them into
/// `ParseError`.
///
/// `validate` reports a `MissingDocument` as an empty file and prints an `UnsupportedDocument` or an
/// `InvalidKeyType` as it is, where a `ParseError` gets the file's first bytes attached. A reader
/// that turned every loader failure into the one variant would take that choice away from every
/// caller at once; what `read_from` guarantees is that the variants reach the caller, and whether a
/// caller keeps them apart is that caller's own decision, made where it can be seen. Each variant is
/// pinned on the data-file reader.
#[test]
fn read_from_hands_the_loaders_error_variants_to_its_caller() {
    let undeclared_alias = "a: *x\nb: &x 1\n";
    assert!(
        matches!(crate::rules::values::read_from(undeclared_alias), Err(Error::UnsupportedDocument(m)) if m.contains("`*x`") && m.contains("declares")),
        "an alias to an anchor no earlier node declares is UnsupportedDocument"
    );

    let comment_only = "# nothing here\n";
    assert!(
        matches!(
            crate::rules::values::read_from(comment_only),
            Err(Error::MissingDocument)
        ),
        "a file holding no document is MissingDocument"
    );

    let null_key = "null: 1\n";
    assert!(
        matches!(
            crate::rules::values::read_from(null_key),
            Err(Error::InternalError(crate::rules::errors::InternalError::InvalidKeyType(m)))
                if m.contains("where the key is null")
        ),
        "a key with no text is InvalidKeyType"
    );
}

/// Text that is neither YAML nor JSON is refused with the YAML reader's message and position, and
/// the JSON reader's refusal is appended only when that reader got at least as far, as a `ParseError`.
///
/// A document with a missing comma between two members is not valid JSON, so
/// `valid_json_the_yaml_reader_cannot_read` does not apply. libyaml's message names where the YAML
/// reader stopped, and stays first on every route: YAML flow style begins with `{` and `[` as JSON
/// does, so the first character does not say which the author meant, and the JSON reader's position
/// on YAML flow text points at valid YAML (an unquoted key, say). So the JSON reader's refusal, which
/// `json_shape` produced while deciding that the text is not JSON, is appended as a second line only
/// when its position is at least as far into the text as libyaml's: on a JSON template missing a comma
/// between two members both readers stop at the member that follows the gap, and the JSON line is
/// shown; on `{"A": 1\n "B": 2}` libyaml stops after scanning `"B"` and the JSON reader at its quote,
/// earlier, so nothing of the JSON reader's is shown; and on a YAML flow mapping with a value missing
/// its comma the JSON reader stops at the first unquoted key, long before libyaml does, and is not
/// shown. The variant is `ParseError`, which is what malformed text is to the library's callers (FFI
/// code 5); `UnsupportedDocument` (code 25) is a construct cfn-guard will not model in a document that
/// parses, and this text does not parse. A YAML document that fails keeps the YAML reader's message
/// alone, and the spec reader answers as the data-file reader does. Text that does not begin with `{`
/// or `[` once a byte order mark and whitespace are passed over was not written as JSON, and gets
/// nothing from the JSON reader even where both readers stop at the same place: a document that fails
/// at its first character fails there for both, and "expected value at line 1 column 1" would be
/// added to every such YAML file otherwise.
#[test]
fn read_from_names_the_json_readers_position_when_text_that_begins_like_json_is_not_json() {
    let template_missing_a_comma =
        include_str!("../../resources/validate/missing-comma-template.json");
    for (route, result) in [
        (
            "read_from",
            crate::rules::values::read_from(template_missing_a_comma),
        ),
        (
            "read_spec_from",
            crate::rules::values::read_spec_from(template_missing_a_comma)
                .map(|loaded| loaded.value),
        ),
    ] {
        match result {
            Err(Error::ParseError(m)) => assert!(
                m.starts_with("error parsing file: did not find expected ',' or '}' at L:5,C:7")
                    && m.contains("\nRead as JSON as well, the text fails with: expected `,` or `}` at line 5 column 7"),
                "{}: libyaml's message and position come first, and the JSON reader's follow on a \
                 second line, because it read as far:\n{}",
                route,
                m
            ),
            other => panic!(
                "{}: text that is neither YAML nor JSON is a ParseError carrying libyaml's message, \
                 got {:?}",
                route, other
            ),
        }
    }

    for (what, text) in [
        ("a JSON reader stopping earlier", "{\"A\": 1\n \"B\": 2}\n"),
        (
            "YAML flow style with a value missing its comma",
            "[{name: a, input: {A: 1 B: 2}, expectations: {rules: {r: PASS}}}]\n",
        ),
        (
            "YAML flow style missing a closing brace",
            "{Resources: {B: {Type: X}}\n",
        ),
    ] {
        match crate::rules::values::read_from(text) {
            Err(Error::ParseError(m)) => assert!(
                m.starts_with("error parsing file: did not find expected ',' or '}' at L:")
                    && !m.contains("JSON"),
                "{}: libyaml's message and position alone, nothing from the JSON reader, which \
                 stopped earlier at valid YAML:\n{}",
                what,
                m
            ),
            other => panic!("{}: malformed text is a ParseError, got {:?}", what, other),
        }
    }

    let yaml = "A: [1, 2\n";
    match crate::rules::values::read_from(yaml) {
        Err(Error::ParseError(m)) => assert!(
            !m.contains("JSON") && m.contains("L:2,C:1"),
            "a YAML document keeps the YAML reader's message, with where it stopped:\n{}",
            m
        ),
        other => panic!("malformed YAML is a ParseError, got {:?}", other),
    }

    // Text that fails at its first character fails there for both readers, and the JSON reader's
    // "expected value at line 1 column 1" is as far as libyaml got; it is still not shown, because
    // nothing that begins with `@`, a backtick or a directive was written as JSON.
    for (what, text) in [
        ("an at sign", "@a: 1\n"),
        ("a backtick", "`a`: 1\n"),
        (
            "a directive libyaml refuses",
            "%YAML 1.1\n%YAML 1.1\n---\na: 1\n",
        ),
        ("whitespace, then an at sign", "  \n\t@a: 1\n"),
    ] {
        for (route, result) in [
            ("read_from", crate::rules::values::read_from(text)),
            (
                "read_spec_from",
                crate::rules::values::read_spec_from(text).map(|loaded| loaded.value),
            ),
        ] {
            match result {
                Err(Error::ParseError(m)) => assert!(
                    m.contains(" at L:") && !m.contains("JSON"),
                    "{} through {}: libyaml's message and position alone, nothing from the JSON \
                     reader, since the text does not begin like JSON:\n{}",
                    what,
                    route,
                    m
                ),
                other => panic!(
                    "{} through {}: malformed text is a ParseError, got {:?}",
                    what, route, other
                ),
            }
        }
    }
}

/// `read_spec_from` keeps the two document-level variants and turns a refused node into a `Refused`
/// node in the document, so a `test` spec loses one case rather than the file.
///
/// The spec loader marks a refused mapping rather than refusing, so `InvalidKeyType` does not come
/// back from it; what comes back is the document with a `Refused` node where the mapping was, which
/// the per-case conversion fails with. The two refusals that are about the document rather than a
/// node -- no document at all, and nesting past the bound -- keep their variants.
#[test]
fn read_spec_from_keeps_the_document_level_variants_and_marks_a_refused_node() -> Result<()> {
    let comment_only = "# nothing here\n";
    assert!(
        matches!(
            crate::rules::values::read_spec_from(comment_only),
            Err(Error::MissingDocument)
        ),
        "a spec holding no document is MissingDocument"
    );

    let too_deep = format!("a: {}x{}\n", "[".repeat(128), "]".repeat(128));
    assert!(
        matches!(
            crate::rules::values::read_spec_from(&too_deep),
            Err(Error::UnsupportedDocument(m)) if m.contains("nested at most")
        ),
        "nesting past the bound is UnsupportedDocument on the spec route too"
    );

    let null_key = "- good: 1\n- null: 1\n";
    let loaded = crate::rules::values::read_spec_from(null_key)?;
    match &loaded.value {
        MarkedValue::List(cases, _) => {
            assert!(
                matches!(&cases[0], MarkedValue::Map(..)),
                "the good case loads"
            );
            assert!(
                matches!(&cases[1], MarkedValue::Refused(m, _) if m.contains("where the key is null")),
                "the refused mapping is marked refused, carrying the refusal, got {:?}",
                cases[1]
            );
        }
        other => unreachable!("a sequence loads as a list, got {:?}", other),
    }

    Ok(())
}

/// The spec reader hands back the spelling of each number and boolean beside the document, and a
/// rewrite of the text moves those positions with everything else.
///
/// The `test` command renders a case's `name` from this table, so `1.50` is reported as `1.50`. The
/// JSON case holds a surrogate pair before the number on the same line, so the recorded position has
/// to be the source's column -- `{` 1, `"Label"` 2 to 8, `:` 9, the string 10 to 23, `,` 24, `"n"`
/// 25 to 27, `:` 28, `1.50` 29 -- for the lookup by position to find it.
#[test]
fn read_spec_from_records_scalar_spellings_at_source_positions() -> Result<()> {
    let yaml = "- name: 1.50\n- name: 1e3\n";
    let loaded = crate::rules::values::read_spec_from(yaml)?;
    assert_eq!(
        Some(&"1.50".to_string()),
        loaded.scalar_texts.get(&Location::new(1, 9)),
        "the float's spelling, by its position"
    );
    assert_eq!(
        Some(&"1e3".to_string()),
        loaded.scalar_texts.get(&Location::new(2, 9)),
        "the exponent spelling too"
    );

    let json = "{\"Label\":\"\\ud83d\\ude00\",\"n\":1.50}";
    let loaded = crate::rules::values::read_spec_from(json)?;
    assert_eq!(
        Some(&"1.50".to_string()),
        loaded.scalar_texts.get(&Location::new(1, 29)),
        "after a rewritten pair the spelling is filed under the source column: {:?}",
        loaded.scalar_texts
    );

    Ok(())
}

/// Valid JSON with a tab outside its root container loads on both routes.
///
/// A tab is JSON whitespace, and at the start of a line libyaml's scanner refuses it as indentation
/// ("found character that cannot start any token"). The rewrite turns a tab outside a string into a
/// space, as a YAML emitter would write the same whitespace, so `\t{"A": 1}` and a tab on a line of
/// its own after the document load as the document they hold.
#[rstest::rstest]
#[case::before_the_root("\t{\"A\": 1}\n")]
#[case::on_a_line_of_its_own_after_the_root("{\"A\": 1}\n\t\n")]
fn read_from_reads_valid_json_with_a_tab_outside_the_root(#[case] text: &str) {
    for (route, result) in [
        ("read_from", crate::rules::values::read_from(text)),
        (
            "read_spec_from",
            crate::rules::values::read_spec_from(text).map(|loaded| loaded.value),
        ),
    ] {
        let value =
            result.unwrap_or_else(|e| panic!("{}: valid JSON with a tab loads: {}", route, e));
        let MarkedValue::Map(entries, _) = value else {
            panic!("{}: a JSON object loads as a mapping", route);
        };
        assert!(
            entries
                .iter()
                .any(|((key, _), value)| key == "A" && matches!(value, MarkedValue::Int(1, _))),
            "{}: the document's one member is read: {:?}",
            route,
            entries.keys().collect::<Vec<_>>()
        );
    }
}

/// When valid JSON is refused by libyaml for a reason no known limit explains, the refusal carries
/// libyaml's own message and position rather than a fixed text.
///
/// Pinned on the function, because every shape of valid JSON that libyaml refuses is either rewritten
/// or named by `json_limit_hit`; the arm is for the shape nobody has met yet, and what it has to say
/// then is what libyaml said.
#[test]
fn an_unrecognized_refusal_of_valid_json_carries_libyamls_message() {
    let refusal = valid_json_the_yaml_reader_cannot_read(
        "{\"A\": 1}",
        &PositionMap::new(&[]),
        "error parsing file: found something libyaml did not expect at L:1,C:2",
    );
    match refusal {
        Error::UnsupportedDocument(message) => assert!(
            message.contains(
                "valid JSON that cfn-guard's YAML reader cannot read: error parsing \
                              file: found something libyaml did not expect at L:1,C:2"
            ) && !message.contains("does not recognize"),
            "the refusal carries libyaml's text and position:\n{}",
            message
        ),
        other => panic!(
            "valid JSON libyaml refuses is an UnsupportedDocument, got {:?}",
            other
        ),
    }
}

/// Restoring the source positions of a rewritten document costs a step per rewrite and a step per
/// position, not a step per rewrite for every position.
///
/// `json.dumps` writes a document on one line and every character outside the BMP as a surrogate
/// pair, so a one-line document of N nodes with M pairs is the shape that matters: walking the
/// rewrites from the start for each node is N times M steps, a billion on a few hundred thousand nodes
/// with tens of thousands of pairs. The position index is built once and searched per position, so
/// the steps counted are one per rewrite plus one per position restored (a node, a key, a recorded
/// scalar spelling), and the bound here is a small multiple of M + N.
#[test]
fn restoring_positions_costs_a_step_per_rewrite_and_per_node() {
    let members = 20_000usize;
    let mut text = String::from("{");
    for n in 0..members {
        if n > 0 {
            text.push(',');
        }
        text.push_str(&format!("\"k{n}\":\"\\ud83d\\ude00\""));
    }
    text.push('}');

    POSITION_STEPS.store(0, std::sync::atomic::Ordering::Relaxed);
    let loaded = crate::rules::values::read_from(&text).expect("valid JSON with pairs loads");
    let steps = POSITION_STEPS.load(std::sync::atomic::Ordering::Relaxed);
    let MarkedValue::Map(entries, _) = loaded else {
        panic!("a JSON object loads as a mapping");
    };
    assert_eq!(members, entries.len());
    // M = 20,000 rewrites; positions restored: the root, 20,000 keys and 20,000 values, so N + M is
    // about 60,000, and the walk from the start would have been about 400 million.
    let positions = 1 + 2 * members;
    assert!(
        steps <= 2 * (members + positions),
        "restoring {} positions over {} rewrites took {} steps, more than twice their sum",
        positions,
        members,
        steps
    );
}

/// A byte order mark before JSON does not keep the JSON gate from seeing the text as JSON.
///
/// `read_to_string` keeps a leading U+FEFF, libyaml consumes one before it counts a position, and
/// `serde_json` refuses one, so JSON that begins with a byte order mark and holds a surrogate pair was
/// refused with libyaml's escape message instead of being rewritten and read. The mark is dropped
/// before either reader sees the text; the positions do not move, since libyaml never counted it.
#[test]
fn read_from_reads_json_behind_a_byte_order_mark() {
    let text = "\u{FEFF}{\"A\": 1, \"L\": \"\\ud83d\\ude00\"}\n";
    let loaded =
        crate::rules::values::read_from(text).expect("JSON behind a byte order mark loads");
    let MarkedValue::Map(entries, _) = loaded else {
        panic!("a JSON object loads as a mapping");
    };
    let label = entries
        .iter()
        .find(|((key, _), _)| key == "L")
        .map(|(_, value)| value)
        .expect("L is read");
    // The string's opening quote is the fifteenth character after the mark.
    assert!(
        matches!(label, MarkedValue::String(s, loc) if s == "\u{1F600}" && loc.col == 15),
        "the pair is decoded and the position is the source's, counted from after the mark: {:?}",
        label
    );
}

/// JSON nested to the loader's bound is rewritten like any other, so a raw NEL inside one of its
/// strings is read as the character.
///
/// The JSON gate followed `serde_json`'s own recursion limit of 128, one level short of the loader's
/// bound, so text at the bound skipped the rewrite and a raw NEL in a string loaded as a folded line
/// break: `"a<NEL>b"` read as `a b`, the silent change the rewrite exists to prevent. The gate reads
/// to the loader's bound and one past it now.
#[test]
fn read_from_rewrites_a_raw_break_in_json_nested_to_the_loaders_bound() {
    // The object is the first container; 127 arrays inside it make 128 levels, the loader's bound.
    let text = format!(
        "{{\"deep\":{}\"a\u{0085}b\"{}}}",
        "[".repeat(127),
        "]".repeat(127)
    );
    let mut value = crate::rules::values::read_from(&text).expect("128 levels load");
    for _ in 0..128 {
        value = match value {
            MarkedValue::Map(mut entries, _) => entries.pop().expect("deep").1,
            MarkedValue::List(mut items, _) => items.pop().expect("one item"),
            other => panic!("expected a container, got {:?}", other),
        };
    }
    assert!(
        matches!(&value, MarkedValue::String(s, _) if s == "a\u{0085}b"),
        "the raw NEL is kept as the character, not folded: {:?}",
        value
    );
}

/// Two keys that differ as YAML scalars but read as one name are refused by both public conversions
/// from a `serde_yaml::Value`, naming the key.
///
/// `serde_yaml` keeps the integer `1` and the string `"1"` as two keys; the mapping arm renders both to
/// the text "1" and refuses the pair rather than letting the second insert replace the first silently.
/// `PathAwareValue`'s conversion goes through `Value`'s, so the refusal has to surface from both: a caller
/// holding either gets `ParseError`, not a map holding whichever value came last. A single key named "1" is
/// the control.
#[test]
fn two_keys_that_read_as_one_name_are_refused_by_both_conversions() -> Result<()> {
    let colliding: serde_yaml::Value =
        serde_yaml::from_str("Tags:\n  1: first\n  \"1\": second\n")?;

    let via_value = Value::try_from(&colliding);
    assert!(
        matches!(via_value, Err(Error::ParseError(ref m)) if m.contains("read as the key `1`")),
        "Value::try_from must refuse the pair naming the key, got {:?}",
        via_value
    );

    let via_path_value = PathAwareValue::try_from(colliding);
    assert!(
        matches!(via_path_value, Err(Error::ParseError(ref m)) if m.contains("read as the key `1`")),
        "PathAwareValue::try_from must refuse the pair naming the key, got {:?}",
        via_path_value
    );

    let single: serde_yaml::Value = serde_yaml::from_str("Tags:\n  \"1\": only\n")?;
    let converted = Value::try_from(&single)?;
    match &converted {
        Value::Map(outer) => match outer.get("Tags") {
            Some(Value::Map(tags)) => {
                assert_eq!(tags.keys().collect::<Vec<_>>(), vec!["1"]);
                assert_eq!(tags.get("1"), Some(&Value::String("only".to_string())));
            }
            other => panic!("Tags held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }

    Ok(())
}

/// Two keys inside one merge source that read as one name are refused the same way, and a merged key
/// under an explicit key of the same kind and name is a same-key override: skipped as shadowed, not
/// refused, the explicit value standing, which matches the libyaml loader's `apply_merges`. A merged
/// key under a held key of another kind is a collision and is refused, as the next tests pin.
///
/// `merge_into` skipped a merged name the map already held, whatever its kind, as the libyaml loader
/// then did. The same test also hid a collision *inside* a source: `<<: { 1: a, "1": b }` inserted the
/// first and silently skipped the second, where the same two keys written as explicit entries are
/// refused. Each entry is now checked against the live map as it arrives: a name this source already
/// inserted is a repeat and refused; a name the map holds is an override when the held key was written
/// as the same kind, skipped, and a collision otherwise, refused; anything else is inserted.
#[test]
fn two_merged_keys_that_read_as_one_name_are_refused() -> Result<()> {
    let colliding: serde_yaml::Value =
        serde_yaml::from_str("Outer:\n  <<: { 1: first, \"1\": second }\n")?;
    let converted = Value::try_from(&colliding);
    assert!(
        matches!(converted, Err(Error::ParseError(ref m)) if m.contains("read as the key `1`")),
        "a collision inside a merge source must be refused naming the key, got {:?}",
        converted
    );

    let explicit_wins: serde_yaml::Value =
        serde_yaml::from_str("Outer:\n  <<: { \"1\": merged }\n  \"1\": explicit\n")?;
    let converted = Value::try_from(&explicit_wins)?;
    match &converted {
        Value::Map(outer) => match outer.get("Outer") {
            Some(Value::Map(inner)) => {
                assert_eq!(inner.keys().collect::<Vec<_>>(), vec!["1"]);
                assert_eq!(
                    inner.get("1"),
                    Some(&Value::String("explicit".to_string())),
                    "an explicit key keeps precedence over a merged key of the same kind and name"
                );
            }
            other => panic!("Outer held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }

    Ok(())
}

/// The refusal on the conversion the one production caller uses: `json_parse` converts through
/// `Value::try_from_json`, the literal merge-key mode, and `{1: a, "1": b}` is refused there too,
/// naming the key.
///
/// The `TryFrom` impls the tests above exercise are public API no production code calls; this is the
/// arm that runs in a rule. The control is the pair JSON itself can write, `{"1": a, "1": b}`: two
/// string keys whose resolved values are equal, which `serde_yaml` refuses before any conversion runs
/// ("duplicate entry"), so it never reaches the collision check and the error is `serde_yaml`'s. The
/// rule-level half, what a rule sees when its embedded string holds either pair, is in
/// guard/tests/validate.rs.
#[test]
fn try_from_json_refuses_two_keys_that_read_as_one_name() -> Result<()> {
    let colliding: serde_yaml::Value = serde_yaml::from_str(r#"{1: "a", "1": "b"}"#)?;
    let converted = Value::try_from_json(&colliding);
    assert!(
        matches!(converted, Err(Error::ParseError(ref m)) if m.contains("read as the key `1`")),
        "the literal-merge-key conversion must refuse the pair naming the key, got {:?}",
        converted
    );

    let equal_valued = serde_yaml::from_str::<serde_yaml::Value>(r#"{"1": "a", "1": "b"}"#);
    assert!(
        matches!(&equal_valued, Err(e) if e.to_string().contains("duplicate entry")),
        "serde_yaml refuses two string keys of one name before conversion, got {:?}",
        equal_valued
    );

    let single: serde_yaml::Value = serde_yaml::from_str(r#"{"1": "only"}"#)?;
    let converted = Value::try_from_json(&single)?;
    assert!(
        matches!(&converted, Value::Map(map) if map.get("1") == Some(&Value::String("only".to_string()))),
        "one key named \"1\" converts as written, got {:?}",
        converted
    );

    Ok(())
}

/// A collision is two keys that read as one name but are not the same YAML key, wherever the two
/// sit: in one merge source, across two sources, or a merged key under an explicit one. Every
/// collision is refused on this route, which has no warning channel; the libyaml loader keeps its
/// value and warns on each of the same shapes. A same-key override -- a merged plain `Type` under an
/// explicit plain `Type`, the merge key's documented use -- is neither, and resolves silently on both.
///
/// Across two sources `<<: [{ 1: a }, { "1": b }]` and a merged `1` under an explicit `"1"` are
/// collisions by kind, not by name: the integer and the string are two YAML keys, and only this value
/// model's text rendering folds them, which is the collapse the mapping arm refuses for explicit
/// entries. Both are refused naming the key; the same-kind override control still resolves to
/// `explicit`.
#[rstest::rstest]
#[case::across_two_sources("Outer:\n  <<: [{ 1: a }, { \"1\": b }]\n")]
#[case::merged_under_explicit("Outer:\n  <<: { 1: a }\n  \"1\": explicit\n")]
#[case::merged_pair_under_explicit("Outer:\n  <<: { 1: a, \"1\": b }\n  \"1\": explicit\n")]
fn a_merged_key_that_reads_as_a_held_key_of_another_kind_is_refused(
    #[case] document: &str,
) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document)?;
    let converted = Value::try_from(&parsed);
    assert!(
        matches!(converted, Err(Error::ParseError(ref m)) if m.contains("read as the key `1`")),
        "{:?} must be refused naming the key, got {:?}",
        document,
        converted
    );
    Ok(())
}

/// The same-key override control: a merged key under an explicit key of the same kind and name is
/// the merge key's documented use, resolves to the explicit value, and is refused on no route.
///
/// Spelling is not kind. A plain `x` and a quoted `"x"` are the same string key, and so is a `!!str 1`
/// beside a `"1"`: YAML resolves all three to the string, and so does `serde_yaml`, so each pair is an
/// override here and silent on the libyaml loader. The forms that do differ are the resolved ones:
/// the integer `1` beside the string `"1"`. The libyaml loader has one more form, a plain literal it
/// keeps as text though YAML resolves it, and warns when one sits beside its quoted spelling; this
/// conversion never sees that form, and the tests after this pin what it reads instead (the four
/// cases are listed on `libyaml::loader::KeyForm`).
#[rstest::rstest]
#[case::plain_under_quoted("Outer:\n  <<: { x: merged }\n  \"x\": explicit\n", "x", "explicit")]
#[case::quoted_under_plain("Outer:\n  <<: { \"x\": merged }\n  x: explicit\n", "x", "explicit")]
#[case::tagged_string_beside_quoted("Outer:\n  <<: [{ !!str 1: a }, { \"1\": b }]\n", "1", "a")]
fn a_merged_key_of_the_same_kind_in_another_spelling_is_an_override(
    #[case] document: &str,
    #[case] key: &str,
    #[case] expected: &str,
) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document)?;
    let converted = Value::try_from(&parsed)
        .unwrap_or_else(|e| panic!("{:?} is a same-key override, got {:?}", document, e));
    match &converted {
        Value::Map(outer) => match outer.get("Outer") {
            Some(Value::Map(inner)) => {
                assert_eq!(inner.keys().collect::<Vec<_>>(), vec![key]);
                assert_eq!(
                    inner.get(key),
                    Some(&Value::String(expected.to_string())),
                    "{:?}: the held value stands",
                    document
                );
            }
            other => panic!("Outer held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }
    Ok(())
}

/// What this conversion reads for the pairs the libyaml loader calls a kept-literal collision, pinned
/// so the two routes' documented difference cannot drift.
///
/// A plain literal the libyaml loader keeps as text where YAML would resolve it reaches this
/// conversion as whatever `serde_yaml` made of it, and the spellings go four ways here (the four
/// cases are listed on `libyaml::loader::KeyForm`), each pinned by this test or one of the three
/// after it. This one is the differently-named row: `.Inf` and `1e-400` resolve to floats this
/// conversion renders `.inf` and `0.0`, so each sits beside its quoted spelling as a *differently
/// named* key: two entries, nothing collides, nothing is refused, where the loader keeps one name and
/// warns. The loader alone warns on these pairs; that is a measured difference between the routes,
/// not an agreement.
#[rstest::rstest]
#[case::non_finite_becomes_another_name(
    "Outer:\n  <<: { .Inf: merged }\n  \".Inf\": explicit\n",
    &[(".Inf", "explicit"), (".inf", "merged")]
)]
#[case::underflow_becomes_another_name(
    "Outer:\n  <<: { 1e-400: merged }\n  \"1e-400\": explicit\n",
    &[("1e-400", "explicit"), ("0.0", "merged")]
)]
fn a_literal_the_loader_keeps_as_text_is_resolved_to_another_name_here(
    #[case] document: &str,
    #[case] expected: &[(&str, &str)],
) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document)?;
    let converted = Value::try_from(&parsed).unwrap_or_else(|e| {
        panic!(
            "{:?} is not a collision on this route, got {:?}",
            document, e
        )
    });
    match &converted {
        Value::Map(outer) => match outer.get("Outer") {
            Some(Value::Map(inner)) => {
                let found: Vec<(&str, &Value)> =
                    inner.iter().map(|(k, v)| (k.as_str(), v)).collect();
                let want: Vec<(&str, Value)> = expected
                    .iter()
                    .map(|(k, v)| (*k, Value::String(v.to_string())))
                    .collect();
                assert_eq!(
                    found.len(),
                    want.len(),
                    "{:?}: entry count, got {:?}",
                    document,
                    found
                );
                for (k, v) in &want {
                    assert_eq!(inner.get(*k), Some(v), "{:?}: key {:?}", document, k);
                }
            }
            other => panic!("Outer held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }
    Ok(())
}

/// The kept literals the two routes agree on: a rendering that spells the key as the document wrote
/// it. `.inf` resolves to a float this conversion renders `.inf`, and an integer in
/// `(i64::MAX, u64::MAX]` resolves to a `u64` rendered digit for digit, so beside its quoted spelling
/// each is a number beside a string of one name and is refused here, where the libyaml loader keeps
/// one name and warns.
#[rstest::rstest]
#[case::lowercase_non_finite("Outer:\n  <<: { .inf: merged }\n  \".inf\": explicit\n", ".inf")]
#[case::integer_past_i64_within_u64(
    "Outer:\n  <<: { 9223372036854775808: merged }\n  \"9223372036854775808\": explicit\n",
    "9223372036854775808"
)]
fn a_literal_the_loader_keeps_as_text_that_renders_as_written_is_a_collision_here(
    #[case] document: &str,
    #[case] name: &str,
) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document)?;
    let converted = Value::try_from(&parsed);
    let expected = format!("read as the key `{}`", name);
    assert!(
        matches!(converted, Err(Error::ParseError(ref m)) if m.contains(&expected)),
        "{:?} must be refused naming the key, got {:?}",
        document,
        converted
    );
    Ok(())
}

/// `serde_yaml` leaves two integer-looking spellings strings, so beside the quoted spelling each is
/// two string keys of one name and a silent same-key override here: the explicit value stands and
/// nothing is refused. `0755` is a string on both routes -- the libyaml loader's `resolve_int` keeps
/// a decimal with a redundant leading zero on purpose, since YAML 1.1 and 1.2 give the text different
/// values -- so that pair is silent everywhere. `1e400` is a string here because `serde_yaml` does
/// not resolve a float that overflows, where the libyaml loader keeps it as a literal and warns on
/// the pair; that one is the loader's alone.
#[rstest::rstest]
#[case::leading_zero("Outer:\n  <<: { 0755: merged }\n  \"0755\": explicit\n", "0755")]
#[case::overflowing_float("Outer:\n  <<: { 1e400: merged }\n  \"1e400\": explicit\n", "1e400")]
fn an_integer_looking_spelling_serde_yaml_leaves_a_string_is_an_override_here(
    #[case] document: &str,
    #[case] name: &str,
) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document)?;
    let converted = Value::try_from(&parsed).expect("two string keys of one name are an override");
    match &converted {
        Value::Map(outer) => match outer.get("Outer") {
            Some(Value::Map(inner)) => {
                assert_eq!(
                    inner.keys().collect::<Vec<_>>(),
                    vec![name],
                    "{:?}",
                    document
                );
                assert_eq!(
                    inner.get(name),
                    Some(&Value::String("explicit".to_string())),
                    "{:?}",
                    document
                );
            }
            other => panic!("Outer held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }
    Ok(())
}

/// A mapping key wider than `u64` never reaches this conversion: `serde_yaml::from_str` refuses the
/// document itself ("invalid type: integer ... as u128"), so a document the libyaml loader reads,
/// keeping the digits as the key, does not load at all on this route. Pinned so the list on
/// `libyaml::loader::KeyForm` of what each route does with a kept literal stays measured.
#[test]
fn a_key_wider_than_u64_is_refused_by_serde_yaml_itself() {
    let parsed: std::result::Result<serde_yaml::Value, _> =
        serde_yaml::from_str("Outer:\n  18446744073709551616: a\n");
    match parsed {
        Err(e) => assert!(
            e.to_string().contains("18446744073709551616"),
            "the refusal names the integer, got {}",
            e
        ),
        Ok(value) => panic!("serde_yaml loaded a key wider than u64 as {:?}", value),
    }
}

/// YAML 1.2 core resolves `.inf`, `.Inf` and `.INF` (and `.nan`, `.NaN`, `.NAN`) and nothing else, so
/// `.iNf` is a plain string: `serde_yaml` reads it as one, and so does the libyaml loader since it
/// matches the spellings exactly. Beside its quoted spelling it is two string keys of one name, a
/// silent override on both routes. The control is `.INF`, a float here rendered `.inf`, a differently
/// named key beside `".INF"`.
#[rstest::rstest]
#[case::mixed_case_is_a_string(
    "Outer:\n  <<: { .iNf: merged }\n  \".iNf\": explicit\n",
    &[(".iNf", "explicit")]
)]
#[case::upper_case_is_a_float(
    "Outer:\n  <<: { .INF: merged }\n  \".INF\": explicit\n",
    &[(".INF", "explicit"), (".inf", "merged")]
)]
fn only_the_core_non_finite_spellings_resolve_to_floats_here(
    #[case] document: &str,
    #[case] expected: &[(&str, &str)],
) -> Result<()> {
    let parsed: serde_yaml::Value = serde_yaml::from_str(document)?;
    let converted = Value::try_from(&parsed).unwrap_or_else(|e| {
        panic!(
            "{:?} is not a collision on this route, got {:?}",
            document, e
        )
    });
    match &converted {
        Value::Map(outer) => match outer.get("Outer") {
            Some(Value::Map(inner)) => {
                let found: Vec<(&str, &Value)> =
                    inner.iter().map(|(k, v)| (k.as_str(), v)).collect();
                assert_eq!(
                    found.len(),
                    expected.len(),
                    "{:?}: entry count, got {:?}",
                    document,
                    found
                );
                for (k, v) in expected {
                    assert_eq!(
                        inner.get(*k),
                        Some(&Value::String(v.to_string())),
                        "{:?}: key {:?}",
                        document,
                        k
                    );
                }
            }
            other => panic!("Outer held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }
    Ok(())
}

#[test]
fn a_merged_key_under_an_explicit_key_of_the_same_kind_is_an_override() -> Result<()> {
    let overridden: serde_yaml::Value = serde_yaml::from_str(
        "Outer:\n  <<: { Type: merged, \"1\": merged }\n  Type: explicit\n  \"1\": explicit\n",
    )?;
    let converted = Value::try_from(&overridden).expect("a same-key override is not a collision");
    match &converted {
        Value::Map(outer) => match outer.get("Outer") {
            Some(Value::Map(inner)) => {
                assert_eq!(inner.keys().collect::<Vec<_>>(), vec!["Type", "1"]);
                assert_eq!(
                    inner.get("Type"),
                    Some(&Value::String("explicit".to_string()))
                );
                assert_eq!(inner.get("1"), Some(&Value::String("explicit".to_string())));
            }
            other => panic!("Outer held {:?}", other),
        },
        other => unreachable!("a mapping converts to a map, got {:?}", other),
    }
    Ok(())
}
