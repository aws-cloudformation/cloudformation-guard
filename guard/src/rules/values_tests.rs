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

/// The document `both_loaders_resolve_the_same_document_to_the_same_value` asserts agreement on.
///
/// A `const` rather than a local so `the_spellings_the_two_loaders_read_differently` can check that
/// none of the divergent spellings is in it. Without that check, a spelling could be taken out of
/// this document and added to the exclusion list in one commit and nothing would fail, which is the
/// half of the exclusion bookkeeping neither test used to cover.
const AGREEMENT_DOCUMENT: &str = r#"
Mappings:
  NonStringKeys:
    123456789012: an account id
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
///     extension would re-add a 1.1-ism the boolean set dropped. A choice, not a limit, and pinned in
///     `DIVERGENT` with both of its readings rather than only described here. A divergence held open
///     deliberately still has to fail something when it closes: accepting binary makes the two loaders
///     agree on `0b101`, which trips the `assert_ne!` over the table and names the row to move.
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
///
/// The spellings deliberately NOT in `AGREEMENT_DOCUMENT` are the ones the two loaders read
/// differently, whether by limit or by choice. `the_spellings_the_two_loaders_read_differently` holds
/// them in `DIVERGENT`, pins each one's two readings, and asserts that each is absent from this
/// document, so a change to either side fails while this test keeps asserting agreement on everything
/// else. How many there are is asserted there too, against the table, rather than counted here where
/// nothing would read it. Moving them there rather than deleting them is the point -- an agreement
/// claim that quietly excluded them would be weaker than one that names them.
#[test]
fn both_loaders_resolve_the_same_document_to_the_same_value() -> Result<()> {
    let document = AGREEMENT_DOCUMENT;

    let via_libyaml = PathAwareValue::try_from(crate::rules::values::read_from(document)?)?;
    let via_serde = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;

    let (_, libyaml_json): (String, serde_json::Value) = (&via_libyaml).try_into()?;
    let (_, serde_json_value): (String, serde_json::Value) = (&via_serde).try_into()?;

    assert_eq!(
        serde_json_value, libyaml_json,
        "the two loaders read the same bytes as different values, so which command read a file \
         decides what it means"
    );

    // The document's own size, asserted so it cannot shrink unnoticed. Deleting a line from it makes
    // this test cover less while still passing, which is the one direction the divergence bookkeeping
    // in `the_spellings_the_two_loaders_read_differently` cannot see: that test only checks that the
    // excluded spellings are *absent*, so a spelling quietly removed from here and listed nowhere
    // leaves every assertion green. Counted from the string at run time rather than declared as a
    // length, so the number moves when the document does.
    let asserted_values = AGREEMENT_DOCUMENT
        .lines()
        .filter_map(|line| line.split_once(": "))
        .filter(|(_, value)| !value.trim().is_empty())
        .count();
    assert_eq!(
        40, asserted_values,
        "the agreement document lost a value; a spelling removed from it is only covered if it is \
         listed as a divergence, so restore it or add it to DIVERGENT"
    );

    Ok(())
}

/// The spellings the two loaders read differently, with each one's two readings.
///
/// `(scalar, the libyaml loader's reading, the serde reading)`. One table, read by one test. It used to
/// be an `rstest` carrying its own three spellings beside a separate `DIVERGENT` array in a second
/// test, and nothing tied the two together: measured, a fourth case added to the `rstest` and left out
/// of the array kept the whole suite green, which is the quiet growth the pair was written to prevent.
/// The array's `assert_eq!(3, DIVERGENT.len())` could not catch it either -- on a fixed-size array that
/// compares two compile-time constants, so it only ever fired for an edit that grew the array *and* its
/// declared length, which is the direction already being done deliberately.
///
/// A slice rather than a `[_; N]` for that same reason. A fixed-size array declares its length beside
/// its rows, so any assertion over that length compares two constants and cannot move; a slice's length
/// comes from its contents, so the size assertion in the test below fails when a row is added or
/// dropped. Removal is the direction nothing else sees: delete a row and every remaining assertion
/// still passes while one divergence is no longer pinned anywhere, which is what the same guard over
/// `AGREEMENT_DOCUMENT` catches for the other table.
///
/// The cost of one table is the `rstest` case names, which named each spelling in the output. Every
/// assertion below carries the scalar in its message instead.
const DIVERGENT: &[(&str, &str, &str)] = &[
    ("0755", "755", "0755"),
    ("0b101", "0b101", "5"),
    (
        "0xFFFFFFFFFFFFFFFF",
        "0xFFFFFFFFFFFFFFFF",
        "18446744073709551615",
    ),
    (
        "+18446744073709551615",
        "+18446744073709551615",
        "18446744073709551615",
    ),
];

/// Each spelling excluded from the agreement document reads two ways, and is really excluded.
///
/// These are left out of `both_loaders_resolve_the_same_document_to_the_same_value` because they do not
/// agree. Most of them cannot be made to; `0b101` could be, and is not, which is why it is pinned here
/// with the rest rather than left as a sentence somebody has to trust. Pinned rather than dropped, so
/// that a change to either side fails: the agreement test proves nothing about a case it does not
/// contain, and a reader who found one of these missing from it would have no way to tell a deliberate
/// exclusion from an oversight.
///
/// What each divergence is:
///
///   - `0755`. The libyaml loader resolves a leading-zero decimal, which is the reading it has always
///     had, so the value is `755` and a mapping key spelled that way is addressed as `755`.
///     `serde_yaml` gates its number path behind `digits_but_not_number`, which is true for a
///     leading-zero decimal, so it yields the string. Choosing this loader's own reading is what stops
///     a numeric `when` condition over a file mode from failing to apply; the cost is this divergence,
///     which predates the choice -- `serde_yaml` and `parse::<i64>` never agreed on these characters.
///   - `0b101`. YAML 1.2 core has no binary form -- it is 1.1's -- so this loader leaves the characters
///     as text, and `serde_yaml`, which carries the 1.1 extension, resolves them to 5. A choice rather
///     than a limit, unlike the others here: accepting binary would re-add a 1.1-ism of exactly the kind
///     that cutting the boolean set from 22 spellings to 6 removed. Both readings are pinned anyway,
///     because a choice nothing checks is indistinguishable from an oversight, and because the row is
///     what reports the choice being reversed -- the `assert_ne!` below fails the moment the two loaders
///     agree on it.
///   - `0xFFFFFFFFFFFFFFFF` and `+18446744073709551615`. Both are integers above `i64::MAX`. The
///     libyaml loader keeps the literal source text, so the hex spelling stays hex and the signed
///     spelling keeps its `+`. `serde_yaml` resolves each to a `u64` first and the conversion then
///     writes the decimal digits, so both arrive as `18446744073709551615`. Same value, different
///     text, and a clause comparing against either spelling holds under one command and not the other.
///
/// Asserted as a mapping value rather than a key so the reading under test is the scalar conversion
/// and not `scalar_key_name`, which has its own rendering rules.
///
/// # Why removing these from the agreement document is scoping and not weakening
///
/// The distinction is worth stating because the two look alike in a diff. Weakening would be relaxing
/// the comparison in `both_loaders_resolve_the_same_document_to_the_same_value` -- comparing fewer
/// fields, or tolerating a mismatch -- which would leave it unable to detect *any* divergence,
/// including one nobody has seen. That is not what happened. It still compares whole documents
/// exactly, so a spelling that starts diverging fails it.
///
/// What changed is which spellings are in its input, and the ones that came out are pinned here with
/// both of their readings. A case that starts agreeing fails the `assert_ne!`, a spelling listed here
/// that is *also* still a value in the agreement document fails the exclusion assertion, and a row
/// added or dropped fails the size assertion -- together those make the exclusion bookkeeping hold in
/// every direction rather than one.
#[test]
fn the_spellings_the_two_loaders_read_differently() -> Result<()> {
    // The table's own size, asserted so a row cannot leave or arrive unnoticed. This is the number
    // `resolve_int`'s contract used to state in prose, moved to the one place that computes it: a count
    // written beside a table it does not read is a second copy of that table's contents, and that copy
    // has already been wrong -- `resolve_int` named a total its own arms had moved past, and nothing
    // failed. Removal is the direction the per-row assertions below cannot see -- delete a row and they
    // all still pass, one divergence simply stops being pinned -- which is the same hole the value count
    // in `both_loaders_resolve_the_same_document_to_the_same_value` closes for its document.
    //
    // Honest only because `DIVERGENT` is a slice: on a `[_; N]` the length is declared beside the rows,
    // so this would compare two compile-time constants and fire for no edit that was not already
    // deliberate, which is precisely the guard this test replaced.
    assert_eq!(
        4,
        DIVERGENT.len(),
        "the divergence table changed size; a spelling added needs both of its readings and its \
         exclusion from the agreement document checked, and one removed is no longer pinned at all"
    );

    for &(scalar, expected_libyaml, expected_serde) in DIVERGENT {
        let document = format!("probe: {scalar}\n");

        let via_libyaml = PathAwareValue::try_from(crate::rules::values::read_from(&document)?)?;
        let via_serde =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(&document)?)?;

        let (_, libyaml_json): (String, serde_json::Value) = (&via_libyaml).try_into()?;
        let (_, serde_json_value): (String, serde_json::Value) = (&via_serde).try_into()?;

        let rendered = |value: &serde_json::Value| -> String {
            match value.get("probe").expect("the key is present") {
                serde_json::Value::String(s) => s.clone(),
                other => other.to_string(),
            }
        };

        assert_eq!(
            expected_libyaml,
            rendered(&libyaml_json),
            "the libyaml loader's reading of `{scalar}` changed"
        );
        assert_eq!(
            expected_serde,
            rendered(&serde_json_value),
            "the serde reading of `{scalar}` changed"
        );
        assert_ne!(
            rendered(&libyaml_json),
            rendered(&serde_json_value),
            "`{scalar}` now reads the same through both loaders, so it belongs in \
             both_loaders_resolve_the_same_document_to_the_same_value rather than here"
        );

        // Matched as a whole value after `": "` rather than as a substring, so that a spelling which
        // merely occurs inside a longer scalar is not read as being in the document.
        let still_in_agreement_document = AGREEMENT_DOCUMENT
            .lines()
            .filter_map(|line| line.split_once(": "))
            .any(|(_, value)| value.trim() == scalar);
        assert!(
            !still_in_agreement_document,
            "`{}` is pinned here as a divergence and is still a value in the agreement document, \
             which asserts the two loaders agree on everything in it -- one of the two has to be \
             wrong",
            scalar
        );
    }

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
