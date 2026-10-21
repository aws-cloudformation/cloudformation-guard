use crate::rules::path_value::DuplicateKey;
use crate::rules::Result;
use pretty_assertions::assert_eq;

use super::*;

#[test]
fn yaml_loader() -> Result<()> {
    let docs = r###"
#    apiVersion: v1
#    next: true
#    number: 3
#    spec:
#      containers:
#        - image: blah
#          second: true
    Name: !Sub
      - www.${Domain}
      - { Domain: !Ref RootDomainName }
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Name", Location { line: 9, col: 5 }): Map({("Fn::Sub", Location { line: 9, col: 11 }): List([String("www.${Domain}", Location { line: 10, col: 9 }), Map({("Domain", Location { line: 11, col: 11 }): Map({("Ref", Location { line: 11, col: 19 }): String("RootDomainName", Location { line: 11, col: 19 })}, Location { line: 11, col: 19 })}, Location { line: 11, col: 9 })], Location { line: 9, col: 11 })}, Location { line: 9, col: 11 })}, Location { line: 9, col: 5 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

/// The whole boolean set, which is the YAML 1.2 core schema's six spellings.
///
/// The assertion is unconditional: one that sat inside an `if let MarkedValue::Bool(..)` would let
/// every spelling read as a string satisfy its case by never reaching it. YAML 1.1's `y`, `yes`,
/// `on` and the rest of its 22 are strings here, and are asserted to be strings in
/// `a_scalar_outside_the_boolean_set_is_still_a_string`.
#[rstest::rstest]
#[case::standard_lowercase_true("true", true)]
#[case::standard_capitalized_true("True", true)]
#[case::standard_uppercase_true("TRUE", true)]
#[case::standard_lowercase_false("false", false)]
#[case::standard_capitalized_false("False", false)]
#[case::standard_uppercase_false("FALSE", false)]
fn test_handle_bool_happy_path(#[case] arg: &str, #[case] expected: bool) -> Result<()> {
    let mut loader = Loader::new();
    let value = loader.load(format!("check: {arg}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    assert_eq!(1, map.len());
    let (.., loaded) = map.first().unwrap();

    assert!(
        matches!(loaded, MarkedValue::Bool(b, ..) if *b == expected),
        "{} loaded as {:?}, not the boolean {}",
        arg,
        loaded,
        expected
    );

    Ok(())
}

#[test]
fn yaml_loader2() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: false
      InstanceCount: 312
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: String
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): Int(312, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): String("String", Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader3() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: false
      InstanceCount: 3.12
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: String
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): Float(3.12, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): String("String", Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader4() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: !!bool "false"
      InstanceCount: !!float "3.12"
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: String
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): Float(3.12, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): String("String", Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader5() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: false
      InstanceCount: !!int "312"
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: !!null "null"
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): Int(312, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): Null(Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader6() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: false
      InstanceCount: !!int "312"
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: !!null "~"
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): Int(312, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): Null(Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader7() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: false
      InstanceCount: !!int "3x12"
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: !!null "~"
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): BadValue("!!int 3x12", None, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): Null(Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader8() -> Result<()> {
    let docs = r###"
Resources:
  MyEc2Thing:
    Type: AWS::EC2::CapacityReservation
    Properties:
      AvailabilityZone: "some string"
      EbsOptimized: true
      EndDate: "12/31/2023"
      EphemeralStorage: false
      InstanceCount: !!int "3x12"
      InstanceMatchCriteria: "open"
      TagSpecifications:
      - ResourceType: instance
        Tags:
        - Key: Name
          Value: CFN EC2 Spot Instance
      Tenancy: !!str ~
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): BadValue("!!int 3x12", None, Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): String("~", Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[test]
fn yaml_loader_with_alias() -> Result<()> {
    let docs = r###"
a: &numbers
- 1
- 2
- 3
b: *numbers
    "###;

    // `Loader::new` is the data-file loader, the one `validate` and `rulegen` read with. It resolves
    // the alias as the spec-file loader does: the serde reader every route used before this loader
    // resolved aliases, and refusing them here was the one route-level difference the loader rewrite
    // introduced. The tests after this one cover the budget and the refusals.
    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let MarkedValue::List(items, _) = entry(&value, "b") else {
        panic!("`b` is a copy of the anchored sequence, got {:?}", value);
    };
    let ints: Vec<i64> = items
        .iter()
        .map(|item| match item {
            MarkedValue::Int(i, _) => *i,
            other => panic!("an integer, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![1, 2, 3],
        ints,
        "the data-file loader resolves the alias to a copy of the anchored node"
    );

    Ok(())
}

/// An alias is a copy of the node its anchor named, for a scalar, a sequence and a mapping alike, and
/// a mapping aliased under `<<` merges as the inline form does.
///
/// The copy keeps the anchored node's positions, so the aliased sequence under `b` reports the lines
/// its items are written on under `a`; a finding inside an aliased `input:` then points at the text
/// the author has to change. The explicit key next to the merged alias wins over the merged one, as
/// `apply_merges` has it for the inline spelling.
#[test]
fn a_spec_loader_resolves_an_alias_to_a_copy_of_the_anchored_node() -> Result<()> {
    let docs = r###"
scalar: &s hello
a: &numbers
- 1
- 2
b: *numbers
again: *s
base: &base
  Shared: from_base
  Overridden: from_base
merged:
  <<: *base
  Overridden: explicit
"###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let top = match &value {
        MarkedValue::Map(map, _) => map,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let entry = |name: &str| {
        top.iter()
            .find(|((key, _), _)| key == name)
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("{} is present", name))
    };

    assert_eq!(
        entry("a"),
        entry("b"),
        "the aliased sequence is a copy of the anchored one, positions included"
    );
    // Column 9 is the `&s`: libyaml starts a node's event at its properties, as it does for a tag.
    assert_eq!(
        &MarkedValue::String("hello".to_string(), Location::new(2, 9)),
        entry("again"),
        "the aliased scalar is the anchored scalar, at the anchor's position"
    );

    let merged = match entry("merged") {
        MarkedValue::Map(map, _) => map,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let merged_values: Vec<(&str, &str)> = merged
        .iter()
        .map(|((key, _), value)| match value {
            MarkedValue::String(text, _) => (key.as_str(), text.as_str()),
            other => unreachable!("a scalar value, got {:?}", other),
        })
        .collect();
    assert_eq!(
        vec![("Overridden", "explicit"), ("Shared", "from_base")],
        merged_values,
        "`<<: *base` merges the anchored mapping, and the explicit key wins"
    );

    Ok(())
}

/// An alias to a name that no earlier node anchors is refused, naming the alias.
///
/// libyaml hands over the alias event without checking it, so the loader is what has to refuse the
/// forward reference; YAML has no forward references. A name anchored again later replaces the
/// earlier node for the aliases after it, as the second case shows.
#[test]
fn a_spec_loader_refuses_an_alias_to_an_anchor_no_earlier_node_declares() {
    let forward = "a: *later\nb: &later 1\n";
    let mut loader = Loader::new();
    let value = loader.load(String::from(forward));
    assert!(
        matches!(&value, Err(Error::UnsupportedDocument(m)) if m.contains("`*later`") && m.contains("declares")),
        "a forward alias gave {:?}, not a refusal naming it",
        value
    );

    let re_anchored = "a: &n 1\nb: *n\nc: &n 2\nd: *n\n";
    let mut loader = Loader::new();
    let value = loader
        .load(String::from(re_anchored))
        .expect("re-anchoring a name is allowed");
    let ints: Vec<i64> = match value {
        MarkedValue::Map(map, _) => map
            .into_iter()
            .map(|(_, value)| match value {
                MarkedValue::Int(i, _) => i,
                other => unreachable!("an integer, got {:?}", other),
            })
            .collect(),
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    assert_eq!(
        vec![1, 1, 2, 2],
        ints,
        "each alias sees the anchor most recently declared"
    );
}

/// The copies an alias makes are counted against `MAX_ALIAS_EXPANSION_NODES` for the document, and
/// the alias that would cross it refuses the document naming the budget and itself.
///
/// Six anchors that each alias the one before them ten times is the billion-laughs shape: ten
/// scalars, then a sequence copied ten times at each level. The aliases cost 110, 1,110, 11,110 and
/// 111,110 nodes at the second to fifth levels, 123,440 in all; recording the five anchors is not
/// charged. The sixth level's eighth alias of 111,111 nodes would take the count past a million. The
/// same chain one level shorter loads, which pins that the budget is where the constant says and not
/// lower.
#[test]
fn a_spec_loader_refuses_alias_expansion_past_the_budget() {
    let level = |name: char, previous: char| {
        format!(
            "{name}: &{name} [{}]\n",
            std::iter::repeat(format!("*{previous}"))
                .take(10)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut five_levels = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
    for (name, previous) in [('b', 'a'), ('c', 'b'), ('d', 'c'), ('e', 'd')] {
        five_levels.push_str(&level(name, previous));
    }
    let mut six_levels = five_levels.clone();
    six_levels.push_str(&level('f', 'e'));

    let mut loader = Loader::new();
    assert!(
        loader.load(five_levels).is_ok(),
        "123,440 copied nodes are inside the budget"
    );

    let mut loader = Loader::new();
    let value = loader.load(six_levels);
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m))
                if m.contains("through aliases") && m.contains("`*e`") && m.contains("1000000")
        ),
        "the sixth level gave {:?}, not a refusal naming the budget and the alias",
        value
    );
}

/// The entry named `key` of a loaded mapping.
fn entry<'a>(value: &'a MarkedValue, key: &str) -> &'a MarkedValue {
    let MarkedValue::Map(map, _) = value else {
        panic!("a mapping loads as a map, got {:?}", value);
    };
    map.iter()
        .find(|((name, _), _)| name == key)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("the mapping has no `{key}`: {:?}", map.keys()))
}

/// The billion-laughs chain of [`a_spec_loader_refuses_alias_expansion_past_the_budget`] up to its
/// fifth level, `e`, which holds 111,111 nodes; 123,440 nodes are charged by the time it is read.
fn five_level_chain() -> String {
    let level = |name: char, previous: char| {
        format!(
            "{name}: &{name} [{}]\n",
            std::iter::repeat(format!("*{previous}"))
                .take(10)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut text = String::from("a: &a [x, x, x, x, x, x, x, x, x, x]\n");
    for (name, previous) in [('b', 'a'), ('c', 'b'), ('d', 'c'), ('e', 'd')] {
        text.push_str(&level(name, previous));
    }
    text
}

/// An alias the budget refuses costs nothing but its message: the anchored node is neither walked
/// nor cloned for it.
///
/// `resolve_alias` reads the size from the anchor table, where it was measured when the anchor was
/// recorded, and makes the clone only after `charge_copy` has accepted the charge. Measuring the
/// anchored node with `size_of` and cloning it before the charge is decided would build a refused
/// copy in full and then drop it. Under `RefusalPolicy::MarkBadValue` a refused copy is not charged,
/// so every later alias of the same anchor is refused the same way, and each refusal would walk the
/// anchored node twice over. Ten thousand aliases of the 111,111-node `e`, about 40 KiB of text,
/// would then cost over two billion node visits and allocations with the budget already spent, and
/// `cfn-guard test` on such a spec would not come back.
///
/// The bound is a count of the clones and the measurements the loader made, not the wall clock: a
/// clock bound flakes under coverage or load, and the property under test is how many times the
/// anchored node is walked and copied. Loading the chain copies 45 nodes -- recording the five
/// anchors and resolving the forty aliases inside `b` to `e` -- and measures five, one per anchor
/// recorded; `g` adds the seven copies that fit and nothing else. The refusal itself does not move:
/// 123,440 nodes are charged before `g`, so seven aliases of `e` fit (901,217) and the eighth would
/// reach 1,012,328; every one of the 9,993 after that is marked refused with the message naming the
/// alias and the node budget, and the seven that fit are copies.
#[test]
fn a_spec_loader_refuses_an_alias_past_the_budget_without_copying_the_anchored_node() {
    let mut text = five_level_chain();
    text.push_str(&format!(
        "g: [{}]\n",
        std::iter::repeat("*e")
            .take(10_000)
            .collect::<Vec<_>>()
            .join(", ")
    ));

    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text)
        .expect("a refused alias is one node of the document, not a refusal of it");

    let MarkedValue::List(items, _) = entry(&value, "g") else {
        panic!("g is a sequence");
    };
    let copies = items
        .iter()
        .filter(|item| matches!(item, MarkedValue::List(..)))
        .count();
    let refused = items
        .iter()
        .filter(|item| {
            matches!(
                item,
                MarkedValue::Refused(m, _)
                    if m.contains("through aliases") && m.contains("`*e`") && m.contains("1000000")
            )
        })
        .count();
    assert_eq!(
        (7, 9_993),
        (copies, refused),
        "seven aliases of `e` fit the budget and every later one is refused naming it"
    );
    assert_eq!(
        (45 + 7, 5),
        (loader.copies_made, loader.nodes_measured),
        "the chain's anchors and aliases and the seven copies that fit are the only clones, and the \
         five anchors the only measurements: a refused alias neither walks nor clones the anchored \
         node"
    );
}

/// A merge key whose alias the loader refused reports the alias's refusal, not a merge error.
///
/// `<<: *base` is how a shared mapping is usually reused, so a misspelled anchor, or an anchor the
/// budget will not copy again, arrives at `apply_merges` as a `Refused` node under `MarkBadValue`.
/// The refusal the node carries is the one the mapping is refused with, whether the alias is the
/// merge key's value or an entry of its sequence. Treating the node as a source that is not a mapping
/// and refusing the mapping with "must be given a mapping, or a sequence of mappings" would hide the
/// only message that says what to fix.
///
/// The budget half: the chain charges 123,440 nodes and the alias of `e` inside `m` copies 111,111
/// more, so 234,551 are spent before `g`; recording `m`, a mapping around that copy, is not charged.
/// Each `<<: *m` copies 111,112 nodes: six fit (901,223) and the seventh would reach 1,012,335, so of
/// seven merges six are mappings and one is a refusal naming `*m` and the budget.
#[test]
fn a_spec_loader_reports_the_alias_refusal_behind_a_merge_key() {
    for text in [
        "base: &base {A: 1}\nuses: {<<: *bsae, B: 2}\n",
        "base: &base {A: 1}\nuses: {<<: [*base, *bsae], B: 2}\n",
    ] {
        let mut loader = Loader::for_spec_file();
        let value = loader
            .load(String::from(text))
            .expect("a refused node is marked, not a refusal of the document");
        match entry(&value, "uses") {
            MarkedValue::Refused(m, _) => {
                assert!(
                    m.contains("`*bsae`") && m.contains("declares"),
                    "{:?}: the refusal must name the alias:\n{}",
                    text,
                    m
                );
                assert!(
                    !m.contains("must be given a mapping"),
                    "{:?}: the merge error must not replace the alias's refusal:\n{}",
                    text,
                    m
                );
            }
            other => panic!(
                "{text:?}: `uses` must be marked unreadable, got {:?}",
                other
            ),
        }
    }

    let mut text = five_level_chain();
    text.push_str("m: &m {k: *e}\n");
    text.push_str(&format!(
        "g: [{}]\n",
        std::iter::repeat("{<<: *m}")
            .take(7)
            .collect::<Vec<_>>()
            .join(", ")
    ));
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text)
        .expect("a refused node is marked, not a refusal of the document");
    let MarkedValue::List(items, _) = entry(&value, "g") else {
        panic!("g is a sequence");
    };
    let merged = items
        .iter()
        .filter(|item| matches!(item, MarkedValue::Map(..)))
        .count();
    let refused = items
        .iter()
        .filter(|item| {
            matches!(
                item,
                MarkedValue::Refused(m, _)
                    if m.contains("through aliases") && m.contains("`*m`") && !m.contains("must be given a mapping")
            )
        })
        .count();
    assert_eq!(
        (6, 1),
        (merged, refused),
        "six merges of `m` fit the budget and the one after them is refused naming it: {:?}",
        items
            .iter()
            .map(|item| match item {
                MarkedValue::Refused(m, _) => m.as_str(),
                MarkedValue::Map(..) => "a mapping",
                _ => "something else",
            })
            .collect::<Vec<_>>()
    );
}

/// A copy placed deeper than the anchored node was written cannot pass `MAX_NESTING_DEPTH` either.
///
/// `enter_container` bounds the depth where a container is written. An alias copies a node that was
/// bounded there into another position, so a node 100 containers deep aliased under 29 open containers
/// would be a 129-level value, the one shape the bound exists to keep from being built. The depth of
/// the copy is added to the depth it lands at and held under the same bound, which is also where the
/// same sequence written inline at that position would be refused; the alias one container shallower
/// loads.
#[test]
fn a_spec_loader_refuses_an_alias_that_would_nest_past_the_depth_limit() {
    // `deep` is 100 nested sequences. Under the top-level mapping and `k` nested mappings the copy's
    // deepest container is at level k + 101, so k = 27 fits exactly (128) and k = 28 does not.
    let deep = format!("deep: &deep {}x{}\n", "[".repeat(100), "]".repeat(100));
    let nested_alias = |mappings: usize| {
        let mut text = deep.clone();
        for level in 0..mappings {
            text.push_str(&format!("{}m{level}:\n", "  ".repeat(level)));
        }
        text.push_str(&format!("{}leaf: *deep\n", "  ".repeat(mappings)));
        text
    };

    let mut loader = Loader::new();
    assert!(
        loader.load(nested_alias(27)).is_ok(),
        "a copy whose deepest container lands at level 128 is accepted"
    );

    let mut loader = Loader::new();
    let value = loader.load(nested_alias(28));
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m)) if m.contains("nested at most") && m.contains("`*deep`")
        ),
        "a copy that would land at level 129 gave {:?}, not the depth refusal",
        value
    );

    // The depth bound is a property of the document, not of one node: a `MarkedValue` nested past it
    // is the thing the bound exists to keep from ever being built, whichever node asked for it. So
    // the spec loader, which otherwise marks a refused alias and reads on, refuses the document here
    // as the inline nesting refuses it, and the `test` command refuses the whole file.
    let mut loader = Loader::for_spec_file();
    let value = loader.load(nested_alias(28));
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m)) if m.contains("nested at most") && m.contains("`*deep`")
        ),
        "under the spec loader a copy that would land at level 129 gave {:?}, not the depth refusal \
         of the document",
        value.as_ref().map(|_| "a loaded document")
    );
}

/// The bytes a copy holds are counted against `MAX_ALIAS_EXPANSION_BYTES`, so a long scalar cannot be
/// copied without limit by staying inside the node budget.
///
/// A scalar is one node whatever its length. A 64 KiB string anchored once and aliased a million
/// times is a million nodes, inside the node budget, and 64 GiB of copies. Each alias is one copy and
/// recording the anchor is none, so with a 64 MiB byte budget the 1,024th alias of a 64 KiB scalar
/// fills the budget exactly and loads; the 1,025th alias is refused, naming the byte budget and the
/// alias. The same document one alias shorter loads, which pins that the budget is where the constant
/// says and not lower.
#[test]
fn a_spec_loader_refuses_alias_expansion_past_the_byte_budget() {
    let scalar = "x".repeat(64 * 1024);
    let document = |aliases: usize| {
        format!(
            "s: &s {scalar}\nt: [{}]\n",
            std::iter::repeat("*s")
                .take(aliases)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };

    let mut loader = Loader::new();
    assert!(
        loader.load(document(1024)).is_ok(),
        "1,024 copies of 64 KiB are exactly the byte budget and load"
    );

    let mut loader = Loader::new();
    let value = loader.load(document(1025));
    // The error only: a loaded value here is 64 MiB of text, which no failure message should carry.
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m))
                if m.contains("bytes") && m.contains("`*s`") && m.contains("67108864")
        ),
        "the 1,025th alias gave {:?}, not a refusal naming the byte budget and the alias",
        value.as_ref().err()
    );
}

/// An anchor nothing aliases is not a copy and is not charged to the budget; its first alias is.
///
/// The budget counts the copies aliases make. Recording an anchor clones the node into the anchor
/// table, and nested anchors clone each subtree once per enclosing anchor, so charging the clones made
/// a template with no alias at all refusable: a hundred anchored sequences around ten thousand scalars
/// were a hundred clones of ten thousand nodes, over the million-node budget, in a document of ten
/// thousand nodes. The same template loads with every anchor recorded, one alias of its outermost
/// anchor charges that one copy of 10,100 nodes and loads, and a hundred aliases of it charge a
/// hundred copies and are refused naming the alias and the budget: the clones are memory the loader
/// holds while it reads, not nodes the document gains.
#[test]
fn an_anchor_nothing_aliases_is_not_charged_to_the_budget() {
    let scalars = std::iter::repeat("x")
        .take(10_000)
        .collect::<Vec<_>>()
        .join(", ");
    let anchored = |aliases: usize| {
        let open: String = (1..=100).map(|n| format!("&a{n} [")).collect();
        let aliases = std::iter::repeat("*a1")
            .take(aliases)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "deep: {open}{scalars}{}\nuses: [{aliases}]\n",
            "]".repeat(100)
        )
    };

    let mut loader = Loader::new();
    assert!(
        loader.load(anchored(0)).is_ok(),
        "a hundred nested anchors around ten thousand scalars load with no alias: the clones are not \
         charged"
    );

    let mut loader = Loader::new();
    assert!(
        loader.load(anchored(1)).is_ok(),
        "one alias of the outermost anchor is one copy of 10,100 nodes, inside the budget"
    );

    let mut loader = Loader::new();
    let value = loader.load(anchored(100));
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m))
                if m.contains("through aliases") && m.contains("`*a1`") && m.contains("1000000")
        ),
        "a hundred aliases of the 10,100-node anchor gave {:?}, not a refusal naming the alias and \
         the budget",
        value.as_ref().err()
    );
}

/// What the anchor table holds is bounded at the budget plus the input's length, over the whole
/// document, so nested anchors cannot make a small file cost gigabytes while it is read.
///
/// Recording an anchor is not charged to the alias budget, and nested anchors hold their content once
/// per enclosing anchor, so a document of a hundred nested anchors around a sequence of sixty-four
/// aliases of a 64 KiB scalar (4 MiB of copies, charged once) would have held a hundred copies of the
/// 4 MiB, 400 MiB, from a 65 KiB file; a thousand aliases in place of the sixty-four is the 6.4 GiB
/// shape. The anchors are named from the inside out, so the seventeenth recorded is `&t17`: sixteen
/// hold 64 MiB plus the scalar itself, inside 64 MiB plus the file's bytes, and the seventeenth would
/// take the table to 68 MiB and is refused by name. The same document ten anchors deep loads, and what
/// the table held at the refusal is inside the bound.
#[test]
fn an_anchor_table_past_the_budget_plus_the_input_is_refused_at_the_anchor() {
    let scalar = "x".repeat(64 * 1024);
    let aliases = std::iter::repeat("*s")
        .take(64)
        .collect::<Vec<_>>()
        .join(", ");
    let document = |levels: usize| {
        let open: String = (1..=levels).rev().map(|n| format!("&t{n} [")).collect();
        format!("s: &s {scalar}\nt: {open}{aliases}{}\n", "]".repeat(levels))
    };
    let input_bytes = document(100).len();
    let byte_bound = MAX_ALIAS_EXPANSION_BYTES + input_bytes;

    let mut loader = Loader::new();
    assert!(
        loader.load(document(10)).is_ok(),
        "ten nested anchors around 4 MiB of copies hold 40 MiB, inside the bound"
    );

    let mut loader = Loader::new();
    let value = loader.load(document(100));
    // The error only: a loaded value here is 4 MiB of text, which no failure message should carry.
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m))
                if m.contains("anchored") && m.contains("`&t17`") && m.contains(&byte_bound.to_string())
        ),
        "the seventeenth nested anchor gave {:?}, not a refusal naming the anchor and the bound",
        value.as_ref().err()
    );
    assert!(
        loader.anchored_bytes() <= byte_bound,
        "the table held {} bytes at the refusal, past the bound of {}",
        loader.anchored_bytes(),
        byte_bound
    );
}

/// A data file is parsed once, a spec file once when nothing in it is aliased and twice when something
/// is: the count behind the whole-document ceiling is a second parse, and it runs only where the
/// ceiling can bind.
///
/// Under one budget for the document the ceiling, `max(events x 1,000, the budget)`, is never below
/// the budget, so a copy the budget accepts the ceiling accepts too and the count would decide nothing;
/// a data file, which may be a large template, is read once. Under the per-case budget the count is
/// taken at the first copy charged, so a spec file with no alias is read once as well.
#[test]
fn a_data_file_is_parsed_once_and_a_spec_file_at_most_twice() {
    let aliasing =
        "- name: a\n  input: &i {A: 1}\n  expectations: {rules: {r: PASS}}\n- name: b\n  \
                    input: *i\n  expectations: {rules: {r: PASS}}\n";
    let plain = "- name: a\n  input: {A: 1}\n  expectations: {rules: {r: PASS}}\n";

    let mut loader = Loader::new();
    loader.load(String::from(aliasing)).expect("loads");
    assert_eq!(1, loader.parses, "a data file with aliases is parsed once");

    let mut loader = Loader::for_spec_file();
    loader.load(String::from(plain)).expect("loads");
    assert_eq!(1, loader.parses, "a spec file with no alias is parsed once");

    let mut loader = Loader::for_spec_file();
    loader.load(String::from(aliasing)).expect("loads");
    assert_eq!(
        2, loader.parses,
        "a spec file with an alias is parsed twice: once to count its events for the ceiling"
    );
}

/// Under `RefusalPolicy::MarkBadValue`, a mapping the loader will not model becomes a `Refused` node
/// carrying the refusal, where under `RefuseDocument` the same text refuses the document.
///
/// The three mapping shapes are a null key, a sequence key and a merge key given a scalar. Each sits
/// inside one entry of a two-entry document, and the other entry loads untouched, which is what lets
/// a `test` spec lose one case rather than the file. The node carries the mapping's position and the
/// refusal's text, so the conversion that fails on it names both.
#[rstest::rstest]
#[case::a_null_key("bad:\n  null: 1\n", "where the key is null")]
#[case::a_sequence_key("bad:\n  ? [a, b]\n  : 1\n", "where the key is a sequence")]
#[case::a_merge_key_given_a_scalar("bad:\n  <<: not a mapping\n", "must be given a mapping")]
fn a_spec_loader_marks_a_mapping_it_refuses_as_refused(#[case] shape: &str, #[case] refusal: &str) {
    let document = format!("good:\n  A: 1\n{shape}");

    // The data-file loader refuses the document, with the variant each refusal has always had: the
    // key refusals are `InvalidKeyType`, which `validate` and the FFI tell apart from the rest.
    let mut loader = Loader::new();
    let refused = loader.load(document.clone());
    match &refused {
        Err(Error::InternalError(InvalidKeyType(m))) | Err(Error::UnsupportedDocument(m)) => {
            assert!(m.contains(refusal), "the refusal names the shape: {}", m);
        }
        other => panic!(
            "the data-file loader refuses the document with its own variant, got {:?}",
            other
        ),
    }

    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(document)
        .expect("the spec loader reads the document around the refused mapping");
    let top = match &value {
        MarkedValue::Map(map, _) => map,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let entry = |name: &str| {
        top.iter()
            .find(|((key, _), _)| key == name)
            .map(|(_, value)| value)
            .unwrap_or_else(|| panic!("{} is present", name))
    };
    assert!(
        matches!(entry("good"), MarkedValue::Map(..)),
        "the entry beside the refused one is loaded: {:?}",
        entry("good")
    );
    match entry("bad") {
        MarkedValue::Refused(message, location) => {
            assert!(
                message.contains(refusal),
                "the refused node carries the refusal: {}",
                message
            );
            assert_eq!(
                &Location::new(4, 3),
                location,
                "the refused node sits where the refused mapping starts"
            );
        }
        other => panic!(
            "the refused mapping should be marked refused, got {:?}",
            other
        ),
    }
}

/// Under `RefusalPolicy::MarkBadValue`, an alias the loader cannot resolve becomes a `Refused` node
/// in the alias's place: a name no earlier node anchors, and a copy that would cross the budget.
///
/// A refused copy is not charged, so every alias after the one that crossed the budget is refused the
/// same way instead of the budget being spent on refusals; the two `*big` aliases past the limit are
/// both marked refused and the scalar beside them is untouched.
#[test]
fn a_spec_loader_marks_an_alias_it_refuses_as_refused() {
    let forward = "a: *later\nb: &later 1\n";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(String::from(forward))
        .expect("the spec loader reads around a forward alias");
    match &value {
        MarkedValue::Map(map, _) => match &map[0] {
            MarkedValue::Refused(message, location) => {
                assert!(message.contains("`*later`") && message.contains("declares"));
                assert_eq!(&Location::new(1, 4), location, "at the alias");
            }
            other => panic!(
                "the forward alias should be marked refused, got {:?}",
                other
            ),
        },
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    }

    // 1,024 copies of 64 KiB fill the byte budget; the 1,025th and 1,026th are refused.
    let scalar = "x".repeat(64 * 1024);
    let budget = format!(
        "big: &big {scalar}\nt: [{}, *big, *big, ok]\n",
        std::iter::repeat("*big")
            .take(1024)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(budget)
        .expect("the spec loader reads around a refused copy");
    let items = match &value {
        MarkedValue::Map(map, _) => match &map[1] {
            MarkedValue::List(items, _) => items,
            other => unreachable!("t is a sequence, got {:?}", other),
        },
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    assert_eq!(1027, items.len(), "every alias has a node, refused or not");
    assert!(
        matches!(&items[1023], MarkedValue::String(text, _) if text.len() == 64 * 1024),
        "the last copy inside the budget is the scalar"
    );
    for refused in [&items[1024], &items[1025]] {
        assert!(
            matches!(refused, MarkedValue::Refused(m, _) if m.contains("bytes") && m.contains("`*big`")),
            "a copy past the budget is marked refused naming the budget, got {:?}",
            refused.location()
        );
    }
    assert!(
        matches!(&items[1026], MarkedValue::String(text, _) if text == "ok"),
        "the scalar after the refused aliases is untouched"
    );
}

/// A refused alias standing where a mapping key should be refuses the mapping with the alias's own
/// message, as `apply_merges` does for a `<<` whose alias was refused.
///
/// Under `MarkBadValue` the alias is a `Refused` node by the time `fill_mapping` reads the key.
/// Treating it as one more key without text would refuse the mapping as "non string type detected
/// for key in a map at ..., where the key is an unreadable value, ... Quote it to make it a string",
/// with the alias's refusal buried in the middle of advice that does not apply, since quoting
/// `*later` makes a key named `*later`. The refusal the node carries is
/// the one the mapping is refused with, whether the alias names an anchor no earlier node declares
/// or a copy past the budget, and the entry beside the refused mapping loads.
#[test]
fn a_spec_loader_reports_the_alias_refusal_behind_a_mapping_key() {
    let undeclared = "good:\n  A: 1\nbad:\n  *later: 1\n";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(String::from(undeclared))
        .expect("a refused node is marked, not a refusal of the document");
    assert!(
        matches!(entry(&value, "good"), MarkedValue::Map(..)),
        "the entry beside the refused one is loaded: {:?}",
        entry(&value, "good")
    );
    match entry(&value, "bad") {
        MarkedValue::Refused(m, _) => {
            assert!(
                m.contains("`*later`") && m.contains("declares"),
                "the refusal must name the alias:\n{}",
                m
            );
            assert!(
                !m.contains("non string type") && !m.contains("Quote it"),
                "the non-string-key refusal must not stand in for the alias's:\n{}",
                m
            );
        }
        other => panic!("`bad` must be marked unreadable, got {:?}", other),
    }

    // The budget half: 1,024 copies of a 64 KiB scalar fill the byte budget, so the alias used as
    // a key after them is refused by it, and the mapping holding that key reports the budget.
    let scalar = "x".repeat(64 * 1024);
    let budget = format!(
        "big: &big {scalar}\nt: [{}]\nu:\n  *big: 1\n",
        std::iter::repeat("*big")
            .take(1024)
            .collect::<Vec<_>>()
            .join(", ")
    );
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(budget)
        .expect("a refused node is marked, not a refusal of the document");
    match entry(&value, "u") {
        MarkedValue::Refused(m, _) => {
            assert!(
                m.contains("bytes") && m.contains("`*big`"),
                "the refusal must name the byte budget and the alias:\n{}",
                m
            );
            assert!(
                !m.contains("non string type") && !m.contains("Quote it"),
                "the non-string-key refusal must not stand in for the budget's:\n{}",
                m
            );
        }
        other => panic!("`u` must be marked unreadable, got {:?}", other.location()),
    }
}

/// The expansion budget is spent per item of a document whose root is a sequence, so a value
/// anchored in one `test` case and aliased by every other case costs each case one copy.
///
/// Counted over the whole document, a 10,000-node value anchored once and aliased a hundred times
/// was 1,010,000 nodes: the hundredth alias crossed the node budget, and which case failed moved
/// with the order of the cases. Each item of the root sequence starts with the budget whole, while
/// the anchor table and the nesting bound stay per document, so every alias finds its anchor. The
/// chain inside one item is still stopped there: the second document puts the six-level
/// billion-laughs chain in one item, where the eighth alias of `e` and every alias after it is
/// refused naming the alias and the budget, and the item after it aliases `e` and loads a copy
/// that the spent budget would have refused. A root mapping keeps the budget for the document,
/// which [`a_spec_loader_refuses_alias_expansion_past_the_budget`] pins.
///
/// The second document starts with an item of 1,100 scalars, so that the ceiling over the whole
/// document, a thousand nodes for each of its events other than aliases, stands above one item's
/// budget and the per-item reset is what the third item measures. A document of a few hundred events
/// has the ceiling at one item's budget, and the third item's copy would be refused by it;
/// [`a_spec_loader_holds_the_whole_document_under_a_ceiling_that_no_item_resets`] pins that.
#[test]
fn a_spec_loader_charges_the_expansion_budget_per_item_of_a_root_sequence() {
    let mut shared = format!(
        "- &t [{}]\n",
        std::iter::repeat("x")
            .take(9_999)
            .collect::<Vec<_>>()
            .join(", ")
    );
    for _ in 0..100 {
        shared.push_str("- *t\n");
    }
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(shared)
        .expect("a refused alias is one node of the document, not a refusal of it");
    let MarkedValue::List(items, _) = &value else {
        panic!("a sequence loads as a list, got {:?}", value.location());
    };
    let copies = items
        .iter()
        .filter(|item| matches!(item, MarkedValue::List(xs, _) if xs.len() == 9_999))
        .count();
    let first_refusal = items.iter().find_map(|item| match item {
        MarkedValue::Refused(m, _) => Some(m.as_str()),
        _ => None,
    });
    assert_eq!(
        (101, 101, None),
        (items.len(), copies, first_refusal),
        "the anchored item and every one of its hundred aliases is a 10,000-node copy"
    );

    let level = |name: char, previous: char| {
        format!(
            "  {name}: &{name} [{}]\n",
            std::iter::repeat(format!("*{previous}"))
                .take(10)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut chain = format!(
        "- [{}]\n- a: &a [x, x, x, x, x, x, x, x, x, x]\n",
        std::iter::repeat("x")
            .take(1_100)
            .collect::<Vec<_>>()
            .join(", ")
    );
    for (name, previous) in [('b', 'a'), ('c', 'b'), ('d', 'c'), ('e', 'd'), ('f', 'e')] {
        chain.push_str(&level(name, previous));
    }
    chain.push_str("- *e\n");
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(chain)
        .expect("a refused alias is one node of the document, not a refusal of it");
    let MarkedValue::List(items, _) = &value else {
        panic!("a sequence loads as a list, got {:?}", value.location());
    };
    assert_eq!(3, items.len(), "three items");
    let MarkedValue::List(sixth_level, _) = entry(&items[1], "f") else {
        panic!(
            "f is a sequence, got {:?}",
            entry(&items[1], "f").location()
        );
    };
    let copied = sixth_level
        .iter()
        .filter(|item| matches!(item, MarkedValue::List(..)))
        .count();
    let refused = sixth_level
        .iter()
        .filter(|item| {
            matches!(
                item,
                MarkedValue::Refused(m, _)
                    if m.contains("through aliases") && m.contains("`*e`") && m.contains("1000000")
            )
        })
        .count();
    assert_eq!(
        (7, 3),
        (copied, refused),
        "the chain inside one item is refused there: seven aliases of `e` fit and three are refused"
    );
    assert!(
        matches!(&items[2], MarkedValue::List(xs, _) if xs.len() == 10),
        "the item after the chain starts with the budget whole and its alias of `e` is a copy, got {:?}",
        match &items[2] {
            MarkedValue::Refused(m, _) => m.as_str(),
            _ => "something that is not a ten-item sequence",
        }
    );
}

/// The six-level billion-laughs chain, `a` to `f`, as the items of a root sequence: one item holding
/// the whole chain under `- `, for the spec loader, or the same mapping at the root for the data-file
/// loader.
fn chain_item(indent: &str) -> String {
    let level = |name: char, previous: char| {
        format!(
            "{indent}{name}: &{name} [{}]\n",
            std::iter::repeat(format!("*{previous}"))
                .take(10)
                .collect::<Vec<_>>()
                .join(", ")
        )
    };
    let mut text = format!("{indent}a: &a [x, x, x, x, x, x, x, x, x, x]\n");
    for (name, previous) in [('b', 'a'), ('c', 'b'), ('d', 'c'), ('e', 'd'), ('f', 'e')] {
        text.push_str(&level(name, previous));
    }
    text
}

/// The budget refusal says what the budget is spent over: one test case, an item of the root
/// sequence, under the spec loader, and one document under the data-file loader.
///
/// Saying "in one document" on both would be wrong for a spec file: a case that spent its own budget
/// would be told the document had, sending the author looking for aliases in the other cases. The
/// scope is the loader's to name, since the spec loader is the one that resets the
/// count at each item of the root sequence.
#[test]
fn the_budget_refusal_names_the_scope_the_budget_is_spent_over() {
    let spec = format!("- {}", chain_item("  ").trim_start());
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(spec)
        .expect("a refused alias is one node of the document, not a refusal of it");
    let MarkedValue::List(items, _) = &value else {
        panic!("a sequence loads as a list, got {:?}", value.location());
    };
    let MarkedValue::List(sixth_level, _) = entry(&items[0], "f") else {
        panic!("f is a sequence");
    };
    let refusal = sixth_level
        .iter()
        .find_map(|item| match item {
            MarkedValue::Refused(m, _) => Some(m.as_str()),
            _ => None,
        })
        .expect("the eighth alias of `e` is refused");
    assert!(
        refusal.contains("in one test case (one item of the root sequence)")
            && !refusal.contains("in one document"),
        "under the spec loader the refusal names the case:\n{}",
        refusal
    );

    let mut loader = Loader::new();
    let value = loader.load(chain_item(""));
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m))
                if m.contains("through aliases") && m.contains("in one document") && !m.contains("test case")
        ),
        "under the data-file loader the refusal names the document, got {:?}",
        value.as_ref().err()
    );
}

/// The data-file loader spends one budget over the whole document whatever its root is: only the spec
/// loader resets the count at each item of a root sequence.
///
/// The reset was decided on the document's shape alone, so a data file whose root is a sequence --
/// a JSON array handed to `validate` or to the library entry point -- got a budget per item, and a
/// document of N items could copy N times the budget. The reset is the spec loader's, chosen in its
/// constructor; here the chain in the first item and the nine aliases of `e` in the second cross
/// the one budget together, at the second item's eighth alias.
#[test]
fn a_data_loader_spends_one_budget_over_a_document_whose_root_is_a_sequence() {
    let mut text = chain_item("  ").replacen("  a:", "- a:", 1);
    // Without `f`, so that the first item alone is inside the budget: 123,440 nodes.
    let f = text
        .lines()
        .last()
        .expect("the chain has a last line")
        .to_string();
    text = text.replace(&format!("{f}\n"), "");
    for _ in 0..2 {
        text.push_str("- [*e, *e, *e, *e, *e, *e, *e, *e, *e]\n");
    }

    let mut loader = Loader::new();
    let value = loader.load(text);
    assert!(
        matches!(
            &value,
            Err(Error::UnsupportedDocument(m))
                if m.contains("through aliases") && m.contains("`*e`") && m.contains("in one document")
        ),
        "the second item's aliases are charged to the same budget as the first item's chain, got {:?}",
        value.as_ref().err()
    );
}

/// A ceiling over the whole document that no item resets: however many cases a spec file has, what
/// it copies through aliases in all is bounded.
///
/// The per-case budget made the number of cases the multiplier: a chain anchored in one case and
/// nine aliases of its fifth level in each of N more cases copied N million nodes from a few hundred
/// bytes per case, and each case was inside its own budget. The ceiling is proportional to the
/// document's own size as libyaml saw it, a thousand nodes for each of its events other than aliases,
/// counted over the whole file before anything is copied, and never below the per-case figure, so a
/// document of a few hundred such events cannot copy more than one case's budget in total, however it
/// is laid out or ordered. Here the chain charges 123,440 nodes, the first flood item fits seven more
/// copies of `e` (901,217) and its eighth alias would reach 1,012,328; every alias after that, in
/// that item and in every later one, is refused naming the ceiling, and nothing is copied for it.
#[test]
fn a_spec_loader_holds_the_whole_document_under_a_ceiling_that_no_item_resets() {
    let mut text = chain_item("  ").replacen("  a:", "- a:", 1);
    let f = text
        .lines()
        .last()
        .expect("the chain has a last line")
        .to_string();
    text = text.replace(&format!("{f}\n"), "");
    for _ in 0..12 {
        text.push_str("- [*e, *e, *e, *e, *e, *e, *e, *e, *e]\n");
    }

    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text)
        .expect("a refused alias is one node of the document, not a refusal of it");
    let MarkedValue::List(items, _) = &value else {
        panic!("a sequence loads as a list, got {:?}", value.location());
    };
    assert_eq!(13, items.len(), "the chain and twelve flood items");

    let shape = |item: &MarkedValue| -> (usize, usize) {
        let MarkedValue::List(aliases, _) = item else {
            panic!("a flood item is a sequence, got {:?}", item.location());
        };
        let copies = aliases
            .iter()
            .filter(|alias| matches!(alias, MarkedValue::List(..)))
            .count();
        let refused = aliases
            .iter()
            .filter(|alias| {
                matches!(
                    alias,
                    MarkedValue::Refused(m, _)
                        if m.contains("across the whole document") && m.contains("`*e`")
                )
            })
            .count();
        (copies, refused)
    };
    assert_eq!(
        (7, 2),
        shape(&items[1]),
        "the first flood item fits seven copies and its last two aliases are refused at the ceiling"
    );
    for (index, item) in items.iter().enumerate().skip(2) {
        assert_eq!(
            (0, 9),
            shape(item),
            "flood item {index} copies nothing: every alias is refused at the ceiling"
        );
    }
}

/// How many `Refused` nodes a loaded document holds, anywhere in it.
fn refused_nodes(value: &MarkedValue) -> usize {
    match value {
        MarkedValue::Refused(..) => 1,
        MarkedValue::List(items, _) => items.iter().map(refused_nodes).sum(),
        MarkedValue::Map(entries, _) => entries.values().map(refused_nodes).sum(),
        _ => 0,
    }
}

/// The ceiling is the same for every alias in a file, wherever the alias sits: a file loads or is
/// refused the same way whatever order its cases come in.
///
/// Counted as the document was read, the ceiling was lower near the top of a file than near the
/// bottom. Twenty cases aliasing a 100,000-node input that is itself written with aliases, about two
/// million copied nodes, followed by a thousand plain cases were refused from the eleventh aliasing
/// case on, because the ceiling stood at about 1.1 million when they were read; with the plain cases
/// first the same file loaded under a ceiling of about eight million. That is the order dependence
/// the per-case budget was introduced to remove. The events are counted over the whole file before
/// anything is copied now, so both orders load, and the count is the same for both.
#[rstest::rstest]
#[case::aliasing_cases_first(true)]
#[case::plain_cases_first(false)]
fn the_ceiling_does_not_depend_on_the_order_of_the_cases(#[case] aliasing_first: bool) {
    let row = std::iter::repeat("x")
        .take(100)
        .collect::<Vec<_>>()
        .join(", ");
    let more = std::iter::repeat("*row")
        .take(990)
        .collect::<Vec<_>>()
        .join(", ");
    let mut aliasing = format!(
        "- name: a0\n  input: &big\n    Pad: &row [{row}]\n    More: [{more}]\n  expectations: \
         {{rules: {{r: PASS}}}}\n"
    );
    for i in 1..20 {
        aliasing.push_str(&format!(
            "- {{name: a{i}, input: *big, expectations: {{rules: {{r: PASS}}}}}}\n"
        ));
    }
    let mut plain = String::new();
    for i in 0..1000 {
        plain.push_str(&format!(
            "- {{name: p{i}, input: {{A: 1}}, expectations: {{rules: {{r: PASS}}}}}}\n"
        ));
    }
    let text = if aliasing_first {
        format!("{aliasing}{plain}")
    } else {
        format!("{plain}{aliasing}")
    };

    let mut loader = Loader::for_spec_file();
    let value = loader.load(text).expect("the file loads");
    let MarkedValue::List(items, _) = &value else {
        panic!("a sequence loads as a list, got {:?}", value.location());
    };
    assert_eq!(1020, items.len());
    assert_eq!(
        0,
        refused_nodes(&value),
        "every alias is a copy in either order; the ceiling is fixed for the file before any copy"
    );
}

/// An alias does not count towards its own ceiling.
///
/// Every event of the document counted, aliases included, so each alias of an anchor of a thousand
/// nodes or fewer raised the ceiling by as much as it copied and the ceiling never stopped it: two
/// cases each aliasing a 1,000-node anchor 999 times, 1,998,000 copies from a file of about forty
/// events other than the aliases, both loaded. Only what the text spells out counts now: this file
/// is 1,061 such events (the 999 scalars of the anchor are most of them), so its ceiling is
/// 1,061,000 nodes, the first aliasing case fits inside it and the second is refused at it.
#[test]
fn an_alias_does_not_raise_the_ceiling_it_is_held_to() {
    let big = std::iter::repeat("x")
        .take(999)
        .collect::<Vec<_>>()
        .join(", ");
    let aliases = std::iter::repeat("*big")
        .take(999)
        .collect::<Vec<_>>()
        .join(", ");
    let text = format!(
        "- name: c0\n  input: {{A: 1, big: &big [{big}]}}\n  expectations: {{rules: {{r: PASS}}}}\n\
         - {{name: c1, input: {{A: 1, B: [{aliases}]}}, expectations: {{rules: {{r: PASS}}}}}}\n\
         - {{name: c2, input: {{A: 1, B: [{aliases}]}}, expectations: {{rules: {{r: PASS}}}}}}\n"
    );

    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text)
        .expect("a refused alias is one node of the document");
    let MarkedValue::List(items, _) = &value else {
        panic!("a sequence loads as a list, got {:?}", value.location());
    };
    assert_eq!(3, items.len());
    assert_eq!(
        0,
        refused_nodes(&items[1]),
        "the first aliasing case is inside its budget and under the ceiling"
    );
    let refused = refused_nodes(&items[2]);
    assert!(
        refused > 0 && refused <= 999,
        "the second aliasing case is refused at the ceiling, got {} refused aliases",
        refused
    );
    let MarkedValue::Map(fields, _) = &items[2] else {
        panic!("a case is a mapping");
    };
    let input = fields
        .iter()
        .find(|((key, _), _)| key == "input")
        .map(|(_, value)| value)
        .expect("the case has an input");
    let MarkedValue::Map(input_fields, _) = input else {
        panic!("the input is a mapping");
    };
    let b = input_fields
        .iter()
        .find(|((key, _), _)| key == "B")
        .map(|(_, value)| value)
        .expect("the input has B");
    let MarkedValue::List(copies, _) = b else {
        panic!("B is a sequence");
    };
    let message = copies
        .iter()
        .find_map(|copy| match copy {
            MarkedValue::Refused(message, _) => Some(message.clone()),
            _ => None,
        })
        .expect("a refused alias carries the ceiling's message");
    assert!(
        message.contains("across the whole document") && message.contains("other than aliases"),
        "the refusal names the ceiling and says that aliases do not count: {}",
        message
    );
}

/// A `!!int`, `!!float` or `!!bool` whose payload is not one is a refused key and a refused merge
/// source for the reasons those shapes always had, under both loaders.
///
/// The spec loader marks a node it refuses, and the refusal's message is forwarded when such a node
/// stands where a key or a merge source should be, because it is the message that says what to fix.
/// A tagged scalar that could not be read is marked too, but its mark carries the scalar's own text,
/// and forwarding that reported "in data file t.yaml: abc", with no position and no word about the
/// merge key, where the same text under a plain `<<` says the merge key must be given a mapping,
/// and `!!int abc` as a key lost the key refusal's position and its advice. Only the loader's own
/// refusals are forwarded; a tag payload keeps the key and merge refusals.
#[rstest::rstest]
#[case::as_a_merge_source(
    "bad: {<<: !!int abc, B: 2}\n",
    "the merge key `<<` at L:3,C:11 must be given a mapping"
)]
#[case::as_a_key(
    "bad: {!!int abc: 1}\n",
    "L:3,C:7, where the key is an unreadable value, !!int abc. Quote it to make it a string"
)]
fn a_tagged_scalar_that_is_not_its_type_keeps_the_key_and_merge_refusals(
    #[case] shape: &str,
    #[case] refusal: &str,
) {
    let document = format!("good:\n  A: 1\n{shape}");

    let mut loader = Loader::new();
    let refused = loader.load(document.clone());
    match &refused {
        Err(Error::InternalError(InvalidKeyType(m))) | Err(Error::UnsupportedDocument(m)) => {
            assert!(
                m.contains(refusal),
                "the data-file loader refuses the document with the key or merge refusal:\n{}",
                m
            );
        }
        other => panic!("the data-file loader refuses the document, got {:?}", other),
    }

    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(document)
        .expect("the spec loader reads the document around the refused mapping");
    assert!(
        matches!(entry(&value, "good"), MarkedValue::Map(..)),
        "the entry beside the refused one is loaded"
    );
    match entry(&value, "bad") {
        MarkedValue::Refused(m, _) => assert!(
            m.contains(refusal),
            "the spec loader marks the mapping with the key or merge refusal:\n{}",
            m
        ),
        other => panic!("`bad` must be marked unreadable, got {:?}", other),
    }
}

/// A tagged leading-zero integer as a key is refused with its reason and the advice for a key.
///
/// `describe_key` gives the node as written and the reason's `why`; the advice that follows is the
/// reason's own, "Write ...; the tag can then be dropped", in place of "Quote it to make it a
/// string". Quoting does not fix this key: `!!int "0755"` is refused the same way (the quoted row of
/// the tagged integer test pins that), and quoting the whole key gives the text "0755" or
/// "!!int 0755", which is neither YAML 1.1's "493" nor YAML 1.2's "755". Nor does dropping the tag
/// on its own: an untagged `0755` is kept as the string "0755" (`a_leading_zero_stays_text`), the
/// same key quoting would give, so the integer is written first and the tag goes after. The whole
/// message is asserted, not a fragment,
/// so the three parts stay in this order with this punctuation: as `InvalidKeyType`'s payload from
/// the data-file loader, and as the displayed error, wrapper included, that the spec loader marks the
/// mapping with.
#[test]
fn a_tagged_leading_zero_integer_as_a_key_is_refused_with_its_reason_and_the_key_advice() {
    let document = String::from("good:\n  A: 1\nbad: {!!int 0755: 1}\n");
    let refusal =
        "L:3,C:7, where the key is an unreadable value, !!int 0755: a leading zero reads \
                   as octal in YAML 1.1 and as decimal in YAML 1.2. Write \"493\" if octal 755 was \
                   meant, or \"755\" if decimal was meant; the tag can then be dropped";

    // The data-file loader refuses the document with the refusal as `InvalidKeyType`'s payload;
    // the error's own sentence wraps it when the error is displayed.
    let mut loader = Loader::new();
    match loader.load(document.clone()) {
        Err(Error::InternalError(InvalidKeyType(m))) => assert_eq!(refusal, m),
        other => panic!("the data-file loader refuses the key, got {:?}", other),
    }

    // The spec loader marks the mapping with the displayed error, wrapper included, since that is
    // the text a test case's author reads.
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(document)
        .expect("the spec loader reads the document around the refused mapping");
    let displayed = format!(
        "non string type detected for key in a map at {refusal}, cfn-guard only supports keys \
         that are string types"
    );
    match entry(&value, "bad") {
        MarkedValue::Refused(m, _) => assert_eq!(&displayed, m),
        other => panic!("`bad` must be marked unreadable, got {:?}", other),
    }
}

/// A tagged leading-zero integer key with a reading too wide for an `i64` gets advice that holds
/// together: the spelling that fits, then the tag, or the note alone where nothing fits.
///
/// The key advice is built from the same parts as the value's: a spelling sentence where at least
/// one reading fits, with the integer quoted since a key is text, then "the tag can then be
/// dropped" right after the spelling, then the note on the reading that does not fit. Twenty sevens
/// read as octal fit an `i64` while their decimal reading does not; a 1 with twenty-one zeros is too
/// wide under both readings; twenty nines have only a decimal reading, which is too wide. Each is
/// pinned as a key, whole message, under the data-file loader.
#[rstest::rstest]
#[case::octal_fits_decimal_does_not(
    "077777777777777777777",
    "Write \"1152921504606846975\" if octal 77777777777777777777 was meant; the tag can then be dropped; the decimal reading is too wide for a 64-bit integer"
)]
#[case::both_too_wide(
    "01000000000000000000000",
    "Both readings are too wide for a 64-bit integer"
)]
#[case::no_octal_reading_decimal_too_wide(
    "099999999999999999999",
    "The decimal reading is too wide for a 64-bit integer, and YAML 1.1 reads no integer in a leading-zero number with a digit 8 or 9"
)]
fn a_tagged_leading_zero_integer_key_too_wide_for_an_integer_gets_whole_advice(
    #[case] payload: &str,
    #[case] advice: &str,
) {
    let document = format!("m: {{!!int {payload}: 1}}\n");
    let refusal = format!(
        "L:1,C:5, where the key is an unreadable value, !!int {payload}: a leading zero reads as \
         octal in YAML 1.1 and as decimal in YAML 1.2. {advice}"
    );

    let mut loader = Loader::new();
    match loader.load(document) {
        Err(Error::InternalError(InvalidKeyType(m))) => assert_eq!(refusal, m),
        other => panic!("the data-file loader refuses the key, got {:?}", other),
    }
}

/// A tagged leading-zero integer that both YAML versions read as one number is that integer as a
/// key, so `!!int 007: 1` has the key "7", under both loaders.
///
/// The key was refused before, with the whole class of leading-zero payloads: a tagged `007` was a
/// `BadValue` wherever it stood. The narrowing of the refusal to the payloads the two readers
/// disagree on reaches keys too, through `stringify_scalar_key`, which gives an integer key the text
/// CloudFormation's own conversion would. `!!int 0755: 1` is still refused, with the key advice (see
/// the test above).
#[test]
fn a_tagged_leading_zero_integer_key_both_readers_agree_on_is_the_integer_key() {
    let document = String::from("m: {!!int 007: 1}\n");

    for mut loader in [Loader::new(), Loader::for_spec_file()] {
        let value = loader
            .load(document.clone())
            .expect("a key both readers agree on loads");
        match entry(&value, "m") {
            MarkedValue::Map(m, ..) => {
                let keys: Vec<&str> = m.keys().map(|(k, _)| k.as_str()).collect();
                assert_eq!(vec!["7"], keys, "the tagged key is the integer's text");
            }
            other => panic!("`m` must be a mapping, got {:?}", other),
        }
    }
}

/// A tagged leading-zero integer costs the alias-expansion budget what its text costs, as a plain
/// scalar of the same length does.
///
/// The reason beside a `BadValue`'s text is `Copy` data with no heap of its own, so a copy made for an
/// alias carries nothing the budget does not see. Held as sentences it would have carried about 180
/// bytes per copy against the 10 charged for `!!int 0755`, and a document anchoring one such node and
/// aliasing it up to the node budget would have held tens of megabytes of sentences that neither the
/// byte budget nor the anchor table's bound counted.
#[test]
fn a_refused_leading_zero_integer_is_charged_its_text_alone() {
    fn is_copy<T: Copy>() {}
    is_copy::<BadValueReason>();

    // Ten bytes as written on both sides: the tagged node, and a plain scalar that stays text.
    let mut tagged = Loader::new();
    let value = tagged
        .load(String::from("k: &a !!int 0755\n"))
        .expect("a refused tagged scalar is a value of the document");
    let mut plain = Loader::new();
    plain
        .load(String::from("k: &a 0755_abcde\n"))
        .expect("a plain scalar loads");

    let node = entry(&value, "k");
    assert!(
        matches!(node, MarkedValue::BadValue(text, Some(_), _) if text == "!!int 0755"),
        "the anchored node is the refused tagged scalar with its reason, got {:?}",
        node
    );
    assert_eq!(
        "!!int 0755".len(),
        size_of(node).bytes,
        "a refused tagged scalar is charged its text"
    );
    assert_eq!(
        plain.anchored_bytes(),
        tagged.anchored_bytes(),
        "the anchor table charges the tagged node what it charges a plain scalar of the same length"
    );
}

/// A mapping key's bytes are charged once for every node under the key, because that is how many
/// times the converted document carries them.
///
/// `PathAwareValue` stores a full path at every node, so a key of a thousand bytes over a subtree of
/// a hundred nodes is a hundred thousand bytes of path once the document is converted. The byte
/// budget charged each key once per copy, so a hundred nested mappings with one such key each were
/// 100 KB to the budget and about 670 aliases of them fit, which converted to several gigabytes of
/// path strings; the budget's promise, that a document takes at most this many bytes on top of
/// itself, did not hold for a caller that converts the result. Charged per descendant, the same
/// shape is 5,150,000 bytes a copy and thirteen copies fit the 64 MiB budget; recording the anchor is
/// not one of them, so thirteen of twenty aliases load and seven are refused naming the byte budget.
#[test]
fn a_spec_loader_charges_a_keys_bytes_once_per_node_under_it() {
    let key = "k".repeat(1000);
    let mut deep = String::new();
    for level in 0..100 {
        deep.push_str(&format!("{}{key}:\n", "  ".repeat(level + 1)));
    }
    deep.push_str(&format!("{}x\n", "  ".repeat(101)));
    let text = format!(
        "deep: &deep\n{deep}copies: [{}]\n",
        std::iter::repeat("*deep")
            .take(20)
            .collect::<Vec<_>>()
            .join(", ")
    );

    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text)
        .expect("a refused alias is one node of the document, not a refusal of it");
    let MarkedValue::List(copies, _) = entry(&value, "copies") else {
        panic!("copies is a sequence");
    };
    let loaded = copies
        .iter()
        .filter(|copy| matches!(copy, MarkedValue::Map(..)))
        .count();
    let refused = copies
        .iter()
        .filter(|copy| {
            matches!(
                copy,
                MarkedValue::Refused(m, _)
                    if m.contains("bytes") && m.contains("`*deep`") && m.contains("67108864")
            )
        })
        .count();
    assert_eq!(
        (13, 7),
        (loaded, refused),
        "thirteen aliases of the deep chain of long keys fit the byte budget and seven are refused"
    );
}

/// A recording loader keeps the spelling of every integer, float and boolean it resolves, by
/// position, and of nothing else.
///
/// `MarkedValue` has no slot for a spelling, and the `test` command reports a case's `name` as the
/// author wrote it, so `1.50`, `1e3`, `0x1F` and `True` have to be recoverable after the loader has
/// made them `1.5`, `1000.0`, `31` and `true`. A string is its own spelling and a null has none, so
/// neither is recorded; an aliased copy keeps the anchored scalar's position and so shares its entry.
#[test]
fn a_recording_loader_keeps_the_spelling_of_numbers_and_booleans() {
    let document = "a: 1.50\nb: 1e3\nc: 0x1F\nd: True\ne: text\nf: ~\ng: &n 2024\nh: *n\n";

    let mut loader = Loader::for_spec_file();
    loader.load(String::from(document)).expect("loads");
    let mut texts: Vec<(Location, String)> = loader.take_scalar_texts().into_iter().collect();
    texts.sort_by_key(|(location, _)| (location.line, location.col));

    assert_eq!(
        vec![
            (Location::new(1, 4), "1.50".to_string()),
            (Location::new(2, 4), "1e3".to_string()),
            (Location::new(3, 4), "0x1F".to_string()),
            (Location::new(4, 4), "True".to_string()),
            // Column 4 is the `&n`: libyaml starts a node's event at its properties.
            (Location::new(7, 4), "2024".to_string()),
        ],
        texts,
        "numbers and booleans by position; the string, the null and the alias add nothing"
    );

    // The same scalars without the alias, which the data-file loader refuses: it records nothing.
    let mut loader = Loader::new();
    loader
        .load(String::from(
            "a: 1.50\nb: 1e3\nc: 0x1F\nd: True\ne: text\nf: ~\ng: 2024\n",
        ))
        .expect("loads");
    assert!(
        loader.take_scalar_texts().is_empty(),
        "the data-file loader records nothing"
    );
}

#[test]
fn test_handle_null() {
    let docs = r###"
    Resources: NULL
    "###;

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs)).unwrap();

    let map = match &value {
        MarkedValue::Map(m, _) => m,
        _ => unreachable!(),
    };

    let val = map
        .get(&("Resources".to_string(), Location::new(2, 5)))
        .unwrap()
        .to_owned();

    assert!(matches!(val, MarkedValue::Null(_)));

    let docs = r###"
    Resources: ~
    "###;

    let value = loader.load(String::from(docs)).unwrap();

    let map = match &value {
        MarkedValue::Map(m, _) => m,
        _ => unreachable!(),
    };

    let val = map
        .get(&("Resources".to_string(), Location::new(2, 5)))
        .unwrap()
        .to_owned();

    assert!(matches!(val, MarkedValue::Null(_)));

    let docs = r###"
    Resources: "~"
    "###;

    let value = loader.load(String::from(docs)).unwrap();

    let map = match &value {
        MarkedValue::Map(m, _) => m,
        _ => unreachable!(),
    };

    let val = map
        .get(&("Resources".to_string(), Location::new(2, 5)))
        .unwrap()
        .to_owned();

    assert!(matches!(val, MarkedValue::String(..)));

    let docs = r###"
    Resources: "null"
    "###;

    let value = loader.load(String::from(docs)).unwrap();

    let map = match &value {
        MarkedValue::Map(m, _) => m,
        _ => unreachable!(),
    };

    let val = map
        .get(&("Resources".to_string(), Location::new(2, 5)))
        .unwrap()
        .to_owned();

    assert!(matches!(val, MarkedValue::String(..)));
}

/// `f64::from_str` accepts `nan`, `inf` and `infinity`. YAML resolves none of those to a float --
/// it spells the non-finite floats `.nan` and `.inf`, and both of those were already falling
/// through to `String` here, so the two halves of the same question disagreed.
///
/// What the disagreement cost: `Float(NaN)` is not equal to itself, and `PathAwareValue` asserts
/// `Eq` while hashing its own contents. Two identical scalars in one document compared unequal,
/// and the negation of that comparison passed -- a clause asserting two fields *differ* was
/// satisfied by two fields spelled the same way.
#[rstest::rstest]
#[case::bare_nan("nan")]
#[case::capitalized_nan("NaN")]
#[case::uppercase_nan("NAN")]
#[case::yaml_nan(".nan")]
#[case::bare_inf("inf")]
#[case::negative_inf("-inf")]
#[case::spelled_out_infinity("infinity")]
#[case::yaml_inf(".inf")]
#[case::overflowing_exponent("1e999")]
fn a_non_finite_scalar_is_not_a_float(#[case] scalar: &str) -> Result<()> {
    let mut loader = Loader::new();
    let value = loader.load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, _) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    let (.., loaded) = map.first().unwrap();

    assert!(
        matches!(loaded, MarkedValue::String(s, ..) if s == scalar),
        "{} loaded as {:?}, but YAML resolves it to a string",
        scalar,
        loaded
    );

    Ok(())
}

/// The control for the case above: rejecting the non-finite spellings must not cost the finite
/// floats, which is the entire reason the `f64` arm is there.
#[rstest::rstest]
#[case::simple_fraction("1.5", 1.5)]
#[case::negative_fraction("-1.5", -1.5)]
#[case::exponent("1e3", 1000.0)]
#[case::negative_exponent("1e-3", 0.001)]
#[case::largest_finite_f64("1.7976931348623157e308", f64::MAX)]
fn a_finite_scalar_is_still_a_float(#[case] scalar: &str, #[case] expected: f64) -> Result<()> {
    let mut loader = Loader::new();
    let value = loader.load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, _) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    let (.., loaded) = map.first().unwrap();

    assert!(
        matches!(loaded, MarkedValue::Float(f, ..) if *f == expected),
        "{} loaded as {:?}, not the float {}",
        scalar,
        loaded,
        expected
    );

    Ok(())
}

/// A file holding no document at all -- nothing but comments -- aborted the process with this panic,
/// quoted verbatim, so the `event.rs` line number in it is the panic's own and not a reference to the
/// current tree:
///
/// ```text
/// thread 'main' panicked at guard/src/rules/libyaml/event.rs:63:14:
/// not implemented
/// ```
///
/// `load` returns only on `DocumentEnd`, so a stream with no document in it had no exit from the
/// loop. It ran past `StreamEnd`, libyaml answered the next pull with `YAML_NO_EVENT`, and the
/// wildcard arm of `convert_event` met that with `unimplemented!()`. An empty file and a
/// whitespace-only file were both already reported as empty, so the degenerate case was handled
/// and this one was not.
///
/// `catch_unwind` is what makes the absence of the panic explicit. Asserting on the returned
/// `Err` alone would not: an aborting build never returns a value to assert on, so the assertion
/// would be unreachable rather than false, which is how the vacuous `if let` in
/// `test_handle_bool_happy_path` hid a defect for so long.
#[rstest::rstest]
#[case::a_single_comment_line("# just a comment\n")]
#[case::a_comment_with_no_trailing_newline("# just a comment")]
#[case::comments_separated_by_blank_lines("\n# a\n\n#  b\n")]
#[case::a_fully_commented_out_template(
    "# Resources:\n#   B:\n#     Properties:\n#       Encrypted: true\n"
)]
fn a_stream_with_no_document_is_an_error_and_not_a_panic(#[case] content: &str) {
    let owned = content.to_string();
    let outcome = std::panic::catch_unwind(move || Loader::new().load(owned));

    let loaded = match outcome {
        Ok(loaded) => loaded,
        Err(..) => panic!(
            "loading {:?} panicked instead of returning an error",
            content
        ),
    };

    assert!(
        matches!(loaded, Err(Error::MissingDocument)),
        "loading {:?} gave {:?}, not the missing-document error",
        content,
        loaded
    );
}

/// The control for the case above. Comments are not the problem and must still be skipped when
/// there is a document underneath them, so the fix cannot be "reject anything with a comment".
#[test]
fn comments_around_a_real_document_are_still_skipped() -> Result<()> {
    let docs = "# leading\nEncrypted: true\n# trailing\n";

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    let (.., loaded) = map.first().unwrap();

    assert!(
        matches!(loaded, MarkedValue::Bool(true, ..)),
        "the document under the comments loaded as {:?}",
        loaded
    );

    Ok(())
}

/// The other half of `test_handle_bool_happy_path`: widening the boolean set must not sweep in
/// everything that looks like one. YAML 1.1 admits three casings of each word -- all lowercase,
/// initial capital, all uppercase -- so a mixed-case spelling is a string, and so is a word that
/// merely contains one. Without these cases a `to_lowercase` or a `starts_with` would pass the set
/// above while making `tRuE` a boolean, which no schema does.
#[rstest::rstest]
#[case::mixed_case_true("tRuE")]
#[case::mixed_case_yes("yES")]
#[case::mixed_case_off("oFf")]
#[case::a_word_outside_the_set("enabled")]
#[case::a_single_letter_outside_the_set("t")]
#[case::a_word_that_starts_with_one("TRUE_VALUE")]
#[case::a_word_that_ends_with_one("NOT_TRUE")]
// The YAML 1.1-only spellings, which the loader reads as strings. Read as booleans, `AttributeType: N`
// would become `false` and `on:` in a GitHub Actions workflow a key no mapping can hold.
#[case::yaml_1_1_yes("yes")]
#[case::yaml_1_1_yes_capitalized("Yes")]
#[case::yaml_1_1_yes_uppercase("YES")]
#[case::yaml_1_1_no("no")]
#[case::yaml_1_1_no_capitalized("No")]
#[case::yaml_1_1_no_uppercase("NO")]
#[case::yaml_1_1_on("on")]
#[case::yaml_1_1_on_capitalized("On")]
#[case::yaml_1_1_on_uppercase("ON")]
#[case::yaml_1_1_off("off")]
#[case::yaml_1_1_off_capitalized("Off")]
#[case::yaml_1_1_off_uppercase("OFF")]
#[case::yaml_1_1_y("y")]
#[case::yaml_1_1_y_uppercase("Y")]
#[case::yaml_1_1_n("n")]
#[case::yaml_1_1_n_uppercase("N")]
fn a_scalar_outside_the_boolean_set_is_still_a_string(#[case] scalar: &str) -> Result<()> {
    let mut loader = Loader::new();
    let value = loader.load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    let (.., loaded) = map.first().unwrap();

    assert!(
        matches!(loaded, MarkedValue::String(s, ..) if s == scalar),
        "{} loaded as {:?}, but no YAML schema resolves it to a boolean",
        scalar,
        loaded
    );

    Ok(())
}

/// An explicit `!!bool` tag went through `str::parse::<bool>`, which takes `true` and `false` and
/// nothing else, so the tagged path was stricter than the untagged one it should agree with:
/// `!!bool True` loaded as the string "True". Both paths now read the same set.
#[rstest::rstest]
#[case::lowercase("true", true)]
#[case::capitalized("True", true)]
#[case::uppercase("TRUE", true)]
#[case::lowercase_false("false", false)]
#[case::capitalized_false("False", false)]
#[case::uppercase_false("FALSE", false)]
fn an_explicitly_tagged_bool_reads_the_same_set_as_a_plain_one(
    #[case] scalar: &str,
    #[case] expected: bool,
) -> Result<()> {
    let mut loader = Loader::new();
    let value = loader.load(format!("check: !!bool {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    let (.., loaded) = map.first().unwrap();

    assert!(
        matches!(loaded, MarkedValue::Bool(b, ..) if *b == expected),
        "!!bool {} loaded as {:?}, not the boolean {}",
        scalar,
        loaded,
        expected
    );

    Ok(())
}

/// A payload outside the boolean set under an explicit `!!bool` is refused, not turned into a string.
///
/// Narrowing `parse_bool` to the YAML 1.2 core set made the `!!bool` arm's fallback reachable, and it
/// returned a *string*: `!!bool yes` became "yes", which neither reads the node as the boolean the
/// author asked for nor says it could not be read as one. `!!int abc` two arms below is a loud
/// `BadValue`, so one out-of-set payload under an explicit type tag was a hard error and the other a
/// silent type change.
///
/// `serde_yaml` refuses every one of these outright, so refusing here closes a divergence rather than
/// opening one. Measured against it payload by payload, including `tRuE`, which neither accepts.
#[rstest::rstest]
#[case::a_yaml_1_1_word("yes")]
#[case::a_yaml_1_1_letter("y")]
#[case::a_yaml_1_1_switch("off")]
#[case::mixed_case("tRuE")]
#[case::a_number("1")]
#[case::not_a_boolean_at_all("maybe")]
fn a_bool_tag_over_something_outside_the_set_is_refused(#[case] scalar: &str) -> Result<()> {
    let value = Loader::new().load(format!("check: !!bool {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        _ => unreachable!("a single mapping loads as a map"),
    };
    let (.., loaded) = map.first().unwrap();

    // The refusal carries the node as written, tag included, so the report says what made the
    // payload unreadable: "Value = maybe" did not, "Value = !!bool maybe" does.
    let written = format!("!!bool {scalar}");
    assert!(
        matches!(loaded, MarkedValue::BadValue(v, ..) if *v == written),
        "!!bool {} loaded as {:?}, not a BadValue holding {:?}",
        scalar,
        loaded,
        written
    );

    Ok(())
}

/// A `---` stream held more than one document and the loader answered with the first one, in
/// silence. `Loader::load` returned at the first `DocumentEnd`, so a template prefixed with a
/// compliant document and a `---` had every finding in it suppressed at exit 0, and -- because
/// returning there dropped the parser -- the bytes after that point were never handed to libyaml,
/// so a stream whose later document was not YAML at all also passed.
///
/// The cases below are the two shapes that matter: content in the first document, and an *empty*
/// first document, which is the worse one because the loader then evaluated nothing whatsoever.
///
/// The empty-first-document case reads `---\n---\nb: 2\n---\nc: 3\n` rather than `---\n---\nb: 2\n`.
/// The shorter file holds *one* document behind two separators, and refusing it was this fix
/// overshooting: see `a_leading_separator_does_not_make_a_second_document`. The concern the case exists
/// for -- an empty first document must not make the loader evaluate nothing -- is what that test
/// asserts, and this one keeps the part that belongs here, which is that a leading separator does not
/// stop a genuine two-document stream from being refused.
#[rstest::rstest]
#[case::two_documents_with_content("a: 1\n---\nb: 2\n", "holds 2 -- the second starts at L:2,C:1")]
#[case::an_empty_first_document(
    "---\n---\nb: 2\n---\nc: 3\n",
    "holds 2 -- the second starts at L:4,C:1"
)]
// A written `null` at the leading end is content, the same as the trailing `~` case below, so the two
// ends of the file agree on what "holds nothing" means. Both go through `is_empty_node`.
#[case::a_leading_document_holding_an_explicit_null(
    "--- null\n---\nb: 2\n",
    "holds 2 -- the second starts at L:2,C:1"
)]
#[case::three_documents(
    "a: 1\n---\nb: 2\n---\nc: 3\n",
    "holds 3 -- the second starts at L:2,C:1"
)]
#[case::a_later_document_that_is_not_yaml(
    "a: 1\n---\nb: [ this is : not valid yaml {{{\n",
    "holds at least 2 -- the second starts at L:2,C:1"
)]
// A separator between two real documents is not one of them, so the count is 2 and the position is
// the second real document rather than the empty one. Counting every `DocumentStart` said 3, at the
// separator.
#[case::a_separator_between_two_documents(
    "a: 1\n---\n---\nb: 2\n",
    "holds 2 -- the second starts at L:3,C:1"
)]
// `~` is written, so the document holding it holds something.
#[case::a_trailing_document_holding_a_tilde(
    "a: 1\n---\n~\n",
    "holds 2 -- the second starts at L:2,C:1"
)]
fn a_stream_holding_more_than_one_document_is_refused(
    #[case] content: &str,
    #[case] expected: &str,
) {
    let loaded = Loader::new().load(content.to_string());

    let message = match &loaded {
        Err(Error::UnsupportedDocument(m)) if m.contains("one document per file") => m.clone(),
        other => panic!(
            "loading {:?} gave {:?}, not the multiple-document error",
            content, other
        ),
    };

    assert!(
        message.contains(expected),
        "loading {:?} said {:?}, which does not carry {:?}",
        content,
        message,
        expected
    );
}

/// A document holding only the empty node is a separator, not a document.
///
/// libyaml emits a whole document -- start, empty scalar, end -- for a `---` with nothing after it, so
/// counting `DocumentStart` events made a file of one template plus a trailing `---` "hold 2". The
/// count was wrong by one and the advice it carried -- split them into separate files -- could not be
/// followed, because there is nothing at the `---` to put in the second file. A trailing separator is
/// what a generator or a concatenation leaves behind.
#[rstest::rstest]
#[case::a_trailing_separator("a: 1\n---\n")]
#[case::a_trailing_separator_and_a_blank_line("a: 1\n---\n\n")]
#[case::two_trailing_separators("a: 1\n---\n---\n")]
#[case::a_trailing_separator_and_a_comment("a: 1\n---\n# nothing here\n")]
fn a_trailing_separator_does_not_make_a_second_document(#[case] content: &str) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    assert!(
        matches!(&value, MarkedValue::Map(m, ..) if m.len() == 1),
        "loading {:?} gave {:?}, not the single mapping it holds",
        content,
        value
    );

    Ok(())
}

/// The other end of the file, and the same rule: a document holding only the empty node is a separator
/// wherever it sits.
///
/// The trailing fix above was applied to one end only. `count_remaining_documents` skipped every empty
/// document it scanned, but the document the caller already held was counted unconditionally, and a
/// leading `---\n---\n` is exactly how that document comes to be empty. So the defect the fix had just
/// closed came straight back: `---\n---\nResources: {}` reported "holds 2" where one document held
/// anything, and the position it named as where "the second" starts was the start of the only document
/// in the file -- so the advice, split them into separate files, put the template in file two and left
/// file one holding a `---`.
///
/// The last case is the reachable one. A header comment block in its own document, ahead of the
/// template, is an ordinary way to write a YAML file, and it arrives here as a leading empty document.
#[rstest::rstest]
#[case::a_leading_separator_pair("---\n---\na: 1\n")]
#[case::two_leading_separator_pairs("---\n---\n---\na: 1\n")]
#[case::a_leading_separator_at_both_ends("---\n---\na: 1\n---\n")]
#[case::a_comment_block_in_its_own_document(
    "---\n# a header block\n# describing the template\n---\na: 1\n"
)]
fn a_leading_separator_does_not_make_a_second_document(#[case] content: &str) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    assert!(
        matches!(&value, MarkedValue::Map(m, ..) if m.len() == 1),
        "loading {:?} gave {:?}, not the single mapping it holds",
        content,
        value
    );

    Ok(())
}

/// A file of nothing but separators still loads, as the empty node, which is what a single `---` has
/// always done. The rule above is that an empty document does not take the slot from one holding
/// something; when nothing holds anything there is nothing to take it for.
#[rstest::rstest]
#[case::one_separator("---\n")]
#[case::a_separator_pair("---\n---\n")]
#[case::three_separators("---\n---\n---\n")]
fn a_file_of_only_separators_loads_as_the_empty_node(#[case] content: &str) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    assert!(
        matches!(&value, MarkedValue::Null(..)),
        "loading {:?} gave {:?}, not the empty node",
        content,
        value
    );

    Ok(())
}

/// The control for the trailing-separator case above, and the reason it cannot be written as "reject
/// any `---`".
/// A leading `---` is a directives-end marker opening the *first* document, not a separator, and
/// comments before it do not start a document of their own. Every `*_tests.yml` in the rules
/// registry has exactly this shape -- a `###` banner, then `---`, then one document -- so a fix
/// that counted `---` lines instead of `DocumentStart` events would refuse the whole registry.
#[rstest::rstest]
#[case::a_bare_leading_marker("---\na: 1\n")]
#[case::a_comment_then_a_marker("# just a comment\n---\na: 1\n")]
#[case::a_banner_then_a_marker("###\n# TITLE tests\n###\n---\na: 1\n")]
#[case::no_marker_at_all("a: 1\n")]
#[case::a_marker_and_an_explicit_end("---\na: 1\n...\n")]
fn one_document_with_a_marker_or_a_banner_still_loads(#[case] content: &str) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    assert!(
        matches!(&value, MarkedValue::Map(m, ..) if m.len() == 1),
        "loading {:?} gave {:?}, not the single mapping it holds",
        content,
        value
    );

    Ok(())
}

/// Data-file markers count lines and columns from one, the same as everything that reads them.
///
/// libyaml counts from zero and `system_mark_to_location` passed the numbers through, so every
/// `Path=[L:n,C:m]` in every data-file finding named the line above the one a person editing the
/// file sees. The report contradicted itself in one block, because `emit_code` prints a one-based
/// excerpt beside the `L:` value: a finding at physical line 14 read `L:13` above its own excerpt
/// line `14.`, and the excerpt window -- which starts two lines above `line` -- was centred on the
/// wrong line too. Rules-file locations were already one-based, since they come from `nom`'s
/// `LocatedSpan`, so the product printed one convention for the rules file and another for the data.
///
/// The expectations here are computed from the fixture rather than written as numbers, so the test
/// says "the marker is where the text is" rather than restating whatever the loader currently does.
#[test]
fn a_marker_names_the_one_based_position_of_its_scalar() -> Result<()> {
    let content = "Resources:\n  B:\n    Type: AWS::S3::Bucket\n";

    let expected_line = content
        .lines()
        .position(|l| l.contains("AWS::S3::Bucket"))
        .expect("the fixture holds the value")
        + 1;
    let expected_col = content
        .lines()
        .nth(expected_line - 1)
        .expect("the line exists")
        .find("AWS::S3::Bucket")
        .expect("the value is on that line")
        + 1;

    let value = Loader::new().load(content.to_string())?;

    let type_value = match &value {
        MarkedValue::Map(root, ..) => match root.first().expect("Resources is present").1 {
            MarkedValue::Map(resources, ..) => match resources.first().expect("B is present").1 {
                MarkedValue::Map(b, ..) => b.first().expect("Type is present").1.clone(),
                other => unreachable!("B is a mapping, got {:?}", other),
            },
            other => unreachable!("Resources is a mapping, got {:?}", other),
        },
        other => unreachable!("the document is a mapping, got {:?}", other),
    };

    assert_eq!(
        &Location {
            line: expected_line,
            col: expected_col,
        },
        type_value.location(),
        "the marker for {:?} does not name its own line {} and column {}",
        "AWS::S3::Bucket",
        expected_line,
        expected_col
    );

    Ok(())
}

/// The other half of the convention, and the reason the offset is added in the conversion rather
/// than in `Display`. `Location::default()` is what a literal written in the *rules* file is given,
/// and SARIF's `build_region` reads `line < 1` as "this finding has no position at all". Adding the
/// offset where `Display` runs would have turned every literal into a claim about line 1.
#[test]
fn a_location_with_no_position_stays_zero() {
    assert_eq!(Location { line: 0, col: 0 }, Location::default());
}

/// An empty node is null, and a quoted empty string is not.
///
/// The null set was `~` and `null` only, so the *empty* scalar -- the value of a key written with
/// nothing after the colon, which both the YAML 1.1 and 1.2 schemas resolve to the null node -- fell
/// through to `String("")`. The loader could not tell `k:` from `k: ""`, and `is_string` or
/// `!= null` on a property that is actually absent-valued passed. Writing the same document with
/// the null spelled inverted all three of `== ""`, `is_string` and `is_null`, which is what made it
/// a defect rather than a choice: the two spellings of one value disagreed.
///
/// `serde_yaml`, which was the loader `guard test` and `run_checks` used on the same bytes, already
/// answered null here. The quoted case is the control, and the reason emptiness alone is enough to
/// decide: every quoted scalar is taken by the `style != Plain` arm before this one.
#[rstest::rstest]
#[case::nothing_after_the_colon("k:", true)]
#[case::a_tilde("k: ~", true)]
#[case::the_word("k: null", true)]
#[case::the_word_uppercased("k: NULL", true)]
#[case::a_double_quoted_empty_string("k: \"\"", false)]
#[case::a_single_quoted_empty_string("k: ''", false)]
fn an_empty_plain_scalar_is_null_and_a_quoted_one_is_not(
    #[case] content: &str,
    #[case] expected_null: bool,
) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    if expected_null {
        assert!(
            matches!(loaded, MarkedValue::Null(..)),
            "{:?} loaded as {:?}, but YAML resolves it to the null node",
            content,
            loaded
        );
    } else {
        assert!(
            matches!(loaded, MarkedValue::String(s, ..) if s.is_empty()),
            "{:?} loaded as {:?}, but a quoted empty scalar is the empty string",
            content,
            loaded
        );
    }

    Ok(())
}

/// Integer resolution is the YAML 1.2 core schema's three forms, with a leading sign allowed on the
/// radix ones and a redundant leading zero left as text.
///
/// This was `str::parse::<i64>`, which takes a sign and decimal digits and nothing else, so no radix
/// prefix resolved as a number -- `0x1F` and `0o17` were strings and a rule comparing a netmask or a
/// permission bitmask to a number could not match -- while `0755` was read as decimal 755. The
/// leading-zero case is the one where the two YAML versions assign different *values* to the same
/// characters, 493 under 1.1 and 755 under 1.2 core, so it stays the literal text rather than
/// becoming either.
///
/// The `0X`/`0O`/`0b` cases are the boundary: 1.2 core's regexes are lowercase-only and have no
/// binary form, and each of these would be a number under some other schema.
#[rstest::rstest]
#[case::decimal("42", Some(42))]
#[case::signed_decimal("+42", Some(42))]
#[case::negative_decimal("-7", Some(-7))]
#[case::zero("0", Some(0))]
#[case::negative_zero("-0", Some(0))]
#[case::hex("0x1F", Some(31))]
#[case::negative_hex("-0x10", Some(-16))]
#[case::octal("0o17", Some(15))]
#[case::negative_octal("-0o17", Some(-15))]
#[case::i64_max("9223372036854775807", Some(i64::MAX))]
#[case::i64_min("-9223372036854775808", Some(i64::MIN))]
#[case::redundant_leading_zero("0755", None)]
#[case::two_zeros("00", None)]
#[case::signed_leading_zero("+0755", None)]
#[case::uppercase_hex_prefix("0X1F", None)]
#[case::uppercase_octal_prefix("0O17", None)]
#[case::binary("0b101", None)]
#[case::a_time("1:30", None)]
#[case::underscored("1_000", None)]
#[case::a_word("abc", None)]
fn an_integer_resolves_by_the_1_2_core_forms(
    #[case] scalar: &str,
    #[case] expected: Option<i64>,
) -> Result<()> {
    let value = Loader::new().load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    match expected {
        Some(n) => assert!(
            matches!(loaded, MarkedValue::Int(i, ..) if *i == n),
            "{} loaded as {:?}, not the integer {}",
            scalar,
            loaded,
            n
        ),
        // Not merely "is not an Int": the float resolver takes most of these if it is given a turn,
        // and `Float(755.0)` for `0755` would be the same defect wearing another type.
        None => assert!(
            matches!(loaded, MarkedValue::String(s, ..) if s == scalar),
            "{} loaded as {:?}, but no integer form of YAML 1.2 core resolves it",
            scalar,
            loaded
        ),
    }

    Ok(())
}

/// Two integer literals the document spells differently stay different values.
///
/// An integer too wide for `i64` that fell through to the float resolver, which accepts it, would turn
/// `9223372036854775809` and `9223372036854775810` both into `9.223372036854776e18`, and they would
/// compare *equal*. A clause asserting they differ would be reported non-compliant -- a wrong answer
/// about identity, at the ordinary exit code, with nothing on either channel to notice it by.
///
/// The boundary cases are here because the fix is a range check and an off-by-one in it would either
/// leave the defect in place or turn `i64::MAX` into text.
#[rstest::rstest]
#[case::i64_max("9223372036854775807", true)]
#[case::i64_min("-9223372036854775808", true)]
#[case::just_past_i64_max("9223372036854775808", false)]
#[case::just_past_i64_min("-9223372036854775809", false)]
#[case::far_past("99999999999999999999", false)]
#[case::hex_too_wide("0xFFFFFFFFFFFFFFFFF", false)]
fn an_integer_wider_than_i64_keeps_its_text(
    #[case] scalar: &str,
    #[case] fits: bool,
) -> Result<()> {
    let value = Loader::new().load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    if fits {
        assert!(
            matches!(loaded, MarkedValue::Int(..)),
            "{} loaded as {:?}, but it fits in an i64",
            scalar,
            loaded
        );
    } else {
        assert!(
            matches!(loaded, MarkedValue::String(s, ..) if s == scalar),
            "{} loaded as {:?}; a float cannot tell it from its neighbour",
            scalar,
            loaded
        );
    }

    Ok(())
}

/// The consequence the case above exists to prevent, asserted directly on two values one apart.
#[test]
fn two_integers_wider_than_i64_do_not_collapse_into_one() -> Result<()> {
    let value =
        Loader::new().load("a: 9223372036854775809\nb: 9223372036854775810\n".to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let a = map.get_index(0).expect("a is present").1;
    let b = map.get_index(1).expect("b is present").1;

    let (a, b) = match (a, b) {
        (MarkedValue::String(a, ..), MarkedValue::String(b, ..)) => (a, b),
        other => panic!("expected both to keep their text, got {:?}", other),
    };

    assert_ne!(
        a, b,
        "two integers one apart loaded as the same value, so a clause asserting they differ \
         cannot be answered correctly"
    );

    Ok(())
}

/// The three spellings of one `Fn::GetAtt` produce one shape.
///
/// CloudFormation documents `!GetAtt logicalNameOfResource.attributeName` as the short form of
/// `{ "Fn::GetAtt": [ "logicalNameOfResource", "attributeName" ] }`, and the dotted spelling is
/// YAML-only -- JSON has the list and nothing else. Nothing split on the dot, so the dotted form was
/// a *string* while the sequence and long forms were both a *list*. A filter reaching
/// `"Fn::GetAtt"[0]` matched the list forms and selected nothing on the dotted one, so a rule
/// authored against JSON templates skipped YAML ones at exit 0 with an empty stderr.
///
/// The multi-dot case is the reason the split is on the first dot only: AWS gives
/// `!GetAtt myELB.SourceSecurityGroup.OwnerAlias` as `["myELB", "SourceSecurityGroup.OwnerAlias"]`.
#[rstest::rstest]
#[case::dotted("v: !GetAtt Other.Arn", "Other", "Arn")]
#[case::sequence("v: !GetAtt [Other, Arn]", "Other", "Arn")]
#[case::long_form("v:\n  Fn::GetAtt: [Other, Arn]", "Other", "Arn")]
#[case::dotted_attribute_with_a_dot(
    "v: !GetAtt myELB.SourceSecurityGroup.OwnerAlias",
    "myELB",
    "SourceSecurityGroup.OwnerAlias"
)]
#[case::sequence_attribute_with_a_dot(
    "v: !GetAtt [myELB, SourceSecurityGroup.OwnerAlias]",
    "myELB",
    "SourceSecurityGroup.OwnerAlias"
)]
fn every_spelling_of_getatt_builds_the_same_list(
    #[case] content: &str,
    #[case] resource: &str,
    #[case] attribute: &str,
) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let wrapper = match map.first().expect("v is present").1 {
        MarkedValue::Map(inner, ..) => inner,
        other => panic!(
            "{:?} did not wrap the value in a map, got {:?}",
            content, other
        ),
    };
    let ((name, ..), payload) = wrapper.first().expect("the function is present");

    assert_eq!(
        "Fn::GetAtt", name,
        "{:?} named the function {}",
        content, name
    );

    let parts = match payload {
        MarkedValue::List(parts, ..) => parts,
        other => panic!(
            "{:?} gave Fn::GetAtt a {:?}; the JSON form can only be a list, so the two spellings \
             of one reference would not be comparable",
            content, other
        ),
    };

    let as_strings: Vec<&str> = parts
        .iter()
        .map(|p| match p {
            MarkedValue::String(s, ..) => s.as_str(),
            other => panic!("a GetAtt element loaded as {:?}", other),
        })
        .collect();

    assert_eq!(vec![resource, attribute], as_strings, "for {:?}", content);

    Ok(())
}

/// A `!GetAtt` with no dot is not a valid `Fn::GetAtt` -- the function takes a resource *and* an
/// attribute -- so it keeps its string rather than becoming a one-element list, which is a shape
/// neither the long form nor JSON can produce.
#[test]
fn a_getatt_with_no_attribute_is_left_alone() -> Result<()> {
    let value = Loader::new().load("v: !GetAtt myELB".to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let wrapper = match map.first().expect("v is present").1 {
        MarkedValue::Map(inner, ..) => inner,
        other => panic!("expected a wrapper map, got {:?}", other),
    };
    let (.., payload) = wrapper.first().expect("the function is present");

    assert!(
        matches!(payload, MarkedValue::String(s, ..) if s == "myELB"),
        "a dotless GetAtt loaded as {:?}",
        payload
    );

    Ok(())
}

/// A document nested deeper than the loader will read is refused, rather than taken as far as the
/// stack allows.
///
/// `PathAwareValue::try_from_marked` recurses once per level, and past roughly 5300 levels it
/// overflowed the stack: SIGABRT, "thread 'main' has overflowed its stack" on stderr, no diagnostic
/// from cfn-guard and an exit code outside the documented set. Depth was also expensive long before
/// it was fatal, because every node rebuilds its full path string from its parent's -- depth 1600
/// took 39 seconds and depth 2000 took 76.
///
/// The bound is checked in `Loader::load`, which is iterative, so nothing deep is ever built for a
/// later pass to recurse over. That placement is what the isolation measurement decided: `load`
/// itself survived depth 20000 on a 16 KB thread in both profiles. Dropping the value it returned
/// is recursive drop glue and needs a stack of its own -- at that depth it survives `main`'s 8 MB
/// and aborts a 2 MB libtest thread -- so name the stack whenever quoting that half. Only the
/// conversion died at every stack it was given.
///
/// The boundary cases matter more than the extremes. An off-by-one here either refuses a document one
/// level inside the documented limit or admits one past it, and neither shows up in the deep cases.
#[rstest::rstest]
#[case::one_level_inside_the_limit(126, true)]
#[case::exactly_the_limit(127, true)]
#[case::one_level_past_the_limit(128, false)]
#[case::far_past_the_limit(2000, false)]
#[case::deep_enough_to_have_overflowed(20000, false)]
fn a_document_nested_past_the_limit_is_refused(#[case] brackets: usize, #[case] accepted: bool) {
    // One root mapping plus `brackets` nested sequences, so the deepest container is at level
    // `brackets + 1`.
    let content = format!("a: {}{}\n", "[".repeat(brackets), "]".repeat(brackets));

    let loaded = Loader::new().load(content);

    if accepted {
        assert!(
            loaded.is_ok(),
            "{} levels was refused, but the limit admits up to {}: {:?}",
            brackets + 1,
            MAX_NESTING_DEPTH,
            loaded.err()
        );
    } else {
        assert!(
            matches!(loaded, Err(Error::UnsupportedDocument(ref m)) if m.contains("nested at most")),
            "{} levels gave {:?}, not the depth error",
            brackets + 1,
            loaded
        );
    }
}

/// A flat mapping of twenty thousand entries loads with every entry in place: the count, a duplicate
/// resolving last-wins with its warning, and a merge key folded in after the explicit keys, all exactly
/// as a mapping of three entries does.
///
/// This is a shape pin, not a cost pin: it is green under a quadratic take of the entries too, so it does
/// not prove the cost. Nothing in the tests does: `fill_mapping` takes the entries as a `std::vec::IntoIter`,
/// which rules out a shifting take from the storage itself, and a consumer that copied the entries out
/// first would not be caught by any count here (see `fill_mapping` for what a `remove(0)` walk would
/// cost, with its timings). What this test guards is that the walk keeps the pairing and the merge-key
/// offset bookkeeping straight at a width where a one-off error anywhere in it would land on a visibly
/// wrong key.
///
/// The width is 20,000 so the test stays cheap under a quadratic take too, about a second in a debug
/// build, which is what lets it run red-side as a control.
#[test]
fn a_wide_mapping_keeps_every_entry_and_resolves_its_duplicate_and_merge_key() -> Result<()> {
    const WIDTH: usize = 20_000;
    let mut content = String::from("wide:\n");
    for i in 0..WIDTH {
        if i == WIDTH / 2 {
            content.push_str("  <<: { Kmerged: merged, K00001: shadowed }\n");
        }
        content.push_str(&format!("  K{i:05}: v{i}\n"));
    }
    content.push_str("  K00000: last\n");

    let loaded = Loader::new().load(content)?;

    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked(
        (loaded, crate::rules::path_value::Path::root()),
        &mut duplicates,
    )?;

    let wide = match &converted {
        crate::rules::path_value::PathAwareValue::Map((_, outer)) => {
            match outer.values.get("wide") {
                Some(crate::rules::path_value::PathAwareValue::Map((_, inner))) => inner,
                other => panic!("wide held {:?}", other),
            }
        }
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };

    // Every distinct explicit key, plus the one the merge brought in.
    assert_eq!(WIDTH + 1, wide.values.len(), "the entry count moved");
    assert_eq!(
        wide.keys.len(),
        wide.values.len(),
        "the key list and the value map must stay the same length"
    );

    let text = |key: &str| match wide.values.get(key) {
        Some(crate::rules::path_value::PathAwareValue::String((_, s))) => s.clone(),
        other => panic!("{key} held {:?}", other),
    };
    assert_eq!(
        "last",
        text("K00000"),
        "a repeated key resolves to its last value"
    );
    assert_eq!(
        "v1",
        text("K00001"),
        "an explicit key wins over the merged one"
    );
    assert_eq!(
        "merged",
        text("Kmerged"),
        "the merge key's own entry is folded in"
    );
    // Every other key, not a sample: an offset mistake at the merge key (index WIDTH / 2) lands on
    // the keys beside it, which a sample at the ends never reads.
    for i in 2..WIDTH {
        let key = format!("K{i:05}");
        assert_eq!(
            format!("v{i}"),
            text(&key),
            "{key} holds another key's value"
        );
    }

    assert_eq!(
        duplicates
            .iter()
            .map(|d| d.path.as_str())
            .collect::<Vec<_>>(),
        vec!["/wide/K00000"],
        "exactly the repeated key is reported as a duplicate"
    );

    Ok(())
}

/// The index walks to load a flat mapping cost exactly what its width predicts.
///
/// This is the regression guard for the loader's two index walks; the shape pin above passes on either
/// side of a cost fix. Not a clock: a time bound holds on one machine, and a ratio of times needed ten
/// loads of documents up to 16 MB, in a debug build on every CI runner, to stand clear of scheduling
/// noise. The loader counts its own work under `cfg(test)` (`Loader::work`), and all three of its
/// counts (`index_visits`, `kept_literals_recorded`, `forms_recorded`) are asserted exactly, per shape,
/// from figures derived from the walks below. Not by ratio, because a quadratic revert can move the
/// count either way: a prune rewritten as a whole-index `retain` drops the loader's increments with
/// it, so the count falls, and a counter that counts less passes any ratio; a read walk whose stop is
/// turned into a skip keeps its hook and visits every entry, so the count rises. The exact figure
/// catches both, provided a shape makes the scanned index wide, which is what the fifth shape is for.
///
/// The take of a closed mapping's entries is not counted here. `fill_mapping` receives them as a
/// `std::vec::IntoIter`, which rules out a shifting take from the storage itself; a consumer that
/// copied them out first would not be caught by any count the loader keeps (see `fill_mapping`).
///
/// `index_visits`: the loader has two walks whose cost can turn quadratic, over the per-scalar indices
/// `merge_key_index` and `kept_literal_index`. Every container close prunes both
/// (`forget_scalars_above`, one visit per popped entry), and every mapping close reads its own entries
/// out of both (`handle_mapping_end`, one visit per step, the stopping step included). Each walk starts
/// at the end of the index and stops at the closing container's slot. A whole-index `retain` in a prune,
/// or a read walk that skips past the slot instead of stopping, costs each close the length of the
/// index, about N^2 / 2 visits on a document whose N keys sit in that index while N value mappings
/// close. The `retain` has no per-visit hook, so under it the count falls; the skipping walk keeps its
/// hook, so under it the count rises. Either moves the exact figure. Per key, the shapes cost:
///
/// - plain keys and scalar values: nothing enters either index, 0 visits, `kept_literals_recorded` 0,
///   `forms_recorded` 0 (a plain string key is `Text`, which is never recorded);
/// - quoted keys and mapping values, what a JSON data file or a `Mappings` table looks like, the
///   negative control: a quoted key is never a kept literal and resolved integers are not either, so
///   0 visits and 0 forms;
/// - kept-literal keys and values, integers in `(i64::MAX, u64::MAX]` (`1` followed by nineteen
///   digits): two kept literals per key, asserted exactly, 1 form per key (the outer key is
///   `KeyForm::Literal`; the inner `v` is `Text`), and 5 visits per key. At the value mapping's close
///   the walk visits the inner literal and stops on the outer key (2) and the prune pops the inner
///   literal (1); at the outer mapping's close the walk visits every key (1 per key) and the prune pops
///   every key (1 per key). This is the shape a whole-index prune of `kept_literal_index` turns
///   quadratic, and a skipping read walk of it too: the outer keys stay recorded until the outer mapping
///   closes;
/// - a merge key in every value mapping: one `<<` per key through `merge_key_index`, 0 forms (`<<` and
///   `K` are `Text`), and 3 visits per key. The innermost mapping's close stops on the `<<` below it
///   (1); the value mapping's close visits it (1) and pops it (1). `merge_key_index` never holds more
///   than one entry here, so this shape does not catch a quadratic walk over it: a skipping read walk
///   still counts 1 at each close, and the figure stays 3 per key. It is the control that the merge-key
///   index is written and read back;
/// - a merge key for every entry of the wide mapping (`<<: { K: v }` per key): one `<<` per key through
///   `merge_key_index`, all of them recorded while the wide mapping is open, 0 forms, and 3 visits per
///   key. Each value mapping's close stops on its own `<<` below it (1); at the wide mapping's close the
///   walk visits every `<<` (1 per key) and the prune pops every `<<` (1 per key). This is the shape a
///   skipping read walk of `merge_key_index` turns quadratic: at the i-th value mapping's close the walk
///   would visit the i entries already recorded instead of stopping at the first, so the count rises to
///   about N^2 / 2 and the exact figure fails.
#[rstest::rstest]
#[case::plain_keys_and_scalar_values("  K{i:06}: v{i}\n", 0, 0, 0)]
#[case::quoted_keys_and_mapping_values("  \"K{i:06}\": {{ \"v\": {i} }}\n", 0, 0, 0)]
#[case::kept_literal_keys_and_values("  1{i:019}: {{ v: 1{i:019} }}\n", 2, 1, 5)]
#[case::merge_keys_in_mapping_values("  K{i:06}: {{ <<: {{ v: {i} }} }}\n", 0, 0, 3)]
#[case::merge_keys_in_the_wide_mapping("  <<: {{ K{i:06}: v{i} }}\n", 0, 0, 3)]
fn a_wide_mapping_loads_with_exactly_the_index_work_its_shape_owes(
    #[case] line: &str,
    #[case] kept_literals_per_key: usize,
    #[case] forms_per_key: usize,
    #[case] index_visits_per_key: usize,
) -> Result<()> {
    const NARROW: usize = 2_000;
    const WIDE: usize = 8 * NARROW;

    // `line` is a template with `{i:06}` or `{i:019}` for the key number and `{i}` for the value,
    // written out here rather than through `format!`, whose template has to be a literal.
    fn flat_mapping(width: usize, line: &str) -> String {
        let mut content = String::from("wide:\n");
        for i in 0..width {
            let rendered = line
                .replace("{i:06}", &format!("{i:06}"))
                .replace("{i:019}", &format!("{i:019}"))
                .replace("{i}", &i.to_string())
                .replace("{{", "{")
                .replace("}}", "}");
            content.push_str(&rendered);
        }
        content
    }

    fn work_to_load(width: usize, line: &str) -> Result<Work> {
        let mut loader = Loader::new();
        loader.load(flat_mapping(width, line))?;
        Ok(loader.work)
    }

    let narrow = work_to_load(NARROW, line)?;
    let wide = work_to_load(WIDE, line)?;

    assert_eq!(
        (kept_literals_per_key * NARROW, kept_literals_per_key * WIDE),
        (narrow.kept_literals_recorded, wide.kept_literals_recorded),
        "{:?}: the shape must put exactly the scalars it is meant to into the kept-literal index",
        line
    );
    assert_eq!(
        (forms_per_key * NARROW, forms_per_key * WIDE),
        (narrow.forms_recorded, wide.forms_recorded),
        "{:?}: exactly the keys whose form is not `Text` must be recorded in `key_forms`",
        line
    );
    assert_eq!(
        (index_visits_per_key * NARROW, index_visits_per_key * WIDE),
        (narrow.index_visits, wide.index_visits),
        "{:?}: the index walks must visit exactly the entries the shape puts in their way: a \
         whole-index prune moves the visits into `std` and counts fewer, a read walk that skips past \
         the closing slot instead of stopping keeps its hook and counts more ({:?} against {:?})",
        line,
        narrow,
        wide
    );

    Ok(())
}

/// The control: the bound is on nesting, not on size. A flat document of the same element count is
/// unaffected, which is what says the cost being bounded is depth and not the number of scalars.
#[test]
fn a_wide_but_shallow_document_is_not_affected_by_the_depth_bound() -> Result<()> {
    let content = format!(
        "a: [{}]\n",
        (0..2000)
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );

    let value = Loader::new().load(content)?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    match map.first().expect("a is present").1 {
        MarkedValue::List(items, ..) => assert_eq!(2000, items.len()),
        other => panic!("expected a list of 2000, got {:?}", other),
    }

    Ok(())
}

/// A key that is not a string is refused with the key named, not with a bare position.
///
/// The refusal carried `val.location().to_string()` and nothing else, so a run over a directory of
/// templates reported a position in an unnamed file -- `L:2,C:4` identifies neither which key nor
/// which of N templates, and cannot be searched for either. The type and the value are named here;
/// the file name is added by `validate::build_data_file`, which is the only place that knows it.
///
/// The value is named but deliberately not *used* to accept the key. `MarkedValue` holds the resolved
/// value rather than the text the document wrote, so rendering an `Int` back gives "31" for a key
/// written `0x1F`, a `Float` gives "1" for `1.0` and a `Bool` gives "true" for `True`. Turning those
/// into key names would invent names the document does not contain.
#[rstest::rstest]
#[case::a_null("~: x", "null")]
// The only spelling of an empty key YAML accepts. A bare `: x` does not parse at all, so the
// refusal here is for a key that resolved to null rather than for one that is missing.
#[case::an_explicit_empty_key("? \n: x", "null")]
#[case::a_sequence("? [a, b]\n: x", "a sequence")]
#[case::a_mapping("? {a: b}\n: x", "a mapping")]
fn a_non_string_key_is_refused_with_the_key_named(#[case] content: &str, #[case] expected: &str) {
    let loaded = Loader::new().load(content.to_string());

    let message = match loaded {
        Err(Error::InternalError(InvalidKeyType(message))) => message,
        other => panic!("{:?} gave {:?}, not the invalid-key error", content, other),
    };

    assert!(
        message.contains(expected),
        "the refusal for {:?} was {:?}, which does not name the key as {:?}",
        content,
        message,
        expected
    );
    assert!(
        message.contains("Quote it"),
        "the refusal for {:?} was {:?}, which does not say what to do about it",
        content,
        message
    );
}

/// A `<<` key is YAML's merge key, and its value's keys belong to the mapping that carries it.
///
/// Nothing resolved it, so `<<` became an ordinary key of that name and everything under it was
/// hidden. On the shape essentially every real rule uses that was a silent wrong SKIP: a template
/// whose `Type` arrived through a merge was invisible to `Resources[ Type == "AWS::S3::Bucket" ]`, so
/// the filter selected nothing, the rule was skipped, and a wide-open bucket exited 0 unchecked.
///
/// Each case is a precedence rule from <https://yaml.org/type/merge.html>, except the last two, which
/// the spec does not define. Two `<<` keys in one mapping is a duplicate key, and a name repeated
/// inside one merge source is too, so both follow the rule cfn-guard applies to a duplicated key
/// everywhere else: the last value wins. PyYAML agrees; `serde_yaml` refuses a duplicate key
/// outright, so it has no answer to compare against.
#[rstest::rstest]
#[case::a_merged_key_is_reachable("<<: { a: merged }", "a", "merged")]
#[case::an_explicit_key_wins("<<: { a: merged }\n  a: explicit", "a", "explicit")]
#[case::an_explicit_key_wins_when_written_first(
    "a: explicit\n  <<: { a: merged }",
    "a",
    "explicit"
)]
#[case::a_sequence_merges_each("<<: [{ a: first }, { b: second }]", "b", "second")]
#[case::an_earlier_sequence_entry_wins("<<: [{ a: first }, { a: second }]", "a", "first")]
#[case::a_later_merge_key_wins("<<: { a: first }\n  <<: { a: second }", "a", "second")]
fn a_merge_key_folds_its_value_into_the_mapping(
    #[case] body: &str,
    #[case] key: &str,
    #[case] expected: &str,
) -> Result<()> {
    let value = Loader::new().load(format!("outer:\n  {body}\n"))?;

    let outer = match &value {
        MarkedValue::Map(m, ..) => match m.first().expect("outer is present").1 {
            MarkedValue::Map(inner, ..) => inner,
            other => panic!("outer held {:?}", other),
        },
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };

    assert!(
        !outer.keys().any(|(name, _)| name == "<<"),
        "the merge key survived as a literal key in {:?}",
        outer
    );

    let found = outer
        .iter()
        .find(|((name, _), _)| name == key)
        .map(|(_, v)| v);

    assert!(
        matches!(found, Some(MarkedValue::String(s, ..)) if s == expected),
        "{:?} gave {} = {:?}, not {:?}",
        body,
        key,
        found,
        expected
    );

    Ok(())
}

/// A name repeated inside one merge source resolves the way a repeated key in a plain mapping does:
/// the last value, with the duplicate-key warning.
///
/// `apply_merges` claimed each name as it inserted it, so the *first* of two same-named entries of one
/// source won and the second was dropped -- the opposite of the plain mapping, whose two entries both
/// survive the loader (the map is keyed on `(name, location)`) and collapse last-wins in
/// `try_from_marked`. Dropping the loser in `apply_merges` also silenced the warning, because
/// `try_from_marked` is the only place a duplicate is visible.
///
/// So one malformed shape had two answers and only the quieter one, depending on whether the duplicate
/// arrived through `<<`. Asserted through `try_from_marked` rather than on the loader's map, because
/// that is where the collapse and the warning both happen.
#[rstest::rstest]
#[case::inside_one_merge_source("<<: { a: first, a: second }")]
#[case::a_plain_mapping("a: first\n  a: second")]
fn a_duplicate_name_resolves_last_wins_and_warns_wherever_it_arrived_from(
    #[case] body: &str,
) -> Result<()> {
    let loaded = Loader::new().load(format!("outer:\n  {body}\n"))?;

    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked(
        (loaded, crate::rules::path_value::Path::root()),
        &mut duplicates,
    )?;

    let (_, json): (String, serde_json::Value) =
        std::convert::TryInto::try_into(&converted).map_err(|e: Error| e)?;
    assert_eq!(
        json,
        serde_json::json!({ "outer": { "a": "second" } }),
        "{:?} resolved to {}",
        body,
        json
    );

    assert_eq!(
        duplicates
            .iter()
            .map(|d| d.path.as_str())
            .collect::<Vec<_>>(),
        vec!["/outer/a"],
        "{:?} did not report the duplicate",
        body
    );

    Ok(())
}

/// A merged key that reads as a held key of another kind is a collision: the held value stands and
/// the pair is reported as a duplicate key. A merged key under a held key of the same kind is a
/// same-key override, the merge key's documented use, and stays silent.
///
/// Two keys that read as one name but are not the same YAML key -- the integer `1` beside the string
/// `"1"` -- collide wherever the two sit: in one merge source, across two sources, or a merged key
/// under an explicit one. The last two shapes are the ones a by-name check of a shadowed merged entry
/// passes silently while the same pair written as explicit entries, or inside one source, warns, so
/// the collision is recorded by the position of the mapping that applied the merge paired with the
/// held key's position, and the conversion reports it when its walk reaches that key in that mapping
/// (see the paragraph below). The value on every shape is the one the loader gives without the
/// record; only the warning is added.
///
/// Spelling is not kind. A plain `x`, a quoted `"x"` and a `!!str 1` beside a `"1"` are the same string
/// key -- YAML resolves each to the string -- so each is a silent override, as it is on the serde
/// conversion, and so is `0755` beside `"0755"`: `resolve_int` keeps a decimal with a redundant
/// leading zero as the string "0755" on purpose, the same string `serde_yaml` gives it, so it is an
/// ordinary string key on both routes. The one form that is neither a resolved kind nor a plain
/// string is a plain literal this loader keeps as text though YAML would resolve it: beside its
/// quoted spelling it is a collision and warns here. Only YAML 1.2 core's own non-finite spellings
/// count, matched exactly, so `.iNf` is a plain string in core and to `serde_yaml`, and its row is a
/// silent override. What the serde conversion makes of each kept-literal pair differs by spelling;
/// the four cases are listed on `KeyForm` and pinned in `values_tests`.
///
/// The collision is recorded on the loader (`Loader::collisions`) by the position of the mapping that
/// applied the merge paired with the held key's position, not kept in the mapping: the merged entry is
/// dropped, so the mapping holds one entry of the name and nothing downstream has to order the pair.
/// `try_from_marked_reporting` emits the record when its walk reaches the held key in that mapping,
/// beside the duplicate pairs it finds itself; the explicit-duplicates row is the control
/// for that second source: two explicit entries are a pair the conversion detects, and the loader
/// records nothing for them.
///
/// The last column says whether the mapping keeps both spellings as two entries: a merged key that
/// reads as a held one is dropped, as an override or as a recorded collision, so the mapping holds one
/// entry of the name; only a pair written into one mapping with neither held -- two explicit entries,
/// or one source holding both -- stays a pair, and that pair is the conversion's own to collapse and
/// report rather than the loader's to record.
#[rstest::rstest]
#[case::one_source_with_the_collision("<<: { 1: a, \"1\": b }", "1", "b", 1, true)]
#[case::across_two_sources("<<: [{ 1: a }, { \"1\": b }]", "1", "a", 1, false)]
#[case::merged_under_explicit("<<: { 1: a }\n  \"1\": explicit", "1", "explicit", 1, false)]
#[case::merged_pair_under_explicit(
    "<<: { 1: a, \"1\": b }\n  \"1\": explicit",
    "1",
    "explicit",
    1,
    false
)]
#[case::explicit_duplicates("1: a\n  \"1\": b", "1", "b", 1, true)]
#[case::leading_zero_beside_quoted("<<: [{ 0755: a }, { \"0755\": b }]", "0755", "a", 0, false)]
#[case::kept_wide_integer_beside_quoted(
    "<<: [{ 9223372036854775808: a }, { \"9223372036854775808\": b }]",
    "9223372036854775808",
    "a",
    1,
    false
)]
#[case::kept_overflow_beside_quoted("<<: [{ 1e400: a }, { \"1e400\": b }]", "1e400", "a", 1, false)]
#[case::kept_underflow_beside_quoted(
    "<<: { 1e-400: a }\n  \"1e-400\": explicit",
    "1e-400",
    "explicit",
    1,
    false
)]
#[case::kept_non_finite_beside_quoted(
    "<<: { .Inf: a }\n  \".Inf\": explicit",
    ".Inf",
    "explicit",
    1,
    false
)]
#[case::mixed_case_non_finite_is_a_plain_string(
    "<<: [{ .iNf: a }, { \".iNf\": b }]",
    ".iNf",
    "a",
    0,
    false
)]
#[case::quoted_beside_plain_across_sources("<<: [{ x: a }, { \"x\": b }]", "x", "a", 0, false)]
#[case::plain_under_quoted_explicit(
    "<<: { BucketName: a }\n  \"BucketName\": b",
    "BucketName",
    "b",
    0,
    false
)]
#[case::tagged_string_beside_quoted("<<: [{ !!str 1: a }, { \"1\": b }]", "1", "a", 0, false)]
#[case::same_kind_override("<<: { \"1\": merged }\n  \"1\": explicit", "1", "explicit", 0, false)]
#[case::plain_same_kind_override(
    "<<: { Type: merged }\n  Type: explicit",
    "Type",
    "explicit",
    0,
    false
)]
#[case::same_kind_across_sources(
    "<<: [{ Type: first }, { Type: second }]",
    "Type",
    "first",
    0,
    false
)]
#[case::inside_a_source_that_is_itself_a_merge_mapping(
    "<<: { <<: [{ 1: a }, { \"1\": b }] }",
    "1",
    "a",
    1,
    false
)]
fn a_merged_key_of_another_kind_is_a_collision_that_warns(
    #[case] body: &str,
    #[case] key: &str,
    #[case] expected: &str,
    #[case] warnings: usize,
    #[case] pair_kept_in_mapping: bool,
) -> Result<()> {
    let mut loader = Loader::new();
    let loaded = loader.load(format!("outer:\n  {body}\n"))?;

    let entries_of_name = match &loaded {
        MarkedValue::Map(m, ..) => match m.first().expect("outer is present").1 {
            MarkedValue::Map(inner, ..) => inner.keys().filter(|(name, _)| name == key).count(),
            other => panic!("outer held {:?}", other),
        },
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    assert_eq!(
        entries_of_name,
        if pair_kept_in_mapping { 2 } else { 1 },
        "{:?}: the mapping must hold one entry of the name unless both spellings were written into \
         it with neither held",
        body
    );

    // The loader records a merged collision by the merging mapping's position and the held key's; the
    // conversion turns it into the record as it reaches that key in that mapping, beside the pairs it
    // finds itself, so one walk yields both. Counted as the records the walk reaches, not as the map's
    // sum: a record carried into an enclosing merge is held once per level (the source's copy stays,
    // for an alias of the source that is walked on its own), so on the nested row the map holds two
    // records and the walk reaches one.
    let recorded_by_loader = reached_collision_records(&loaded, loader.collisions());
    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked_reporting(
        (loaded, crate::rules::path_value::Path::root()),
        loader.collisions(),
        &mut duplicates,
    )?;

    let (_, json): (String, serde_json::Value) =
        std::convert::TryInto::try_into(&converted).map_err(|e: Error| e)?;
    assert_eq!(
        json["outer"][key],
        serde_json::json!(expected),
        "{:?}: the value must be the one the loader always gave, got {}",
        body,
        json
    );
    assert!(
        !json["outer"]
            .as_object()
            .expect("outer is a map")
            .contains_key("<<"),
        "{:?}: the merge key must be folded",
        body
    );

    // One source per shape: the loader's record for a merged collision, the conversion's own
    // detection for a pair the mapping kept; the records themselves all come out of the conversion.
    // The loader side is the records the walk reaches (see above), which is what the conversion
    // reports once each; the map's own sum is larger on the nested row and is not the behavior.
    assert_eq!(
        (recorded_by_loader, duplicates.len()),
        (if pair_kept_in_mapping { 0 } else { warnings }, warnings),
        "{:?}: a collision warns once, an override not at all; loader {:?}, records {:?}",
        body,
        loader.collisions(),
        duplicates
    );
    for duplicate in duplicates.iter() {
        assert_eq!(duplicate.path, format!("/outer/{key}"), "{:?}", body);
        assert!(
            (duplicate.first.line, duplicate.first.col)
                < (duplicate.repeated.line, duplicate.repeated.col),
            "{:?}: the two positions must be distinct and in document order, got {:?}",
            body,
            duplicate
        );
        assert!(
            duplicate.evaluated == duplicate.first || duplicate.evaluated == duplicate.repeated,
            "{:?}: the evaluated position must be one of the two, got {:?}",
            body,
            duplicate
        );
    }

    Ok(())
}

/// An alias of a kept literal is the kept literal: `*big` for `&big 9223372036854775808` is a key of
/// the `Literal` form wherever the anchor was written, so beside the quoted `"9223372036854775808"` it
/// is the same collision the written literal is, and warns once.
///
/// The form travelled by position. A kept literal was recorded only by its stack index as the scalar
/// was read, and that index names the written scalar, not the copy an alias pushes for it; the copy
/// carries the anchored node's position, so looking its form up found whatever that position had
/// recorded. An anchor written as a key of a mapping that had already closed had its `Literal` form
/// on record, and the alias collided; an anchor written as a value, or as the key of a mapping still
/// open around the alias, had none, and the same alias was read as `Text`, a silent override. One
/// pair, two verdicts, decided by where the author put the anchor. Red on the anchor-as-value and
/// enclosing-key rows with the alias read as text; green with the copy carrying the form.
///
/// The same alias as the mapping's own key, with the written literal merged under it, is the other
/// direction through `apply_merges` (the held keys' forms, not the merged key's): the two are the same
/// YAML key, so it is a silent same-key override, where the alias read as text had made it a warned
/// collision. That row pins the warning this change takes away.
///
/// The resolved kinds are the controls: `*one` for `&one 1` was already `Int` wherever the anchor sat,
/// because its form is read off the value, and `*name` for `&name x` is still `Text` beside `"x"`, a
/// same-key override, so an alias is not made a literal by being an alias. Every row checks the value
/// that stands: the held entry's, never the merged `a`.
#[rstest::rstest]
#[case::anchor_as_a_key_of_a_mapping_closed_earlier(
    "anchors:\n  &big 9223372036854775808: x\nouter:\n  <<: { *big: a }\n  \"9223372036854775808\": explicit\n",
    "/outer/9223372036854775808",
    "explicit",
    1
)]
#[case::anchor_as_a_value(
    "anchors:\n  hold: &big 9223372036854775808\nouter:\n  <<: { *big: a }\n  \"9223372036854775808\": explicit\n",
    "/outer/9223372036854775808",
    "explicit",
    1
)]
#[case::anchor_as_the_key_of_the_enclosing_mapping(
    "&big 9223372036854775808:\n  <<: { *big: a }\n  \"9223372036854775808\": explicit\n",
    "/9223372036854775808/9223372036854775808",
    "explicit",
    1
)]
#[case::anchor_as_a_value_across_two_sources(
    "anchors:\n  hold: &inf .Inf\nouter:\n  <<: [{ \".Inf\": b }, { *inf: a }]\n",
    "/outer/.Inf",
    "b",
    1
)]
#[case::alias_as_the_held_key_under_the_written_literal_is_an_override(
    "anchors:\n  hold: &big 9223372036854775808\nouter:\n  <<: { 9223372036854775808: a }\n  *big: explicit\n",
    "/outer/9223372036854775808",
    "explicit",
    0
)]
#[case::resolved_integer_as_a_value_is_an_int_key(
    "anchors:\n  hold: &one 1\nouter:\n  <<: { *one: a }\n  \"1\": explicit\n",
    "/outer/1",
    "explicit",
    1
)]
#[case::plain_text_as_a_value_is_a_text_key(
    "anchors:\n  hold: &name x\nouter:\n  <<: { *name: a }\n  \"x\": explicit\n",
    "/outer/x",
    "explicit",
    0
)]
fn an_aliased_kept_literal_keeps_its_form_wherever_the_anchor_was_written(
    #[case] document: &str,
    #[case] path: &str,
    #[case] expected: &str,
    #[case] warnings: usize,
) -> Result<()> {
    let mut loader = Loader::new();
    let loaded = loader.load(document.to_string())?;
    let recorded_by_loader: usize = loader.collisions().merged_count();
    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked_reporting(
        (loaded, crate::rules::path_value::Path::root()),
        loader.collisions(),
        &mut duplicates,
    )?;

    // The held value stands on every row, override or collision, so the merged `a` never wins.
    let (_, json): (String, serde_json::Value) =
        std::convert::TryInto::try_into(&converted).map_err(|e: Error| e)?;
    let held = json
        .pointer(path)
        .unwrap_or_else(|| panic!("{:?}: no value at {}: {}", document, path, json));
    assert_eq!(
        held,
        &serde_json::json!(expected),
        "{:?}: the held value must stand, got {}",
        document,
        json
    );

    assert_eq!(
        (recorded_by_loader, duplicates.len()),
        (warnings, warnings),
        "{:?}: the alias must be the key the anchor is, wherever the anchor was written; loader \
         {:?}, records {:?}",
        document,
        loader.collisions(),
        duplicates
    );
    for duplicate in duplicates.iter() {
        assert_eq!(duplicate.path, path, "{:?}", document);
        assert_ne!(
            duplicate.first, duplicate.repeated,
            "{:?}: the two positions must be distinct",
            document
        );
    }
    Ok(())
}

/// An alias of a merge key is a merge key: `*m` for `&m <<` merges the mapping under it into the
/// mapping that carries it, as the written `<<` does, so `y` lands under `b` and no key named `<<`
/// remains.
///
/// The merge key is known by stack slot, like a kept literal (`merge_key_index`), and the slot recorded
/// was the written scalar's. The alias pushed a copy, `String("<<")`, with a slot of its own that no
/// index named, so `fill_mapping` read it as an ordinary key named `<<` and the merged mapping sat
/// hidden under `b.<<`, where no rule finds it; PyYAML merges it, since the alias is the same
/// merge-typed node. The flow and block alias rows pin it: a loader that gave the copy no merge-key
/// slot leaves `y` under `b.<<` and fails them; recording the copy as the merge key the anchor is
/// passes them. The quoted row is the control: a quoted `"<<"` is an ordinary key whose name happens
/// to be `<<`, and its alias stays one. An explicit `!!merge "<<"` is the type said out loud and a
/// merge key in any style (`explicitly_merge` in `handle_scalar_event`), so its alias merges as its
/// anchor does; that row pins the tagged route through the same fact, with no red run behind it.
///
/// Every row runs on both loaders. The spec loader (`Loader::for_spec_file`) differs in its refusal
/// policy, its spelling record and its budget scope, none of which touches how an alias's copy is
/// recorded, so the spec-route cells are pins: added green, with the planted-control run that showed
/// each of them checking its row.
#[rstest::rstest]
#[case::flow_alias_merges(
    "a: { &m <<: { x: 1 } }\nb: { *m: { y: 2 } }\n",
    serde_json::json!({ "a": { "x": 1 }, "b": { "y": 2 } })
)]
#[case::block_alias_merges(
    "a:\n  &m <<:\n    x: 1\nb:\n  *m:\n    y: 2\n  z: 3\n",
    serde_json::json!({ "a": { "x": 1 }, "b": { "z": 3, "y": 2 } })
)]
#[case::quoted_alias_stays_an_ordinary_key(
    "a: { &q \"<<\": { x: 1 } }\nb: { *q: { y: 2 } }\n",
    serde_json::json!({ "a": { "<<": { "x": 1 } }, "b": { "<<": { "y": 2 } } })
)]
#[case::tagged_quoted_alias_merges(
    "a: { &m !!merge \"<<\": { x: 1 } }\nb: { *m: { y: 2 } }\n",
    serde_json::json!({ "a": { "x": 1 }, "b": { "y": 2 } })
)]
fn an_aliased_merge_key_merges_like_the_written_one(
    #[case] document: &str,
    #[case] expected: serde_json::Value,
    #[values(false, true)] spec_route: bool,
) -> Result<()> {
    let mut loader = if spec_route {
        Loader::for_spec_file()
    } else {
        Loader::new()
    };
    let loaded = loader.load(document.to_string())?;
    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked(
        (loaded, crate::rules::path_value::Path::root()),
        &mut duplicates,
    )?;
    let (_, json): (String, serde_json::Value) =
        std::convert::TryInto::try_into(&converted).map_err(|e: Error| e)?;
    assert_eq!(json, expected, "{:?} loaded as {}", document, json);
    assert!(
        duplicates.is_empty(),
        "{:?}: nothing here is written twice, got {:?}",
        document,
        duplicates
    );
    Ok(())
}

/// An aliased merge key given something that is not a mapping is refused as the written `<<` is:
/// `*m: abc` for `&m <<` earns the merge-value refusal on both routes. Under `Loader::new`, the
/// template and data route, the document is refused with it; under `Loader::for_spec_file`, which
/// marks a refused node instead of refusing the document, the mapping that carried the alias becomes a
/// `Refused` node holding the same message, the way a written `<<: abc` does, and the rest of the
/// document loads. An alias read as an ordinary key named `<<` holding `abc` would load on both
/// routes with nothing said. Each alias row has the written `<<` beside it as the control for the
/// message and the shape (the message names the value's position, the same on both spellings); the
/// spec route's merging row shows the alias merges there too. These rows pin behavior the alias fact
/// already gives; no tree is red on them.
#[rstest::rstest]
#[case::alias_refused_under_validate("a: { &m <<: { x: 1 } }\nb: { *m: abc }\n", false, "L:2,C:10")]
#[case::written_refused_under_validate("a: { x: 1 }\nb: { <<: abc }\n", false, "L:2,C:10")]
#[case::alias_refused_under_the_spec_loader(
    "a: { &m <<: { x: 1 } }\nb: { *m: abc }\n",
    true,
    "L:2,C:10"
)]
#[case::written_refused_under_the_spec_loader("a: { x: 1 }\nb: { <<: abc }\n", true, "L:2,C:10")]
fn an_aliased_merge_key_given_a_scalar_is_refused_like_the_written_one(
    #[case] document: &str,
    #[case] spec_route: bool,
    #[case] value_at: &str,
) -> Result<()> {
    let mut loader = if spec_route {
        Loader::for_spec_file()
    } else {
        Loader::new()
    };
    let message = format!("the merge key `<<` at {value_at} must be given a mapping");
    match loader.load(document.to_string()) {
        Err(error) => {
            assert!(
                !spec_route,
                "{:?}: the spec route marks, never refuses the document",
                document
            );
            let text = error.to_string();
            assert!(
                text.contains(&message),
                "{:?}: refused with {:?}",
                document,
                text
            );
        }
        Ok(loaded) => {
            assert!(
                spec_route,
                "{:?}: the data route must refuse the document",
                document
            );
            let b = match &loaded {
                MarkedValue::Map(map, ..) => map.get_index(1).expect("b is present").1,
                other => unreachable!("a mapping loads as a map, got {:?}", other),
            };
            match b {
                MarkedValue::Refused(text, _) => {
                    assert!(
                        text.contains(&message),
                        "{:?}: `b` refused with {:?}",
                        document,
                        text
                    );
                }
                other => panic!("{:?}: `b` must be the refusal, got {:?}", document, other),
            }
            let a = match &loaded {
                MarkedValue::Map(map, ..) => map.get_index(0).expect("a is present").1,
                _ => unreachable!(),
            };
            assert!(
                matches!(a, MarkedValue::Map(..)),
                "{:?}: `a` must still load, got {:?}",
                document,
                a
            );
        }
    }
    Ok(())
}

/// The record a collision leaves, once `try_from_marked_reporting` has emitted it, names the entry
/// whose value is evaluated: the earlier source's key across two sources, so the *first* position in
/// document order, and the mapping's own key under an explicit entry, so the *last*. A notice that
/// assumed the last value would misname the winner on the two-sources shape. The path is the one the
/// value has in the finished document: through a sequence item, inside a merge source that the
/// enclosing merge then places under its own key (`/outer/inner/1`, not the source's position under
/// `<<`), and under the `Fn::` name of a tagged sequence item. When the held name is itself written
/// twice, the record pairs the merged key with the entry kept, the last, so the sentence names the
/// value that stands; the pair's own duplicate record comes first. A collision inside a source that
/// the enclosing merge drops as a same-key override is never reached and leaves no record, as a plain
/// duplicate pair in that subtree leaves none. The nested, tagged, duplicated-name and dropped rows
/// are what tell a record the conversion emits from one built from the loader's stack at the inner
/// mapping's close: that one would carry a `<<` segment in the path, count a wrapper slot as an item,
/// name the first held entry, and report the dropped source.
///
/// The positions of an aliased key are its anchor's. A copy keeps the anchored node's positions by
/// design (`resolve_alias`: a finding inside an aliased input points at the line the value is written
/// on), so a record whose held key is an alias's copy names the anchor's position as `first` and as
/// `evaluated`, not the `*big:` site the author wrote, and a held copy of an anchor written as a value
/// elsewhere names a position outside the mapping that collided. The path names the mapping, which is
/// what makes the notice usable; naming the alias site beside the copy is a change to the record and
/// is not made here.
///
/// A record attaches to the mapping that merged, and to a copy of that mapping, never to another
/// mapping that merely holds the same keys. An alias is a copy of the anchored node with its
/// positions, so the anchored mapping and every mapping that merges it hold the held key at one
/// position; on the alias rows only `X` (and `R`) merged a colliding key beside the alias, and the
/// anchor and the other mappings that merged it alone get no record. Red with the record keyed by the
/// held key's position alone, which attached it to all of them; green with the merging mapping's
/// position in the key. When the mapping that merged is itself aliased (`X: &x { <<: [...] }` then
/// `Y: *x`) the copy carries `X`'s position and the record matches there too, so the pair is reported
/// once per copy, as a duplicate pair written inside an aliased mapping is. A source that is itself
/// a mapping that merged (`<<: { <<: [...] }`, anchored or not) is taken apart by the enclosing merge
/// and never walked, so its records are carried over to the enclosing mapping with its entries and
/// reported there; red with the record left under the source's position, where nothing is walked.
#[rstest::rstest]
#[case::across_two_sources_the_first_is_evaluated(
    "outer:\n  <<:\n    - { 1: a }\n    - { \"1\": b }\n",
    &[("/outer/1", (3, 9), (4, 9), (3, 9))]
)]
#[case::under_an_explicit_key_the_last_is_evaluated(
    "outer:\n  <<: { 1: a }\n  \"1\": explicit\n",
    &[("/outer/1", (2, 9), (3, 3), (3, 3))]
)]
#[case::inside_a_sequence_item(
    "list:\n  - <<: { 1: a }\n    \"1\": explicit\n",
    &[("/list/0/1", (2, 11), (3, 5), (3, 5))]
)]
#[case::inside_a_merge_source_at_its_merged_path(
    "outer:\n  <<:\n    inner:\n      <<: { 1: a }\n      \"1\": b\n",
    &[("/outer/inner/1", (4, 13), (5, 7), (5, 7))]
)]
#[case::inside_a_dropped_merge_source_is_silent(
    "outer:\n  <<:\n    inner:\n      <<: { 1: a }\n      \"1\": b\n  inner: explicit\n",
    &[]
)]
#[case::inside_a_tagged_sequence_item(
    "List:\n  - !If [cond, { <<: { 1: a }, \"1\": b }, x]\n",
    &[("/List/0/Fn::If/1/1", (2, 24), (2, 32), (2, 32))]
)]
#[case::under_a_name_written_twice_the_kept_entry_is_named(
    "outer:\n  <<: { 1: a }\n  \"1\": b\n  \"1\": c\n",
    &[
        ("/outer/1", (3, 3), (4, 3), (4, 3)),
        ("/outer/1", (2, 9), (4, 3), (4, 3))
    ]
)]
#[case::under_a_name_written_twice_in_an_earlier_source(
    "outer:\n  <<:\n    - { 1: a, 1: b }\n    - { \"1\": c }\n",
    &[
        ("/outer/1", (3, 9), (3, 15), (3, 15)),
        ("/outer/1", (3, 15), (4, 9), (3, 15))
    ]
)]
#[case::a_key_written_three_times_names_the_third_as_evaluated(
    "outer:\n  x: 1\n  x: 2\n  x: 3\n",
    &[
        ("/outer/x", (2, 3), (3, 3), (4, 3)),
        ("/outer/x", (2, 3), (4, 3), (4, 3))
    ]
)]
#[case::records_come_out_in_document_order_across_children(
    "outer:\n  <<: { 1: a }\n  \"1\": b\n  inner: { x: 1, x: 2 }\n",
    &[
        ("/outer/1", (2, 9), (3, 3), (3, 3)),
        ("/outer/inner/x", (4, 12), (4, 18), (4, 18))
    ]
)]
#[case::through_an_alias_only_the_mapping_that_merged_is_named(
    "Base: &b { 1: a }\nResources:\n  X: { <<: [*b, {\"1\": b}] }\n  Y: { <<: *b }\n",
    &[("/Resources/X/1", (1, 12), (3, 18), (1, 12))]
)]
#[case::across_two_aliases_only_the_mapping_that_merged_both_is_named(
    "Defaults:\n  A: &a\n    \"8080\": web\n  B: &b\n    8080: api\nResources:\n  R:\n    <<: [*a, *b]\n  \
     S:\n    <<: *a\n",
    &[("/Resources/R/8080", (3, 5), (5, 5), (3, 5))]
)]
#[case::inside_a_source_that_is_itself_a_merge_mapping(
    "R:\n  <<:\n    <<: [{ 1: a }, { \"1\": b }]\n",
    &[("/R/1", (3, 12), (3, 22), (3, 12))]
)]
#[case::inside_an_anchored_source_that_is_itself_a_merge_mapping(
    "A: &a { 1: a }\nB: &b { \"1\": b }\nR:\n  <<: &shared\n    <<: [*a, *b]\nS:\n  <<: *shared\n",
    &[
        ("/R/1", (1, 9), (2, 9), (1, 9)),
        ("/S/1", (1, 9), (2, 9), (1, 9))
    ]
)]
#[case::an_alias_of_the_mapping_that_merged_reports_once_per_copy(
    "Base: &b { 1: a }\nX: &x { <<: [*b, {\"1\": b}] }\nY: *x\n",
    &[
        ("/X/1", (1, 12), (2, 19), (1, 12)),
        ("/Y/1", (1, 12), (2, 19), (1, 12))
    ]
)]
#[case::inside_a_merging_source_listed_beside_another(
    "A: &a { 1: a }\nB: &b { \"1\": b }\nC: &c { <<: [*a, *b] }\nR: { <<: [*c, { x: 1 }] }\n",
    &[
        ("/C/1", (1, 9), (2, 9), (1, 9)),
        ("/R/1", (1, 9), (2, 9), (1, 9))
    ]
)]
#[case::a_merging_source_listed_beside_one_of_its_own_inputs_is_reported_once(
    "A: &a { 1: a }\nB: &b { \"1\": b }\nS: &s { <<: [*a, *b] }\nR: { <<: [*s, *b] }\n",
    &[
        ("/S/1", (1, 9), (2, 9), (1, 9)),
        ("/R/1", (1, 9), (2, 9), (1, 9))
    ]
)]
// A held key written through an alias is named at the alias's own line, where the author wrote the
// key that stands, not at the anchor's position: for the three rows below that is the `*big:` line
// of the mapping that merged, so the record pairs it with the merged key in document order and the
// merged key, written earlier, comes first.
#[case::a_held_alias_copy_is_reported_once_at_the_merging_mappings_path(
    "&big 9223372036854775808:\n  <<: { \"9223372036854775808\": a }\n  *big: explicit\n",
    &[("/9223372036854775808/9223372036854775808", (2, 9), (3, 3), (3, 3))]
)]
#[case::a_held_alias_copy_also_held_elsewhere_is_reported_once(
    "anchors:\n  hold: &big 9223372036854775808\nouter:\n  <<: { \"9223372036854775808\": a }\n  *big: explicit\nother:\n  *big: x\n",
    &[("/outer/9223372036854775808", (4, 9), (5, 3), (5, 3))]
)]
#[case::the_same_held_alias_copy_colliding_in_two_mappings_is_reported_once_each(
    "anchors:\n  hold: &big 9223372036854775808\nouter:\n  <<: { \"9223372036854775808\": a }\n  *big: e1\nother:\n  <<: { \"9223372036854775808\": b }\n  *big: e2\n",
    &[
        ("/outer/9223372036854775808", (4, 9), (5, 3), (5, 3)),
        ("/other/9223372036854775808", (7, 9), (8, 3), (8, 3))
    ]
)]
fn a_collision_record_names_both_positions_in_order_and_the_evaluated_one(
    #[case] document: &str,
    #[case] expected: &[(&str, (usize, usize), (usize, usize), (usize, usize))],
) -> Result<()> {
    let mut loader = Loader::new();
    let loaded = loader.load(document.to_string())?;
    let mut duplicates = vec![];
    crate::rules::path_value::PathAwareValue::try_from_marked_reporting(
        (loaded, crate::rules::path_value::Path::root()),
        loader.collisions(),
        &mut duplicates,
    )?;
    let at = |(line, col): (usize, usize)| Location::new(line, col);
    let expected: Vec<DuplicateKey> = expected
        .iter()
        .map(|(path, first, repeated, evaluated)| DuplicateKey {
            path: path.to_string(),
            first: at(*first),
            repeated: at(*repeated),
            evaluated: at(*evaluated),
        })
        .collect();
    assert_eq!(expected, duplicates, "{:?}", document);
    Ok(())
}

/// The collision records `try_from_marked_reporting`'s walk of `value` reaches: for every mapping the
/// walk meets, the records keyed by that mapping's position and one of its keys' positions. A record
/// left under the position of a merge source that was taken apart, and so is never walked as a mapping,
/// is not reached and not counted, which is how the loader's map, which holds a carried record once per
/// merge level, is read as the behavior the conversion shows.
fn reached_collision_records(
    value: &MarkedValue,
    collisions: &crate::rules::path_value::KeyCollisions,
) -> usize {
    match value {
        MarkedValue::Map(entries, mapping_at) => entries
            .iter()
            .map(|((_, key_at), child)| {
                collisions
                    .merged_against(*mapping_at, *key_at)
                    .map_or(0, Vec::len)
                    + reached_collision_records(child, collisions)
            })
            .sum(),
        MarkedValue::List(items, _) => items
            .iter()
            .map(|item| reached_collision_records(item, collisions))
            .sum(),
        _ => 0,
    }
}

/// Two keys of one mapping that share an anchor's position are a key written twice: `&k x: 1` beside
/// `*k: 2`, or `*k: 1` beside `*k: 2`, is the name `x` twice in one mapping, the last value stands, and
/// the pair is reported as a duplicate key, as `x: 1` beside `x: 2` is.
///
/// The loader keys a mapping on `(name, position)`, and an alias's copy keeps its anchor's position,
/// so the two keys were one entry to the map: the second insert replaced the first value and said
/// nothing, where the plain pair survives as two entries for the conversion to collapse and report.
/// The repeated position is recorded, as its own kind of record beside the merge collisions, and the
/// conversion reports it once at the entry it belongs to, with the pair the plain spelling gets. The
/// value that stands is the last one written, as for any key written twice, and the notice says so.
/// The plain row is the control that its record is unchanged. Red on the two alias rows with no record
/// and `b.x` silently `2`; green with the record.
///
/// The record names the sites the key was WRITTEN at, not the anchor's position twice: the loader
/// keeps each alias's own position beside the entry it wrote, so `&k x: 1` beside `*k: 2` is first at
/// line 2 and again at line 3, and two aliases of an anchor written elsewhere are the two alias lines,
/// not the anchor's line in another mapping. Red before: both positions were the anchor's, so the
/// warning said "first at L:2,C:3 and again at L:2,C:3", one position written twice, and for the two
/// aliases it named a line in the `anchors` mapping that holds no `b.x` at all.
///
/// A name written both ways in one mapping gets one notice per extra entry and keeps the last value
/// written, whichever spelling wrote it, and every notice names the site whose value stands. With the
/// plain `x: 3` last, the mapping holds the anchored entry and the plain one, so the walk reports the
/// alias's write at the anchored entry and the plain pair at the plain one, and `3` stands at line 4,
/// which the first record names as the site written at and the second as the last of its two. With the
/// alias `*k: 3` last, the alias writes the anchored entry again after the plain `x: 2` was inserted,
/// so the loader moves that entry to the end and `3` stands there, written at line 4; the plain pair is
/// named in document order (lines 2 and 3) with line 4 as the site whose value stands, since neither of
/// its two positions is where that value was written, and the alias's write follows it as lines 2 and 4
/// with the last standing. Before this, the repeated position rode the merge collisions' record and was
/// attached at the name's last entry, so the walk re-paired it into the same record the plain pair had
/// already produced (two identical notices), and the replaced entry kept its slot, so `2` stood where
/// the author wrote `3` last (red: two identical records and `b.x` 2). Then the pair's record read
/// "first at L:2,C:3 and again at L:3,C:3. The first value is the one evaluated.", which sent the reader
/// to `&k x: 1` while `3` stood, and the record after it said "last" of one position written twice:
/// two lines about one key that contradicted each other, neither naming line 4 (red: the first word).
#[rstest::rstest]
#[case::anchored_key_beside_its_alias(
    "b:\n  &k x: 1\n  *k: 2\n",
    2,
    &[("/b/x", (2, 3), (3, 3), (3, 3), "The last value is the one evaluated.")]
)]
#[case::two_aliases_of_one_anchored_key(
    "anchors:\n  k: &k x\nb:\n  *k: 1\n  *k: 2\n",
    2,
    &[("/b/x", (4, 3), (5, 3), (5, 3), "The last value is the one evaluated.")]
)]
#[case::plain_pair_is_the_control(
    "b:\n  x: 1\n  x: 2\n",
    2,
    &[("/b/x", (2, 3), (3, 3), (3, 3), "The last value is the one evaluated.")]
)]
#[case::anchored_then_alias_then_plain(
    "b:\n  &k x: 1\n  *k: 2\n  x: 3\n",
    3,
    &[
        ("/b/x", (2, 3), (3, 3), (4, 3), "The value written at L:4,C:3 is the one evaluated."),
        ("/b/x", (2, 3), (4, 3), (4, 3), "The last value is the one evaluated.")
    ]
)]
#[case::anchored_then_plain_then_alias(
    "b:\n  &k x: 1\n  x: 2\n  *k: 3\n",
    3,
    &[
        ("/b/x", (2, 3), (3, 3), (4, 3), "The value written at L:4,C:3 is the one evaluated."),
        ("/b/x", (2, 3), (4, 3), (4, 3), "The last value is the one evaluated.")
    ]
)]
#[case::plain_then_anchored_then_alias(
    "b:\n  x: 2\n  &k x: 1\n  *k: 3\n",
    3,
    &[
        ("/b/x", (2, 3), (3, 3), (4, 3), "The value written at L:4,C:3 is the one evaluated."),
        ("/b/x", (3, 3), (4, 3), (4, 3), "The last value is the one evaluated.")
    ]
)]
// The record travels with the entry a merge moves: the anchored mapping is walked on its own and
// reports its pair, and the mapping that merged it reports the same pair at its own path, with the
// count and the alias's site carried together, so `b.x` names line 3 as the site whose value stands.
#[case::carried_whole_through_a_merge(
    "s: &s\n  &k x: 1\n  *k: 2\nb:\n  <<: *s\n",
    2,
    &[
        ("/s/x", (2, 3), (3, 3), (3, 3), "The last value is the one evaluated."),
        ("/b/x", (2, 3), (3, 3), (3, 3), "The last value is the one evaluated.")
    ]
)]
fn two_keys_sharing_an_anchors_position_are_a_duplicate(
    #[case] document: &str,
    #[case] stands: i64,
    #[case] expected: &[(&str, (usize, usize), (usize, usize), (usize, usize), &str)],
) -> Result<()> {
    let mut loader = Loader::new();
    let loaded = loader.load(document.to_string())?;
    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked_reporting(
        (loaded, crate::rules::path_value::Path::root()),
        loader.collisions(),
        &mut duplicates,
    )?;
    let (_, json): (String, serde_json::Value) =
        std::convert::TryInto::try_into(&converted).map_err(|e: Error| e)?;
    assert_eq!(
        json["b"]["x"],
        serde_json::json!(stands),
        "{:?}: the last value written stands, got {}",
        document,
        json
    );
    let at = |(line, col): (usize, usize)| Location::new(line, col);
    let expected_records: Vec<DuplicateKey> = expected
        .iter()
        .map(|(path, first, repeated, evaluated, _)| DuplicateKey {
            path: path.to_string(),
            first: at(*first),
            repeated: at(*repeated),
            evaluated: at(*evaluated),
        })
        .collect();
    assert_eq!(expected_records, duplicates, "{:?}", document);
    let sentences: Vec<String> = duplicates
        .iter()
        .map(DuplicateKey::evaluated_sentence)
        .collect();
    let expected_sentences: Vec<&str> = expected.iter().map(|row| row.4).collect();
    assert_eq!(
        expected_sentences, sentences,
        "{:?}: the notice must name the value that stands; records {:?}",
        document, duplicates
    );
    Ok(())
}

/// An alias that writes an anchored key again keeps the key where the anchor put it when no other
/// spelling of the name follows: `&k x: 1`, `y: 2`, `*k: 3` loads with the keys `x, y`, as the plain
/// `x: 1`, `y: 2`, `x: 3` does, and `3` stands. The order reaches `keys`, so a capture over the map
/// and a `.*` enumeration read the entries as the author wrote them. The entry moves to the end only
/// when a plain spelling of the name sits after its slot, since then the value written last has to
/// stand over the plain one: for `&k x: 1`, `y: 2`, `x: 2`, `*k: 3` the anchored entry goes behind
/// the plain `x: 2`, so the name's last entry holds `3`, and the keys read `y, x`, the one order in
/// which a repeat still moves a key (the plain pair cannot be told from this shape, so the cost is
/// named here). Red before: the loader removed and re-inserted the entry on every repeat, so `x`
/// moved behind `y` in the first row too while the plain pair kept its place.
#[rstest::rstest]
#[case::alias_with_another_key_between("b:\n  &k x: 1\n  y: 2\n  *k: 3\n", &["x", "y"], 3)]
#[case::plain_pair_with_another_key_between("b:\n  x: 1\n  y: 2\n  x: 3\n", &["x", "y"], 3)]
#[case::plain_spelling_between_anchor_and_alias_still_moves(
    "b:\n  &k x: 1\n  y: 2\n  x: 2\n  *k: 3\n",
    &["y", "x"],
    3
)]
#[case::alias_right_after_its_anchor("b:\n  &k x: 1\n  *k: 3\n  y: 2\n", &["x", "y"], 3)]
fn an_alias_repeat_keeps_the_key_order(
    #[case] document: &str,
    #[case] keys: &[&str],
    #[case] stands: i64,
) -> Result<()> {
    let mut loader = Loader::new();
    let loaded = loader.load(document.to_string())?;
    let mut duplicates = vec![];
    let converted = crate::rules::path_value::PathAwareValue::try_from_marked_reporting(
        (loaded, crate::rules::path_value::Path::root()),
        loader.collisions(),
        &mut duplicates,
    )?;
    let b = match &converted {
        crate::rules::path_value::PathAwareValue::Map((_, root)) => match &root.values["b"] {
            crate::rules::path_value::PathAwareValue::Map((_, b)) => b,
            other => panic!("{:?}: b is a map, got {:?}", document, other),
        },
        other => panic!("{:?}: the document is a map, got {:?}", document, other),
    };
    let key_names: Vec<&str> = b
        .keys
        .iter()
        .map(|key| match key {
            crate::rules::path_value::PathAwareValue::String((_, name)) => name.as_str(),
            other => panic!("{:?}: a key is a string, got {:?}", document, other),
        })
        .collect();
    assert_eq!(
        keys.to_vec(),
        key_names,
        "{:?}: `keys` in document order",
        document
    );
    let value_names: Vec<&str> = b.values.keys().map(String::as_str).collect();
    assert_eq!(
        keys.to_vec(),
        value_names,
        "{:?}: the entries `.*` enumerates, in document order",
        document
    );
    let (_, json): (String, serde_json::Value) =
        std::convert::TryInto::try_into(&converted).map_err(|e: Error| e)?;
    assert_eq!(json["b"]["x"], serde_json::json!(stands), "{:?}", document);
    Ok(())
}

/// A key written twice at one position keeps the slot the anchor put it in and takes the last value,
/// over several keys at once: `&k0 x0`, `&k1 x1`, `y`, then `*k1`, `*k0`, `z` loads as `x0, x1, y, z`
/// with `2` in both anchored keys, and a key written three times with other keys between the writes
/// keeps its first slot and holds its third value. The first row is the shape whose aliases repeat the
/// anchors in their own order and is the control that a repeat alone moves nothing. Every repeat is
/// one duplicate-key record (the sentences those records carry are pinned beside the single-key rows
/// above). What these rows refuse is a loader that moves a repeated key to the slot of its last write,
/// under which the second row reads `y, x1, x0, z` and the third `y, z, x`, and a plain `insert` that
/// drops the later value, under which both anchored keys of the second row hold `1`.
#[rstest::rstest]
#[case::aliases_in_the_anchors_order(
    "b:\n  &k0 x0: 1\n  &k1 x1: 1\n  &k2 x2: 1\n  *k0: 2\n  *k1: 2\n  *k2: 2\n",
    &[("x0", 2), ("x1", 2), ("x2", 2)],
    3
)]
#[case::aliases_in_reverse_order_past_plain_keys(
    "b:\n  &k0 x0: 1\n  &k1 x1: 1\n  y: 1\n  *k1: 2\n  *k0: 2\n  z: 1\n",
    &[("x0", 2), ("x1", 2), ("y", 1), ("z", 1)],
    2
)]
#[case::a_key_written_three_times_keeps_its_slot(
    "b:\n  &k x: 1\n  y: 1\n  *k: 2\n  z: 1\n  *k: 3\n",
    &[("x", 3), ("y", 1), ("z", 1)],
    2
)]
fn repeated_keys_keep_their_slot_and_take_the_last_value(
    #[case] document: &str,
    #[case] expected: &[(&str, i64)],
    #[case] repeats: usize,
) -> Result<()> {
    let mut loader = Loader::new();
    let loaded = loader.load(document.to_string())?;
    let MarkedValue::Map(map, _) = entry(&loaded, "b") else {
        panic!("`b` loads as a map");
    };
    let order: Vec<(&str, i64)> = map
        .iter()
        .map(|((name, _), value)| match value {
            MarkedValue::Int(n, _) => (name.as_str(), *n),
            other => panic!(
                "{:?}: `{}` holds {:?}, not an integer",
                document, name, other
            ),
        })
        .collect();
    assert_eq!(expected.to_vec(), order, "{:?}", document);
    let mut duplicates = vec![];
    crate::rules::path_value::PathAwareValue::try_from_marked_reporting(
        (loaded, crate::rules::path_value::Path::root()),
        loader.collisions(),
        &mut duplicates,
    )?;
    assert_eq!(
        repeats,
        duplicates.len(),
        "{:?}: {:?}",
        document,
        duplicates
    );
    Ok(())
}

/// Filling a mapping writes each key into the map once per time the document writes it, a repeat
/// replacing its value in place, and rebuilds the map only when a repeat has to move an entry behind a
/// plain spelling of its name. The counts are `Work::map_changes` (one per key the document wrote, plus
/// one per entry a rebuild puts back) and `Work::map_rebuilds`, over the whole document, so the root
/// mapping's one key is in every total. The flat row is the shape nearly every template has: three
/// keys, three writes, no rebuild, and nothing built for repeats. The three ordering rows repeat keys
/// without moving any, so they cost exactly the keys the document wrote and no rebuild; the row whose
/// plain spelling sits between the anchor and the alias is the one shape that moves, and it costs its
/// four written keys plus the three entries put back by its one rebuild. A loader that removed and
/// re-inserted the entry on every repeat (the shape that loaded 80,000 anchored keys in 46 s) counts two
/// writes more per repeat on the repeating rows, and one that rebuilt every mapping counts a rebuild and
/// three more writes on the flat row.
#[rstest::rstest]
#[case::a_flat_mapping("b:\n  x: 1\n  y: 2\n  z: 3\n", 1 + 3, 0)]
#[case::aliases_in_the_anchors_order(
    "b:\n  &k0 x0: 1\n  &k1 x1: 1\n  &k2 x2: 1\n  *k0: 2\n  *k1: 2\n  *k2: 2\n",
    1 + 6,
    0
)]
#[case::aliases_in_reverse_order_past_plain_keys(
    "b:\n  &k0 x0: 1\n  &k1 x1: 1\n  y: 1\n  *k1: 2\n  *k0: 2\n  z: 1\n",
    1 + 6,
    0
)]
#[case::a_key_written_three_times("b:\n  &k x: 1\n  y: 1\n  *k: 2\n  z: 1\n  *k: 3\n", 1 + 5, 0)]
#[case::plain_spelling_between_anchor_and_alias_rebuilds_once(
    "b:\n  &k x: 1\n  y: 2\n  x: 2\n  *k: 3\n",
    1 + 4 + 3,
    1
)]
fn filling_a_mapping_writes_each_key_once_and_rebuilds_only_to_move_one(
    #[case] document: &str,
    #[case] changes: usize,
    #[case] rebuilds: usize,
) -> Result<()> {
    let mut loader = Loader::new();
    loader.load(document.to_string())?;
    assert_eq!(
        (changes, rebuilds),
        (loader.work.map_changes, loader.work.map_rebuilds),
        "{:?}: (map writes, rebuilds), got {:?}",
        document,
        loader.work
    );
    Ok(())
}

/// `fill_mapping` reads a repeat off the map itself, so it has to start from an empty map: an entry
/// seeded before the call would be written over in its old slot with no repeat recorded, the silent
/// first-slot bug the function exists to avoid. The one caller makes the map fresh; a debug build
/// refuses any other map at the door.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "fill_mapping fills a fresh map")]
fn filling_a_seeded_map_is_refused() {
    let mut seeded: indexmap::IndexMap<(String, Location), MarkedValue> = indexmap::IndexMap::new();
    seeded.insert(
        (String::from("x"), Location::new(1, 1)),
        MarkedValue::Int(1, Location::new(1, 4)),
    );
    let mut key_forms = HashMap::new();
    let mut collisions = KeyCollisions::new();
    let _ = fill_mapping(
        &mut seeded,
        Location::new(1, 1),
        Vec::new().into_iter(),
        &HashSet::new(),
        &HashSet::new(),
        &HashMap::new(),
        &mut key_forms,
        &mut collisions,
    );
}

/// Only a key form other than `Text` is recorded, so a document whose keys are all strings records
/// none, with or without a merge key; a numeric key records one. `apply_merges` reads a missing entry
/// as `Text` for a held key and a merged key alike, so the empty map is the ordinary case and every
/// explicit name is present to it by construction. The counter is the map's growth: an alias's copy
/// of a recorded key keeps the anchor's position, so whichever of the anchored key and its copies
/// closes first records the position and the rest add nothing; the alias row has two keys of a form
/// other than `Text` and records one.
#[rstest::rstest]
#[case::no_merge_key("a:\n  b: 1\n  c: [x, y]\n", 0)]
#[case::merge_key_over_string_keys("a:\n  <<: { b: 1 }\n  c: 2\n", 0)]
#[case::one_integer_key("a:\n  1: x\n  b: y\n", 1)]
#[case::an_aliased_integer_key_adds_nothing("a: { &k 1: x }\nb: { *k: y }\n", 1)]
fn only_a_form_other_than_text_is_recorded(
    #[case] document: &str,
    #[case] forms: usize,
) -> Result<()> {
    let mut loader = Loader::new();
    loader.load(document.to_string())?;
    assert_eq!(
        loader.work.forms_recorded, forms,
        "{:?}: {:?}",
        document, loader.work
    );
    Ok(())
}

/// A *quoted* `<<` is an ordinary key whose name happens to be `<<`, and is not merged.
///
/// The merge type is an implicit resolution -- `tag:yaml.org,2002:merge` -- and implicit resolution
/// applies to the plain style, so quoting is the documented way to write a key literally named `<<`.
/// The test ran on the resolved key string, by which point `"<<"` and `<<` are the same
/// `String("<<")`, so both spellings were merged. `"<<": plain string value` -- a perfectly ordinary
/// pair -- was refused at exit 5 for not being a mapping, which also removed the only escape hatch
/// for the name.
///
/// PyYAML on the same bytes gives `{"A": {"<<": "plain string value"}}` for the quoted spelling and
/// merges the plain one, which is the pair of answers asserted here.
#[rstest::rstest]
#[case::double_quoted("\"<<\": { a: kept }")]
#[case::single_quoted("'<<': { a: kept }")]
fn a_quoted_merge_key_is_an_ordinary_key(#[case] body: &str) -> Result<()> {
    let value = Loader::new().load(format!("outer:\n  {body}\n"))?;

    let outer = match &value {
        MarkedValue::Map(m, ..) => match m.first().expect("outer is present").1 {
            MarkedValue::Map(inner, ..) => inner,
            other => panic!("outer held {:?}", other),
        },
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };

    assert!(
        outer.keys().any(|(name, _)| name == "<<"),
        "{:?} lost the quoted key, giving {:?}",
        body,
        outer
    );
    assert!(
        !outer.keys().any(|(name, _)| name == "a"),
        "{:?} merged a quoted key, giving {:?}",
        body,
        outer
    );

    Ok(())
}

/// The same pair through the whole loader: a quoted `<<` given a scalar loads, a plain one is refused.
///
/// This is the shape the defect was found on. The two documents differ in nothing but the quotes, and
/// before this they got the same answer.
#[test]
fn quoting_the_merge_key_decides_whether_an_unmergeable_value_is_refused() {
    let quoted = Loader::new().load("outer:\n  \"<<\": plain string value\n".to_string());
    let plain = Loader::new().load("outer:\n  <<: plain string value\n".to_string());

    assert!(quoted.is_ok(), "the quoted key was refused: {:?}", quoted);
    assert!(
        matches!(plain, Err(Error::UnsupportedDocument(ref m)) if m.contains("merge key")),
        "the plain key gave {:?}, not the merge-value error",
        plain
    );
}

/// A merge key whose value cannot be merged is refused rather than folded into nothing. The spec
/// requires a mapping or a sequence of mappings, and there is no sensible reading of anything else.
#[rstest::rstest]
#[case::a_scalar("outer:\n  <<: 5\n")]
#[case::a_string("outer:\n  <<: hello\n")]
#[case::a_sequence_of_scalars("outer:\n  <<: [1, 2]\n")]
#[case::a_sequence_holding_a_sequence("outer:\n  <<: [[a]]\n")]
fn a_merge_key_given_something_unmergeable_is_refused(#[case] content: &str) {
    let loaded = Loader::new().load(content.to_string());

    assert!(
        matches!(loaded, Err(Error::UnsupportedDocument(ref m)) if m.contains("merge key")),
        "{:?} gave {:?}, not the merge-value error",
        content,
        loaded
    );
}

/// A `!Foo` tag is preserved under the long function name whatever shape its payload is and whether
/// or not the loader has heard of the name.
///
/// Checking the tag against a hand-written set of names and discarding it on a miss would turn the
/// short form of an intrinsic the set did not list into a bare value: `!Transform { ... }` would be
/// indistinguishable from a plain mapping, and a rule forbidding the macro would pass at exit 0 where
/// the long `Fn::Transform` spelling of the same template fails. That is the opposite of how `!!`-tags
/// behave: `!!int abc` becomes a `BadValue` and is reported, so a bad *type* tag would be loud while
/// an unknown *function* tag was silent.
///
/// Enumeration is the wrong mechanism because a set goes stale: Cidr, ForEach, GetStackOutput,
/// Length, ToJsonString, Transform and ValueOfAll are all in the CloudFormation Template Reference,
/// and a set written by hand has to be kept up with it. One set per position also sets a trap -- a
/// name listed for scalars only, or for sequences only, loses its tag when written in the other
/// position.
///
/// The mapping cases are the ones no set covers: a `handle_mapping_start` that never looked at the
/// tag would lose it even for a name every set listed.
#[rstest::rstest]
#[case::a_known_scalar_name("v: !Ref Param", "Ref")]
#[case::a_known_sequence_name("v: !Select [0, [a, b]]", "Fn::Select")]
#[case::a_known_name_in_the_other_position("v: !GetAZs [us-east-1]", "Fn::GetAZs")]
#[case::an_unlisted_scalar_name("v: !Length x", "Fn::Length")]
#[case::an_unlisted_sequence_name("v: !Cidr [\"10.0.0.0/16\", 6, 5]", "Fn::Cidr")]
#[case::an_unlisted_mapping_name("v: !ToJsonString { a: 1 }", "Fn::ToJsonString")]
#[case::a_known_mapping_name("v: !Transform { Name: AWS::Include }", "Fn::Transform")]
#[case::a_name_aws_has_not_published("v: !SomethingNew x", "Fn::SomethingNew")]
#[case::the_other_prefixless_name("v: !Condition IsProd", "Condition")]
fn a_tagged_value_keeps_its_function_name(
    #[case] content: &str,
    #[case] expected: &str,
) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let wrapper = match map.first().expect("v is present").1 {
        MarkedValue::Map(inner, ..) => inner,
        other => panic!(
            "{:?} lost its tag and loaded the payload alone as {:?}",
            content, other
        ),
    };
    let ((name, ..), _) = wrapper.first().expect("the function is present");

    assert_eq!(expected, name, "{:?} named the function {}", content, name);

    Ok(())
}

/// A bare `!` is YAML's non-specific tag, not a function name, so it is not wrapped. Without this the
/// `Fn::` fallback would name the key "Fn::".
#[rstest::rstest]
#[case::a_bare_tag_on_a_scalar("v: ! plain")]
#[case::a_bare_tag_on_a_sequence("v: ! [a]")]
fn a_bare_non_specific_tag_is_not_a_function(#[case] content: &str) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let (.., payload) = map.first().expect("v is present");

    if let MarkedValue::Map(inner, ..) = payload {
        let ((name, ..), _) = inner.first().expect("non-empty");
        assert!(
            !name.starts_with("Fn::"),
            "a bare `!` was read as the function {:?}",
            name
        );
    }

    Ok(())
}

/// A float literal that reached zero only because it was too small to represent keeps its text.
///
/// `f64::from_str` signals overflow with an infinity, which the `is_finite` gate caught, and
/// underflow with a silent zero, which it did not. So `1e-400` became `Float(0.0)` and answered
/// `== 0` with a PASS while `> 0` failed -- a value the author wrote as positive, read as zero, at
/// exit 0. The other end of the same exponent range already refused, so one rule disagreed with
/// itself.
///
/// The zero cases are the control and they are the reason the test is on the mantissa rather than on
/// the literal: `0e400` is a genuine zero whose exponent contains a nonzero digit.
#[rstest::rstest]
#[case::underflow("1e-400", false)]
#[case::negative_underflow("-1e-400", false)]
#[case::underflow_with_a_fraction("1.5e-400", false)]
#[case::underflow_from_a_small_mantissa("0.0001e-400", false)]
#[case::plain_zero("0", true)]
#[case::zero_with_a_point("0.0", true)]
#[case::negative_zero("-0.0", true)]
#[case::zero_with_places("0.000", true)]
#[case::zero_with_a_big_exponent("0e400", true)]
#[case::zero_with_a_small_exponent("0.0e-400", true)]
#[case::zero_exponent("0e0", true)]
fn a_float_that_underflowed_to_zero_keeps_its_text(
    #[case] scalar: &str,
    #[case] is_a_real_zero: bool,
) -> Result<()> {
    let value = Loader::new().load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    if is_a_real_zero {
        assert!(
            matches!(loaded, MarkedValue::Int(0, ..))
                || matches!(loaded, MarkedValue::Float(f, ..) if *f == 0.0),
            "{} loaded as {:?}, but every significant digit in it is zero",
            scalar,
            loaded
        );
    } else {
        assert!(
            matches!(loaded, MarkedValue::String(s, ..) if s == scalar),
            "{} loaded as {:?}; read as a number it answers `== 0` for a value the document \
             writes as non-zero",
            scalar,
            loaded
        );
    }

    Ok(())
}

/// The control for the case above: a small float that is still representable stays a float. Without
/// it the fix is also satisfied by refusing every negative exponent.
#[rstest::rstest]
#[case::subnormal("1e-320")]
#[case::small_but_normal("1e-300")]
#[case::ordinary("1.5")]
fn a_small_float_that_is_still_representable_stays_a_float(#[case] scalar: &str) -> Result<()> {
    let value = Loader::new().load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    assert!(
        matches!(loaded, MarkedValue::Float(f, ..) if *f != 0.0),
        "{} loaded as {:?}, but it is representable and non-zero",
        scalar,
        loaded
    );

    Ok(())
}

/// A scalar key becomes the text CloudFormation would give it.
///
/// These were refused, which refused templates CloudFormation accepts: a template is converted to
/// JSON before deployment and JSON has no key but a string, so an unquoted account id under
/// `Mappings` is ordinary -- and the same document written in JSON already loaded. The retrieval half
/// of this was fixed long ago and `path_value::list_index_of`'s doc comment says so; the template half
/// was unreachable, because a document writing the key the natural way never reached retrieval.
///
/// The expected text is not this loader's invention. Each case matches what a YAML-to-JSON round trip
/// produces for the same key, which is what CloudFormation does before it deploys: `80` becomes "80",
/// `1.0` becomes "1.0" and not Rust's "1", and `0x1F` becomes "31" because YAML 1.2 core resolves it
/// to 31 first. That last case is the one that makes the rule "render the resolved value", not
/// "render the source text".
#[rstest::rstest]
#[case::an_integer("80: http", "80")]
#[case::an_account_id("123456789012: prod", "123456789012")]
#[case::a_negative_integer("-1: x", "-1")]
#[case::a_whole_float("1.0: x", "1.0")]
#[case::a_fractional_float("1.5: x", "1.5")]
#[case::a_true("true: x", "true")]
#[case::a_capitalised_true("True: x", "true")]
#[case::a_false("false: x", "false")]
#[case::hex_resolved_first("0x1F: x", "31")]
#[case::a_leading_zero_stays_text("0755: x", "0755")]
fn a_scalar_key_becomes_the_text_cloudformation_would_give_it(
    #[case] content: &str,
    #[case] expected: &str,
) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let ((name, ..), _) = map.first().expect("the key is present");

    assert_eq!(expected, name, "for the document {:?}", content);

    Ok(())
}

/// The refusal says how many documents the stream holds, not merely that it holds more than one.
///
/// "More than one" leaves the reader to find out whether they have two documents or twenty. Counting
/// means draining the rest of the stream, and the rest may not parse -- a file whose *later* document
/// is not YAML is one of the shapes this refusal exists for -- so the count degrades to a lower bound
/// rather than to a syntax error from further down the file, which would replace a message about
/// document structure with one about the wrong thing.
#[rstest::rstest]
#[case::two("a: 1\n---\nb: 2\n", "holds 2")]
#[case::three("a: 1\n---\nb: 2\n---\nc: 3\n", "holds 3")]
#[case::five("a: 1\n---\nb: 2\n---\nc: 3\n---\nd: 4\n---\ne: 5\n", "holds 5")]
#[case::a_later_document_that_does_not_parse(
    "a: 1\n---\nb: [ this is : not valid yaml {{{\n---\nc: 3\n",
    "holds at least 2"
)]
fn the_multiple_document_refusal_counts_them(#[case] content: &str, #[case] expected: &str) {
    let loaded = Loader::new().load(content.to_string());

    let message = match loaded {
        Err(Error::UnsupportedDocument(message)) => message,
        other => panic!(
            "{:?} gave {:?}, not the multiple-document error",
            content, other
        ),
    };

    assert!(
        message.contains(expected),
        "the refusal for {:?} was {:?}, which does not say it {:?}",
        content,
        message,
        expected
    );
}

/// The five line breaks libyaml recognizes, from `IS_BREAK_AT!` in `unsafe-libyaml/src/macros.rs`.
///
/// `Cargo.toml` asks for `0.2.10` and `Cargo.lock` resolves `0.2.11`; `macros.rs` is byte-identical
/// between the two, so this list holds for the version actually compiled.
const LINE_BREAKS: [(&str, &str, &[u8]); 6] = [
    ("LF", "\n", &[0x0A]),
    ("CRLF", "\r\n", &[0x0D, 0x0A]),
    ("bare CR", "\r", &[0x0D]),
    ("NEL U+0085", "\u{0085}", &[0xC2, 0x85]),
    ("LS U+2028", "\u{2028}", &[0xE2, 0x80, 0xA8]),
    ("PS U+2029", "\u{2029}", &[0xE2, 0x80, 0xA9]),
];

/// The deepest line any node in `value` was loaded from.
fn deepest_line(value: &MarkedValue) -> usize {
    let mut deepest = value.location().line;
    match value {
        MarkedValue::List(items, _) => {
            for item in items {
                deepest = deepest.max(deepest_line(item));
            }
        }
        MarkedValue::Map(entries, _) => {
            for ((_, key_location), item) in entries {
                deepest = deepest.max(key_location.line).max(deepest_line(item));
            }
        }
        _ => {}
    }
    deepest
}

/// The two halves of a report agree on what a line is, for every line break and every mixture of them.
///
/// This is the property behind a defect that had two separate lives. A position comes from this loader,
/// which counts lines the way libyaml does. The `Code:` excerpt printed beside that position is numbered
/// by `ReadCursor` in `utils/mod.rs`, which counted them its own way. When the two disagree the report is
/// internally inconsistent and there is nothing in it that tells a reader which half to believe: the
/// loader said `Encrypted[L:6,C:18]` and the excerpt labelled the same text `5.`, with two lines' worth
/// of it merged onto one and the separator invisible in a terminal.
///
/// Stated as a property rather than as a list of cases, because the list is what went wrong twice.
/// `ReadCursor` first counted one break, then three, and both times the code beside it read as complete
/// -- the second time with a doc comment that named the three it handled, which is the summary that hid
/// the other two. Anchoring on the loader instead means a break this file has never heard of is still
/// caught, as long as libyaml counts it.
///
/// The document is shaped so the assertion is meaningful: its last line carries a scalar, so the deepest
/// line the loader reports is the file's last line, and that is the number the excerpt's last line must
/// match. A document ending in a comment or a blank line would make the two legitimately differ and the
/// property would not be a property.
///
/// `deepest_line` reads the loader's own marks rather than the rendered `[L:n]` string, so the assertion
/// does not depend on any reporter being reachable from here.
#[test]
fn the_loader_and_the_read_cursor_agree_on_the_line_count() -> Result<()> {
    // Six logical lines with the interesting value on the last one, which is the shape that made the
    // disagreement visible: `emit_code` seeks two lines above the violation and reads five more, so on a
    // six-line file the excerpt's last line is the violation's own.
    let lines = [
        "Resources:",
        "  One:",
        "    Type: AWS::S3::Bucket",
        "    Properties:",
        "      Tags: []",
        "      Encrypted: false",
    ];

    // Every uniform document, every document holding exactly one non-LF break among LF ones, and every
    // document ending in a terminator. The single-break case is the one worth naming: a lone `U+2028` in
    // an otherwise-LF file is a routine artifact of JavaScript tooling, and its output looks plausible
    // rather than broken.
    let mut documents: Vec<(String, String)> = Vec::new();
    for (spelling, separator, bytes) in LINE_BREAKS {
        assert_eq!(
            bytes,
            separator.as_bytes(),
            "{} is not the bytes it claims to be -- a mistyped separator reads as a different defect",
            spelling
        );

        documents.push((
            format!("uniform {}", spelling),
            lines.join(separator).to_string(),
        ));
        documents.push((
            format!("uniform {} with a final terminator", spelling),
            format!("{}{}", lines.join(separator), separator),
        ));

        for at in 0..lines.len() - 1 {
            let mut document = String::new();
            for (index, line) in lines.iter().enumerate() {
                if index > 0 {
                    document.push_str(if index - 1 == at { separator } else { "\n" });
                }
                document.push_str(line);
            }
            documents.push((
                format!("a lone {} after line {}", spelling, at + 1),
                document,
            ));
        }
    }

    for (description, document) in documents {
        let loaded = Loader::new().load(document.clone())?;
        let reported = deepest_line(&loaded);

        let mut cursor = crate::utils::ReadCursor::new(&document);
        let mut excerpt_last = 0;
        while let Some((number, _)) = cursor.next() {
            excerpt_last = number;
        }

        assert_eq!(
            reported,
            excerpt_last,
            "{}: the loader reported L:{} and the excerpt's last line is numbered {}. Bytes: {:?}",
            description,
            reported,
            excerpt_last,
            document.as_bytes()
        );
        assert_eq!(
            lines.len(),
            excerpt_last,
            "{}: and both should be {} lines",
            description,
            lines.len()
        );
    }

    Ok(())
}

/// A libyaml failure is reported with its problem text and where the parser stopped, in the three
/// shapes libyaml records: a scanner failure with its mark alone, a parser failure with the mark and
/// the construct it was inside, and a reader failure, which has no mark.
///
/// libyaml's reader decodes the text ahead of the scanner and records a character it will not accept
/// by its byte offset and its value, leaving `problem_mark` at zero, so rendering the mark put every
/// raw control character at `L:1,C:1` however deep in the file it sat. The position is computed from
/// the offset instead, counting line breaks the way the loader does, which the CRLF row checks, and
/// the character is named.
#[rstest::rstest]
#[case::a_scanner_failure(
    "a: b: c\n",
    "error parsing file: mapping values are not allowed in this context at L:1,C:5"
)]
#[case::a_parser_failure_with_its_context(
    "A: [1, 2\n",
    "error parsing file: did not find expected ',' or ']' at L:2,C:1, while parsing a flow sequence that starts at L:1,C:4"
)]
#[case::a_reader_failure_on_a_control_character(
    "A: 1\nB: 2\nC: 3\nD: 4\nE: \x1b\n",
    "error parsing file: control characters are not allowed (#x1B) at L:5,C:4"
)]
#[case::a_reader_failure_after_crlf_lines(
    "A: 1\r\nB: \x07\r\n",
    "error parsing file: control characters are not allowed (#x7) at L:2,C:4"
)]
fn a_parse_failure_names_libyamls_problem_and_where_it_stopped(
    #[case] text: &str,
    #[case] expected: &str,
) {
    let mut parser = Parser::new(Cow::Borrowed(text.as_bytes()));
    let failure = loop {
        match parser.next() {
            Ok((Event::StreamEnd, _)) => {
                panic!("{:?} parsed to the end without a failure", text)
            }
            Ok(_) => continue,
            Err(failure) => break failure,
        }
    };
    match failure {
        Error::ParseError(message) => assert_eq!(expected, message),
        other => panic!("a libyaml failure is a ParseError, got {:?}", other),
    }
}

/// What a payload under an explicit `!!int` loads as, for the test below: the integer, a refusal
/// holding the node as written, or the leading-zero refusal, which goes on to the given hint.
#[derive(Clone, Copy)]
enum Tagged {
    Int(i64),
    Refused,
    LeadingZero(&'static str),
}

/// An explicit `!!int` resolves by the same forms as a plain scalar, and is refused otherwise.
///
/// This arm was `str::parse::<i64>`, decimal only, after the plain arm had moved to `resolve_int`. So
/// `Mode: !!int 0o755` was a `BadValue` and the whole file was refused at exit 5, while the same
/// document with the tag removed loaded as 493 and the rules ran: making the type explicit is what
/// broke a valid YAML 1.2 document. The two arms now share one resolver.
///
/// A payload no integer form reads -- a word, a float, an integer wider than `i64` -- is refused
/// under the tag, as `!!int abc` always was. An explicit type tag has no string to fall back to.
///
/// A decimal with a redundant leading zero is refused under the tag when the two YAML versions read
/// it as two different numbers, and loads when they agree. YAML 1.1 reads `0755` as octal 493 and
/// YAML 1.2 core as decimal 755; CloudFormation reads YAML 1.1, this loader reads 1.2, and the tag
/// says the node is an integer without saying which radix the digits are in. So `0755` is refused,
/// with a reason beside the text naming both readings and, as plain decimal, the integer each one
/// means: 493 if the octal was meant, 755 if the decimal was. The `0o755` spelling is not named at
/// all, because a YAML 1.1 reader has no `0o` form and reads it as a string, so offering it would
/// recommend the one spelling that diverges silently between the two readers (the KNOWN_ISSUES
/// entry warns against writing it). `007`, `+007`, `-007`, `00` and `-00`
/// are the same integer under both readings, so they load; `08` and `-08` have a digit YAML 1.1's
/// octal cannot hold, so 1.1 reads no integer there at all, and they are refused with that said.
///
/// This arm once read every leading-zero payload as a signed decimal, so `!!int 0755` loaded as 755
/// with nothing said; then it refused the whole class, `007` included, with a hint that recommended
/// `0o755`. The untagged rule is not touched by any of this: a plain `0755` stays the string "0755".
///
/// Every integer the reason offers is the result of reading a candidate spelling back through
/// `resolve_int` first, so nothing is offered that would not load: a reading too wide for an `i64`
/// is named as such instead. The wide rows pin both ends: 21 sevens read as octal are exactly
/// `i64::MAX`, and a 1 with 21 zeros under a minus sign is exactly `i64::MIN`, a magnitude that fits
/// only because of the sign, while both decimal readings are too wide; a leading 1 without the sign
/// makes both readings too wide; and a run of nines has only a decimal reading, which is too wide.
/// Under both refusal policies the answer is the same `BadValue`: it is a scalar's own text, not a
/// `Refused` node, so the policy does not change it.
///
/// The edges of the rule: `0`, `-0` and `+0` are a lone zero and load; `+0755` is refused like
/// `-0755`, the sign kept in the integers it offers; a quoted `"0755"` reaches the arm as the same
/// text (libyaml drops the quotes, as it does for the quoted `"312"` that resolves) and is refused
/// the same way.
#[rstest::rstest]
#[case::decimal("7", Tagged::Int(7))]
#[case::zero("0", Tagged::Int(0))]
#[case::negative_zero("-0", Tagged::Int(0))]
#[case::positive_zero("+0", Tagged::Int(0))]
#[case::ten("10", Tagged::Int(10))]
#[case::octal("0o755", Tagged::Int(493))]
#[case::hex("0x1ED", Tagged::Int(493))]
#[case::negative_hex("-0x10", Tagged::Int(-16))]
#[case::quoted_decimal("\"312\"", Tagged::Int(312))]
#[case::a_word("abc", Tagged::Refused)]
#[case::a_float("1.5", Tagged::Refused)]
#[case::a_leading_zero_decimal(
    "0755",
    Tagged::LeadingZero("write 493 if octal 755 was meant, or 755 if decimal was meant")
)]
#[case::a_leading_zero_both_readers_agree_on("007", Tagged::Int(7))]
#[case::a_negative_leading_zero_both_readers_agree_on("-007", Tagged::Int(-7))]
#[case::a_plus_signed_leading_zero_both_readers_agree_on("+007", Tagged::Int(7))]
#[case::a_leading_zero_that_is_not_octal(
    "08",
    Tagged::LeadingZero(
        "write 8 if decimal was meant; YAML 1.1 reads no integer in a leading-zero number with a digit 8 or 9"
    )
)]
#[case::a_negative_leading_zero_that_is_not_octal(
    "-08",
    Tagged::LeadingZero(
        "write -8 if decimal was meant; YAML 1.1 reads no integer in a leading-zero number with a digit 8 or 9"
    )
)]
#[case::a_signed_leading_zero_decimal(
    "-0755",
    Tagged::LeadingZero("write -493 if octal -755 was meant, or -755 if decimal was meant")
)]
#[case::a_plus_signed_leading_zero_decimal(
    "+0755",
    Tagged::LeadingZero("write 493 if octal 755 was meant, or 755 if decimal was meant")
)]
#[case::two_zeros("00", Tagged::Int(0))]
#[case::negative_two_zeros("-00", Tagged::Int(0))]
#[case::a_quoted_leading_zero_decimal(
    "\"0755\"",
    Tagged::LeadingZero("write 493 if octal 755 was meant, or 755 if decimal was meant")
)]
#[case::a_leading_zero_whose_octal_reading_is_the_widest_integer(
    "0777777777777777777777",
    Tagged::LeadingZero(
        "write 9223372036854775807 if octal 777777777777777777777 was meant; the decimal reading is too wide for a 64-bit integer"
    )
)]
#[case::a_leading_zero_whose_octal_reading_is_the_most_negative_integer(
    "-01000000000000000000000",
    Tagged::LeadingZero(
        "write -9223372036854775808 if octal -1000000000000000000000 was meant; the decimal reading is too wide for a 64-bit integer"
    )
)]
#[case::a_leading_zero_whose_octal_reading_fits_and_decimal_does_not(
    "077777777777777777777",
    Tagged::LeadingZero(
        "write 1152921504606846975 if octal 77777777777777777777 was meant; the decimal reading is too wide for a 64-bit integer"
    )
)]
#[case::a_leading_zero_too_wide_under_both_readings(
    "01777777777777777777777",
    Tagged::LeadingZero("both readings are too wide for a 64-bit integer")
)]
#[case::a_leading_one_too_wide_under_both_readings(
    "01000000000000000000000",
    Tagged::LeadingZero("both readings are too wide for a 64-bit integer")
)]
#[case::twenty_nines_too_wide_as_decimal_with_no_octal_reading(
    "099999999999999999999",
    Tagged::LeadingZero(
        "the decimal reading is too wide for a 64-bit integer, and YAML 1.1 reads no integer in a leading-zero number with a digit 8 or 9"
    )
)]
#[case::a_leading_zero_too_wide_as_decimal_with_no_octal_reading(
    "0999999999999999999999",
    Tagged::LeadingZero(
        "the decimal reading is too wide for a 64-bit integer, and YAML 1.1 reads no integer in a leading-zero number with a digit 8 or 9"
    )
)]
#[case::wider_than_i64("9223372036854775808", Tagged::Refused)]
fn an_explicitly_tagged_int_resolves_by_the_same_forms_as_a_plain_one(
    #[case] scalar: &str,
    #[case] expected: Tagged,
) -> Result<()> {
    // libyaml hands the arm the scalar without its quotes, so a quoted payload is read, and refused,
    // by its text.
    let written = format!("!!int {}", scalar.trim_matches('"'));

    for refusals in [RefusalPolicy::RefuseDocument, RefusalPolicy::MarkBadValue] {
        let value = Loader::new()
            .with_refusals(refusals)
            .load(format!("check: !!int {scalar}"))?;

        let map = match &value {
            MarkedValue::Map(m, ..) => m,
            other => unreachable!("a single mapping loads as a map, got {:?}", other),
        };
        let (.., loaded) = map.first().expect("the key is present");

        // The text of every refusal is the node as written and nothing more; the leading-zero
        // refusal carries its explanation beside the text, as a reason, so that the places which
        // render a `BadValue`'s text alone (a key refusal, a test-case field, a document comparison)
        // still show the scalar the document wrote.
        // The reason is compared as rendered, since what it holds is data and what the author
        // reads is the sentence built from it.
        let expected_reason = match expected {
            Tagged::Int(n) => {
                assert!(
                    matches!(loaded, MarkedValue::Int(i, ..) if *i == n),
                    "under {:?}, !!int {} loaded as {:?}, not the integer {}",
                    refusals,
                    scalar,
                    loaded,
                    n
                );
                continue;
            }
            Tagged::Refused => None,
            Tagged::LeadingZero(hint) => Some((
                "a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2",
                String::from(hint),
            )),
        };
        let rendered = match loaded {
            MarkedValue::BadValue(v, r, ..) if *v == written => {
                r.as_ref().map(|r| (r.why(), r.fix()))
            }
            other => panic!(
                "under {:?}, !!int {} loaded as {:?}, not a BadValue holding {:?}",
                refusals, scalar, other, written
            ),
        };
        assert_eq!(
            expected_reason, rendered,
            "under {:?}, the reason beside !!int {}",
            refusals, scalar
        );
    }

    Ok(())
}

/// An explicit `!!float` is gated the way a plain one is: finite, and not an underflow to zero.
///
/// This arm was `str::parse::<f64>` with no check on the answer. `f64::from_str` accepts `nan`, `inf`
/// and `infinity`, so `!!float nan` built a `Float(NaN)`, which `PathAwareValue` cannot hold and no
/// reporter can serialize: `validate` printed its verdict and then exited 255 on "Could not convert
/// float NaN to serde::Value::Number", and `-o json` stopped mid-document. `!!float inf` passed
/// `!= 1.0`. At the other end of the exponent range, `1e-400` parses to a silent `0.0`, so
/// `!!float 1e-400` answered `== 0` with a PASS for a literal the author wrote as positive -- the
/// defect `underflowed_to_zero` was written for, reached through the one arm it was not applied to.
///
/// A payload that fails the gate is a `BadValue`, not a string. The untagged arm falls back to the
/// literal text; under an explicit `!!float` there is nothing to fall back to. YAML's own `.inf` and
/// `.nan` spellings already came out as `BadValue` here, because `f64::from_str` does not read them,
/// so a non-finite float is now refused under the tag however it is spelled. The finite cases are the
/// control, with the genuine zeros and a subnormal among them so the gate is known to refuse only
/// what it is meant to.
#[rstest::rstest]
#[case::nan("nan", None)]
#[case::capitalized_nan("NaN", None)]
#[case::inf("inf", None)]
#[case::negative_inf("-inf", None)]
#[case::infinity("infinity", None)]
#[case::yaml_negative_inf("-.inf", None)]
#[case::overflow("1e999", None)]
#[case::underflow("1e-400", None)]
#[case::negative_underflow("-1e-400", None)]
#[case::a_word("abc", None)]
#[case::ordinary("1.5", Some(1.5))]
#[case::negative("-2.25", Some(-2.25))]
#[case::exponent("1e3", Some(1000.0))]
#[case::genuine_zero("0.0", Some(0.0))]
#[case::zero_with_a_big_exponent("0e400", Some(0.0))]
#[case::subnormal("1e-320", Some(1e-320))]
fn an_explicitly_tagged_float_is_gated_like_a_plain_one(
    #[case] scalar: &str,
    #[case] expected: Option<f64>,
) -> Result<()> {
    let value = Loader::new().load(format!("check: !!float {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    match expected {
        Some(f) => assert!(
            matches!(loaded, MarkedValue::Float(v, ..) if *v == f),
            "!!float {} loaded as {:?}, not the float {}",
            scalar,
            loaded,
            f
        ),
        None => {
            let written = format!("!!float {scalar}");
            assert!(
                matches!(loaded, MarkedValue::BadValue(v, ..) if *v == written),
                "!!float {} loaded as {:?}, not a BadValue holding {:?}",
                scalar,
                loaded,
                written
            )
        }
    }

    Ok(())
}

/// An explicit `!!null` takes the YAML 1.2 core null spellings and refuses everything else.
///
/// This arm returned `Null` without reading its payload, so `IsLogging: !!null false` was a null and
/// the `false` was gone, with no diagnostic and no way to recover the author's text from any output:
/// a rule `IsLogging == false` reported "not comparable null, bool" where the untagged `false`
/// compared. The sibling arms each read their payload and answer `BadValue` on a miss -- `!!bool abc`
/// and `!!int abc` are both refused -- and this was the one tag that accepted anything.
///
/// The set is `null | Null | NULL | ~` and the empty scalar, by exact spelling, which is what the
/// core schema resolves (<https://yaml.org/spec/1.2.2/#103-core-schema>). A quoted payload in the set
/// is still a null: the tag decides the type, the quotes only the style.
#[rstest::rstest]
#[case::nothing_after_the_tag("", true)]
#[case::a_tilde("~", true)]
#[case::the_word("null", true)]
#[case::the_word_capitalized("Null", true)]
#[case::the_word_uppercased("NULL", true)]
#[case::the_word_quoted("\"null\"", true)]
#[case::a_boolean("false", false)]
#[case::a_word("String", false)]
#[case::a_mixed_case_null("nUlL", false)]
#[case::a_number("0", false)]
fn an_explicit_null_tag_takes_only_the_null_spellings(
    #[case] scalar: &str,
    #[case] expected_null: bool,
) -> Result<()> {
    let value = Loader::new().load(format!("check: !!null {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    if expected_null {
        assert!(
            matches!(loaded, MarkedValue::Null(..)),
            "!!null {} loaded as {:?}, not the null node",
            scalar,
            loaded
        );
    } else {
        let written = format!("!!null {scalar}");
        assert!(
            matches!(loaded, MarkedValue::BadValue(v, ..) if *v == written),
            "!!null {} loaded as {:?}, not a BadValue holding {:?}",
            scalar,
            loaded,
            written
        );
    }

    Ok(())
}

/// A `!!` type tag the loader does not know is refused, and the report names the tag.
///
/// `handle_type_ref`'s fallthrough was `_ => String`, so an unrecognized `tag:yaml.org,2002:*` was
/// dropped and its payload evaluated as a plain string. `RoleName: !!Ref Foo` -- a typo of `!Ref Foo`
/// -- loaded as "Foo", a rule `RoleName == "Foo"` passed at exit 0, and nothing in any output said a
/// tag had been written. Every other route was already loud or faithful: an unknown `!Foo` is kept
/// as `Fn::Foo` (see `a_tagged_value_keeps_its_function_name`) and a known `!!` tag over a bad
/// payload is a `BadValue`. This was the one silent route left.
///
/// The `BadValue` carries the tag as the document spelled it, not the payload alone: `Value = Foo`
/// would not say what was wrong with `!!Ref Foo`.
///
/// Only a tag that reads as an intrinsic written with one `!` too many is refused: a suffix starting
/// with an ASCII uppercase letter, or one the short-form table knows. A tag from another YAML
/// dialect's namespace -- `!!python/name:x` -- is not a typo of anything cfn-guard reads, and a
/// `-d .` walk over a directory holding such a file should not stop on it, so it loads as text with a
/// one-line warning on stderr naming the tag. The yaml.org types whose scalar *is* a string -- `str`,
/// and the 1.1 types `binary` and `timestamp`, whose text is the honest reading when the loader does
/// not decode them -- are the control and still load as strings without a warning.
///
/// The boundary is spelled out by `!!ref Foo`: CloudFormation's intrinsics are capitalized and so is
/// every name in the short-form table, so a lowercase `ref` spells no intrinsic and is warned, not
/// refused.
#[rstest::rstest]
#[case::a_function_name_with_two_bangs("!!Ref Foo", None)]
#[case::a_miscased_known_type("!!Str Foo", None)]
#[case::a_sequence_intrinsic_on_a_scalar("!!If x", None)]
#[case::an_unknown_type_with_no_payload("!!Ref", None)]
#[case::str_over_a_word("!!str Foo", Some("Foo"))]
#[case::str_over_a_number("!!str 123", Some("123"))]
#[case::binary("!!binary aGk=", Some("aGk="))]
#[case::timestamp("!!timestamp 2001-12-14", Some("2001-12-14"))]
#[case::a_foreign_namespace("!!python/name:x", Some(""))]
#[case::a_foreign_namespace_with_a_payload("!!python/str Foo", Some("Foo"))]
#[case::a_collection_type_on_a_scalar("!!seq a", Some("a"))]
#[case::a_lowercase_intrinsic_spelling_is_warned_not_refused("!!ref Foo", Some("Foo"))]
fn an_unknown_type_tag_is_refused_with_the_tag_named(
    #[case] scalar: &str,
    #[case] expected_string: Option<&str>,
) -> Result<()> {
    let value = Loader::new().load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    match expected_string {
        Some(s) => assert!(
            matches!(loaded, MarkedValue::String(v, ..) if v == s),
            "{} loaded as {:?}, not the string {:?}",
            scalar,
            loaded,
            s
        ),
        None => assert!(
            matches!(loaded, MarkedValue::BadValue(v, ..) if v == scalar),
            "{} loaded as {:?}, not a BadValue naming the tag",
            scalar,
            loaded
        ),
    }

    Ok(())
}

/// An intrinsic name under a `!!` tag on a sequence or mapping refuses the document, naming the tag,
/// under `RefusalPolicy::RefuseDocument`, which is the data-file loader's policy.
///
/// `!!If [IsProd, a, b]` is `!If` with one `!` too many. The scalar form of the typo becomes a
/// `BadValue` that the file-level report names; a container has no such slot, and `push_tag_wrapper`
/// read only `!` handles, so the tag was dropped and the sequence loaded as a bare list. A rule reading
/// `Fn::If` found nothing and the typo was invisible. The yaml.org collection tags (`!!seq`, `!!map`)
/// are not intrinsic names and still pass through silently, a foreign namespace (`!!python/dict`)
/// passes through with the same one-line stderr warning its scalar form gets, and `!If` with one `!`
/// still wraps. What the same tag costs under the spec-file loader's policy is
/// [`a_spec_loader_marks_an_intrinsic_name_under_a_type_tag_on_a_container`].
#[rstest::rstest]
#[case::if_over_a_sequence("v: !!If [IsProd, a, b]", Some("!!If"))]
#[case::join_over_a_sequence("v: !!Join [\",\", [a, b]]", Some("!!Join"))]
#[case::equals_over_a_mapping("v: !!Equals { a: b }", Some("!!Equals"))]
#[case::seq_passes_through("v: !!seq [a, b]", None)]
#[case::map_passes_through("v: !!map { a: b }", None)]
#[case::a_foreign_namespace_passes_through_with_a_warning("v: !!python/dict { a: b }", None)]
#[case::one_bang_still_wraps("v: !If [IsProd, a, b]", None)]
fn an_intrinsic_name_under_a_type_tag_on_a_container_is_refused(
    #[case] content: &str,
    #[case] refused_tag: Option<&str>,
) {
    let result = Loader::new().load(content.to_string());

    match refused_tag {
        Some(tag) => {
            let message = match result {
                Err(err) => err.to_string(),
                Ok(loaded) => panic!(
                    "{:?} loaded as {:?} instead of being refused",
                    content, loaded
                ),
            };
            assert!(
                message.contains(tag) && message.contains("L:1,C:4"),
                "{:?} was refused, but the message names neither the tag nor its position: {}",
                content,
                message
            );
        }
        None => {
            result.unwrap_or_else(|err| panic!("{:?} was refused: {}", content, err));
        }
    }
}

/// Under `RefusalPolicy::MarkBadValue`, the spec-file loader's policy, an intrinsic name under a `!!`
/// tag on a container costs the one node and not the document.
///
/// `push_tag_wrapper` returned the refusal as an error and the container's start handler passed it up
/// with `?`, so it never reached `refuse_node` and the policy was never asked: a `!!If [IsProd, a, b]`
/// inside one case's `input:` refused the whole test file, with every other case lost to it, while the
/// scalar typo `!!Ref Foo` in the same position becomes a `BadValue` and fails only its case. The
/// container now loads as a `Refused` node carrying the message, with the tag and its position in it,
/// and the entries around it are read as they were written. The same tag on the same document under
/// `Loader::new()` is still a refusal of the document
/// ([`an_intrinsic_name_under_a_type_tag_on_a_container_is_refused`]).
#[rstest::rstest]
#[case::if_over_a_sequence("!!If [IsProd, a, b]", "!!If")]
#[case::join_over_a_nested_sequence("!!Join [\",\", [a, b]]", "!!Join")]
#[case::equals_over_a_mapping("!!Equals { a: b }", "!!Equals")]
#[case::sub_over_a_mapping_holding_a_tagged_scalar("!!Sub { k: !Ref Foo }", "!!Sub")]
#[case::a_block_sequence("!!If\n  - IsProd\n  - a\n  - b", "!!If")]
#[case::nested_in_another_refused_sequence("!!If [!!If [a], b]", "!!If")]
#[case::nested_in_a_refused_mapping("!!Equals { k: !!If [a] }", "!!Equals")]
fn a_spec_loader_marks_an_intrinsic_name_under_a_type_tag_on_a_container(
    #[case] body: &str,
    #[case] tag: &str,
) {
    let text = format!("before: 1\nv: {body}\nafter: 2\n");
    let mut loader = Loader::for_spec_file();
    let value = loader.load(text.clone()).unwrap_or_else(|err| {
        panic!(
            "{:?}: a refused node is marked, not a refusal of the document: {}",
            text, err
        )
    });

    match entry(&value, "v") {
        MarkedValue::Refused(message, location) => {
            assert!(
                message.contains(tag) && message.contains("L:2,C:4"),
                "{:?}: the refusal names neither the tag nor its position:\n{}",
                text,
                message
            );
            assert_eq!(
                *location,
                Location { line: 2, col: 4 },
                "{:?}: the `Refused` node sits where the container was written",
                text
            );
        }
        other => panic!("{:?}: `v` must be marked unreadable, got {:?}", text, other),
    }
    assert!(
        matches!(entry(&value, "before"), MarkedValue::Int(1, _)),
        "{:?}: the entry before the refused container must be intact, got {:?}",
        text,
        entry(&value, "before")
    );
    assert!(
        matches!(entry(&value, "after"), MarkedValue::Int(2, _)),
        "{:?}: the entry after the refused container must be intact, got {:?}",
        text,
        entry(&value, "after")
    );
}

/// The shape the policy exists for: a `!!`-tagged container inside one case of a test file is that
/// case's mistake, and the other cases are read whole.
#[test]
fn a_spec_loader_keeps_the_cases_around_a_type_tagged_container() {
    let text = "\
- name: first
  input:
    Cond: !!If [IsProd, a, b]
  expectations: {rules: {r: PASS}}
- name: second
  input: {Cond: ok}
  expectations: {rules: {r: PASS}}
";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text.to_string())
        .expect("a refused node is marked, not a refusal of the document");

    let MarkedValue::List(cases, _) = &value else {
        panic!("a sequence of cases loads as a list, got {:?}", value);
    };
    assert_eq!(cases.len(), 2, "both cases are kept: {:?}", cases);

    match entry(entry(&cases[0], "input"), "Cond") {
        MarkedValue::Refused(message, _) => assert!(
            message.contains("!!If") && message.contains("L:3,C:11"),
            "the refusal names neither the tag nor its position:\n{}",
            message
        ),
        other => panic!(
            "the first case's `Cond` must be marked unreadable, got {:?}",
            other
        ),
    }
    assert!(
        matches!(entry(&cases[0], "name"), MarkedValue::String(name, _) if name == "first"),
        "the first case's other fields are intact: {:?}",
        cases[0]
    );
    assert!(
        matches!(entry(entry(&cases[1], "input"), "Cond"), MarkedValue::String(s, _) if s == "ok"),
        "the second case is read as written: {:?}",
        cases[1]
    );
}

/// A refused `!!` container inside a `!Foo` wrapper: the wrapper still wraps, and holds the `Refused`
/// node where the container was.
///
/// `push_tag_wrapper` puts the `!Sub` wrapper below its sequence and records it in
/// `func_support_index`; the inner `!!If` records nothing there and a pending refusal instead. When
/// the inner sequence closes, `close_tagged_container` must not take the outer wrapper for the inner
/// container's, and when the outer closes it must still find its wrapper one below. The two indices
/// are kept apart, and this pins that a change to either one's matching cannot make them collide.
#[test]
fn a_spec_loader_keeps_the_wrapper_around_a_refused_type_tagged_container() {
    let text = "v: !Sub [\"${A}\", !!If [a], last]\n";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text.to_string())
        .expect("a refused node is marked, not a refusal of the document");

    let items = match entry(&value, "v") {
        MarkedValue::Map(m, _) => match m.iter().next() {
            Some(((name, _), MarkedValue::List(items, _))) if name == "Fn::Sub" => items,
            other => panic!("`v` must be `Fn::Sub` over a list, got {:?}", other),
        },
        other => panic!("`v` must be the `!Sub` wrapper, got {:?}", other),
    };
    assert_eq!(
        3,
        items.len(),
        "every item of the wrapped list is kept: {:?}",
        items
    );
    assert!(
        matches!(&items[0], MarkedValue::String(s, _) if s == "${A}"),
        "the item before the refused container is intact: {:?}",
        items[0]
    );
    assert!(
        matches!(&items[1], MarkedValue::Refused(m, _) if m.contains("!!If") && m.contains("L:1,C:18")),
        "the refused container is marked where it was written: {:?}",
        items[1]
    );
    assert!(
        matches!(&items[2], MarkedValue::String(s, _) if s == "last"),
        "the item after the refused container is intact: {:?}",
        items[2]
    );
}

/// An anchor written on a refused `!!` container names the `Refused` node, so an alias to it copies
/// the refusal.
///
/// `refuse_pending_tag` runs before `remember_anchored_container`, which records whatever is then on
/// top of the stack. Were the order reversed, the anchor would hold the bare list and `*x` would read
/// as `[a]` while `v` is unreadable: the same bytes, two different values.
#[test]
fn a_spec_loader_aliases_a_refused_type_tagged_container_as_the_refusal() {
    let text = "v: &x !!If [a]\nw: *x\nz: 1\n";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text.to_string())
        .expect("a refused node is marked, not a refusal of the document");

    let message = match entry(&value, "v") {
        MarkedValue::Refused(m, _) => m,
        other => panic!("`v` must be marked unreadable, got {:?}", other),
    };
    // The node's position is where its anchor is written, as for every anchored node.
    assert!(
        message.contains("!!If") && message.contains("L:1,C:4"),
        "the refusal names the tag and its position:\n{}",
        message
    );
    match entry(&value, "w") {
        MarkedValue::Refused(copied, _) => assert_eq!(
            message, copied,
            "the alias copies the anchored refusal, message included"
        ),
        other => panic!("`w` must be the copied refusal, got {:?}", other),
    }
    assert!(
        matches!(entry(&value, "z"), MarkedValue::Int(1, _)),
        "the entry after the alias is intact: {:?}",
        entry(&value, "z")
    );
}

/// A `!!`-tagged mapping that `fill_mapping` refuses as well keeps the tag refusal.
///
/// `handle_mapping_end` lets `fill_mapping` refuse the mapping first (here for its null key) and then
/// `refuse_pending_tag` replaces that `Refused` node with the tag's. The doc comment there says the
/// tag wins because it sits on the container that holds the keys; this pins the order.
#[test]
fn a_spec_loader_keeps_the_tag_refusal_over_a_key_refusal_of_the_same_mapping() {
    let text = "v: !!Equals {null: 1}\nafter: 2\n";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text.to_string())
        .expect("a refused node is marked, not a refusal of the document");
    match entry(&value, "v") {
        MarkedValue::Refused(m, _) => assert!(
            m.contains("!!Equals") && !m.contains("key is null"),
            "the tag refusal must stand, not the key refusal:\n{}",
            m
        ),
        other => panic!("`v` must be marked unreadable, got {:?}", other),
    }
    assert!(
        matches!(entry(&value, "after"), MarkedValue::Int(2, _)),
        "the entry after the refused mapping is intact: {:?}",
        entry(&value, "after")
    );
}

/// A `!!`-tagged container as the whole document loads as a `Refused` root under the spec loader.
///
/// The spec reader then refuses the file, because a root that is not a sequence of cases leaves
/// nothing to run; what this pins is that the loader hands it that `Refused` node with the tag's
/// message rather than refusing the document itself, so the file-level error can name the tag. The
/// data-file loader still refuses the document outright.
#[test]
fn a_spec_loader_marks_a_type_tagged_root_container() {
    let text = "!!If [a]\n";
    let mut loader = Loader::for_spec_file();
    let value = loader
        .load(text.to_string())
        .expect("a refused node is marked, not a refusal of the document");
    match &value {
        MarkedValue::Refused(m, location) => {
            assert!(
                m.contains("!!If") && m.contains("L:1,C:1"),
                "the root refusal names the tag and its position:\n{}",
                m
            );
            assert_eq!(&Location { line: 1, col: 1 }, location);
        }
        other => panic!("the root must be marked unreadable, got {:?}", other),
    }

    let refused = Loader::new().load(text.to_string());
    assert!(
        matches!(&refused, Err(err) if err.to_string().contains("!!If")),
        "the data-file loader still refuses the document: {:?}",
        refused
    );
}

/// An explicit `!!merge` over `<<` is a merge key whatever its style, and over anything else is
/// refused.
///
/// The merge type is what a plain `<<` resolves to implicitly, so the tag written out is the same
/// key said explicitly, and it is the one spelling that makes a *quoted* `<<` a merge key. The merge
/// index was decided on `tag.is_none()`, so `!!merge <<` fell through as an ordinary key named `<<`
/// and everything under it was hidden. `!!merge` over any other text names a type the payload cannot
/// be, as `!!bool maybe` does, and is refused the same way.
#[rstest::rstest]
#[case::plain("!!merge <<: { a: merged }")]
#[case::quoted("!!merge \"<<\": { a: merged }")]
fn an_explicit_merge_tag_makes_a_merge_key(#[case] body: &str) -> Result<()> {
    let value = Loader::new().load(format!("outer:\n  {body}\n"))?;

    let outer = match &value {
        MarkedValue::Map(m, ..) => match m.first().expect("outer is present").1 {
            MarkedValue::Map(inner, ..) => inner,
            other => panic!("outer held {:?}", other),
        },
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };

    assert!(
        !outer.keys().any(|(name, _)| name == "<<"),
        "{:?}: the merge key survived as a literal key in {:?}",
        body,
        outer
    );
    let found = outer
        .iter()
        .find(|((name, _), _)| name == "a")
        .map(|(_, v)| v);
    assert!(
        matches!(found, Some(MarkedValue::String(s, ..)) if s == "merged"),
        "{:?} gave a = {:?}, not \"merged\"",
        body,
        found
    );

    Ok(())
}

/// A `!!` tag read past is reported in the loader's result, one entry per tagged node with its
/// position, and nothing is written to stderr by the loader itself.
///
/// The warning was an `eprintln!` in the loader, which reached every caller's process stderr --
/// library callers included -- and could be neither captured nor carried in a report. It is a value
/// now: `take_warnings` hands the list to whoever loaded the document, `validate` and `test` print it
/// through the command writer beside the duplicate-key warnings, and a library entry point can put it
/// in its report. The lowercase `!!ref` here is the boundary case: it spells no intrinsic, so it is
/// warned rather than refused, and this is where that one warning is asserted.
#[rstest::rstest]
#[case::a_lowercase_intrinsic_spelling("check: !!ref Foo", vec![("ref", 1, 8)])]
#[case::a_foreign_namespace("check: !!python/name:x", vec![("python/name:x", 1, 8)])]
#[case::one_warning_per_node(
    "A: !!python/str Foo\nB:\n  !!python/list\n  - !!python/str a\n",
    vec![("python/str", 1, 4), ("python/list", 3, 3), ("python/str", 4, 5)]
)]
#[case::a_known_type_says_nothing("check: !!str Foo", vec![])]
#[case::a_collection_type_on_a_container_says_nothing("check: !!seq [a, b]", vec![])]
fn a_tag_read_past_is_reported_in_the_result_not_on_stderr(
    #[case] content: &str,
    #[case] expected: Vec<(&str, usize, usize)>,
) -> Result<()> {
    let mut loader = Loader::new();
    loader.load(content.to_string())?;

    let warnings: Vec<(String, usize, usize)> = loader
        .take_warnings()
        .into_iter()
        .map(|w| (w.tag, w.location.line, w.location.col))
        .collect();
    let expected: Vec<(String, usize, usize)> = expected
        .into_iter()
        .map(|(tag, line, col)| (tag.to_string(), line, col))
        .collect();

    assert_eq!(expected, warnings, "{:?} reported {:?}", content, warnings);
    assert!(
        loader.take_warnings().is_empty(),
        "take_warnings hands the list over once"
    );

    Ok(())
}

#[test]
fn a_merge_tag_over_anything_but_the_merge_key_is_refused() -> Result<()> {
    let value = Loader::new().load("check: !!merge foo".to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    assert!(
        matches!(loaded, MarkedValue::BadValue(v, ..) if v == "!!merge foo"),
        "!!merge foo loaded as {:?}, not a BadValue naming the tag",
        loaded
    );

    Ok(())
}

/// A plain scalar is null only in the YAML 1.2 core spellings, by exact case.
///
/// YAML 1.2 core resolves `null | Null | NULL | ~` (<https://yaml.org/spec/1.2.2/#103-core-schema>)
/// and nothing else, so `nUlL` and `NuLL` are strings, as `serde_yaml` reads them on the same bytes.
/// The boolean arm beside the null arm is narrowed to three casings on purpose, with the note that
/// matching case-insensitively "would have accepted spellings no schema makes boolean"; a null arm
/// that lowercased the scalar before matching would make null the one scalar resolved that way, and a
/// `Tag is_null` clause would answer differently here and under a loader that agrees with the schema.
///
/// The canonical spellings are the control: they must still be null, or the fix narrowed too far. The
/// mixed-case cases are named for their casing in words, because rstest makes a function of each case
/// name and a spelling like `nUlL` in one is a `non_snake_case` error under `-D warnings`.
#[rstest::rstest]
#[case::lowercase("null", true)]
#[case::capitalized("Null", true)]
#[case::uppercase("NULL", true)]
#[case::a_tilde("~", true)]
#[case::alternating_case("nUlL", false)]
#[case::capitalized_first_and_last_two("NuLL", false)]
#[case::lowercase_first_letter_only("nULL", false)]
#[case::lowercase_last_letter_only("NULl", false)]
fn a_plain_null_is_resolved_by_exact_case(
    #[case] scalar: &str,
    #[case] expected_null: bool,
) -> Result<()> {
    let value = Loader::new().load(format!("check: {scalar}"))?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a single mapping loads as a map, got {:?}", other),
    };
    let (.., loaded) = map.first().expect("the key is present");

    if expected_null {
        assert!(
            matches!(loaded, MarkedValue::Null(..)),
            "{} loaded as {:?}, but YAML 1.2 core resolves it to the null node",
            scalar,
            loaded
        );
    } else {
        assert!(
            matches!(loaded, MarkedValue::String(s, ..) if s == scalar),
            "{} loaded as {:?}, but no schema resolves that casing to null",
            scalar,
            loaded
        );
    }

    Ok(())
}

/// The payload of a `!Tag`-ed scalar is kept as the text the document wrote.
///
/// A node with a specific tag is not implicitly resolved -- the tag *is* its type -- so `!Ref 123`
/// carries the text "123" and a bare `!GetAZs` the empty text, which is what cfn-lint and cfn-flip
/// read too. Typing the payload by the plain-scalar schema was tried, to match what `serde_yaml` gave
/// while `guard test` still read through it; that route reads through this loader now, so the split
/// it was meant to close no longer exists, and the schema reading is the one kept. `!GetAtt` is the one
/// payload read further, into its two-element list.
#[rstest::rstest]
#[case::a_number("v: !Ref 123", "Ref", "123")]
#[case::a_boolean("v: !Ref true", "Ref", "true")]
#[case::a_null_spelling("v: !Ref ~", "Ref", "~")]
#[case::nothing("v: !GetAZs", "Fn::GetAZs", "")]
#[case::a_word("v: !Ref Foo", "Ref", "Foo")]
#[case::a_quoted_number("v: !Ref \"123\"", "Ref", "123")]
fn a_tagged_scalar_payload_keeps_its_text(
    #[case] content: &str,
    #[case] function: &str,
    #[case] expected: &str,
) -> Result<()> {
    let value = Loader::new().load(content.to_string())?;

    let map = match &value {
        MarkedValue::Map(m, ..) => m,
        other => unreachable!("a mapping loads as a map, got {:?}", other),
    };
    let wrapper = match map.first().expect("v is present").1 {
        MarkedValue::Map(inner, ..) => inner,
        other => panic!("{:?} lost its tag and loaded as {:?}", content, other),
    };
    let ((name, ..), payload) = wrapper.first().expect("the function is present");
    assert_eq!(function, name, "{:?} named the function {}", content, name);
    assert!(
        matches!(payload, MarkedValue::String(s, ..) if s == expected),
        "{:?} carried {:?}, not the text {:?}",
        content,
        payload,
        expected
    );

    Ok(())
}

/// A YAML syntax error is reported with libyaml's own description of it and the position libyaml
/// recorded, counted from one as every other position in a report is.
///
/// libyaml records all three on the parser when it fails: the problem text, the mark it occurred
/// at, and for some failures the construct it was inside and where that began. A parser that read
/// none of them and returned the fixed text "error parsing file" would hand a syntax error on line
/// 2500 of a template to the reader as a message holding no position and no description. The
/// cases cover the three places libyaml sets an error from: the scanner and the parser (a mark, and
/// a context when the failure was inside a construct), and the reader (a byte offset and no mark,
/// which this loader converts to a line and column itself, plus the offending character, which is
/// invisible in the message otherwise).
///
/// The reader rows break their lines with a bare CR and a lone LS as well as LF, because the offset
/// is placed against libyaml's five line breaks, not against `\n` alone; counting `\n` only would
/// have put both failures on line 1.
///
/// The first document is 102 bytes, and the second `:` on its last line is at column 18; the
/// expected position is the one serde_yaml reports for the same bytes through the same libyaml, in
/// this loader's `L:n,C:m` form, which is how `parse_failure` renders every position.
#[rstest::rstest]
#[case::scanner_error_carries_its_mark(
    "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: x: y\n",
    &["mapping values are not allowed in this context", "L:5,C:18"]
)]
#[case::scanner_error_carries_its_context(
    "a: 'unterminated\n",
    &["found unexpected end of stream", "while scanning a quoted scalar", "L:1,C:4"]
)]
#[case::parser_error_carries_its_context(
    "a: [1, 2\n",
    &["did not find expected ',' or ']'", "while parsing a flow sequence", "L:1,C:4"]
)]
#[case::reader_error_is_placed_from_its_offset(
    "a: b\nc: \u{1}\n",
    &["control characters are not allowed", "(#x1)", "L:2,C:4"]
)]
#[case::reader_error_after_a_bare_carriage_return(
    "a: b\rc: \u{1}\n",
    &["control characters are not allowed", "(#x1)", "L:2,C:4"]
)]
#[case::reader_error_after_a_line_separator(
    "a: b\u{2028}c: \u{1}\n",
    &["control characters are not allowed", "(#x1)", "L:2,C:4"]
)]
fn a_syntax_error_names_the_problem_and_its_position(
    #[case] content: &str,
    #[case] expected: &[&str],
) {
    let loaded = Loader::new().load(content.to_string());

    let message = match &loaded {
        Err(Error::ParseError(message)) => message,
        other => panic!("{:?} gave {:?}, not a parse error", content, other),
    };
    for part in expected {
        assert!(
            message.contains(part),
            "the parse error for {:?} was {:?}, which does not say {:?}",
            content,
            message,
            part
        );
    }
}

/// The whole message for the 102-byte document above, so that its shape is pinned and not just its
/// parts: the problem, then the position, with nothing else for a failure libyaml gave no context.
#[test]
fn a_syntax_error_message_is_the_problem_at_its_position() {
    let content = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  B:\n    Type: AWS::S3::Bucket\n    Properties: x: y\n";

    let loaded = Loader::new().load(content.to_string());

    assert!(
        matches!(
            &loaded,
            Err(Error::ParseError(message))
                if message
                    == "error parsing file: mapping values are not allowed in this context at L:5,C:18"
        ),
        "the document gave {:?}",
        loaded
    );
}

/// A file that starts with a UTF-8 byte order mark loads to the same value, at the same positions,
/// as the same file without it.
///
/// Some editors write U+FEFF at the start of a file. The loader hands libyaml the bytes with the
/// encoding preset to UTF-8, which skips libyaml's own reader-level handling of the mark, so the
/// scanner met it as the first character of line 1 and counted it as a column. Every position on
/// line 1 was then one column to the right of where the text sits, and the `Code:` excerpt beside
/// it, which indexes the text by character, disagreed with it: `BucketName[L:1,C:66]` for an `x`
/// at column 65. Only line 1 was affected, which is where a template's top-level key usually is.
///
/// The whole Debug rendering is compared, which carries every node's line and column, and the
/// position of the first key is pinned so that the two renderings cannot agree by both being
/// shifted.
#[test]
fn a_leading_byte_order_mark_does_not_shift_the_first_lines_columns() -> Result<()> {
    let body = "Resources: {B: {Type: AWS::S3::Bucket, Properties: {BucketName: x}}}\n";

    let plain = Loader::new().load(body.to_string())?;
    let with_bom = Loader::new().load(format!("\u{FEFF}{body}"))?;

    let plain = format!("{:?}", plain);
    assert!(
        plain.contains(r#"("Resources", Location { line: 1, col: 1 })"#),
        "without a mark the first key is at column 1: {}",
        plain
    );
    assert_eq!(plain, format!("{:?}", with_bom));

    Ok(())
}

/// The file a tag warning names keeps its backslashes and has its control characters escaped, while
/// the tag itself, document text, is escaped with the backslash too: a Windows path reads in the
/// warning as it reads everywhere else, and a file name holding a line feed still gives one line.
#[test]
fn an_unread_tag_warning_names_its_file_as_written_and_escapes_its_tag() {
    let tag = UnreadTag {
        tag: "python/na\\me:x".to_string(),
        location: Location::new(3, 5),
    };
    let line = tag.in_file("data file C:\\dir\\t.yaml");
    assert_eq!(1, line.lines().count(), "{:?}", line);
    assert!(
        line.contains("`!!python/na\\\\me:x` at L:3,C:5 in data file C:\\dir\\t.yaml;"),
        "the tag's backslash is doubled and the file's is kept: {:?}",
        line
    );
    let line = tag.in_file("data file li\nne.yaml");
    assert_eq!(1, line.lines().count(), "{:?}", line);
    assert!(
        line.contains("in data file li\\nne.yaml;"),
        "the file name's line feed is written as its escape: {:?}",
        line
    );
}
