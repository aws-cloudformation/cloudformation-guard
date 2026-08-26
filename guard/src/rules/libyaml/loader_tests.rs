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
/// The cases used to be YAML 1.1's 22, and this test could not fail: the assertion sat inside an
/// `if let MarkedValue::Bool(..)`, so every spelling read as a string satisfied its case by never
/// reaching the assertion. Fourteen of the 22 passed while asserting nothing. The assertion is now
/// unconditional, and the 1.1-only spellings have moved to
/// `a_scalar_outside_the_boolean_set_is_still_a_string`, where they are asserted to be strings.
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
      Tenancy: !!null "String"
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

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): BadValue("3x12", Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): Null(Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 2, col: 1 }): Map({("MyEc2Thing", Location { line: 3, col: 3 }): Map({("Type", Location { line: 4, col: 5 }): String("AWS::EC2::CapacityReservation", Location { line: 4, col: 11 }), ("Properties", Location { line: 5, col: 5 }): Map({("AvailabilityZone", Location { line: 6, col: 7 }): String("some string", Location { line: 6, col: 25 }), ("EbsOptimized", Location { line: 7, col: 7 }): Bool(true, Location { line: 7, col: 21 }), ("EndDate", Location { line: 8, col: 7 }): String("12/31/2023", Location { line: 8, col: 16 }), ("EphemeralStorage", Location { line: 9, col: 7 }): Bool(false, Location { line: 9, col: 25 }), ("InstanceCount", Location { line: 10, col: 7 }): BadValue("3x12", Location { line: 10, col: 22 }), ("InstanceMatchCriteria", Location { line: 11, col: 7 }): String("open", Location { line: 11, col: 30 }), ("TagSpecifications", Location { line: 12, col: 7 }): List([Map({("ResourceType", Location { line: 13, col: 9 }): String("instance", Location { line: 13, col: 23 }), ("Tags", Location { line: 14, col: 9 }): List([Map({("Key", Location { line: 15, col: 11 }): String("Name", Location { line: 15, col: 16 }), ("Value", Location { line: 16, col: 11 }): String("CFN EC2 Spot Instance", Location { line: 16, col: 18 })}, Location { line: 15, col: 11 })], Location { line: 15, col: 9 })}, Location { line: 13, col: 9 })], Location { line: 13, col: 7 }), ("Tenancy", Location { line: 17, col: 7 }): String("~", Location { line: 17, col: 16 })}, Location { line: 6, col: 7 })}, Location { line: 4, col: 5 })}, Location { line: 3, col: 3 })}, Location { line: 2, col: 1 })"#;
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

    let mut loader = Loader::new();
    let value = loader.load(String::from(docs));

    // The variant and the wording, not just `is_err`. `is_err` alone was satisfied by any failure,
    // including the one this used to produce: a `ParseError`, which `build_data_file` replaced with
    // the file's first hundred bytes, so the only message that says what to change never reached
    // anyone. `UnsupportedDocument` is what survives that substitution.
    assert!(
        matches!(&value, Err(Error::UnsupportedDocument(m)) if m.contains("aliases")),
        "an aliased document gave {:?}, not an alias diagnostic that reaches the reader",
        value
    );

    Ok(())
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

/// A file holding no document at all -- nothing but comments -- aborted the process. Quoted verbatim,
/// so the `event.rs` line number in it is the one the panic printed at the time and not a reference to
/// today's tree:
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
// The YAML 1.1-only spellings. These used to be booleans here, which is how `AttributeType: N`
// became `false` and how `on:` in a GitHub Actions workflow became a key no mapping can hold.
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
/// `serde_yaml` -- the loader `guard test` and the public `run_checks` reach on the same bytes --
/// refuses every one of these outright, so this closes a divergence rather than opening one. Measured
/// against it payload by payload, including `tRuE`, which neither accepts.
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

    assert!(
        matches!(loaded, MarkedValue::BadValue(v, ..) if v == scalar),
        "!!bool {} loaded as {:?}, not a BadValue holding the payload",
        scalar,
        loaded
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
/// `serde_yaml`, which is the loader `guard test` and `run_checks` use on the same bytes, already
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
/// An integer too wide for `i64` used to fall through to the float resolver, which accepted it, so
/// `9223372036854775809` and `9223372036854775810` both became `9.223372036854776e18` and compared
/// *equal*. A clause asserting they differ was reported non-compliant -- a wrong answer about
/// identity, at the ordinary exit code, with nothing on either channel to notice it by.
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
/// itself survived depth 20000, and so did dropping the value it returned; only the conversion died.
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
/// The tag used to be checked against two hand-written sets and, on a miss, discarded -- so the short
/// form of an intrinsic neither set listed became a bare value. `!Transform { ... }` was
/// indistinguishable from a plain mapping, and a rule forbidding the macro passed at exit 0 where the
/// long `Fn::Transform` spelling of the same template failed. That is the opposite of how `!!`-tags
/// behave: `!!int abc` becomes a `BadValue` and is reported, so a bad *type* tag was loud while an
/// unknown *function* tag was silent.
///
/// The sets had gone stale, which is why enumeration was the wrong mechanism: Cidr, ForEach,
/// GetStackOutput, Length, ToJsonString, Transform and ValueOfAll are all in the CloudFormation
/// Template Reference and were in neither. They also created a position trap -- `GetAZs` was in the
/// scalar set only and `Select` in the sequence set only, so a known name used in the other position
/// lost its tag too.
///
/// The mapping cases are the ones no set could have covered: `handle_mapping_start` never looked at
/// the tag at all, so a tagged mapping lost it even for a name both sets listed.
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
