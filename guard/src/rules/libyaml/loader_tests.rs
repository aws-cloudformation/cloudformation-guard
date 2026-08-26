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
    assert!(value.is_err());

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

/// A file holding no document at all -- nothing but comments -- aborted the process:
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
/// `!!bool yes` loaded as the string "yes" while a bare `yes` was already a boolean, and
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

/// A `---` stream held more than one document and the loader answered with the first one, in
/// silence. `Loader::load` returned at the first `DocumentEnd`, so a template prefixed with a
/// compliant document and a `---` had every finding in it suppressed at exit 0, and -- because
/// returning there dropped the parser -- the bytes after that point were never handed to libyaml,
/// so a stream whose later document was not YAML at all also passed.
///
/// The cases below are the two shapes that matter: content in the first document, and an *empty*
/// first document, which is the worse one because the loader then evaluated nothing whatsoever.
#[rstest::rstest]
#[case::two_documents_with_content("a: 1\n---\nb: 2\n")]
#[case::an_empty_first_document("---\n---\nb: 2\n")]
#[case::three_documents("a: 1\n---\nb: 2\n---\nc: 3\n")]
#[case::a_later_document_that_is_not_yaml("a: 1\n---\nb: [ this is : not valid yaml {{{\n")]
fn a_stream_holding_more_than_one_document_is_refused(#[case] content: &str) {
    let loaded = Loader::new().load(content.to_string());

    assert!(
        matches!(loaded, Err(Error::UnsupportedDocument(ref m)) if m.contains("one document per file")),
        "loading {:?} gave {:?}, not the multiple-document error",
        content,
        loaded
    );
}

/// The control for the case above, and the reason it cannot be written as "reject any `---`".
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
