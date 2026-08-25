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

    let expected_string = r#"Map({("Name", Location { line: 8, col: 4 }): Map({("Fn::Sub", Location { line: 8, col: 10 }): List([String("www.${Domain}", Location { line: 9, col: 8 }), Map({("Domain", Location { line: 10, col: 10 }): Map({("Ref", Location { line: 10, col: 18 }): String("RootDomainName", Location { line: 10, col: 18 })}, Location { line: 10, col: 18 })}, Location { line: 10, col: 8 })], Location { line: 8, col: 10 })}, Location { line: 8, col: 10 })}, Location { line: 8, col: 4 })"#;
    let result_as_string = format!("{:?}", value);
    assert_eq!(expected_string, result_as_string);

    Ok(())
}

#[rstest::rstest]
#[case::standard_lowercase_true("true", true)]
#[case::standard_capitalized_true("True", true)]
#[case::standard_uppercase_true("TRUE", true)]
#[case::yaml_yes_lowercase("yes", true)]
#[case::yaml_yes_capitalized("Yes", true)]
#[case::yaml_yes_uppercase("YES", true)]
#[case::yaml_on_lowercase("on", true)]
#[case::yaml_on_capitalized("On", true)]
#[case::yaml_on_uppercase("ON", true)]
#[case::yaml_y_lowercase("y", true)]
#[case::yaml_y_uppercase("Y", true)]
#[case::standard_lowercase_false("false", false)]
#[case::standard_capitalized_false("False", false)]
#[case::standard_uppercase_false("FALSE", false)]
#[case::yaml_no_lowercase("no", false)]
#[case::yaml_no_capitalized("No", false)]
#[case::yaml_no_uppercase("NO", false)]
#[case::yaml_off_lowercase("off", false)]
#[case::yaml_off_capitalized("Off", false)]
#[case::yaml_off_uppercase("OFF", false)]
#[case::yaml_n_lowercase("n", false)]
#[case::yaml_n_uppercase("N", false)]
fn test_handle_bool_happy_path(#[case] arg: &str, #[case] expected: bool) -> Result<()> {
    let docs = format!("check: {arg}");

    let mut loader = Loader::new();
    match loader.load(String::from(docs))? {
        MarkedValue::Map(map, ..) => {
            assert!(map.len() == 1);
            let (.., result) = map.first().unwrap();

            if let MarkedValue::Bool(result, ..) = *result {
                assert_eq!(result, expected);
            }
        }
        _ => unreachable!("this isn't possible"),
    }

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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): Int(312, Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): String("String", Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): Float(3.12, Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): String("String", Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): Float(3.12, Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): String("String", Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): Int(312, Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): Null(Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): Int(312, Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): Null(Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): BadValue("3x12", Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): Null(Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): BadValue("3x12", Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): String("~", Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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
        .get(&("Resources".to_string(), Location::new(1, 4)))
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
        .get(&("Resources".to_string(), Location::new(1, 4)))
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
        .get(&("Resources".to_string(), Location::new(1, 4)))
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
        .get(&("Resources".to_string(), Location::new(1, 4)))
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
