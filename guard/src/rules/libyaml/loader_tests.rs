use crate::rules::Result;

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

    let expected_string = r#"Map({("Resources", Location { line: 1, col: 0 }): Map({("MyEc2Thing", Location { line: 2, col: 2 }): Map({("Type", Location { line: 3, col: 4 }): String("AWS::EC2::CapacityReservation", Location { line: 3, col: 10 }), ("Properties", Location { line: 4, col: 4 }): Map({("AvailabilityZone", Location { line: 5, col: 6 }): String("some string", Location { line: 5, col: 24 }), ("EbsOptimized", Location { line: 6, col: 6 }): Bool(true, Location { line: 6, col: 20 }), ("EndDate", Location { line: 7, col: 6 }): String("12/31/2023", Location { line: 7, col: 15 }), ("EphemeralStorage", Location { line: 8, col: 6 }): Bool(false, Location { line: 8, col: 24 }), ("InstanceCount", Location { line: 9, col: 6 }): Int(312, Location { line: 9, col: 21 }), ("InstanceMatchCriteria", Location { line: 10, col: 6 }): String("open", Location { line: 10, col: 29 }), ("TagSpecifications", Location { line: 11, col: 6 }): List([Map({("ResourceType", Location { line: 12, col: 8 }): String("instance", Location { line: 12, col: 22 }), ("Tags", Location { line: 13, col: 8 }): List([Map({("Key", Location { line: 14, col: 10 }): String("Name", Location { line: 14, col: 15 }), ("Value", Location { line: 15, col: 10 }): String("CFN EC2 Spot Instance", Location { line: 15, col: 17 })}, Location { line: 14, col: 10 })], Location { line: 14, col: 8 })}, Location { line: 12, col: 8 })], Location { line: 12, col: 6 }), ("Tenancy", Location { line: 16, col: 6 }): BadValue("String", Location { line: 16, col: 15 })}, Location { line: 5, col: 6 })}, Location { line: 3, col: 4 })}, Location { line: 2, col: 2 })}, Location { line: 1, col: 0 })"#;
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
