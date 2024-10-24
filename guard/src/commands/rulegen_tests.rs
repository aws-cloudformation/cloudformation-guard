use crate::commands::rulegen;
use crate::utils::writer::Writer;
use pretty_assertions::assert_eq;

#[test]
fn test_rulegen() {
    let data = String::from(
        r#"
        {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 500,
                        "Encrypted": false,
                        "AvailabilityZone" : "us-west-2b"
                    }
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                    "Properties" : {
                        "Size" : 50,
                        "Encrypted": false,
                        "AvailabilityZone" : "us-west-2c"
                    }
                }
            }
        }
        "#,
    );

    let mut writer = Writer::default();
    let generated_rules = rulegen::parse_template_and_call_gen(&data, &mut writer);

    assert_eq!(1, generated_rules.len());
    assert!(generated_rules.contains_key("AWS::EC2::Volume"));

    let property_map = &generated_rules["AWS::EC2::Volume"];

    assert_eq!(3, property_map.len());
    assert!(property_map.contains_key("Encrypted"));
    assert!(property_map.contains_key("Size"));
    assert!(property_map.contains_key("AvailabilityZone"));
}

#[test]
fn test_rulegen_no_properties() {
    let data = String::from(
        r#"
        {
            "Resources": {
                "NewVolume" : {
                    "Type" : "AWS::EC2::Volume",
                },
                "NewVolume2" : {
                    "Type" : "AWS::EC2::Volume",
                }
            }
        }
        "#,
    );

    let mut writer = Writer::default();
    let generated_rules = rulegen::parse_template_and_call_gen(&data, &mut writer);

    assert_eq!(0, generated_rules.len());
}
