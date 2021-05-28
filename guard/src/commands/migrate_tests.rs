use super::*;
use crate::migrate::parser::{Clause, BaseRule, PropertyComparison, CmpOperator, OldGuardValues, ConditionalRule, TypeName};
use crate::rules::values::Value;
use crate::rules::parser::rules_file;

#[test]
fn test_get_resource_types_in_ruleset() {
    let rules = vec![
        RuleLineType::Comment(String::from("MyComment")),
        RuleLineType::Clause(Clause {
            rules: vec![
                Rule::Basic(
                    BaseRule{
                        type_name: TypeName {type_name: String::from("AWS::S3::Bucket")},
                        property_comparison: PropertyComparison {
                            property_path: String::from("Path.To.Property"),
                            operator: CmpOperator::Eq,
                            comparison_value: OldGuardValues::Value(Value::String(String::from("Test")))
                        },
                        custom_message: None
                    }
                ),
                Rule::Conditional(
                    ConditionalRule {
                        type_name: TypeName {type_name: String::from("AWS::S3::BucketPolicy")},
                        when_condition: PropertyComparison {
                            property_path: String::from("Path.To.Property"),
                            operator: CmpOperator::Eq,
                            comparison_value: OldGuardValues::Value(Value::String(String::from("Test")))
                        },
                        check_condition: PropertyComparison {
                            property_path: String::from("Path.To.Property"),
                            operator: CmpOperator::Eq,
                            comparison_value: OldGuardValues::Value(Value::String(String::from("Test")))
                        }
                    }
                ),
                Rule::Basic(
                    BaseRule{
                        type_name: TypeName {type_name: String::from("AWS::S3::Bucket")},
                        property_comparison: PropertyComparison {
                            property_path: String::from("Path.To.Property"),
                            operator: CmpOperator::Eq,
                            comparison_value: OldGuardValues::Value(Value::String(String::from("Test1")))
                        },
                        custom_message: None
                    }
                )
            ]
        }),
        RuleLineType::Clause(Clause {
            rules: vec![
                Rule::Basic(
                    BaseRule{
                        type_name: TypeName {type_name: String::from("AWS::EC2::Instance")},
                        property_comparison: PropertyComparison {
                            property_path: String::from("Path.To.Property"),
                            operator: CmpOperator::Eq,
                            comparison_value: OldGuardValues::Value(Value::String(String::from("Test1")))
                        },
                        custom_message: None
                    }
                )
            ]
        })
    ];
    let expected_resource_types = vec![
        TypeName{type_name: String::from("AWS::EC2::Instance")},
        TypeName{type_name: String::from("AWS::S3::Bucket")},
        TypeName{type_name: String::from("AWS::S3::BucketPolicy")}];

    let result_resource_types = get_resource_types_in_ruleset(&rules).unwrap();
    assert_eq!(expected_resource_types, result_resource_types)
}

#[test]
fn test_migrate_conditional_rules() -> Result<()> {
    let old_ruleset = String::from(
        r#"
        let my_variable = true
        AWS::EC2::Instance WHEN InstanceType == "m2.large" CHECK .Encryption == %my_variable"#);

    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");
    rules_file(span)?;

    let expected_rule = String::from("let my_variable = true
let aws_ec2_instance = Resources.*[ Type == \"AWS::EC2::Instance\" ]
rule aws_ec2_instance_checks WHEN %aws_ec2_instance NOT EMPTY {
    %aws_ec2_instance {
        when Properties.InstanceType == \"m2.large\" {
            Encryption == %my_variable
        }
    }
}
\n");
    assert_eq!(result, expected_rule);
    Ok(())
}

#[test]
fn test_migrate_basic_rules_disjunction() -> Result<()> {
    let old_ruleset = String::from(
        "let encryption_flag = true \n AWS::EC2::Volume Encrypted == %encryption_flag \n AWS::EC2::Volume Size == 100 |OR| AWS::EC2::Volume Size == 50"
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");

    let expected_rule = String::from("let encryption_flag = true
let aws_ec2_volume = Resources.*[ Type == \"AWS::EC2::Volume\" ]
rule aws_ec2_volume_checks WHEN %aws_ec2_volume NOT EMPTY {
    %aws_ec2_volume {
        Properties.Encrypted == %encryption_flag
        Properties.Size == 100 or Properties.Size == 50
    }
}
\n");
    assert_eq!(result, expected_rule);
    rules_file(span)?;
    Ok(())
}

#[test]
fn test_migrate_conditional_rules_disjunction() -> Result<()> {
    let old_ruleset = String::from(
        r#"AWS::EC2::Instance WHEN InstanceType == "m2.large" CHECK .DeletionPolicy == Retain |OR| AWS::EC2::Instance WHEN InstanceType == "t2.micro" CHECK .Encrypted == true"#
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");

    let expected_rule = String::from(r#"let aws_ec2_instance = Resources.*[ Type == "AWS::EC2::Instance" ]
rule aws_ec2_instance_checks WHEN %aws_ec2_instance NOT EMPTY {
    %aws_ec2_instance {
        when Properties.InstanceType == "m2.large" {
            DeletionPolicy == "Retain"
        } or when Properties.InstanceType == "t2.micro" {
            Encrypted == true
        }
    }
}

"#);
    println!("{}", result);
    assert_eq!(result, expected_rule);
    rules_file(span)?;
    Ok(())
}

#[test]
fn test_migrate_rules_different_types() -> Result<()> {
    let old_ruleset = String::from(
        "let encryption_flag = true \n AWS::S3::Bucket Encrypted == %encryption_flag \n AWS::EC2::Volume Size == 50"
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");

    let expected_rule = String::from("let encryption_flag = true
let aws_ec2_volume = Resources.*[ Type == \"AWS::EC2::Volume\" ]
rule aws_ec2_volume_checks WHEN %aws_ec2_volume NOT EMPTY {
    %aws_ec2_volume {
        Properties.Size == 50
    }
}

let aws_s3_bucket = Resources.*[ Type == \"AWS::S3::Bucket\" ]
rule aws_s3_bucket_checks WHEN %aws_s3_bucket NOT EMPTY {
    %aws_s3_bucket {
        Properties.Encrypted == %encryption_flag
    }
}
\n");
    assert_eq!(result, expected_rule);
    rules_file(span)?;
    Ok(())
}

#[test]
fn test_migrate_basic_rules_with_custom_messages() -> Result<()> {
    let old_ruleset = String::from(
        r#"AWS::S3::Bucket Foo.Bar == 2 << this must equal 2"#
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");

    let expected_rule = String::from("let aws_s3_bucket = Resources.*[ Type == \"AWS::S3::Bucket\" ]
rule aws_s3_bucket_checks WHEN %aws_s3_bucket NOT EMPTY {
    %aws_s3_bucket {
        Properties.Foo.Bar == 2 <<this must equal 2>>
    }
}
\n");
    assert_eq!(result, expected_rule);
    rules_file(span)?;
    Ok(())
}

#[test]
fn test_migrate_disjunction_basic_and_conditional() -> Result<()> {
    let old_ruleset = String::from(
        r#"AWS::EC2::Instance WHEN InstanceType == "m2.large" CHECK .DeletionPolicy == Retain |OR| AWS::EC2::Instance InstanceType == "t2.micro" << Deletion policy for m2.large"#
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");

    let expected_rule = String::from("let aws_ec2_instance = Resources.*[ Type == \"AWS::EC2::Instance\" ]
rule aws_ec2_instance_checks WHEN %aws_ec2_instance NOT EMPTY {
    %aws_ec2_instance {
        when Properties.InstanceType == \"m2.large\" {
            DeletionPolicy == \"Retain\"
        } or Properties.InstanceType == \"t2.micro\" <<Deletion policy for m2.large>>
    }
}
\n");
    assert_eq!(result, expected_rule);
    rules_file(span)?;
    Ok(())
}
