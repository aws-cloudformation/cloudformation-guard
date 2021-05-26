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
        TypeName{type_name: String::from("aws_ec2_instance")},
        TypeName{type_name: String::from("aws_s3_bucket")},
        TypeName{type_name: String::from("aws_s3_bucketpolicy")}];

    let result_resource_types = get_resource_types_in_ruleset(&rules).unwrap();
    assert_eq!(expected_resource_types, result_resource_types)
}

#[test]
fn test_migrate_rules() -> Result<()> {
    let old_ruleset = String::from(
        r#"
        AWS::S3::Bucket WHEN .property.path.* IN ["a", "b", "c"] CHECK BucketName.Encryption == "Enabled"
        let my_variable = true

        # this is a comment
        AWS::EC2::Instance InstanceType == "m2.large"
        AWS::S3::Bucket BucketName == /Encrypted/ << Buckets should be encrypted, or instance type large, or property path in a,b,c |OR| AWS::EC2::Instance WHEN InstanceType == "m2.large" CHECK .DeletionPolicy == Retain |OR| AWS::S3::Bucket Properties.Foo.Bar == 2 << this must equal 2"#,
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");
    rules_file(span)?;
    Ok(())
}

#[test]
fn test_migrate_rules_disjunction() -> Result<()> {
    let old_ruleset = String::from(
        "let encryption_flag = true \n AWS::EC2::Volume Encrypted == %encryption_flag \n AWS::EC2::Volume Size == 100 |OR| AWS::EC2::Volume Size == 50"
    );
    let rule_lines = parse_rules_file(&old_ruleset, &String::from("test-file")).unwrap();
    let result = migrate_rules(rule_lines).unwrap();
    let span = crate::rules::parser::Span::new_extra(&result, "");

    let expected_rule = String::from("rule migrated_rules {
	let aws_ec2_volume = Resources.*[ Type == \"AWS::EC2::Volume\" ]
		let encryption_flag = true
	%aws_ec2_volume.Properties.Encrypted == \"%encryption_flag\"
	%aws_ec2_volume {
		Properties.Size == 100 or Properties.Size == 50
	}
}\n");
    assert_eq!(result, expected_rule);
    rules_file(span)?;
    Ok(())
}