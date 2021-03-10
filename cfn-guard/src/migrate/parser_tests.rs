use super::*;
use crate::rules::parser::{from_str2, Span, parse_value, rules_file};
use crate::rules::errors::{Error, ErrorKind};
use indexmap::map::IndexMap;
use crate::rules::exprs::RulesFile;
use crate::migrate::parser::Rule::Basic;
use nom_locate::LocatedSpan;

#[test]
fn test_assignment() {
    let examples =  vec!["let my_variable = 1234", "letpropertyaccess", "let my IN"];

    let expected = vec![
        Ok((make_empty_span(examples[0].len()), Assignment {
            var_name: String::from("my_variable"),
            value: OldGuardValues::Value(Value::Int(1234))
        })),
        Err(nom::Err::Error(ParserError {
            context: String::from(""),
            span: unsafe { Span::new_from_raw_offset(examples[1].find("propertyaccess").unwrap(), 1, examples[1].trim_start_matches("let"), "") },
            kind: nom::error::ErrorKind::Space
        })),
        // fails because after let var_name, if assignment operator is not found, line is unrecoverable
        Err(nom::Err::Failure(ParserError {
            context: String::from(""),
            span: unsafe { Span::new_from_raw_offset(examples[2].find("IN").unwrap(), 1, examples[2].trim_start_matches("let my "), "") },
            kind: nom::error::ErrorKind::Tag
        }))
    ];
    for (i, example) in examples.into_iter().enumerate() {
        assert_eq!(
            assignment(from_str2(example)),
            expected[i]
        )
    }
}

#[test]
fn test_parse_old_guard_values_integer() {
    let mut nested_map = IndexMap::new();
    nested_map.insert("foo".to_string(), Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)]));
    let mut map = IndexMap::new();
    map.insert("test".to_string(), Value::String("key".to_string()));
    map.insert("myValue".to_string(), Value::Map(nested_map));
    let string_list = vec![Value::String("list".to_string()), Value::String("of".to_string()), Value::String("values".to_string())];

    let example_expected = vec![
        ("    13249", OldGuardValues::Value(Value::Int(13249))),
        ("   \"This is a quoted string\"", OldGuardValues::Value(Value::String(String::from("This is a quoted string")))),
        ("  this is a bare string   ", OldGuardValues::Value(Value::String(String::from("this is a bare string")))),
        ("{ \"test\": \"key\", \"myValue\": { \"foo\": [ 1, 2, 3]}}", OldGuardValues::Value(Value::Map(map))),
        ("  /match(.*)this/", OldGuardValues::Value(Value::Regex("match(.*)this".to_string()))),
        ("true", OldGuardValues::Value(Value::Bool(true))),
        ("[\"list\", \"of\", \"values\"]", OldGuardValues::Value(Value::List(string_list))),
        ("%deref_this", OldGuardValues::VariableAccess(String::from("deref_this"))),
        // test version numbers correctly get parsed as strings and not as floats
        ("2.1.4-latest", OldGuardValues::Value(Value::String(String::from("2.1.4-latest"))))
    ];

    for (example, expected) in example_expected.into_iter() {
        assert_eq!(
            parse_old_guard_value(from_str2(example)),
            Ok((make_empty_span(example.len()), expected))
        )
    }
}

#[test]
fn test_parse_old_guard_value_optional_message() {
    let example = "  this is a bare string << with optional message";
    let expected_span = unsafe {Span::new_from_raw_offset(example.find("<<").unwrap(), 1, "<< with optional message", "")};
    assert_eq!(
        parse_old_guard_value(from_str2(example)),
        Ok((expected_span, OldGuardValues::Value(Value::String(String::from("this is a bare string")))))
    )
}

#[test]
fn test_comment_parse() {
    let s = "#this is a comment ";
    assert_eq!(
        comment(from_str2(s)),
        Ok((make_empty_span(s.len()), "this is a comment ".to_string()))
    )
}

#[test]
fn test_value_cmp() {
    let example = vec![
        "==",
        "!=",
        ">",
        "<",
        "IN",
        "NOT_IN",
        ">=",
        "<=",
        "NotAnOperator",
        "<< custom message"
    ];
    let expected = vec![
        Ok((make_empty_span(example[0].len()), CmpOperator::Eq)),
        Ok((make_empty_span(example[1].len()), CmpOperator::Ne)),
        Ok((make_empty_span(example[2].len()), CmpOperator::Gt)),
        Ok((make_empty_span(example[3].len()), CmpOperator::Lt)),
        Ok((make_empty_span(example[4].len()), CmpOperator::In)),
        Ok((make_empty_span(example[5].len()), CmpOperator::NotIn)),
        Ok((make_empty_span(example[6].len()), CmpOperator::Ge)),
        Ok((make_empty_span(example[7].len()), CmpOperator::Le)),
        Err(nom::Err::Error( ParserError {
            context: String::from(""),
            span: unsafe { Span::new_from_raw_offset(0, 1, example[8], "") },
            kind: nom::error::ErrorKind::Tag
        })),
        Err(nom::Err::Error( ParserError {
            context: String::from("Custom message tag detected"),
            span: unsafe { Span::new_from_raw_offset(0, 1, example[9], "") },
            kind: nom::error::ErrorKind::Tag
        }))

    ];

    for (i, example) in example.into_iter().enumerate() {
        assert_eq!(
            value_operator(from_str2(example)),
            expected[i]
        )
    }

}

#[test]
fn test_property_path() {
    let examples = vec![
        ".property.path.*.",
        "property.b.path.*.as",
        "noaccess",
        "[NotAPropertyPath]"
    ];
    let expectations = vec![
        Ok((make_empty_span(examples[0].len()), examples[0].to_string())),
        Ok((make_empty_span(examples[1].len()), examples[1].to_string())),
        Ok((make_empty_span(examples[2].len()), examples[2].to_string())),
        // since first characted is not a valid part of the property path, error
        Err(nom::Err::Error( ParserError {
            context: String::from(""),
            span: unsafe { Span::new_from_raw_offset(examples[3].find('[').unwrap(), 1, "[NotAPropertyPath]", "") },
            kind: nom::error::ErrorKind::TakeWhile1
        }))
    ];

    for (i, example) in examples.into_iter().enumerate() {
        assert_eq!(
            property_path(from_str2(example)),
            expectations[i]
        )
    }

}

#[test]
fn test_property_path_stops_whitespace() {
    let example = ".property.path.*     ";

    let span = unsafe { Span::new_from_raw_offset(example.trim().len(), 1, "     ", "") };

    assert_eq!(
        property_path(from_str2(example)),
        Ok((span, example.trim().to_string()))
    )
}

#[test]
fn test_prop_comparison() {
    let value_list = vec![Value::String(String::from("a")), Value::String(String::from("b")), Value::String(String::from("c"))];
    let example = ".property.path.* == [\"a\", \"b\", \"c\"]";
    let span = make_empty_span(example.len());

    assert_eq!(
        property_comparison(from_str2(example)),
        Ok((span, PropertyComparison{
            property_path: String::from(".property.path.*"),
            operator: CmpOperator::Eq,
            comparison_value: OldGuardValues::Value(Value::List(value_list))
        }))
    )
}
#[test]
fn test_prop_comparison_invalid_operator_fail() {
    let example = ".property.path.* NOT EXISTS";
    let error_span = unsafe { Span::new_from_raw_offset(example.find("NOT").unwrap(), 1, "NOT EXISTS", "") };

    assert_eq!(
        property_comparison(from_str2(example)),
        // we cut before attempting to parse comparison operator, so this is a  failure and unrecoverable for the line
        Err(nom::Err::Failure( ParserError {
            context: String::from(""),
            span: error_span,
            kind: nom::error::ErrorKind::Tag
        }))
    )
}

#[test]
fn test_base_rule() {
    let value_list = vec![Value::String(String::from("a")), Value::String(String::from("b")), Value::String(String::from("c"))];
    let example = "AWS::S3::Bucket .property.path.* IN [\"a\", \"b\", \"c\"]";
    let span = make_empty_span(example.len());
    let prop_comparison = PropertyComparison{
        property_path: String::from(".property.path.*"),
        operator: CmpOperator::In,
        comparison_value: OldGuardValues::Value(Value::List(value_list))
    };


    assert_eq!(
        base_rule(from_str2(example)),
        Ok((span, BaseRule{
            type_name: String::from("AWS::S3::Bucket"),
            property_comparison: prop_comparison,
            custom_message: None
        }))
    )
}

#[test]
fn test_conditional_rule() {
    let value_list = vec![Value::String(String::from("a")), Value::String(String::from("b")), Value::String(String::from("c"))];
    let example = "AWS::S3::Bucket WHEN .property.path.* IN [\"a\", \"b\", \"c\"] CHECK BucketName.Encryption == Enabled  ";
    let span = make_empty_span(example.len());
    let when_condition = PropertyComparison{
        property_path: String::from(".property.path.*"),
        operator: CmpOperator::In,
        comparison_value: OldGuardValues::Value(Value::List(value_list))
    };
    let check_condition = PropertyComparison{
        property_path: String::from("BucketName.Encryption"),
        operator: CmpOperator::Eq,
        comparison_value: OldGuardValues::Value(Value::String(String::from("Enabled")))
    };


    assert_eq!(
        conditional_rule(from_str2(example)),
        Ok((span, ConditionalRule{
            type_name: String::from("AWS::S3::Bucket"),
            when_condition,
            check_condition
        }))
    )
}

#[test]
fn test_clause_with_message() {
    let value_list = vec![Value::String(String::from("a")), Value::String(String::from("b")), Value::String(String::from("c"))];
    let example = "AWS::S3::Bucket WHEN  .property.path.* IN [\"a\", \"b\", \"c\"]  CHECK BucketName.Encryption == Enabled   |OR| AWS::EC2::Instance InstanceType == \"m2.large\" << Instance Types must be m2.large |OR| AWS::S3::Bucket BucketName == /Encrypted/ << Buckets should be encrypted, or instance type large, or property path in a,b,c";

    let span = make_empty_span(example.len());
    let when_condition = PropertyComparison{
        property_path: String::from(".property.path.*"),
        operator: CmpOperator::In,
        comparison_value: OldGuardValues::Value(Value::List(value_list))
    };

    let check_condition = PropertyComparison{
        property_path: String::from("BucketName.Encryption"),
        operator: CmpOperator::Eq,
        comparison_value: OldGuardValues::Value(Value::String(String::from("Enabled")))
    };
    let conditional_rule = Rule::Conditional(
        ConditionalRule {
            type_name: String::from("AWS::S3::Bucket"),
            when_condition,
            check_condition
        }
    );
    let basic_rule_1 = Rule::Basic(
        BaseRule{
            type_name: String::from("AWS::EC2::Instance"),
            property_comparison: PropertyComparison {
                property_path: String::from("InstanceType"),
                operator: CmpOperator::Eq,
                comparison_value: OldGuardValues::Value(Value::String(String::from("m2.large")))
            },
            custom_message: Some(String::from("Instance Types must be m2.large"))
        }
    );
    let basic_rule_2 = Rule::Basic(
        BaseRule {
            type_name: String::from("AWS::S3::Bucket"),
            property_comparison: PropertyComparison {
                property_path: String::from("BucketName"),
                operator: CmpOperator::Eq,
                comparison_value: OldGuardValues::Value(Value::Regex(String::from("Encrypted")))
            },
            custom_message: Some(String::from("Buckets should be encrypted, or instance type large, or property path in a,b,c"))
        }
    );


    let clause = Clause {
        rules: vec![conditional_rule, basic_rule_1, basic_rule_2]
    };

    assert_eq!(
        rule_line(from_str2(example)),
        Ok((span,RuleLineType::Clause(clause)))
    );
}

#[test]
fn test_parse_rules_file() {
    let value_list = vec![Value::String(String::from("a")), Value::String(String::from("b")), Value::String(String::from("c"))];
    let example = "AWS::S3::Bucket WHEN .property.path.* IN [\"a\", \"b\", \"c\"] CHECK BucketName.Encryption == \"Enabled\" \n\
     let my_variable = true \n\
     \n\
     # this is a comment \n\
     AWS::EC2::Instance InstanceType == \"m2.large\"\n\
     AWS::S3::Bucket BucketName == /Encrypted/ << Buckets should be encrypted, or instance type large, or property path in a,b,c |OR| AWS::EC2::Instance InstanceType == \"m2.large\" \n";

    let span = make_empty_span(example.len());
    let when_condition = PropertyComparison{
        property_path: String::from(".property.path.*"),
        operator: CmpOperator::In,
        comparison_value: OldGuardValues::Value(Value::List(value_list))
    };

    let check_condition = PropertyComparison{
        property_path: String::from("BucketName.Encryption"),
        operator: CmpOperator::Eq,
        comparison_value: OldGuardValues::Value(Value::String(String::from("Enabled")))
    };
    let conditional_rule = Rule::Conditional(
        ConditionalRule {
            type_name: String::from("AWS::S3::Bucket"),
            when_condition,
            check_condition
        }
    );
    let basic_rule_1 = Rule::Basic(
        BaseRule{
            type_name: String::from("AWS::EC2::Instance"),
            property_comparison: PropertyComparison {
                property_path: String::from("InstanceType"),
                operator: CmpOperator::Eq,
                comparison_value: OldGuardValues::Value(Value::String(String::from("m2.large")))
            },
            custom_message: None
        }
    );
    let basic_rule_clone = basic_rule_1.clone();
    let basic_rule_2 = Rule::Basic(
        BaseRule {
            type_name: String::from("AWS::S3::Bucket"),
            property_comparison: PropertyComparison {
                property_path: String::from("BucketName"),
                operator: CmpOperator::Eq,
                comparison_value: OldGuardValues::Value(Value::Regex(String::from("Encrypted")))
            },
            custom_message: Some(String::from("Buckets should be encrypted, or instance type large, or property path in a,b,c"))
        }
    );

    let expected_rules = vec![
        RuleLineType::Clause(Clause {
            rules: vec![conditional_rule]
        }),
        RuleLineType::Assignment(Assignment {
            var_name: String::from("my_variable"),
            value: OldGuardValues::Value(Value::Bool(true))
        }),
        RuleLineType::EmptyLine,
        RuleLineType::Comment(String::from(" this is a comment ")),
        RuleLineType::Clause(Clause {
            rules: vec![basic_rule_1]
        }),
        RuleLineType::Clause(Clause {
            rules: vec![basic_rule_2, basic_rule_clone]
        }),
    ];
    let parsed_rules = parse_rules_file(&String::from(example), &String::from("file_name")).unwrap();
    assert_eq!(
        parsed_rules,
        expected_rules
    );
}
#[test]
fn test_parse_rules_file_rule_error() {
    let example = "AWS::S3::Bucket WHEN .property.path.*  CHECK BucketName.Encryption == \"Enabled\" \n";
    assert!(
        parse_rules_file(&String::from(example), &String::from("file_name")).is_err()
    );
}


fn make_empty_span(offset: usize) -> Span<'static> {
    unsafe { Span::new_from_raw_offset(offset, 1, "", "") }
}