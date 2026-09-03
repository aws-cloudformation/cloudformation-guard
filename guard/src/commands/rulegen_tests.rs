use crate::commands::rulegen;
use crate::commands::rulegen::{generate_rule_map, print_rules};
use crate::commands::{ERROR_STATUS_CODE, SUCCESS_STATUS_CODE};
use crate::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
use pretty_assertions::assert_eq;

/// Run a whole generation over `template` -- both halves, not just the map -- and return the
/// generated rules text with the status code.
///
/// `Writer` hands out its output buffer or its error buffer, not both, so the warnings are read by
/// `warnings_for` below running the generation again. That is well defined because the output is now
/// deterministic; before this change the two runs could disagree.
fn generate(template: &str) -> (String, i32) {
    let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).unwrap();
    let (rule_map, omissions) = generate_rule_map(template).unwrap();
    let status = print_rules(rule_map, omissions, &mut writer).unwrap();

    (writer.into_string().unwrap(), status)
}

/// The warnings a generation over `template` writes to stderr.
fn warnings_for(template: &str) -> String {
    let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).unwrap();
    let (rule_map, omissions) = generate_rule_map(template).unwrap();
    print_rules(rule_map, omissions, &mut writer).unwrap();

    writer.err_to_stripped().unwrap()
}

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
    let generated_rules = rulegen::parse_template_and_call_gen(&data, &mut writer).unwrap();

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
    let generated_rules = rulegen::parse_template_and_call_gen(&data, &mut writer).unwrap();

    assert_eq!(0, generated_rules.len());
}

/// A resource carrying `Properties` and no usable `Type` used to abort the process: the resource type
/// was read as `cfn_resource["Type"].as_str().unwrap()` inside the property loop, so a `None` there
/// panicked at exit 101. `guard/resources/validate/mixed-extension-dir/template.json` does this.
#[rstest::rstest]
#[case::type_absent(r#"{"Resources": {"B": {"Properties": {"Encrypted": false}}}}"#)]
#[case::type_is_a_map(
    r#"{"Resources": {"B": {"Type": {"inner": "x"}, "Properties": {"Encrypted": false}}}}"#
)]
#[case::type_is_a_list(
    r#"{"Resources": {"B": {"Type": ["x"], "Properties": {"Encrypted": false}}}}"#
)]
fn test_rulegen_resource_without_a_usable_type_is_skipped_rather_than_panicking(
    #[case] template: &str,
) {
    let mut writer = Writer::default();
    let generated_rules = rulegen::parse_template_and_call_gen(template, &mut writer).unwrap();

    assert_eq!(0, generated_rules.len());
    assert!(warnings_for(template).contains("a generated rule is keyed on the resource type"));
}

/// The skip is per resource: a template mixing one untyped resource with a usable one still
/// generates for the usable one.
#[test]
fn test_rulegen_skips_only_the_resource_without_a_type() {
    let template = r#"
        {
            "Resources": {
                "Untyped": { "Properties": { "Encrypted": false } },
                "Volume": {
                    "Type": "AWS::EC2::Volume",
                    "Properties": { "Size": 500 }
                }
            }
        }
        "#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(rules.contains("%aws_ec2_volume_resources.Properties.Size == 500"));
}

/// A null in a template loads as a null, so the clause has to say `null`.
///
/// This asserted `== ""`, and that was right against a loader which resolved an empty node to the
/// empty string -- the same commit's other half was that `== null` compared a string against a null
/// and could never pass. The loader now resolves an empty node to null, deliberately, so that `k:`
/// and `k: ""` stop being indistinguishable, and the two readings crossed over: `"NULL"` against `""`
/// is `not comparable null, String`. Three templates under `guard/resources/validate` carry an empty
/// `BucketEncryption:` and this is the clause they need.
#[test]
fn test_rulegen_renders_a_null_property_as_null() {
    let (rules, status) =
        generate(r#"{"Resources": {"B": {"Type": "T", "Properties": {"E": null}}}}"#);

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains(r#"%t_resources.Properties.E == null"#),
        "{}",
        rules
    );
}

/// The same rendering has to reach a null nested inside a property's value, because the loader reads
/// it the same way at any depth: `Outer: {Inner: null}` satisfies `== {"Inner":null}`.
#[test]
fn test_rulegen_renders_a_nested_null_as_null() {
    let (rules, _) = generate(
        r#"{"Resources": {"B": {"Type": "T", "Properties": {"Outer": {"Inner": null}}}}}"#,
    );

    assert!(
        rules.contains(r#"%t_resources.Properties.Outer == {"Inner":null}"#),
        "{}",
        rules
    );
}

/// A value holding a quote used to be pasted between two quotes unescaped, which produced a clause
/// that did not parse -- and the whole generation was then discarded at exit 0.
#[test]
fn test_rulegen_escapes_a_quote_in_a_value() {
    let (rules, status) =
        generate(r#"{"Resources": {"B": {"Type": "T", "Properties": {"M": "he said \"hi\""}}}}"#);

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains(r#"%t_resources.Properties.M == "he said \"hi\"""#),
        "{}",
        rules
    );
}

/// A property name the parser's `var_name` will not accept bare has to be quoted. `property_name` is
/// `var_name` or a string literal, so `Properties."Weird Name"` is legal; emitted bare it ended the
/// query at the space and took the file's parse with it.
#[rstest::rstest]
#[case::space("Weird Name")]
#[case::dot("dotted.name")]
#[case::slash("slash/name")]
#[case::hyphen("hyphen-name")]
#[case::leading_digit("1st")]
fn test_rulegen_quotes_a_property_name_the_grammar_will_not_take_bare(#[case] name: &str) {
    let template =
        format!(r#"{{"Resources": {{"B": {{"Type": "T", "Properties": {{"{name}": "ok"}}}}}}}}"#);

    let (rules, status) = generate(&template);

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains(&format!(r#"%t_resources.Properties."{name}" == "ok""#)),
        "{}",
        rules
    );
}

/// A name that needs no quoting keeps none, so output for a template that already worked does not
/// move.
#[test]
fn test_rulegen_leaves_an_ordinary_property_name_bare() {
    let (rules, _) =
        generate(r#"{"Resources": {"B": {"Type": "T", "Properties": {"Size_2": 1}}}}"#);

    assert!(
        rules.contains("%t_resources.Properties.Size_2 == 1"),
        "{}",
        rules
    );
}

/// No guard string literal denotes a value containing a line ending: the literal ends at the end of
/// its line, and `\n` is not an escape it understands. This used to delete the newlines and assert
/// the lines run together, which is a value the template never held.
#[rstest::rstest]
#[case::newline("line one\nline two")]
#[case::carriage_return("line one\rline two")]
#[case::tab("before\tafter")]
fn test_rulegen_refuses_a_value_no_string_literal_can_carry(#[case] value: &str) {
    let template =
        serde_json::json!({"Resources": {"B": {"Type": "T", "Properties": {"Script": value}}}})
            .to_string();

    let (rules, status) = generate(&template);

    assert_eq!(ERROR_STATUS_CODE, status, "{}", rules);
    assert!(warnings_for(&template).contains(
        "no check generated for T.Properties.Script: its value holds a line ending or another control character"
    ));
}

/// Surrounding whitespace is part of the value. It used to be trimmed away, which is the same
/// corruption as deleting the newlines but silent: the clause parses and looks plausible.
#[test]
fn test_rulegen_keeps_whitespace_around_a_value() {
    let (rules, _) =
        generate(r#"{"Resources": {"B": {"Type": "T", "Properties": {"N": "  padded  "}}}}"#);

    assert!(
        rules.contains(r#"%t_resources.Properties.N == "  padded  ""#),
        "{}",
        rules
    );
}

/// A boolean observed both ways collapses to `IN [false, true]`, a clause no boolean value can fail,
/// so the generated rule cannot tell the insecure template from the secure one. Refused for the
/// reason the parser refuses a reversed range literal.
#[test]
fn test_rulegen_refuses_a_clause_no_boolean_value_can_fail() {
    let template = r#"
        {
            "Resources": {
                "VolA": { "Type": "AWS::EC2::Volume", "Properties": { "Encrypted": true } },
                "VolB": { "Type": "AWS::EC2::Volume", "Properties": { "Encrypted": false } }
            }
        }
        "#;

    let (rules, status) = generate(template);

    assert_eq!(ERROR_STATUS_CODE, status, "{}", rules);
    assert!(warnings_for(template).contains("a clause no boolean value can fail"));
}

/// Only the boolean case is refused. `Size IN [50, 500]` is weaker than the docstring used to claim
/// but a template holding some other size still fails it, so it is still written.
#[test]
fn test_rulegen_still_writes_a_non_boolean_in_clause() {
    let template = r#"
        {
            "Resources": {
                "VolA": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 500 } },
                "VolB": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50 } }
            }
        }
        "#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains("%aws_ec2_volume_resources.Properties.Size IN [50, 500]"),
        "{}",
        rules
    );
}

/// A clause is evaluated against every resource its `Type ==` filter admits, so a property only some
/// of them carry produces a clause the source template itself fails -- a missing property is a
/// retrieval failure, not a skip.
#[test]
fn test_rulegen_refuses_a_property_only_some_resources_of_the_type_carry() {
    let template = r#"
        {
            "Resources": {
                "One": { "Type": "T", "Properties": { "Shared": 1, "OnlyHere": 2 } },
                "Two": { "Type": "T", "Properties": { "Shared": 1 } }
            }
        }
        "#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains("%t_resources.Properties.Shared == 1"),
        "{}",
        rules
    );
    assert!(!rules.contains("OnlyHere == 2"), "{}", rules);
    assert!(warnings_for(template).contains("only 1 of the 2 resources of this type carry it"));
}

/// The denominator counts a resource of the type that has no `Properties` at all, because a clause
/// fails against that resource too.
#[test]
fn test_rulegen_counts_a_resource_with_no_properties_toward_its_type() {
    let template = r#"
        {
            "Resources": {
                "One": { "Type": "T", "Properties": { "P": 1 } },
                "Two": { "Type": "T" }
            }
        }
        "#;

    let (_, status) = generate(template);

    assert_eq!(ERROR_STATUS_CODE, status);
    assert!(warnings_for(template).contains("only 1 of the 2 resources of this type carry it"));
}

/// Generating nothing is not success. `validate -r` against an empty rules file reports every
/// document compliant, so a caller that generates and then validates went green having evaluated
/// nothing -- both halves silent, both exiting 0.
#[rstest::rstest]
#[case::no_resources_at_all(r#"{"Resources": {}}"#)]
#[case::no_properties(r#"{"Resources": {"B": {"Type": "T"}}}"#)]
#[case::every_property_refused(
    r#"{"Resources": {"B": {"Type": "T", "Properties": {"S": "a\nb"}}}}"#
)]
fn test_rulegen_refuses_to_report_success_having_generated_no_rules(#[case] template: &str) {
    let (rules, status) = generate(template);

    assert_eq!(ERROR_STATUS_CODE, status);
    assert_eq!("", rules);
    assert!(warnings_for(template).contains("No rules were generated from this template"));
}

/// Resource types, property names and `IN` value lists are all sorted, so the same template
/// generates the same bytes every time. They came out of `HashMap`s and `HashSet`s before, whose
/// iteration order is seeded per process: two resources with five properties between them produced
/// 16 distinct outputs over 30 runs of the same command.
#[test]
fn test_rulegen_output_is_deterministic() {
    let template = r#"
        {
            "Resources": {
                "Vol": {
                    "Type": "AWS::EC2::Volume",
                    "Properties": { "Size": 500, "Encrypted": false, "Zone": "us-west-2b" }
                },
                "VolTwo": {
                    "Type": "AWS::EC2::Volume",
                    "Properties": { "Size": 50, "Encrypted": false, "Zone": "us-west-2c" }
                },
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": { "Name": "b", "Versioning": { "Status": "Enabled" } }
                }
            }
        }
        "#;

    let (first, _) = generate(template);

    for _ in 0..16 {
        let (again, _) = generate(template);
        assert_eq!(first, again);
    }

    assert_eq!(
        "\
let aws_ec2_volume_resources = Resources.*[ Type == 'AWS::EC2::Volume' ]
rule aws_ec2_volume when %aws_ec2_volume_resources !empty {
  %aws_ec2_volume_resources.Properties.Encrypted == false
  %aws_ec2_volume_resources.Properties.Size IN [50, 500]
  %aws_ec2_volume_resources.Properties.Zone IN [\"us-west-2b\", \"us-west-2c\"]
}
let aws_s3_bucket_resources = Resources.*[ Type == 'AWS::S3::Bucket' ]
rule aws_s3_bucket when %aws_s3_bucket_resources !empty {
  %aws_s3_bucket_resources.Properties.Name == \"b\"
  %aws_s3_bucket_resources.Properties.Versioning == {\"Status\":\"Enabled\"}
}
",
        first
    );
}

/// The generated file says what it left out, in the position the clause would have held. A rules file
/// that is simply missing a property reads as though the template never carried one.
#[test]
fn test_rulegen_records_an_omission_in_the_generated_file() {
    let (rules, status) = generate(
        r#"{"Resources": {"B": {"Type": "T", "Properties": {"Kept": 1, "Script": "a\nb"}}}}"#,
    );

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains("%t_resources.Properties.Kept == 1"),
        "{}",
        rules
    );
    assert!(
        rules.contains("  # no check generated for T.Properties.Script:"),
        "{}",
        rules
    );
}
