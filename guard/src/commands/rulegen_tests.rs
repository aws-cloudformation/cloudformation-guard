use crate::commands::rulegen;
use crate::commands::rulegen::{generate_rule_map, print_rules, RuleMap};
use crate::commands::{ERROR_STATUS_CODE, SUCCESS_STATUS_CODE};
use crate::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
use pretty_assertions::assert_eq;
use std::collections::{HashMap, HashSet};

/// Run a whole generation over `template` -- both halves, not just the map -- and return the
/// generated rules text with the status code.
///
/// `Writer` hands out its output buffer or its error buffer, not both, so the warnings are read by
/// `warnings_for` below running the generation again. That is well defined because the output is
/// deterministic, so the two runs agree.
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

/// A resource carrying `Properties` and no usable `Type` is skipped rather than aborting the process: a
/// bare `cfn_resource["Type"].as_str().unwrap()` inside the property loop would panic at exit 101 on the
/// `None`. `guard/resources/validate/mixed-extension-dir/template.json` has such a resource.
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

/// A value holding a quote is escaped: pasted between two quotes unescaped it produces a clause that
/// does not parse -- and the whole generation is then discarded.
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
/// its line, and `\n` is not an escape it understands. Deleting the newlines and asserting the lines
/// run together would assert a value the template never holds.
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

/// Surrounding whitespace is part of the value. Trimming it away is the same corruption as deleting
/// the newlines but silent: the clause parses and looks plausible.
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

/// Only the boolean case is refused. `Size IN [50, 500]` is weaker than an ALL reading but a template
/// holding some other size still fails it, so it is written.
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
let aws_ec2_volume_resources = Resources.*[ Type == \"AWS::EC2::Volume\" ]
rule aws_ec2_volume when %aws_ec2_volume_resources !empty {
  %aws_ec2_volume_resources.Properties.Encrypted == false
  %aws_ec2_volume_resources.Properties.Size IN [50, 500]
  %aws_ec2_volume_resources.Properties.Zone IN [\"us-west-2b\", \"us-west-2c\"]
}
let aws_s3_bucket_resources = Resources.*[ Type == \"AWS::S3::Bucket\" ]
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

/// The comment recording a refused property name has to stay on one line. A `#` comment ends at the
/// first line ending, and a name holding one is exactly what `property_path_segment` refuses, so the
/// comment written to say so was itself split: the half after the line ending failed the parse of
/// the generated file, the run exited with no rules written, and the sibling `Kept` went with it.
/// The name is written with its control characters escaped, in the file and in the stderr warning.
///
/// `name` is the JSON spelling of the property name, decoded by the template loader.
#[rstest::rstest]
#[case::line_feed(r"Line\nBreak", r"T.Properties.Line\nBreak")]
#[case::carriage_return(r"Carriage\rReturn", r"T.Properties.Carriage\rReturn")]
#[case::tab(r"Tab\tHere", r"T.Properties.Tab\tHere")]
#[case::escape(concat!(r"Esc\", "u001bHere"), r"T.Properties.Esc\u{1b}Here")]
fn test_rulegen_escapes_a_control_character_in_the_omission_comment(
    #[case] name: &str,
    #[case] subject: &str,
) {
    let template = format!(
        r#"{{"Resources": {{"B": {{"Type": "T", "Properties": {{"Kept": 1, "{name}": 2}}}}}}}}"#
    );
    let reason = "the property name holds a line ending or another control character, and a guard \
                  string literal ends at the end of its line";

    let (rules, status) = generate(&template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(&template));
    assert!(
        rules.contains("%t_resources.Properties.Kept == 1"),
        "{}",
        rules
    );

    let comment_lines = rules
        .lines()
        .filter(|line| line.starts_with("  # no check generated for "))
        .collect::<Vec<&str>>();
    assert_eq!(
        vec![format!("  # no check generated for {subject}: {reason}")],
        comment_lines,
        "{}",
        rules
    );

    let span = crate::rules::parser::Span::new_extra(&rules, "");
    assert!(crate::rules::parser::rules_file(span).is_ok(), "{}", rules);

    let warnings = warnings_for(&template);
    assert_eq!(
        vec![format!(
            "Warning: no check generated for {subject}: {reason}"
        )],
        warnings.lines().collect::<Vec<&str>>(),
        "{}",
        warnings
    );
}

/// Control for the test above: the escaping must not touch a name that has nothing to escape. A
/// property omitted for its value, not its name, has its name written into the comment as it
/// stands. `Naïve` is a legal name with a non-ASCII letter and no control
/// character or backslash; the comment names it unchanged, with the value's reason, and `Kept` is
/// still generated beside it.
#[test]
fn test_rulegen_leaves_an_ordinary_name_alone_in_the_omission_comment() {
    let (rules, status) = generate(
        r#"{"Resources": {"B": {"Type": "T", "Properties": {"Kept": 1, "Naïve": "a\nb"}}}}"#,
    );

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert!(
        rules.contains("%t_resources.Properties.Kept == 1"),
        "{}",
        rules
    );
    assert!(
        rules.contains(
            "  # no check generated for T.Properties.Naïve: its value holds a line ending or \
             another control character, and a guard string literal ends at the end of its line\n"
        ),
        "{}",
        rules
    );
}

/// The escaped form has to map back to one name. A property named `Line<LF>Break` is refused for
/// its name; one named with the two characters `\` `n` is a legal name that is refused here for its
/// value. Written with only the control character escaped, both read `Line\nBreak`, and the two
/// comments could not be told apart. The backslash is escaped too, so the second reads
/// `Line\\nBreak`.
#[test]
fn test_rulegen_tells_a_line_feed_from_a_backslash_n_in_the_comment() {
    let template = r#"{"Resources": {"B": {"Type": "T", "Properties": {"Kept": 1, "Line\nBreak": 2, "Line\\nBreak": "a\nb"}}}}"#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(template));
    assert!(
        rules.contains("%t_resources.Properties.Kept == 1"),
        "{}",
        rules
    );

    let comment_lines = rules
        .lines()
        .filter(|line| line.starts_with("  # no check generated for "))
        .collect::<Vec<&str>>();
    assert_eq!(
        vec![
            r"  # no check generated for T.Properties.Line\nBreak: the property name holds a line ending or another control character, and a guard string literal ends at the end of its line",
            r"  # no check generated for T.Properties.Line\\nBreak: its value holds a line ending or another control character, and a guard string literal ends at the end of its line",
        ],
        comment_lines,
        "{}",
        rules
    );
}

/// Two things are made from a resource type. The filter in the `let` line is a guard string literal,
/// and the rule name and the variable name are the type with `::` replaced by `_`, lowercased, and
/// written bare; the parser's `var_name` takes one ASCII letter, then only letters, digits and
/// underscores. Rule and variable names are not sanitized (see `print_rules`), so a type whose
/// derived name is not a `var_name` -- one holding a quote, a backslash or a line ending, one whose
/// name does not start with an ASCII letter (an empty type, a leading `_` or `::`, a leading digit),
/// or one holding a character CloudFormation allows in a custom resource type and the parser does
/// not allow in a name (a hyphen, an `@`, a single `:`, a space, a dot) -- broke the `let` and `rule`
/// lines the way a property name broke its comment: the generated file failed its own parse and
/// nothing was written, the other types included. Such a resource is now left out like one with no
/// usable `Type`, and the rest of the template still generates. The warning quotes the type and the
/// rule name it gives in Rust debug spelling, so a `"`, a `\` or a control character inside either
/// is escaped and each quoted name has one end, the way the non-string-`Type` warning names the
/// value it found.
///
/// `resource_type` is the JSON spelling, decoded by the template loader; `shown` is the debug
/// spelling of the type and `rule_name` that of the name derived from it, as the warning uses them.
#[rstest::rstest]
#[case::line_feed(r"T\nU", r#""T\nU""#, r#""t\nu""#)]
#[case::single_quote(r"T'U", r#""T'U""#, r#""t'u""#)]
#[case::double_quote(r#"T\"U"#, r#""T\"U""#, r#""t\"u""#)]
#[case::double_and_single_quote(r#"A\"B'C"#, r#""A\"B'C""#, r#""a\"b'c""#)]
#[case::trailing_backslash(r"T\\", r#""T\\""#, r#""t\\""#)]
#[case::doubled_backslash(r"A\\\\B", r#""A\\\\B""#, r#""a\\\\b""#)]
#[case::empty("", r#""""#, r#""""#)]
#[case::leading_underscore("_X", r#""_X""#, r#""_x""#)]
#[case::leading_colons("::Foo", r#""::Foo""#, r#""_foo""#)]
#[case::leading_digit("9Lives", r#""9Lives""#, r#""9lives""#)]
#[case::hyphen(
    "Custom::My-Resource",
    r#""Custom::My-Resource""#,
    r#""custom_my-resource""#
)]
#[case::at_sign(
    "Custom::My@Resource",
    r#""Custom::My@Resource""#,
    r#""custom_my@resource""#
)]
#[case::single_colon("AWS:S3", r#""AWS:S3""#, r#""aws:s3""#)]
#[case::space("Custom::A B", r#""Custom::A B""#, r#""custom_a b""#)]
#[case::dot("Custom::A.B", r#""Custom::A.B""#, r#""custom_a.b""#)]
fn test_rulegen_refuses_a_type_the_rule_name_cannot_carry(
    #[case] resource_type: &str,
    #[case] shown: &str,
    #[case] rule_name: &str,
) {
    let reason = format!(
        "gives the rule name {rule_name}, and a rule name is one ASCII letter, then only letters, \
         digits and underscores"
    );
    let template = format!(
        r#"{{"Resources": {{"B": {{"Type": "{resource_type}", "Properties": {{"Kept": 1}}}}, "C": {{"Type": "V", "Properties": {{"Kept": 1}}}}}}}}"#
    );

    let (rules, status) = generate(&template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(&template));
    assert_eq!(
        "\
let v_resources = Resources.*[ Type == \"V\" ]
rule v when %v_resources !empty {
  %v_resources.Properties.Kept == 1
}
",
        rules
    );

    let warnings = warnings_for(&template);
    assert_eq!(
        vec![format!(
            "Warning: no check generated for resource B: its Type {shown} {reason}"
        )],
        warnings.lines().collect::<Vec<&str>>(),
        "{}",
        warnings
    );
}

/// The logical id of a resource left out for its `Type` goes into the warning through the same
/// escaping as a property name, so an id holding a line ending keeps the warning on one line. The
/// Unicode line and paragraph separators (U+2028, U+2029) are not control characters, but libyaml
/// and most terminals break the line at them, so they are escaped too. The resource has no `Type`
/// at all here, the omission that exists for every version of this command.
///
/// `name` is the logical id as the loader decodes it; `shown` is how the warning spells it.
#[rstest::rstest]
#[case::line_feed("B\nC", r"B\nC")]
#[case::line_separator("B\u{2028}C", r"B\u{2028}C")]
#[case::paragraph_separator("B\u{2029}C", r"B\u{2029}C")]
fn test_rulegen_escapes_a_line_break_in_a_resource_name(#[case] name: &str, #[case] shown: &str) {
    // The loader reads a raw line feed, U+2028 or U+2029 as a line break, so the id goes into the
    // JSON text as its escape and reaches the loader decoded, the way a template file carries it.
    let name = name
        .replace('\n', concat!("\\", "n"))
        .replace('\u{2028}', concat!("\\", "u2028"))
        .replace('\u{2029}', concat!("\\", "u2029"));
    let template = format!(
        r#"{{"Resources": {{"{name}": {{"Properties": {{"Kept": 1}}}}, "D": {{"Type": "V", "Properties": {{"Kept": 1}}}}}}}}"#
    );

    let (rules, status) = generate(&template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(&template));
    assert!(
        rules.contains("%v_resources.Properties.Kept == 1"),
        "{}",
        rules
    );

    let warnings = warnings_for(&template);
    assert_eq!(
        vec![format!(
            "Warning: no check generated for resource {shown}: it has no Type, and a generated \
             rule is keyed on the resource type"
        )],
        warnings.lines().collect::<Vec<&str>>(),
        "{}",
        warnings
    );
}

/// The rule name is checked with the parser's own `var_name` predicate, which takes one ASCII
/// letter and then any Unicode letter or digit, so a type holding a non-ASCII letter after the
/// first character generates exactly as it did before the check existed.
#[test]
fn test_rulegen_keys_a_rule_on_a_type_holding_a_non_ascii_letter() {
    let template = r#"{"Resources": {"B": {"Type": "Custom::Café", "Properties": {"Kept": 1}}}}"#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(template));
    assert_eq!(
        "\
let custom_café_resources = Resources.*[ Type == \"Custom::Café\" ]
rule custom_café when %custom_café_resources !empty {
  %custom_café_resources.Properties.Kept == 1
}
",
        rules
    );
    assert_eq!("", warnings_for(template));
}

/// Two types can give one rule name, because `::` becomes `_` and the rest is lowercased. Written
/// twice, the `let` and the `rule` are each defined twice, the generated file fails its own parse,
/// and nothing is written, every type included. The type sorted second is now left out with a
/// warning naming the type that holds the name, and the file parses.
///
/// Resources are written in sorted type order, so `kept` is the type that sorts first.
#[rstest::rstest]
#[case::case_of_letters(
    "Custom::Foo",
    "Custom::FOO",
    "Custom::FOO",
    "Custom::Foo",
    "custom_foo"
)]
#[case::separator_placement(
    "MyOrg::A_B::C",
    "MyOrg::A::B_C",
    "MyOrg::A::B_C",
    "MyOrg::A_B::C",
    "myorg_a_b_c"
)]
fn test_rulegen_skips_a_type_whose_rule_name_another_type_holds(
    #[case] type_b: &str,
    #[case] type_c: &str,
    #[case] kept: &str,
    #[case] skipped: &str,
    #[case] rule_name: &str,
) {
    let template = format!(
        r#"{{"Resources": {{"B": {{"Type": "{type_b}", "Properties": {{"Alpha": 1}}}}, "C": {{"Type": "{type_c}", "Properties": {{"Beta": 2}}}}}}}}"#
    );
    let kept_property = if kept == type_b { "Alpha" } else { "Beta" };
    let skipped_property = if kept == type_b { "Beta" } else { "Alpha" };

    let (rules, status) = generate(&template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(&template));
    assert_eq!(
        format!(
            "\
let {rule_name}_resources = Resources.*[ Type == \"{kept}\" ]
rule {rule_name} when %{rule_name}_resources !empty {{
  %{rule_name}_resources.Properties.{kept_property} == {}
}}
",
            if kept_property == "Alpha" { 1 } else { 2 }
        ),
        rules
    );
    assert!(!rules.contains(skipped_property), "{}", rules);

    let span = crate::rules::parser::Span::new_extra(&rules, "");
    assert!(crate::rules::parser::rules_file(span).is_ok(), "{}", rules);

    let warnings = warnings_for(&template);
    assert_eq!(
        vec![format!(
            "Warning: no check generated for type {skipped}: gives the rule name {rule_name:?}, \
             which type {kept:?} already holds"
        )],
        warnings.lines().collect::<Vec<&str>>(),
        "{}",
        warnings
    );
}

/// `print_rules` is handed a map keyed on a type no rule can be keyed on, which `generate_rule_map`
/// never produces today: one holding a line feed, and one holding a hyphen, which no guard string
/// literal refuses but the parser's `var_name` does. Written bare into the `let` and `rule` lines,
/// either made the generated file fail its own parse, and the whole file was thrown away. The type
/// is left out with a warning, written through the same escaping as every other omission, and the
/// other type's rule is still written.
#[rstest::rstest]
#[case::line_feed("T\nU", r#""t\nu""#, r"T\nU")]
#[case::hyphen("Custom::A-B", r#""custom_a-b""#, "Custom::A-B")]
fn test_rulegen_print_rules_leaves_out_a_type_no_rule_can_be_keyed_on(
    #[case] resource_type: &str,
    #[case] rule_name: &str,
    #[case] shown: &str,
) {
    let rule_map = || -> RuleMap {
        let kept = || HashSet::from([String::from("1")]);
        HashMap::from([
            (
                String::from(resource_type),
                HashMap::from([(String::from("Kept"), kept())]),
            ),
            (
                String::from("V"),
                HashMap::from([(String::from("Kept"), kept())]),
            ),
        ])
    };

    let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).unwrap();
    let status = print_rules(rule_map(), vec![], &mut writer).unwrap();
    let rules = writer.into_string().unwrap();

    assert_eq!(SUCCESS_STATUS_CODE, status);
    assert_eq!(
        "\
let v_resources = Resources.*[ Type == \"V\" ]
rule v when %v_resources !empty {
  %v_resources.Properties.Kept == 1
}
",
        rules
    );

    let mut writer = Writer::new_with_err(WBVec(vec![]), WBVec(vec![])).unwrap();
    print_rules(rule_map(), vec![], &mut writer).unwrap();
    let warnings = writer.err_to_stripped().unwrap();
    assert_eq!(
        vec![format!(
            "Warning: no check generated for type {shown}: gives the rule name {rule_name}, and a \
             rule name is one ASCII letter, then only letters, digits and underscores"
        )],
        warnings.lines().collect::<Vec<&str>>(),
        "{}",
        warnings
    );
}

/// A non-string `Type` is quoted back in the warning as a clause would have written it, and a guard
/// literal escapes neither U+2028 nor U+2029, so a line separator inside it reached the warning raw
/// and broke the line on screen. Those two are escaped in the rendering; the guard escapes it
/// already holds are left as they are.
#[test]
fn test_rulegen_escapes_a_line_separator_in_a_non_string_type() {
    let template = concat!(
        r#"{"Resources": {"B": {"Type": ["a"#,
        "\\",
        r#"u2028b"], "Properties": {"Kept": 1}}, "D": {"Type": "V", "Properties": {"Kept": 1}}}}"#
    );

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(template));
    assert!(
        rules.contains("%v_resources.Properties.Kept == 1"),
        "{}",
        rules
    );

    let warnings = warnings_for(template);
    assert_eq!(
        vec![
            r#"Warning: no check generated for resource B: its Type is ["a\u{2028}b"] rather than a string, and a generated rule is keyed on the resource type"#
        ],
        warnings.lines().collect::<Vec<&str>>(),
        "{}",
        warnings
    );
}

/// Control for the test above: a namespaced type, the shape every AWS type has, is keyed on as
/// before. `::` becomes `_` in the rule and variable names, and the type goes into the filter as the
/// double-quoted literal the clauses' values use, written by the same function.
#[test]
fn test_rulegen_keys_a_rule_on_a_namespaced_type() {
    let template = r#"{"Resources": {"B": {"Type": "Custom::Foo", "Properties": {"Kept": 1}}}}"#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(template));
    assert_eq!(
        "\
let custom_foo_resources = Resources.*[ Type == \"Custom::Foo\" ]
rule custom_foo when %custom_foo_resources !empty {
  %custom_foo_resources.Properties.Kept == 1
}
",
        rules
    );
    assert_eq!("", warnings_for(template));
}

/// A hyphen is legal in a CloudFormation custom resource type and illegal in the rule and variable
/// names `print_rules` derives from it, so `Custom::My-Resource` is refused with a warning and, as
/// the only type here, generates nothing. Rule and variable names are not sanitized; see
/// `print_rules`. This pins the gap until they are: a sanitized name would let the type generate a
/// rule that parses.
#[test]
#[ignore = "rule and variable names are not sanitized; see print_rules"]
fn test_rulegen_output_parses_for_a_type_holding_a_hyphen() {
    let template =
        r#"{"Resources": {"B": {"Type": "Custom::My-Resource", "Properties": {"Kept": 1}}}}"#;

    let (rules, status) = generate(template);

    assert_eq!(SUCCESS_STATUS_CODE, status, "{}", warnings_for(template));
    // `rules_file("")` is `Ok(None)`, so the parse alone would pass on an empty output.
    assert!(!rules.trim().is_empty(), "no rules were generated");
    let span = crate::rules::parser::Span::new_extra(&rules, "");
    assert!(crate::rules::parser::rules_file(span).is_ok(), "{}", rules);
}
