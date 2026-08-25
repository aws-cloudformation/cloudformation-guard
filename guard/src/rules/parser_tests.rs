use crate::rules::path_value::PathAwareValue;
use crate::rules::values::WithinRange;
use crate::rules::{EvaluationContext, EvaluationType, Status};
use pretty_assertions::assert_eq;
use std::vec;

use super::*;

#[test]
fn test_int_parse() {
    let s = "-124";
    let span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_int_value(Span::new_extra(s, "")),
        Ok((span, Value::Int(-124i64)))
    );
}

#[test]
fn test_int_parse_pos() {
    let s = "12670090";
    let span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_int_value(from_str2(s)),
        Ok((span, Value::Int(12670090)))
    )
}

#[test]
fn test_parse_string() {
    let s = "\"Hi there\"";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_string(from_str2(s)),
        Ok((cmp, Value::String("Hi there".to_string())))
    );

    // Testing embedded quotes using '' for the string
    let s = r#"'"Hi there"'"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_string(from_str2(s)),
        Ok((cmp, Value::String("\"Hi there\"".to_string())))
    );

    let s = r#"'Hi there'"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_string(from_str2(s)),
        Ok((cmp, Value::String("Hi there".to_string())))
    );

    let s = r#""\"#;
    let res = parse_string(from_str2(s));
    assert!(res.is_err());
}

#[test]
fn test_embedded_string_parsing() {
    let s = "\"\\\"Hi There\\\"\"";
    let string = parse_string(from_str2(s));
    assert!(string.is_ok());
    assert_eq!(string.unwrap().1, Value::String("\"Hi There\"".to_string()));

    let s = "\"{\\\"hi\\\": \\\"there\\\"}\"";
    let string = parse_string(from_str2(s));
    assert!(string.is_ok());
    let json = r#"{"hi": "there"}"#.to_string();
    if let Value::String(val) = string.unwrap().1 {
        assert_eq!(val, json);
        let json = serde_json::from_str::<serde_json::Value>(&val);
        assert!(json.is_ok());
    }

    let s = "\"Hi \\\"embedded\\\" there\"";
    let string = parse_string(from_str2(s));
    assert!(string.is_ok());
    assert_eq!(
        string.unwrap().1,
        Value::String("Hi \"embedded\" there".to_owned())
    );
}

#[test]
fn test_parse_string_rest() {
    let hi = "\"Hi there\"";
    let s = hi.to_owned() + " 1234";
    let cmp = unsafe { Span::new_from_raw_offset(hi.len(), 1, " 1234", "") };
    assert_eq!(
        parse_string(from_str2(&s)),
        Ok((cmp, Value::String("Hi there".to_string())))
    );
}

#[test]
fn test_parse_string_from_scalar() {
    let hi = "\"Hi there\"";
    let s = hi.to_owned() + " 1234";
    let cmp = unsafe { Span::new_from_raw_offset(hi.len(), 1, " 1234", "") };
    assert_eq!(
        parse_scalar_value(from_str2(&s)),
        Ok((cmp, Value::String("Hi there".to_string())))
    );
}

#[test]
fn test_parse_bool() {
    let s = "True";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(parse_bool(from_str2(s)), Ok((cmp, Value::Bool(true))));
    let s = "true";
    assert_eq!(parse_bool(from_str2(s)), Ok((cmp, Value::Bool(true))));
    let s = "False";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(parse_bool(from_str2(s)), Ok((cmp, Value::Bool(false))));
    let s = "false";
    assert_eq!(parse_bool(from_str2(s)), Ok((cmp, Value::Bool(false))));
    let s = "1234";
    let cmp = unsafe { Span::new_from_raw_offset(0, 1, "1234", "") };
    assert_eq!(
        parse_bool(from_str2(s)),
        Err(nom::Err::Error(ParserError {
            span: cmp,
            kind: ErrorKind::Tag,
            context: "".to_string()
        }))
    );
    // All three spellings, because `TRUE` was missing and fell through to a property access. In a
    // `when` gate that made the condition compare a property against a property named `TRUE`, which no
    // document has, so the gate never fired and the rule it guarded never ran.
    for spelling in ["true", "True", "TRUE"] {
        let cmp = unsafe { Span::new_from_raw_offset(spelling.len(), 1, "", "") };
        assert_eq!(
            parse_bool(from_str2(spelling)),
            Ok((cmp, Value::Bool(true))),
            "{} is a boolean",
            spelling
        );
    }
    for spelling in ["false", "False", "FALSE"] {
        let cmp = unsafe { Span::new_from_raw_offset(spelling.len(), 1, "", "") };
        assert_eq!(
            parse_bool(from_str2(spelling)),
            Ok((cmp, Value::Bool(false))),
            "{} is a boolean",
            spelling
        );
    }

    // A keyword may not run into an identifier. This used to return `Bool(true)` and leave the rest
    // behind, and the caller then read the remainder as a separate clause: `Public == falseFlag` became
    // `Public == false` AND a reference to a rule named `Flag`, reporting PASS where the author asked
    // whether one property equalled another. Failing here is what lets the alternation fall through to
    // `property_name`, which is the reading that was written.
    for not_a_bool in ["true1234", "trueFlag", "false_flag", "nullable"] {
        assert!(
            parse_bool(from_str2(not_a_bool)).is_err(),
            "{} is a property name, not a boolean followed by something else",
            not_a_bool
        );
    }
}

#[rstest::rstest]
#[case("12.0", Value::Float(12.0))]
#[case("12e+2", Value::Float(1200.0))]
#[case("1.0", Value::Float(1.0))]
#[case("1.5", Value::Float(1.5))]
fn test_parse_float(#[case] s: &str, #[case] expected: Value) {
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(parse_float(from_str2(s)), Ok((cmp, expected)));
}

#[test]
fn test_parse_float_error() {
    let s = "error";
    let cmp = unsafe { Span::new_from_raw_offset(0, 1, "error", "") };
    assert_eq!(
        parse_float(from_str2(s)),
        Err(nom::Err::Error(ParserError {
            span: cmp,
            kind: ErrorKind::Digit,
            context: "".to_string()
        }))
    );
}

/// `double` never fails on an exponent it cannot represent: it saturates to an infinity, or rounds to
/// zero. Either way the clause reads as one bound and means another. `Size < 1e999` cannot fail for any
/// input, `Size > 1e999` cannot pass for any input -- the comparison reported `ComparedWith = inf` --
/// and `Size == 1e-999` is satisfied by a `Size` of 0.
///
/// `Failure`, not `Error`, is half the point. A recoverable error sent `alt` back to the other value
/// productions, `parse_int_value` matched the leading digits and left the rest, and the author was told
/// about a stray fragment instead: `1.5e999` blamed `.5e999` with an empty context, and the message
/// below never appeared at all. So the kind of error is asserted, not just that there was one.
#[rstest::rstest]
#[case::just_past_the_exponent_range("1e309")]
#[case::far_past_the_exponent_range("1e999")]
#[case::negative_and_out_of_range("-1e999")]
#[case::fraction_and_out_of_range("1.5e999")]
#[case::rounds_to_zero("1e-999")]
#[case::rounds_to_zero_with_a_longer_mantissa("10e-999")]
#[case::negative_and_rounds_to_zero("-1e-999")]
fn a_float_literal_out_of_range_is_rejected(#[case] s: &str) {
    let err = parse_float(from_str2(s)).expect_err("an unrepresentable literal must not parse");

    assert!(
        matches!(err, nom::Err::Failure(_)),
        "{} must fail unrecoverably, or `alt` backtracks and reports something else: {:?}",
        s,
        err
    );

    let context = match &err {
        nom::Err::Failure(e) | nom::Err::Error(e) => e.context.clone(),
        nom::Err::Incomplete(_) => String::new(),
    };
    assert!(
        context.contains("out of range for a 64 bit float"),
        "{} must be named as out of range, not merely rejected: {:?}",
        s,
        context
    );
}

/// The control. Rejecting the unrepresentable literals must not cost the representable ones, and the
/// boundary is asserted where it actually falls rather than somewhere safely inside it.
///
/// `0.0e5` and `0e0` are zero and mean zero, so they are not underflow -- the mantissa is what
/// separates them from `1e-999`. `2.2250738585072014e-308` is the smallest positive normal and
/// `1e-320` is subnormal: both are representable, both must parse.
#[rstest::rstest]
#[case::simple_fraction("1.5", 1.5)]
#[case::negative_fraction("-1.5", -1.5)]
#[case::exponent("1e3", 1000.0)]
#[case::negative_exponent("1e-3", 0.001)]
#[case::largest_finite("1.7976931348623157e308", f64::MAX)]
#[case::smallest_positive_normal("2.2250738585072014e-308", f64::MIN_POSITIVE)]
#[case::subnormal("1e-320", 1e-320)]
#[case::zero_with_an_exponent("0.0e5", 0.0)]
#[case::plain_zero_exponent("0e0", 0.0)]
fn a_float_literal_in_range_is_still_parsed(#[case] s: &str, #[case] expected: f64) {
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(parse_float(from_str2(s)), Ok((cmp, Value::Float(expected))));
}

#[test]
fn test_parse_regex() {
    let s = "/.*PROD.*/";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_regex(from_str2(s)),
        Ok((cmp, Value::Regex(".*PROD.*".to_string())))
    );

    let improperly_escaped_regular_expression =
        "/arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/";
    let _cmp = unsafe {
        Span::new_from_raw_offset(
            11,
            1,
            ",.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/",
            "",
        )
    };
    assert_eq!(
        parse_regex(from_str2(improperly_escaped_regular_expression)),
        Err(nom::Err::Error(ParserError {
                context: "Could not parse regular expression: Parsing error at position 9: Invalid character class".to_string(),
                kind: ErrorKind::RegexpMatch,
                span: unsafe { Span::new_from_raw_offset(
                    1,
                    1,
                    "arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/",
                    ""
                ) },
            }))
    );

    let properly_escaped_regular_expression = "/arn:[\\w+=\\/,.@-]+:[\\w+=\\/,.@-]+:[\\w+=\\/,.@-]*:[0-9]*:[\\w+=,.@-]+(\\/[\\w+=,.@-]+)*/";
    let cmp =
        unsafe { Span::new_from_raw_offset(properly_escaped_regular_expression.len(), 1, "", "") };
    assert_eq!(
        parse_regex(from_str2(properly_escaped_regular_expression)),
        Ok((
            cmp,
            Value::Regex(
                "arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*"
                    .to_string()
            )
        ))
    );
}

#[test]
fn test_parse_scalar() {
    let s = "1234";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_scalar_value(from_str2(s)),
        Ok((cmp, Value::Int(1234)))
    );
    let s = "12.089";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_scalar_value(from_str2(s)),
        Ok((cmp, Value::Float(12.089)))
    );
    let s = "\"String in here\"";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_scalar_value(from_str2(s)),
        Ok((cmp, Value::String("String in here".to_string())))
    );
    let s = "true";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_scalar_value(from_str2(s)),
        Ok((cmp, Value::Bool(true)))
    );
    let s = "false";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_scalar_value(from_str2(s)),
        Ok((cmp, Value::Bool(false)))
    );
}

#[test]
fn test_lists_success() {
    let s = "[]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(parse_list(from_str2(s)), Ok((cmp, Value::List(vec![]))));
    let s = "[1, 2]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((cmp, Value::List(vec![Value::Int(1), Value::Int(2)])))
    );
    let s = "[\"hi\", \"there\"]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((
            cmp,
            Value::List(vec![
                Value::String("hi".to_string()),
                Value::String("there".to_string())
            ])
        ))
    );
    let s = "[1,       \"hi\",\n\n3]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 3, "", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((
            cmp,
            Value::List(vec![
                Value::Int(1),
                Value::String("hi".to_string()),
                Value::Int(3)
            ])
        ))
    );

    let s = "[[1, 2], [3, 4]]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((
            cmp,
            Value::List(vec![
                Value::List(vec![Value::Int(1), Value::Int(2)]),
                Value::List(vec![Value::Int(3), Value::Int(4)])
            ])
        ))
    );
}

#[test]
fn test_broken_lists() {
    let s = "[";
    let cmp = unsafe { Span::new_from_raw_offset(1, 1, "", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Err(nom::Err::Error(ParserError {
            span: cmp,
            kind: ErrorKind::Char,
            context: "".to_string()
        }))
    );
    let s = "[]]";
    let cmp = unsafe { Span::new_from_raw_offset(2, 1, "]", "") };
    assert_eq!(parse_list(from_str2(s)), Ok((cmp, Value::List(vec![]))))
}

#[test]
fn test_map_key_part() {
    let s = "keyword";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(key_part(from_str2(s)), Ok((cmp, "keyword".to_string())));

    let s = r#"'keyword'"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(key_part(from_str2(s)), Ok((cmp, "keyword".to_string())));

    let s = r#""keyword""#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(key_part(from_str2(s)), Ok((cmp, "keyword".to_string())));
}

#[test]
fn test_map_success() {
    let s = "{ key: 1, value: \"there\"}";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    let map = make_linked_hashmap(vec![
        ("key", Value::Int(1)),
        ("value", Value::String("there".to_string())),
    ]);

    assert_eq!(parse_map(from_str2(s)), Ok((cmp, Value::Map(map))));
    let s = "{}";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_map(from_str2(s)),
        Ok((cmp, Value::Map(IndexMap::new())))
    );
    let s = "{ key:\n 1}";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
    let map = make_linked_hashmap(vec![("key", Value::Int(1))]);
    assert_eq!(parse_map(from_str2(s)), Ok((cmp, Value::Map(map.clone()))));
    let s = "{\n\n\nkey:\n\n\n1\n\t   }";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 8, "", "") };
    assert_eq!(parse_map(from_str2(s)), Ok((cmp, Value::Map(map))));
    let s = "{ list: [{a: 1}, {b: 2}], c: 1, d: \"String\"}";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    let map = make_linked_hashmap(vec![
        (
            "list",
            Value::List(vec![
                Value::Map(make_linked_hashmap(vec![("a", Value::Int(1))])),
                Value::Map(make_linked_hashmap(vec![("b", Value::Int(2))])),
            ]),
        ),
        ("c", Value::Int(1)),
        ("d", Value::String("String".to_string())),
    ]);
    assert_eq!(parse_map(from_str2(s)), Ok((cmp, Value::Map(map.clone()))));
    assert_eq!(parse_value(from_str2(s)), Ok((cmp, Value::Map(map))));

    let s = r#"{
    'postgres':      ["postgresql", "upgrade"],
    'mariadb':       ["audit", "error", "general", "slowquery"],
    'mysql':         ["audit", "error", "general", "slowquery"],
    'oracle-ee':     ["trace", "audit", "alert", "listener"],
    'oracle-se':     ["trace", "audit", "alert", "listener"],
    'oracle-se1':    ["trace", "audit", "alert", "listener"],
    'oracle-se2':    ["trace", "audit", "alert", "listener"],
    'sqlserver-ee':  ["error", "agent"],
    'sqlserver-ex':  ["error"],
    'sqlserver-se':  ["error", "agent"],
    'sqlserver-web': ["error", "agent"],
    'aurora':        ["audit", "error", "general", "slowquery"],
    'aurora-mysql':  ["audit", "error", "general", "slowquery"],
    'aurora-postgresql': ["postgresql", "upgrade"]
}
        "#;
    let map = parse_map(from_str2(s));
    assert!(map.is_ok());
    let map = if let Ok((_ign, Value::Map(om))) = map {
        om
    } else {
        unreachable!()
    };
    assert_eq!(map.len(), 14);
    assert!(map.contains_key("aurora"));
    assert_eq!(
        map.get("aurora").unwrap(),
        &Value::List(
            ["audit", "error", "general", "slowquery"]
                .iter()
                .map(|s| Value::String((*s).to_string()))
                .collect::<Vec<Value>>()
        )
    );

    let s = r#"{"IntegrationHttpMethod":"POST","Type":"AWS_PROXY","Uri":"arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaWAFBadBotParserFunction.Arn}/invocations"}"#;
    let map = parse_map(from_str2(s));
    assert!(map.is_ok());
    let map = if let Ok((_ign, Value::Map(om))) = map {
        om
    } else {
        unreachable!()
    };
    assert_eq!(map.len(), 3);
    assert_eq!(
        map.get("IntegrationHttpMethod").unwrap(),
        &Value::String("POST".to_string())
    );
}

#[test]
fn test_map_success_2() {
    let s = r#"[
            {
                vehicle: "Honda",
                done: false
            }]"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 5, "", "") };
    let map_value = Value::Map(make_linked_hashmap(vec![
        ("vehicle", Value::String("Honda".to_string())),
        ("done", Value::Bool(false)),
    ]));
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((cmp, Value::List(vec![map_value.clone()])))
    );
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((cmp, Value::List(vec![map_value])))
    );
}

#[test]
fn test_range_type_success() {
    let s = "r(10,20)";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    let v = parse_range(from_str2(s));
    assert_eq!(
        v,
        Ok((
            cmp,
            Value::RangeInt(RangeType {
                upper: 20,
                lower: 10,
                inclusive: 0
            })
        ))
    );
    let r = match v.unwrap().1 {
        Value::RangeInt(val) => val,
        _ => unreachable!(),
    };
    assert!(!10.is_within(&r));
    assert!(15.is_within(&r));
    assert!(!20.is_within(&r));

    let s = "r[10, 20)";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    let v = parse_range(from_str2(s));
    assert_eq!(
        v,
        Ok((
            cmp,
            Value::RangeInt(RangeType {
                upper: 20,
                lower: 10,
                inclusive: LOWER_INCLUSIVE
            })
        ))
    );
    let r = match v.unwrap().1 {
        Value::RangeInt(val) => val,
        _ => unreachable!(),
    };
    assert!(10.is_within(&r));
    assert!(15.is_within(&r));
    assert!(!20.is_within(&r));
    let s = "r[10, 20]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    let v = parse_range(from_str2(s));
    assert_eq!(
        v,
        Ok((
            cmp,
            Value::RangeInt(RangeType {
                upper: 20,
                lower: 10,
                inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE
            })
        ))
    );
    let r = match v.unwrap().1 {
        Value::RangeInt(val) => val,
        _ => unreachable!(),
    };
    assert!(10.is_within(&r));
    assert!(15.is_within(&r));
    assert!(20.is_within(&r));
    let s = "r(10.2, 50.5)";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_range(from_str2(s)),
        Ok((
            cmp,
            Value::RangeFloat(RangeType {
                upper: 50.5,
                lower: 10.2,
                inclusive: 0
            })
        ))
    );
}

#[test]
fn test_range_type_failures() {
    let s = "(10, 20)";
    let cmp = unsafe { Span::new_from_raw_offset(0, 1, "(10, 20)", "") };
    assert_eq!(
        parse_range(from_str2(s)),
        Err(nom::Err::Error(ParserError {
            span: cmp,
            kind: ErrorKind::Char,
            context: "".to_string()
        }))
    );
}

//
// test with comments
//
#[test]
fn test_parse_value_with_comments() {
    let s = "1234 # this comment\n";
    let cmp = unsafe { Span::new_from_raw_offset(4, 1, " # this comment\n", "") };
    assert_eq!(parse_value(from_str2(s)), Ok((cmp, Value::Int(1234i64))));

    let s = "#this is a comment\n1234";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
    assert_eq!(parse_value(from_str2(s)), Ok((cmp, Value::Int(1234i64))));

    let s = r#"

        # this comment is skipped
        # this one too
        [ "value1", # this one is skipped as well
          "value2" ]"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 6, "", "") };
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((
            cmp,
            Value::List(vec![
                Value::String("value1".to_string()),
                Value::String("value2".to_string())
            ])
        ))
    );

    let s = r#"{
        # this comment is skipped
        # this one as well
        key: # how about this
           "Value"
        }"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 6, "", "") };
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((
            cmp,
            Value::Map(make_linked_hashmap(vec![(
                "key",
                Value::String("Value".to_string())
            )]))
        ))
    )
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                          Expressions Parsing Routines Testing                                  //
//                                                                                                //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

#[test]
fn test_white_space_with_comments() {
    let examples = [
        "",
        r###"  # this is a comment that needs to be discarded
            "###,
        r###"


                # all of this must be discarded as well
            "###,
        "let a := 10", // this must fail one_or_more, success zero_or_more
    ];

    let expectations = [
        [
            Err(nom::Err::Error(ParserError {
                span: from_str2(""),
                kind: ErrorKind::Char,
                context: "".to_string(),
            })), // white_space_or_comment
            Ok((from_str2(""), ())), // zero_or_more
            Err(nom::Err::Error(ParserError {
                span: from_str2(""),
                kind: ErrorKind::Char,
                context: "".to_string(),
            })), // white_space_or_comment
        ],
        [
            Ok((
                unsafe {
                    Span::new_from_raw_offset(
                        2,
                        1,
                        "# this is a comment that needs to be discarded\n            ",
                        "",
                    )
                },
                (),
            )), // white_space_or_comment, only consumes white-space)
            Ok((
                unsafe { Span::new_from_raw_offset(examples[1].len(), 2, "", "") },
                (),
            )), // consumes everything
            Ok((
                unsafe { Span::new_from_raw_offset(examples[1].len(), 2, "", "") },
                (),
            )), // consumes everything
        ],
        [
            //
            // Offset = 3 * '\n' + (col = 17) - 1 = 19
            //
            Ok((
                unsafe {
                    Span::new_from_raw_offset(
                        19,
                        4,
                        r###"# all of this must be discarded as well
            "###,
                        "",
                    )
                },
                (),
            )), // white_space_or_comment, only consumes white-space
            Ok((
                unsafe { Span::new_from_raw_offset(examples[2].len(), 5, "", "") },
                (),
            )), // consumes everything
            Ok((
                unsafe { Span::new_from_raw_offset(examples[2].len(), 5, "", "") },
                (),
            )), // consumes everything
        ],
        [
            Err(nom::Err::Error(ParserError {
                span: from_str2(examples[3]),
                kind: ErrorKind::Char,
                context: "".to_string(),
            })), // white_space_or_comment
            Ok((from_str2(examples[3]), ())), // zero_or_more
            Err(nom::Err::Error(ParserError {
                span: from_str2(examples[3]),
                kind: ErrorKind::Char,
                context: "".to_string(),
            })), // white_space_or_comment
        ],
    ];

    for (index, expected) in expectations.iter().enumerate() {
        for (idx, each) in [
            white_space_or_comment,
            zero_or_more_ws_or_comment,
            one_or_more_ws_or_comment,
        ]
        .iter()
        .enumerate()
        {
            let actual = each(from_str2(examples[index]));
            assert_eq!(&actual, &expected[idx]);
        }
    }
}

#[test]
fn test_var_name() {
    let examples = [
        "",                     // err
        "v",                    // ok
        "var_10",               // ok
        "_v",                   // error
        "engine_name",          // ok
        "rule_name_",           // ok
        "var_name # remaining", // ok
        "var name",             // Ok, var == "var", remaining = " name"
        "10",                   // err
    ];

    let expectations = [
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: ErrorKind::Alpha,
            context: "".to_string(),
        })),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[1].len(), 1, "", "") },
            "v".to_string(),
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            "var_10".to_string(),
        )),
        Err(nom::Err::Error(ParserError {
            span: from_str2("_v"),
            kind: ErrorKind::Alpha,
            context: "".to_string(),
        })), // white_space_or_comment
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            "engine_name".to_string(),
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[5].len(), 1, "", "") },
            "rule_name_".to_string(),
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(8, 1, " # remaining", "") },
            "var_name".to_string(),
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(3, 1, " name", "") },
            "var".to_string(),
        )),
        Err(nom::Err::Error(ParserError {
            span: from_str2("10"),
            kind: ErrorKind::Alpha,
            context: "".to_string(),
        })),
    ];

    for (idx, text) in examples.iter().enumerate() {
        let span = from_str2(text);
        let actual = var_name(span);
        assert_eq!(&actual, &expectations[idx]);
    }
}

#[test]
fn test_var_name_access() {
    let examples = [
        "",                 // Err
        "var",              // err
        "%var",             // ok
        "%_var",            // err
        "%var_10",          // ok
        " %var",            // err
        "%var # remaining", // ok
        "%var this",        // ok
    ];

    let expectations = [
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })), // white_space_or_comment
        Err(nom::Err::Error(ParserError {
            span: from_str2("var"),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            "var".to_string(),
        )),
        Err(nom::Err::Error(ParserError {
            span: unsafe { Span::new_from_raw_offset(1, 1, "_var", "") },
            kind: ErrorKind::Alpha,
            context: "".to_string(),
        })),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            "var_10".to_string(),
        )),
        Err(nom::Err::Error(ParserError {
            span: from_str2(" %var"),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        Ok((
            unsafe { Span::new_from_raw_offset("%var".len(), 1, " # remaining", "") },
            "var".to_string(),
        )),
        Ok((
            unsafe { Span::new_from_raw_offset("%var".len(), 1, " this", "") },
            "var".to_string(),
        )),
    ];

    for (idx, text) in examples.iter().enumerate() {
        let span = from_str2(text);
        let actual = var_name_access(span);
        assert_eq!(&actual, &expectations[idx]);
    }
}

fn to_query_part(vec: Vec<&str>) -> Vec<QueryPart> {
    to_string_vec(&vec)
}

fn to_string_vec<'loc>(list: &[&str]) -> Vec<QueryPart<'loc>> {
    let mut list = list
        .iter()
        .map(|part| {
            if *part == "*" {
                QueryPart::AllValues(None)
            } else {
                QueryPart::Key(String::from(*part))
            }
        })
        .collect::<Vec<QueryPart>>();
    if list[0].is_variable() {
        list.insert(1, QueryPart::AllIndices(None));
    }
    list
}

#[test]
fn test_dotted_access() {
    let examples = [
        "",                      // err
        ".",                     // err
        ".configuration.engine", // ok,
        ".config.engine.",       // ok
        ".config.easy",          // ok
        //".%engine_map.%engine", // ok
        ".*.*.port",         // ok
        ".port.*.ok",        // ok
        ".first. second",    // ok, why, as the firs part is valid, the remainder will be ". second"
        " .first.second",    // err
        ".first.0.path ",    // ok
        ".first.*.path == ", // ok
        ".first.* == ",      // ok
    ];

    let expectations = [
        // fold_many1 returns Many1 as the error, many1 appends to error hence only propagates
        // the embedded parser's error
        // "", // err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: ErrorKind::Many1,
            context: "".to_string(),
        })),
        // ".", // err
        Err(nom::Err::Error(ParserError {
            span: unsafe { Span::new_from_raw_offset(0, 1, ".", "") },
            kind: ErrorKind::Many1, // last one char('*')
            context: "".to_string(),
        })),
        // ".configuration.engine", // ok,
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            to_string_vec(&["configuration", "engine"]),
        )),
        // ".config.engine.", // Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[3].len() - 1, 1, ".", "") },
            to_string_vec(&["config", "engine"]),
        )),
        // ".config.easy", // Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            to_string_vec(&["config", "easy"]),
        )),
        //        // ".%engine_map.%engine"
        //        Ok((
        //            unsafe {
        //                Span::new_from_raw_offset(
        //                    examples[5].len(),
        //                    1,
        //                    "",
        //                    "",
        //                )
        //            },
        //            to_string_vec(&["%engine_map", "%engine"])
        //        )),

        // ".*.*.port", // ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[5].len(), 1, "", "") },
            to_string_vec(&["*", "*", "port"]),
        )),
        //".port.*.ok", // ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[6].len(), 1, "", "") },
            to_string_vec(&["port", "*", "ok"]),
        )),
        //".first. second", // Ok
        Ok((
            unsafe { Span::new_from_raw_offset(".first".len(), 1, ". second", "") },
            to_string_vec(&["first"]),
        )),
        //" .first.second", // Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[8].len(), 1, "", "") },
            to_string_vec(&["first", "second"]),
        )),
        //".first.0.path ", // ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[9].len() - 1, 1, " ", "") },
            vec![
                QueryPart::Key("first".to_string()),
                QueryPart::Index(0),
                QueryPart::Key("path".to_string()),
            ],
        )),
        //".first.*.path == ", // ok
        Ok((
            unsafe { Span::new_from_raw_offset(".first.*.path".len(), 1, " == ", "") },
            to_string_vec(&["first", "*", "path"]),
        )),
        // ".first.* == ", // ok
        Ok((
            unsafe { Span::new_from_raw_offset(".first.*".len(), 1, " == ", "") },
            to_string_vec(&["first", "*"]),
        )),
    ];

    for (idx, text) in examples.iter().enumerate() {
        let span = from_str2(text);
        let actual = dotted_access(span);
        println!("#{} Example = {}, Result = {:?}", idx, *text, actual);
        assert_eq!(&actual, &expectations[idx]);
    }
}

#[test]
fn test_access() {
    let examples = [
        "",        // 0, err
        ".",       // 1, err
        ".engine", // 2 err
        " engine", // 4 err
        // testing property access
        "engine",             // 4, ok
        "engine.type",        // 5 ok
        "engine.type.*",      // 6 ok
        "engine.*.type.port", // 7 ok
        "engine.*.type.%var", // 8 ok
        "engine[0]",          // 9 ok
        "engine [0]",         // 10 ok engine will be property access part
        "engine.ok.*",        // 11 Ok
        "engine.%name.*",     // 12 ok
        // testing variable access
        "%engine.type",         // 13 ok
        "%engine.*.type[0]",    // 14 ok
        "%engine.%type.*",      // 15 ok
        "%engine.%type.*.port", // 16 ok
        "%engine.*.",           // 17 ok . is remainder
        // matches { 'engine': [{'type': 'cfn', 'position': 1, 'other': 20}, {'type': 'tf', 'position': 2, 'other': 10}] }
        "engine[type == \"cfn\"].port", // 18 Ok
        " %engine",                     // 18 err
    ];

    let expectations = [
        Err(nom::Err::Error(ParserError {
            // 0
            span: from_str2(""),
            kind: ErrorKind::Char, // change as we use parse_string
            context: "".to_string(),
        })),
        Err(nom::Err::Error(ParserError {
            // 1
            span: from_str2("."),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        Err(nom::Err::Error(ParserError {
            // 2
            span: from_str2(".engine"),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        Err(nom::Err::Error(ParserError {
            // 3
            span: from_str2(" engine"),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        Ok((
            // 4
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            AccessQuery {
                query: vec![QueryPart::Key("engine".to_string())],
                match_all: true,
            },
        )),
        Ok((
            // 5
            unsafe { Span::new_from_raw_offset(examples[5].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Key("type".to_string()),
                ],
                match_all: true,
            },
        )),
        Ok((
            // 6
            unsafe { Span::new_from_raw_offset(examples[6].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Key("type".to_string()),
                    QueryPart::AllValues(None),
                ],
                match_all: true,
            },
        )),
        Ok((
            // 7
            unsafe { Span::new_from_raw_offset(examples[7].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Key("type".to_string()),
                    QueryPart::Key("port".to_string()),
                ],
                match_all: true,
            },
        )),
        Ok((
            // "engine.*.type.%var", // 8 ok
            unsafe { Span::new_from_raw_offset(examples[8].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Key("type".to_string()),
                    QueryPart::Key("%var".to_string()),
                ],
                match_all: true,
            },
        )),
        Ok((
            // "engine[0]", // 9 ok
            unsafe { Span::new_from_raw_offset(examples[9].len(), 1, "", "") },
            AccessQuery {
                query: vec![QueryPart::Key("engine".to_string()), QueryPart::Index(0)],
                match_all: true,
            },
        )),
        Ok((
            // 10 "engine [0]", // 10 ok engine will be property access part
            unsafe { Span::new_from_raw_offset(examples[10].len(), 1, "", "") },
            AccessQuery {
                query: vec![QueryPart::Key("engine".to_string()), QueryPart::Index(0)],
                match_all: true,
            },
        )),
        // "engine.ok.*",// 11 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[11].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Key("ok".to_string()),
                    QueryPart::AllValues(None),
                ],
                match_all: true,
            },
        )),
        // "engine.%name.*", // 12 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[12].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Key("%name".to_string()),
                    QueryPart::AllValues(None),
                ],
                match_all: true,
            },
        )),
        // "%engine.type", // 13 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[13].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("%engine".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("type".to_string()),
                ],
                match_all: true,
            },
        )),
        // "%engine.*.type[0]", // 14 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[14].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("%engine".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::AllValues(None),
                    QueryPart::Key("type".to_string()),
                    QueryPart::Index(0),
                ],
                match_all: true,
            },
        )),
        // "%engine.%type.*", // 15 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[15].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("%engine".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("%type".to_string()),
                    QueryPart::AllValues(None),
                ],
                match_all: true,
            },
        )),
        // "%engine.%type.*.port", // 16 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[16].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("%engine".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("%type".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Key("port".to_string()),
                ],
                match_all: true,
            },
        )),
        // "%engine.*.", // 17 ok . is remainder
        Ok((
            unsafe { Span::new_from_raw_offset(examples[17].len() - 1, 1, ".", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("%engine".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::AllValues(None),
                ],
                match_all: true,
            },
        )),
        // matches { 'engine': [{'type': 'cfn', 'position': 1, 'other': 20}, {'type': 'tf', 'position': 2, 'other': 10}] }
        // "engine[type==\"cfn\"].port", // 18 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[18].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Filter(
                        None,
                        vec![vec![GuardClause::Clause(GuardAccessClause {
                            access_clause: AccessClause {
                                query: AccessQuery {
                                    query: vec![QueryPart::Key(String::from("type"))],
                                    match_all: true,
                                },
                                comparator: (CmpOperator::Eq, false),
                                custom_message: None,
                                compare_with: Some(LetValue::Value(
                                    PathAwareValue::try_from(Value::String(String::from("cfn")))
                                        .unwrap(),
                                )),
                                location: FileLocation {
                                    line: 1,
                                    column: "engine[".len() as u32 + 1,
                                    file_name: "",
                                },
                            },
                            negation: false,
                        })]],
                    ),
                    QueryPart::Key(String::from("port")),
                ],
                match_all: true,
            },
        )),
        // " %engine", // 18 err
        Err(nom::Err::Error(ParserError {
            // 19
            span: from_str2(" %engine"),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = Span::new_extra(*each, "");
        let result = access(span);
        println!("Testing @{}, Result = {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_other_operations() {
    let examples = [
        "",                  // 0 err
        " exists",           // 1 err
        "exists",            // 2 ok
        "not exists",        // 3 ok
        "!exists",           // 4 ok
        "!EXISTS",           // 5 ok
        "notexists",         // 6 err
        "in",                // 7, ok
        "not in",            // 8 ok
        "!in",               // 9 ok,
        "EMPTY",             // 10 ok,
        "! EMPTY",           // 11 err
        "NOT EMPTY",         // 12 ok
        "IN [\"t\", \"n\"]", // 13 ok
    ];

    let expectations = [
        // "", // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            context: "".to_string(),
            kind: ErrorKind::Tag,
        })),
        // " exists", // 1 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(" exists"),
            context: "".to_string(),
            kind: ErrorKind::Tag,
        })),
        // "exists", // 2 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            (CmpOperator::Exists, false),
        )),
        // "not exists", // 3 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[3].len(), 1, "", "") },
            (CmpOperator::Exists, true),
        )),
        // "!exists", // 4 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            (CmpOperator::Exists, true),
        )),
        // "!EXISTS", // 5 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[5].len(), 1, "", "") },
            (CmpOperator::Exists, true),
        )),
        // "notexists", // 6 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(examples[6]),
            //
            // why Tag?, not is optional, this is without space
            // so it discards opt and then tries, in, exists or empty
            // all of them fail with tag
            //
            kind: ErrorKind::Tag,
            context: "".to_string(),
        })),
        // "in", // 7, ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[7].len(), 1, "", "") },
            (CmpOperator::In, false),
        )),
        // "not in", // 8 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[8].len(), 1, "", "") },
            (CmpOperator::In, true),
        )),
        // "!in", // 9 ok,
        Ok((
            unsafe { Span::new_from_raw_offset(examples[9].len(), 1, "", "") },
            (CmpOperator::In, true),
        )),
        // "EMPTY", // 10 ok,
        Ok((
            unsafe { Span::new_from_raw_offset(examples[10].len(), 1, "", "") },
            (CmpOperator::Empty, false),
        )),
        // "! EMPTY", // 11 err
        Err(nom::Err::Error(ParserError {
            span: unsafe { Span::new_from_raw_offset(1, 1, " EMPTY", "") },
            kind: ErrorKind::Tag,
            context: "".to_string(),
        })),
        // "NOT EMPTY", // 12 ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[12].len(), 1, "", "") },
            (CmpOperator::Empty, true),
        )),
        // "IN [\"t\", \"n\"]", // 13 ok
        Ok((
            unsafe { Span::new_from_raw_offset(2, 1, " [\"t\", \"n\"]", "") },
            (CmpOperator::In, false),
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(each);
        let result = other_operations(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_keys_keyword() {
    let examples = [
        "",                         // 0 err
        "[KEYS]",                   // 1 err
        "[KEYS IN %var]",           // 2 Ok
        "[KEYS NOT IN %var]",       // 3 Ok
        "[KEYS == /aws:S/]",        // 6 Ok
        "[KEYS != 'aws:IsSecure']", // 7 Ok
        "[keys !in %var]",          // 8 err after !
        "KEYS IN",                  // 11 err
        "KEYS ",                    // 12 err
    ];

    let expectations = [
        // "", // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        // "KEYS", // 1 err
        //
        // A recoverable `Error`, not a `Failure`, and that change is the point rather than an accident.
        // `map_keys_match` used to commit with `cut` the moment it had seen `keys`, so `[ keys EXISTS ]`
        // could never fall through to the filter-clause branch that parses it -- a filter on a property
        // actually named `keys` was unparsable in first position and parsed one slot later, which is how
        // it was established that nothing ambiguous forced the rejection.
        //
        // `keys` stays reserved for the four key-filter comparators; it is no longer reserved for every
        // other clause that happens to start with it.
        Err(nom::Err::Error(ParserError {
            span: unsafe { Span::new_from_raw_offset("[KEYS".len(), 1, "]", "") },
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        // "KEYS IN", // 2 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            QueryPart::MapKeyFilter(
                None,
                MapKeyFilterClause {
                    comparator: MapKeyComparator::In,
                    compare_with: LetValue::AccessClause(AccessQuery {
                        match_all: true,
                        query: vec![QueryPart::Key("%var".to_string())],
                    }),
                },
            ),
        )),
        // "KEYS NOT IN", // 3 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[3].len(), 1, "", "") },
            QueryPart::MapKeyFilter(
                None,
                MapKeyFilterClause {
                    comparator: MapKeyComparator::NotIn,
                    compare_with: LetValue::AccessClause(AccessQuery {
                        match_all: true,
                        query: vec![QueryPart::Key("%var".to_string())],
                    }),
                },
            ),
        )),
        // "[KEYS == /aws:S/]", // 6 Ok
        // "KEYS ==", // 6 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            QueryPart::MapKeyFilter(
                None,
                MapKeyFilterClause {
                    comparator: MapKeyComparator::Eq,
                    compare_with: LetValue::Value(
                        PathAwareValue::try_from(Value::Regex("aws:S".to_string())).unwrap(),
                    ),
                },
            ),
        )),
        // "[KEYS != 'aws:IsSecure']", // 7 Ok
        // "KEYS !=", // 7 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[5].len(), 1, "", "") },
            QueryPart::MapKeyFilter(
                None,
                MapKeyFilterClause {
                    comparator: MapKeyComparator::NotEq,
                    compare_with: LetValue::Value(
                        PathAwareValue::try_from(Value::String("aws:IsSecure".to_string()))
                            .unwrap(),
                    ),
                },
            ),
        )),
        // "[keys !in %var]", // 8 err after !
        Ok((
            unsafe { Span::new_from_raw_offset(examples[6].len(), 1, "", "") },
            QueryPart::MapKeyFilter(
                None,
                MapKeyFilterClause {
                    comparator: MapKeyComparator::NotIn,
                    compare_with: LetValue::AccessClause(AccessQuery {
                        match_all: true,
                        query: vec![QueryPart::Key("%var".to_string())],
                    }),
                },
            ),
        )),
        // " KEYS IN", // 11 err
        Err(nom::Err::Error(ParserError {
            span: from_str2("KEYS IN"),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        // "KEYS ", // 12 err
        Err(nom::Err::Error(ParserError {
            span: from_str2("KEYS "),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(each);
        let result = map_keys_match(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_value_cmp() {
    let examples = [
        "",      // err 0
        " >",    // err 1,
        ">",     // ok, 2
        ">=",    // ok, 3
        "<",     // ok, 4
        "<= ",   // ok, 5
        ">=\n",  // ok, 6
        "IN\n",  // ok 7
        "!IN\n", // ok 8
    ];

    let expectations = [
        // "", // err 0
        Err(nom::Err::Error(ParserError {
            span: from_str2(examples[0]),
            context: "".to_string(),
            kind: ErrorKind::Tag,
        })),
        // " >", // err 1,
        Err(nom::Err::Error(ParserError {
            span: from_str2(examples[1]),
            context: "".to_string(),
            kind: ErrorKind::Tag,
        })),
        // ">", // ok, 2
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            (CmpOperator::Gt, false),
        )),
        // ">=", // ok, 3
        Ok((
            unsafe { Span::new_from_raw_offset(examples[3].len(), 1, "", "") },
            (CmpOperator::Ge, false),
        )),
        // "<", // ok, 4
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 1, "", "") },
            (CmpOperator::Lt, false),
        )),
        // "<= ", // ok, 5
        Ok((
            unsafe { Span::new_from_raw_offset(examples[5].len() - 1, 1, " ", "") },
            (CmpOperator::Le, false),
        )),
        // ">=\n", // ok, 6
        Ok((
            unsafe { Span::new_from_raw_offset(examples[6].len() - 1, 1, "\n", "") },
            (CmpOperator::Ge, false),
        )),
        // "IN\n", // ok 7
        Ok((
            unsafe { Span::new_from_raw_offset(examples[7].len() - 1, 1, "\n", "") },
            (CmpOperator::In, false),
        )),
        // "!IN\n", // ok 8
        Ok((
            unsafe { Span::new_from_raw_offset(examples[8].len() - 1, 1, "\n", "") },
            (CmpOperator::In, true),
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(each);
        let result = value_cmp(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_clause_success() {
    let lhs = ["configuration.containers.*.image", "engine"];

    let rhs = "PARAMETERS.ImageList";
    let comparators = [
        (">", (CmpOperator::Gt, false)),
        ("<", (CmpOperator::Lt, false)),
        ("==", (CmpOperator::Eq, false)),
        ("!=", (CmpOperator::Eq, true)),
        ("IN", (CmpOperator::In, false)),
        ("!IN", (CmpOperator::In, true)),
        ("not IN", (CmpOperator::In, true)),
        ("NOT IN", (CmpOperator::In, true)),
    ];
    let separators = [
        (" ", " "),
        ("\t", "\n\n\t"),
        ("\t  ", "\t\t"),
        (" ", "\n#this comment\n"),
        (" ", "#this comment\n"),
    ];

    let rhs_dotted: Vec<&str> = rhs.split('.').collect();
    let rhs_dotted = to_string_vec(&rhs_dotted);
    let rhs_access = Some(LetValue::AccessClause(AccessQuery {
        query: rhs_dotted,
        match_all: true,
    }));

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split('.').collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery {
            query: dotted,
            match_all: true,
        };
        testing_access_with_cmp(
            &separators,
            &comparators,
            each_lhs,
            rhs,
            || dotted.clone(),
            || rhs_access.clone(),
        );
    }

    let comparators = [
        ("EXISTS", (CmpOperator::Exists, false)),
        ("!EXISTS", (CmpOperator::Exists, true)),
        ("EMPTY", (CmpOperator::Empty, false)),
        ("NOT EMPTY", (CmpOperator::Empty, true)),
    ];

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split('.').collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery {
            query: dotted,
            match_all: true,
        };

        testing_access_with_cmp(
            &separators,
            &comparators,
            each_lhs,
            "",
            || dotted.clone(),
            || None,
        );
    }

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split('.').collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery {
            query: dotted,
            match_all: true,
        };

        testing_access_with_cmp(
            &separators,
            &comparators,
            each_lhs,
            " does.not.error", // this will not error,
            // the fragment you are left with is the one above and
            // the next clause fetch will error out for either no "OR" or
            // not newline for "and"
            || dotted.clone(),
            || None,
        );
    }

    let lhs = [
        "%engine.port",
        //"%engine.%port",
        "%engine.*.image",
    ];

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split('.').collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery {
            query: dotted,
            match_all: true,
        };

        testing_access_with_cmp(
            &separators,
            &comparators,
            each_lhs,
            "",
            || dotted.clone(),
            || None,
        );
    }

    let rhs = [
        "\"ami-12344545\"",
        "/ami-12/",
        "[\"ami-12\", \"ami-21\"]",
        "{ bare: 10, 'work': 20, 'other': 12.4 }",
    ];
    let comparators = [
        (">", (CmpOperator::Gt, false)),
        ("<", (CmpOperator::Lt, false)),
        ("==", (CmpOperator::Eq, false)),
        ("!=", (CmpOperator::Eq, true)),
        ("IN", (CmpOperator::In, false)),
        ("!IN", (CmpOperator::In, true)),
    ];

    for each_rhs in &rhs {
        for each_lhs in lhs.iter() {
            let dotted = (*each_lhs).split('.').collect::<Vec<&str>>();
            let dotted = to_string_vec(&dotted);
            let dotted = AccessQuery {
                query: dotted,
                match_all: true,
            };

            let rhs_value =
                PathAwareValue::try_from(parse_value(from_str2(each_rhs)).unwrap().1).unwrap();
            testing_access_with_cmp(
                &separators,
                &comparators,
                each_lhs,
                each_rhs,
                || dotted.clone(),
                || Some(LetValue::Value(rhs_value.clone())),
            );
        }
    }
}

fn testing_access_with_cmp<'loc, A, C>(
    separators: &[(&str, &str)],
    comparators: &[(&str, (CmpOperator, bool))],
    lhs: &str,
    rhs: &str,
    access: A,
    cmp_with: C,
) where
    A: Fn() -> AccessQuery<'loc>,
    C: Fn() -> Option<LetValue<'loc>>,
{
    for (lhs_sep, rhs_sep) in separators {
        for (each_op, value_cmp) in comparators.iter() {
            let access_pattern = format!(
                "{lhs}{lhs_sep}{op}{rhs_sep}{rhs}",
                lhs = lhs,
                rhs = rhs,
                op = *each_op,
                lhs_sep = *lhs_sep,
                rhs_sep = *rhs_sep
            );
            println!("Testing Access pattern = {}", access_pattern);
            let span = from_str2(&access_pattern);
            let result = clause(span);
            if let Err(parser_error) = result {
                let parser_error = match parser_error {
                    nom::Err::Error(p) | nom::Err::Failure(p) => {
                        format!("ParserError = {} fragment = {}", p, *p.span.fragment())
                    }
                    nom::Err::Incomplete(_) => "More input needed".to_string(),
                };
                println!("{}", parser_error);
                assert_eq!(false, true);
            } else {
                assert!(result.is_ok());
                let result_clause = match result.unwrap().1 {
                    GuardClause::Clause(clause) => clause,
                    _ => unreachable!(),
                };
                let result = &result_clause.access_clause;
                assert_eq!(result.query, access());
                assert_eq!(result.compare_with, cmp_with());
                assert_eq!(&result.comparator, value_cmp);
                assert_eq!(result.custom_message, None);
            }
        }
    }
}

#[test]
fn test_predicate_clause_success() {
    let examples = [
        "resources",                         // 0 Ok
        "resources.*.type",                  // 1 Ok
        "resources.*[ type == /AWS::RDS/ ]", // 2 Ok
        r#"resources.*[ type == /AWS::RDS/
                            deletion_policy EXISTS
                            deletion_policy == "RETAIN" ].properties"#, // 3 ok
        r#"resources.*[]"#,                  // 4 err
        "resources.*[type == /AWS::RDS/",    // 4 err
    ];

    let expectations = [
        // "resources", // 0 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[0].len(), 1, "", "") },
            AccessQuery {
                query: vec![QueryPart::Key(examples[0].to_string())],
                match_all: true,
            },
        )),
        // "resources.*.type", // 1 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[1].len(), 1, "", "") },
            AccessQuery {
                query: to_query_part(examples[1].split('.').collect()),
                match_all: true,
            },
        )),
        // "resources.*[ type == /AWS::RDS/ ]", // 2 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("resources".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Filter(
                        None,
                        Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(
                                        PathAwareValue::try_from(Value::Regex(
                                            "AWS::RDS".to_string(),
                                        ))
                                        .unwrap(),
                                    )),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from("type"))],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 1,
                                        column: "resources.*[ ".len() as u32 + 1,
                                        file_name: "",
                                    },
                                },
                                negation: false,
                            },
                        )])]),
                    ),
                ],
                match_all: true,
            },
        )),
        // r#"resources.*[ type == /AWS::RDS/
        //                 deletion_policy EXISTS
        //                 deletion_policy == "RETAIN" ].properties"#
        Ok((
            unsafe { Span::new_from_raw_offset(examples[3].len(), 3, "", "") },
            AccessQuery {
                query: vec![
                    QueryPart::Key("resources".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Filter(
                        None,
                        Conjunctions::from([
                            Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(
                                        PathAwareValue::try_from(Value::Regex(
                                            "AWS::RDS".to_string(),
                                        ))
                                        .unwrap(),
                                    )),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from("type"))],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 1,
                                        column: "resources.*[ ".len() as u32 + 1,
                                        file_name: "",
                                    },
                                },
                                negation: false,
                            })]),
                            Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: None,
                                    comparator: (CmpOperator::Exists, false),
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from(
                                            "deletion_policy",
                                        ))],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 2,
                                        column: 29,
                                        file_name: "",
                                    },
                                },
                                negation: false,
                            })]),
                            Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(
                                        PathAwareValue::try_from(Value::String(
                                            "RETAIN".to_string(),
                                        ))
                                        .unwrap(),
                                    )),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from(
                                            "deletion_policy",
                                        ))],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 3,
                                        column: 29,
                                        file_name: "",
                                    },
                                },
                                negation: false,
                            })]),
                        ]),
                    ),
                    QueryPart::Key("properties".to_string()),
                ],
                match_all: true,
            },
        )),
        // r#"resources.*[]"#, // 4 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe { Span::new_from_raw_offset("resources.*[".len(), 1, "]", "") },
            context: "There were no clauses present #1@13".to_string(),
            kind: ErrorKind::Many1, // for negative number in parse_int_value
        })),
        // "resources.*[type == /AWS::RDS/", // 5 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset("resources.*[type == /AWS::RDS/".len(), 1, "", "")
            },
            context: "".to_string(),
            kind: ErrorKind::Char,
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Test # {}: {}", idx, *each);
        let span = from_str2(each);
        let result = access(span);
        println!("Result for Test # {}, {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_clause_failures() {
    let lhs = ["configuration.containers.*.image", "engine"];

    //
    // Testing white space problems
    //
    let _rhs = "PARAMETERS.ImageList";
    let _lhs_separator = "";
    let _rhs_separator = "";
    let comparators = [
        (">", (CmpOperator::Gt, false)),
        ("<", (CmpOperator::Lt, false)),
        ("==", (CmpOperator::Eq, false)),
        ("!=", (CmpOperator::Eq, true)),
    ];

    //
    // Testing for missing access part
    //
    assert_eq!(
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        clause(from_str2(""))
    );

    //
    // Testing for missing access
    //
    assert_eq!(
        Err(nom::Err::Error(ParserError {
            span: unsafe { Span::new_from_raw_offset(1, 1, "> 10", "") },
            kind: ErrorKind::Char,
            context: "".to_string(),
        })),
        clause(from_str2(" > 10"))
    );

    //
    // Testing binary operator missing RHS
    //
    for each in lhs.iter() {
        for (op, _) in comparators.iter() {
            let access_pattern = format!("{lhs} {op} << message >>", lhs = *each, op = *op);
            println!("Testing for {}", access_pattern);
            let offset = (*each).len() + (*op).len() + 1; // 2 is for 2 spaces
            let error = Err(nom::Err::Failure(ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        offset,
                        1,
                        " << message >>",
                        "",
                    )
                },
                kind: ErrorKind::Char, // this comes off access
                context: r#"expecting either a property access "engine.core" or value like "string" or ["this", "that"]"#.to_string(),
            }));
            assert_eq!(clause(from_str2(&access_pattern)), error);
        }
    }
}

#[test]
fn test_rule_clauses() {
    let examples = [
        "",                                                              // 0 err
        "secure\n",                                                      // 1 Ok
        "!secure or !encrypted",                                         // 2 Ok
        "secure\n\nor\t encrypted",                                      // 3 Ok
        "let x = 10",                                                    // 4 err
        "port == 10",                                                    // 5 err
        "secure <<this is secure ${PARAMETER.MSG}>>",                    // 6 Ok
        "!secure <<this is not secure ${PARAMETER.MSG}>> or !encrypted", // 7 Ok
    ];

    let expectations = [
        // "",                             // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: ErrorKind::Alpha,
            context: "".to_string(),
        })),
        // "secure",                       // 1 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[1].len() - 1, 1, "\n", "") },
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: false,
                custom_message: None,
            }),
        )),
        // "!secure or !encrypted",        // 2 Ok
        Ok((
            unsafe { Span::new_from_raw_offset("!secure".len(), 1, " or !encrypted", "") },
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: true,
                custom_message: None,
            }),
        )),
        // "secure\n\nor\t encrypted",     // 3 Ok
        Ok((
            unsafe { Span::new_from_raw_offset("secure".len(), 1, "\n\nor\t encrypted", "") },
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: false,
                custom_message: None,
            }),
        )),
        // "let x = 10",                   // 4 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe { Span::new_from_raw_offset("let ".len(), 1, "x = 10", "") },
            kind: ErrorKind::Tag,
            context: "".to_string(),
        })),
        // "port == 10",                   // 5 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe { Span::new_from_raw_offset("port ".len(), 1, "== 10", "") },
            kind: ErrorKind::Tag,
            context: "".to_string(),
        })),
        // "secure <<this is secure ${PARAMETER.MSG}>>", // 6 Ok
        Ok((
            unsafe { Span::new_from_raw_offset(examples[6].len(), 1, "", "") },
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: false,
                custom_message: Some("this is secure ${PARAMETER.MSG}".to_string()),
            }),
        )),
        // "!secure <<this is not secure ${PARAMETER.MSG}>> or !encrypted" // 8 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[7].len() - " or !encrypted".len(),
                    1,
                    " or !encrypted",
                    "",
                )
            },
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: true,
                custom_message: Some("this is not secure ${PARAMETER.MSG}".to_string()),
            }),
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(each);
        let result = rule_clause(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_clauses() {
    let examples = [
        "",                                                         // Ok 0
        "secure\n",                                                 // Ok 1
        "!secure << was not secure ${PARAMETER.SECURE_MSG}>>",      // Ok 2
        "secure\nconfigurations.containers.*.image == /httpd:2.4/", // Ok 3
        r#"secure or
               !exception

               configurations.containers[*].image == /httpd:2.4/"#, // Ok 4
        r#"secure or
               !exception
               let x = 10"#, // Ok 5
    ];

    let expectations = [
        // "", // err 0
        Err(nom::Err::Failure(ParserError {
            span: unsafe { Span::new_from_raw_offset(0, 1, "", "") },
            context: "There were no clauses present #1@1".to_string(),
            kind: ErrorKind::Many1, // for negative number in parse_int_value
        })),
        // "secure\n", // Ok 1
        Ok((
            unsafe { Span::new_from_raw_offset(examples[1].len() - 1, 1, "\n", "") },
            vec![vec![GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: false,
                custom_message: None,
            })]],
        )),
        // "!secure << was not secure ${PARAMETER.SECURE_MSG}>>", // Ok 2
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            vec![vec![GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: "secure".to_string(),
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: "",
                },
                negation: true,
                custom_message: Some(" was not secure ${PARAMETER.SECURE_MSG}".to_string()),
            })]],
        )),
        // "secure\nconfigurations.containers.*.image == /httpd:2.4/", // Ok 3
        Ok((
            unsafe { Span::new_from_raw_offset(examples[3].len(), 2, "", "") },
            vec![
                vec![GuardClause::NamedRule(GuardNamedRuleClause {
                    dependent_rule: "secure".to_string(),
                    location: FileLocation {
                        line: 1,
                        column: 1,
                        file_name: "",
                    },
                    negation: false,
                    custom_message: None,
                })],
                vec![GuardClause::Clause(GuardAccessClause {
                    access_clause: AccessClause {
                        location: FileLocation {
                            file_name: "",
                            column: 1,
                            line: 2,
                        },
                        compare_with: Some(LetValue::Value(
                            PathAwareValue::try_from(Value::Regex("httpd:2.4".to_string()))
                                .unwrap(),
                        )),
                        query: AccessQuery {
                            query: "configurations.containers.*.image"
                                .split('.')
                                .map(|s| {
                                    if s == "*" {
                                        QueryPart::AllValues(None)
                                    } else {
                                        QueryPart::Key(s.to_string())
                                    }
                                })
                                .collect(),
                            match_all: true,
                        },
                        custom_message: None,
                        comparator: (CmpOperator::Eq, false),
                    },
                    negation: false,
                })],
            ],
        )),
        // r#"secure or
        //    !exception
        //
        //    configurations.containers.*.image == /httpd:2.4/"#, // Ok 4
        Ok((
            unsafe { Span::new_from_raw_offset(examples[4].len(), 4, "", "") },
            vec![
                vec![
                    GuardClause::NamedRule(GuardNamedRuleClause {
                        dependent_rule: "secure".to_string(),
                        location: FileLocation {
                            line: 1,
                            column: 1,
                            file_name: "",
                        },
                        negation: false,
                        custom_message: None,
                    }),
                    GuardClause::NamedRule(GuardNamedRuleClause {
                        dependent_rule: "exception".to_string(),
                        location: FileLocation {
                            line: 2,
                            column: 16,
                            file_name: "",
                        },
                        negation: true,
                        custom_message: None,
                    }),
                ],
                vec![GuardClause::Clause(GuardAccessClause {
                    access_clause: AccessClause {
                        location: FileLocation {
                            file_name: "",
                            column: 16,
                            line: 4,
                        },
                        compare_with: Some(LetValue::Value(
                            PathAwareValue::try_from(Value::Regex("httpd:2.4".to_string()))
                                .unwrap(),
                        )),
                        query: AccessQuery {
                            query: "configurations.containers[*].image"
                                .split('.')
                                .flat_map(|part| {
                                    if part.contains('[') {
                                        vec![
                                            QueryPart::Key("containers".to_string()),
                                            QueryPart::AllIndices(None),
                                        ]
                                    } else {
                                        vec![QueryPart::Key(part.to_string())]
                                    }
                                })
                                .collect(),
                            match_all: true,
                        },
                        custom_message: None,
                        comparator: (CmpOperator::Eq, false),
                    },
                    negation: false,
                })],
            ],
        )),
        // r#"secure or
        //    !exception
        //    let x = 10"# // Err, can not handle assignments
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(examples[5].len() - "x = 10".len(), 3, "x = 10", "")
            },
            kind: ErrorKind::Tag,
            context: "".to_string(),
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Testing #{}, Case = {}", idx, each);
        let span = from_str2(each);
        let result = clauses(span);
        assert_eq!(&result, &expectations[idx]);
        println!("{:?}", result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[rstest::rstest]
#[case("letx", Err(nom::Err::Error(ParserError {
    span: unsafe {
        Span::new_from_raw_offset(
            "let".len(),
            1,
            "x",
            ""
            )
    },
    context: "".to_string(),
    kind: nom::error::ErrorKind::Char, // from comment
})))]
// Still a Failure at the same place, and it now says what is missing. The sign is what tells an assignment
// from a clause about a property named `let`, so the two readings are separated here rather than by a `cut`;
// see `let_assignment_expr`.
#[case("let x", Err(nom::Err::Failure(ParserError {
    span: unsafe {
        Span::new_from_raw_offset(
            "let x".len(),
            1,
            "",
            ""
            )
    },
    context: "Expected = or := after let x, as in \"let x = 10\".".to_string(),
    kind: nom::error::ErrorKind::Tag, // from "="
})))]
#[case("let x = 10",
       Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "let x = 10".len(),
                    1,
                    "",
                    ""
                    )
            },
            LetExpr {
                var: String::from("x"),
                value: LetValue::Value(PathAwareValue::try_from(Value::Int(10)).unwrap())
            }
            )))]
#[case("let x = [10, 20]", Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "let x = [10, 20]".len(),
                    1,
                    "",
                    ""
                    )
            },
            LetExpr {
                var: String::from("x"),
                value: LetValue::Value(PathAwareValue::try_from(Value::List(vec![
                                                                            Value::Int(10), Value::Int(20)
                ])).unwrap())
            }
            )))]
#[case("let x = engine", Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "let x = engine".len(),
                    1,
                    "",
                    ""
                    )
            },
            LetExpr {
                var: String::from("x"),
                value: LetValue::AccessClause(AccessQuery{ query: vec![
                    QueryPart::Key(String::from("engine"))], match_all: true })
            }
            )))]
#[case("let engines = %engines", Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "let engines = %engines".len(),
                    1,
                    "",
                    ""
                    )
            },
            LetExpr {
                var: String::from("engines"),
                value: LetValue::AccessClause(AccessQuery{ query: vec![
                    QueryPart::Key(String::from("%engines"))], match_all: true })
            }
            )))]
#[case("let x =", Err(nom::Err::Failure(ParserError {
    span: unsafe {
        Span::new_from_raw_offset(
            "let x =".len(),
            1,
            "",
            ""
            )
    },
    context: "".to_string(),
    kind: nom::error::ErrorKind::Char, // from access with usage of parse_string
})))]
#[case("let aurora_dbs = resources.*[ type IN [/AWS::RDS::DBCluster/, /AWS::RDS::GlobalCluster/]]", Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "let aurora_dbs = resources.*[ type IN [/AWS::RDS::DBCluster/, /AWS::RDS::GlobalCluster/]]".len(),
                    1,
                    "",
                    ""
                    )
            },
            LetExpr {
                var: String::from("aurora_dbs"),
                value: LetValue::AccessClause(AccessQuery {
                    query: vec![
                        QueryPart::Key(String::from("resources")),
                        QueryPart::AllValues(None),
                        QueryPart::Filter(None, Conjunctions::from(
                                [
                                Disjunctions::from(
                                    [
                                    GuardClause::Clause(
                                        GuardAccessClause {
                                            access_clause: AccessClause {
                                                compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::List(
                                                                              vec![Value::Regex(String::from("AWS::RDS::DBCluster")),
                                                                              Value::Regex(String::from("AWS::RDS::GlobalCluster"))])).unwrap())),
                                                                              query: AccessQuery{ query: vec![QueryPart::Key(String::from("type"))], match_all: true },
                                                                              custom_message: None,
                                                                              comparator: (CmpOperator::In, false),
                                                                              location: FileLocation {
                                                                                  line: 1,
                                                                                  column: "let aurora_dbs = resources.*[ ".len() as u32 + 1,
                                                                                  file_name: ""
                                                                              }
                                            },
                                            negation: false
                                        }
                                        ),
                                    ]),
                                    ],
                                    ))
                                        ], match_all: true }
                )
            }

)))]
#[case(r#"let ENGINE_LOGS = {
    'mariadb':       ["audit", "error", "general", "slowquery"],
    'aurora-postgresql': ["postgresql", "upgrade"]
}"#, Ok((
        unsafe {
            Span::new_from_raw_offset(
r#"let ENGINE_LOGS = {
    'mariadb':       ["audit", "error", "general", "slowquery"],
    'aurora-postgresql': ["postgresql", "upgrade"]
}"#.len(),
                4,
                "",
                ""
                )
        },
        LetExpr {
            var: String::from("ENGINE_LOGS"),
            value: LetValue::Value(PathAwareValue::try_from(r#"
        {
            'mariadb':       ["audit", "error", "general", "slowquery"],
            'aurora-postgresql': ["postgresql", "upgrade"]
        }
                "#).unwrap())
        }
        )))]
fn test_assignments(#[case] each: &str, #[case] expected: IResult<Span, LetExpr>) {
    let span = Span::new_extra(each, "");
    let result = assignment(span);
    assert_eq!(result, expected);
}

#[test]
fn test_type_name() {
    let examples = [
        "AWS::Resource::Type",
        "Custom::Resource",
        "AWS::Module::Type::MODULE",
        "AWS::", // Failure
    ];
    let expectations = [
        Ok((
            unsafe { Span::new_from_raw_offset(examples[0].len(), 1, "", "") },
            TypeName {
                type_name: String::from("AWS::Resource::Type"),
            },
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[1].len(), 1, "", "") },
            TypeName {
                type_name: String::from("Custom::Resource"),
            },
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 1, "", "") },
            TypeName {
                type_name: String::from("AWS::Module::Type"),
            },
        )),
        Err(nom::Err::Error(ParserError {
            span: unsafe { Span::new_from_raw_offset(examples[3].len(), 1, "", "") },
            kind: ErrorKind::Alpha,
            context: "".to_string(),
        })),
    ];
    for (idx, each) in examples.iter().enumerate() {
        println!("Test #{}: {}", idx, *each);
        let span = Span::new_extra(*each, "");
        let result = type_name(span);
        println!("Test #{} Result: {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_type_block() {
    let examples = [
        r#"AWS::EC2::Instance {
                let keyName := keyName

                %keyName        IN ["keyName", "keyName2", "keyName3"]
                %keyName        NOT IN ["keyNameIs", "notInthis"]
            }"#,
        r#"AWS::EC2::Instance keyName == /EC2_KEY/"#,
        r#"AWS::EC2::Instance when instance_type == "m4.xlarge" {
                security_groups EXISTS
            }"#,
    ];

    let expectations = [
        Ok((
            unsafe { Span::new_from_raw_offset(examples[0].len(), 6, "", "") },
            TypeBlock {
                type_name: String::from("AWS::EC2::Instance"),
                conditions: None,
                block: Block {
                    assignments: vec![LetExpr {
                        var: String::from("keyName"),
                        value: LetValue::AccessClause(AccessQuery {
                            query: vec![QueryPart::Key(String::from("keyName"))],
                            match_all: true,
                        }),
                    }],
                    conjunctions: Conjunctions::from([
                        Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                            access_clause: AccessClause {
                                query: AccessQuery {
                                    query: vec![QueryPart::Key(String::from("%keyName"))],
                                    match_all: true,
                                },
                                comparator: (CmpOperator::In, false),
                                custom_message: None,
                                compare_with: Some(LetValue::Value(
                                    PathAwareValue::try_from(Value::List(vec![
                                        Value::String(String::from("keyName")),
                                        Value::String(String::from("keyName2")),
                                        Value::String(String::from("keyName3")),
                                    ]))
                                    .unwrap(),
                                )),
                                location: FileLocation {
                                    file_name: "",
                                    column: 17,
                                    line: 4,
                                },
                            },
                            negation: false,
                        })]),
                        Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                            access_clause: AccessClause {
                                query: AccessQuery {
                                    query: vec![QueryPart::Key(String::from("%keyName"))],
                                    match_all: true,
                                },
                                comparator: (CmpOperator::In, true),
                                custom_message: None,
                                compare_with: Some(LetValue::Value(
                                    PathAwareValue::try_from(Value::List(vec![
                                        Value::String(String::from("keyNameIs")),
                                        Value::String(String::from("notInthis")),
                                    ]))
                                    .unwrap(),
                                )),
                                location: FileLocation {
                                    file_name: "",
                                    column: 17,
                                    line: 5,
                                },
                            },
                            negation: false,
                        })]),
                    ]),
                },
                query: vec![
                    QueryPart::Key("Resources".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Filter(
                        None,
                        Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                            GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key("Type".to_string())],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        column: 1,
                                        line: 1,
                                        file_name: "",
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((
                                        Path::root(),
                                        "AWS::EC2::Instance".to_string(),
                                    )))),
                                    comparator: (CmpOperator::Eq, false),
                                },
                            },
                        )])]),
                    ),
                ],
            },
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[1].len(), 1, "", "") },
            TypeBlock {
                type_name: String::from("AWS::EC2::Instance"),
                conditions: None,
                block: Block {
                    assignments: vec![],
                    conjunctions: vec![vec![GuardClause::Clause(GuardAccessClause {
                        access_clause: AccessClause {
                            query: AccessQuery {
                                query: vec![QueryPart::Key(String::from("keyName"))],
                                match_all: true,
                            },
                            comparator: (CmpOperator::Eq, false),
                            location: FileLocation {
                                file_name: "",
                                column: ("AWS::EC2::Instance ".len() + 1) as u32,
                                line: 1,
                            },
                            compare_with: Some(LetValue::Value(
                                PathAwareValue::try_from(Value::Regex("EC2_KEY".to_string()))
                                    .unwrap(),
                            )),
                            custom_message: None,
                        },
                        negation: false,
                    })]],
                },
                query: vec![
                    QueryPart::Key("Resources".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Filter(
                        None,
                        Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                            GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key("Type".to_string())],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        column: 1,
                                        line: 1,
                                        file_name: "",
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((
                                        Path::root(),
                                        "AWS::EC2::Instance".to_string(),
                                    )))),
                                    comparator: (CmpOperator::Eq, false),
                                },
                            },
                        )])]),
                    ),
                ],
            },
        )),
        Ok((
            unsafe { Span::new_from_raw_offset(examples[2].len(), 3, "", "") },
            TypeBlock {
                type_name: String::from("AWS::EC2::Instance"),
                conditions: Some(vec![vec![WhenGuardClause::Clause(GuardAccessClause {
                    access_clause: AccessClause {
                        query: AccessQuery {
                            query: vec![QueryPart::Key(String::from("instance_type"))],
                            match_all: true,
                        },
                        comparator: (CmpOperator::Eq, false),
                        location: FileLocation {
                            file_name: "",
                            column: 25,
                            line: 1,
                        },
                        compare_with: Some(LetValue::Value(
                            PathAwareValue::try_from(Value::String(String::from("m4.xlarge")))
                                .unwrap(),
                        )),
                        custom_message: None,
                    },
                    negation: false,
                })]]),
                block: Block {
                    assignments: vec![],
                    conjunctions: vec![vec![GuardClause::Clause(GuardAccessClause {
                        access_clause: AccessClause {
                            query: AccessQuery {
                                query: vec![QueryPart::Key(String::from("security_groups"))],
                                match_all: true,
                            },
                            comparator: (CmpOperator::Exists, false),
                            location: FileLocation {
                                file_name: "",
                                column: 17,
                                line: 2,
                            },
                            compare_with: None,
                            custom_message: None,
                        },
                        negation: false,
                    })]],
                },
                query: vec![
                    QueryPart::Key("Resources".to_string()),
                    QueryPart::AllValues(None),
                    QueryPart::Filter(
                        None,
                        Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                            GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key("Type".to_string())],
                                        match_all: true,
                                    },
                                    custom_message: None,
                                    location: FileLocation {
                                        column: 1,
                                        line: 1,
                                        file_name: "",
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((
                                        Path::root(),
                                        "AWS::EC2::Instance".to_string(),
                                    )))),
                                    comparator: (CmpOperator::Eq, false),
                                },
                            },
                        )])]),
                    ),
                ],
            },
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Test #{}: {}", idx, *each);
        let span = from_str2(each);
        let result = type_block(span);
        println!("Result #{} = {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_rule_block() {
    let examples = [r#"rule example_rule when stage == 'prod' {
    let ec2_instance_types := [/^t*/, /^m*/]   # scoped variable assignments

    # clause can reference another rule for composition
    dependent_rule                            # named rule reference

    # IN (disjunction, one of them)
    AWS::EC2::Instance InstanceType IN %ec2_instance_types

    # Block groups for evaluating groups of clauses together.
    # The "type" "AWS::EC2::Instance" is static
    # type information that help validate if access query inside the block is
    # valid or invalid
    AWS::EC2::Instance {                          # Either an EBS volume
        let volumes := block_device_mappings      # var local, snake case allowed.
          %volumes.*.Ebs EXISTS
          %volumes.*.device_name == /^\/dev\/ebs-/  # must have ebs in the name
          %volumes.*.Ebs.encrypted == true               # Ebs volume must be encrypted
          %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
    } or
    AWS::EC2::Instance {                   # OR a regular volume (disjunction)
        block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
    }
}"#];

    let type_name = "AWS::EC2::Instance";

    let expectations = [Ok((
        unsafe { Span::new_from_raw_offset(examples[0].len(), 24, "", "") },
        Rule {
            rule_name: String::from("example_rule"),
            conditions: Some(Conjunctions::from([Disjunctions::from([
                WhenGuardClause::Clause(GuardAccessClause {
                    access_clause: AccessClause {
                        custom_message: None,
                        query: AccessQuery {
                            query: vec![QueryPart::Key("stage".to_string())],
                            match_all: true,
                        },
                        compare_with: Some(LetValue::Value(
                            PathAwareValue::try_from(Value::String("prod".to_string())).unwrap(),
                        )),
                        location: FileLocation {
                            file_name: "",
                            line: 1,
                            column: "rule example_rule when ".len() as u32 + 1,
                        },
                        comparator: (CmpOperator::Eq, false),
                    },
                    negation: false,
                }),
            ])])),
            block: Block {
                assignments: vec![LetExpr {
                    var: String::from("ec2_instance_types"),
                    value: LetValue::Value(
                        PathAwareValue::try_from(Value::List(vec![
                            Value::Regex("^t*".to_string()),
                            Value::Regex("^m*".to_string()),
                        ]))
                        .unwrap(),
                    ),
                }],
                conjunctions: Conjunctions::from([
                    Disjunctions::from([RuleClause::Clause(GuardClause::NamedRule(
                        GuardNamedRuleClause {
                            dependent_rule: String::from("dependent_rule"),
                            location: FileLocation {
                                file_name: "",
                                line: 5,
                                column: 5,
                            },
                            negation: false,
                            custom_message: None,
                        },
                    ))]),
                    Disjunctions::from([RuleClause::TypeBlock(TypeBlock {
                        type_name: type_name.to_string(),
                        conditions: None,
                        block: Block {
                            assignments: vec![],
                            conjunctions: Conjunctions::from([Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    access_clause: AccessClause {
                                        custom_message: None,
                                        query: AccessQuery {
                                            query: vec![QueryPart::Key("InstanceType".to_string())],
                                            match_all: true,
                                        },
                                        compare_with: Some(LetValue::AccessClause(AccessQuery {
                                            query: vec![QueryPart::Key(
                                                "%ec2_instance_types".to_string(),
                                            )],
                                            match_all: true,
                                        })),
                                        location: FileLocation {
                                            file_name: "",
                                            line: 8,
                                            column: 24,
                                        },
                                        comparator: (CmpOperator::In, false),
                                    },
                                    negation: false,
                                }),
                            ])]),
                        },

                        query: vec![
                            QueryPart::Key("Resources".to_string()),
                            QueryPart::AllValues(None),
                            QueryPart::Filter(
                                None,
                                Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                                    GuardAccessClause {
                                        negation: false,
                                        access_clause: AccessClause {
                                            query: AccessQuery {
                                                query: vec![QueryPart::Key("Type".to_string())],
                                                match_all: true,
                                            },
                                            custom_message: None,
                                            location: FileLocation {
                                                column: 5,
                                                line: 8,
                                                file_name: "",
                                            },
                                            compare_with: Some(LetValue::Value(
                                                PathAwareValue::String((
                                                    Path::root(),
                                                    "AWS::EC2::Instance".to_string(),
                                                )),
                                            )),
                                            comparator: (CmpOperator::Eq, false),
                                        },
                                    },
                                )])]),
                            ),
                        ],
                    })]),
                    Disjunctions::from([
                        RuleClause::TypeBlock(TypeBlock {
                            type_name: type_name.to_string(),
                            conditions: None,
                            block: Block {
                                assignments: vec![LetExpr {
                                    var: "volumes".to_string(),
                                    value: LetValue::AccessClause(AccessQuery {
                                        query: vec![QueryPart::Key(
                                            "block_device_mappings".to_string(),
                                        )],
                                        match_all: true,
                                    }),
                                }],
                                // %volumes.*.Ebs EXISTS
                                // %volumes.*.device_name == /^\/dev\/ebs-/  # must have ebs in the name
                                // %volumes.*.Ebs.encrypted == true               # Ebs volume must be encrypted
                                // %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
                                conjunctions: Conjunctions::from([
                                    Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                        access_clause: AccessClause {
                                            query: AccessQuery {
                                                query: vec![
                                                    QueryPart::Key("%volumes".to_string()),
                                                    QueryPart::AllIndices(None),
                                                    QueryPart::AllValues(None),
                                                    QueryPart::Key("Ebs".to_string()),
                                                ],
                                                match_all: true,
                                            },
                                            comparator: (CmpOperator::Exists, false),
                                            compare_with: None,
                                            custom_message: None,
                                            location: FileLocation {
                                                file_name: "",
                                                line: 16,
                                                column: 11,
                                            },
                                        },
                                        negation: false,
                                    })]),
                                    Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                        access_clause: AccessClause {
                                            query: AccessQuery {
                                                query: vec![
                                                    QueryPart::Key("%volumes".to_string()),
                                                    QueryPart::AllIndices(None),
                                                    QueryPart::AllValues(None),
                                                    QueryPart::Key("device_name".to_string()),
                                                ],
                                                match_all: true,
                                            },
                                            comparator: (CmpOperator::Eq, false),
                                            compare_with: Some(LetValue::Value(
                                                PathAwareValue::try_from(Value::Regex(
                                                    "^/dev/ebs-".to_string(),
                                                ))
                                                .unwrap(),
                                            )),
                                            custom_message: None,
                                            location: FileLocation {
                                                file_name: "",
                                                line: 17,
                                                column: 11,
                                            },
                                        },
                                        negation: false,
                                    })]),
                                    Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                        access_clause: AccessClause {
                                            query: AccessQuery {
                                                query: vec![
                                                    QueryPart::Key("%volumes".to_string()),
                                                    QueryPart::AllIndices(None),
                                                    QueryPart::AllValues(None),
                                                    QueryPart::Key("Ebs".to_string()),
                                                    QueryPart::Key("encrypted".to_string()),
                                                ],
                                                match_all: true,
                                            },
                                            comparator: (CmpOperator::Eq, false),
                                            compare_with: Some(LetValue::Value(
                                                PathAwareValue::try_from(Value::Bool(true))
                                                    .unwrap(),
                                            )),
                                            custom_message: None,
                                            location: FileLocation {
                                                file_name: "",
                                                line: 18,
                                                column: 11,
                                            },
                                        },
                                        negation: false,
                                    })]),
                                    Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                                        access_clause: AccessClause {
                                            query: AccessQuery {
                                                query: vec![
                                                    QueryPart::Key("%volumes".to_string()),
                                                    QueryPart::AllIndices(None),
                                                    QueryPart::AllValues(None),
                                                    QueryPart::Key("Ebs".to_string()),
                                                    QueryPart::Key(
                                                        "delete_on_termination".to_string(),
                                                    ),
                                                ],
                                                match_all: true,
                                            },
                                            comparator: (CmpOperator::Eq, false),
                                            compare_with: Some(LetValue::Value(
                                                PathAwareValue::try_from(Value::Bool(true))
                                                    .unwrap(),
                                            )),
                                            custom_message: None,
                                            location: FileLocation {
                                                file_name: "",
                                                line: 19,
                                                column: 11,
                                            },
                                        },
                                        negation: false,
                                    })]),
                                ]),
                            },
                            query: vec![
                                QueryPart::Key("Resources".to_string()),
                                QueryPart::AllValues(None),
                                QueryPart::Filter(
                                    None,
                                    Conjunctions::from([Disjunctions::from([
                                        GuardClause::Clause(GuardAccessClause {
                                            negation: false,
                                            access_clause: AccessClause {
                                                query: AccessQuery {
                                                    query: vec![QueryPart::Key("Type".to_string())],
                                                    match_all: true,
                                                },
                                                custom_message: None,
                                                location: FileLocation {
                                                    column: 5,
                                                    line: 14,
                                                    file_name: "",
                                                },
                                                compare_with: Some(LetValue::Value(
                                                    PathAwareValue::String((
                                                        Path::root(),
                                                        "AWS::EC2::Instance".to_string(),
                                                    )),
                                                )),
                                                comparator: (CmpOperator::Eq, false),
                                            },
                                        }),
                                    ])]),
                                ),
                            ],
                        }),
                        RuleClause::TypeBlock(TypeBlock {
                            type_name: type_name.to_string(),
                            conditions: None,
                            block: Block {
                                assignments: vec![],
                                // block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
                                conjunctions: Conjunctions::from([Disjunctions::from([
                                    GuardClause::Clause(GuardAccessClause {
                                        access_clause: AccessClause {
                                            query: AccessQuery {
                                                query: vec![
                                                    QueryPart::Key(
                                                        "block_device_mappings".to_string(),
                                                    ),
                                                    QueryPart::AllValues(None),
                                                    QueryPart::Key("device_name".to_string()),
                                                ],
                                                match_all: true,
                                            },
                                            comparator: (CmpOperator::Eq, false),
                                            compare_with: Some(LetValue::Value(
                                                PathAwareValue::try_from(Value::Regex(
                                                    "^/dev/sdc-\\d".to_string(),
                                                ))
                                                .unwrap(),
                                            )),
                                            custom_message: None,
                                            location: FileLocation {
                                                file_name: "",
                                                line: 22,
                                                column: 9,
                                            },
                                        },
                                        negation: false,
                                    }),
                                ])]),
                            },
                            query: vec![
                                QueryPart::Key("Resources".to_string()),
                                QueryPart::AllValues(None),
                                QueryPart::Filter(
                                    None,
                                    Conjunctions::from([Disjunctions::from([
                                        GuardClause::Clause(GuardAccessClause {
                                            negation: false,
                                            access_clause: AccessClause {
                                                query: AccessQuery {
                                                    query: vec![QueryPart::Key("Type".to_string())],
                                                    match_all: true,
                                                },
                                                custom_message: None,
                                                location: FileLocation {
                                                    column: 5,
                                                    line: 21,
                                                    file_name: "",
                                                },
                                                compare_with: Some(LetValue::Value(
                                                    PathAwareValue::String((
                                                        Path::root(),
                                                        "AWS::EC2::Instance".to_string(),
                                                    )),
                                                )),
                                                comparator: (CmpOperator::Eq, false),
                                            },
                                        }),
                                    ])]),
                                ),
                            ],
                        }),
                    ]),
                ]),
            },
        },
    ))];

    let val = rule_block(from_str2(examples[0]));
    assert_eq!(val, expectations[0]);
    println!("{:?}", val.unwrap().1);
}

#[test]
fn test_rules_file() -> Result<(), Error> {
    let s = r#"
#
#  this is the set of rules for secure S3 bucket
#  it must not be public AND
#  it must have a policy associated
#
rule s3_secure {
    AWS::S3::Bucket {
        public != true
        policy != null
    }
}

#
# must be s3_secure or
# there must a tag with a key ExternalS3Approved as an exception
#
rule s3_secure_exception {
    s3_secure or
    AWS::S3::Bucket tags.*.key in ["ExternalS3Approved"]
}

let kms_keys := [
    "arn:aws:kms:123456789012:alias/allowed-primary",
    "arn:aws:kms:123456789012:alias/allowed-secondary"
]

let encrypted := false
let latest := "ami-6458235"
        "#;

    let _rules_files = rules_file(from_str2(s))?;
    Ok(())
}

#[test]
fn test_rule_block_clause() -> Result<(), Error> {
    let s = "{ %select_lambda_service EMPTY or
     %select_lambda_service.Action.* == /sts:AssumeRole/ }";
    let span = from_str2(s);
    let _rule_block = block(rule_block_clause)(span)?;
    Ok(())
}

#[test]
fn test_try_from_access() -> Result<(), Error> {
    let access = "%roles.Document";
    let access = AccessQuery::try_from(access)?;
    println!("{:?} {}", &access, SliceDisplay(&access.query));
    Ok(())
}

#[test]
fn test_try_from_rule_block() -> Result<(), Error> {
    let rule = r#"
    rule s3_secure_exception {
        s3_secure or
        AWS::S3::Bucket tags.*.key in ["ExternalS3Approved"]
    }
    "#;
    let rule_statement = Rule::try_from(rule)?;
    let expected = Rule {
        rule_name: String::from("s3_secure_exception"),
        conditions: None,
        block: Block {
            assignments: vec![],
            conjunctions: Conjunctions::from([Disjunctions::from([
                RuleClause::Clause(GuardClause::NamedRule(GuardNamedRuleClause {
                    negation: false,
                    dependent_rule: String::from("s3_secure"),
                    location: FileLocation {
                        file_name: "",
                        line: 3,
                        column: 9,
                    },
                    custom_message: None,
                })),
                RuleClause::TypeBlock(TypeBlock {
                    type_name: String::from("AWS::S3::Bucket"),
                    conditions: None,
                    block: Block {
                        assignments: vec![],
                        conjunctions: Conjunctions::from([Disjunctions::from([
                            GuardClause::Clause(GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![
                                            QueryPart::Key(String::from("tags")),
                                            QueryPart::AllValues(None),
                                            QueryPart::Key(String::from("key")),
                                        ],
                                        match_all: true,
                                    },
                                    comparator: (CmpOperator::In, false),
                                    compare_with: Some(LetValue::Value(
                                        PathAwareValue::try_from(Value::List(vec![Value::String(
                                            String::from("ExternalS3Approved"),
                                        )]))
                                        .unwrap(),
                                    )),
                                    custom_message: None,
                                    location: FileLocation {
                                        file_name: "",
                                        line: 4,
                                        column: 25,
                                    },
                                },
                            }),
                        ])]),
                    },
                    query: vec![
                        QueryPart::Key("Resources".to_string()),
                        QueryPart::AllValues(None),
                        QueryPart::Filter(
                            None,
                            Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                                GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        query: AccessQuery {
                                            query: vec![QueryPart::Key("Type".to_string())],
                                            match_all: true,
                                        },
                                        custom_message: None,
                                        location: FileLocation {
                                            column: 9,
                                            line: 4,
                                            file_name: "",
                                        },
                                        compare_with: Some(LetValue::Value(
                                            PathAwareValue::String((
                                                Path::root(),
                                                "AWS::S3::Bucket".to_string(),
                                            )),
                                        )),
                                        comparator: (CmpOperator::Eq, false),
                                    },
                                },
                            )])]),
                        ),
                    ],
                }),
            ])]),
        },
    };
    assert_eq!(rule_statement, expected);
    Ok(())
}

#[test]
fn parse_list_of_map() -> Result<(), Error> {
    let s = r#"let allowlist = [
     {
         "serviceAccount": "analytics",
         "images": ["banzaicloud/allspark:0.1.2", "banzaicloud/istio-proxyv2:1.7.0-bzc"],
         # possible nodeSelector combinations we allow, the pod can have more nodeSelectors of course
         "nodeSelector": [{"failure-domain.beta.kubernetes.io/region": "europe-west1"}]
         # "nodeSelector": [],
     }
 ]

  "#;

    let value = assignment(from_str2(s))?.1;
    println!("{:?}", value);
    Ok(())
}

#[test]
fn parse_rule_block_with_mixed_assignment() -> Result<(), Error> {
    let r = r#"
    rule is_service_account_operation_valid {
     request.kind.kind == "Pod"
     request.operation == "CREATE"
     let service_name = request.object.spec.serviceAccountName
     %allowlist[ this.serviceAccount == %service_name ] !EMPTY
 }"#;
    let rule = Rule::try_from(r)?;
    println!("{:?}", rule);

    let r = r###"
    rule check_all_resources_have_tags_present {
    let all_resources = Resources.*.Properties

    %all_resources.Tags EXISTS
    %all_resources.Tags !EMPTY
}
    "###;
    let _rule = Rule::try_from(r)?;
    Ok(())
}

#[test]
fn parse_regex_tests() -> Result<(), Error> {
    let inner = "(\\d{4})-(\\d{2})-(\\d{2})";
    let regex = format!("/{}/", inner);
    let value = Value::try_from(regex.as_str())?;
    assert_eq!(Value::Regex(inner.to_string()), value);
    Ok(())
}

#[test]
fn test_complex_predicate_clauses() -> Result<(), Error> {
    let clause = "Statement[ Condition EXISTS ].Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY";
    // let clause = "Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ]";
    let _parsed = GuardClause::try_from(clause)?;

    let clause = r#"Statement[ Condition EXISTS
                                     Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] NOT EMPTY
    "#;
    let _parsed = GuardClause::try_from(clause)?;
    Ok(())
}

struct DummyEval {}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, _variable: &str) -> crate::rules::Result<Vec<&PathAwareValue>> {
        unimplemented!()
    }

    fn rule_status(&self, _rule_name: &str) -> crate::rules::Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(
        &self,
        _eval_type: EvaluationType,
        _context: &str,
        _msg: String,
        _from: Option<PathAwareValue>,
        _to: Option<PathAwareValue>,
        _status: Option<Status>,
        _cmp: Option<(CmpOperator, bool)>,
    ) {
    }

    fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {}
}

#[test]
fn select_any_one_from_list_clauses() -> Result<(), Error> {
    let clause = "this == /\\{\\{resolve:secretsmanager/";
    let parsed = super::clause(from_str2(clause))?.1;
    let expected = GuardClause::Clause(GuardAccessClause {
        access_clause: AccessClause {
            location: FileLocation {
                column: 1,
                line: 1,
                file_name: "",
            },
            compare_with: Some(LetValue::Value(
                PathAwareValue::try_from(Value::Regex("\\{\\{resolve:secretsmanager".to_string()))
                    .unwrap(),
            )),
            comparator: (CmpOperator::Eq, false),
            custom_message: None,
            query: AccessQuery {
                query: vec![QueryPart::This],
                match_all: true,
            },
        },
        negation: false,
    });
    assert_eq!(parsed, expected);

    let _templates = [
        r#"
        {
            "Resources": {
                "rds": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "MasterUserPassword": "{{resolve:secretsmanager:my-secret:SecretString:password::}}"
                    }
                }
            }
        }
        "#,
        r#"
        {
            "Resources": {
                "rds": {
                    "Type": "AWS::RDS::DBInstance",
                    "Properties": {
                        "MasterUserPassword": {
                          "Fn::Join": [
                            "",
                            [
                              "{{resolve:secretsmanager:",
                              {
                                "Ref": "FtCdkRDSStackInstanceSecret719B40CE3fdaad7efa858a3daf9490cf0a702aeb"
                              },
                              ":SecretString:password::}}"
                            ]
                          ]
                        }
                    }
                }
            }
        }
        "#,
    ];

    let _dummy = DummyEval {};
    let _clause = GuardClause::try_from(
        r#"Resources.*[ this.Type == "AWS::RDS::DBInstance" ].Properties.MasterUserPassword.'Fn::Join'[1][ this == /\{\{resolve:secretsmanager/ ] !EMPTY"#,
    )?;
    Ok(())
}

#[test]
fn test_rules_file_default_rules() -> Result<(), Error> {
    let s = r#"
    AWS::AmazonMQ::Broker Properties.AutoMinorVersionUpgrade == false <<Version upgrades should be enabled to receive security updates>>
    AWS::AmazonMQ::Broker Properties.EncryptionOptions.UseAwsOwnedKey == false <<CMKs should be used instead of AWS-provided KMS keys>>
    AWS::ApiGateway::Method Properties.ResourceId == "ApiGatewayBadBot.RootResourceId" <<Should be root resource id>> or  AWS::ApiGateway::Method Properties.ResourceId == "ApiGatewayBadBotResource"
    "#;
    let default_rule = Rule {
        rule_name: String::from("default"),
        conditions: None,
        block: Block {
            assignments: vec![],

            conjunctions: vec![
                vec![RuleClause::TypeBlock(TypeBlock {
                    type_name: String::from("AWS::AmazonMQ::Broker"),
                    conditions: None,
                    block: Block {
                        assignments: vec![],
                        conjunctions: vec![
                            vec![GuardClause::Clause(GuardAccessClause{
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from("Properties")), QueryPart::Key(String::from("AutoMinorVersionUpgrade"))],
                                        match_all: true
                                    },
                                    comparator: (CmpOperator::Eq, false),
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Bool(false)).unwrap())),
                                    custom_message: Some(String::from("Version upgrades should be enabled to receive security updates")),
                                    location: FileLocation {
                                        line: 2,
                                        column: 27,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })]
                        ]
                    },
                    query: vec![
                        QueryPart::Key("Resources".to_string()),
                        QueryPart::AllValues(None),
                        QueryPart::Filter(None, Conjunctions::from([
                            Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        query: AccessQuery {
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ],
                                            match_all: true
                                        },
                                        custom_message: None,
                                        location: FileLocation {
                                            column: 5,
                                            line: 2,
                                            file_name: ""
                                        },
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::AmazonMQ::Broker".to_string())))),
                                        comparator: (CmpOperator::Eq, false)
                                    }
                                })
                            ])
                        ]))
                    ]
                })],
                vec![RuleClause::TypeBlock(TypeBlock {
                    type_name: String::from("AWS::AmazonMQ::Broker"),
                    conditions: None,
                    block: Block {
                        assignments: vec![],
                        conjunctions: vec![
                            vec![GuardClause::Clause(GuardAccessClause{
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from("Properties")), QueryPart::Key(String::from("EncryptionOptions")), QueryPart::Key(String::from("UseAwsOwnedKey"))],
                                        match_all: true
                                    },
                                    comparator: (CmpOperator::Eq, false),
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Bool(false)).unwrap())),
                                    custom_message: Some(String::from("CMKs should be used instead of AWS-provided KMS keys")),
                                    location: FileLocation {
                                        line: 3,
                                        column: 27,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })]
                        ]
                    },
                    query: vec![
                        QueryPart::Key("Resources".to_string()),
                        QueryPart::AllValues(None),
                        QueryPart::Filter(None, Conjunctions::from([
                            Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        query: AccessQuery {
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ],
                                            match_all: true
                                        },
                                        custom_message: None,
                                        location: FileLocation {
                                            column: 5,
                                            line: 3,
                                            file_name: ""
                                        },
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::AmazonMQ::Broker".to_string())))),
                                        comparator: (CmpOperator::Eq, false)
                                    }
                                })
                            ])
                        ]))
                    ]
                })],
                vec![RuleClause::TypeBlock(TypeBlock {
                    type_name: String::from("AWS::ApiGateway::Method"),
                    conditions: None,
                    block: Block {
                        assignments: vec![],
                        conjunctions: vec![
                            vec![GuardClause::Clause(GuardAccessClause{
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![QueryPart::Key(String::from("Properties")), QueryPart::Key(String::from("ResourceId"))],
                                        match_all: true
                                    },
                                    comparator: (CmpOperator::Eq, false),
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::String(String::from("ApiGatewayBadBot.RootResourceId"))).unwrap())),
                                    custom_message: Some(String::from("Should be root resource id")),
                                    location: FileLocation {
                                        line: 4,
                                        column: 29,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })]
                        ]
                    },
                    query: vec![
                        QueryPart::Key("Resources".to_string()),
                        QueryPart::AllValues(None),
                        QueryPart::Filter(None, Conjunctions::from([
                            Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        query: AccessQuery {
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ],
                                            match_all: true
                                        },
                                        custom_message: None,
                                        location: FileLocation {
                                            column: 5,
                                            line: 4,
                                            file_name: ""
                                        },
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::ApiGateway::Method".to_string())))),
                                        comparator: (CmpOperator::Eq, false)
                                    }
                                })
                            ])
                        ]))
                    ]
                }),
                 RuleClause::TypeBlock(TypeBlock {
                     type_name: String::from("AWS::ApiGateway::Method"),
                     conditions: None,
                     block: Block {
                         assignments: vec![],
                         conjunctions: vec![
                             vec![GuardClause::Clause(GuardAccessClause{
                                 access_clause: AccessClause {
                                     query: AccessQuery {
                                         query: vec![QueryPart::Key(String::from("Properties")), QueryPart::Key(String::from("ResourceId"))],
                                         match_all: true
                                     },
                                     comparator: (CmpOperator::Eq, false),
                                     compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::String(String::from("ApiGatewayBadBotResource"))).unwrap())),
                                     custom_message: None,
                                     location: FileLocation {
                                         line: 4,
                                         column: 147,
                                         file_name: ""
                                     }
                                 },
                                 negation: false
                             })]
                         ]
                     },
                     query: vec![
                         QueryPart::Key("Resources".to_string()),
                         QueryPart::AllValues(None),
                         QueryPart::Filter(None, Conjunctions::from([
                             Disjunctions::from([
                                 GuardClause::Clause(GuardAccessClause {
                                     negation: false,
                                     access_clause: AccessClause {
                                         query: AccessQuery {
                                             query: vec![
                                                 QueryPart::Key("Type".to_string())
                                             ],
                                             match_all: true
                                         },
                                         custom_message: None,
                                         location: FileLocation {
                                             column: 123,
                                             line: 4,
                                             file_name: ""
                                         },
                                         compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::ApiGateway::Method".to_string())))),
                                         comparator: (CmpOperator::Eq, false)
                                     }
                                 })
                             ])
                         ]))
                     ]
                 })]
            ]

            }
        };

    let rules_file = rules_file(from_str2(s))?;
    assert_eq!(
        rules_file,
        Some(RulesFile {
            assignments: vec![],
            guard_rules: vec![default_rule],
            parameterized_rules: vec![],
        })
    );
    Ok(())
}

#[test]
fn rule_parameters_parse_test() -> Result<(), Error> {
    let parameters = "(statements, policy)";
    let (_span, parsed_parameters) = parameter_names(from_str2(parameters))?;
    assert_eq!(parsed_parameters.len(), 2);
    assert_eq!(
        parsed_parameters,
        ["statements", "policy"]
            .iter()
            .map(|s| s.to_string())
            .collect::<indexmap::IndexSet<String>>()
    );

    let parameters = "(statements)";
    let (_span, parsed_parameters) = parameter_names(from_str2(parameters))?;
    assert_eq!(parsed_parameters.len(), 1);
    assert_eq!(
        parsed_parameters,
        ["statements"]
            .iter()
            .map(|s| s.to_string())
            .collect::<indexmap::IndexSet<String>>()
    );

    let parameters = "( statements  , policy    )";
    let (_span, parsed_parameters) = parameter_names(from_str2(parameters))?;
    assert_eq!(parsed_parameters.len(), 2);
    assert_eq!(
        parsed_parameters,
        ["statements", "policy"]
            .iter()
            .map(|s| s.to_string())
            .collect::<indexmap::IndexSet<String>>()
    );

    //
    // Error cases
    //

    let parameters = "statements";
    let result = parameter_names(from_str2(parameters));
    assert!(result.is_err());
    assert_eq!(
        result.err(),
        Some(nom::Err::Error(ParserError {
            kind: ErrorKind::Char, // no '('
            context: "".to_string(),
            span: unsafe { Span::new_from_raw_offset(0, 1, "statements", "") }
        }))
    );

    let parameters = "(statements";
    let result = parameter_names(from_str2(parameters));
    assert!(result.is_err());
    assert_eq!(
        result.err(),
        Some(nom::Err::Failure(ParserError {
            // expect failure to not close
            kind: ErrorKind::Char, // no ')'
            context: "".to_string(),
            span: unsafe { Span::new_from_raw_offset("(statements".len(), 1, "", "") }
        }))
    );

    let parameters = "(statements,)"; // missing second parameter
    let result = parameter_names(from_str2(parameters));
    assert!(result.is_err());
    assert_eq!(
        result.err(),
        Some(nom::Err::Failure(ParserError {
            // expect failure to not close
            kind: ErrorKind::Alpha, // due to var_name
            context: "".to_string(),
            span: unsafe { Span::new_from_raw_offset("(statements,".len(), 1, ")", "") }
        }))
    );

    Ok(())
}

#[test]
fn parameterized_rule_parse_test() -> Result<(), Error> {
    let params_rule = r#"
    rule policy_checks(statements) {
        %statements {
            Effect == 'Allow'
        }
    }"#;

    let parameterized_rule = ParameterizedRule::try_from(params_rule)?;
    let mut parameters = indexmap::IndexSet::new();
    parameters.insert("statements".to_string());
    let expected = ParameterizedRule {
        parameter_names: parameters,
        rule: Rule {
            rule_name: "policy_checks".to_string(),
            conditions: None,
            block: Block {
                assignments: vec![],
                conjunctions: Conjunctions::from([Disjunctions::from([RuleClause::Clause(
                    GuardClause::BlockClause(BlockGuardClause {
                        location: FileLocation {
                            file_name: "",
                            line: 3,
                            column: 9,
                        },
                        query: AccessQuery {
                            match_all: true,
                            query: vec![QueryPart::Key("%statements".to_string())],
                        },
                        block: Block {
                            assignments: vec![],
                            conjunctions: Conjunctions::from([Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        query: AccessQuery {
                                            query: vec![QueryPart::Key("Effect".to_string())],
                                            match_all: true,
                                        },
                                        location: FileLocation {
                                            file_name: "",
                                            line: 4,
                                            column: 13,
                                        },
                                        comparator: (CmpOperator::Eq, false),
                                        custom_message: None,
                                        compare_with: Some(LetValue::Value(
                                            PathAwareValue::String((
                                                Path::root(),
                                                "Allow".to_string(),
                                            )),
                                        )),
                                    },
                                }),
                            ])]),
                        },
                        not_empty: false,
                    }),
                )])]),
            },
        },
    };
    assert_eq!(parameterized_rule, expected);

    Ok(())
}

#[test]
fn some_clause_parse() -> Result<(), Error> {
    let clause = GuardClause::try_from(
        r#"some %api_gws.Properties.Policy.Statement[*].Condition[
            keys ==  /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !empty"#,
    )?;
    let parsed_clause = GuardClause::Clause(GuardAccessClause {
        negation: false,
        access_clause: AccessClause {
            query: AccessQuery {
                match_all: false,
                query: vec![
                    QueryPart::Key("%api_gws".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("Policy".to_string()),
                    QueryPart::Key("Statement".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("Condition".to_string()),
                    QueryPart::MapKeyFilter(
                        None,
                        MapKeyFilterClause {
                            comparator: MapKeyComparator::Eq,
                            compare_with: LetValue::Value(
                                PathAwareValue::try_from(Value::Regex(
                                    "aws:[sS]ource(Vpc|VPC|Vpce|VPCE)".to_string(),
                                ))
                                .unwrap(),
                            ),
                        },
                    ),
                ],
            },
            compare_with: None,
            comparator: (CmpOperator::Empty, true),
            custom_message: None,
            location: FileLocation {
                line: 1,
                column: 1,
                file_name: "",
            },
        },
    });
    assert_eq!(parsed_clause, clause);
    Ok(())
}

#[test]
fn it_support_test() -> Result<(), Error> {
    let query = r#"Tags[ some this == { Key: "Hi", Value: "There" }]"#;
    let parsed_query = AccessQuery::try_from(query)?;
    println!("{:?}", parsed_query);
    let expected = AccessQuery {
        match_all: true,
        query: vec![
            QueryPart::Key("Tags".to_string()),
            QueryPart::Filter(
                None,
                Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                    GuardAccessClause {
                        negation: false,
                        access_clause: AccessClause {
                            query: AccessQuery {
                                match_all: false,
                                query: vec![QueryPart::This],
                            },
                            custom_message: None,
                            comparator: (CmpOperator::Eq, false),
                            location: FileLocation {
                                file_name: "",
                                column: 7,
                                line: 1,
                            },
                            compare_with: Some(LetValue::Value(
                                PathAwareValue::try_from(Value::Map(make_linked_hashmap(vec![
                                    ("Key", Value::String("Hi".to_string())),
                                    ("Value", Value::String("There".to_string())),
                                ])))
                                .unwrap(),
                            )),
                        },
                    },
                )])]),
            ),
        ],
    };
    assert_eq!(parsed_query, expected);
    Ok(())
}

#[test]
fn test_block_properties() -> Result<(), Error> {
    let block_str = r###"Properties.Statements[*] {
        Effect == 'Deny'
        Principal != '*'
    }
    "###;
    let block_clause = GuardClause::try_from(block_str)?;
    let expected = GuardClause::BlockClause(BlockGuardClause {
        location: FileLocation {
            file_name: "",
            column: 1,
            line: 1,
        },
        query: AccessQuery {
            query: vec![
                QueryPart::Key("Properties".to_string()),
                QueryPart::Key("Statements".to_string()),
                QueryPart::AllIndices(None),
            ],
            match_all: true,
        },
        block: Block {
            assignments: vec![],
            conjunctions: vec![
                Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                    access_clause: AccessClause {
                        query: AccessQuery {
                            query: vec![QueryPart::Key("Effect".to_string())],
                            match_all: true,
                        },
                        location: FileLocation {
                            file_name: "",
                            line: 2,
                            column: 9,
                        },
                        compare_with: Some(LetValue::Value(
                            PathAwareValue::try_from(Value::String("Deny".to_string())).unwrap(),
                        )),
                        comparator: (CmpOperator::Eq, false),
                        custom_message: None,
                    },
                    negation: false,
                })]),
                Disjunctions::from([GuardClause::Clause(GuardAccessClause {
                    access_clause: AccessClause {
                        query: AccessQuery {
                            query: vec![QueryPart::Key("Principal".to_string())],
                            match_all: true,
                        },
                        location: FileLocation {
                            file_name: "",
                            line: 3,
                            column: 9,
                        },
                        compare_with: Some(LetValue::Value(
                            PathAwareValue::try_from(Value::String("*".to_string())).unwrap(),
                        )),
                        comparator: (CmpOperator::Eq, true),
                        custom_message: None,
                    },
                    negation: false,
                })]),
            ],
        },
        not_empty: false,
    });
    assert_eq!(block_clause, expected);
    Ok(())
}

#[test]
fn test_block_in_block_properties() -> Result<(), Error> {
    let block_str = r###"Properties {
        Statements[*] {
            Effect == 'Deny'
            Principal != '*'
        }
    }"###;
    let block = GuardClause::try_from(block_str)?;
    match &block {
        GuardClause::BlockClause(block) => match &block.block.conjunctions[0][0] {
            GuardClause::BlockClause(blk) => {
                assert!(blk.block.assignments.is_empty());
                let conjunctions = &blk.block.conjunctions;
                assert_eq!(conjunctions.len(), 2);
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
    Ok(())
}

#[test]
fn test_incorrect_block_in_block_properties() -> Result<(), Error> {
    // Empty does not contain properties
    let block_str = r###"Properties {}"###;
    if GuardClause::try_from(block_str).is_ok() {
        unreachable!()
    }

    // Incomplete block
    let block_str = r###"Properties { Statements[*]"###;
    if GuardClause::try_from(block_str).is_ok() {
        unreachable!()
    }

    Ok(())
}

#[test]
fn block_parse_test() -> Result<(), Error> {
    let block = r#"Resources.*[ Type == /ApiGateway/ ] { Properties.Tags !empty }"#;
    let _clause = GuardClause::try_from(block)?;
    Ok(())
}

#[test]
fn when_inside_when_parse_test() -> Result<(), Error> {
    let when_inside_when = r###"#
    # If no associations are present in the template then we SKIP the check
    #
    when %route_tables !empty {
        #
        # Ensure that all of these references where indeed RouteTable references
        #
        Resources.%route_tables.Type == 'AWS::EC2::RouteTable'

        #
        # Find all routes that have a gateways associated with the route table and extract
        # all their references
        #
        let gws_ids = some Resources.*[
            Type == 'AWS::EC2::Route'
            Properties.GatewayId.Ref exists
            Properties.RouteTableId.Ref in %route_tables
        ].Properties.GatewayId.Ref

        #
        # if no gateways or route association were found then we skip the check
        #
        when %gws_ids !empty {
            Resources.%gws_ids.Type != 'AWS::EC2::InternetGateway'
        }
    }
    "###;
    let (_span, _clause) = rule_block_clause(from_str2(when_inside_when))?;
    Ok(())
}

#[test]
fn is_list_check_parser_bug() -> Result<(), Error> {
    let bug_test =
        "some %normal_managed_policies.Properties.PolicyDocument.Statement[ Action is_list ]";
    let _access = AccessQuery::try_from(bug_test)?;
    Ok(())
}

#[test]
fn does_this_work() -> Result<(), Error> {
    let _query =
        AccessQuery::try_from(r#"Resources[ keys == /s3/ ][ Type == "AWS::S3::BucketPolicy" ]"#)?
            .query;
    Ok(())
}

#[rstest::rstest]
#[case("is_string", CmpOperator::IsString)]
#[case("IS_STRING", CmpOperator::IsString)]
#[case("is_list", CmpOperator::IsList)]
#[case("IS_LIST", CmpOperator::IsList)]
#[case("is_bool", CmpOperator::IsBool)]
#[case("IS_BOOL", CmpOperator::IsBool)]
#[case("is_int", CmpOperator::IsInt)]
#[case("IS_INT", CmpOperator::IsInt)]
#[case("IS_FLOAT", CmpOperator::IsFloat)]
#[case("is_float", CmpOperator::IsFloat)]
#[case("is_null", CmpOperator::IsNull)]
#[case("IS_NULL", CmpOperator::IsNull)]
fn unary_parse(#[case] s: &str, #[case] expected: CmpOperator) -> Result<(), Error> {
    let parsed = value_cmp(LocatedSpan::new_extra(s, ""))?.1 .0;
    assert_eq!(expected, parsed);
    assert!(expected.is_unary());
    Ok(())
}

#[test]
fn parameterized_rule_block() -> Result<(), Error> {
    let parameterized_rule = r###"
    rule iam_disallowed_attributes_check(iam_statements) {
      %iam_statements {
         Action != '*'
      }
    }
    "###;
    let parameterized = ParameterizedRule::try_from(parameterized_rule)?;
    let mut parameter_names = indexmap::IndexSet::new();
    parameter_names.insert("iam_statements".to_string());
    let expected = ParameterizedRule {
        parameter_names,
        rule: Rule {
            rule_name: "iam_disallowed_attributes_check".to_string(),
            block: Block {
                assignments: vec![],
                conjunctions: Conjunctions::from([Disjunctions::from([RuleClause::Clause(
                    GuardClause::BlockClause(BlockGuardClause {
                        not_empty: false,
                        query: AccessQuery {
                            match_all: true,
                            query: vec![QueryPart::Key("%iam_statements".to_string())],
                        },
                        location: FileLocation {
                            file_name: "",
                            line: 3,
                            column: 7,
                        },
                        block: Block {
                            assignments: vec![],
                            conjunctions: Conjunctions::from([Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        query: AccessQuery {
                                            match_all: true,
                                            query: vec![QueryPart::Key("Action".to_string())],
                                        },
                                        custom_message: None,
                                        comparator: (CmpOperator::Eq, true),
                                        compare_with: Some(LetValue::Value(
                                            PathAwareValue::String((Path::root(), "*".to_string())),
                                        )),
                                        location: FileLocation {
                                            file_name: "",
                                            line: 4,
                                            column: 10,
                                        },
                                    },
                                }),
                            ])]),
                        },
                    }),
                )])]),
            },
            conditions: None,
        },
    };
    assert_eq!(parameterized, expected);
    Ok(())
}

#[test]
fn parameters_guard_clause() -> Result<(), Error> {
    let guard_clause = r#"not iam_disallowed_attributes_check(
        Resources[ Type == 'AWS::IAM::Role' or
                   Type == 'AWS::IAM::ManagedPolicy' ]
           .Properties.PolicyDocument.Statement[*]
       )"#;

    let parameterized_guard_clause = ParameterizedNamedRuleClause::try_from(guard_clause)?;
    let expected = ParameterizedNamedRuleClause {
        named_rule: GuardNamedRuleClause {
            location: FileLocation {
                file_name: "",
                line: 1,
                column: 1,
            },
            custom_message: None,
            negation: true,
            dependent_rule: "iam_disallowed_attributes_check".to_string(),
        },
        parameters: vec![LetValue::AccessClause(AccessQuery {
            match_all: true,
            query: vec![
                QueryPart::Key("Resources".to_string()),
                QueryPart::Filter(
                    None,
                    Conjunctions::from([Disjunctions::from([
                        GuardClause::Clause(GuardAccessClause {
                            negation: false,
                            access_clause: AccessClause {
                                compare_with: Some(LetValue::Value(PathAwareValue::String((
                                    Path::root(),
                                    "AWS::IAM::Role".to_string(),
                                )))),
                                location: FileLocation {
                                    file_name: "",
                                    line: 2,
                                    column: 20,
                                },
                                query: AccessQuery {
                                    match_all: true,
                                    query: vec![QueryPart::Key("Type".to_string())],
                                },
                                ..Default::default()
                            },
                        }),
                        GuardClause::Clause(GuardAccessClause {
                            negation: false,
                            access_clause: AccessClause {
                                compare_with: Some(LetValue::Value(PathAwareValue::String((
                                    Path::root(),
                                    "AWS::IAM::ManagedPolicy".to_string(),
                                )))),
                                location: FileLocation {
                                    file_name: "",
                                    line: 3,
                                    column: 20,
                                },
                                query: AccessQuery {
                                    match_all: true,
                                    query: vec![QueryPart::Key("Type".to_string())],
                                },
                                ..Default::default()
                            },
                        }),
                    ])]),
                ),
                QueryPart::Key("Properties".to_string()),
                QueryPart::Key("PolicyDocument".to_string()),
                QueryPart::Key("Statement".to_string()),
                QueryPart::AllIndices(None),
            ],
        })],
    };
    assert_eq!(parameterized_guard_clause, expected);
    Ok(())
}

#[test]
fn parameters_guard_clause_multiple() -> Result<(), Error> {
    let guard_clause = r#"not iam_disallowed_attributes_check(
        Resources[ Type == 'AWS::IAM::Role' or
                   Type == 'AWS::IAM::ManagedPolicy' ]
           .Properties.PolicyDocument.Statement[*],
        %var.Properties.Tags,
        "hardcoded",
        count(%var)
       )"#;

    let parameterized_guard_clause = ParameterizedNamedRuleClause::try_from(guard_clause)?;
    let expected = ParameterizedNamedRuleClause {
        named_rule: GuardNamedRuleClause {
            location: FileLocation {
                file_name: "",
                line: 1,
                column: 1,
            },
            custom_message: None,
            negation: true,
            dependent_rule: "iam_disallowed_attributes_check".to_string(),
        },
        parameters: vec![
            LetValue::AccessClause(AccessQuery {
                match_all: true,
                query: vec![
                    QueryPart::Key("Resources".to_string()),
                    QueryPart::Filter(
                        None,
                        Conjunctions::from([Disjunctions::from([
                            GuardClause::Clause(GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((
                                        Path::root(),
                                        "AWS::IAM::Role".to_string(),
                                    )))),
                                    location: FileLocation {
                                        file_name: "",
                                        line: 2,
                                        column: 20,
                                    },
                                    query: AccessQuery {
                                        match_all: true,
                                        query: vec![QueryPart::Key("Type".to_string())],
                                    },
                                    ..Default::default()
                                },
                            }),
                            GuardClause::Clause(GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((
                                        Path::root(),
                                        "AWS::IAM::ManagedPolicy".to_string(),
                                    )))),
                                    location: FileLocation {
                                        file_name: "",
                                        line: 3,
                                        column: 20,
                                    },
                                    query: AccessQuery {
                                        match_all: true,
                                        query: vec![QueryPart::Key("Type".to_string())],
                                    },
                                    ..Default::default()
                                },
                            }),
                        ])]),
                    ),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("PolicyDocument".to_string()),
                    QueryPart::Key("Statement".to_string()),
                    QueryPart::AllIndices(None),
                ],
            }),
            LetValue::AccessClause(AccessQuery {
                match_all: true,
                query: vec![
                    QueryPart::Key("%var".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("Tags".to_string()),
                ],
            }),
            LetValue::Value(PathAwareValue::try_from(Value::String(
                "hardcoded".to_string(),
            ))?),
            LetValue::FunctionCall(FunctionExpr {
                parameters: vec![LetValue::AccessClause(AccessQuery {
                    query: vec![QueryPart::Key("%var".to_string())],
                    match_all: true,
                })],
                name: FunctionName::Count,
                location: FileLocation {
                    line: 7,
                    column: 9,
                    file_name: "",
                },
            }),
        ],
    };
    assert_eq!(parameterized_guard_clause, expected);
    Ok(())
}

#[test]
fn parameterized_rule_single_param_function_with_one_argument() -> Result<(), Error> {
    let guard_clause = r#"not iam_disallowed_attributes_check(count(%var))"#;

    let parameterized_guard_clause = ParameterizedNamedRuleClause::try_from(guard_clause)?;
    let expected = ParameterizedNamedRuleClause {
        named_rule: GuardNamedRuleClause {
            location: FileLocation {
                file_name: "",
                line: 1,
                column: 1,
            },
            custom_message: None,
            negation: true,
            dependent_rule: "iam_disallowed_attributes_check".to_string(),
        },
        parameters: vec![LetValue::FunctionCall(FunctionExpr {
            parameters: vec![LetValue::AccessClause(AccessQuery {
                query: vec![QueryPart::Key("%var".to_string())],
                match_all: true,
            })],
            name: FunctionName::Count,
            location: FileLocation {
                line: 1,
                column: 37,
                file_name: "",
            },
        })],
    };
    assert_eq!(parameterized_guard_clause, expected);
    Ok(())
}

#[test]
fn parameterized_rule_single_param_function_with_multiple_arguments() -> Result<(), Error> {
    let guard_clause = r#"not iam_disallowed_attributes_check(regex_replace(%var, "^arn:(\w+):(\w+):([\w0-9-]+):(\d+):(.+)$", "${1}/${4}/${3}/${2}-${5}"))"#;

    let parameterized_guard_clause = ParameterizedNamedRuleClause::try_from(guard_clause)?;
    let expected = ParameterizedNamedRuleClause {
        named_rule: GuardNamedRuleClause {
            location: FileLocation {
                file_name: "",
                line: 1,
                column: 1,
            },
            custom_message: None,
            negation: true,
            dependent_rule: "iam_disallowed_attributes_check".to_string(),
        },
        parameters: vec![LetValue::FunctionCall(FunctionExpr {
            parameters: vec![
                LetValue::AccessClause(AccessQuery {
                    query: vec![QueryPart::Key("%var".to_string())],
                    match_all: true,
                }),
                LetValue::Value(PathAwareValue::try_from(Value::String(
                    "^arn:(\\w+):(\\w+):([\\w0-9-]+):(\\d+):(.+)$".to_string(),
                ))?),
                LetValue::Value(PathAwareValue::try_from(Value::String(
                    "${1}/${4}/${3}/${2}-${5}".to_string(),
                ))?),
            ],
            name: FunctionName::RegexReplace,
            location: FileLocation {
                line: 1,
                column: 37,
                file_name: "",
            },
        })],
    };
    assert_eq!(parameterized_guard_clause, expected);
    Ok(())
}

#[test]
fn parameterized_clause_errors() -> Result<(), Error> {
    let just_name_rule_clause = "not named_rule";
    let result = ParameterizedNamedRuleClause::try_from(just_name_rule_clause);
    assert!(result.is_err());

    let result = GuardClause::try_from(just_name_rule_clause);
    assert!(result.is_err()); // this does not match rule_clause

    let result = RuleClause::try_from(just_name_rule_clause);
    assert!(result.is_ok());
    match result.unwrap() {
        RuleClause::Clause(GuardClause::NamedRule(gnr)) => {
            assert_eq!(gnr.dependent_rule.as_str(), "named_rule");
            assert_eq!(gnr.custom_message, None);
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[test]
fn parameterized_clause_in_when_condition() -> Result<(), Error> {
    let rule_when_clause = r#"rule call_parameterized when parameterized(%x) {
        Resources[ Type == /IAM::Role/ ] {
            check_iam_statements(Properties.PolicyDocument.Statement[*], "some-hardcoded-param")
            when check_required_tags_present(Properties.Tags)
                 %someref not empty
            {
                some Properties.PolicyDocument.Statement[*].Principal == '*'
            }
        }
    }"#;

    let rule = Rule::try_from(rule_when_clause)?;
    assert_eq!(rule.rule_name.as_str(), "call_parameterized");
    assert!(rule.conditions.is_some());
    let conditions = rule.conditions.as_ref().unwrap();
    assert_eq!(conditions.len(), 1);
    let contained = &conditions[0][0];
    match contained {
        WhenGuardClause::ParameterizedNamedRule(pr) => {
            assert_eq!(pr.named_rule.dependent_rule.as_str(), "parameterized");
            assert_eq!(pr.parameters.len(), 1);
            let acc_query = &pr.parameters[0];
            match acc_query {
                LetValue::AccessClause(query) => {
                    assert_eq!(query.query.len(), 1);
                    assert_eq!(&query.query[0], &QueryPart::Key("%x".to_string()));
                }
                _ => unreachable!(),
            }
        }
        _ => unreachable!(),
    }

    assert_eq!(rule.block.conjunctions.len(), 1);
    match &rule.block.conjunctions[0][0] {
        RuleClause::Clause(GuardClause::BlockClause(block)) => {
            assert_eq!(block.block.conjunctions.len(), 2);
            for each in &block.block.conjunctions {
                match &each[0] {
                    GuardClause::ParameterizedNamedRule(prc) => {
                        assert_eq!(
                            prc.named_rule.dependent_rule.as_str(),
                            "check_iam_statements"
                        );
                        assert!(matches!(&prc.parameters[0], LetValue::AccessClause(_)));
                        assert!(matches!(&prc.parameters[1], LetValue::Value(_)));
                    }

                    GuardClause::WhenBlock(conds, _) => {
                        assert_eq!(conds.len(), 2);
                        match &conds[0][0] {
                            WhenGuardClause::ParameterizedNamedRule(prc) => {
                                assert_eq!(
                                    prc.named_rule.dependent_rule.as_str(),
                                    "check_required_tags_present"
                                );
                                assert!(matches!(&prc.parameters[0], LetValue::AccessClause(_)));
                            }
                            _ => unreachable!(),
                        }
                    }

                    _ => unreachable!(),
                }
            }
        }
        _ => unreachable!(),
    }

    Ok(())
}

#[test]
fn test_variable_capture_syntax() -> Result<(), Error> {
    let map_index_capture = "Resources[ resource_name ].Properties";
    let access = AccessQuery::try_from(map_index_capture)?.query;
    assert_eq!(access.len(), 3);
    // `AllIndices`, not `AllValues`, and the old expectation was the defect rather than the contract.
    // `all_indices`'s named branch did not skip leading whitespace, so this spelling fell through to
    // `map_key_lookup` and came back a different query part than `Resources[resource_name]` -- which
    // matters because the `%var` interpolation arm accepts one and not the other.
    assert_eq!(
        access[1],
        QueryPart::AllIndices(Some(String::from("resource_name")))
    );
    // Both spellings, so the equivalence is the assertion rather than one side of it.
    let no_spaces = AccessQuery::try_from("Resources[resource_name].Properties")?.query;
    assert_eq!(access, no_spaces);

    let map_index_with_filter =
        "Resources[ resource_name | Type == 'AWS::S3::Bucket' ].Properties.BucketName";
    let access = AccessQuery::try_from(map_index_with_filter)?.query;
    assert_eq!(access.len(), 4);
    let filters = &access[1];
    assert!(matches!(filters, QueryPart::Filter(_, _)));
    let (name, _filter) = match filters {
        QueryPart::Filter(name, filters) => (name, filters),
        _ => unreachable!(),
    };
    assert_eq!(name, &Some(String::from("resource_name")));
    Ok(())
}

#[test]
fn test_builtin_function_call_expr() -> Result<(), Error> {
    let call_expr = "count(Resources.*)";
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, FunctionName::Count);
    assert_eq!(function.parameters.len(), 1);
    let parameter = &function.parameters[0];
    assert!(matches!(parameter, LetValue::AccessClause(_)));
    if let LetValue::AccessClause(query) = parameter {
        assert!(query.match_all);
        assert_eq!(query.query.len(), 2);
        let expected = vec![
            QueryPart::Key("Resources".to_string()),
            QueryPart::AllValues(None),
        ];
        assert_eq!(&query.query, &expected);
    }

    let call_expr =
        r#"json_parse(Resources[ Type == 'AWS::SNS::TopicPolicy' ].Properties.PolicyDocument)"#;
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, FunctionName::JsonParse);
    assert_eq!(function.parameters.len(), 1);
    let parameter = &function.parameters[0];
    assert!(matches!(parameter, LetValue::AccessClause(_)));
    if let LetValue::AccessClause(query) = parameter {
        assert!(query.match_all);
        assert_eq!(query.query.len(), 4);
    }

    let call_expr =
        r#"json_parse(Resources[ Type == 'AWS::SNS::TopicPolicy' ].Properties.PolicyDocument)"#;
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, FunctionName::JsonParse);
    assert_eq!(function.parameters.len(), 1);
    let parameter = &function.parameters[0];
    assert!(matches!(parameter, LetValue::AccessClause(_)));
    if let LetValue::AccessClause(query) = parameter {
        assert!(query.match_all);
        assert_eq!(query.query.len(), 4);
    }

    let call_expr = r#"substring(%sqs_queues.Arn, 0, 6)"#;
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, FunctionName::Substring);
    assert_eq!(function.parameters.len(), 3);
    let parameter = &function.parameters[0];
    assert!(matches!(parameter, LetValue::AccessClause(_)));
    if let LetValue::AccessClause(query) = parameter {
        assert!(query.match_all);
        assert_eq!(query.query.len(), 3);
    }

    let parameter = &function.parameters[1];
    assert!(matches!(parameter, LetValue::Value(_)));
    if let LetValue::Value(PathAwareValue::Int((_, v))) = parameter {
        assert_eq!(*v, 0);
    }

    let parameter = &function.parameters[2];
    assert!(matches!(parameter, LetValue::Value(_)));
    if let LetValue::Value(PathAwareValue::Int((_, v))) = parameter {
        assert_eq!(*v, 6);
    }

    Ok(())
}

#[test]
fn test_parse_regex_inner_when_regex_is_not_valid() {
    let invalid = r"\";
    let invalid_cmp = unsafe { Span::new_from_raw_offset(invalid.len(), 1, invalid, "") };
    let expected_invalid = Err(nom::Err::Error(ParserError {
        context: "Could not parse regular expression".to_string(),
        kind: ErrorKind::RegexpMatch,
        span: invalid_cmp,
    }));

    assert_eq!(expected_invalid, parse_regex_inner(invalid_cmp));
}

#[test]
fn test_parse_regex_inner_when_regex_is_valid() {
    let valid = "\\w+/";
    let valid_cmp = unsafe { Span::new_from_raw_offset(valid.len(), 5, valid, "") };

    assert!(parse_regex_inner(valid_cmp).is_ok())
}

#[test]
fn test_parse_regex_when_regex_contains_incomplete_group_structure() {
    std::env::set_var("RUST_BACKTRACE", "1");

    let invalid = r#"/!w(?()"Kuz>/"#;

    let invalid_cmp = unsafe { Span::new_from_raw_offset(invalid.len(), 1, invalid, "") };
    assert!(parse_regex(invalid_cmp).is_err());
}

#[test]
fn test_parse_regex_when_regex_contains_complete_group_structure_and_escaped_opening_paren() {
    let invalid = r#"/!w\(?()"Kuz>/"#;

    let invalid_cmp = unsafe { Span::new_from_raw_offset(invalid.len(), 1, invalid, "") };
    assert!(parse_regex(invalid_cmp).is_ok());
}

#[test]
fn test_parse_regex_when_regex_contains_control_characters() {
    let invalid = r#"t(/(FF      ()!t	(?(
{),:?t.+
                    "#;

    let invalid_cmp = unsafe { Span::new_from_raw_offset(invalid.len(), 1, invalid, "") };
    assert!(parse_regex_inner(invalid_cmp).is_err());
}

#[test]
fn test_parse_value_when_strings_are_randomly_generated() {
    let values = vec!["weifhasidhhfasidf77627&^&*^**", "IiI+L1w="];

    for value in values {
        let cmp = unsafe { Span::new_from_raw_offset(value.len(), 5, value, "") };
        assert!(parse_value(cmp).is_err())
    }
}

#[test]
fn test_parse_assignment_with_function_call() {
    let input = "let num = count(%s3_buckets_bucket_logging_enabled)";

    let res = assignment(from_str2(input)).unwrap();

    assert_eq!(res.1.var, "num");

    let function = res.1.value;
    assert!(matches!(function, LetValue::FunctionCall(_)));

    if let LetValue::FunctionCall(function) = function {
        assert_eq!(function.name, FunctionName::Count);
        assert_eq!(function.parameters.len(), 1);
        assert!(matches!(function.parameters[0], LetValue::AccessClause(_)));
    }
}

#[test]
fn test_parse_assignment_with_function_call2() {
    let input = r#"let num = regex_replace(%s3_buckets_bucket_logging_enabled, "^arn:(\\w+):(\\w+):([\\w0-9-]+):(\\d+):(.+)$", "${1}/${4}/${3}/${2}-${5}")"#;
    let res = assignment(from_str2(input)).unwrap();

    assert_eq!(res.1.var, "num");

    let function = res.1.value;
    assert!(matches!(function, LetValue::FunctionCall(_)));

    if let LetValue::FunctionCall(function) = function {
        assert_eq!(function.name, FunctionName::RegexReplace);
        assert_eq!(function.parameters.len(), 3);
        assert!(matches!(
            function.parameters[1],
            LetValue::Value(PathAwareValue::String(_))
        ));
        assert!(matches!(
            function.parameters[2],
            LetValue::Value(PathAwareValue::String(_))
        ));
        assert_eq!(function.parameters.len(), 3);
        assert!(matches!(function.parameters[0], LetValue::AccessClause(_)));
    }
}

#[test]
fn test_get_rule_name() {
    let rule_clause_name1 = "harry";
    let rule_file_name = "lily.guard";
    let rule_clause_name2 = "lily.guard/harry";

    assert_eq!(
        get_rule_name(rule_file_name, rule_clause_name1),
        rule_clause_name1
    );
    assert_eq!(
        get_rule_name(rule_file_name, rule_clause_name2),
        rule_clause_name1
    );
}

/// A rule name defined twice is rejected rather than resolved to one of them.
///
/// A rule name is what a reference resolves through, so two definitions make every reference to it
/// ambiguous. The file was accepted, and the reference bound to whichever definition appeared first:
/// with one definition holding and one not, `rule user when dup { ... }` reported PASS when the
/// holding definition came first and SKIP when it came second. Both definitions still run and report,
/// so the file exits 19 either way and the exit code cannot see the difference -- the guarded rule
/// silently went from enforced to not-applicable on a reordering.
///
/// Parameterized rules share the namespace, so `rule r` beside `rule r(x)` is the same collision.
#[rstest::rstest]
#[case::two_plain_rules("rule dup { Resources.A == 1 }\nrule dup { Resources.A == 2 }\n")]
#[case::plain_beside_parameterized(
    "rule r { Resources.A == 1 }\nrule r(x) { Resources.A == %x }\n"
)]
#[case::two_parameterized("rule r(x) { Resources.A == %x }\nrule r(y) { Resources.A == %y }\n")]
#[case::three_definitions(
    "rule d { Resources.A == 1 }\nrule d { Resources.A == 2 }\nrule d { Resources.A == 3 }\n"
)]
fn a_rule_defined_twice_is_rejected(#[case] rules: &str) {
    let err = rules_file(from_str2(rules)).expect_err("a duplicated rule name must not parse");
    let rendered = format!("{}", err);
    assert!(
        rendered.contains("defined more than once"),
        "the error must name the problem, not merely fail: {}",
        rendered
    );
}

/// The control for the case above, so the check cannot pass by rejecting everything.
#[rstest::rstest]
#[case::distinct_names("rule one { Resources.A == 1 }\nrule two { Resources.A == 2 }\n")]
#[case::distinct_parameterized(
    "rule one(x) { Resources.A == %x }\nrule two(y) { Resources.A == %y }\n"
)]
#[case::a_reference_to_a_single_definition(
    "rule inner { Resources.A == 1 }\nrule outer when inner { Resources.B == 2 }\n"
)]
#[case::default_clauses_beside_a_named_rule("Resources.A == 1\nrule named { Resources.B == 2 }\n")]
fn distinct_rule_names_still_parse(#[case] rules: &str) -> Result<(), Error> {
    assert!(
        rules_file(from_str2(rules))?.is_some(),
        "these names are distinct and must parse: {}",
        rules
    );
    Ok(())
}

/// A parameter declared twice is rejected at the definition, not at every call.
///
/// The names were collected straight into an `IndexSet`, so the duplicate vanished and `rule r(a, a)`
/// became a one-parameter rule. The definition parsed without complaint, and the arity check then
/// failed at every call site -- blaming the caller for passing two arguments to a rule written to take
/// two -- and ended the run at 255, an internal failure, for a rule-authoring mistake.
#[rstest::rstest]
#[case::two_of_two("rule r(a, a) { Resources.A == %a }\n")]
#[case::two_of_three("rule r(a, b, a) { Resources.A == %a }\n")]
#[case::spaced("rule r( a , a ) { Resources.A == %a }\n")]
fn a_parameter_declared_twice_is_rejected(#[case] rules: &str) {
    let err = rules_file(from_str2(rules)).expect_err("a duplicated parameter must not parse");
    let rendered = format!("{}", err);
    assert!(
        rendered.contains("declared more than once"),
        "the error must name the problem: {}",
        rendered
    );
}

/// The control, so the check above cannot pass by rejecting every parameter list.
#[rstest::rstest]
#[case::one("rule r(a) { Resources.A == %a }\n")]
#[case::two_distinct("rule r(a, b) { Resources.A == %a }\n")]
#[case::three_distinct("rule r(a, b, c) { Resources.A == %a }\n")]
#[case::names_sharing_a_prefix("rule r(a, ab, abc) { Resources.A == %a }\n")]
fn distinct_parameter_names_still_parse(#[case] rules: &str) -> Result<(), Error> {
    assert!(
        rules_file(from_str2(rules))?.is_some(),
        "these parameter names are distinct and must parse: {}",
        rules
    );
    Ok(())
}

/// An unterminated `<<` is rejected rather than eating the rest of the file.
///
/// `extract_message` searched all remaining input for `>>`, so one forgotten closing tag consumed every
/// rule up to the *next* rule's tag as message text. Those rules ceased to exist: the file below reported
/// PASS at exit 0 against a template its second rule violates, with a parse tree containing only the first
/// rule and the rest of the file inside its custom message. A typo deleted a check and the run called the
/// template compliant, with no diagnostic on any channel.
///
/// Both halves are asserted. Rejecting the broken file is the fix; parsing the multi-line message is what
/// the fix must not cost, and 231 of the 232 messages in the rule registry and this repository's fixtures
/// are multi-line.
#[test]
fn an_unterminated_message_does_not_swallow_the_rules_after_it() -> Result<(), Error> {
    let swallowed = r###"
rule first_rule {
    Resources.Bad.Properties.BucketName == "mybucket" << oops I forgot the closing tag
}

rule second_rule {
    Resources.Bad.Properties.Public == false << buckets must not be public >>
}
"###;
    assert!(
        rules_file(from_str2(swallowed)).is_err(),
        "an unterminated << must be rejected, not close itself on a later rule's >>"
    );

    // The same defect one scope narrower, and the case the first version of this bound missed: the next
    // `>>` belongs to the very next clause of the *same* rule, so nothing that scans for a closing brace or
    // a `rule` line ever sees a boundary. Clause two was swallowed and the rule reported PASS at exit 0.
    let swallowed_sibling = r###"
rule r {
    Resources.Bad.Properties.BucketName == "mybucket" << oops I forgot the closing tag
    Resources.Bad.Properties.Public == false << buckets must not be public >>
}
"###;
    assert!(
        rules_file(from_str2(swallowed_sibling)).is_err(),
        "an unterminated << must not close itself on the next clause's >> either"
    );

    let multi_line = r###"
rule r {
    Resources.Bad.Properties.Public == false
    <<
      Violation: buckets must not be public
      Fix: set Public to false
    >>
}
"###;
    assert!(
        rules_file(from_str2(multi_line))?.is_some(),
        "a message spanning lines is the ordinary case and must still parse"
    );

    // And the shape the first version of this bound wrongly rejected. A body that quotes example JSON has a
    // line starting with `}`, which is what a "Fix: add one, for example ..." message looks like.
    let quotes_json = r###"
rule r {
    Resources.One.Properties.PolicyDocument exists
    <<
      Violation: no policy document.
      Fix: add one, for example
      {
        "Version": "2012-10-17",
        "Statement": []
      }
    >>
}
"###;
    assert!(
        rules_file(from_str2(quotes_json))?.is_some(),
        "a message body may contain braces at the start of a line: it is quoting JSON, not closing a block"
    );
    Ok(())
}

/// The same defect inside a nested block, which is a separate parse path rather than a repeat.
///
/// `message_bound` is one function and every scope calls it, so it is fair to ask why a nested block needs
/// its own assertion. Because the bound is shared and the parsers that reach it are not. Three separate
/// `block(...)` instantiations can hold a clause carrying a message: `rule_block` builds
/// `block(rule_block_clause)` for a rule body, `type_block` builds `block(clause)`, and the `when`-block arm
/// of `rule_block_clause` builds `block(alt((clause, rule_clause)))`. A change that re-routes or
/// special-cases the message scan in one of them leaves the other two alone, and an assertion written
/// against a rule body would not see it.
///
/// What makes that worth an assertion rather than a comment is the shape of the failure. A wrong bound does
/// not error: the message swallows the clause after it, and the swallowed check is then reported as
/// compliant. Measured against a bucket whose name matches the first clause and whose `Encrypted` is
/// `false`, both broken files below exited 0 under the `}`-or-`rule` bound and exit 5 under the current one.
///
/// A rule-level `when` is not a third parser -- `rule_block` calls `block(rule_block_clause)` whether or not
/// it parsed a condition -- but it is the form real rules files are written in, so it is asserted too.
#[test]
fn an_unterminated_message_does_not_swallow_the_clauses_in_a_nested_block() -> Result<(), Error> {
    let type_block_swallow = r###"
rule r {
    AWS::S3::Bucket {
        Properties.BucketName == "mybucket" << oops no closing tag
        Properties.Encrypted == true << must be encrypted >>
    }
}
"###;
    assert!(
        rules_file(from_str2(type_block_swallow)).is_err(),
        "an unterminated << inside a type block must be rejected, not close itself on the next clause's >>"
    );

    let when_rule_swallow = r###"
rule r when Resources.One.Type == "AWS::S3::Bucket" {
    Resources.One.Properties.BucketName == "mybucket" << oops
    Resources.One.Properties.Encrypted == true << must be encrypted >>
}
"###;
    assert!(
        rules_file(from_str2(when_rule_swallow)).is_err(),
        "a rule-level when does not buy the body a different bound: the unterminated << is still rejected"
    );

    let nested_when_swallow = r###"
rule r {
    when Resources.One.Type == "AWS::S3::Bucket" {
        Resources.One.Properties.BucketName == "mybucket" << oops
        Resources.One.Properties.Encrypted == true << must be encrypted >>
    }
}
"###;
    assert!(
        rules_file(from_str2(nested_when_swallow)).is_err(),
        "a when block inside a rule body is the third block parser, and it must reject the tag as well"
    );

    // The legitimate form of each, so none of the three can pass by rejecting whatever it is handed. The
    // body here starts on the `<<` line and closes on a line of its own, which is the permissive half of
    // the block form: entering block mode does not require `<<` to be the last thing on its line.
    let type_block_message = r###"
rule r {
    AWS::S3::Bucket {
        Properties.Encrypted == true
        << Violation: not encrypted
           Fix: set Encrypted to true
        >>
    }
}
"###;
    assert!(
        rules_file(from_str2(type_block_message))?.is_some(),
        "a closed multi-line message inside a type block is ordinary and must still parse"
    );

    let when_rule_message = r###"
rule r when Resources.One.Type == "AWS::S3::Bucket" {
    Resources.One.Properties.Encrypted == true << Violation: not encrypted >>
}
"###;
    assert!(
        rules_file(from_str2(when_rule_message))?.is_some(),
        "a closed message in the body of a conditional rule is ordinary and must still parse"
    );

    let nested_when_message = r###"
rule r {
    when Resources.One.Type == "AWS::S3::Bucket" {
        Resources.One.Properties.Encrypted == true << Violation: not encrypted >>
    }
}
"###;
    assert!(
        rules_file(from_str2(nested_when_message))?.is_some(),
        "a closed message inside a nested when block is ordinary and must still parse"
    );
    Ok(())
}

/// A `>>` that is not a closing tag does not close a message.
///
/// Both earlier bounds on this search read a `>>` as a terminator wherever they found one, and differed only
/// in where they stopped looking. That is what a comment defeats: a `>>` inside a comment is not a closing
/// tag, and no bound expressed in braces or in `<<` can tell the difference. Bounding at the next `<<` let a
/// comment in a *later* rule close a forgotten tag, which exited 0 against a template that later rule
/// violates and left it out of the parse tree entirely -- the original silent-deletion defect. A comment at
/// the end of the *same* block defeats both bounds at once, because neither a `}` line nor a second `<<`
/// sits between the two tags, and both exited 0 on it.
///
/// The terminator is now a line whose trimmed text is exactly `>>`, so a `>>` with anything else on its line
/// is text rather than a tag, and both shapes are rejected.
#[test]
fn a_stray_closing_tag_does_not_close_a_message() -> Result<(), Error> {
    // The `>>` sits in a comment in a later rule, with no second `<<` anywhere to bound the search.
    let comment_in_a_later_rule = r###"
rule one {
    Resources.One.Type == "AWS::S3::Bucket" << closing tag forgotten
}
rule two {
    Resources.One.Properties.Encrypted == true
    # see the runbook for escalation >>
}
rule three {
    Resources.One.Properties.Public == true
}
"###;
    assert!(
        rules_file(from_str2(comment_in_a_later_rule)).is_err(),
        "a >> inside a comment is not a closing tag, whichever rule the comment belongs to"
    );

    // The same `>>`, in a comment at the end of the block that holds the forgotten tag. No `}` line and no
    // second `<<` lies between the two, which is why neither of the earlier bounds saw anything wrong.
    let trailing_comment_in_the_same_block = r###"
rule one {
    Resources.One.Type == "AWS::S3::Bucket" << forgot
    Resources.One.Properties.Encrypted == true
    # trailing comment with >>
}
"###;
    assert!(
        rules_file(from_str2(trailing_comment_in_the_same_block)).is_err(),
        "a trailing comment carrying >> must not close a tag forgotten earlier in the same block"
    );

    // The other direction, and the reason the test is "the line is exactly `>>`" rather than "the line
    // contains `>>`": a body line may hold a `>>` of its own. Every earlier version closed the message at
    // the first `>>` it found, so this file did not parse.
    let closing_tag_shares_the_body_with_another = r###"
rule r {
    Resources.One.Properties.Public == false
    <<
      Violation: buckets must not be public
      Fix: rewrite A >> B as a redirect
    >>
}
"###;
    assert!(
        rules_file(from_str2(closing_tag_shares_the_body_with_another))?.is_some(),
        "a >> inside the body is text: the terminator is a line that is exactly >>, not one containing it"
    );
    Ok(())
}

/// Both message forms parse, and only those two.
///
/// The grammar now treats them differently, so each needs pinning. Of the 233 messages in the AWS rule
/// registry and this repository's fixtures, 231 are block form with the closing `>>` alone on its line and 2
/// are inline with both tags on one line; nothing follows `>>` on its line in any of them.
///
/// The last assertion is the cost of closing the defect, recorded on purpose so that it is not reopened by
/// loosening the terminator. A block body whose `>>` shares a line with body text cannot be admitted,
/// because the swallowed clause of an intra-block forgotten tag is itself a line ending in `>>`: accepting
/// one accepts the other. No message in the corpus is written that way.
#[test]
fn the_inline_and_block_message_forms_are_both_accepted() -> Result<(), Error> {
    let inline = r###"
rule r {
    Resources.One.Properties.Public == false << buckets must not be public >>
}
"###;
    assert!(
        rules_file(from_str2(inline))?.is_some(),
        "a message with both tags on one line is one of the two forms that occur"
    );

    let empty_spaced = r###"
rule r {
    Resources.One.Properties.Public == false << >>
}
"###;
    assert!(
        rules_file(from_str2(empty_spaced))?.is_some(),
        "an empty inline message is still a closed message"
    );

    let empty_tight = r###"
rule r {
    Resources.One.Properties.Public == false <<>>
}
"###;
    assert!(
        rules_file(from_str2(empty_tight))?.is_some(),
        "an empty inline message with no space between the tags is closed too"
    );

    let block = r###"
rule r {
    Resources.One.Properties.Public == false
    <<
      Violation: buckets must not be public
    >>
}
"###;
    assert!(
        rules_file(from_str2(block))?.is_some(),
        "a block message with the closing tag alone on its line is the shape 231 of the 233 use"
    );

    let closing_tag_not_alone_on_its_line = r###"
rule r {
    Resources.One.Properties.Public == false
    << Violation: buckets must not be public
       Fix: set Public to false >>
}
"###;
    assert!(
        rules_file(from_str2(closing_tag_not_alone_on_its_line)).is_err(),
        "a block body whose >> shares a line with body text is rejected: admitting it admits the swallow"
    );
    Ok(())
}

/// A leading space inside `[...]` does not change the query part.
///
/// The named branch of `all_indices` did not skip whitespace, so `[ x ]` fell through to `map_key_lookup`
/// and returned `AllValues` where `[x]` returned `AllIndices`. Two spaces were then the difference between
/// a rule that works and one that cannot be evaluated, because the `%var` map-key interpolation arm accepts
/// `AllIndices` and not `AllValues`.
#[test]
fn whitespace_inside_a_named_index_does_not_change_the_query_part() -> Result<(), Error> {
    let spellings = [
        "Resources[x].Properties",
        "Resources[x ].Properties",
        "Resources[ x].Properties",
        "Resources[ x ].Properties",
        "Resources[  x  ].Properties",
    ];
    let expected = AccessQuery::try_from(spellings[0])?.query;
    for spelling in &spellings[1..] {
        assert_eq!(
            AccessQuery::try_from(*spelling)?.query,
            expected,
            "all spellings of a named index must parse the same: {}",
            spelling
        );
    }
    Ok(())
}

/// A leading space before a numeric index does not change the query part.
///
/// Same omission as the named branch above, in `array_index`. `open_array` and `close_array` both skip
/// whitespace, so `Names[0 ]` parsed and `Names[ 0]` did not: the space reached `parse_int_value`, whose
/// `digit1` cannot start on one. Nothing else in `predicate_or_index` reads a bare integer, so the query
/// fell through to `predicate_filter_clauses` and the file was rejected at "There were no clauses present".
#[test]
fn whitespace_inside_a_numeric_index_does_not_change_the_query_part() -> Result<(), Error> {
    let spellings = [
        "Names[0].Value",
        "Names[0 ].Value",
        "Names[ 0].Value",
        "Names[ 0 ].Value",
        "Names[  0  ].Value",
    ];
    let expected = AccessQuery::try_from(spellings[0])?.query;
    for spelling in &spellings[1..] {
        assert_eq!(
            AccessQuery::try_from(*spelling)?.query,
            expected,
            "all spellings of a numeric index must parse the same: {}",
            spelling
        );
    }
    Ok(())
}

/// A negative index takes whitespace on both sides too.
///
/// Its own branch of `parse_int_value`, so it needed asserting separately: the sign is parsed with the
/// digits rather than applied afterwards, and a space between `[` and `-` failed for the same reason a
/// space before a digit did.
#[test]
fn whitespace_inside_a_negative_numeric_index_does_not_change_the_query_part() -> Result<(), Error>
{
    let spellings = [
        "Names[-1].Value",
        "Names[-1 ].Value",
        "Names[ -1].Value",
        "Names[ -1 ].Value",
    ];
    let expected = AccessQuery::try_from(spellings[0])?.query;
    for spelling in &spellings[1..] {
        assert_eq!(
            AccessQuery::try_from(*spelling)?.query,
            expected,
            "all spellings of a negative index must parse the same: {}",
            spelling
        );
    }
    Ok(())
}

/// The nested positions, which the same omission also rejected.
///
/// An index inside a filter and an index followed by a key access are the two spellings an author is most
/// likely to write with spaces, and both were parse errors.
#[test]
fn whitespace_inside_a_nested_numeric_index_does_not_change_the_query_part() -> Result<(), Error> {
    for (spaced, unspaced) in [
        (
            "Resources[ Properties.Names[ 0 ] == \"a\" ]",
            "Resources[ Properties.Names[0] == \"a\" ]",
        ),
        ("Tags[ 0 ].Key", "Tags[0].Key"),
    ] {
        assert_eq!(
            AccessQuery::try_from(spaced)?.query,
            AccessQuery::try_from(unspaced)?.query,
            "a spaced nested index must parse the same as the unspaced one: {}",
            spaced
        );
    }
    Ok(())
}

/// The last bracket form with the omission: a quoted key, in `map_key_lookup`.
///
/// `Resources["MyBucket"]` resolves to `Key("MyBucket")`, so a string literal names a property whose
/// characters a bare identifier cannot spell. `Resources[ "MyBucket" ]` was rejected for the same reason
/// the numeric index was, one function along: `parse_string` was called on the input directly while
/// `open_array` and `close_array` skipped whitespace either side of it.
#[test]
fn whitespace_inside_a_quoted_key_does_not_change_the_query_part() -> Result<(), Error> {
    let spellings = [
        r#"Resources["MyBucket"].Type"#,
        r#"Resources["MyBucket" ].Type"#,
        r#"Resources[ "MyBucket"].Type"#,
        r#"Resources[ "MyBucket" ].Type"#,
        r#"Resources[  "MyBucket"  ].Type"#,
    ];
    let expected = AccessQuery::try_from(spellings[0])?.query;
    for spelling in &spellings[1..] {
        assert_eq!(
            AccessQuery::try_from(*spelling)?.query,
            expected,
            "all spellings of a quoted key must parse the same: {}",
            spelling
        );
    }
    Ok(())
}

/// A filter whose first token is a quoted string stays a filter.
///
/// Unlike the numeric index, this branch competes for input that already parses: a string literal opens
/// a clause as readily as it names a key, and `Resources[ "AWS::CloudFormation::Authentication" exists ]`
/// is a filter in the AWS rule registry. Reading it as a key would change what the rule tests rather than
/// reject it, so it is asserted rather than left to the sweep. What separates the two is the token after
/// the string: `map_key_lookup` requires `]` next, and its `close_array` carries no `cut`, so a clause
/// backtracks into `predicate_filter_clauses` with the string unconsumed.
#[test]
fn a_filter_beginning_with_a_quoted_string_is_not_read_as_a_key() -> Result<(), Error> {
    for spelling in [
        r#"Resources[ "AWS::CloudFormation::Authentication" exists ]"#,
        r#"Resources["AWS::CloudFormation::Authentication" exists]"#,
    ] {
        let query = AccessQuery::try_from(spelling)?.query;
        assert!(
            matches!(query.get(1), Some(QueryPart::Filter(..))),
            "expected a filter, got {:?} for {}",
            query.get(1),
            spelling
        );
    }
    Ok(())
}

/// A clause whose first identifier starts with `when` is a clause, not a parse failure.
///
/// `tag("when")` matched the first four characters of `whenCreated`, the whitespace `when_conditions`
/// requires then failed, and the `cut` inside it made that unrecoverable -- so the `alt` that would have
/// read the line as an ordinary clause never got the chance. Only the exact-case prefixes reached the tag,
/// which is why `WhenCreated` was fine and `WHENCREATED` was not.
#[test]
fn a_clause_starting_with_the_when_prefix_still_parses() -> Result<(), Error> {
    for rules in [
        "rule r {\n  Resources.*.Properties {\n    whenCreated EXISTS\n  }\n}",
        "rule r {\n  Resources.*.Properties {\n    WHENCREATED EXISTS\n  }\n}",
        "rule r {\n  Resources.*.Properties {\n    WhenCreated EXISTS\n  }\n}",
        "rule r {\n  Resources.*.Properties {\n    createdWhen EXISTS\n  }\n}",
    ] {
        assert!(
            rules_file(from_str2(rules))?.is_some(),
            "a property whose name starts with a keyword is a property: {}",
            rules
        );
    }

    // And `when` itself still gates a rule.
    assert!(rules_file(from_str2(
        "rule r when Resources.*.Properties.Size > 10 {\n  Resources.*.Properties.Encrypted == true\n}"
    ))?
    .is_some());
    Ok(())
}

/// A name assigned twice in one scope is rejected rather than resolved by kind precedence.
///
/// Both orders were accepted and they disagreed: with `Size: 1` in the template, `let v = 1` then
/// `let v = 999` failed the rule and the reverse passed it. Worse, two assignments of *different* kinds
/// ignored their order entirely, because `extract_variables` files literals, queries and function calls
/// into separate maps and `resolve_variable` consults them in a fixed order. So the winner was decided by
/// the kind of each value, which is not something an author can see.
///
/// Both scopes, because they are collected in different places: file-level in `rules_file`, everything
/// nested in `block`.
#[test]
fn a_variable_assigned_twice_in_one_scope_is_rejected() -> Result<(), Error> {
    for rules in [
        "let v = 1\nlet v = 999\nrule r {\n  Resources.R.Properties.Size == %v\n}",
        "let v = 999\nlet v = 1\nrule r {\n  Resources.R.Properties.Size == %v\n}",
        "let v = 999\nlet v = Resources.R.Properties.Size\nrule r {\n  Resources.R.Properties.Size == %v\n}",
        "rule r {\n  Resources.R {\n    let v = 1\n    let v = 999\n    Properties.Size == %v\n  }\n}",
    ] {
        assert!(
            rules_file(from_str2(rules)).is_err(),
            "a duplicate assignment must be rejected: {}",
            rules
        );
    }

    // Distinct names in one scope, and the same name in sibling scopes, are both fine.
    assert!(rules_file(from_str2(
        "let a = 1\nlet b = 2\nrule r {\n  Resources.R.Properties.Size == %a\n}"
    ))?
    .is_some());
    assert!(rules_file(from_str2(
        "rule one {\n  let v = 1\n  Resources.R.Properties.Size == %v\n}\nrule two {\n  let v = 2\n  Resources.R.Properties.Size == %v\n}"
    ))?
    .is_some());
    Ok(())
}

/// A filter over a property named `keys` parses, and a key filter still does.
///
/// `map_keys_match` committed with `cut` as soon as it had seen `keys`, so a following token that was not
/// one of the four key-filter comparators produced a Failure and stopped the filter-clause branch from
/// running at all. The proof that nothing ambiguous forced it was positional: the identical clause parsed
/// one slot later, as `[ Size EXISTS keys EXISTS ]`.
#[test]
fn a_filter_on_a_property_named_keys_parses() -> Result<(), Error> {
    for rules in [
        "rule r {\n  Resources.*.Properties[ keys EXISTS ] !EMPTY\n}",
        "rule r {\n  Resources.*.Properties[ keys EMPTY ] !EMPTY\n}",
        "rule r {\n  Resources.*.Properties[ keys >= 1 ] !EMPTY\n}",
    ] {
        assert!(
            rules_file(from_str2(rules))?.is_some(),
            "`keys` is reserved for the key-filter comparators, not for every clause: {}",
            rules
        );
    }

    // The key filter itself is unaffected, in both spellings.
    for rules in [
        "rule r {\n  Resources[ keys == /^Bucket/ ] !EMPTY\n}",
        "rule r {\n  Resources[ KEYS != 'aws:IsSecure' ] !EMPTY\n}",
    ] {
        assert!(rules_file(from_str2(rules))?.is_some(), "{}", rules);
    }
    Ok(())
}

/// An operator that is a prefix of a longer identifier does not split the clause in two.
///
/// `tag("IS_INT")` matched the first six characters of `IS_INTEGER` and left `EGER` behind, and a bare
/// identifier is a valid clause -- a reference to a rule of that name. So `Size IS_INTEGER` parsed as
/// `Size IS_INT` *and* a reference to a rule called `EGER`: loud when no such rule existed, and PASS at
/// exit 0 when one did. The same guard the boolean and null keywords already had, applied to this group
/// and to `in`.
#[test]
fn an_operator_that_prefixes_an_identifier_is_not_an_operator() -> Result<(), Error> {
    for rules in [
        "rule r {\n  Resources.R.Properties.Size IS_INTEGER\n}",
        "rule r {\n  Resources.R.Properties.Size is_integer\n}",
        "rule r {\n  Resources.R.Properties.Size IS_LISTING\n}",
        "rule r {\n  Resources.R.Properties.Size inside [1, 2]\n}",
    ] {
        assert!(
            rules_file(from_str2(rules)).is_err(),
            "a longer identifier must not be read as the shorter operator plus a rule reference: {}",
            rules
        );
    }

    // The operators themselves still parse.
    for rules in [
        "rule r {\n  Resources.R.Properties.Size IS_INT\n}",
        "rule r {\n  Resources.R.Properties.Size is_list\n}",
        "rule r {\n  Resources.R.Properties.Size in [1, 2]\n}",
        "rule r {\n  Resources.R.Properties.Size IN [1, 2]\n}",
    ] {
        assert!(rules_file(from_str2(rules))?.is_some(), "{}", rules);
    }
    Ok(())
}

/// The integer boundary is exact in both directions.
///
/// `parse_int_value` parsed the digits of a negative literal and negated afterwards, which caps the
/// magnitude at `i64::MAX` -- so `i64::MIN` was the one expressible value the parser refused. Loud, so it
/// never produced a wrong verdict, and one fewer thing for an author to discover. `i64::MAX + 1` is still
/// rejected, which is the half that must not change: a wrap there would compare the wrong number.
#[test]
fn the_integer_literal_boundary_is_exact() -> Result<(), Error> {
    for accepted in [
        "-9223372036854775808",
        "-9223372036854775807",
        "9223372036854775807",
        "0",
        "-0",
    ] {
        let rules = format!("rule r {{\n  Resources.X == {accepted}\n}}");
        assert!(
            rules_file(from_str2(&rules))?.is_some(),
            "an expressible integer must parse: {}",
            accepted
        );
    }

    for rejected in ["9223372036854775808", "-9223372036854775809"] {
        let rules = format!("rule r {{\n  Resources.X == {rejected}\n}}");
        assert!(
            rules_file(from_str2(&rules)).is_err(),
            "an integer that does not fit must be rejected rather than wrapped: {}",
            rejected
        );
    }
    Ok(())
}

/// A rule reference may end its line or its block.
///
/// `rule_clause` peeked for newline, comment, `{` and `or`, and anything else fell to a `cut` whose Failure
/// escaped the enclosing alternation. So `rule b { a }` was rejected -- with an error naming `}` rather than
/// the reference -- while the same rule written over three lines parsed. Every other clause form works
/// inline, which made this specific to rule references.
#[test]
fn a_rule_reference_can_end_its_block() -> Result<(), Error> {
    for rules in [
        "rule a { Resources EXISTS }\nrule b { a }",
        "rule a { Resources EXISTS }\nrule b {\n  a\n}",
        "rule a { Resources EXISTS }\nrule b { !a }",
        "rule a { Resources EXISTS }\nrule b when a { Resources EXISTS }",
    ] {
        assert!(
            rules_file(from_str2(rules))?.is_some(),
            "a rule reference is a clause like any other: {}",
            rules
        );
    }
    Ok(())
}

/// The two forms the grammar comment used to document but the parser never accepted.
///
/// Pinned so the ABNF and the code cannot drift apart again in that direction: if either spelling is ever
/// implemented, this test is where the grammar comment gets updated with it.
#[test]
fn the_two_forms_the_grammar_no_longer_claims_are_still_rejected() -> Result<(), Error> {
    for rejected in [
        "rule r {\n  Resources.X NOT_IN [\"a\", \"b\"]\n}",
        "rule r {\n  Resources.X KEYS == /^a/\n}",
    ] {
        assert!(
            rules_file(from_str2(rejected)).is_err(),
            "not accepted, and the grammar no longer says otherwise: {}",
            rejected
        );
    }

    // The spellings that do work, so this test fails if the intent is ever inverted.
    assert!(rules_file(from_str2(
        "rule r {\n  Resources.X not in [\"a\", \"b\"]\n}"
    ))?
    .is_some());
    assert!(rules_file(from_str2("rule r {\n  Resources[ keys == /^a/ ] !EMPTY\n}"))?.is_some());
    Ok(())
}

/// The parse tree `parse-tree` prints, with one substitution applied to it.
///
/// The tests below compare the tree rather than assert that a file parses, because a clause read as something
/// other than what it says parses too: `[x]` and `[ x ]` both parsed and built different query parts, which is
/// how the first attempt at the bracket whitespace fix on this branch did its damage. Each caller spells out
/// its own substitution, because `Key: rule` cannot be shortened to `rule` -- that is a substring of the
/// tree's own field names, `guard_rules`, `rule_name` and `parameterized_rules`.
fn parse_tree_with(rules: &str, from: &str, to: &str) -> Result<String, Error> {
    let parsed =
        rules_file(from_str2(rules))?.expect("these rules files all hold at least one rule");
    let tree = serde_yaml::to_string(&parsed).expect("a parsed rules file serialises");
    Ok(tree.replace(from, to))
}

/// A clause whose first identifier *is* `when` reads as a clause about a property of that name.
///
/// `keyword("when")` rejects a trailing identifier character, which is what fixed `whenCreated`. A trailing
/// `.`, `[` or `(` is not an identifier character, so those spellings still matched the keyword, still failed
/// the whitespace `when_conditions` requires, and the `cut` around that requirement still turned the failure
/// into a Failure that escaped the alternation reading the line as a clause. A `when` block cannot be spelled
/// without that space, so moving the requirement out of the `cut` admits nothing else.
///
/// CloudFormation permits a property named `when`, so these come from templates rather than from pedantry.
#[test]
fn a_clause_whose_first_identifier_is_when_reads_as_that_clause() -> Result<(), Error> {
    for (spelled, keyword, control) in [
        (
            "rule r {\n  when.foo == \"bar\"\n}",
            "when",
            "rule r {\n  wibble.foo == \"bar\"\n}",
        ),
        (
            "rule r {\n  when[\"foo\"] == \"bar\"\n}",
            "when",
            "rule r {\n  wibble[\"foo\"] == \"bar\"\n}",
        ),
        (
            "rule r {\n  when.foo EXISTS\n}",
            "when",
            "rule r {\n  wibble.foo EXISTS\n}",
        ),
        ("when.foo == \"bar\"", "when", "wibble.foo == \"bar\""),
        (
            "rule r {\n  Resources[ when.foo == \"bar\" ] !EMPTY\n}",
            "when",
            "rule r {\n  Resources[ wibble.foo == \"bar\" ] !EMPTY\n}",
        ),
        (
            "AWS::S3::Bucket when.foo == \"bar\"",
            "when",
            "AWS::S3::Bucket wibble.foo == \"bar\"",
        ),
        (
            "rule r {\n  WHEN.foo == \"bar\"\n}",
            "WHEN",
            "rule r {\n  wibble.foo == \"bar\"\n}",
        ),
    ] {
        assert_eq!(
            parse_tree_with(spelled, &format!("Key: {}", keyword), "Key: IDENT")?,
            parse_tree_with(control, "Key: wibble", "Key: IDENT")?,
            "a clause about a property named {} must read as that clause: {}",
            keyword,
            spelled
        );
    }

    // And a parameterized rule named `when` can be called, which is the tell the `whenever` fix was named
    // for: the definition always worked and the call did not. Substituting the bare word here rather than
    // `Key: when`, because the name appears as `rule_name` and as `dependent_rule` in this tree.
    assert_eq!(
        parse_tree_with(
            "rule when(t) {\n  Resources.*.Type == %t\n}\nrule user {\n  when(\"AWS::S3::Bucket\")\n}",
            "when",
            "IDENT",
        )?,
        parse_tree_with(
            "rule wibble(t) {\n  Resources.*.Type == %t\n}\nrule user {\n  wibble(\"AWS::S3::Bucket\")\n}",
            "wibble",
            "IDENT",
        )?,
        "a parameterized rule named when must be callable"
    );
    Ok(())
}

/// `when` is still the gate keyword in all three positions it appears in.
///
/// This is the half of the fix that must not move: the requirement came out of the `cut`, not out of the
/// grammar, so a `when` followed by a space and conditions still opens a block.
#[test]
fn when_is_still_the_gate_keyword() -> Result<(), Error> {
    let gated = rules_file(from_str2(
        "rule r when Resources.*.Properties.Size > 10 {\n  Resources.*.Properties.Encrypted == true\n}",
    ))?
    .expect("a gated rule");
    assert!(
        gated.guard_rules[0].conditions.is_some(),
        "a rule-level when must still be the rule's condition"
    );

    for rules in [
        "rule r {\n  when Resources.Size > 10 {\n    Resources.Encrypted == true\n  }\n}",
        "when Resources.Size > 10 {\n  Resources.Encrypted == true\n}",
    ] {
        let parsed = rules_file(from_str2(rules))?.expect("a rules file with a when block");
        assert!(
            matches!(
                parsed.guard_rules[0].block.conjunctions[0][0],
                RuleClause::WhenBlock(..)
            ),
            "a when block must still be a when block: {}",
            rules
        );
    }

    // What stays rejected, and why it is not part of the fix above: everything after `when` and a space that
    // is not a condition list. `single_clauses` raises its own Failure for that, and the readings it would
    // otherwise have to choose between are real ones -- `when` alone is a reference to a rule of that name,
    // `when == "bar"` is a clause, `when { ... }` is a block clause over a property named `when` -- so a
    // `when` block that lost its conditions would become a silently different rule rather than an error.
    // Quoting the key reaches every one of them. If that trade is ever revisited, it is revisited here.
    for still_rejected in [
        "when == \"bar\"",
        "when .foo == \"bar\"",
        "when [\"foo\"] == \"bar\"",
        "when {\n  Resources EXISTS\n}",
        "rule when {\n  Resources EXISTS\n}\nrule user {\n  when\n}",
    ] {
        assert!(
            rules_file(from_str2(still_rejected)).is_err(),
            "left rejected rather than guessed at: {}",
            still_rejected
        );
    }
    assert!(rules_file(from_str2("\"when\" == \"bar\""))?.is_some());
    Ok(())
}

/// A file-level clause whose first identifier is `rule` reads as a clause about a property of that name.
///
/// `cut(var_name)` in both rule-definition parsers said that `rule` and a space is a definition. `rule` is a
/// legal property name, so it is not: `var_name` failed on the `==` and the Failure escaped `rules_file`'s
/// alternation before the arm that reads clauses ran. The same clause inside a rule body always parsed,
/// because a definition is not one of the alternatives a block tries.
#[test]
fn a_file_level_clause_whose_first_identifier_is_rule_reads_as_that_clause() -> Result<(), Error> {
    for (spelled, control) in [
        ("rule == \"bar\"", "wibble == \"bar\""),
        ("rule != \"bar\"", "wibble != \"bar\""),
        ("rule > 10", "wibble > 10"),
        ("rule.foo == \"bar\"", "wibble.foo == \"bar\""),
        // A space before the accessor, which `dotted_property` and `predicate_or_index` both allow. These
        // reach the name check as surely as `==` does, and neither can begin a rule name.
        ("rule .foo == \"bar\"", "wibble .foo == \"bar\""),
        ("rule [\"foo\"] == \"bar\"", "wibble [\"foo\"] == \"bar\""),
        ("rule [0] == \"bar\"", "wibble [0] == \"bar\""),
    ] {
        assert_eq!(
            parse_tree_with(spelled, "Key: rule", "Key: IDENT")?,
            parse_tree_with(control, "Key: wibble", "Key: IDENT")?,
            "a clause about a property named rule must read as that clause: {}",
            spelled
        );
    }

    // The commitment moved to the name rather than being dropped, so a name that cannot be one is still an
    // error -- and now says which of the two readings it was trying.
    let rejected = rules_file(from_str2("rule 1x {\n  Resources EXISTS\n}")).expect_err("no name");
    assert!(
        rejected
            .to_string()
            .contains("Expected a name for this rule"),
        "a malformed rule name says so: {}",
        rejected
    );
    Ok(())
}

/// `rule` still defines rules, including one named after a comparator.
///
/// The commitment moved to the name rather than being dropped, so a malformed name is still an error -- and
/// now says what is wrong. A rule named `exists` is the case that would break if the fall-through were
/// decided by looking for a comparator instead of for the name.
#[test]
fn rule_still_defines_a_rule() -> Result<(), Error> {
    let parsed = rules_file(from_str2(
        "rule plain {\n  Resources EXISTS\n}\nrule exists {\n  Resources EXISTS\n}\n\
         rule gated when Resources EXISTS {\n  Resources EXISTS\n}\n\
         rule taking(t) {\n  Resources.*.Type == %t\n}",
    ))?
    .expect("four rule definitions");
    let defined = parsed
        .guard_rules
        .iter()
        .map(|r| r.rule_name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(defined, vec!["plain", "exists", "gated"]);
    assert_eq!(parsed.parameterized_rules[0].rule.rule_name, "taking");
    assert!(parsed.guard_rules[2].conditions.is_some());
    Ok(())
}

/// A clause whose first identifier is `some` reads as a clause about a property of that name.
///
/// `opt(some_keyword)` inside `access` commits: once the word and a space have matched, the rest of the clause
/// is parsed as though the modifier were meant, and what fails afterwards fails for the whole clause. So
/// `some == "bar"` failed inside `access`, where an operator cannot begin a query, and `some exists` failed one
/// step later in `clause_with_map`, where `exists` had been taken as the query and no comparator was left.
/// Neither is ambiguous: the modifier reading of both is a `some` with no clause after it.
#[test]
fn a_clause_whose_first_identifier_is_some_reads_as_that_clause() -> Result<(), Error> {
    for (spelled, keyword, control) in [
        (
            "rule r {\n  some == \"bar\"\n}",
            "some",
            "rule r {\n  wibble == \"bar\"\n}",
        ),
        (
            "rule r {\n  some EXISTS\n}",
            "some",
            "rule r {\n  wibble EXISTS\n}",
        ),
        ("SOME == \"bar\"", "SOME", "wibble == \"bar\""),
        ("some EMPTY", "some", "wibble EMPTY"),
        // A space before the accessor: the modifier matches, the query after it is the accessor, and there is
        // no comparator left. Same shape as `some EXISTS`, one step further along.
        ("some .foo == \"bar\"", "some", "wibble .foo == \"bar\""),
        (
            "some [\"foo\"] == \"bar\"",
            "some",
            "wibble [\"foo\"] == \"bar\"",
        ),
        (
            "rule r when some == \"bar\" {\n  Resources EXISTS\n}",
            "some",
            "rule r when wibble == \"bar\" {\n  Resources EXISTS\n}",
        ),
        (
            "rule r {\n  Resources[ some == \"bar\" ] !EMPTY\n}",
            "some",
            "rule r {\n  Resources[ wibble == \"bar\" ] !EMPTY\n}",
        ),
    ] {
        assert_eq!(
            parse_tree_with(spelled, &format!("Key: {}", keyword), "Key: IDENT")?,
            parse_tree_with(control, "Key: wibble", "Key: IDENT")?,
            "a clause about a property named {} must read as that clause: {}",
            keyword,
            spelled
        );
    }
    Ok(())
}

/// `some` is still the modifier, and a rule named `some` is still a rule reference.
///
/// The fallback clause parser is tried only after the modifier reading fails, and it succeeds only where a
/// comparator follows the name -- which is disjoint from what `rule_clause` reads, a bare name followed by a
/// newline, a comment, `{`, `}` or `or`.
#[test]
fn some_is_still_the_any_modifier() -> Result<(), Error> {
    for rules in [
        "rule r {\n  some Resources.*.Type == \"AWS::S3::Bucket\"\n}",
        "rule r {\n  SOME Resources.*.Type == \"AWS::S3::Bucket\"\n}",
    ] {
        let parsed = rules_file(from_str2(rules))?.expect("a rule with a modified clause");
        let clause = match &parsed.guard_rules[0].block.conjunctions[0][0] {
            RuleClause::Clause(GuardClause::Clause(clause)) => clause,
            other => panic!("expected a plain clause, got {:?} for {}", other, rules),
        };
        assert!(
            !clause.access_clause.query.match_all,
            "the modifier must still turn off match_all: {}",
            rules
        );
    }

    let referenced = rules_file(from_str2(
        "rule some {\n  Resources EXISTS\n}\nrule user {\n  some\n}",
    ))?
    .expect("a rule named some and a reference to it");
    assert!(
        matches!(
            referenced.guard_rules[1].block.conjunctions[0][0],
            RuleClause::Clause(GuardClause::NamedRule(..))
        ),
        "a bare name is still a rule reference"
    );
    Ok(())
}

/// A clause whose first identifier is `let` reads as a clause about a property of that name.
///
/// `var_name` reads the comparator as the variable being assigned, and the `cut` on the assignment sign then
/// made the missing sign unrecoverable. Only the unary comparators were affected: `let == "bar"` fails at
/// `var_name`, which was already recoverable.
#[test]
fn a_clause_whose_first_identifier_is_let_reads_as_that_clause() -> Result<(), Error> {
    for (spelled, control) in [
        ("rule r {\n  let EXISTS\n}", "rule r {\n  wibble EXISTS\n}"),
        ("rule r {\n  let EMPTY\n}", "rule r {\n  wibble EMPTY\n}"),
        (
            "rule r {\n  let IS_STRING\n}",
            "rule r {\n  wibble IS_STRING\n}",
        ),
        ("let exists", "wibble exists"),
    ] {
        assert_eq!(
            parse_tree_with(spelled, "Key: let", "Key: IDENT")?,
            parse_tree_with(control, "Key: wibble", "Key: IDENT")?,
            "a clause about a property named let must read as that clause: {}",
            spelled
        );
    }

    // What the name is decides which reading it is, so an assignment that has lost its sign still says so
    // rather than falling through to be reported as a malformed clause.
    for missing_sign in ["let x", "rule r {\n  let x\n}"] {
        let rejected = rules_file(from_str2(missing_sign)).expect_err("no assignment sign");
        assert!(
            rejected
                .to_string()
                .contains("Expected = or := after let x"),
            "an assignment with no sign says so: {} gave {}",
            missing_sign,
            rejected
        );
    }
    Ok(())
}

/// `let` still declares a variable in both scopes, with either sign.
#[test]
fn let_still_declares_a_variable() -> Result<(), Error> {
    let parsed = rules_file(from_str2(
        "let outer = 5\nrule r {\n  let inner := 7\n  Resources.Size == %outer\n}",
    ))?
    .expect("two assignments");
    assert_eq!(parsed.assignments[0].var, "outer");
    assert_eq!(parsed.guard_rules[0].block.assignments[0].var, "inner");
    Ok(())
}
