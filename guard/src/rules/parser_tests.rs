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

/// What a backslash means inside a string literal, at every position it can appear in.
///
/// The escapes that existed before this were the quote alone, decided by whether the text in front of a
/// quote ended in a backslash. `\\` was read backwards by that test -- as one backslash plus an escaped
/// quote -- so every spelling of a string ending in a backslash was rejected. `\\` resolves to one
/// backslash now, which is the change that makes those spellings mean something, and which changes
/// `"a\\b"` from two backslashes to one.
#[test]
fn test_parse_string_backslash_escapes() {
    for (source, expected) in [
        // The escapes that existed before, unchanged.
        (r"'it\'s'", "it's"),
        (r#""say \"hi\"""#, r#"say "hi""#),
        // A backslash before anything that is not the active delimiter or another backslash is not an
        // escape and stays in the value, so a regex written as a string keeps its own escapes.
        (r#""a\bc""#, r"a\bc"),
        (r#""^arn:(\w+):(\d+)$""#, r"^arn:(\w+):(\d+)$"),
        // Only the quote that opened the literal is escapable; the other one needs no escape and a
        // backslash in front of it is retained.
        (r#""it\'s""#, r"it\'s"),
        (r#"'say \"hi\"'"#, r#"say \"hi\""#),
        // `\\` is one backslash. Each of these was rejected outright before.
        (r"'x\\'", r"x\"),
        (r#""x\\""#, r"x\"),
        (r#""C:\\""#, r"C:\"),
        (r#""x\\\\""#, r"x\\"),
        (r#""a\\b""#, r"a\b"),
        // A `#` in a string is part of the string, not the start of a comment.
        (r"'a # b'", "a # b"),
    ] {
        let cmp = unsafe { Span::new_from_raw_offset(source.len(), 1, "", "") };
        assert_eq!(
            parse_string(from_str2(source)),
            Ok((cmp, Value::String(expected.to_string()))),
            "{source} is the string {expected}"
        );
    }
}

/// A string with no closing quote on its line is an error, and the error says so.
///
/// This is the half of the defect that silently deleted rules. `'x\'` escapes its own closing quote, so
/// the literal had the rest of the file to look through for another one, and it ended at an apostrophe in
/// a comment two lines down. Every clause in between was absorbed into the value -- not evaluated and not
/// reported -- and the run exited 0. Ending the literal at the line ending keeps the mistake where the
/// author made it. `'x\\'` is the spelling that means `x` followed by a backslash.
#[test]
fn test_parse_string_does_not_cross_a_line_ending() {
    let swallow = "'x\\' }\nrule b { Encrypted == true  # don'\n}";
    let result = parse_string(from_str2(swallow));
    assert!(
        result.is_err(),
        "an escaped closing quote leaves the literal unterminated, got {:?}",
        result
    );
    if let Err(nom::Err::Failure(e)) = &result {
        assert!(
            e.context.contains("not terminated"),
            "the error names the problem, got {}",
            e.context
        );
    } else {
        panic!(
            "expected a Failure so the value alternation cannot report someone else's complaint, got {:?}",
            result
        );
    }

    for unterminated in [r"'abc", r"'C:\'", r#""C:\""#, "'abc\n'"] {
        assert!(
            parse_string(from_str2(unterminated)).is_err(),
            "{} is unterminated",
            unterminated
        );
    }
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

    // A pattern the engine cannot compile. The variant is asserted once, because a recoverable error
    // is swallowed by the alternation above `parse_regex` and the message below never reaches the
    // author; the context is then matched by substring so this does not re-break if the variant moves
    // again. Same shape as `a_float_literal_out_of_range_is_rejected`.
    let improperly_escaped_regular_expression =
        "/arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/";
    let err = parse_regex(from_str2(improperly_escaped_regular_expression))
        .expect_err("a pattern the engine cannot compile must not parse");

    assert!(
        matches!(err, nom::Err::Failure(_)),
        "an uncompilable pattern must fail unrecoverably, or `alt` backtracks and reports something else: {:?}",
        err
    );

    let context = match &err {
        nom::Err::Failure(e) | nom::Err::Error(e) => e.context.clone(),
        nom::Err::Incomplete(_) => String::new(),
    };
    assert!(
        context.contains("Could not parse regular expression: ")
            && context.contains("Invalid character class"),
        "the engine's explanation must survive to the author, not merely a rejection: {:?}",
        context
    );

    // The span is the pattern itself, taken after the opening delimiter.
    let span = match &err {
        nom::Err::Failure(e) | nom::Err::Error(e) => e.span,
        nom::Err::Incomplete(_) => unreachable!(),
    };
    assert_eq!(span, unsafe {
        Span::new_from_raw_offset(
            1,
            1,
            "arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/",
            "",
        )
    });

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

/// A range whose lower bound is above its upper admits nothing, so a clause over it cannot fail for
/// any input in one direction and cannot pass for any input in the other. Each of these parsed
/// before, and the span is the literal rather than what follows it.
#[test]
fn test_range_type_rejects_reversed_bounds() {
    for s in ["r[20,10]", "r(20,10)", "r[20,10)", "r(20,10]", "r[-1,-9]"] {
        let err = parse_range(from_str2(s));
        let span = unsafe { Span::new_from_raw_offset(0, 1, s, "") };
        match err {
            Err(nom::Err::Failure(e)) => {
                assert_eq!(e.span, span, "span must be the literal for {}", s);
                assert_eq!(e.kind, ErrorKind::IsNot);
                assert!(
                    e.context.contains("no value can satisfy it"),
                    "{} gave {}",
                    s,
                    e.context
                );
                assert!(e.context.contains("20") || e.context.contains("-1"));
            }
            other => panic!("{} must be a Failure, got {:?}", s, other),
        }
    }

    // The same emptiness through a float and through a char, with the bound named as written.
    for (s, bounds) in [
        ("r[2.0,1.0]", "2.0 is above the upper bound 1.0"),
        ("r[z,a]", "'z' is above the upper bound 'a'"),
    ] {
        match parse_range(from_str2(s)) {
            Err(nom::Err::Failure(e)) => {
                assert!(e.context.contains(bounds), "{} gave {}", s, e.context)
            }
            other => panic!("{} must be a Failure, got {:?}", s, other),
        }
    }
}

/// Equal bounds split on whether the range admits its one value. `r[15,15]` is 15 and is kept; the
/// three spellings that open an end of it admit nothing and go with the reversed ranges.
#[test]
fn test_range_type_equal_bounds() {
    let s = "r[15,15]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    let v = parse_range(from_str2(s));
    assert_eq!(
        v,
        Ok((
            cmp,
            Value::RangeInt(RangeType {
                upper: 15,
                lower: 15,
                inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE
            })
        ))
    );
    let r = match v.unwrap().1 {
        Value::RangeInt(val) => val,
        _ => unreachable!(),
    };
    assert!(15.is_within(&r));
    assert!(!14.is_within(&r));
    assert!(!16.is_within(&r));

    assert!(matches!(
        parse_range(from_str2("r[1.5,1.5]")),
        Ok((_, Value::RangeFloat(_)))
    ));
    assert!(matches!(
        parse_range(from_str2("r[m,m]")),
        Ok((_, Value::RangeChar(_)))
    ));

    for s in ["r(15,15)", "r[15,15)", "r(15,15]"] {
        match parse_range(from_str2(s)) {
            Err(nom::Err::Failure(e)) => assert!(
                e.context.contains("both bounds are 15")
                    && e.context.contains("no value can satisfy it"),
                "{} gave {}",
                s,
                e.context
            ),
            other => panic!("{} must be a Failure, got {:?}", s, other),
        }
    }
}

/// One integer bound and one float bound widen to a float range, which is what the evaluator's
/// `int_within_float_range` and `float_within_int_range` already check either kind of value against.
/// Each of these was a parse error before.
#[test]
fn test_range_type_mixed_numeric_bounds() {
    let s = "r[0,20.5]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_range(from_str2(s)),
        Ok((
            cmp,
            Value::RangeFloat(RangeType {
                upper: 20.5,
                lower: 0.0,
                inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE
            })
        ))
    );

    let s = "r(0.5,20]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_range(from_str2(s)),
        Ok((
            cmp,
            Value::RangeFloat(RangeType {
                upper: 20.0,
                lower: 0.5,
                inclusive: UPPER_INCLUSIVE
            })
        ))
    );

    // Emptiness is still measured after the widening, so a mixed pair cannot smuggle a reversed
    // range through.
    for s in ["r[20.5,0]", "r[20,0.5]"] {
        match parse_range(from_str2(s)) {
            Err(nom::Err::Failure(e)) => assert!(
                e.context.contains("no value can satisfy it"),
                "{} gave {}",
                s,
                e.context
            ),
            other => panic!("{} must be a Failure, got {:?}", s, other),
        }
    }

    // An integer bound above 2^53 does not fit a float exactly, and widening it would move the
    // bound, so it is refused rather than silently shifted.
    let s = "r[9007199254740993,1e300]";
    match parse_range(from_str2(s)) {
        Err(nom::Err::Failure(e)) => assert!(
            e.context.contains("would move the bound"),
            "{} gave {}",
            s,
            e.context
        ),
        other => panic!("{} must be a Failure, got {:?}", s, other),
    }
    // 2^53 itself is exact, and so is any smaller magnitude.
    assert!(matches!(
        parse_range(from_str2("r[9007199254740992,1e300]")),
        Ok((_, Value::RangeFloat(_)))
    ));
    assert!(matches!(
        parse_range(from_str2("r[-9007199254740992,1e300]")),
        Ok((_, Value::RangeFloat(_)))
    ));

    // A pairing that is not two numbers still has no comparison, and the span is the literal rather
    // than what follows it.
    for s in ["r[0,z]", "r[a,2.5]", "r[a,5]"] {
        let span = unsafe { Span::new_from_raw_offset(0, 1, s, "") };
        match parse_range(from_str2(s)) {
            Err(nom::Err::Failure(e)) => {
                assert_eq!(e.span, span, "span must be the literal for {}", s);
                assert!(
                    e.context.contains("not both numbers"),
                    "{} gave {}",
                    s,
                    e.context
                );
            }
            other => panic!("{} must be a Failure, got {:?}", s, other),
        }
    }
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

/// The three ways a literal reaches the end of its line with no unescaped delimiter, each of which
/// `scan_escaped_literal` answers with `None`. A lone backslash is the third: it has nothing to escape
/// and no delimiter follows, so this is the unterminated case rather than the invalid-regex one.
///
/// `Failure` rather than `Error` for the reason on `parse_regex_inner`: the message names the missing
/// delimiter, and a recoverable error means the author is told about a property access instead.
#[test]
fn test_parse_regex_inner_when_regex_is_not_terminated() {
    for invalid in [
        // A backslash with nothing on its line to escape.
        "\\",
        // A line ending before any unescaped delimiter, which is the ordinary forgotten-slash typo.
        "abc\n== 5",
        "abc\r\n",
        // End of input before any unescaped delimiter.
        "abc",
        // An escaped delimiter does not close, so this one runs to the end of input too.
        "abc\\/",
    ] {
        let cmp = unsafe { Span::new_from_raw_offset(invalid.len(), 1, invalid, "") };
        let err =
            parse_regex_inner(cmp).expect_err("an unterminated regular expression must not parse");

        assert!(
            matches!(err, nom::Err::Failure(_)),
            "{:?} must fail unrecoverably, or `alt` backtracks and reports something else: {:?}",
            invalid,
            err
        );

        let context = match &err {
            nom::Err::Failure(e) | nom::Err::Error(e) => e.context.clone(),
            nom::Err::Incomplete(_) => String::new(),
        };
        assert_eq!(
            context, "Could not parse regular expression: no closing / before the end of the line",
            "{:?} must be named as unterminated",
            invalid
        );
    }
}

/// What a backslash means inside a regular expression.
///
/// `\/` stands for a plain `/`; every other backslash reaches the regex engine as written, because the
/// engine has an escape layer of its own. `\\` is the case the old scan got backwards: it read the second
/// backslash as escaping the delimiter behind it, so `/^x\\/` ran past its own closing slash and ended at
/// the next `/` in the file. An escaped slash immediately before the delimiter was rejected for the
/// opposite reason -- the old scan needed a character after the escape and there was none.
#[test]
fn test_parse_regex_backslash_escapes() {
    for (source, expected) in [
        // An escaped delimiter, including at the very end, where these were rejected before.
        (r"/a\//", "a/"),
        (r"/\//", "/"),
        (r"/^\/dev\/ebs-/", "^/dev/ebs-"),
        (r"/\/32/", "/32"),
        // `\\` is two characters to the regex engine, and it closes, so the `/` behind it ends the regex.
        (r"/^x\\/", r"^x\\"),
        // Everything else arrives intact. All three of these are in the AWS rule registry.
        (
            r"/{{resolve\:secretsmanager\:.*}}/",
            r"{{resolve\:secretsmanager\:.*}}",
        ),
        (r"/^\d{12}$/", r"^\d{12}$"),
        (r"/^[a-zA-Z0-9]*:\*$/", r"^[a-zA-Z0-9]*:\*$"),
        // A character class holding a `/` needs the slash escaped, since the scan does not know about
        // classes. This is `advanced_regex_negative_lookbehind_rule.guard`, which was written `\\/` and
        // only parsed because the old scan misread it.
        (
            r"/(?<![A-Za-z0-9\/+=])[A-Za-z0-9\/+=]{40}/",
            "(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}",
        ),
    ] {
        let cmp = unsafe { Span::new_from_raw_offset(source.len(), 1, "", "") };
        assert_eq!(
            parse_regex(from_str2(source)),
            Ok((cmp, Value::Regex(expected.to_string()))),
            "{source} is the regex {expected}"
        );
    }
}

/// A regex stops at its own delimiter instead of reading on to the next one in the file.
///
/// `/^x\\/` followed by a comment containing a URL used to produce one clause where the author wrote two,
/// and the run exited 0 with the second rule absorbed into the regex.
#[test]
fn test_parse_regex_does_not_run_past_its_delimiter() {
    let source = "/^x\\\\/ }\nrule b { Encrypted == true  # see aws/ docs\n}";
    let (rest, value) = parse_regex(from_str2(source)).unwrap();
    assert_eq!(value, Value::Regex(r"^x\\".to_string()));
    assert!(
        rest.fragment().starts_with(" }"),
        "the regex ends at its own slash, leaving {:?}",
        rest.fragment()
    );

    for unterminated in [r"/abc", "/abc\n/"] {
        assert!(
            parse_regex(from_str2(unterminated)).is_err(),
            "{} is unterminated",
            unterminated
        );
    }
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

/// A `let` whose right-hand side reads a name its own scope declares is rejected, and every spelling
/// of it is.
///
/// It used to exhaust the stack and abort the process at exit 134 with a core dump. That is outside
/// the documented exit codes -- 0, 5 and 19 -- so a caller saw neither a pass nor a failure it could
/// report, and nothing in the output said which name was at fault. `resolve_variable` writes its memo
/// after the query it is memoizing completes, so the second visit to the same name finds no
/// in-progress marker and recurses again; both copies of it, root and block, have that shape.
///
/// The last two accepted spellings are the ones that make a depth limit the wrong instrument. An
/// acyclic chain resolves however long it is, so a limit would have to guess a length no legal file
/// exceeds; and `let a = json_parse(%a)` is a cycle at depth one, so no useful limit catches it.
#[test]
fn a_let_defined_in_terms_of_itself_is_rejected() -> Result<(), Error> {
    for rules in [
        // Both scopes, reached through the two copies of `resolve_variable`.
        "let a = %a\nrule r {\n  %a == 1\n}",
        "rule r {\n  let a = %a\n  %a == 1\n}",
        // A ring rather than a self-reference, at two lengths.
        "let a = %b\nlet b = %a\nrule r {\n  %a == 1\n}",
        "let a = %b\nlet b = %c\nlet c = %a\nrule r {\n  %a == 1\n}",
        // The reference does not have to be the whole right-hand side, or even in the first
        // position: a filter clause, an interpolated key and a function argument all resolve
        // through the same scope.
        "let a = Resources.*[ Type == %a ]\nrule r {\n  %a !empty\n}",
        "let a = Resources.Alpha.Properties.Config[ keys == %a ]\nrule r {\n  %a !empty\n}",
        "let a = Resources.%a.Type\nrule r {\n  %a !empty\n}",
        "let a = json_parse(%a)\nrule r {\n  %a !empty\n}",
        // An inner declaration does not reach the outer one of the same name. The block reads its
        // own `variable_queries` before deferring to the parent, so this is a cycle and not a read
        // of the outer `x`, and it aborted like the rest.
        "let x = 1\nrule r {\n  let x = %x\n  %x == 1\n}",
        // A name that is a capture in the same block as well as a `let`. This one exited 0 on a
        // document where the filter captured a key -- `captured` is consulted before
        // `variable_queries`, so the `let` was never resolved -- and aborted at 134 on a document
        // where it captured nothing. Rejected rather than left to the data: the file cannot resolve
        // the name it declares, whichever document it is run against.
        "rule r {\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    let cfg = %cfg\n    Properties.Config[ cfg | Enabled == true ] !empty\n    %cfg != 'nope'\n  }\n}",
    ] {
        assert!(
            rules_file(from_str2(rules)).is_err(),
            "a variable defined in terms of itself must be rejected: {}",
            rules
        );
    }

    // The message names every member of the ring, because either declaration is the one to edit and
    // the author has to see both to choose.
    let ring = rules_file(from_str2("let a = %b\nlet b = %a\nrule r {\n  %a == 1\n}"))
        .expect_err("a ring is rejected")
        .to_string();
    assert!(
        ring.contains("a -> b -> a"),
        "the ring has to be spelled out: {}",
        ring
    );

    let itself = rules_file(from_str2("let a = %a\nrule r {\n  %a == 1\n}"))
        .expect_err("a self-reference is rejected")
        .to_string();
    assert!(
        itself.contains("Variable a is defined in terms of itself"),
        "a one-member cycle names the variable rather than a chain: {}",
        itself
    );

    // An acyclic chain resolves at any length, in either scope. This is the control that separates a
    // cycle check from a recursion depth limit: a limit low enough to catch the cycles above would
    // reject one of these.
    let mut chain = String::from("let a0 = 1\n");
    for step in 1..=12 {
        chain.push_str(&format!("let a{} = %a{}\n", step, step - 1));
    }
    chain.push_str("rule r {\n  Resources.R.Properties.Size == %a12\n}");
    assert!(rules_file(from_str2(&chain))?.is_some(), "{}", chain);
    assert!(rules_file(from_str2(
        "rule r {\n  let b1 = 1\n  let b2 = %b1\n  let b3 = %b2\n  let b4 = %b3\n  Resources.R.Properties.Size == %b4\n}"
    ))?
    .is_some());

    // A name reused in a nested scope is two declarations, not a cycle.
    assert!(rules_file(from_str2(
        "let x = 1\nrule r {\n  let x = 2\n  Resources.R.Properties.Size == %x\n}"
    ))?
    .is_some());

    // A property that happens to be spelled like a declared variable is a key, not a reference to
    // it. Only a leading `%` makes a query part a variable.
    assert!(rules_file(from_str2(
        "let alpha = Resources.Alpha.Properties.Config.alpha.Enabled\nrule r {\n  %alpha == true\n}"
    ))?
    .is_some());

    // A nested block inside a right-hand side is walked, and walking it does not invent a cycle.
    assert!(rules_file(from_str2(
        "let a = Resources.*[ Properties { Size > 0 } ]\nrule r {\n  %a !empty\n}"
    ))?
    .is_some());
    Ok(())
}

/// A rule that references itself is rejected, in both spellings of a reference and at both ends of a
/// ring.
///
/// Every case below aborted the process on a stack overflow at exit 134, outside the documented exit
/// codes -- 0, 5 and 19 -- so a caller saw neither a pass nor a failure it could report; and the abort
/// happens before any finding is written, so the file said nothing about its other rules either.
/// `RootScope::rule_status` writes its memo after `eval_rule` returns, so a reference reaching a rule
/// already in progress finds no marker and evaluates it again -- the same shape as the `let` cycle in
/// `a_let_defined_in_terms_of_itself_is_rejected`, one namespace over.
///
/// Both spellings are asserted here rather than in two tests on purpose. They do not share an
/// evaluation path -- `eval_parameterized_rule_call` calls `eval_rule` directly instead of going
/// through `rule_status` -- so a change that reintroduced the crash in one of them would pass a test
/// covering only the other. The mixed pair is what pins that they are one graph and not two.
///
/// The 12-deep chains are the control that separates a cycle check from a recursion depth limit: an
/// acyclic chain of references resolves at any length, so a limit low enough to catch
/// `rule loop { loop }` -- a cycle at depth one -- would reject every one of them.
#[test]
fn a_rule_that_references_itself_is_rejected() -> Result<(), Error> {
    for rules in [
        // The plain spelling, self and mutual.
        "rule loop {\n  loop\n}\nrule MAIN {\n  loop\n}",
        "rule a {\n  b\n}\nrule b {\n  a\n}\nrule MAIN {\n  a\n}",
        // The parameterized spelling of the same two.
        "rule loop(n) {\n  loop(%n)\n}\nrule MAIN {\n  loop(1)\n}",
        "rule a(n) {\n  b(%n)\n}\nrule b(n) {\n  a(%n)\n}\nrule MAIN {\n  a(1)\n}",
        // A ring closing through one of each. Parameterized rules share the rule namespace, so a
        // cycle does not have to stay in one spelling.
        "rule a {\n  b(\"x\")\n}\nrule b(n) {\n  a\n}\nrule MAIN {\n  a\n}",
        // A rule's own `when` conditions are evaluated by `eval_rule` as its body is, so a reference
        // there recurses the same way.
        "rule a when b {\n  Resources !empty\n}\nrule b {\n  a\n}\nrule MAIN {\n  a\n}",
        // A type block's conditions, one level further in.
        "rule a {\n  AWS::EC2::Volume when b {\n    Encrypted == true\n  }\n}\nrule b {\n  a\n}\nrule MAIN {\n  a\n}",
        // A nested `when` block inside a body. This is the case a depth limit would have had to
        // guess about, because whether it recurses at all is decided by the document.
        "rule a {\n  when Resources !empty {\n    a\n  }\n}\nrule MAIN {\n  a\n}",
        // A negated reference recursed identically; the `not` is applied to the status the recursion
        // never returns.
        "rule a {\n  not a\n}\nrule MAIN {\n  a\n}",
    ] {
        assert!(
            rules_file(from_str2(rules)).is_err(),
            "a rule that references itself must be rejected: {}",
            rules
        );
    }

    // The message names every member of the ring, because either definition is the one to edit.
    let ring = rules_file(from_str2(
        "rule a {\n  b\n}\nrule b {\n  a\n}\nrule MAIN {\n  a\n}",
    ))
    .expect_err("a ring is rejected")
    .to_string();
    assert!(
        ring.contains("a -> b -> a"),
        "the ring has to be spelled out: {}",
        ring
    );

    let itself = rules_file(from_str2("rule loop {\n  loop\n}\nrule MAIN {\n  loop\n}"))
        .expect_err("a self-reference is rejected")
        .to_string();
    assert!(
        itself.contains("Rule loop references itself"),
        "a one-member cycle names the rule rather than a chain: {}",
        itself
    );

    // An acyclic chain of references resolves at any length, in either spelling and in a chain that
    // alternates between them. A depth limit catching the cycles above would reject all three.
    let mut plain = String::from("rule r12 {\n  Resources !empty\n}\n");
    let mut parameterized = String::from("rule p12(n) {\n  Resources !empty\n}\n");
    let mut mixed = String::from("rule m12 {\n  Resources !empty\n}\n");
    for step in (0..12).rev() {
        plain.push_str(&format!("rule r{} {{\n  r{}\n}}\n", step, step + 1));
        parameterized.push_str(&format!("rule p{}(n) {{\n  p{}(%n)\n}}\n", step, step + 1));
        // Even steps take no parameter, odd ones take one, so every edge crosses the two spellings.
        mixed.push_str(&match (step % 2 == 0, (step + 1) % 2 == 0) {
            (true, _) => format!("rule m{} {{\n  m{}(\"x\")\n}}\n", step, step + 1),
            (false, true) => format!("rule m{}(n) {{\n  m{}\n}}\n", step, step + 1),
            (false, false) => format!("rule m{}(n) {{\n  m{}(%n)\n}}\n", step, step + 1),
        });
    }
    plain.push_str("rule MAIN {\n  r0\n}");
    parameterized.push_str("rule MAIN {\n  p0(1)\n}");
    mixed.push_str("rule MAIN {\n  m0\n}");
    for chain in [&plain, &parameterized, &mixed] {
        assert!(rules_file(from_str2(chain))?.is_some(), "{}", chain);
    }

    // A diamond reaches one rule down two paths without a cycle, and the walk marks a completed
    // subtree `Done` rather than treating the second arrival as a ring.
    assert!(rules_file(from_str2(
        "rule leaf {\n  Resources !empty\n}\nrule left {\n  leaf\n}\nrule right {\n  leaf\n}\nrule MAIN {\n  left\n  right\n}"
    ))?
    .is_some());

    // A reference to a rule the file does not declare is not an edge. It stays the undeclared-name
    // path, which reports the missing rule by name and already exits 5.
    assert!(rules_file(from_str2("rule MAIN {\n  nosuchrule\n}"))?.is_some());

    // A clause about a property that happens to be spelled like a rule in the file is a clause, not
    // a reference to that rule.
    assert!(rules_file(from_str2(
        "rule Resources {\n  Resources !empty\n}\nrule MAIN {\n  Resources\n}"
    ))?
    .is_some());
    Ok(())
}

/// A parameterized call is read against the definition it names, and both ways of disagreeing with it
/// are rejected by the parser rather than at evaluation.
///
/// The arity mismatch used to be `Error::IncompatibleError` from `eval_parameterized_rule_call`, which
/// no command classifies, so it propagated to `main` and exited -1 -- `INTERNAL_FAILURE` in
/// `guard/tests/utils.rs` -- for an authoring mistake, while an unknown rule name on the same code path
/// exited 5. Calling a rule that has no parameter list reported that the rule "was not found", with an
/// empty candidate list, three lines under a report listing that same rule as PASS.
///
/// Both are decidable from the text, so both are answered here. The two accepted cases at the end are
/// what keeps this check from taking over the undeclared-name path.
#[test]
fn a_parameterized_call_must_match_the_rule_it_names() -> Result<(), Error> {
    for rules in [
        // More arguments than parameters, and fewer.
        "rule check(t) {\n  Resources !empty\n}\nrule MAIN {\n  check(1, 2)\n}",
        "rule check(t, u) {\n  Resources !empty\n}\nrule MAIN {\n  check(1)\n}",
        // No arguments at all, against a rule that takes one. `call_expr` accepts an empty argument
        // list, so this parses and only the counts say it is wrong.
        "rule check(t) {\n  Resources !empty\n}\nrule MAIN {\n  check()\n}",
        // A rule declared without a parameter list, called as though it had one.
        "rule check {\n  Resources !empty\n}\nrule MAIN {\n  check()\n}",
        "rule check {\n  Resources !empty\n}\nrule MAIN {\n  check(1)\n}",
        // A call site in a `when` condition rather than a body.
        "rule check(t) {\n  Resources !empty\n}\nrule MAIN when check(1, 2) {\n  Resources !empty\n}",
        // A call site inside a rule nothing references. This is the case evaluation could not reach:
        // it exited 0 with nothing said, because the mistake only reported where something ran it.
        "rule check(t) {\n  Resources !empty\n}\nrule unused {\n  check(1, 2)\n}\nrule MAIN {\n  Resources !empty\n}",
    ] {
        assert!(
            rules_file(from_str2(rules)).is_err(),
            "a call that does not match the rule it names must be rejected: {}",
            rules
        );
    }

    // Both counts are named, with the noun agreeing, because the exit code was carrying the whole
    // message before.
    let too_many = rules_file(from_str2(
        "rule check(t) {\n  Resources !empty\n}\nrule MAIN {\n  check(1, 2)\n}",
    ))
    .expect_err("too many arguments is rejected")
    .to_string();
    assert!(
        too_many
            .contains("Rule check is declared with 1 parameter, and a call passes it 2 arguments"),
        "the message names the rule and both counts: {}",
        too_many
    );

    let too_few = rules_file(from_str2(
        "rule check(t, u) {\n  Resources !empty\n}\nrule MAIN {\n  check(1)\n}",
    ))
    .expect_err("too few arguments is rejected")
    .to_string();
    assert!(
        too_few.contains("declared with 2 parameters, and a call passes it 1 argument"),
        "the nouns agree with their counts in both directions: {}",
        too_few
    );

    // The rule exists, so the message must not say it was not found -- that was the old message, and
    // it contradicted a report listing the same rule as PASS.
    let not_parameterized = rules_file(from_str2(
        "rule check {\n  Resources !empty\n}\nrule MAIN {\n  check()\n}",
    ))
    .expect_err("calling a rule with no parameter list is rejected")
    .to_string();
    assert!(
        not_parameterized.contains("Rule check is declared without a parameter list"),
        "the message says what is actually wrong: {}",
        not_parameterized
    );
    assert!(
        !not_parameterized.contains("was not found"),
        "the rule is right there in the file, so nothing may claim it is missing: {}",
        not_parameterized
    );

    // A call to a name the file does not declare at all is left alone. It stays
    // `find_parameterized_rule`'s undeclared-name error, which already reports at exit 5 and which a
    // `when` might never reach; rejecting the file for it here would be a different decision.
    assert!(rules_file(from_str2("rule MAIN {\n  nosuch()\n}"))?.is_some());

    // A call that does match is untouched, at one and at two parameters.
    assert!(rules_file(from_str2(
        "rule check(t) {\n  Resources !empty\n}\nrule MAIN {\n  check(1)\n}"
    ))?
    .is_some());
    assert!(rules_file(from_str2(
        "rule check(t, u) {\n  Resources !empty\n}\nrule MAIN {\n  check(1, 2)\n}"
    ))?
    .is_some());

    // A plain reference to a plain rule is not a call and is not checked against a parameter list.
    assert!(rules_file(from_str2(
        "rule check {\n  Resources !empty\n}\nrule MAIN {\n  check\n}"
    ))?
    .is_some());
    Ok(())
}

/// A parameterized rule cannot be declared with an empty parameter list, and says which spelling to
/// use instead.
///
/// `rule r()` was already rejected, but only because `separated_list1` failed inside `var_name` on the
/// `)`: the diagnostic had an empty "when handling" field and reported the whole remainder of the file
/// as its fragment, so nothing in it said what a parameter list needs.
///
/// Kept illegal rather than admitted for symmetry with the call form, which accepts `r()` because
/// `call_expr` uses `separated_list0`. A rule that takes no parameters already has a spelling, and a
/// second one would not mean the same thing: a rule in `guard_rules` gets a verdict of its own in every
/// report, while a parameterized rule is only evaluated where a clause invokes it. `rule r()` would be
/// a way to write a rule that silently never reports, for no gain over `rule r`.
#[test]
fn a_parameterized_rule_needs_at_least_one_parameter() -> Result<(), Error> {
    for rules in [
        "rule check() {\n  Resources !empty\n}\nrule MAIN {\n  check()\n}",
        // Whitespace inside the parentheses is still an empty list.
        "rule check(  ) {\n  Resources !empty\n}\nrule MAIN {\n  check()\n}",
        "rule check(\n) {\n  Resources !empty\n}\nrule MAIN {\n  check()\n}",
    ] {
        let rejected = rules_file(from_str2(rules))
            .expect_err("an empty parameter list is rejected")
            .to_string();
        assert!(
            rejected.contains("A parameterized rule needs at least one parameter"),
            "the message has to name the spelling that works: {}",
            rejected
        );
    }

    // Dropping the parentheses is the spelling the message points at, and it parses. This is the
    // control that shows the rejection is the empty list and not anything else on the line.
    assert!(rules_file(from_str2(
        "rule check {\n  Resources !empty\n}\nrule MAIN {\n  check\n}"
    ))?
    .is_some());

    // One parameter still parses, so the empty-list check did not consume the list.
    assert!(rules_file(from_str2(
        "rule check(t) {\n  Resources !empty\n}\nrule MAIN {\n  check(1)\n}"
    ))?
    .is_some());

    // A rule name that ends in something the empty-list peek could have misread, and a rule with no
    // parameter list followed by a clause about a property named the same, both still parse.
    assert!(rules_file(from_str2(
        "rule check(t) {\n  Resources.*[ Type == %t ] !empty\n}\nrule MAIN {\n  check(\"AWS::EC2::Volume\")\n}"
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
fn parse_tree_of(rules: &str) -> Result<String, Error> {
    let parsed =
        rules_file(from_str2(rules))?.expect("these rules files all hold at least one rule");
    Ok(serde_yaml::to_string(&parsed).expect("a parsed rules file serialises"))
}

fn parse_tree_with(rules: &str, from: &str, to: &str) -> Result<String, Error> {
    Ok(parse_tree_of(rules)?.replace(from, to))
}

/// A bare CR ends a line in every construct, as it already did in every whitespace position.
///
/// `multispace1` accepts `" \t\r\n"`, so a lone CR was whitespace everywhere -- except in two places that
/// looked for a line ending themselves. `rule_clause` peeked through `newline`, which listed `\n` and `\r\n`
/// and not `\r`, and everything outside that peek set falls to the `cut` on `custom_message`; and `comment2`
/// searched for `\n` alone, so a comment ran to the end of the file. Across 25 constructs written three ways, a
/// CR-only file rejected 6, parsed 1 to *no rules at all*, and read the other 18 as it should. The one that
/// parsed to nothing is the worst of them: a leading comment consumed every rule in the file, and `validate`
/// then reported a violating template compliant at exit 0 with nothing on any channel. The grammar block
/// already said a comment ends at LF or CR.
///
/// This used to compare the three spellings with every line and column blanked out, because `nom_locate`
/// counts lines by `\n` and so reported every clause in a CR-only file at line 1 -- called a property of the
/// position tracking rather than of the parse, and left. It was both: a file that parses correctly and then
/// says every clause is on line 1 is answering a question wrongly. `position_of` counts the endings this
/// parser accepts, so the trees are now compared whole, positions included, and that is the assertion that
/// would fail if the counting were reverted.
#[test]
fn a_bare_carriage_return_ends_a_line_like_the_other_two_spellings() -> Result<(), Error> {
    for body in [
        // the five that a CR-only file could not express, one per mechanism
        "rule a { A == 1 }@rule b {@  a@}@",
        "rule a { A == 1 }@rule b {@  !a@}@",
        "rule a { A == 1 }@rule c { A == 2 }@rule b {@  a or c@}@",
        "rule r {@  Resources exists # trailing@}@",
        "# leading@rule r {@  Resources exists@}@",
        // and shapes that already worked, which must not move
        "rule r {@  Resources exists@}@",
        "rule r {@  when Resources exists {@    A == 1@  }@}@",
        "AWS::S3::Bucket {@  Properties.Encrypted == true@}@",
        "let x = 5@rule r {@  A == %x@}@",
    ] {
        let lf = body.replace('@', "\n");
        let crlf = body.replace('@', "\r\n");
        let cr = body.replace('@', "\r");
        let expected = parse_tree_of(&lf)?;
        assert_eq!(
            parse_tree_of(&cr)?,
            expected,
            "a CR-only file must parse to what the LF spelling parses to, positions included: {}",
            body
        );
        assert_eq!(
            parse_tree_of(&crlf)?,
            expected,
            "and CRLF, which already worked: {}",
            body
        );
    }

    // The one that did not fail loudly, stated on its own. A comment on the first line of a CR-only file
    // swallowed every rule after it, and an empty rules file is not an error -- so the run passed.
    let swallowed =
        "# encryption is mandatory\rrule encrypted {\r  Resources.*.Encrypted == true\r}\r";
    let parsed =
        rules_file(from_str2(swallowed))?.expect("a comment must not consume the rules after it");
    assert_eq!(
        parsed.guard_rules.len(),
        1,
        "the rule after the comment has to survive"
    );

    // A multi-line message keeps its line endings verbatim, which is the one thing that does differ between
    // the spellings and is meant to: the reporter prints the message as written.
    let message = "rule r {\r  Resources exists <<\r  why\r  >>\r}\r";
    assert!(
        parse_tree_of(message)?.contains(r#""\r  why\r  ""#),
        "the message text is verbatim"
    );
    Ok(())
}

/// The negation spellings the parser accepts, which is what the grammar block now says.
///
/// The grammar had `not_keyword 1*SP other_operators` with `not_keyword` including `!`, which admits `! empty`
/// and does not admit `!empty`. `!empty` is the only spelling in use: 82 occurrences across this repository's
/// 95 rules files, 47 across `docs/`, and no occurrence of `!` followed by a space before an operator in
/// either. So the space belongs to the word spellings, where it is what stops `notempty` reading as a negated
/// `empty`, and the grammar was corrected to say so rather than the parser widened to match it. This test is
/// what keeps the two from drifting apart again.
#[test]
fn the_negation_spellings_are_the_ones_the_grammar_claims() -> Result<(), Error> {
    for accepted in [
        "rule r {\n  A !empty\n}",
        "rule r {\n  A !EMPTY\n}",
        "rule r {\n  A !exists\n}",
        "rule r {\n  A !in [1, 2]\n}",
        "rule r {\n  A !IS_LIST\n}",
        "rule r {\n  A not empty\n}",
        "rule r {\n  A NOT empty\n}",
        "rule a { A == 1 }\nrule r {\n  !a\n}",
        "rule a { A == 1 }\nrule r {\n  not a\n}",
    ] {
        assert!(
            rules_file(from_str2(accepted))?.is_some(),
            "accepted: {}",
            accepted
        );
    }

    for rejected in [
        "rule r {\n  A ! empty\n}",
        "rule r {\n  A ! exists\n}",
        "rule r {\n  A ! in [1, 2]\n}",
        "rule a { A == 1 }\nrule r {\n  ! a\n}",
        // and the word spellings still need their space, which is the reason the space is on them
        "rule r {\n  A notempty\n}",
    ] {
        assert!(
            rules_file(from_str2(rejected)).is_err(),
            "rejected: {}",
            rejected
        );
    }
    Ok(())
}

/// A type block needs a space after the type name, which is what the grammar block now says.
///
/// It said `type_name *SP [when] "{"`. The parser requires one space, for the block and the clause form
/// together, and rejects `AWS::S3::Bucket{`. No rules file in this repository or in the AWS rule registry
/// writes it that way and neither does `docs/`, while 16 write the spaced form; and the zero-space clause form
/// cannot be written at all, because `type_name` is greedy over alphanumerics and would absorb the property.
/// So the grammar line was corrected to `1*SP`. The `cut` behind that requirement is what turns a mistake
/// here into an error against the type block rather than a fall-through, and it still does.
#[test]
fn a_type_block_needs_its_space_as_the_grammar_claims() -> Result<(), Error> {
    for accepted in [
        "AWS::S3::Bucket {\n  Properties.Encrypted == true\n}",
        "AWS::S3::Bucket\n{\n  Properties.Encrypted == true\n}",
        "AWS::S3::Bucket   {\n  Properties.Encrypted == true\n}",
        "AWS::S3::Bucket when Properties exists {\n  Properties.Encrypted == true\n}",
        "AWS::S3::Bucket Properties.Encrypted == true",
    ] {
        assert!(
            rules_file(from_str2(accepted))?.is_some(),
            "accepted: {}",
            accepted
        );
    }

    assert!(
        rules_file(from_str2(
            "AWS::S3::Bucket{\n  Properties.Encrypted == true\n}"
        ))
        .is_err(),
        "a type name run straight into the brace is rejected, and the grammar says so"
    );
    Ok(())
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
/// step later in `clause_tail_with_map`, where `exists` had been taken as the query and no comparator was left.
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

/// A function call on the right of `keys` builds a key filter, like the other two right-hand sides.
///
/// `map_keys_match` accepted a value and an access there and not a function call, so `access` matched the
/// function's name as a query, `close_array` -- which carries no `cut` -- failed recoverably on the `(`, and
/// `predicate_filter_clauses` read the same text as an ordinary filter over a child property named `keys`. The
/// clause parsed either way, which is the whole problem: the query part is what changed, and with it what the
/// clause asks. See `a_function_call_on_the_right_of_keys_compares_against_the_keys` in eval_tests for the two
/// verdicts.
#[test]
fn a_function_call_on_the_right_of_keys_is_a_key_filter() -> Result<(), Error> {
    for (spelled, comparator) in [
        (r#"Tags[ keys == to_lower("ALPHA") ]"#, MapKeyComparator::Eq),
        (
            r#"Tags[ keys != to_lower("ALPHA") ]"#,
            MapKeyComparator::NotEq,
        ),
        (r#"Tags[ keys in to_lower("ALPHA") ]"#, MapKeyComparator::In),
        (
            r#"Tags[ keys not in to_lower("ALPHA") ]"#,
            MapKeyComparator::NotIn,
        ),
        (r#"Tags[ keys == count(Resources) ]"#, MapKeyComparator::Eq),
    ] {
        let query = AccessQuery::try_from(spelled)?.query;
        match &query[1] {
            QueryPart::MapKeyFilter(None, clause) => {
                assert_eq!(
                    clause.comparator, comparator,
                    "the comparator a key filter was built with: {}",
                    spelled
                );
                assert!(
                    matches!(clause.compare_with, LetValue::FunctionCall(..)),
                    "a function call on the right must stay a function call: {} gave {:?}",
                    spelled,
                    clause.compare_with
                );
            }
            other => panic!(
                "expected a key filter, got {:?} for {} -- a Filter here is the defect",
                other, spelled
            ),
        }
    }

    // The capture form too, since the name is read before the comparator.
    let captured = AccessQuery::try_from(r#"Tags[ mk | keys == to_lower("ALPHA") ]"#)?.query;
    assert!(
        matches!(&captured[1], QueryPart::MapKeyFilter(Some(name), _) if name == "mk"),
        "the capture name survives: {:?}",
        captured.get(1)
    );
    Ok(())
}

/// `keys` still names a property when the comparator is not one a key filter takes.
///
/// This is the boundary the earlier `keys` fix on this branch drew, and the new alternative sits inside it: the
/// four key-filter comparators are what reserve the word, and `EXISTS` is not one of them. A quoted first
/// token reaches the property reading even for those four.
#[test]
fn keys_is_still_a_property_name_outside_a_key_filter() -> Result<(), Error> {
    for spelled in [
        "Tags[ keys EXISTS ]",
        "Tags[ keys EMPTY ]",
        "Tags[ keys >= 1 ]",
        r#"Tags[ "keys" == to_lower("ALPHA") ]"#,
    ] {
        let query = AccessQuery::try_from(spelled)?.query;
        assert!(
            matches!(query.get(1), Some(QueryPart::Filter(..))),
            "expected an ordinary filter, got {:?} for {}",
            query.get(1),
            spelled
        );
    }

    // And the two right-hand sides that always worked still build a key filter.
    for spelled in [r#"Tags[ keys == "alpha" ]"#, "Tags[ keys not in %denied ]"] {
        let query = AccessQuery::try_from(spelled)?.query;
        assert!(
            matches!(query.get(1), Some(QueryPart::MapKeyFilter(..))),
            "expected a key filter, got {:?} for {}",
            query.get(1),
            spelled
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

/// A name that one scope both assigns and declares as a filter capture is rejected, for the same reason
/// as a name assigned twice there.
///
/// The check above compares assignment names to each other. A filter's capture name is a variable
/// defined in the scope as well -- it is read back as `%name` like any other -- and a name that is both
/// resolved by kind precedence in exactly the way that check refuses to guess at. The scope holds the
/// assignment's value under its kind and the capture's keys in a map of their own, and
/// `resolve_variable` reads the captures after the literals and before the queries, so over a bucket
/// whose enabled config is named `alpha`, in one block:
///
///     let cfg = "fromlet"        + Properties.Config[ cfg | ... ]   ->  %cfg was "fromlet", exit 0
///     let cfg = Properties.Name  + Properties.Config[ cfg | ... ]   ->  %cfg was "alpha",   exit 0
///
/// Both silent, and writing the `let` after the capturing clause changed neither -- so declaration
/// order, the one cue an author would look for, carried nothing.
///
/// The line is lexical: a capture written inside a nested `{ ... }` belongs to that nested scope, so an
/// assignment outside it and a capture inside it are ordinary shadowing and accepted. Drawing the line on
/// where a block's keys land at runtime instead made two files an author cannot tell apart disagree -- a
/// rule-body `let` with a capture in a block inside the rule was refused while the same capture with the
/// `let` moved out to the file level was accepted, and both read as "assignment outside, capture inside".
///
/// A rule's `when` conditions are the one case the text does not settle, since they sit at the rule's
/// head: outside the body's braces, but attached to the rule. Measured rather than reasoned about. With
/// one bucket `Alpha` whose `Properties.Name` is `fromquery`, and the file
///
///     let cfg = <value>
///     rule r when Resources[ cfg | Type == 'AWS::S3::Bucket' ] !EMPTY { %cfg == ... }
///
///     let cfg = "fromlet"                             -> %cfg was "fromlet", the assignment
///     let cfg = Resources.Alpha.Properties.Name       -> %cfg was "Alpha",   the capture
///
/// Each was run in both polarities and the failing one named the value it read, so this is what `%cfg`
/// held rather than a clause that could not fail. The literal winning and the query losing is kind
/// precedence within one scope -- `resolve_variable` reads literals, then captures, then queries -- and
/// two scopes could not produce it, because a more local capture would win against both. So the
/// conditions are the file scope's and this stays rejected.
#[test]
fn a_name_both_assigned_and_captured_in_one_scope_is_rejected() -> Result<(), Error> {
    for rules in [
        // The literal spelling, where the assignment used to win.
        "rule r {\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    let cfg = \"fromlet\"\n    Properties.Config[ cfg | Enabled == true ] !EMPTY\n    some %cfg == \"alpha\"\n  }\n}",
        // The query spelling, where the capture used to win. Same position, opposite winner.
        "rule r {\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    let cfg = Properties.Name\n    Properties.Config[ cfg | Enabled == true ] !EMPTY\n    some %cfg == \"alpha\"\n  }\n}",
        // The assignment written after the capturing clause, which changed nothing.
        "rule r {\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    Properties.Config[ cfg | Enabled == true ] !EMPTY\n    let cfg = \"fromlet\"\n    some %cfg == \"alpha\"\n  }\n}",
        // A capture on a block clause's own query, which is evaluated in the scope the clause is written
        // in rather than inside the braces it opens.
        "rule r {\n  let cfg = \"fromlet\"\n  Resources.*[ cfg | Type == 'AWS::S3::Bucket' ] {\n    Properties.Size > 0\n  }\n}",
        // The file level, against a capture in a rule's `when` condition. See the measurement above.
        "let cfg = \"fromlet\"\nrule r when Resources[ cfg | Type == 'AWS::S3::Bucket' ] !EMPTY {\n  %cfg == \"fromlet\"\n}",
        // One statement doing both.
        "let cfg = Resources[ cfg | Type == 'AWS::S3::Bucket' ]\nrule r {\n  %cfg !EMPTY\n}",
    ] {
        let error = rules_file(from_str2(rules))
            .expect_err("a name both assigned and captured in one scope must be rejected");
        assert!(
            error.to_string().contains("cfg"),
            "the diagnostic has to name the variable, got: {} for {}",
            error,
            rules
        );
    }

    // An assignment outside a block and a capture inside it are shadowing, at either depth, and the
    // depth is what the earlier version of this check got wrong: it accepted the first of these and
    // refused the second. `a_capture_shadows_an_enclosing_assignment_of_the_same_name` asserts which
    // value the block reads.
    for rules in [
        // The assignment at the file level.
        "let cfg = \"fromlet\"\nrule r {\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    Properties.Config[ cfg | Enabled == true ] !EMPTY\n    some %cfg == \"alpha\"\n  }\n}",
        // The same, with the assignment in the rule body instead. Indistinguishable to an author.
        "rule r {\n  let cfg = \"fromlet\"\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    Properties.Config[ cfg | Enabled == true ] !EMPTY\n    some %cfg == \"alpha\"\n  }\n}",
        // No assignment at all.
        "rule r {\n  Resources.*[ Type == 'AWS::S3::Bucket' ] {\n    Properties.Config[ cfg | Enabled == true ] !EMPTY\n    some %cfg == \"alpha\"\n  }\n}",
    ] {
        assert!(
            rules_file(from_str2(rules))?.is_some(),
            "a capture inside a block and a binding outside it are ordinary shadowing: {}",
            rules
        );
    }
    Ok(())
}

/// A thread stack sized for the deepest rules file the bound admits, for the cases below that parse one.
///
/// libtest runs each test on a thread it spawns, which gets Rust's default 2 MB rather than the 8 MB the
/// CLI's `main` has, and 2 MB is not enough in an unoptimized build. Measured on this tree by bisecting
/// `RUST_MIN_STACK` to 64 KB, the most expensive shape -- 128 nested query filters -- needs **3648 KB**
/// under `cargo test` against **927 KB** under `cargo test --release`, a factor of 3.9. So fifteen of the
/// cases here aborted the whole test binary under the plain `cargo test` that CONTRIBUTING.md asks
/// contributors to run and that `.github/workflows/pr.yml` runs on all three platforms.
///
/// That read as one fragile test rather than as the whole family, for two reasons worth recording. The
/// message names a thread, and which one reaches the overflow first varies with scheduling, so separate
/// runs blamed separate cases. And several overflow at once, so their writes interleave: over five runs
/// the name in `thread '...' has overflowed its stack` came out spliced from four test names once and
/// empty twice.
///
/// 16 MB is 4.5x the largest figure measured here and 17x the release one. It is deliberately far above
/// both. These are one toolchain on one platform, per-frame cost is not a portable quantity -- these
/// tests also run on macOS and Windows, neither of which is measured here -- and the cost of
/// over-reserving a test thread's stack is a virtual mapping nothing ever writes to.
const DEEP_PARSE_STACK: usize = 16 * 1024 * 1024;

/// Runs a parse that nests near [`MAX_NESTING_DEPTH`] on a [`DEEP_PARSE_STACK`] thread, so that what the
/// case asserts does not depend on the build profile or on libtest's default stack.
///
/// The bound itself is a count and is already profile-independent, which is what the `NESTING_DEPTH`
/// comment is about; this only gives the recursion room to reach it. A panic inside -- which is what a
/// failed assertion is -- is resumed on the caller, so a genuine failure still reports as this test
/// failing with its own message rather than as a join error.
///
/// The new thread takes the calling test's name so that a panic inside it still prints
/// `thread '<the test>' panicked at`. Without that it prints `thread '<unnamed>'`, which costs the reader
/// the one field that says which case failed -- and this file's cases differ only by their names.
fn on_a_stack_that_reaches_the_bound<T: Send + 'static>(
    parse: impl FnOnce() -> T + Send + 'static,
) -> T {
    let mut builder = std::thread::Builder::new().stack_size(DEEP_PARSE_STACK);
    if let Some(name) = std::thread::current().name() {
        builder = builder.name(name.to_string());
    }

    builder
        .spawn(parse)
        .expect("a thread for a parse that nests to the bound")
        .join()
        .unwrap_or_else(|payload| std::panic::resume_unwind(payload))
}

/// A rules file nested deeper than the parser will read is refused, rather than taken as far as the
/// stack allows.
///
/// The recursive descent recurses once per level and had no bound, so a deep enough file aborted the
/// process: SIGABRT, "fatal runtime error: stack overflow" on stderr, reported as 134 by a shell and
/// outside the exit codes this tool documents. Ten spellings reached it, at depths from 1107 for a query
/// filter up to 8000 for nested list literals, and they share no single function, so each of the six
/// places a level is opened is exercised here -- `block`, `parse_list`, `parse_map`,
/// `predicate_filter_clauses`, `map_keys_match` and `call_expr`.
///
/// The first bound covered the first four spellings only. A query filter, a key filter and a function
/// call each still recursed with nothing counting the levels, so each still aborted: the three cases
/// below at 2000, 2000 and 3000 are the depths that were measured aborting before this was fixed.
///
/// The boundary cases matter more than the extremes. An off-by-one either refuses a file one level
/// inside the documented limit or admits one past it, and neither shows up in the deep cases.
///
/// One boundary is deliberately not asserted: `filters` "exactly the limit". A query filter is also
/// exponential in its depth -- a separate defect, unrelated to the stack -- and 127 nested filters is
/// 2^127 units of backtracking. Measured on this build, a 124-level filter file does not finish inside
/// 60 seconds while the same file at 129 levels is refused in 0.01, because the bound fires during the
/// linear descent and never reaches the backtracking. So the accepted side is asserted at 9 levels,
/// where it takes milliseconds, and the refused side at the boundary and beyond.
///
/// That exclusion is removable, but not on this branch and not by editing this case alone: the
/// backtracking is being fixed separately, and on that fix 127 nested filters parses in 0.038 seconds.
/// Until it merges, raising this case to `MAX_NESTING_DEPTH` does not fail the test, it hangs the suite.
///
/// Every case here parses on a thread sized by [`on_a_stack_that_reaches_the_bound`] rather than on
/// libtest's default 2 MB, because 2 MB does not reach the bound in an unoptimized build. See the note on
/// `NESTING_DEPTH` for the measurements: with the bound raised, the shape that overflows a libtest thread
/// first is the **query** filter, 290 ok and 291 aborting optimized, ahead of the key filter at 315/317 --
/// but the same ladder unoptimized is 67 ok and 68 aborting, which is *below* 128. So "128 is safe with
/// about 2.3x to spare" holds only in release; under plain `cargo test` fifteen of the cases below aborted
/// the whole test binary before that thread was introduced.
///
/// A future raise still breaks these cases by aborting rather than by failing, and now the depth at which
/// that happens is the explicit stack size rather than whatever libtest defaults to.
#[rstest::rstest]
#[case::block_one_inside_the_limit("blocks", MAX_NESTING_DEPTH - 1, true)]
#[case::block_exactly_the_limit("blocks", MAX_NESTING_DEPTH, true)]
#[case::block_one_past_the_limit("blocks", MAX_NESTING_DEPTH + 1, false)]
#[case::block_past_where_it_used_to_abort("blocks", 1700, false)]
#[case::when_block_exactly_the_limit("when_blocks", MAX_NESTING_DEPTH, true)]
#[case::when_block_one_past_the_limit("when_blocks", MAX_NESTING_DEPTH + 1, false)]
#[case::when_block_past_where_it_used_to_abort("when_blocks", 4000, false)]
#[case::list_exactly_the_limit("lists", MAX_NESTING_DEPTH, true)]
#[case::list_one_past_the_limit("lists", MAX_NESTING_DEPTH + 1, false)]
#[case::list_past_where_it_used_to_abort("lists", 8000, false)]
#[case::map_exactly_the_limit("maps", MAX_NESTING_DEPTH, true)]
#[case::map_one_past_the_limit("maps", MAX_NESTING_DEPTH + 1, false)]
#[case::map_past_where_it_used_to_abort("maps", 4000, false)]
#[case::filter_well_inside_the_limit("filters", 9, true)]
// Asserted at the limit like every other shape. It was not, until the exponential
// backtracking in this same integration was fixed: 127 nested filters used to be 2^127 units
// of work and a 124-level file did not finish inside 60 seconds, so the accepted side could
// only be checked far inside the limit. It now parses in 0.05s. This is the shape whose abort
// is nearest the limit, so it is the one whose accepted side most wants asserting there.
#[case::filter_exactly_the_limit("filters", MAX_NESTING_DEPTH, true)]
#[case::filter_one_past_the_limit("filters", MAX_NESTING_DEPTH + 1, false)]
#[case::filter_past_where_it_used_to_abort("filters", 2000, false)]
#[case::key_filter_exactly_the_limit("key_filters", MAX_NESTING_DEPTH, true)]
#[case::key_filter_one_past_the_limit("key_filters", MAX_NESTING_DEPTH + 1, false)]
#[case::key_filter_past_where_it_used_to_abort("key_filters", 2000, false)]
#[case::function_call_exactly_the_limit("function_calls", MAX_NESTING_DEPTH, true)]
#[case::function_call_one_past_the_limit("function_calls", MAX_NESTING_DEPTH + 1, false)]
#[case::function_call_past_where_it_used_to_abort("function_calls", 3000, false)]
fn a_rules_file_nested_past_the_limit_is_refused(
    #[case] shape: &'static str,
    #[case] depth: usize,
    #[case] accepted: bool,
) {
    on_a_stack_that_reaches_the_bound(move || {
        let rules = nested_rules_file(shape, depth);

        let parsed = rules_file(from_str2(&rules));

        if accepted {
            assert!(
                parsed.is_ok(),
                "{shape} nested {depth} levels was refused, but the limit admits up to \
                 {MAX_NESTING_DEPTH}: {:?}",
                parsed.err().map(|e| e.to_string())
            );
        } else {
            let error = parsed
                .expect_err("a file past the limit has to be refused")
                .to_string();
            assert!(
                error.contains("nested at most"),
                "{} nested {} levels was rejected for the wrong reason: {}",
                shape,
                depth,
                error
            );
        }
    });
}

/// The refusal says which limit was passed, where, and at what level, so an author can find the
/// construct rather than bisecting the file. The position is the one the level was opened at.
#[test]
fn the_depth_refusal_names_the_limit_and_the_position() {
    let error = on_a_stack_that_reaches_the_bound(|| {
        let rules = nested_rules_file("blocks", MAX_NESTING_DEPTH + 1);

        rules_file(from_str2(&rules))
            .expect_err("a file one level past the limit is refused")
            .to_string()
    });

    for expected in [
        "nested at most 128 levels deep",
        "is at level 129",
        "the block opened at line",
    ] {
        assert!(
            error.contains(expected),
            "the diagnostic has to contain {:?}, got: {}",
            expected,
            error
        );
    }
}

/// The count of open constructs is restored when a parse fails, so a refused file does not leave the
/// parser primed to refuse the next one.
///
/// The level is opened by an RAII guard and closed by its `Drop`, which is what makes this hold under
/// `nom`'s backtracking as well: an `alt` arm that opens a block and then fails unwinds the scope. A
/// leak would not show up in either half of this on its own -- it needs the legal parse, then the
/// failure, then the same legal parse again.
#[test]
fn a_refused_file_does_not_leave_the_depth_count_raised() -> Result<(), Error> {
    on_a_stack_that_reaches_the_bound(|| {
        let at_the_limit = nested_rules_file("blocks", MAX_NESTING_DEPTH);

        assert!(rules_file(from_str2(&at_the_limit))?.is_some());

        for shape in [
            "blocks",
            "when_blocks",
            "lists",
            "maps",
            "filters",
            "key_filters",
            "function_calls",
        ] {
            assert!(
                rules_file(from_str2(&nested_rules_file(shape, MAX_NESTING_DEPTH + 1))).is_err(),
                "{} past the limit is refused",
                shape
            );
        }

        // A block opened inside an `alt` arm that then fails, so a guard is created and dropped on a
        // backtracking path rather than on a returning one.
        assert!(rules_file(from_str2("rule a {\n  Resources {\n    Type ==\n")).is_err());

        assert!(
            rules_file(from_str2(&at_the_limit))?.is_some(),
            "the same file that parsed before the failures has to parse after them"
        );

        Ok(())
    })
}

/// The control: the bound is on nesting, not on how much of the file is nested. Many shallow blocks are
/// unaffected however many there are, which is what says the quantity being bounded is depth.
#[test]
fn a_wide_but_shallow_rules_file_is_not_affected_by_the_depth_bound() -> Result<(), Error> {
    let mut rules = String::new();
    for i in 0..500 {
        rules.push_str(&format!(
            "rule r{i} {{\n  Resources {{\n    Properties {{\n      Type exists\n    }}\n  }}\n}}\n"
        ));
    }

    assert!(
        rules_file(from_str2(&rules))?.is_some(),
        "500 rules of 4 levels each is 2000 blocks and 4 levels, and 4 is inside the limit"
    );

    Ok(())
}

/// A rules file whose deepest construct sits at `depth` levels, in one of the spellings that recurses.
///
/// Built iteratively on purpose. The generator that produced these fixtures outside the test suite was
/// recursive to begin with and hit Python's own recursion limit long before cfn-guard saw a file deep
/// enough to matter, which is a way to measure the harness rather than the parser.
///
/// The rule body is itself the first level, so `depth` levels means `depth - 1` nested constructs
/// inside it.
fn nested_rules_file(shape: &str, depth: usize) -> String {
    let inner = depth - 1;
    match shape {
        "blocks" => format!(
            "rule a {{\n{}Type exists\n{}}}\n",
            "Resources {\n".repeat(inner),
            "}\n".repeat(inner)
        ),
        "when_blocks" => format!(
            "rule a {{\n{}Type exists\n{}}}\n",
            "when Type == \"x\" {\n".repeat(inner),
            "}\n".repeat(inner)
        ),
        "lists" => format!(
            "rule a {{\n  Type == {}1{}\n}}\n",
            "[".repeat(inner),
            "]".repeat(inner)
        ),
        "maps" => format!(
            "rule a {{\n  Type == {}1{}\n}}\n",
            "{k: ".repeat(inner),
            "}".repeat(inner)
        ),
        // `A[ A[ ... ] exists ]`: a query filter, which recurses `predicate_filter_clauses` ->
        // `cnf_clauses` -> `clause` -> `access` -> `predicate_or_index` -> `predicate_filter_clauses`.
        "filters" => format!(
            "rule a {{\n  {}Type exists{}\n}}\n",
            "A[ ".repeat(inner),
            " ] exists".repeat(inner)
        ),
        // `Tags[ keys == a[ keys == a ] ]`: a key filter, whose right-hand side is a query, so it
        // recurses through `map_keys_match` -> `access` -> `predicate_or_index` -> `map_keys_match`.
        // Linear in the depth, unlike the ordinary filter beside it.
        "key_filters" => format!(
            "rule a {{\n  Tags{}{} exists\n}}\n",
            "[ keys == a".repeat(inner),
            " ]".repeat(inner)
        ),
        // `Type == to_upper(to_upper( ... ))`: a function call, which recurses `function_expr` ->
        // `call_expr` -> `let_value` -> `function_expr`. This is the clause right-hand side spelling; the
        // two other routes into `call_expr` are covered by
        // `the_other_two_routes_to_a_function_call_are_bounded_and_say_so`.
        "function_calls" => format!(
            "rule a {{\n  Type == {}\"x\"{}\n}}\n",
            "to_upper(".repeat(inner),
            ")".repeat(inner)
        ),
        other => unreachable!("no generator for {}", other),
    }
}

/// The two routes into `call_expr` that do not go through a clause right-hand side: a `let` assignment,
/// and an argument to a parameterized rule call.
///
/// The `let` route is here for its message rather than its verdict. `assignment` used to fall through to
/// reading the same text as a property access on *any* error from `function_expr`, a `Failure` included,
/// so a file past the bound was refused -- correctly, at 5 -- by `access` then failing on the `(` with a
/// `ParserError` whose context was the empty string. The verdict was right and the diagnostic named
/// neither the depth nor the construct, which is the half a test on `is_err()` alone would have missed.
#[test]
fn the_other_two_routes_to_a_function_call_are_bounded_and_say_so() {
    on_a_stack_that_reaches_the_bound(|| {
        let open = "to_upper(".repeat(200);
        let close = ")".repeat(200);

        for (route, rules) in [
            (
                "a let assignment",
                format!(
                    "let y = Resources.*.Type\nlet x = {open}%y{close}\nrule a {{\n  Type exists\n}}\n"
                ),
            ),
            (
                "a rule call argument",
                format!("rule b(t) {{ Type == %t }}\nrule a {{\n  b({open}\"x\"{close})\n}}\n"),
            ),
        ] {
            let error = rules_file(from_str2(&rules))
                .expect_err("a call nested past the limit has to be refused")
                .to_string();

            for expected in ["nested at most", "the function call opened at line"] {
                assert!(
                    error.contains(expected),
                    "{} past the limit has to be refused with {:?}, got: {}",
                    route,
                    expected,
                    error
                );
            }
        }
    });
}

/// A block clause's body and a type block's body each carry a rule reference, in two spellings, and a
/// cycle through either is reported.
///
/// This is the pair of `RuleRefs` arms whose doc comment used to call them unreachable -- "their clause
/// parsers take access clauses only" -- and offer that as the reason they recurse rather than being
/// folded into the `Clause(_)` catch-all. The claim was false: both bodies take `block(clause)`, and
/// `clause` admits a nested block clause, a `when_block` and a `parameterized_rule_call_clause`
/// alongside its comparison clauses. Nothing pinned these two positions, so a reader who trusted the
/// comment and deleted the recursion would have found every test still passing.
///
/// The controls are what make the cases non-vacuous. `rule a { Resources { a } }` really is a syntax
/// error, which is the half of the comment that was right, and an `is_err()` assertion cannot tell that
/// apart from a cycle -- so every case here asserts the message.
#[test]
fn a_cycle_through_a_block_clause_or_type_block_body_is_reported() {
    for rules in [
        // The call spelling, directly in each kind of body.
        "rule a(t) {\n  Resources {\n    a(%t)\n  }\n}\nrule MAIN {\n  a(1)\n}",
        "rule a(t) {\n  AWS::EC2::Volume {\n    a(%t)\n  }\n}\nrule MAIN {\n  a(1)\n}",
        // The plain spelling, as the condition of a `when` block nested inside each kind of body. This
        // is the one rj-grammar's report did not have: it concluded only that the call spelling gets
        // there.
        "rule a {\n  Resources {\n    when a {\n      Type exists\n    }\n  }\n}\nrule MAIN {\n  a\n}",
        "rule a {\n  AWS::EC2::Volume {\n    when a {\n      Encrypted == true\n    }\n  }\n}\nrule MAIN {\n  a\n}",
    ] {
        let error = rules_file(from_str2(rules))
            .expect_err("a cycle through a nested body has to be rejected")
            .to_string();
        assert!(
            error.contains("Rule a references itself"),
            "the cycle has to be named rather than the file failing for some other reason: {} \
             for {}",
            error,
            rules
        );
    }

    // The control for the live cases: the same two spellings, naming a different rule, parse. The call
    // spelling has to stay a call here -- `rule a(t) { Resources { b } }` with a bare `b` is a syntax
    // error, which is the half of the old comment that was right, and writing that as the control makes
    // the control fail for the reason the cases exist to distinguish.
    for rules in [
        "rule b(t) { Type == %t }\nrule a(t) {\n  Resources {\n    b(%t)\n  }\n}",
        "rule b { Type exists }\nrule a {\n  Resources {\n    when b {\n      Type exists\n    }\n  }\n}",
    ] {
        assert!(
            rules_file(from_str2(rules)).is_ok(),
            "a reference to another rule from a nested body is not a cycle: {}",
            rules
        );
    }

    // The control for the half of the old comment that was true: the *direct* plain spelling is absent
    // from `clause`, so these are syntax errors and not cycles. Asserted by message, because an
    // `is_err()` here would be satisfied by either outcome.
    for rules in [
        "rule a {\n  Resources {\n    a\n  }\n}",
        "rule a {\n  AWS::EC2::Volume {\n    a\n  }\n}",
    ] {
        let error = rules_file(from_str2(rules))
            .expect_err("a bare rule name is not a clause inside these bodies")
            .to_string();
        assert!(
            !error.contains("references itself"),
            "this one is a syntax error, not a cycle: {} for {}",
            error,
            rules
        );
    }
}

/// A query whose filters nest costs time linear in the depth, not twice as much for each level.
///
/// `clause` reads a block clause and a comparison clause, and both open with an `access`. As separate
/// arms of one alternation each got its own attempt at it: the block reading parsed the whole query,
/// found no `{` where `block` needs one, returned a recoverable error, and the comparison arm parsed the
/// identical text again. A filter inside a query is itself a `clause`, so the two attempts doubled at
/// every level of nesting. `rule a { q[ q[ .. ] exists ] exists }` measured 2.00x per level over nine
/// consecutive levels: 0.06s at twelve levels, 14.5s at twenty, 58s at twenty-two, and about nine hours
/// at thirty, for a file of under 400 bytes. Every depth parsed correctly and exited 0, so nothing was
/// ever reported -- a caller with a timeout saw a timeout and one without saw nothing at all.
///
/// The assertion is a ratio and not a wall-clock bound, so that it states the growth rather than the
/// speed of whichever machine runs it. Both depths are ones the doubling parse could still finish,
/// which is the point of choosing them: a deeper pair would make a reintroduction hang here instead of
/// failing, and a test that hangs reports nothing. Doubling puts the deep depth at 2^8 = 256 times the
/// shallow one and measured 234x. Linear measures 1.4x here -- 112us against 151us per parse -- so the
/// 50x ceiling sits 36x above what passes and 4.7x below what used to fail. Reaching it by noise alone
/// would take a stall that hit one of the two measurements and not the other by a factor of thirty; a
/// machine that is uniformly slower does not move a ratio at all.
#[test]
fn nested_query_filters_cost_time_linear_in_the_depth() {
    const SHALLOW: usize = 13;
    const DEEP: usize = 21;
    const RUNS: u32 = 10;

    fn parse_repeatedly(depth: usize, runs: u32) -> std::time::Duration {
        let rules = nested_rules_file("filters", depth);
        let start = std::time::Instant::now();
        for _ in 0..runs {
            assert!(
                rules_file(from_str2(&rules)).is_ok(),
                "a query with {} nested filters has to parse",
                depth - 1
            );
        }
        start.elapsed()
    }

    let shallow = parse_repeatedly(SHALLOW, RUNS);
    let deep = parse_repeatedly(DEEP, RUNS);
    let ratio = deep.as_secs_f64() / shallow.as_secs_f64();

    assert!(
        ratio < 50.0,
        "{} more levels of filter nesting cost {:.1}x, where a linear parse costs a few times as \
         much: {} levels took {:?} and {} levels took {:?}, over {} runs each. A factor anywhere \
         near 2^{} = {} means every level is being parsed twice again.",
        DEEP - SHALLOW,
        ratio,
        SHALLOW - 1,
        shallow,
        DEEP - 1,
        deep,
        RUNS,
        DEEP - SHALLOW,
        1usize << (DEEP - SHALLOW),
    );
}

/// A rendering with every spelling of a line ending removed, raw and `Debug`-escaped.
///
/// Line endings are what the tests below vary, so the characters themselves have to come out of the
/// comparison: a message body and an error fragment are borrowed slices of the file and keep whatever ending
/// it used, and the reporter prints a message as written. `Debug` escapes them as the two characters `\` and
/// `n`, `Display` leaves them raw, and both spellings show up in these renderings -- so all four forms are
/// removed, and symmetrically. Removing only the CRs would have compared a CR-stripped rendering against an
/// LF-bearing one and failed on every file with a multi-line message.
///
/// Nothing else is removed. Positions, rule names, clause structure, comparators and error text all survive,
/// which is what the comparison is for.
fn without_line_endings(rendered: String) -> String {
    rendered
        .replace("\\r", "")
        .replace("\\n", "")
        .replace(['\r', '\n'], "")
}

/// Rewriting a rules file's line endings must not change what the file means, or where it says anything is.
///
/// This is the invariant, and it is stronger than any of the individual shapes below it. Three things in the
/// parser were counting lines by two different rules. `multispace1`, `comment2` and `newline` treat a lone
/// `\r` as a line ending, so most of the grammar read a bare-CR file as a file with lines. `extract_message`
/// split on `\n` alone, so it read the same file as one line, and one forgotten `>>` therefore swallowed the
/// clause after it -- exit 0 on a template that violated the deleted clause. And `nom_locate`, which every
/// reported line and column used to come from, counts `\n` as well, so every position in a bare-CR file came
/// out as line 1 with the whole-file byte offset for a column.
///
/// Written as a property over a corpus rather than as one assertion per shape, because the per-shape form
/// only catches the sites someone thought to enumerate. There were ten reporting sites plus the message
/// scan, and a test naming the message scan would have passed with all ten broken. The comparison is of the
/// whole `Debug` rendering, so the line and column of every clause is compared too, not just the verdict.
///
/// The comparison is over renderings with the line endings themselves removed, by
/// [`without_line_endings`]: they are what is being varied, and a message body or an error fragment is a
/// borrowed slice of the file and keeps whichever ending the file used.
#[rstest::rstest]
#[case::well_formed_inline_message(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\"\n  Resources.One.Properties.Encrypted == true << must be encrypted >>\n}\n"
)]
#[case::well_formed_block_message(
    "rule one {\n  Resources.One.Properties.Encrypted == true\n  <<\n    Violation: not encrypted\n    Fix: set Encrypted to true\n  >>\n}\n"
)]
#[case::a_comment_carrying_a_closing_tag(
    "rule one {\n  # see the runbook >> for escalation\n  Resources.One.Properties.Encrypted == true\n}\n"
)]
#[case::forgotten_tag_closed_by_the_next_clause(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\" << forgot\n  Resources.One.Properties.Encrypted == true << must be encrypted >>\n}\n"
)]
#[case::forgotten_tag_closed_by_a_comment(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\" << forgot\n  Resources.One.Properties.Encrypted == true\n  # see the runbook for escalation >>\n}\n"
)]
#[case::forgotten_tag_closed_by_a_later_rule(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\" << forgot\n}\nrule two {\n  Resources.One.Properties.Encrypted == true << must be encrypted >>\n}\n"
)]
#[case::a_parse_error_on_line_six(
    "rule one {\n  # a comment\n  Resources.One.Type == \"AWS::S3::Bucket\"\n}\n\nrule two { Resources.One.Properties.Encrypted ==\n}\n"
)]
#[case::a_let_a_when_block_and_a_parameterized_rule(
    "let expected = true\nrule check(want) {\n  when Resources.One.Type == \"AWS::S3::Bucket\" {\n    Resources.One.Properties.Encrypted == %want\n  }\n}\nrule one { check(%expected) }\n"
)]
fn rewriting_line_endings_does_not_change_how_a_rules_file_parses(#[case] lf: &str) {
    assert!(
        lf.contains('\n'),
        "a single-line case has no line endings to rewrite, which would make both halves of this \
         test vacuous: {}",
        lf
    );

    let render = |text: &str| without_line_endings(format!("{:?}", rules_file(from_str2(text))));

    let expected = render(lf);
    assert_eq!(
        render(&lf.replace('\n', "\r\n")),
        expected,
        "CRLF is an ordinary line ending and must parse to exactly what LF parses to, for {}",
        lf
    );
    assert_eq!(
        render(&lf.replace('\n', "\r")),
        expected,
        "a bare CR is a line ending in this parser, so it must parse to what LF parses to -- verdict, \
         clause structure and every reported position -- for {}",
        lf
    );
}

/// One error, one position, whichever line ending the file uses.
///
/// The error below sits physically on line 6, at column 49. LF reported that, and so did CRLF, because
/// `nom_locate` counts the `\n` of a CRLF pair. Bare CR reported *line 1, column 119*, where 119 is the
/// whole-file byte offset: with no `\n` anywhere the file is one line and the column degenerates into the
/// offset. Every position in such a file was wrong the same way, with nothing in the output to say so --
/// "line 1 column 119" is a position, just not this error's.
///
/// Stated separately from the property test rather than left to it, because the property compares two
/// renderings against each other and would also pass if both moved. This one names the position.
#[test]
fn a_parse_error_reports_the_same_line_and_column_under_every_line_ending() {
    let lf = "rule one {\n  # a comment\n  Resources.One.Type == \"AWS::S3::Bucket\"\n}\n\nrule two { Resources.One.Properties.Encrypted ==\n}\n";

    let error_in = |text: &str| {
        without_line_endings(
            rules_file(from_str2(text))
                .expect_err("an incomplete comparison is a parse error")
                .to_string(),
        )
    };

    let lf_error = error_in(lf);
    assert!(
        lf_error.contains("at line 6 at column 49"),
        "the error is on line 6, column 49 of the file: {}",
        lf_error
    );
    assert_eq!(
        error_in(&lf.replace('\n', "\r\n")),
        lf_error,
        "one error must report one position, and CRLF must not move it"
    );
    assert_eq!(
        error_in(&lf.replace('\n', "\r")),
        lf_error,
        "a bare CR ends a line, so the error is still on line 6 -- it used to report line 1 with the \
         whole-file byte offset for a column"
    );
}

/// A forgotten `>>` is refused whatever the file's line endings are.
///
/// The three shapes are the three ways a forgotten `>>` finds a later one: carried by the next clause, by a
/// comment, and by a later rule. All three were refused under LF and CRLF, and all three exited **0 with the
/// following clause deleted** under bare CR -- measured against a template whose `Encrypted` is `false`, so
/// the deleted clause was the one that would have failed. `parse-tree --rules` on the bare-CR file showed one
/// clause where the LF file has two, with the second clause's text sitting inside the first one's
/// `custom_message`.
///
/// The control matters more than usual here, and it is the last case: fixing the scan must not cost the
/// ordinary file, and a message body is the one place where CRs are kept verbatim rather than treated as
/// structure.
#[rstest::rstest]
#[case::forgotten_tag_closed_by_the_next_clause(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\" << forgot\n  Resources.One.Properties.Encrypted == true << must be encrypted >>\n}\n"
)]
#[case::forgotten_tag_closed_by_a_comment(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\" << forgot\n  Resources.One.Properties.Encrypted == true\n  # see the runbook for escalation >>\n}\n"
)]
#[case::forgotten_tag_closed_by_a_later_rule(
    "rule one {\n  Resources.One.Type == \"AWS::S3::Bucket\" << forgot\n}\nrule two {\n  Resources.One.Properties.Encrypted == true << must be encrypted >>\n}\n"
)]
fn a_forgotten_closing_tag_is_refused_under_every_line_ending(#[case] lf: &str) {
    for (spelling, text) in [
        ("LF", lf.to_string()),
        ("CRLF", lf.replace('\n', "\r\n")),
        ("bare CR", lf.replace('\n', "\r")),
    ] {
        let err = rules_file(from_str2(&text))
            .err()
            .map(|err| err.to_string())
            .unwrap_or_else(|| {
                panic!(
                    "an unterminated << must be refused, and under {} it parsed with the clause \
                     after it deleted: {}",
                    spelling, lf
                )
            });
        assert!(
            err.contains("closing >> tag"),
            "the error must name the missing tag under {}: {}",
            spelling,
            err
        );
    }
}

/// The control for the case above: a closed message parses under every spelling, body CRs and all.
#[rstest::rstest]
#[case::inline_message(
    "rule one {\n  Resources.One.Properties.Encrypted == true << must be encrypted >>\n}\n"
)]
#[case::block_message(
    "rule one {\n  Resources.One.Properties.Encrypted == true\n  <<\n    Violation: not encrypted\n  >>\n}\n"
)]
#[case::a_comment_on_its_own_line(
    "rule one {\n  # a comment\n  Resources.One.Properties.Encrypted == true\n}\n"
)]
#[case::a_closing_tag_indented_under_a_comment(
    "rule one {\n  # why this rule exists\n  Resources.One.Properties.Encrypted == true\n    << must be encrypted\n    >>\n}\n"
)]
fn a_closed_message_parses_under_every_line_ending(#[case] lf: &str) -> Result<(), Error> {
    for (spelling, text) in [
        ("LF", lf.to_string()),
        ("CRLF", lf.replace('\n', "\r\n")),
        ("bare CR", lf.replace('\n', "\r")),
    ] {
        assert!(
            rules_file(from_str2(&text))?.is_some(),
            "this file is ordinary and must parse under {}: {}",
            spelling,
            lf
        );
    }
    Ok(())
}

/// The message scan reads a bare CR as a line ending, asserted at the function that failed open.
///
/// The property test covers this through whole files. This one goes at `custom_message` directly, because
/// that is where the defect was and because the parse it exercises is reachable without `rules_file`: a
/// combinator called on a fragment gets no line index, so if this scan ever goes back to `find('\n')` the
/// whole-file test is not the only thing that has to catch it.
///
/// The mechanism, stated so a reader of a failure knows what broke: splitting on `\n` alone turned "the
/// opening line" into the entire remaining file, and `find(">>")` then latched onto the first `>>` anywhere
/// in it -- including one belonging to the next clause.
#[test]
fn the_message_scan_treats_a_bare_carriage_return_as_a_line_ending() {
    let forgotten_tag =
        "<< forgot\rResources.One.Properties.Encrypted == true << must be encrypted >>\r";
    assert!(
        custom_message(from_str2(forgotten_tag)).is_err(),
        "the >> on the next CR-terminated line belongs to that clause and must not close this message"
    );

    let closed_on_its_own_line = "<< Violation: not encrypted\r>>\r";
    assert!(
        custom_message(from_str2(closed_on_its_own_line)).is_ok(),
        "a CR-terminated line whose text is exactly >> is a closing tag, as it would be under LF"
    );
}

/// A map literal that names the same key twice is refused rather than resolved by position.
///
/// `pairs.into_iter().collect::<IndexMap<_, _>>()` keeps the last value silently, so reordering two
/// entries with the same name changed the verdict. Against a template holding `Encrypted: false`:
///
/// ```text
/// Resources.One.Properties == { "Encrypted": true, "Encrypted": false }   ->  exit 0   PASS
/// Resources.One.Properties == { "Encrypted": false, "Encrypted": true }   ->  exit 19  FAIL
/// ```
///
/// This was the only duplicate-name class the rules parser still resolved by guessing. `block` refuses a
/// variable declared twice in a scope, `rules_file` refuses a duplicated rule name and a duplicated
/// file-level variable, and `parameter_names` refuses a repeated parameter, each for this reason and each
/// saying so: the file is rejected rather than guessed at. Rules files are authored, so an ambiguous one
/// is a mistake to report, not an input to accommodate.
///
/// The document side is deliberately different and is not changed here: a duplicated key in a *template*
/// warns and evaluates the last value, because the template is often not the reader's to edit.
#[rstest::rstest]
#[case::quoted_keys(
    "rule r { Resources.One.Properties == { \"Encrypted\": true, \"Encrypted\": false } }\n"
)]
#[case::the_other_order(
    "rule r { Resources.One.Properties == { \"Encrypted\": false, \"Encrypted\": true } }\n"
)]
#[case::bare_keys("rule r { Resources.One.Properties == { Encrypted: true, Encrypted: false } }\n")]
#[case::quoted_beside_bare(
    "rule r { Resources.One.Properties == { \"Encrypted\": true, Encrypted: false } }\n"
)]
#[case::three_entries(
    "rule r { Resources.One.Properties == { A: 1, Encrypted: true, Encrypted: false } }\n"
)]
#[case::inside_a_nested_map(
    "rule r { Resources.One.Properties == { Tags: { Name: \"a\", Name: \"b\" } } }\n"
)]
#[case::in_a_let_assignment("let want = { Encrypted: true, Encrypted: false }\nrule r { Resources.One.Properties == %want }\n")]
fn a_map_literal_with_a_repeated_key_is_refused(#[case] rules: &str) {
    let err = rules_file(from_str2(rules)).expect_err("a repeated map key must not parse");
    let rendered = format!("{}", err);
    assert!(
        rendered.contains("more than once"),
        "the error must name the problem, not merely fail: {}",
        rendered
    );
}

/// The control, so the check above cannot pass by rejecting every literal.
///
/// The list case is the reason this is a control rather than a formality. A repeated *value* in a list is
/// legitimate -- `in [1, 1, 2]` is a set of candidates, and repeats there mean nothing at all -- so a
/// duplicate check written over `Value` rather than over map keys would reject working rules files.
#[rstest::rstest]
#[case::distinct_keys(
    "rule r { Resources.One.Properties == { Encrypted: true, Public: false } }\n"
)]
#[case::keys_sharing_a_prefix("rule r { Resources.One.Properties == { A: 1, AB: 2, ABC: 3 } }\n")]
#[case::the_same_key_in_two_different_maps(
    "rule r { Resources.One.Properties == { Tags: { Name: \"a\" }, Other: { Name: \"b\" } } }\n"
)]
#[case::a_repeated_list_value(
    "rule r { Resources.One.Properties.Encrypted in [true, true, false] }\n"
)]
#[case::a_repeated_value_under_distinct_keys(
    "rule r { Resources.One.Properties == { A: true, B: true } }\n"
)]
fn distinct_map_keys_and_repeated_list_values_still_parse(
    #[case] rules: &str,
) -> Result<(), Error> {
    assert!(
        rules_file(from_str2(rules))?.is_some(),
        "nothing is ambiguous here and it must parse: {}",
        rules
    );
    Ok(())
}
