use super::*;
use std::convert::TryInto;

use crate::rules::values::WithinRange;


use crate::rules::{EvaluationContext, EvaluationType, Status};
use crate::rules::path_value::PathAwareValue;


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
}

#[test]
fn test_embedded_string_parsing() {
    let s = "\"\\\"Hi There\\\"\"";
    let string = parse_string(from_str2(s));
    assert_eq!(string.is_ok(), true);
    assert_eq!(string.unwrap().1, Value::String("\"Hi There\"".to_string()));

    let s = "\"{\\\"hi\\\": \\\"there\\\"}\"";
    let string = parse_string(from_str2(s));
    assert_eq!(string.is_ok(), true);
    let json = r#"{"hi": "there"}"#.to_string();
    if let Value::String(val) = string.unwrap().1 {
        assert_eq!(val, json);
        let json = serde_json::from_str::<serde_json::Value>(&val);
        assert_eq!(json.is_ok(), true);
    }

    let s = "\"Hi \\\"embedded\\\" there\"";
    let string = parse_string(from_str2(s));
    assert_eq!(string.is_ok(), true);
    assert_eq!(string.unwrap().1, Value::String(String::from("Hi \"embedded\" there".to_owned())));
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
    assert_eq!(
        parse_bool(from_str2(s)),
        Ok((cmp.clone(), Value::Bool(true)))
    );
    let s = "true";
    assert_eq!(
        parse_bool(from_str2(s)),
        Ok((cmp.clone(), Value::Bool(true)))
    );
    let s = "False";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_bool(from_str2(s)),
        Ok((cmp.clone(), Value::Bool(false)))
    );
    let s = "false";
    assert_eq!(
        parse_bool(from_str2(s)),
        Ok((cmp, Value::Bool(false)))
    );
    let s = "1234";
    let cmp = unsafe { Span::new_from_raw_offset(0, 1, "1234", "") };
    assert_eq!(
        parse_bool(from_str2(s)),
        Err(nom::Err::Error(
            ParserError { span: cmp, kind: nom::error::ErrorKind::Tag, context: "".to_string() }))
    );
    let s = "true1234";
    let cmp = unsafe { Span::new_from_raw_offset(4, 1, "1234", "") };
    assert_eq!(parse_bool(from_str2(s)), Ok((cmp, Value::Bool(true))));
}

#[test]
fn test_parse_float() {
    let s = "12.0";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_float(from_str2(s)),
        Ok((cmp, Value::Float(12.0)))
    );
    let s = "12e+2";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_float(from_str2(s)),
        Ok((cmp, Value::Float(12e+2)))
    );
    let s = "error";
    let cmp = unsafe { Span::new_from_raw_offset(0, 1, "error", "") };
    assert_eq!(
        parse_float(from_str2(s)),
        Err(nom::Err::Error(
            ParserError { span: cmp, kind: nom::error::ErrorKind::Digit, context: "".to_string() }))
    );
}

#[test]
fn test_parse_regex() {
    let s = "/.*PROD.*/";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_regex(from_str2(s)),
        Ok((cmp, Value::Regex(".*PROD.*".to_string())))
    );

    let s = "/arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/";
    let cmp = unsafe {
        Span::new_from_raw_offset(11, 1, ",.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/", "") };
    assert_eq!(
        parse_regex(from_str2(s)),
        Ok((cmp, Value::Regex("arn:[\\w+=".to_string())))
    );

    let s = "/arn:[\\w+=\\/,.@-]+:[\\w+=\\/,.@-]+:[\\w+=\\/,.@-]*:[0-9]*:[\\w+=,.@-]+(\\/[\\w+=,.@-]+)*/";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        parse_regex(from_str2(s)),
        Ok((cmp, Value::Regex("arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*".to_string())))
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
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((cmp, Value::List(vec![])))
    );
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
            Value::List(vec![Value::String("hi".to_string()), Value::String("there".to_string())])
        ))
    );
    let s = "[1,       \"hi\",\n\n3]";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 3, "", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((
            cmp,
            Value::List(vec![Value::Int(1), Value::String("hi".to_string()), Value::Int(3)])
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
        Err(nom::Err::Error(
            ParserError { span: cmp, kind: nom::error::ErrorKind::Char, context: "".to_string() }))
    );
    let s = "[]]";
    let cmp = unsafe { Span::new_from_raw_offset(2, 1, "]", "") };
    assert_eq!(
        parse_list(from_str2(s)),
        Ok((cmp, Value::List(vec![])))
    )
}

#[test]
fn test_map_key_part() {
    let s = "keyword";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        key_part(from_str2(s)),
        Ok((cmp, "keyword".to_string()))
    );

    let s = r#"'keyword'"#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        key_part(from_str2(s)),
        Ok((cmp, "keyword".to_string()))
    );

    let s = r#""keyword""#;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
    assert_eq!(
        key_part(from_str2(s)),
        Ok((cmp, "keyword".to_string()))
    );

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
    assert_eq!(
        parse_map(from_str2(s)),
        Ok((cmp, Value::Map(map.clone())))
    );
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
    assert_eq!(
        parse_map(from_str2(s)),
        Ok((cmp.clone(), Value::Map(map.clone())))
    );
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
    assert_eq!(map.is_ok(), true);
    let map = if let Ok((_ign, Value::Map(om))) = map { om } else { unreachable!() };
    assert_eq!(map.len(), 14);
    assert_eq!(map.contains_key("aurora"), true);
    assert_eq!(map.get("aurora").unwrap(),
               &Value::List(
                   vec!["audit", "error", "general", "slowquery"].iter().map(|s|
                       Value::String((*s).to_string())).collect::<Vec<Value>>()
               )
    );

    let s = r#"{"IntegrationHttpMethod":"POST","Type":"AWS_PROXY","Uri":"arn:aws:apigateway:${AWS::Region}:lambda:path/2015-03-31/functions/${LambdaWAFBadBotParserFunction.Arn}/invocations"}"#;
    let map = parse_map(from_str2(s));
    assert_eq!(map.is_ok(), true);
    let map = if let Ok((_ign, Value::Map(om))) = map { om } else { unreachable!() };
    assert_eq!(map.len(), 3);
    assert_eq!(map.get("IntegrationHttpMethod").unwrap(), &Value::String("POST".to_string()));
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
    assert_eq!(10.is_within(&r), false);
    assert_eq!(15.is_within(&r), true);
    assert_eq!(20.is_within(&r), false);

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
    assert_eq!(10.is_within(&r), true);
    assert_eq!(15.is_within(&r), true);
    assert_eq!(20.is_within(&r), false);
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
    assert_eq!(10.is_within(&r), true);
    assert_eq!(15.is_within(&r), true);
    assert_eq!(20.is_within(&r), true);
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
        Err(nom::Err::Error(
            ParserError { span: cmp, kind: nom::error::ErrorKind::Char, context: "".to_string() }))
    );
}

//
// test with comments
//
#[test]
fn test_parse_value_with_comments() {
    let s = "1234 # this comment\n";
    let cmp = unsafe { Span::new_from_raw_offset(4, 1, " # this comment\n", "") };
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((cmp, Value::Int(1234i64)))
    );

    let s = "#this is a comment\n1234";
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((cmp, Value::Int(1234i64)))
    );

    let s = r###"

        # this comment is skipped
        # this one too
        [ "value1", # this one is skipped as well
          "value2" ]"###;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 6, "", "") };
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((
            cmp,
            Value::List(vec![Value::String("value1".to_string()), Value::String("value2".to_string())])
        ))
    );

    let s = r###"{
        # this comment is skipped
        # this one as well
        key: # how about this
           "Value"
        }"###;
    let cmp = unsafe { Span::new_from_raw_offset(s.len(), 6, "", "") };
    assert_eq!(
        parse_value(from_str2(s)),
        Ok((
            cmp,
            Value::Map(make_linked_hashmap(vec![("key", Value::String("Value".to_string()))]))
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
            Err(nom::Err::Error(
                ParserError {
                    span: from_str2(""),
                    kind: nom::error::ErrorKind::Char,
                    context: "".to_string(),
                })), // white_space_or_comment
            Ok((from_str2(""), ())), // zero_or_more
            Err(nom::Err::Error(
                ParserError {
                    span: from_str2(""),
                    kind: nom::error::ErrorKind::Char,
                    context: "".to_string(),
                })), // white_space_or_comment
        ],
        [
            Ok((unsafe { Span::new_from_raw_offset(2, 1, "# this is a comment that needs to be discarded\n            ", "") }, ())), // white_space_or_comment, only consumes white-space)
            Ok((unsafe { Span::new_from_raw_offset(examples[1].len(), 2, "", "") }, ())), // consumes everything
            Ok((unsafe { Span::new_from_raw_offset(examples[1].len(), 2, "", "") }, ())), // consumes everything
        ],
        [
            //
            // Offset = 3 * '\n' + (col = 17) - 1 = 19
            //
            Ok((unsafe {
                Span::new_from_raw_offset(19, 4, r###"# all of this must be discarded as well
            "###, "")
            }, ())), // white_space_or_comment, only consumes white-space
            Ok((unsafe { Span::new_from_raw_offset(examples[2].len(), 5, "", "") }, ())), // consumes everything
            Ok((unsafe { Span::new_from_raw_offset(examples[2].len(), 5, "", "") }, ())), // consumes everything
        ],
        [
            Err(nom::Err::Error(
                ParserError {
                    span: from_str2(examples[3]),
                    kind: nom::error::ErrorKind::Char,
                    context: "".to_string(),
                })), // white_space_or_comment
            Ok((from_str2(examples[3]), ())), // zero_or_more
            Err(nom::Err::Error(
                ParserError {
                    span: from_str2(examples[3]),
                    kind: nom::error::ErrorKind::Char,
                    context: "".to_string(),
                })), // white_space_or_comment
        ],
    ];

    for (index, expected) in expectations.iter().enumerate() {
        for (idx, each) in [white_space_or_comment, zero_or_more_ws_or_comment, one_or_more_ws_or_comment].iter().enumerate() {
            let actual = each(from_str2(examples[index]));
            assert_eq!(&actual, &expected[idx]);
        }
    }
}

#[test]
fn test_var_name() {
    let examples = [
        "", // err
        "v", // ok
        "var_10", // ok
        "_v", // error
        "engine_name", // ok
        "rule_name_", // ok
        "var_name # remaining", // ok
        "var name", // Ok, var == "var", remaining = " name"
        "10", // err
    ];

    let expectations = [
        Err(nom::Err::Error(
            ParserError {
                span: from_str2(""),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[1].len(),
                    1,
                    "",
                    "",
                )
            },
            "v".to_string()
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            "var_10".to_string()
        )),
        Err(nom::Err::Error(
            ParserError {
                span: from_str2("_v"),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })), // white_space_or_comment
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            "engine_name".to_string()
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len(),
                    1,
                    "",
                    "",
                )
            },
            "rule_name_".to_string()
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    8,
                    1,
                    " # remaining",
                    "",
                )
            },
            "var_name".to_string()
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    3,
                    1,
                    " name",
                    "",
                )
            },
            "var".to_string()
        )),
        Err(nom::Err::Error(
            ParserError {
                span: from_str2("10"),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),
    ];

    for (idx, text) in examples.iter().enumerate() {
        let span = from_str2(*text);
        let actual = var_name(span);
        assert_eq!(&actual, &expectations[idx]);
    }
}

#[test]
fn test_var_name_access() {
    let examples = [
        "", // Err
        "var", // err
        "%var", // ok
        "%_var", // err
        "%var_10", // ok
        " %var", // err
        "%var # remaining", // ok
        "%var this", // ok
    ];

    let expectations = [
        Err(nom::Err::Error(
            ParserError {
                span: from_str2(""),
                kind: nom::error::ErrorKind::Char,
                context: "".to_string(),
            })), // white_space_or_comment

        Err(nom::Err::Error(
            ParserError {
                span: from_str2("var"),
                kind: nom::error::ErrorKind::Char,
                context: "".to_string(),
            })),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            "var".to_string()
        )),
        Err(nom::Err::Error(
            ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        1,
                        1,
                        "_var",
                        "",
                    )
                },
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            "var_10".to_string()
        )),
        Err(nom::Err::Error(
            ParserError {
                span: from_str2(" %var"),
                kind: nom::error::ErrorKind::Char,
                context: "".to_string(),
            })),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "%var".len(),
                    1,
                    " # remaining",
                    "",
                )
            },
            "var".to_string()
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "%var".len(),
                    1,
                    " this",
                    "",
                )
            },
            "var".to_string()
        )),
    ];

    for (idx, text) in examples.iter().enumerate() {
        let span = from_str2(*text);
        let actual = var_name_access(span);
        assert_eq!(&actual, &expectations[idx]);
    }
}

fn to_query_part(vec: Vec<&str>) -> Vec<QueryPart> {
    to_string_vec(&vec)
}

fn to_string_vec<'loc>(list: &[&str]) -> Vec<QueryPart<'loc>> {
    let mut list = list.iter()
        .map(|part|
            if *part == "*" {
                QueryPart::AllValues(None)
            }
            else {
                QueryPart::Key(String::from(*part))
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
        "", // err
        ".", // err
        ".configuration.engine", // ok,
        ".config.engine.", // ok
        ".config.easy", // ok
        //".%engine_map.%engine", // ok
        ".*.*.port", // ok
        ".port.*.ok", // ok
        ".first. second", // ok, why, as the firs part is valid, the remainder will be ". second"
        " .first.second", // err
        ".first.0.path ", // ok
        ".first.*.path == ", // ok
        ".first.* == ", // ok
    ];

    let expectations = [
        // fold_many1 returns Many1 as the error, many1 appends to error hence only propagates
        // the embedded parser's error
        // "", // err
        Err(nom::Err::Error(
            ParserError {
                span: from_str2(""),
                kind: nom::error::ErrorKind::Many1,
                context: "".to_string(),
            }
        )),

        // ".", // err
        Err(nom::Err::Error(
            ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        0,
                        1,
                        ".",
                        "",
                    )
                },
                kind: nom::error::ErrorKind::Many1, // last one char('*')
                context: "".to_string(),
            }
        )),

        // ".configuration.engine", // ok,
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            to_string_vec(&["configuration", "engine"])
        )),


        // ".config.engine.", // Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[3].len() - 1,
                    1,
                    ".",
                    "",
                )
            },
            to_string_vec(&["config", "engine"])
        )),

        // ".config.easy", // Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            to_string_vec(&["config", "easy"])
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
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len(),
                    1,
                    "",
                    "",
                )
            },
            to_string_vec(&["*", "*", "port"])
        )),

        //".port.*.ok", // ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[6].len(),
                    1,
                    "",
                    "",
                )
            },
            to_string_vec(&["port", "*", "ok"])
        )),

        //".first. second", // Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    ".first".len(),
                    1,
                    ". second",
                    "",
                )
            },
            to_string_vec(&["first"])
        )),

        //" .first.second", // Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[8].len(),
                    1,
                    "",
                    "",
                )
            },
            to_string_vec(&["first", "second"]),
        )),

        //".first.0.path ", // ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[9].len() - 1,
                    1,
                    " ",
                    "",
                )
            },
            vec![
                QueryPart::Key("first".to_string()),
                QueryPart::Index(0),
                QueryPart::Key("path".to_string())
            ]
        )),

        //".first.*.path == ", // ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    ".first.*.path".len(),
                    1,
                    " == ",
                    "",
                )
            },
            to_string_vec(&["first", "*", "path"]),
        )),

        // ".first.* == ", // ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    ".first.*".len(),
                    1,
                    " == ",
                    "",
                )
            },
            to_string_vec(&["first", "*"]),
        )),
    ];

    for (idx, text) in examples.iter().enumerate() {
        let span = from_str2(*text);
        let actual = dotted_access(span);
        println!("#{} Example = {}, Result = {:?}", idx, *text, actual);
        assert_eq!(&actual, &expectations[idx]);
    }
}

#[test]
fn test_access() {
    let examples = [
        "", // 0, err
        ".", // 1, err
        ".engine", // 2 err
        " engine", // 4 err

        // testing property access
        "engine", // 4, ok
        "engine.type", // 5 ok
        "engine.type.*", // 6 ok
        "engine.*.type.port", // 7 ok
        "engine.*.type.%var", // 8 ok
        "engine[0]", // 9 ok
        "engine [0]", // 10 ok engine will be property access part
        "engine.ok.*",// 11 Ok
        "engine.%name.*", // 12 ok

        // testing variable access
        "%engine.type", // 13 ok
        "%engine.*.type[0]", // 14 ok
        "%engine.%type.*", // 15 ok
        "%engine.%type.*.port", // 16 ok
        "%engine.*.", // 17 ok . is remainder

        // matches { 'engine': [{'type': 'cfn', 'position': 1, 'other': 20}, {'type': 'tf', 'position': 2, 'other': 10}] }
        "engine[type == \"cfn\"].port", // 18 Ok

        " %engine", // 18 err
    ];

    let expectations = [
        Err(nom::Err::Error(ParserError { // 0
            span: from_str2(""),
            kind: nom::error::ErrorKind::Char, // change as we use parse_string
            context: "".to_string(),
        })),
        Err(nom::Err::Error(ParserError { // 1
            span: from_str2("."),
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),
        Err(nom::Err::Error(ParserError { // 2
            span: from_str2(".engine"),
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),
        Err(nom::Err::Error(ParserError { // 3
            span: from_str2(" engine"),
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),
        Ok(( // 4
             unsafe {
                 Span::new_from_raw_offset(
                     examples[4].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec![
                 QueryPart::Key("engine".to_string())
             ],  match_all: true }
        )),
        Ok(( // 5
             unsafe {
                 Span::new_from_raw_offset(
                     examples[5].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec! [
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Key("type".to_string()),
             ], match_all: true }
        )),
        Ok(( // 6
             unsafe {
                 Span::new_from_raw_offset(
                     examples[6].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec![
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Key("type".to_string()),
                 QueryPart::AllValues(None),
             ], match_all: true }
        )),
        Ok(( // 7
             unsafe {
                 Span::new_from_raw_offset(
                     examples[7].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec![
                 QueryPart::Key("engine".to_string()),
                 QueryPart::AllValues(None),
                 QueryPart::Key("type".to_string()),
                 QueryPart::Key("port".to_string()),
             ], match_all: true },
        )),
        Ok(( // "engine.*.type.%var", // 8 ok
             unsafe {
                 Span::new_from_raw_offset(
                     examples[8].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec![
                 QueryPart::Key("engine".to_string()),
                 QueryPart::AllValues(None),
                 QueryPart::Key("type".to_string()),
                 QueryPart::Key("%var".to_string())
             ], match_all: true },
        )),
        Ok(( // "engine[0]", // 9 ok
             unsafe {
                 Span::new_from_raw_offset(
                     examples[9].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec![
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Index(0),
             ], match_all: true },
        )),
        Ok(( // 10 "engine [0]", // 10 ok engine will be property access part
             unsafe {
                 Span::new_from_raw_offset(
                     examples[10].len(),
                     1,
                     "",
                     "",
                 )
             },
             AccessQuery{ query: vec![
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Index(0),
             ], match_all: true },
        )),

        // "engine.ok.*",// 11 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[11].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("engine".to_string()),
                QueryPart::Key("ok".to_string()),
                QueryPart::AllValues(None),
            ], match_all: true },
        )),

        // "engine.%name.*", // 12 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[12].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("engine".to_string()),
                QueryPart::Key("%name".to_string()),
                QueryPart::AllValues(None)
            ], match_all: true },
        )),

        // "%engine.type", // 13 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[13].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllIndices(None),
                QueryPart::Key("type".to_string()),
            ], match_all: true },
        )),


        // "%engine.*.type[0]", // 14 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[14].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllIndices(None),
                QueryPart::AllValues(None),
                QueryPart::Key("type".to_string()),
                QueryPart::Index(0),
            ], match_all: true },
        )),


        // "%engine.%type.*", // 15 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[15].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllIndices(None),
                QueryPart::Key("%type".to_string()),
                QueryPart::AllValues(None),
            ], match_all: true },
        )),


        // "%engine.%type.*.port", // 16 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[16].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllIndices(None),
                QueryPart::Key("%type".to_string()),
                QueryPart::AllValues(None),
                QueryPart::Key("port".to_string())
            ], match_all: true },
        )),


        // "%engine.*.", // 17 ok . is remainder
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[17].len() - 1,
                    1,
                    ".",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllIndices(None),
                QueryPart::AllValues(None),
            ], match_all: true },
        )),

        // matches { 'engine': [{'type': 'cfn', 'position': 1, 'other': 20}, {'type': 'tf', 'position': 2, 'other': 10}] }
        // "engine[type==\"cfn\"].port", // 18 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[18].len(),
                    1,
                    "",
                    "",
                )
            },
            AccessQuery{ query: vec![
                QueryPart::Key("engine".to_string()),
                QueryPart::Filter(None, vec![
                    vec![GuardClause::Clause(
                        GuardAccessClause {
                            access_clause: AccessClause {
                                query: AccessQuery{ query: vec![
                                    QueryPart::Key(String::from("type"))
                                ], match_all: true },
                                comparator: (CmpOperator::Eq, false),
                                custom_message: None,
                                compare_with: Some(LetValue::Value(PathAwareValue::try_from(PathAwareValue::try_from(Value::String(String::from("cfn"))).unwrap()).unwrap())),
                                location: FileLocation {
                                    line: 1,
                                    column: "engine[".len() as u32 + 1,
                                    file_name: ""
                                }
                            },
                            negation: false,
                        }),
                    ]
                ]),
                QueryPart::Key(String::from("port")),
            ], match_all: true },
        )),

        // " %engine", // 18 err
        Err(nom::Err::Error(ParserError { // 19
            span: from_str2(" %engine"),
            kind: nom::error::ErrorKind::Char,
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
        "", // 0 err
        " exists", // 1 err

        "exists", // 2 ok
        "not exists", // 3 ok
        "!exists", // 4 ok
        "!EXISTS", // 5 ok

        "notexists", // 6 err

        "in", // 7, ok
        "not in", // 8 ok
        "!in", // 9 ok,

        "EMPTY", // 10 ok,
        "! EMPTY", // 11 err
        "NOT EMPTY", // 12 ok
        "IN [\"t\", \"n\"]", // 13 ok
    ];

    let expectations = [

        // "", // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            context: "".to_string(),
            kind: nom::error::ErrorKind::Tag,
        })),

        // " exists", // 1 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(" exists"),
            context: "".to_string(),
            kind: nom::error::ErrorKind::Tag,
        })),

        // "exists", // 2 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Exists, false),
        )),

        // "not exists", // 3 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[3].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Exists, true),
        )),

        // "!exists", // 4 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Exists, true),
        )),

        // "!EXISTS", // 5 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Exists, true),
        )),


        // "notexists", // 6 err
        Err(nom::Err::Error(
            ParserError {
                span: from_str2(examples[6]),
                //
                // why Tag?, not is optional, this is without space
                // so it discards opt and then tries, in, exists or empty
                // all of them fail with tag
                //
                kind: nom::error::ErrorKind::Tag,
                context: "".to_string(),
            }
        )),

        // "in", // 7, ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[7].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::In, false),
        )),

        // "not in", // 8 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[8].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::In, true),
        )),

        // "!in", // 9 ok,
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[9].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::In, true),
        )),

        // "EMPTY", // 10 ok,
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[10].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Empty, false),
        )),

        // "! EMPTY", // 11 err
        Err(nom::Err::Error(
            ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        1,
                        1,
                        " EMPTY",
                        "",
                    )
                },
                kind: nom::error::ErrorKind::Tag,
                context: "".to_string(),
            }
        )),

        // "NOT EMPTY", // 12 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[12].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Empty, true),
        )),

        // "IN [\"t\", \"n\"]", // 13 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    2,
                    1,
                    " [\"t\", \"n\"]",
                    "",
                )
            },
            (CmpOperator::In, false),
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(*each);
        let result = other_operations(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_keys_keyword() {
    let examples = [
        "", // 0 err
        "[KEYS]", // 1 err
        "[KEYS IN %var]", // 2 Ok
        "[KEYS NOT IN %var]", // 3 Ok
        "[KEYS == /aws:S/]", // 6 Ok
        "[KEYS != 'aws:IsSecure']", // 7 Ok
        "[keys !in %var]", // 8 err after !
        "KEYS IN", // 11 err
        "KEYS ", // 12 err
    ];

    let expectations = [
        // "", // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),

        // "KEYS", // 1 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    "[KEYS".len(),
                    1,
                    "]",
                    "",
                )
            },
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),

        // "KEYS IN", // 2 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            QueryPart::MapKeyFilter(None, MapKeyFilterClause {
                comparator: (CmpOperator::In, false),
                compare_with: LetValue::AccessClause(AccessQuery {
                    match_all: true,
                    query: vec![
                        QueryPart::Key("%var".to_string())
                    ]
                })
            })
        )),

        // "KEYS NOT IN", // 3 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[3].len(),
                    1,
                    "",
                    "",
                )
            },
            QueryPart::MapKeyFilter(None, MapKeyFilterClause {
                comparator: (CmpOperator::In, true),
                compare_with: LetValue::AccessClause(AccessQuery {
                    match_all: true,
                    query: vec![
                        QueryPart::Key("%var".to_string())
                    ]
                })
            })
        )),

        // "[KEYS == /aws:S/]", // 6 Ok
        // "KEYS ==", // 6 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            QueryPart::MapKeyFilter(None, MapKeyFilterClause {
                comparator: (CmpOperator::Eq, false),
                compare_with: LetValue::Value(PathAwareValue::try_from(Value::Regex("aws:S".to_string())).unwrap()),
            })
        )),

        // "[KEYS != 'aws:IsSecure']", // 7 Ok
        // "KEYS !=", // 7 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len(),
                    1,
                    "",
                    "",
                )
            },
            QueryPart::MapKeyFilter(None, MapKeyFilterClause {
                comparator: (CmpOperator::Eq, true),
                compare_with: LetValue::Value(PathAwareValue::try_from(Value::String("aws:IsSecure".to_string())).unwrap()),
            }),
        )),

        // "[keys !in %var]", // 8 err after !
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[6].len(),
                    1,
                    "",
                    "",
                )
            },
            QueryPart::MapKeyFilter(None, MapKeyFilterClause {
                comparator: (CmpOperator::In, true),
                compare_with: LetValue::AccessClause(AccessQuery {
                    match_all: true,
                    query: vec![
                        QueryPart::Key("%var".to_string())
                    ]
                })
            })
        )),

        // " KEYS IN", // 11 err
        Err(nom::Err::Error(ParserError {
            span: from_str2("KEYS IN"),
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),

        // "KEYS ", // 12 err
        Err(nom::Err::Error(ParserError {
            span: from_str2("KEYS "),
            kind: nom::error::ErrorKind::Char,
            context: "".to_string(),
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(*each);
        let result = map_keys_match(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_value_cmp() {
    let examples = [
        "", // err 0
        " >", // err 1,

        ">", // ok, 2
        ">=", // ok, 3
        "<", // ok, 4
        "<= ", // ok, 5
        ">=\n", // ok, 6
        "IN\n", // ok 7
        "!IN\n", // ok 8
    ];

    let expectations = [
        // "", // err 0
        Err(nom::Err::Error(ParserError {
            span: from_str2(examples[0]),
            context: "".to_string(),
            kind: nom::error::ErrorKind::Tag,
        })),

        // " >", // err 1,
        Err(nom::Err::Error(ParserError {
            span: from_str2(examples[1]),
            context: "".to_string(),
            kind: nom::error::ErrorKind::Tag,
        })),


        // ">", // ok, 2
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Gt, false)
        )),

        // ">=", // ok, 3
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[3].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Ge, false)
        )),

        // "<", // ok, 4
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::Lt, false)
        )),

        // "<= ", // ok, 5
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len() - 1,
                    1,
                    " ",
                    "",
                )
            },
            (CmpOperator::Le, false)
        )),

        // ">=\n", // ok, 6
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[6].len() - 1,
                    1,
                    "\n",
                    "",
                )
            },
            (CmpOperator::Ge, false)
        )),

        // "IN\n", // ok 7
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[7].len() - 1,
                    1,
                    "\n",
                    "",
                )
            },
            (CmpOperator::In, false)
        )),

        // "!IN\n", // ok 8
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[8].len() - 1,
                    1,
                    "\n",
                    "",
                )
            },
            (CmpOperator::In, true)
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(*each);
        let result = value_cmp(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_clause_success() {
    let lhs = [
        "configuration.containers.*.image",
        "engine",
    ];

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
        (" ", "#this comment\n")
    ];

    let rhs_dotted: Vec<&str> = rhs.split(".").collect();
    let rhs_dotted = to_string_vec(&rhs_dotted);
    let rhs_access = Some(LetValue::AccessClause(AccessQuery{ query: rhs_dotted, match_all: true }));

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery { query: dotted, match_all: true };
        let _lhs_access =

            testing_access_with_cmp(&separators, &comparators,
                                    *each_lhs, rhs,
                                    || dotted.clone(),
                                    || rhs_access.clone());
    }

    let comparators = [
        ("EXISTS", (CmpOperator::Exists, false)),
        ("!EXISTS", (CmpOperator::Exists, true)),
        ("EMPTY", (CmpOperator::Empty, false)),
        ("NOT EMPTY", (CmpOperator::Empty, true)),
    ];

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery { query: dotted, match_all: true };

        testing_access_with_cmp(&separators, &comparators,
                                *each_lhs, "",
                                || dotted.clone(),
                                || None);
    }

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery { query: dotted, match_all: true };

        testing_access_with_cmp(&separators, &comparators,
                                *each_lhs, " does.not.error", // this will not error,
                                // the fragment you are left with is the one above and
                                // the next clause fetch will error out for either no "OR" or
                                // not newline for "and"
                                || dotted.clone(),
                                || None);
    }


    let lhs = [
        "%engine.port",
        //"%engine.%port",
        "%engine.*.image"
    ];

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let dotted = AccessQuery { query: dotted, match_all: true };

        testing_access_with_cmp(&separators, &comparators,
                                *each_lhs, "",
                                || dotted.clone(),
                                || None);
    }

    let rhs = [
        "\"ami-12344545\"",
        "/ami-12/",
        "[\"ami-12\", \"ami-21\"]",
        "{ bare: 10, 'work': 20, 'other': 12.4 }"
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
            let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
            let dotted = to_string_vec(&dotted);
            let dotted = AccessQuery { query: dotted, match_all: true };

            let rhs_value = PathAwareValue::try_from(parse_value(from_str2(*each_rhs)).unwrap().1).unwrap();
            testing_access_with_cmp(&separators, &comparators,
                                    *each_lhs, *each_rhs,
                                    || dotted.clone(),
                                    || Some(LetValue::Value(rhs_value.clone())));
        }
    }
}

fn testing_access_with_cmp<'loc, A, C>(separators: &[(&str, &str)],
                                       comparators: &[(&str, (CmpOperator, bool))],
                                       lhs: &str,
                                       rhs: &str,
                                       access: A,
                                       cmp_with: C)
    where A: Fn() -> AccessQuery<'loc>,
          C: Fn() -> Option<LetValue<'loc>>
{
    for (lhs_sep, rhs_sep) in separators {
        for (_idx, (each_op, value_cmp)) in comparators.iter().enumerate() {
            let access_pattern = format!("{lhs}{lhs_sep}{op}{rhs_sep}{rhs}",
                                         lhs = lhs, rhs = rhs, op = *each_op, lhs_sep = *lhs_sep, rhs_sep = *rhs_sep);
            println!("Testing Access pattern = {}", access_pattern);
            let span = from_str2(&access_pattern);
            let result = clause(span);
            if result.is_err() {
                let parser_error = &result.unwrap_err();
                let parser_error = match parser_error {
                    nom::Err::Error(p) | nom::Err::Failure(p) => format!("ParserError = {} fragment = {}", p, *p.span.fragment()),
                    nom::Err::Incomplete(_) => "More input needed".to_string(),
                };
                println!("{}", parser_error);
                assert_eq!(false, true);
            } else {
                assert_eq!(result.is_ok(), true);
                let result_clause = match result.unwrap().1 {
                    GuardClause::Clause(clause) => clause,
                    _ => unreachable!()
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
        "resources", // 0 Ok
        "resources.*.type", // 1 Ok
        "resources.*[ type == /AWS::RDS/ ]", // 2 Ok
        r#"resources.*[ type == /AWS::RDS/
                            deletion_policy EXISTS
                            deletion_policy == "RETAIN" ].properties"#, // 3 ok
        r#"resources.*[]"#, // 4 err
        "resources.*[type == /AWS::RDS/", // 4 err

    ];

    let expectations = [
        // "resources", // 0 Ok
        Ok((unsafe { Span::new_from_raw_offset(
            examples[0].len(),
            1,
            "",
            ""
        )},
            AccessQuery{ query: vec![
                QueryPart::Key(examples[0].to_string())
            ], match_all: true },
        )),

        // "resources.*.type", // 1 Ok
        Ok((unsafe { Span::new_from_raw_offset(
            examples[1].len(),
            1,
            "",
            ""
        )},
            AccessQuery{ query: to_query_part(examples[1].split(".").collect()), match_all: true }
        )),

        // "resources.*[ type == /AWS::RDS/ ]", // 2 Ok
        Ok((unsafe { Span::new_from_raw_offset(
            examples[2].len(),
            1,
            "",
            ""
        )},
            AccessQuery{ query: vec![
                QueryPart::Key("resources".to_string()),
                QueryPart::AllValues(None),
                QueryPart::Filter(None, Conjunctions::from([
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(PathAwareValue::try_from(PathAwareValue::try_from(Value::Regex("AWS::RDS".to_string())).unwrap()).unwrap()).unwrap())),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery{ query: vec![QueryPart::Key(String::from("type"))], match_all: true },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 1,
                                        column: "resources.*[ ".len() as u32 + 1,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })
                    ]),
                ]))
            ], match_all: true },
        )),


        // r#"resources.*[ type == /AWS::RDS/
        //                 deletion_policy EXISTS
        //                 deletion_policy == "RETAIN" ].properties"#
        Ok((unsafe { Span::new_from_raw_offset(
            examples[3].len(),
            3,
            "",
            ""
        )},
            AccessQuery{ query: vec![
                QueryPart::Key("resources".to_string()),
                QueryPart::AllValues(None),
                QueryPart::Filter(None, Conjunctions::from([
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(PathAwareValue::try_from(PathAwareValue::try_from(Value::Regex("AWS::RDS".to_string())).unwrap()).unwrap()).unwrap())),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery{ query: vec![QueryPart::Key(String::from("type"))], match_all: true },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 1,
                                        column: "resources.*[ ".len() as u32 + 1,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })
                    ]),
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: None,
                                    comparator: (CmpOperator::Exists, false),
                                    query: AccessQuery{ query: vec![QueryPart::Key(String::from("deletion_policy"))], match_all: true },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 2,
                                        column: 29,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })
                    ]),
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(PathAwareValue::try_from(Value::String("RETAIN".to_string())).unwrap()).unwrap())),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery{ query: vec![QueryPart::Key(String::from("deletion_policy"))], match_all: true },
                                    custom_message: None,
                                    location: FileLocation {
                                        line: 3,
                                        column: 29,
                                        file_name: ""
                                    }
                                },
                                negation: false
                            })
                    ]),
                ])),
                QueryPart::Key("properties".to_string()),
            ], match_all: true }
        )),

        // r#"resources.*[]"#, // 4 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    "resources.*[".len(),
                    1,
                    "]",
                    ""
                )
            },
            context: "There were no clauses present #1@13".to_string(),
            kind: nom::error::ErrorKind::Many1, // for negative number in parse_int_value
        })),

        // "resources.*[type == /AWS::RDS/", // 5 err
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    "resources.*[type == /AWS::RDS/".len(),
                    1,
                    "",
                    ""
                )
            },
            context: "".to_string(),
            kind: nom::error::ErrorKind::Char,
        }))
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Test # {}: {}", idx, *each);
        let span = from_str2(*each);
        let result = access(span);
        println!("Result for Test # {}, {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_clause_failures() {
    let lhs = [
        "configuration.containers.*.image",
        "engine",
    ];

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

//    for each in lhs.iter() {
//        for (op, _) in comparators.iter() {
//            let access_pattern = format!("{lhs}{lhs_sep}{op}{rhs_sep}{rhs}",
//                                         lhs = *each, rhs = rhs, op = *op, lhs_sep = lhs_separator, rhs_sep = rhs_separator);
//            let offset = (*each).len();
//            let fragment = format!("{op}{sep}{rhs}",
//                                   rhs = rhs, op = *op, sep = rhs_separator);
//            let error = Err(nom::Err::Error(ParserError {
//                span: unsafe {
//                    Span::new_from_raw_offset(
//                        offset,
//                        1,
//                        &fragment,
//                        "",
//                    )
//                },
//                kind: nom::error::ErrorKind::Char,
//                context: "expecting one or more WS or comment blocks".to_string(),
//            }));
//            println!("Testing : {}", access_pattern);
//            assert_eq!(clause(super::from_str2(&access_pattern)), error);
//        }
//    }

    //
    // Testing for missing access part
    //
    assert_eq!(Err(nom::Err::Error(ParserError {
        span: from_str2(""),
        kind: nom::error::ErrorKind::Char,
        context: "".to_string(),
    })), clause(from_str2("")));

    //
    // Testing for missing access
    //
    assert_eq!(Err(nom::Err::Error(ParserError {
        span: unsafe {
            Span::new_from_raw_offset(
                1, 1, "> 10", ""
            )
        },
        kind: nom::error::ErrorKind::Char,
        context: "".to_string(),
    })), clause(from_str2(" > 10")));

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
                kind: nom::error::ErrorKind::Char, // this comes off access
                context: r#"expecting either a property access "engine.core" or value like "string" or ["this", "that"]"#.to_string(),
            }));
            assert_eq!(clause(from_str2(&access_pattern)), error);
        }
    }
}

#[test]
fn test_rule_clauses() {
    let examples = [
        "",                             // 0 err
        "secure\n",                     // 1 Ok
        "!secure or !encrypted",        // 2 Ok
        "secure\n\nor\t encrypted",     // 3 Ok
        "let x = 10",                   // 4 err
        "port == 10",                   // 5 err
        "secure <<this is secure ${PARAMETER.MSG}>>", // 6 Ok
        "!secure <<this is not secure ${PARAMETER.MSG}>> or !encrypted", // 7 Ok
    ];

    let expectations = [
        // "",                             // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: nom::error::ErrorKind::Alpha,
            context: "".to_string(),
        })),

        // "secure",                       // 1 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[1].len() - 1,
                    1,
                    "\n",
                    ""
                )
            },
            GuardClause::NamedRule(
                GuardNamedRuleClause {
                    dependent_rule: "secure".to_string(),
                    location: FileLocation { line: 1, column: 1, file_name: "" },
                    negation: false,
                    custom_message: None
                })
        )),

        // "!secure or !encrypted",        // 2 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "!secure".len(),
                    1,
                    " or !encrypted",
                    ""
                )
            },
            GuardClause::NamedRule(
                GuardNamedRuleClause {
                    dependent_rule: "secure".to_string(),
                    location: FileLocation { line: 1, column: 1, file_name: "" },
                    negation: true,
                    custom_message: None
                })
        )),

        // "secure\n\nor\t encrypted",     // 3 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    "secure".len(),
                    1,
                    "\n\nor\t encrypted",
                    ""
                )
            },
            GuardClause::NamedRule(
                GuardNamedRuleClause {
                    dependent_rule: "secure".to_string(),
                    location: FileLocation { line: 1, column: 1, file_name: "" },
                    negation: false,
                    custom_message: None
                })
        )),

        // "let x = 10",                   // 4 err
        Err(nom::Err::Failure(
            ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        "let ".len(),
                        1,
                        "x = 10",
                        ""
                    )
                },
                kind: nom::error::ErrorKind::Tag,
                context: "".to_string(),
            }
        )),

        // "port == 10",                   // 5 err
        Err(nom::Err::Failure(
            ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        "port ".len(),
                        1,
                        "== 10",
                        ""
                    )
                },
                kind: nom::error::ErrorKind::Tag,
                context: "".to_string(),
            }
        )),

        // "secure <<this is secure ${PARAMETER.MSG}>>", // 6 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[6].len(),
                    1,
                    "",
                    "",
                )
            },
            GuardClause::NamedRule(
                GuardNamedRuleClause {
                    dependent_rule: "secure".to_string(),
                    location: FileLocation { line: 1, column: 1, file_name: "" },
                    negation: false,
                    custom_message: Some("this is secure ${PARAMETER.MSG}".to_string()),
                })
        )),

        // "!secure <<this is not secure ${PARAMETER.MSG}>> or !encrypted" // 8 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[7].len() - " or !encrypted".len(),
                    1,
                    " or !encrypted",
                    ""
                )
            },
            GuardClause::NamedRule(
                GuardNamedRuleClause {
                    dependent_rule: "secure".to_string(),
                    location: FileLocation { line: 1, column: 1, file_name: "" },
                    negation: true,
                    custom_message: Some("this is not secure ${PARAMETER.MSG}".to_string()),
                })
        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(*each);
        let result = rule_clause(span);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_clauses() {
    let examples = [
        "", // Ok 0
        "secure\n", // Ok 1
        "!secure << was not secure ${PARAMETER.SECURE_MSG}>>", // Ok 2
        "secure\nconfigurations.containers.*.image == /httpd:2.4/", // Ok 3
        r#"secure or
               !exception

               configurations.containers[*].image == /httpd:2.4/"#, // Ok 4
        r#"secure or
               !exception
               let x = 10"# // Ok 5
    ];

    let expectations = [

        // "", // err 0
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    0,
                    1,
                    "",
                    ""
                )
            },
            context: "There were no clauses present #1@1".to_string(),
            kind: nom::error::ErrorKind::Many1, // for negative number in parse_int_value
        })),

        // "secure\n", // Ok 1
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[1].len() - 1,
                    1,
                    "\n",
                    "",
                )
            },
            vec![
                vec![GuardClause::NamedRule(
                    GuardNamedRuleClause {
                        dependent_rule: "secure".to_string(),
                        location: FileLocation { line: 1, column: 1, file_name: "" },
                        negation: false,
                        custom_message: None,
                    }
                )]
            ]
        )),

        // "!secure << was not secure ${PARAMETER.SECURE_MSG}>>", // Ok 2
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    "",
                )
            },
            vec![
                vec![GuardClause::NamedRule(
                    GuardNamedRuleClause {
                        dependent_rule: "secure".to_string(),
                        location: FileLocation { line: 1, column: 1, file_name: "" },
                        negation: true,
                        custom_message: Some(" was not secure ${PARAMETER.SECURE_MSG}".to_string()),
                    })
                ]
            ]
        )),

        // "secure\nconfigurations.containers.*.image == /httpd:2.4/", // Ok 3
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[3].len(),
                    2,
                    "",
                    "",
                )
            },
            vec![
                vec![
                    GuardClause::NamedRule(
                        GuardNamedRuleClause {
                            dependent_rule: "secure".to_string(),
                            location: FileLocation { line: 1, column: 1, file_name: "" },
                            negation: false,
                            custom_message: None,
                        })
                ],
                vec![
                    GuardClause::Clause(
                        GuardAccessClause {
                            access_clause: AccessClause {
                                location: FileLocation {
                                    file_name: "",
                                    column: 1,
                                    line: 2,
                                },
                                compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Regex("httpd:2.4".to_string())).unwrap())),
                                query: AccessQuery{ query: "configurations.containers.*.image".split(".")
                                    .map(|s| if s == "*" { QueryPart::AllValues(None) } else { QueryPart::Key(s.to_string()) }).collect(), match_all: true },
                                custom_message: None,
                                comparator: (CmpOperator::Eq, false),
                            },
                            negation: false,
                        }
                    )
                ],
            ]
        )),

        // r#"secure or
        //    !exception
        //
        //    configurations.containers.*.image == /httpd:2.4/"#, // Ok 4
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    4,
                    "",
                    "",
                )
            },
            vec![
                vec![
                    GuardClause::NamedRule(
                        GuardNamedRuleClause {
                            dependent_rule: "secure".to_string(),
                            location: FileLocation { line: 1, column: 1, file_name: "" },
                            negation: false,
                            custom_message: None,
                        }
                    ),
                    GuardClause::NamedRule(
                        GuardNamedRuleClause {
                            dependent_rule: "exception".to_string(),
                            location: FileLocation { line: 2, column: 16, file_name: "" },
                            negation: true,
                            custom_message: None
                        }
                    )
                ],
                vec![
                    GuardClause::Clause(
                        GuardAccessClause {
                            access_clause: AccessClause {
                                location: FileLocation { file_name: "", column: 16, line: 4 },
                                compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Regex("httpd:2.4".to_string())).unwrap())),
                                query: AccessQuery{ query: "configurations.containers[*].image".split(".").map( |part|
                                    if part.contains('[') {
                                        vec![QueryPart::Key("containers".to_string()), QueryPart::AllIndices(None)]
                                    } else {
                                        vec![QueryPart::Key(part.to_string())]
                                    }
                                ).into_iter().flatten().collect(), match_all: true },
                                custom_message: None,
                                comparator: (CmpOperator::Eq, false),
                            },
                            negation: false,
                        }
                    )
                ],
            ]
        )),

        // r#"secure or
        //    !exception
        //    let x = 10"# // Err, can not handle assignments
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    examples[5].len() - "x = 10".len(),
                    3,
                    "x = 10",
                    "",
                )
            },
            kind: nom::error::ErrorKind::Tag,
            context: "".to_string(),
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Testing #{}, Case = {}", idx, each);
        let span = from_str2(*each);
        let result = clauses(span);
        assert_eq!(&result, &expectations[idx]);
        println!("{:?}", result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_assignments() {
    let examples = [
        "letx",                 // 0 Error
        "let x",                // 1 Failure
        "let x = 10",           // 2 Ok
        "let x = [10, 20]",     // 3 Ok
        "let x = engine",       // 4 Ok
        "let engines = %engines", // 5 Ok
        r#"let ENGINE_LOGS = {
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
}"#,                             // 6 Ok
        "let x =",           // 7 Failure
        "let aurora_dbs = resources.*[ type IN [/AWS::RDS::DBCluster/, /AWS::RDS::GlobalCluster/]]", // 8 Ok
    ];

    let engines: serde_json::Value = serde_json::from_str(
        r#"{
                "postgres":      ["postgresql", "upgrade"],
                "mariadb":       ["audit", "error", "general", "slowquery"],
                "mysql":         ["audit", "error", "general", "slowquery"],
                "oracle-ee":     ["trace", "audit", "alert", "listener"],
                "oracle-se":     ["trace", "audit", "alert", "listener"],
                "oracle-se1":    ["trace", "audit", "alert", "listener"],
                "oracle-se2":    ["trace", "audit", "alert", "listener"],
                "sqlserver-ee":  ["error", "agent"],
                "sqlserver-ex":  ["error"],
                "sqlserver-se":  ["error", "agent"],
                "sqlserver-web": ["error", "agent"],
                "aurora":        ["audit", "error", "general", "slowquery"],
                "aurora-mysql":  ["audit", "error", "general", "slowquery"],
                "aurora-postgresql": ["postgresql", "upgrade"]
            }"#
    ).unwrap();

    let engines: Value = engines.try_into().unwrap();

    let expectations = [
        // "letx",                 // 0 Error
        Err(nom::Err::Error(ParserError {
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
        })),

        // "let x",                // 1 Failure
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    "let x".len(),
                    1,
                    "",
                    ""
                )
            },
            context: "".to_string(),
            kind: nom::error::ErrorKind::Tag, // from "="
        })),

        // "let x = 10",           // 2 Ok
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
        )),

        // "let x = [10, 20]",     // 3 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[3].len(),
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
        )),

        // "let x = engine",       // 4 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
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
        )),

        // "let engines = %engines", // 5 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len(),
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
        )),

        // r#"let ENGINE_LOGS = {
        //     'postgres':      ["postgresql", "upgrade"],
        //     'mariadb':       ["audit", "error", "general", "slowquery"],
        //     'mysql':         ["audit", "error", "general", "slowquery"],
        //     'oracle-ee':     ["trace", "audit", "alert", "listener"],
        //     'oracle-se':     ["trace", "audit", "alert", "listener"],
        //     'oracle-se1':    ["trace", "audit", "alert", "listener"],
        //     'oracle-se2':    ["trace", "audit", "alert", "listener"],
        //     'sqlserver-ee':  ["error", "agent"],
        //     'sqlserver-ex':  ["error"],
        //     'sqlserver-se':  ["error", "agent"],
        //     'sqlserver-web': ["error", "agent"],
        //     'aurora':        ["audit", "error", "general", "slowquery"],
        //     'aurora-mysql':  ["audit", "error", "general", "slowquery"],
        //     'aurora-postgresql': ["postgresql", "upgrade"]
        // }"#,                             // 6 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[6].len(),
                    16,
                    "",
                    ""
                )
            },
            LetExpr {
                var: String::from("ENGINE_LOGS"),
                value: LetValue::Value(PathAwareValue::try_from(engines).unwrap())
            }
        )),

        // "let x =",           // 7 Failure
        Err(nom::Err::Failure(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    examples[7].len(),
                    1,
                    "",
                    ""
                )
            },
            context: "".to_string(),
            kind: nom::error::ErrorKind::Char, // from access with usage of parse_string
        })),

        // "let aurora_dbs = resources.*[ type IN [/AWS::RDS::DBCluster/, /AWS::RDS::GlobalCluster/]]", // 8 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[8].len(),
                    1,
                    "",
                    ""
                )
            },
            LetExpr {
                var: String::from("aurora_dbs"),
                value: LetValue::AccessClause(
                    AccessQuery{ query: vec![
                        QueryPart::Key(String::from("resources")),
                        QueryPart::AllValues(None),
                        QueryPart::Filter(None, Conjunctions::from(
                            [
                                Disjunctions::from([
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

        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Test #{}: {}", idx, *each);
        let span = Span::new_extra(*each, "");
        let result = assignment(span);
        println!("Test #{} Result: {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }
}

#[test]
fn test_type_name() {
    let examples = [
        "AWS::Resource::Type",
        "Custom::Resource",
        "AWS::Module::Type::MODULE",
        "AWS::" // Failure
    ];
    let expectations = [
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[0].len(),
                    1,
                    "",
                    ""
                )
            },
            TypeName{type_name: String::from("AWS::Resource::Type")}
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[1].len(),
                    1,
                    "",
                    ""
                )
            },
            TypeName{type_name: String::from("Custom::Resource")}
        )),
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    1,
                    "",
                    ""
                )
            },
            TypeName{type_name: String::from("AWS::Module::Type")}
        )),
        Err(nom::Err::Error(
            ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        examples[3].len(),
                        1,
                        "",
                        ""
                    )
                },
                kind: nom::error::ErrorKind::Alpha, context: "".to_string()
            }
        ))
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
            }"#
    ];

    let expectations = [
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[0].len(),
                    6,
                    "",
                    ""
                )
            },
            TypeBlock {
                type_name: String::from("AWS::EC2::Instance"),
                conditions: None,
                block: Block {
                    assignments: vec![
                        LetExpr {
                            var: String::from("keyName"),
                            value: LetValue::AccessClause(
                                AccessQuery{ query: vec![
                                    QueryPart::Key(String::from("keyName"))
                                ], match_all: true }
                            )
                        }
                    ],
                    conjunctions: Conjunctions::from([
                        Disjunctions::from([
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery{ query: vec![
                                            QueryPart::Key(String::from("%keyName"))
                                        ], match_all: true },
                                        comparator: (CmpOperator::In, false),
                                        custom_message: None,
                                        compare_with: Some(LetValue::Value(
                                            PathAwareValue::try_from(Value::List(vec![
                                                Value::String(String::from("keyName")),
                                                Value::String(String::from("keyName2")),
                                                Value::String(String::from("keyName3")),
                                            ])).unwrap()
                                        )),
                                        location: FileLocation {
                                            file_name: "",
                                            column: 17,
                                            line: 4,
                                        }
                                    },
                                    negation: false
                                }
                            ),
                        ]),
                        Disjunctions::from([
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery{ query: vec![
                                            QueryPart::Key(String::from("%keyName"))
                                        ], match_all: true },
                                        comparator: (CmpOperator::In, true),
                                        custom_message: None,
                                        compare_with: Some(LetValue::Value(
                                            PathAwareValue::try_from(Value::List(vec![
                                                Value::String(String::from("keyNameIs")),
                                                Value::String(String::from("notInthis")),
                                            ])).unwrap()
                                        )),
                                        location: FileLocation {
                                            file_name: "",
                                            column: 17,
                                            line: 5,
                                        }
                                    },
                                    negation: false
                                }
                            ),

                        ]),
                    ])
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
                                        column: 1,
                                        line: 1,
                                        file_name: ""
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::EC2::Instance".to_string())))),
                                    comparator: (CmpOperator::Eq, false)
                                }
                            })
                        ])
                    ]))
                ]

            }
        )),

        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[1].len(),
                    1,
                    "",
                    ""
                )
            },
            TypeBlock {
                type_name: String::from("AWS::EC2::Instance"),
                conditions: None,
                block: Block {
                    assignments: vec![],
                    conjunctions: vec![
                        vec![
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery{ query: vec![
                                            QueryPart::Key(String::from("keyName")),
                                        ], match_all: true },
                                        comparator: (CmpOperator::Eq, false),
                                        location: FileLocation {
                                            file_name: "",
                                            column: ("AWS::EC2::Instance ".len() + 1) as u32,
                                            line: 1
                                        },
                                        compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Regex("EC2_KEY".to_string())).unwrap())),
                                        custom_message: None
                                    },
                                    negation: false,
                                }
                            ),
                        ]
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
                                        column: 1,
                                        line: 1,
                                        file_name: ""
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::EC2::Instance".to_string())))),
                                    comparator: (CmpOperator::Eq, false)
                                }
                            })
                        ])
                    ]))
                ]
            }
        )),

        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[2].len(),
                    3,
                    "",
                    ""
                )
            },
            TypeBlock {
                type_name: String::from("AWS::EC2::Instance"),
                conditions: Some(vec![
                    vec![
                        WhenGuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    query: AccessQuery{ query: vec![
                                        QueryPart::Key(String::from("instance_type")),
                                    ], match_all: true },
                                    comparator: (CmpOperator::Eq, false),
                                    location: FileLocation {
                                        file_name: "",
                                        column: 25,
                                        line: 1
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::String(String::from("m4.xlarge"))).unwrap())),
                                    custom_message: None
                                },
                                negation: false
                            }
                        ),
                    ]]),
                block: Block {
                    assignments: vec![],
                    conjunctions: vec![
                        vec![
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery{ query: vec![
                                            QueryPart::Key(String::from("security_groups")),
                                        ], match_all: true },
                                        comparator: (CmpOperator::Exists, false),
                                        location: FileLocation {
                                            file_name: "",
                                            column: 17,
                                            line: 2
                                        },
                                        compare_with: None,
                                        custom_message: None
                                    },
                                    negation: false
                                }
                            ),
                        ]]
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
                                        column: 1,
                                        line: 1,
                                        file_name: ""
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::EC2::Instance".to_string())))),
                                    comparator: (CmpOperator::Eq, false)
                                }
                            })
                        ])
                    ]))
                ]

            }

        )),
    ];

    for (idx, each) in examples.iter().enumerate() {
        println!("Test #{}: {}", idx, *each);
        let span = from_str2(*each);
        let result = type_block(span);
        println!("Result #{} = {:?}", idx, result);
        assert_eq!(&result, &expectations[idx]);
    }

}

#[test]
fn test_rule_block() {
    let examples = [
        r#"rule example_rule when stage == 'prod' {
    let ec2_instance_types := [/^t*/, /^m*/]   # scoped variable assignments

    # clause can referene another rule for composition
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
          %volumes.*.Ebs.encrypted == true               # Ebs volume must be encryped
          %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
    } or
    AWS::EC2::Instance {                   # OR a regular volume (disjunction)
        block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
    }
}"#
    ];

    let type_name = "AWS::EC2::Instance";

    let expectations = [
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[0].len(),
                    24,
                    "",
                    ""
                )
            },
            Rule {
                rule_name: String::from("example_rule"),
                conditions: Some(Conjunctions::from([
                    Disjunctions::from([
                        WhenGuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause{
                                    custom_message: None,
                                    query: AccessQuery{ query: vec![
                                        QueryPart::Key("stage".to_string())
                                    ], match_all: true },
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::String("prod".to_string())).unwrap())),
                                    location: FileLocation {
                                        file_name: "",
                                        line: 1,
                                        column: "rule example_rule when ".len() as u32 + 1,
                                    },
                                    comparator: (CmpOperator::Eq, false)
                                },
                                negation: false
                            }
                        )
                    ])])),
                block: Block {
                    assignments: vec![
                        LetExpr {
                            var: String::from("ec2_instance_types"),
                            value: LetValue::Value(
                                PathAwareValue::try_from( Value::List(vec![
                                    Value::Regex("^t*".to_string()),
                                    Value::Regex("^m*".to_string())
                                ])).unwrap()
                            )
                        }
                    ],
                    conjunctions: Conjunctions::from([
                        Disjunctions::from([
                            RuleClause::Clause(GuardClause::NamedRule(
                                GuardNamedRuleClause {
                                    dependent_rule: String::from("dependent_rule"),
                                    location: FileLocation {
                                        file_name: "",
                                        line: 5,
                                        column: 5
                                    },
                                    negation: false,
                                    custom_message: None,
                                }
                            ))
                        ]),
                        Disjunctions::from([
                            RuleClause::TypeBlock(TypeBlock {
                                type_name: type_name.to_string(),
                                conditions: None,
                                block: Block {
                                    assignments: vec![],
                                    conjunctions: Conjunctions::from([
                                        Disjunctions::from([
                                            GuardClause::Clause(
                                                GuardAccessClause {
                                                    access_clause: AccessClause {
                                                        custom_message: None,
                                                        query: AccessQuery{ query: vec![
                                                            QueryPart::Key("InstanceType".to_string())
                                                        ], match_all: true },
                                                        compare_with: Some(LetValue::AccessClause(AccessQuery{ query: vec![
                                                            QueryPart::Key("%ec2_instance_types".to_string())
                                                        ], match_all: true })),
                                                        location: FileLocation {
                                                            file_name: "",
                                                            line: 8,
                                                            column: 24,
                                                        },
                                                        comparator: (CmpOperator::In, false)
                                                    },
                                                    negation: false
                                                }
                                            )
                                        ])
                                    ])
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
                                                        line: 8,
                                                        file_name: ""
                                                    },
                                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::EC2::Instance".to_string())))),
                                                    comparator: (CmpOperator::Eq, false)
                                                }
                                            })
                                        ])
                                    ]))
                                ]

                            })
                        ]),
                        Disjunctions::from([
                            RuleClause::TypeBlock(TypeBlock {
                                type_name: type_name.to_string(),
                                conditions: None,
                                block: Block {
                                    assignments: vec![
                                        LetExpr {
                                            var: "volumes".to_string(),
                                            value: LetValue::AccessClause(AccessQuery{ query: vec![
                                                QueryPart::Key("block_device_mappings".to_string()),
                                            ], match_all: true })
                                        }
                                    ],
                                    // %volumes.*.Ebs EXISTS
                                    // %volumes.*.device_name == /^\/dev\/ebs-/  # must have ebs in the name
                                    // %volumes.*.Ebs.encryped == true               # Ebs volume must be encryped
                                    // %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
                                    conjunctions: Conjunctions::from([
                                        Disjunctions::from([
                                            GuardClause::Clause(
                                                GuardAccessClause {
                                                    access_clause: AccessClause {
                                                        query: AccessQuery{ query: vec![
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllIndices(None),
                                                            QueryPart::AllValues(None),
                                                            QueryPart::Key("Ebs".to_string())
                                                        ], match_all: true },
                                                        comparator: (CmpOperator::Exists, false),
                                                        compare_with: None,
                                                        custom_message: None,
                                                        location: FileLocation {
                                                            file_name: "",
                                                            line: 16,
                                                            column: 11
                                                        }
                                                    },
                                                    negation: false
                                                }
                                            ),
                                        ]),
                                        Disjunctions::from([
                                            GuardClause::Clause(
                                                GuardAccessClause {
                                                    access_clause: AccessClause {
                                                        query: AccessQuery{ query: vec![
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllIndices(None),
                                                            QueryPart::AllValues(None),
                                                            QueryPart::Key("device_name".to_string())
                                                        ], match_all: true },
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Regex("^/dev/ebs-".to_string())).unwrap())),
                                                        custom_message: None,
                                                        location: FileLocation {
                                                            file_name: "",
                                                            line: 17,
                                                            column: 11
                                                        }
                                                    },
                                                    negation: false
                                                }
                                            ),
                                        ]),
                                        Disjunctions::from([
                                            GuardClause::Clause(
                                                GuardAccessClause {
                                                    access_clause: AccessClause {
                                                        query: AccessQuery{ query: vec![
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllIndices(None),
                                                            QueryPart::AllValues(None),
                                                            QueryPart::Key("Ebs".to_string()),
                                                            QueryPart::Key("encrypted".to_string())
                                                        ], match_all: true },
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Bool(true)).unwrap())),
                                                        custom_message: None,
                                                        location: FileLocation {
                                                            file_name: "",
                                                            line: 18,
                                                            column: 11
                                                        }
                                                    },
                                                    negation: false
                                                }
                                            ),
                                        ]),
                                        Disjunctions::from([
                                            GuardClause::Clause(
                                                GuardAccessClause {
                                                    access_clause: AccessClause {
                                                        query: AccessQuery{ query: vec![
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllIndices(None),
                                                            QueryPart::AllValues(None),
                                                            QueryPart::Key("Ebs".to_string()),
                                                            QueryPart::Key("delete_on_termination".to_string())
                                                        ], match_all: true },
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Bool(true)).unwrap())),
                                                        custom_message: None,
                                                        location: FileLocation {
                                                            file_name: "",
                                                            line: 19,
                                                            column: 11
                                                        }
                                                    },
                                                    negation: false
                                                }
                                            ),
                                        ]),
                                    ]),
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
                                                        line: 14,
                                                        file_name: ""
                                                    },
                                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::EC2::Instance".to_string())))),
                                                    comparator: (CmpOperator::Eq, false)
                                                }
                                            })
                                        ])
                                    ]))
                                ]
                            }),
                            RuleClause::TypeBlock(TypeBlock {
                                type_name: type_name.to_string(),
                                conditions: None,
                                block: Block {
                                    assignments: vec![],
                                    // block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc

                                    conjunctions: Conjunctions::from([
                                        Disjunctions::from([
                                            GuardClause::Clause(
                                                GuardAccessClause {
                                                    access_clause: AccessClause {
                                                        query: AccessQuery{ query: vec![
                                                            QueryPart::Key("block_device_mappings".to_string()),
                                                            QueryPart::AllValues(None),
                                                            QueryPart::Key("device_name".to_string())
                                                        ], match_all: true },
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Regex("^/dev/sdc-\\d".to_string())).unwrap())),
                                                        custom_message: None,
                                                        location: FileLocation {
                                                            file_name: "",
                                                            line: 22,
                                                            column: 9
                                                        }
                                                    },
                                                    negation: false
                                                }
                                            ),
                                        ])
                                    ])
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
                                                        line: 21,
                                                        file_name: ""
                                                    },
                                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::EC2::Instance".to_string())))),
                                                    comparator: (CmpOperator::Eq, false)
                                                }
                                            })
                                        ])
                                    ]))
                                ]
                            })
                        ])
                    ]),
                }
            }
        )),
    ];

    let val = rule_block(from_str2(examples[0]));
    assert_eq!(val, expectations[0]);
    println!("{:?}", val.unwrap().1);
}

#[test]
fn test_rules_file() -> Result<(), Error> {
    let s = r###"
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
        "###;

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
    let rule = r###"
    rule s3_secure_exception {
        s3_secure or
        AWS::S3::Bucket tags.*.key in ["ExternalS3Approved"]
    }
    "###;
    let rule_statement = Rule::try_from(rule)?;
    let expected = Rule {
        rule_name: String::from("s3_secure_exception"),
        conditions: None,
        block: Block {
            assignments: vec![],
            conjunctions: Conjunctions::from([
                Disjunctions::from([
                    RuleClause::Clause(
                        GuardClause::NamedRule(GuardNamedRuleClause {
                            negation: false,
                            dependent_rule: String::from("s3_secure"),
                            location: FileLocation {
                                file_name: "",
                                line: 3,
                                column: 9,
                            },
                            custom_message: None
                        })
                    ),

                    RuleClause::TypeBlock(
                        TypeBlock {
                            type_name: String::from("AWS::S3::Bucket"),
                            conditions: None,
                            block: Block {
                                assignments: vec![],
                                conjunctions: Conjunctions::from([
                                    Disjunctions::from([
                                        GuardClause::Clause(
                                            GuardAccessClause {
                                                negation: false,
                                                access_clause: AccessClause {
                                                    query: AccessQuery{ query: vec![
                                                        QueryPart::Key(String::from("tags")),
                                                        QueryPart::AllValues(None),
                                                        QueryPart::Key(String::from("key"))
                                                    ], match_all: true },
                                                    comparator: (CmpOperator::In, false),
                                                    compare_with: Some(LetValue::Value(
                                                        PathAwareValue::try_from(Value::List(
                                                            vec![Value::String(String::from("ExternalS3Approved"))]
                                                        )).unwrap()
                                                    )),
                                                    custom_message: None,
                                                    location: FileLocation {
                                                        file_name: "",
                                                        line: 4,
                                                        column: 25
                                                    }
                                                }
                                            }
                                        )
                                    ])
                                ])
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
                                                    column: 9,
                                                    line: 4,
                                                    file_name: ""
                                                },
                                                compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::S3::Bucket".to_string())))),
                                                comparator: (CmpOperator::Eq, false)
                                            }
                                        })
                                    ])
                                ]))
                            ]
                        }
                    )
                ])
            ])
        }
    };
    assert_eq!(rule_statement, expected);
    Ok(())
}

#[test]
fn parse_list_of_map() -> Result<(), Error> {
    let s = r###"let allowlist = [
     {
         "serviceAccount": "analytics",
         "images": ["banzaicloud/allspark:0.1.2", "banzaicloud/istio-proxyv2:1.7.0-bzc"],
         # possible nodeSelector combinations we allow, the pod can have more nodeSelectors of course
         "nodeSelector": [{"failure-domain.beta.kubernetes.io/region": "europe-west1"}]
         # "nodeSelector": [],
     }
 ]

  "###;

    let value = assignment(from_str2(s))?.1;
    println!("{:?}", value);
    Ok(())
}

#[test]
fn parse_rule_block_with_mixed_assignment() -> Result<(), Error> {
    let r = r###"
    rule is_service_account_operation_valid {
     request.kind.kind == "Pod"
     request.operation == "CREATE"
     let service_name = request.object.spec.serviceAccountName
     %allowlist[ this.serviceAccount == %service_name ] !EMPTY
 }"###;
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
    let inner = r#"(\d{4})-(\d{2})-(\d{2})"#;
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

struct DummyEval{}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, _variable: &str) -> crate::rules::Result<Vec<&PathAwareValue>> {
        unimplemented!()
    }

    fn rule_status(&self, _rule_name: &str) -> crate::rules::Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(&self, _eval_type: EvaluationType, _context: &str, _msg: String, _from: Option<PathAwareValue>, _to: Option<PathAwareValue>, _status: Option<Status>, _cmp: Option<(CmpOperator, bool)>) {
    }

    fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {
    }
}


#[test]
fn select_any_one_from_list_clauses() -> Result<(), Error> {
    let clause = "this == /\\{\\{resolve:secretsmanager/";
    let parsed = super::clause(from_str2(clause))?.1;
    let expected = GuardClause::Clause(
        GuardAccessClause {
            access_clause: AccessClause {
                location: FileLocation {
                    column: 1,
                    line: 1,
                    file_name: ""
                },
                compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Regex("\\{\\{resolve:secretsmanager".to_string())).unwrap())),
                comparator: (CmpOperator::Eq, false),
                custom_message: None,
                query: AccessQuery{ query: vec![QueryPart::This], match_all: true }
            },
            negation: false
        }
    );
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

    let _dummy = DummyEval{};
    let _clause = GuardClause::try_from(
        r#"Resources.*[ this.Type == "AWS::RDS::DBInstance" ].Properties.MasterUserPassword.'Fn::Join'[1][ this == /\{\{resolve:secretsmanager/ ] !EMPTY"#)?;
    Ok(())
}


#[test]
fn test_rules_file_default_rules() -> Result<(), Error> {
    let s = r###"
    AWS::AmazonMQ::Broker Properties.AutoMinorVersionUpgrade == false <<Version upgrades should be enabled to receive security updates>>
    AWS::AmazonMQ::Broker Properties.EncryptionOptions.UseAwsOwnedKey == false <<CMKs should be used instead of AWS-provided KMS keys>>
    AWS::ApiGateway::Method Properties.ResourceId == "ApiGatewayBadBot.RootResourceId" <<Should be root resource id>> or  AWS::ApiGateway::Method Properties.ResourceId == "ApiGatewayBadBotResource"
    "###;
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
    assert_eq!(rules_file, RulesFile {
        assignments: vec![],
        guard_rules: vec![default_rule],
        parameterized_rules: vec![],
    });
    Ok(())
}

#[test]
fn rule_parameters_parse_test() -> Result<(), Error> {
    let parameters = "(statements, policy)";
    let (_span, parsed_parameters) = parameter_names(from_str2(parameters))?;
    assert_eq!(parsed_parameters.len(), 2);
    assert_eq!(parsed_parameters, ["statements", "policy"].iter().map(|s| s.to_string()).into_iter().collect::<indexmap::IndexSet<String>>());

    let parameters = "(statements)";
    let (_span, parsed_parameters) = parameter_names(from_str2(parameters))?;
    assert_eq!(parsed_parameters.len(), 1);
    assert_eq!(parsed_parameters, ["statements"].iter().map(|s| s.to_string()).into_iter().collect::<indexmap::IndexSet<String>>());

    let parameters = "( statements  , policy    )";
    let (_span, parsed_parameters) = parameter_names(from_str2(parameters))?;
    assert_eq!(parsed_parameters.len(), 2);
    assert_eq!(parsed_parameters, ["statements", "policy"].iter().map(|s| s.to_string()).into_iter().collect::<indexmap::IndexSet<String>>());

    //
    // Error cases
    //
    let parameters = "()";
    let result = parameter_names(from_str2(parameters));
    assert_eq!(result.is_err(), true);
    assert_eq!(result.err(), Some(nom::Err::Failure(ParserError {
        context: "".to_string(),
        kind: nom::error::ErrorKind::Alpha, // for var_name
        span: unsafe {
            Span::new_from_raw_offset(
                1,
                1,
                ")",
                ""
            )
        }
    })));

    let parameters = "statements";
    let result = parameter_names(from_str2(parameters));
    assert_eq!(result.is_err(), true);
    assert_eq!(result.err(), Some(nom::Err::Error(ParserError {
        kind: nom::error::ErrorKind::Char, // no '('
        context: "".to_string(),
        span: unsafe {
            Span::new_from_raw_offset(
                0,
                1,
                "statements",
                ""
            )
        }
    })));

    let parameters = "(statements";
    let result = parameter_names(from_str2(parameters));
    assert_eq!(result.is_err(), true);
    assert_eq!(result.err(), Some(nom::Err::Failure(ParserError { // expect failure to not close
        kind: nom::error::ErrorKind::Char, // no ')'
        context: "".to_string(),
        span: unsafe {
            Span::new_from_raw_offset(
                "(statements".len(),
                1,
                "",
                ""
            )
        }
    })));

    let parameters = "(statements,)"; // missing second parameter
    let result = parameter_names(from_str2(parameters));
    assert_eq!(result.is_err(), true);
    assert_eq!(result.err(), Some(nom::Err::Failure(ParserError { // expect failure to not close
        kind: nom::error::ErrorKind::Alpha, // due to var_name
        context: "".to_string(),
        span: unsafe {
            Span::new_from_raw_offset(
                "(statements,".len(),
                1,
                ")",
                ""
            )
        }
    })));

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
                conjunctions: Conjunctions::from([
                    Disjunctions::from([
                        RuleClause::Clause(
                            GuardClause::BlockClause(BlockGuardClause {
                                location: FileLocation {
                                    file_name: "",
                                    line: 3,
                                    column: 9,
                                },
                                query: AccessQuery {
                                    match_all: true,
                                    query: vec![
                                        QueryPart::Key("%statements".to_string())
                                    ]
                                },
                                block: Block {
                                    assignments: vec![],
                                    conjunctions: Conjunctions::from([
                                        Disjunctions::from([
                                            GuardClause::Clause(GuardAccessClause {
                                                negation: false,
                                                access_clause: AccessClause {
                                                    query: AccessQuery {
                                                        query: vec![
                                                            QueryPart::Key("Effect".to_string())
                                                        ],
                                                        match_all: true
                                                    },
                                                    location: FileLocation {
                                                        file_name: "",
                                                        line: 4,
                                                        column: 13,
                                                    },
                                                    comparator: (CmpOperator::Eq, false),
                                                    custom_message: None,
                                                    compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "Allow".to_string()))))
                                                }
                                            })
                                        ])
                                    ])
                                },
                                not_empty: false
                            })
                        )
                    ])
                ])
            }
        }
    };
    assert_eq!(parameterized_rule, expected);

    Ok(())
}

#[test]
fn some_clause_parse() -> Result<(), Error> {
    let clause = GuardClause::try_from(
        r#"some %api_gws.Properties.Policy.Statement[*].Condition[
            keys ==  /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !empty"#)?;
    let parsed_clause = GuardClause::Clause(
        GuardAccessClause {
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
                            None, MapKeyFilterClause {
                                comparator: (CmpOperator::Eq, false),
                                compare_with: LetValue::Value(PathAwareValue::try_from(Value::Regex("aws:[sS]ource(Vpc|VPC|Vpce|VPCE)".to_string())).unwrap())
                            }
                        )
                    ]
                },
                compare_with: None,
                comparator: (CmpOperator::Empty, true),
                custom_message: None,
                location: FileLocation {
                    line: 1,
                    column: 1,
                    file_name: ""
                }
            }
        }
    );
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
            QueryPart::Filter(None,
                Conjunctions::from([
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                negation: false,
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        match_all: false,
                                        query: vec![
                                            QueryPart::This
                                        ]
                                    },
                                    custom_message: None,
                                    comparator: (CmpOperator::Eq, false),
                                    location: FileLocation {
                                        file_name: "",
                                        column: 7,
                                        line: 1
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::Map(
                                        make_linked_hashmap(vec![
                                            ("Key", Value::String("Hi".to_string())),
                                            ("Value", Value::String("There".to_string()))
                                        ]))).unwrap()
                                    ))
                                }
                            }
                        )
                    ])
                ])
            )
        ]
    };
    assert_eq!(parsed_query, expected);
    Ok(())
}

#[test]
fn test_block_properties()-> Result<(), Error> {
    let block_str = r###"Properties.Statements[*] {
        Effect == 'Deny'
        Principal != '*'
    }
    "###;
    let block_clause = GuardClause::try_from(block_str)?;
    let expected = GuardClause::BlockClause(
        BlockGuardClause {
            location: FileLocation {
                file_name: "",
                column: 1,
                line:1,
            },
            query: AccessQuery {
                query: vec![
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("Statements".to_string()),
                    QueryPart::AllIndices(None)
                ],
                match_all: true
            },
            block: Block {
                assignments: vec![],
                conjunctions: vec![
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![
                                            QueryPart::Key("Effect".to_string())
                                        ],
                                        match_all: true,
                                    },
                                    location: FileLocation {
                                        file_name: "",
                                        line: 2,
                                        column: 9,
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::String("Deny".to_string())).unwrap())),
                                    comparator: (CmpOperator::Eq, false),
                                    custom_message: None
                                },
                                negation: false
                            }
                        )
                    ]),
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    query: AccessQuery {
                                        query: vec![
                                            QueryPart::Key("Principal".to_string())
                                        ],
                                        match_all: true,
                                    },
                                    location: FileLocation {
                                        file_name: "",
                                        line: 3,
                                        column: 9,
                                    },
                                    compare_with: Some(LetValue::Value(PathAwareValue::try_from(Value::String("*".to_string())).unwrap())),
                                    comparator: (CmpOperator::Eq, true),
                                    custom_message: None
                                },
                                negation: false
                            }
                        )
                    ])

                ]
            },
            not_empty: false
        }
    );
    assert_eq!(block_clause, expected);
    Ok(())
}

#[test]
fn test_block_in_block_properties()-> Result<(), Error> {
    let block_str = r###"Properties {
        Statements[*] {
            Effect == 'Deny'
            Principal != '*'
        }
    }"###;
    let block = GuardClause::try_from(block_str)?;
    match &block {
        GuardClause::BlockClause(block) => {
            match &block.block.conjunctions[0][0] {
                GuardClause::BlockClause(blk) => {
                    assert_eq!(blk.block.assignments.is_empty(), true);
                    let conjuntions = &blk.block.conjunctions;
                    assert_eq!(conjuntions.len(), 2);
                },
                _ => unreachable!()
            }
        },
        _ => unreachable!()
    }
    Ok(())
}

#[test]
fn test_incorrect_block_in_block_properties()-> Result<(), Error> {
    // Empty does not contain properties
    let block_str = r###"Properties {}"###;
    match GuardClause::try_from(block_str) {
        Ok(_) => unreachable!(),
        Err(_) => {}
    }

    // Incomplete block
    let block_str = r###"Properties { Statements[*]"###;
    match GuardClause::try_from(block_str) {
        Ok(_) => unreachable!(),
        Err(_) => {}
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
    let (_span, clause) = rule_block_clause(from_str2(when_inside_when))?;
    Ok(())
}

#[test]
fn is_list_check_parser_bug() -> Result<(), Error> {
    let bug_test = "some %normal_managed_policies.Properties.PolicyDocument.Statement[ Action is_list ]";
    let _access = AccessQuery::try_from(bug_test)?;
    Ok(())
}

#[test]
fn does_this_work() -> Result<(), Error> {
    let query = AccessQuery::try_from(r#"Resources[ keys == /s3/ ][ Type == "AWS::S3::BucketPolicy" ]"#)?.query;
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
                conjunctions: Conjunctions::from([
                    Disjunctions::from([RuleClause::Clause(
                        GuardClause::BlockClause(BlockGuardClause {
                            not_empty: false,
                            query: AccessQuery {
                                match_all: true,
                                query: vec![
                                    QueryPart::Key("%iam_statements".to_string()),
                                ]
                            },
                            location: FileLocation {
                                file_name: "",
                                line: 3,
                                column: 7,
                            },
                            block: Block {
                                assignments: vec![],
                                conjunctions: Conjunctions::from([
                                    Disjunctions::from([
                                        GuardClause::Clause(GuardAccessClause {
                                            negation: false,
                                            access_clause: AccessClause {
                                                query: AccessQuery {
                                                    match_all: true,
                                                    query: vec![
                                                        QueryPart::Key("Action".to_string())
                                                    ]
                                                },
                                                custom_message: None,
                                                comparator: (CmpOperator::Eq, true),
                                                compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "*".to_string())))),
                                                location: FileLocation {
                                                    file_name: "",
                                                    line: 4,
                                                    column: 10
                                                }
                                            }
                                        })
                                    ])
                                ])
                            }
                        })
                    )])
                ])
            },
            conditions: None
        }
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
                column: 1
            },
            custom_message: None,
            negation: true,
            dependent_rule: "iam_disallowed_attributes_check".to_string()
        },
        parameters: vec![
            LetValue::AccessClause(
            AccessQuery {
                match_all: true,
                query: vec![
                    QueryPart::Key("Resources".to_string()),
                    QueryPart::Filter(None,
                        Conjunctions::from([
                            Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::IAM::Role".to_string())))),
                                        location: FileLocation {
                                            file_name: "",
                                            line: 2,
                                            column: 20,
                                        },
                                        query: AccessQuery {
                                            match_all: true,
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ]
                                        },
                                        ..Default::default()
                                    }
                                }),
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::IAM::ManagedPolicy".to_string())))),
                                        location: FileLocation {
                                            file_name: "",
                                            line: 3,
                                            column: 20,
                                        },
                                        query: AccessQuery {
                                            match_all: true,
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ]
                                        },
                                        ..Default::default()
                                    }
                                })

                            ])
                        ])
                    ),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("PolicyDocument".to_string()),
                    QueryPart::Key("Statement".to_string()),
                    QueryPart::AllIndices(None)
                ]
            })
        ]
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
        "hardcoded"
       )"#;

    let parameterized_guard_clause = ParameterizedNamedRuleClause::try_from(guard_clause)?;
    let expected = ParameterizedNamedRuleClause {
        named_rule: GuardNamedRuleClause {
            location: FileLocation {
                file_name: "",
                line: 1,
                column: 1
            },
            custom_message: None,
            negation: true,
            dependent_rule: "iam_disallowed_attributes_check".to_string()
        },
        parameters: vec![
            LetValue::AccessClause(
            AccessQuery {
                match_all: true,
                query: vec![
                    QueryPart::Key("Resources".to_string()),
                    QueryPart::Filter(None,
                        Conjunctions::from([
                            Disjunctions::from([
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::IAM::Role".to_string())))),
                                        location: FileLocation {
                                            file_name: "",
                                            line: 2,
                                            column: 20,
                                        },
                                        query: AccessQuery {
                                            match_all: true,
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ]
                                        },
                                        ..Default::default()
                                    }
                                }),
                                GuardClause::Clause(GuardAccessClause {
                                    negation: false,
                                    access_clause: AccessClause {
                                        compare_with: Some(LetValue::Value(PathAwareValue::String((Path::root(), "AWS::IAM::ManagedPolicy".to_string())))),
                                        location: FileLocation {
                                            file_name: "",
                                            line: 3,
                                            column: 20,
                                        },
                                        query: AccessQuery {
                                            match_all: true,
                                            query: vec![
                                                QueryPart::Key("Type".to_string())
                                            ]
                                        },
                                        ..Default::default()
                                    }
                                })

                            ])
                        ])
                    ),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("PolicyDocument".to_string()),
                    QueryPart::Key("Statement".to_string()),
                    QueryPart::AllIndices(None)
                ]
            }),
            LetValue::AccessClause(AccessQuery {
                match_all: true,
                query: vec![
                    QueryPart::Key("%var".to_string()),
                    QueryPart::AllIndices(None),
                    QueryPart::Key("Properties".to_string()),
                    QueryPart::Key("Tags".to_string())
                ]
            }),
            LetValue::Value(PathAwareValue::try_from(Value::String("hardcoded".to_string()))?)
        ]
    };
    assert_eq!(parameterized_guard_clause, expected);
    Ok(())
}

#[test]
fn paramterized_clause_errors() -> Result<(), Error> {
    let just_name_rule_clause = "not named_rule";
    let result = ParameterizedNamedRuleClause::try_from(just_name_rule_clause);
    assert_eq!(result.is_err(), true);

    let result = GuardClause::try_from(just_name_rule_clause);
    assert_eq!(result.is_err(), true); // this does not match rule_clause

    let result = RuleClause::try_from(just_name_rule_clause);
    assert_eq!(result.is_ok(), true);
    match result.unwrap() {
        RuleClause::Clause(GuardClause::NamedRule(gnr)) => {
            assert_eq!(gnr.dependent_rule.as_str(), "named_rule");
            assert_eq!(gnr.custom_message, None);
        },
        _ => unreachable!()
    }
    Ok(())
}

#[test]
fn parameterized_clause_in_when_condition() -> Result<(), Error> {
    let rule_when_clause = r###"rule call_parameterized when parameterized(%x) {
        Resources[ Type == /IAM::Role/ ] {
            check_iam_statements(Properties.PolicyDocument.Statement[*], "some-hardcoded-param")
            when check_required_tags_present(Properties.Tags)
                 %someref not empty
            {
                some Properties.PolicyDocument.Statement[*].Principal == '*'
            }
        }
    }"###;

    let rule = Rule::try_from(rule_when_clause)?;
    assert_eq!(rule.rule_name.as_str(), "call_parameterized");
    assert_eq!(rule.conditions.is_some(), true);
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
                },
                _ => unreachable!()
            }
        },
        _ => unreachable!()
    }

    assert_eq!(rule.block.conjunctions.len(), 1);
    match &rule.block.conjunctions[0][0] {
        RuleClause::Clause(block) => {
            match block {
                GuardClause::BlockClause(block) => {
                    assert_eq!(block.block.conjunctions.len(), 2);
                    for each in &block.block.conjunctions {
                        match &each[0] {
                            GuardClause::ParameterizedNamedRule(prc) => {
                                assert_eq!(prc.named_rule.dependent_rule.as_str(), "check_iam_statements");
                                assert_eq!(matches!(&prc.parameters[0], LetValue::AccessClause(_)), true);
                                assert_eq!(matches!(&prc.parameters[1], LetValue::Value(_)), true);
                            },

                            GuardClause::WhenBlock(conds, _) => {
                                assert_eq!(conds.len(), 2);
                                match &conds[0][0] {
                                    WhenGuardClause::ParameterizedNamedRule(prc) => {
                                        assert_eq!(prc.named_rule.dependent_rule.as_str(), "check_required_tags_present");
                                        assert_eq!(matches!(&prc.parameters[0], LetValue::AccessClause(_)), true);
                                    },
                                    _ => unreachable!()
                                }
                            },

                            _ => unreachable!()
                        }
                    }
                },
                _ => unreachable!()
            }
        },
        _ => unreachable!()
    }

    Ok(())

}

#[test]
fn test_variable_capture_syntax() -> Result<(), Error> {
    let map_index_capture = "Resources[ resource_name ].Properties";
    let access = AccessQuery::try_from(map_index_capture)?.query;
    assert_eq!(access.len(), 3);
    assert_eq!(access[1], QueryPart::AllValues(Some(String::from("resource_name"))));

    let map_index_with_filter = "Resources[ resource_name | Type == 'AWS::S3::Bucket' ].Properties.BucketName";
    let access = AccessQuery::try_from(map_index_with_filter)?.query;
    assert_eq!(access.len(), 4);
    let filters = &access[1];
    assert_eq!(matches!(filters, QueryPart::Filter(_, _)), true);
    let (name, filter) = match filters {
        QueryPart::Filter(name, filters) => (name, filters),
        _ => unreachable!()
    };
    assert_eq!(name, &Some(String::from("resource_name")));
    Ok(())
}

#[test]
fn test_builtin_function_call_expr() -> Result<(), Error> {
    let call_expr = "count(Resources.*)";
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, "count");
    assert_eq!(function.parameters.len(), 1);
    let parameter = &function.parameters[0];
    assert_eq!(matches!(parameter, LetValue::AccessClause(_)), true);
    if let LetValue::AccessClause(query) = parameter {
        assert_eq!(query.match_all, true);
        assert_eq!(query.query.len(), 2);
        let expected = vec![
            QueryPart::Key("Resources".to_string()),
            QueryPart::AllValues(None),
        ];
        assert_eq!(&query.query, &expected);
    }

    let call_expr = r#"json_parse(Resources[ Type == 'AWS::SNS::TopicPolicy' ].Properties.PolicyDocument)"#;
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, "json_parse");
    assert_eq!(function.parameters.len(), 1);
    let parameter = &function.parameters[0];
    assert_eq!(matches!(parameter, LetValue::AccessClause(_)), true);
    if let LetValue::AccessClause(query) = parameter {
        assert_eq!(query.match_all, true);
        assert_eq!(query.query.len(), 4);
    }

    let call_expr = r#"json_parse(Resources[ Type == 'AWS::SNS::TopicPolicy' ].Properties.PolicyDocument)"#;
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, "json_parse");
    assert_eq!(function.parameters.len(), 1);
    let parameter = &function.parameters[0];
    assert_eq!(matches!(parameter, LetValue::AccessClause(_)), true);
    if let LetValue::AccessClause(query) = parameter {
        assert_eq!(query.match_all, true);
        assert_eq!(query.query.len(), 4);
    }

    let call_expr = r#"substring(%sqs_queues.Arn, 0, 6)"#;
    let function = FunctionExpr::try_from(call_expr)?;
    assert_eq!(function.name, "substring");
    assert_eq!(function.parameters.len(), 3);
    let parameter = &function.parameters[0];
    assert_eq!(matches!(parameter, LetValue::AccessClause(_)), true);
    if let LetValue::AccessClause(query) = parameter {
        assert_eq!(query.match_all, true);
        assert_eq!(query.query.len(), 3);
    }

    let parameter = &function.parameters[1];
    assert_eq!(matches!(parameter, LetValue::Value(_)), true);
    if let LetValue::Value(PathAwareValue::Int((_, v))) = parameter {
        assert_eq!(*v, 0);
    }

    let parameter = &function.parameters[2];
    assert_eq!(matches!(parameter, LetValue::Value(_)), true);
    if let LetValue::Value(PathAwareValue::Int((_, v))) = parameter {
        assert_eq!(*v, 6);
    }

    Ok(())
}
