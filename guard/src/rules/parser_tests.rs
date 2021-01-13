use super::*;
use std::convert::TryInto;

use crate::rules::values::WithinRange;

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

/*
#[test]
fn test_parse_string_to_fix() {
    let s = "\"Hi \\\"embedded\\\" there\"";
    assert_eq!(parse_string(s), Ok(("", Value::String(String::from("Hi \"embedded\" there".to_owned())))))
}
 */

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
    list.iter()
        .map(|part|
            if *part == "*" {
                QueryPart::AllValues
            }
            else {
                QueryPart::Key(String::from(*part))
            })
        .collect()
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

        //" .first.second", // err
        Err(nom::Err::Error(
            ParserError {
                span: from_str2(examples[8]),
                kind: nom::error::ErrorKind::Many1,
                context: "".to_string(),
            }
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
            to_string_vec(&["first", "0", "path"]),
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
             AccessQuery::from([
                 QueryPart::Key("engine".to_string())
             ])
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
             AccessQuery::from([
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Key("type".to_string()),
             ])
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
             AccessQuery::from([
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Key("type".to_string()),
                 QueryPart::AllValues,
             ])
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
             AccessQuery::from([
                 QueryPart::Key("engine".to_string()),
                 QueryPart::AllValues,
                 QueryPart::Key("type".to_string()),
                 QueryPart::Key("port".to_string()),
             ])
        )),
        Ok(( // "engine.*.type.%var", // 8 ok
             unsafe {
                 Span::new_from_raw_offset(
                     examples[8].len() - ".%var".len(),
                     1,
                     ".%var",
                     "",
                 )
             },
             AccessQuery::from([
                 QueryPart::Key("engine".to_string()),
                 QueryPart::AllValues,
                 QueryPart::Key("type".to_string()),
             ])
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
             AccessQuery::from([
                 QueryPart::Key("engine".to_string()),
                 QueryPart::Index(0),
             ])
        )),
        Ok(( // 10 "engine [0]", // 10 ok engine will be property access part
             unsafe {
                 Span::new_from_raw_offset(
                     "engine".len(),
                     1,
                     " [0]",
                     "",
                 )
             },
             AccessQuery::from([
                 QueryPart::Key("engine".to_string())
             ])
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
            AccessQuery::from([
                QueryPart::Key("engine".to_string()),
                QueryPart::Key("ok".to_string()),
                QueryPart::AllValues,
            ])
        )),

        // "engine.%name.*", // 12 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[12].len() - ".%name.*".len(),
                    1,
                    ".%name.*",
                    "",
                )
            },
            AccessQuery::from([
                QueryPart::Key("engine".to_string()),
            ])
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
            AccessQuery::from([
                QueryPart::Key("%engine".to_string()),
                QueryPart::Key("type".to_string()),
            ])
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
            AccessQuery::from([
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllValues,
                QueryPart::Key("type".to_string()),
                QueryPart::Index(0),
            ])
        )),


        // "%engine.%type.*", // 15 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[15].len() - ".%type.*".len(),
                    1,
                    ".%type.*",
                    "",
                )
            },
            AccessQuery::from([
                QueryPart::Key("%engine".to_string()),
            ])
        )),


        // "%engine.%type.*.port", // 16 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[16].len() - ".%type.*.port".len(),
                    1,
                    ".%type.*.port",
                    "",
                )
            },
            AccessQuery::from([
                QueryPart::Key("%engine".to_string()),
            ])
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
            AccessQuery::from([
                QueryPart::Key("%engine".to_string()),
                QueryPart::AllValues,
            ])
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
            AccessQuery::from([
                QueryPart::Key("engine".to_string()),
                QueryPart::Filter(vec![
                    vec![GuardClause::Clause(
                        GuardAccessClause {
                            access_clause: AccessClause {
                                query: AccessQuery::from([
                                    QueryPart::Key(String::from("type"))
                                ]),
                                comparator: (CmpOperator::Eq, false),
                                custom_message: None,
                                compare_with: Some(LetValue::Value(Value::String(String::from("cfn")))),
                                location: FileLocation {
                                    line: 1,
                                    column: "engine[".len() as u32 + 1,
                                    file_name: ""
                                }
                            },
                            negation: false
                        }),
                    ]
                ]),
                QueryPart::Key(String::from("port")),
            ])
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
        "KEYS", // 1 err
        "KEYS IN", // 2 Ok
        "KEYS NOT IN", // 3 Ok
        "KEYS EXISTS", // 4 Ok
        "KEYS !EXISTS", // 5 Ok,
        "KEYS ==", // 6 Ok
        "KEYS !=", // 7 Ok
        "keys ! in", // 8 err after !
        "KEYS EMPTY", // 9 ok
        "KEYS !EMPTY", // 10 ok
        " KEYS IN", // 11 err
        "KEYS ", // 12 err
    ];

    let expectations = [
        // "", // 0 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: nom::error::ErrorKind::Tag,
            context: "".to_string(),
        })),

        // "KEYS", // 1 err
        Err(nom::Err::Error(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    examples[1].len(),
                    1,
                    "",
                    "",
                )
            },
            kind: nom::error::ErrorKind::Space,
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
            (CmpOperator::KeysIn, false),
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
            (CmpOperator::KeysIn, true),
        )),

        // "KEYS EXISTS", // 4 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[4].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::KeysExists, false),
        )),

        // "KEYS !EXISTS", // 5 Ok,
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[5].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::KeysExists, true),
        )),

        // "KEYS ==", // 6 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[6].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::KeysEq, false),
        )),

        // "KEYS !=", // 7 Ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[7].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::KeysEq, true),
        )),

        // "keys ! in", // 8 err after !
        Err(nom::Err::Error(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    "keys !".len(),
                    1,
                    " in",
                    "",
                )
            },
            kind: nom::error::ErrorKind::Tag,
            context: "".to_string(),
        })),

        // "KEYS EMPTY", // 9 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[9].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::KeysEmpty, false),
        )),

        // "KEYS !EMPTY", // 10 ok
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[10].len(),
                    1,
                    "",
                    "",
                )
            },
            (CmpOperator::KeysEmpty, true),
        )),

        // " KEYS IN", // 11 err
        Err(nom::Err::Error(ParserError {
            span: from_str2(" KEYS IN"),
            kind: nom::error::ErrorKind::Tag,
            context: "".to_string(),
        })),

        // "KEYS ", // 12 err
        Err(nom::Err::Error(ParserError {
            span: unsafe {
                Span::new_from_raw_offset(
                    "KEYS ".len(),
                    1,
                    "",
                    "",
                )
            },
            kind: nom::error::ErrorKind::Tag,
            context: "".to_string(),
        })),
    ];

    for (idx, each) in examples.iter().enumerate() {
        let span = from_str2(*each);
        let result = keys_keyword(span);
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
        ("KEYS IN", (CmpOperator::KeysIn, false)),
        ("KEYS ==", (CmpOperator::KeysEq, false)),
        ("KEYS !=", (CmpOperator::KeysEq, true)),
        ("KEYS !IN", (CmpOperator::KeysIn, true)),
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
    let rhs_access = Some(LetValue::AccessClause(rhs_dotted));

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);
        let lhs_access =

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
        ("KEYS EXISTS", (CmpOperator::KeysExists, false)),
        ("KEYS NOT EMPTY", (CmpOperator::KeysEmpty, true))
    ];

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);

        testing_access_with_cmp(&separators, &comparators,
                                *each_lhs, "",
                                || dotted.clone(),
                                || None);
    }

    for each_lhs in lhs.iter() {
        let dotted = (*each_lhs).split(".").collect::<Vec<&str>>();
        let dotted = to_string_vec(&dotted);

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

            let rhs_value = parse_value(from_str2(*each_rhs)).unwrap().1;
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
            AccessQuery::from([
                QueryPart::Key(examples[0].to_string())
            ])
        )),

        // "resources.*.type", // 1 Ok
        Ok((unsafe { Span::new_from_raw_offset(
            examples[1].len(),
            1,
            "",
            ""
        )},
            to_query_part(examples[1].split(".").collect())
        )),

        // "resources.*[ type == /AWS::RDS/ ]", // 2 Ok
        Ok((unsafe { Span::new_from_raw_offset(
            examples[2].len(),
            1,
            "",
            ""
        )},
            AccessQuery::from([
                QueryPart::Key("resources".to_string()),
                QueryPart::AllValues,
                QueryPart::Filter(Conjunctions::from([
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(Value::Regex("AWS::RDS".to_string()))),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery::from([QueryPart::Key(String::from("type"))]),
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
            ])
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
            AccessQuery::from([
                QueryPart::Key("resources".to_string()),
                QueryPart::AllValues,
                QueryPart::Filter(Conjunctions::from([
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    compare_with: Some(LetValue::Value(Value::Regex("AWS::RDS".to_string()))),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery::from([QueryPart::Key(String::from("type"))]),
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
                                    query: AccessQuery::from([QueryPart::Key(String::from("deletion_policy"))]),
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
                                    compare_with: Some(LetValue::Value(Value::String("RETAIN".to_string()))),
                                    comparator: (CmpOperator::Eq, false),
                                    query: AccessQuery::from([QueryPart::Key(String::from("deletion_policy"))]),
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
            ])
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
            context: "".to_string(),
            kind: nom::error::ErrorKind::Tag, // for negative number in parse_int_value
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
    let rhs = "PARAMETERS.ImageList";
    let lhs_separator = "";
    let rhs_separator = "";
    let comparators = [
        (">", (CmpOperator::Gt, false)),
        ("<", (CmpOperator::Lt, false)),
        ("==", (CmpOperator::Eq, false)),
        ("!=", (CmpOperator::Eq, true)),
    ];

    for each in lhs.iter() {
        for (op, _) in comparators.iter() {
            let access_pattern = format!("{lhs}{lhs_sep}{op}{rhs_sep}{rhs}",
                                         lhs = *each, rhs = rhs, op = *op, lhs_sep = lhs_separator, rhs_sep = rhs_separator);
            let offset = (*each).len();
            let fragment = format!("{op}{sep}{rhs}",
                                   rhs = rhs, op = *op, sep = rhs_separator);
            let error = Err(nom::Err::Error(ParserError {
                span: unsafe {
                    Span::new_from_raw_offset(
                        offset,
                        1,
                        &fragment,
                        "",
                    )
                },
                kind: nom::error::ErrorKind::Char,
                context: "expecting one or more WS or comment blocks".to_string(),
            }));
            println!("Testing : {}", access_pattern);
            assert_eq!(clause(super::from_str2(&access_pattern)), error);
        }
    }

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
        span: from_str2(" > 10"),
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
                    comment: None
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
                    comment: None
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
                    comment: None
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
                    comment: Some("this is secure ${PARAMETER.MSG}".to_string()),
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
                    comment: Some("this is not secure ${PARAMETER.MSG}".to_string()),
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
        Ok((
            unsafe {
                Span::new_from_raw_offset(
                    examples[0].len(),
                    1,
                    "",
                    "",
                )
            },
            vec![],
        )),

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
                        comment: None,
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
                        comment: Some(" was not secure ${PARAMETER.SECURE_MSG}".to_string()),
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
                            comment: None,
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
                                compare_with: Some(LetValue::Value(Value::Regex("httpd:2.4".to_string()))),
                                query: "configurations.containers.*.image".split(".")
                                    .map(|s| if s == "*" { QueryPart::AllValues } else { QueryPart::Key(s.to_string()) }).collect(),
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
                            comment: None,
                        }
                    ),
                    GuardClause::NamedRule(
                        GuardNamedRuleClause {
                            dependent_rule: "exception".to_string(),
                            location: FileLocation { line: 2, column: 16, file_name: "" },
                            negation: true,
                            comment: None
                        }
                    )
                ],
                vec![
                    GuardClause::Clause(
                        GuardAccessClause {
                            access_clause: AccessClause {
                                location: FileLocation { file_name: "", column: 16, line: 4 },
                                compare_with: Some(LetValue::Value(Value::Regex("httpd:2.4".to_string()))),
                                query: "configurations.containers[*].image".split(".").map( |part|
                                    if part.contains('[') {
                                        vec![QueryPart::Key("containers".to_string()), QueryPart::AllIndices]
                                    } else {
                                        vec![QueryPart::Key(part.to_string())]
                                    }
                                ).into_iter().flatten().collect(),
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
                value: LetValue::Value(Value::Int(10))
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
                value: LetValue::Value(Value::List(vec![
                    Value::Int(10), Value::Int(20)
                ]))
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
                value: LetValue::AccessClause(AccessQuery::from([
                    QueryPart::Key(String::from("engine"))]))
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
                value: LetValue::AccessClause(AccessQuery::from([
                    QueryPart::Key(String::from("%engines"))]))
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
                value: LetValue::Value(engines)
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
                    AccessQuery::from([
                        QueryPart::Key(String::from("resources")),
                        QueryPart::AllValues,
                        QueryPart::Filter(Conjunctions::from(
                            [
                                Disjunctions::from([
                                    GuardClause::Clause(
                                        GuardAccessClause {
                                            access_clause: AccessClause {
                                                compare_with: Some(LetValue::Value(Value::List(
                                                    vec![Value::Regex(String::from("AWS::RDS::DBCluster")),
                                                         Value::Regex(String::from("AWS::RDS::GlobalCluster"))]))),
                                                query: AccessQuery::from([QueryPart::Key(String::from("type"))]),
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
                    ])
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
                                AccessQuery::from([
                                    QueryPart::Key(String::from("keyName"))
                                ])
                            )
                        }
                    ],
                    conjunctions: Conjunctions::from([
                        Disjunctions::from([
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery::from([
                                            QueryPart::Key(String::from("%keyName"))
                                        ]),
                                        comparator: (CmpOperator::In, false),
                                        custom_message: None,
                                        compare_with: Some(LetValue::Value(
                                            Value::List(vec![
                                                Value::String(String::from("keyName")),
                                                Value::String(String::from("keyName2")),
                                                Value::String(String::from("keyName3")),
                                            ])
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
                                        query: AccessQuery::from([
                                            QueryPart::Key(String::from("%keyName"))
                                        ]),
                                        comparator: (CmpOperator::In, true),
                                        custom_message: None,
                                        compare_with: Some(LetValue::Value(
                                            Value::List(vec![
                                                Value::String(String::from("keyNameIs")),
                                                Value::String(String::from("notInthis")),
                                            ])
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
                }
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
                    conjunctions: Conjunctions::from([
                        Disjunctions::from([
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery::from([
                                            QueryPart::Key(String::from("keyName")),
                                        ]),
                                        comparator: (CmpOperator::Eq, false),
                                        location: FileLocation {
                                            file_name: "",
                                            column: ("AWS::EC2::Instance ".len() + 1) as u32,
                                            line: 1
                                        },
                                        compare_with: Some(LetValue::Value(Value::Regex("EC2_KEY".to_string()))),
                                        custom_message: None
                                    },
                                    negation: false,
                                }
                            ),
                        ])
                    ])
                }
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
                conditions: Some(Conjunctions::from([
                    Disjunctions::from([
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause {
                                    query: AccessQuery::from([
                                        QueryPart::Key(String::from("instance_type")),
                                    ]),
                                    comparator: (CmpOperator::Eq, false),
                                    location: FileLocation {
                                        file_name: "",
                                        column: 25,
                                        line: 1
                                    },
                                    compare_with: Some(LetValue::Value(Value::String(String::from("m4.xlarge")))),
                                    custom_message: None
                                },
                                negation: false
                            }
                        ),
                    ]),
                ])),
                block: Block {
                    assignments: vec![],
                    conjunctions: Conjunctions::from([
                        Disjunctions::from([
                            GuardClause::Clause(
                                GuardAccessClause {
                                    access_clause: AccessClause {
                                        query: AccessQuery::from([
                                            QueryPart::Key(String::from("security_groups")),
                                        ]),
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
                        ])
                    ])
                }

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
                        GuardClause::Clause(
                            GuardAccessClause {
                                access_clause: AccessClause{
                                    custom_message: None,
                                    query: AccessQuery::from([
                                        QueryPart::Key("stage".to_string())
                                    ]),
                                    compare_with: Some(LetValue::Value(Value::String("prod".to_string()))),
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
                                Value::List(vec![
                                    Value::Regex("^t*".to_string()),
                                    Value::Regex("^m*".to_string())
                                ])
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
                                    comment: None,
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
                                                        query: AccessQuery::from([
                                                            QueryPart::Key("InstanceType".to_string())
                                                        ]),
                                                        compare_with: Some(LetValue::AccessClause(AccessQuery::from([
                                                            QueryPart::Key("%ec2_instance_types".to_string())
                                                        ]))),
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
                                }
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
                                            value: LetValue::AccessClause(AccessQuery::from([
                                                QueryPart::Key("block_device_mappings".to_string()),
                                            ]))
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
                                                        query: AccessQuery::from([
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllValues,
                                                            QueryPart::Key("Ebs".to_string())
                                                        ]),
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
                                                        query: AccessQuery::from([
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllValues,
                                                            QueryPart::Key("device_name".to_string())
                                                        ]),
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(Value::Regex("^/dev/ebs-".to_string()))),
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
                                                        query: AccessQuery::from([
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllValues,
                                                            QueryPart::Key("Ebs".to_string()),
                                                            QueryPart::Key("encrypted".to_string())
                                                        ]),
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(Value::Bool(true))),
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
                                                        query: AccessQuery::from([
                                                            QueryPart::Key("%volumes".to_string()),
                                                            QueryPart::AllValues,
                                                            QueryPart::Key("Ebs".to_string()),
                                                            QueryPart::Key("delete_on_termination".to_string())
                                                        ]),
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(Value::Bool(true))),
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
                                }
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
                                                        query: AccessQuery::from([
                                                            QueryPart::Key("block_device_mappings".to_string()),
                                                            QueryPart::AllValues,
                                                            QueryPart::Key("device_name".to_string())
                                                        ]),
                                                        comparator: (CmpOperator::Eq, false),
                                                        compare_with: Some(LetValue::Value(Value::Regex("^/dev/sdc-\\d".to_string()))),
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
                                }

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

    let rules_files = rules_file(from_str2(s))?;
    Ok(())
}

#[test]
fn test_rule_block_clause() -> Result<(), Error> {
    let s = "{ %select_lambda_service EMPTY or
     %select_lambda_service.Action.* == /sts:AssumeRole/ }";
    let span = from_str2(s);
    let rule_block = block(rule_block_clause)(span)?;
    Ok(())
}

#[test]
fn test_try_from_access() -> Result<(), Error> {
    let access = "%roles.Document";
    let access: AccessQueryWrapper = AccessQueryWrapper::try_from(access)?;
    let access = access.0;
    println!("{:?} {}", &access, SliceDisplay(&access));
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
                            comment: None
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
                                                    query: AccessQuery::from([
                                                        QueryPart::Key(String::from("tags")),
                                                        QueryPart::AllValues,
                                                        QueryPart::Key(String::from("key"))
                                                    ]),
                                                    comparator: (CmpOperator::In, false),
                                                    compare_with: Some(LetValue::Value(
                                                        Value::List(
                                                            vec![Value::String(String::from("ExternalS3Approved"))]
                                                        )
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
                            }
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
     %allowlist[ serviceAccount == %service_name ] !EMPTY
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
    let rule = Rule::try_from(r)?;
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
    let parsed = GuardClause::try_from(clause)?;

    let clause = r#"Statement[ Condition EXISTS
                                     Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] NOT EMPTY
    "#;
    let parsed = GuardClause::try_from(clause)?;
    Ok(())
}
