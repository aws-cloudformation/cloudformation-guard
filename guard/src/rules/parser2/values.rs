//
// Extern crate dependencies
//
use linked_hash_map::LinkedHashMap;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1, take_while, is_not, is_a};
use nom::character::complete::{alphanumeric1, char, digit1, one_of};
use nom::character::complete::{anychar, space0, space1, multispace0,  multispace1};
use nom::combinator::{map, map_res, opt, value, cut, all_consuming, rest, peek};
use nom::multi::{separated_list, separated_nonempty_list, many0, many1};
use nom::number::complete::double;
use nom::sequence::{delimited, preceded, separated_pair, tuple, terminated};
use nom::{FindSubstring, InputTake};

use crate::rules::values::*;
use super::*;
use super::common::*;

use nom_locate::LocatedSpan;
pub(crate) type Span<'a> = LocatedSpan<&'a str, &'a str>;

pub(crate) fn from_str(in_str: &str) -> Span {
    Span::new_extra(in_str, "")
}

//
// Local crate
//
use crate::rules::values::{Value, RangeType, LOWER_INCLUSIVE, UPPER_INCLUSIVE};
use crate::rules::parser2::common::zero_or_more_ws_or_comment;

//
// Rust std crate
//

///
/// Scalar Values string, bool, int, f64
///

fn parse_int_value(input: Span) -> IResult<Span, Value> {
    let negative = map_res(preceded(tag("-"), digit1), |s: Span| {
        s.fragment().parse::<i64>().map(|i| Value::Int(-1 * i))
    });
    let positive = map_res(digit1, |s: Span| {
        s.fragment().parse::<i64>().map(Value::Int)
    });
    alt((positive, negative))(input)
}

fn parse_string(input: Span) -> IResult<Span, Value> {
    map(
        alt((
            delimited(
                tag("\""),
                take_while(|c| c != '"'),
                tag("\"")),
            delimited(
                tag(from_str("'")),
                take_while(|c| c != '\''),
                tag(from_str("'"))),
        )),
        |s: Span| Value::String((*s.fragment()).to_string()),
    )(input)
}

fn parse_bool(input: Span) -> IResult<Span, Value> {
    let true_parser = value(Value::Bool(true), alt((tag("true"), tag("True"))));
    let false_parser = value(Value::Bool(false), alt((tag("false"), tag("False"))));
    alt((true_parser, false_parser))(input)
}

fn parse_float(input: Span) -> IResult<Span, Value> {
    let whole = digit1(input.clone())?;
    let fraction = opt(preceded(char('.'), digit1))(whole.0)?;
    let exponent = opt(tuple((one_of("eE"), one_of("+-"), digit1)))(fraction.0)?;
    if (fraction.1).is_some() || (exponent.1).is_some() {
        let r = double(input)?;
        return Ok((r.0, Value::Float(r.1)));
    }
    Err(nom::Err::Error(ParserError {
        context: format!("Could not parse floating number"),
        kind: nom::error::ErrorKind::Float,
        span: input
    }))
}

fn parse_regex_inner(input: Span) -> IResult<Span, Value> {
    let mut regex = String::new();
    let parser = is_not("/");
    let mut span = input;
    loop {
        let (remainder, content) = parser(span)?;
        let fragment = *content.fragment();
        //
        // if the last one has an escape, then we need to continue
        //
        if fragment.len() > 0 && fragment.ends_with("\\") {
            regex.push_str(&fragment[0..fragment.len()-1]);
            regex.push('/');
            span = remainder.take_split(1).0;
            continue;
        }
        regex.push_str(fragment);
        return Ok((remainder, Value::Regex(regex)));
    }
}

fn parse_regex(input: Span) -> IResult<Span, Value> {
    delimited(char('/'), parse_regex_inner, char('/'))(input)
}

fn parse_char(input: Span) -> IResult<Span, Value> {
    map(anychar, Value::Char)(input)
}

fn range_value(input: Span) -> IResult<Span, Value> {
    delimited(
        space0,
        alt((parse_float, parse_int_value, parse_char)),
        space0,
    )(input)
}

fn parse_range(input: Span) -> IResult<Span, Value> {
    let parsed = preceded(
        char('r'),
        tuple((
            one_of("(["),
            separated_pair(range_value, char(','), range_value),
            one_of(")]"),
        )),
    )(input)?;
    let (open, (start, end), close) = parsed.1;
    let mut inclusive: u8 = if open == '[' { LOWER_INCLUSIVE } else { 0u8 };
    inclusive |= if close == ']' { UPPER_INCLUSIVE } else { 0u8 };
    let val = match (start, end) {
        (Value::Int(s), Value::Int(e)) => Value::RangeInt(RangeType {
            upper: e,
            lower: s,
            inclusive,
        }),

        (Value::Float(s), Value::Float(e)) => Value::RangeFloat(RangeType {
            upper: e,
            lower: s,
            inclusive,
        }),

        (Value::Char(s), Value::Char(e)) => Value::RangeChar(RangeType {
            upper: e,
            lower: s,
            inclusive,
        }),

        _ => return Err(nom::Err::Failure(ParserError {
            span: parsed.0,
            kind: nom::error::ErrorKind::IsNot,
            context: format!("Could not parse range")
        }))
    };
    Ok((parsed.0, val))
}

//
// Adding the parser to return scalar values
//
fn parse_scalar_value(input: Span) -> IResult<Span, Value> {
    //
    // IMP: order does matter
    // parse_float is before parse_int. the later can parse only the whole part of the float
    // to match.
    alt((
        parse_string,
        parse_float,
        parse_int_value,
        parse_bool,
        parse_regex,
    ))(input)
}

///
/// List Values
///

fn parse_list(input: Span) -> IResult<Span, Value> {
    map(
        delimited(
            preceded_by('['),
            separated_list(separated_by(','), parse_value),
            followed_by(']'),
        ),
        |l| Value::List(l),
    )(input)
}

fn key_part(input: Span) -> IResult<Span, String> {
    alt((
        map(alphanumeric1,
            |s: Span| (*s.fragment()).to_string()),
        map(parse_string, |v| {
            if let Value::String(s) = v {
                s
            }
            else {
                unreachable!()
            }
        })))(input)
}

fn key_value(input: Span) -> IResult<Span, (String, Value)> {
    separated_pair(
        preceded(zero_or_more_ws_or_comment, key_part),
        followed_by(':'),
        parse_value,
    )(input)
}

fn parse_map(input: Span) -> IResult<Span, Value> {
    let result = delimited(
        char('{'),
        separated_list(separated_by(','), key_value),
        followed_by('}'),
    )(input)?;
    Ok((
        result.0,
        Value::Map(
            result
                .1
                .into_iter()
                .collect::<LinkedHashMap<String, Value>>(),
        ),
    ))
}

fn parse_null(input: Span) -> IResult<Span, Value> {
    value(Value::Null, alt((tag("null"), tag("NULL"))))(input)
}

pub(super) fn parse_value(input: Span) -> IResult<Span, Value> {
    preceded(
        zero_or_more_ws_or_comment,
        alt((
            parse_null,
            parse_scalar_value,
            parse_range,
            parse_list,
            parse_map,
        )),
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::values::WithinRange;
    use crate::rules::values::make_linked_hashmap;

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
            Ok((cmp, Value::Map(LinkedHashMap::new())))
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


}

