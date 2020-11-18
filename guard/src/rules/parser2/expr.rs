///
/// Parser Grammar for the CFN Guard rule syntax. Any enhancements to the grammar
/// **MUST** be reflected in this doc section.
///
/// Sample rule language example is as show below
///
/// ```pre
/// let global := [10, 20]                              # common vars for all rules
///
///  rule example_rule {
///    let ec2_instance_types := [/^t*/, /^m*/]   # var regex either t or m family
///
///     dependent_rule                              # named rule reference
///
///    # IN (disjunction, one of them)
///    AWS::EC2::Instance InstanceType IN %ec2_instance_types
///
///    AWS::EC2::Instance {                          # Either an EBS volume
///        let volumes := block_device_mappings      # var local, snake case allowed.
///        when %volumes.*.Ebs != null {                  # Ebs is setup
///          %volumes.*.device_name == /^\/dev\/ebs-/  # must have ebs in the name
///          %volumes.*.Ebs.encryped == true               # Ebs volume must be encryped
///          %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
///        }
///    } or
///    AWS::EC2::Instance {                   # OR a regular volume (disjunction)
///        block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
///    }
///  }
///
///  rule dependent_rule { ... }
/// ```
///
///  The grammar for the language in ABNF form
///
///
///
///  ```ABNF
///
///  or_term                    = "or" / "OR" / "|OR|"
///
///  var_name                   = 1*CHAR [ 1*(CHAR/ALPHA/_) ]
///  var_name_access            = "%" var_name
///
///  dotted_access              = "." (var_name / var_name_access / "*")
///
///  property_access            = var_name [ dotted_access ]
///  variable_access            = var_name_access [ dotted_access ]
///
///  access                     = variable_access /
///                               property_access
///
///  not_keyword                = "NOT" / "not" / "!"
///  basic_cmp                  = "==" / ">=" / "<=" / ">" / "<"
///  other_operators            = "IN" / "EXISTS" / "EMPTY"
///  not_other_operators        = not_keyword 1*SP other_operators
///  not_cmp                    = "!=" / not_other_operators / "NOT_IN"
///  special_operators          = "KEYS" 1*SP ("==" / other_operators / not_other_operators)
///
///  cmp                        = basic_cmp / other_operators / not_cmp / special_operators
///
///  clause                     = access 1*(LWSP/comment) cmp 1*(LWSP/comment) [(access/value)]
///  rule_clause                = rule_name / not_keyword rule_name / clause
///  rule_disjunction_clauses   = rule_clause 1*(or_term 1*(LWSP/comment) rule_clause)
///  rule_conjunction_clauses   = rule_clause 1*( (LSWP/comment) rule_clause )
///
///  type_clause                = type_name 1*SP clause
///  type_block                 = type_name *SP [when] "{" *(LWSP/comment) 1*clause "}"
///
///  type_expr                  = type_clause / type_block
///
///  disjunctions_type_expr     = type_expr 1*(or_term 1*(LWSP/comment) type_expr)
///
///  primitives                 = string / integer / float / regex
///  list_type                  = "[" *(LWSP/comment) *value *(LWSP/comment) "]"
///  map_type                   = "{" key_part *(LWSP/comment) ":" *(LWSP/comment) value
///                                   *(LWSP/comment) "}"
///  key_part                   = string / var_name
///  value                      = primitives / map_type / list_type
///
///  string                     = DQUOTE <any char not DQUOTE> DQUOTE /
///                               "'" <any char not '> "'"
///  regex                      = "/" <any char not / or escaped by \/> "/"
///
///  comment                    =  "#" *CHAR (LF/CR)
///  assignment                 = "let" one_or_more_ws  var_name zero_or_more_ws
///                                     ("=" / ":=") zero_or_more_ws (access/value)
///
///  when_type                  = when 1*( (LWSP/comment) clause (LWSP/comment) )
///  when_rule                  = when 1*( (LWSP/comment) rule_clause (LWSP/comment) )
///  named_rule                 = "rule" 1*SP var_name "{"
///                                   assignment 1*(LWPS/comment)   /
///                                   (type_expr 1*(LWPS/comment))  /
///                                   (disjunctions_type_expr) *(LWSP/comment) "}"
///
///  expressions                = 1*( (assignment / named_rule / type_expr / disjunctions_type_expr / comment) (LWPS/comment) )
///  ```
///
///

//
// Extern crate dependencies
//
use linked_hash_map::LinkedHashMap;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1, take_while, is_not, is_a, take_till};
use nom::character::complete::{alphanumeric1, char, digit1, one_of, alpha1};
use nom::character::complete::{anychar, space0, space1, multispace0, multispace1};
use nom::combinator::{map, map_res, opt, value, cut, all_consuming, rest, peek};
use nom::multi::{separated_list, separated_nonempty_list, many0, many1, fold_many1};
use nom::number::complete::double;
use nom::sequence::{delimited, preceded, separated_pair, tuple, terminated, pair};
use nom::{FindSubstring, InputTake};

use super::super::values::*;
use super::super::common::*;
use super::super::expr::*;

use nom_locate::LocatedSpan;
use nom::error::{ParseError, ErrorKind, context};
use std::fmt::Formatter;
use nom::character::{is_alphabetic, is_digit};

use super::*;
use super::common::*;
use super::values::parse_value;

//
// ABNF     =  1*CHAR [ 1*(CHAR / _) ]
//
// All names start with an alphabet and then can have _ intermixed with it. This
// combinator does not fail, it the responsibility of the consumer to fail based on
// the error
//
// Expected error codes:
//    nom::error::ErrorKind::Alpha => if the input does not start with a char
//
fn var_name(input: Span2) -> IResult<Span2, String> {
    let (remainder, first_part) = alpha1(input)?;
    let (remainder, next_part) = take_while(|c: char| c.is_alphanumeric() || c == '_')(remainder)?;
    let mut var_name = (*first_part.fragment()).to_string();
    var_name.push_str(*next_part.fragment());
    Ok((remainder, var_name))
}

//
//  var_name_access            = "%" var_name
//
//  This combinator does not fail, it is the responsibility of the consumer to fail based
//  on the error.
//
//  Expected error types:
//     nom::error::ErrorKind::Char => if if does not start with '%'
//
//  see var_name for other error codes
//
fn var_name_access(input: Span2) -> IResult<Span2, String> {
    preceded(char('%'), var_name)(input)
}

//
//  dotted_access              = "." (var_name / var_name_access / "*")
//
// This combinator does not fail. It is the responsibility of the consumer to fail based
// on error.
//
// Expected error types:
//    nom::error::ErrorKind::Char => if the start is not '.'
//
// see var_name, var_name_access for other error codes
//
fn dotted_access(input: Span2) -> IResult<Span2, Vec<String>> {
    fold_many1(
        preceded(
            char('.'),
            alt((
                var_name,
                map(var_name_access, |s| format!("%{}", s)),
                value("*".to_string(), char('*')),
                map(take_while1(|c: char| is_digit(c as u8)), |s: Span2| (*s.fragment()).to_string())
            ))),
        Vec::new(),
        |mut acc: Vec<String>, part| {
            acc.push(part);
            acc
        },
    )(input)
}

//
//   access     =   (var_name / var_name_access) [dotted_access]
//
fn access(input: Span2) -> IResult<Span2, PropertyAccess> {
    alt((
        map(pair(var_name_access, opt(dotted_access)),
            |(var_name, dotted)| PropertyAccess {
                var_access: Some(var_name),
                property_dotted_notation:
                if let Some(properties) = dotted { properties } else { vec![] },
            }),
        map(pair(var_name, opt(dotted_access)),
            |(first, dotted)| PropertyAccess {
                var_access: None,
                property_dotted_notation:
                if let Some(mut properties) = dotted {
                    properties.insert(0, first);
                    properties
                } else {
                    vec![first]
                },
            },
        )
    ))(input)
}

//
// Comparison operators
//
fn in_keyword(input: Span2) -> IResult<Span2, CmpOperator>{
    value(CmpOperator::In, alt((
        tag("in"),
        tag("IN")
    )))(input)
}

fn not(input: Span2) -> IResult<Span2, ()> {
    match alt((
        preceded(tag("not"), space1),
        preceded(tag("NOT"), space1)))(input) {
        Ok((remainder, _not)) => Ok((remainder, ())),

        Err(nom::Err::Error(_)) => {
            let (input, _bang_char) = char('!')(input)?;
            Ok((input, ()))
        },

        Err(e) => Err(e)
    }
}

fn eq(input: Span2) -> IResult<Span2, ValueOperator> {
    alt((
        value(ValueOperator::Cmp(CmpOperator::Eq), tag("==")),
        value(ValueOperator::Not(CmpOperator::Eq), tag("!=")),
    ))(input)
}

fn keys(input: Span2) -> IResult<Span2, ()> {
    value((), preceded(
        alt((
            tag("KEYS"),
            tag("keys"))), space1))(input)
}

fn keys_keyword(input: Span2) -> IResult<Span2, ValueOperator> {
    let (input, _keys_word) = keys(input)?;
    let (input, comparator) = alt((
        eq,
        other_operations,
    ))(input)?;

    let is_not = if let ValueOperator::Not(_) = &comparator { true } else { false };
    let comparator = match comparator {
        ValueOperator::Cmp(op) | ValueOperator::Not(op) => {
            match op {
                CmpOperator::Eq => CmpOperator::KeysEq,
                CmpOperator::In => CmpOperator::KeysIn,
                CmpOperator::Exists => CmpOperator::KeysExists,
                CmpOperator::Empty => CmpOperator::KeysEmpty,
                _ => unreachable!(),
            }
        }
    };

    let comparator = if is_not { ValueOperator::Not(comparator) }
    else { ValueOperator::Cmp(comparator) };
    Ok((input, comparator))
}

fn exists(input: Span2) -> IResult<Span2, CmpOperator> {
    value(CmpOperator::Exists, alt((tag("EXISTS"), tag("exists"))))(input)
}

fn empty(input: Span2) -> IResult<Span2, CmpOperator> {
    value(CmpOperator::Empty, alt((tag("EMPTY"), tag("empty"))))(input)
}

fn other_operations(input: Span2) -> IResult<Span2, ValueOperator> {
    let (input, not) = opt(not)(input)?;
    let (input, operation) = alt((
        in_keyword,
        exists,
        empty
    ))(input)?;
    let cmp = if not.is_some() { ValueOperator::Not(operation) } else { ValueOperator::Cmp(operation) };
    Ok((input, cmp))
}


fn value_cmp(input: Span2) -> IResult<Span2, ValueOperator> {
    alt((
        //
        // Basic cmp checks. Order does matter, you always go from more specific to less
        // specific. '>=' before '>' to ensure that we do not compare '>' first and conclude
        //
        eq,
        value(ValueOperator::Cmp(CmpOperator::Ge), tag(">=")),
        value(ValueOperator::Cmp(CmpOperator::Le), tag("<=")),
        value(ValueOperator::Cmp(CmpOperator::Gt), char('>')),
        value(ValueOperator::Cmp(CmpOperator::Lt), char('<')),

        //
        // Other operations
        //
        keys_keyword,
        other_operations,
    ))(input)
}

fn extract_message(input: Span2) -> IResult<Span2, &str> {
    match input.find_substring(">>") {
        None => Err(nom::Err::Failure(ParserError {
            span: input,
            kind: nom::error::ErrorKind::Tag,
            context: format!("Unable to find a closing >> tag for message")
        })),
        Some(v) => {
            let split = input.take_split(v);
            Ok((split.0, *split.1.fragment()))
        }
    }
}
fn custom_message(input: Span2) -> IResult<Span2, &str> {
    delimited(tag("<<"), extract_message, tag(">>"))(input)
}


fn clause(input: Span2) -> IResult<Span2, Clause> {
    let location = Location {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };

    let (rest, (lhs, _ignored_space, cmp, _ignored)) = tuple((
        access,
        // It is an failure to not have a ws/comment following it
        cut(one_or_more_ws_or_comment),
        // failure if there is no value_cmp
        cut(value_cmp),
        // failure if this isn't followed by space or comment or newline
        cut(one_or_more_ws_or_comment)))(input)?;

    let no_rhs_expected = match &cmp {
        ValueOperator::Cmp(op) | ValueOperator::Not(op) =>
            match op {
                CmpOperator::KeysExists     |
                CmpOperator::KeysEmpty      |
                CmpOperator::Empty          |
                CmpOperator::Exists => true,

                _ => false
            }
    };

    let parser = if no_rhs_expected {
        map(preceded(zero_or_more_ws_or_comment, opt(custom_message)),
            |msg| {
                (None, msg.map(String::from).or(None))
            })
    } else {
        alt((
            map(tuple((
                access, preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                |(rhs, msg)| {
                    (Some(LetValue::PropertyAccess(rhs)), msg.map(String::from).or(None))
                }),
            map(tuple((
                parse_value, preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                move |(rhs, msg)| {
                    (Some(LetValue::Value(rhs)), msg.map(String::from).or(None))
                })
        ))
    };

    let (rest, (compare_with, custom_message)) =
        cut(parser)(input)?;

    Ok((rest, Clause {
        access: lhs,
        comparator: cmp,
        compare_with,
        custom_message,
        location
    }))
}

//
//  ABNF        = "or" / "OR" / "|OR|"
//
fn or_term(input: Span2) -> IResult<Span2, Span2> {
    alt((
        tag("or"),
        tag("OR"),
        tag("|OR|")
    ))(input)
}

#[cfg(test)]
mod tests {
    use super::*;

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
                        context: "comment_whitespace".to_string(),
                    })), // white_space_or_comment
                Ok((from_str2(""), ())), // zero_or_more
                Err(nom::Err::Error(
                    ParserError {
                        span: from_str2(""),
                        kind: nom::error::ErrorKind::Char,
                        context: "one_or_more/comment_whitespace".to_string(),
                    })), // white_space_or_comment
            ],
            [
                Ok((unsafe { Span2::new_from_raw_offset(2, 1, "# this is a comment that needs to be discarded\n            ", "") }, ())), // white_space_or_comment, only consumes white-space)
                Ok((unsafe { Span2::new_from_raw_offset(examples[1].len(), 2, "", "") }, ())), // consumes everything
                Ok((unsafe { Span2::new_from_raw_offset(examples[1].len(), 2, "", "") }, ())), // consumes everything
            ],
            [
                //
                // Offset = 3 * '\n' + (col = 17) - 1 = 19
                //
                Ok((unsafe {
                    Span2::new_from_raw_offset(19, 4, r###"# all of this must be discarded as well
            "###, "")
                }, ())), // white_space_or_comment, only consumes white-space
                Ok((unsafe { Span2::new_from_raw_offset(examples[2].len(), 5, "", "") }, ())), // consumes everything
                Ok((unsafe { Span2::new_from_raw_offset(examples[2].len(), 5, "", "") }, ())), // consumes everything
            ],
            [
                Err(nom::Err::Error(
                    ParserError {
                        span: from_str2(examples[3]),
                        kind: nom::error::ErrorKind::Char,
                        context: "comment_whitespace".to_string(),
                    })), // white_space_or_comment
                Ok((from_str2(examples[3]), ())), // zero_or_more
                Err(nom::Err::Error(
                    ParserError {
                        span: from_str2(examples[3]),
                        kind: nom::error::ErrorKind::Char,
                        context: "one_or_more/comment_whitespace".to_string(),
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[2].len(),
                        1,
                        "",
                        "",
                    )
                },
                "var".to_string()
            )),
            Err(nom::Err::Error((
                ParserError {
                    span: unsafe {
                        Span2::new_from_raw_offset(
                            1,
                            1,
                            "_var",
                            "",
                        )
                    },
                    kind: nom::error::ErrorKind::Alpha,
                    context: "".to_string(),
                }))),
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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

    fn to_string_vec(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_string()).collect::<Vec<String>>()
    }

    #[test]
    fn test_dotted_access() {
        let examples = [
            "", // err
            ".", // err
            ".configuration.engine", // ok,
            ".config.engine.", // ok
            ".config.easy", // ok
            ".%engine_map.%engine", // ok
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
                        Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[4].len(),
                        1,
                        "",
                        "",
                    )
                },
                to_string_vec(&["config", "easy"])
            )),

            // ".%engine_map.%engine"
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[5].len(),
                        1,
                        "",
                        "",
                    )
                },
                to_string_vec(&["%engine_map", "%engine"])
            )),

            // ".*.*.port", // ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[6].len(),
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
                    Span2::new_from_raw_offset(
                        examples[7].len(),
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
                    Span2::new_from_raw_offset(
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
                    span: from_str2(examples[9]),
                    kind: nom::error::ErrorKind::Many1,
                    context: "".to_string(),
                }
            )),


            //".first.0.path ", // ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
            "engine.0", // 9 ok
            "engine .0", // 10 ok engine will be property access part
            "engine.ok.*",// 11 Ok
            "engine.%name.*", // 12 ok

            // testing variable access
            "%engine.type", // 13 ok
            "%engine.*.type.0", // 14 ok
            "%engine.%type.*", // 15 ok
            "%engine.%type.*.port", // 16 ok
            "%engine.*.", // 17 ok . is remainder

            " %engine", // 18 err
        ];

        let expectations = [
            Err(nom::Err::Error(ParserError { // 0
                span: from_str2(""),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),

            Err(nom::Err::Error(ParserError { // 1
                span: from_str2("."),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),

            Err(nom::Err::Error(ParserError { // 2
                span: from_str2(".engine"),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),

            Err(nom::Err::Error(ParserError { // 3
                span: from_str2(" engine"),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),

            Ok(( // 4
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[4].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine"]),
                     var_access: None,
                 }
            )),
            Ok(( // 5
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[5].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine", "type"]),
                     var_access: None,
                 }
            )),
            Ok(( // 6
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[6].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine", "type", "*"]),
                     var_access: None,
                 }
            )),
            Ok(( // 7
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[7].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine", "*", "type", "port"]),
                     var_access: None,
                 }
            )),
            Ok(( // 8
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[8].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine", "*", "type", "%var"]),
                     var_access: None,
                 }
            )),
            Ok(( // 9
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[9].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine", "0"]),
                     var_access: None,
                 }
            )),

            Ok(( // 10 "engine .0", // 10 ok engine will be property access part
                 unsafe {
                     Span2::new_from_raw_offset(
                         "engine".len(),
                         1,
                         " .0",
                         "",
                     )
                 },
                 PropertyAccess {
                     property_dotted_notation: to_string_vec(&["engine"]),
                     var_access: None,
                 }
            )),

            // "engine.ok.*",// 11 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[11].len(),
                        1,
                        "",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["engine", "ok", "*"]),
                    var_access: None,
                }
            )),

            // "engine.%name.*", // 12 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[12].len(),
                        1,
                        "",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["engine", "%name", "*"]),
                    var_access: None,
                }
            )),

            // "%engine.type", // 13 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[13].len(),
                        1,
                        "",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["type"]),
                    var_access: Some("engine".to_string()),
                }
            )),


            // "%engine.*.type.0", // 14 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[14].len(),
                        1,
                        "",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["*", "type", "0"]),
                    var_access: Some("engine".to_string()),
                }
            )),


            // "%engine.%type.*", // 15 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[15].len(),
                        1,
                        "",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["%type", "*"]),
                    var_access: Some("engine".to_string()),
                }
            )),


            // "%engine.%type.*.port", // 16 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[16].len(),
                        1,
                        "",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["%type", "*", "port"]),
                    var_access: Some("engine".to_string()),
                }
            )),


            // "%engine.*.", // 17 ok . is remainder
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[17].len() - 1,
                        1,
                        ".",
                        "",
                    )
                },
                PropertyAccess {
                    property_dotted_notation: to_string_vec(&["*"]),
                    var_access: Some("engine".to_string()),
                }
            )),


            // " %engine", // 18 err
            Err(nom::Err::Error(ParserError { // 18
                span: from_str2(" %engine"),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),

        ];

        for (idx, each) in examples.iter().enumerate() {
            let span = Span2::new_extra(examples[idx], "");
            let result = access(span);
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
                kind: nom::error::ErrorKind::Tag
            })),

            // " exists", // 1 err
            Err(nom::Err::Error(ParserError {
                span: from_str2(" exists"),
                context: "".to_string(),
                kind: nom::error::ErrorKind::Tag
            })),

            // "exists", // 2 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[2].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::Exists),
            )),

            // "not exists", // 3 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[3].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::Exists),
            )),

            // "!exists", // 4 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[4].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::Exists),
            )),

            // "!EXISTS", // 5 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[5].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::Exists),
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
                    Span2::new_from_raw_offset(
                        examples[7].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::In),
            )),

            // "not in", // 8 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[8].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::In),
            )),

            // "!in", // 9 ok,
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[9].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::In),
            )),

            // "EMPTY", // 10 ok,
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[10].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::Empty),
            )),

            // "! EMPTY", // 11 err
            Err(nom::Err::Error(
                ParserError {
                    span: unsafe {
                        Span2::new_from_raw_offset(
                            1,
                            1,
                            " EMPTY",
                            ""
                        )
                    },
                    kind: nom::error::ErrorKind::Tag,
                    context: "".to_string(),
                }
            )),

            // "NOT EMPTY", // 12 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[12].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::Empty),
            )),

            // "IN [\"t\", \"n\"]", // 13 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        2,
                        1,
                        " [\"t\", \"n\"]",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::In),
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
                    Span2::new_from_raw_offset(
                        examples[1].len(),
                        1,
                        "",
                        ""
                    )
                },
                kind: nom::error::ErrorKind::Space,
                context: "".to_string(),
            })),

            // "KEYS IN", // 2 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[2].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::KeysIn),
            )),

            // "KEYS NOT IN", // 3 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[3].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::KeysIn),
            )),

            // "KEYS EXISTS", // 4 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[4].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::KeysExists),
            )),

            // "KEYS !EXISTS", // 5 Ok,
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[5].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::KeysExists),
            )),

            // "KEYS ==", // 6 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[6].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::KeysEq),
            )),

            // "KEYS !=", // 7 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[7].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::KeysEq),
            )),

            // "keys ! in", // 8 err after !
            Err(nom::Err::Error(ParserError {
                span: unsafe {
                    Span2::new_from_raw_offset(
                        "keys !".len(),
                        1,
                        " in",
                        ""
                    )
                },
                kind: nom::error::ErrorKind::Tag,
                context: "".to_string(),
            })),

            // "KEYS EMPTY", // 9 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[9].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Cmp(CmpOperator::KeysEmpty),
            )),

            // "KEYS !EMPTY", // 10 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[10].len(),
                        1,
                        "",
                        ""
                    )
                },
                ValueOperator::Not(CmpOperator::KeysEmpty),
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
                    Span2::new_from_raw_offset(
                        "KEYS ".len(),
                        1,
                        "",
                        ""
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
            ""
        ];
    }

}
