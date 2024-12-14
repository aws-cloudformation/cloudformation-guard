use fancy_regex::Regex;
use std::convert::TryFrom;
use std::fmt::{Display, Formatter, Result as FmtResult};

use indexmap::map::IndexMap;
use nom::branch::alt;
use nom::bytes::complete::{is_not, take_while, take_while1};
use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{alpha1, space1};
use nom::character::complete::{anychar, digit1, one_of};
use nom::character::complete::{char, multispace0, multispace1, space0};
use nom::combinator::{all_consuming, cut, peek};
use nom::combinator::{map, value};
use nom::combinator::{map_res, opt};
use nom::error::context;
use nom::error::ErrorKind;
use nom::multi::{fold_many1, separated_list, separated_nonempty_list};
use nom::multi::{many0, many1};
use nom::number::complete::double;
use nom::sequence::{delimited, preceded};
use nom::sequence::{pair, terminated};
use nom::sequence::{separated_pair, tuple};
use nom::{FindSubstring, InputTake, Slice};
use nom_locate::LocatedSpan;

use crate::rules::errors::Error;
use crate::rules::eval_context::FunctionName;
use crate::rules::exprs::*;
use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::values::*;

pub(crate) type Span<'a> = LocatedSpan<&'a str, &'a str>;
const DEFAULT_RULE_NAME: &str = "default";

pub(crate) fn from_str2(in_str: &str) -> Span {
    Span::new_extra(in_str, "")
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ParserError<'a> {
    pub(crate) context: String,
    pub(crate) span: Span<'a>,
    pub(crate) kind: ErrorKind,
}

pub(crate) type IResult<'a, I, O> = nom::IResult<I, O, ParserError<'a>>;

impl<'a> nom::error::ParseError<Span<'a>> for ParserError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        ParserError {
            context: "".to_string(),
            span: input,
            kind,
        }
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }

    fn add_context(input: Span<'a>, ctx: &'static str, other: Self) -> Self {
        let context = if other.context.is_empty() {
            ctx.to_string()
        } else {
            format!("{}/{}", ctx, other.context)
        };

        ParserError {
            context,
            span: input,
            kind: other.kind,
        }
    }
}

impl<'a> std::fmt::Display for ParserError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = format!(
            "Error parsing file {} at line {} at column {}, when handling {}, fragment {}",
            self.span.extra,
            self.span.location_line(),
            self.span.get_utf8_column(),
            self.context,
            *self.span.fragment()
        );
        f.write_str(&message)?;
        Ok(())
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                         HELPER METHODS                                                         //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub(in crate::rules) fn comment2(input: Span) -> IResult<Span, Span> {
    delimited(char('#'), take_till(|c| c == '\n'), multispace0)(input)
}
//
// This function extracts either white-space-CRLF or a comment
// and discards them
//
// (LWSP / comment)
//
// Expected error codes: (remember alt returns the error from the last one)
//    nom::error::ErrorKind::Char => if the comment does not start with '#'
//
pub(in crate::rules) fn white_space_or_comment(input: Span) -> IResult<Span, ()> {
    value((), alt((multispace1, comment2)))(input)
}

//
// This provides extract for 1*(LWSP / comment). It does not indicate
// failure when this isn't the case. Consumers of this combinator must use
// cut or handle it as a failure if that is the right outcome
//
pub(in crate::rules) fn one_or_more_ws_or_comment(input: Span) -> IResult<Span, ()> {
    value((), many1(white_space_or_comment))(input)
}

//
// This provides extract for *(LWSP / comment), same as above but this one never
// errors out
//
pub(in crate::rules) fn zero_or_more_ws_or_comment(input: Span) -> IResult<Span, ()> {
    value((), many0(white_space_or_comment))(input)
}

pub(in crate::rules) fn white_space(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    move |input: Span| preceded(zero_or_more_ws_or_comment, char(ch))(input)
}

pub(in crate::rules) fn preceded_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn separated_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn followed_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                          Value Type Parsing Routines                                           //
//                                                                                                //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

pub(in crate::rules) fn parse_int_value(input: Span) -> IResult<Span, Value> {
    let negative = map_res(preceded(tag("-"), digit1), |s: Span| {
        s.fragment().parse::<i64>().map(|i| Value::Int(-i))
    });
    let positive = map_res(digit1, |s: Span| {
        s.fragment().parse::<i64>().map(Value::Int)
    });
    alt((positive, negative))(input)
}

fn parse_string_inner(ch: char) -> impl Fn(Span) -> IResult<Span, Value> {
    move |input: Span| {
        let mut completed = String::new();
        let (input, _begin) = char(ch)(input)?;
        let mut span = input;
        loop {
            let (remainder, upto) = take_while(|c| c != ch)(span)?;
            let frag = *upto.fragment();
            if frag.ends_with('\\') {
                completed.push_str(frag.slice(0..frag.len() - 1));
                completed.push(ch);

                if remainder.is_empty() {
                    return Err(nom::Err::Error(ParserError {
                        context: String::from("Could not parse string"),
                        kind: ErrorKind::Char,
                        span: input,
                    }));
                }

                span = remainder.slice(1..);
                continue;
            }
            completed.push_str(frag);
            let (remainder, _end) = cut(char(ch))(remainder)?;
            return Ok((remainder, Value::String(completed)));
        }
    }
}

pub(crate) fn parse_string(input: Span) -> IResult<Span, Value> {
    alt((parse_string_inner('\''), parse_string_inner('\"')))(input)
    //    map(
    //        alt((
    //            delimited(
    //                char('"'),
    //                take_while(|c| c != '"'),
    //                char('"')),
    //            delimited(
    //                char('\''),
    //                take_while(|c| c != '\''),
    //                char('\'')),
    //        )),
    //        |s: Span| Value::String((*s.fragment()).to_string()),
    //    )(input)
}

fn parse_bool(input: Span) -> IResult<Span, Value> {
    let true_parser = value(Value::Bool(true), alt((tag("true"), tag("True"))));
    let false_parser = value(Value::Bool(false), alt((tag("false"), tag("False"))));
    alt((true_parser, false_parser))(input)
}

fn parse_float(input: Span) -> IResult<Span, Value> {
    let whole = digit1(input)?;
    let fraction = opt(preceded(char('.'), digit1))(whole.0)?;
    let exponent = opt(tuple((one_of("eE"), one_of("+-"), digit1)))(fraction.0)?;
    if (fraction.1).is_some() || (exponent.1).is_some() {
        let r = double(input)?;
        return Ok((r.0, Value::Float(r.1)));
    }
    Err(nom::Err::Error(ParserError {
        context: "Could not parse floating number".to_string(),
        kind: ErrorKind::Float,
        span: input,
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
        if !fragment.is_empty() && fragment.ends_with('\\') {
            regex.push_str(&fragment[0..fragment.len() - 1]);
            regex.push('/');

            if remainder.is_empty() {
                return Err(nom::Err::Error(ParserError {
                    context: "Could not parse regular expression".to_string(),
                    kind: ErrorKind::RegexpMatch,
                    span: input,
                }));
            }
            span = remainder.take_split(1).0;
            continue;
        }

        regex.push_str(fragment);

        return match Regex::try_from(regex.as_str()) {
            Ok(_) => Ok((remainder, Value::Regex(regex))),
            Err(e) => Err(nom::Err::Error(ParserError {
                context: format!("Could not parse regular expression: {}", e),
                kind: ErrorKind::RegexpMatch,
                span: input,
            })),
        };
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

        _ => {
            return Err(nom::Err::Failure(ParserError {
                span: parsed.0,
                kind: ErrorKind::IsNot,
                context: "Could not parse range".to_string(),
            }))
        }
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
        Value::List,
    )(input)
}

fn key_part(input: Span) -> IResult<Span, String> {
    alt((
        map(
            take_while1(|c: char| c.is_alphanumeric() || c == '-' || c == '_'),
            |s: Span| (*s.fragment()).to_string(),
        ),
        map(parse_string, |v| {
            if let Value::String(s) = v {
                s
            } else {
                unreachable!()
            }
        }),
    ))(input)
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
        Value::Map(result.1.into_iter().collect::<IndexMap<String, Value>>()),
    ))
}

fn parse_null(input: Span) -> IResult<Span, Value> {
    value(Value::Null, alt((tag("null"), tag("NULL"))))(input)
}

pub(crate) fn parse_value(input: Span) -> IResult<Span, Value> {
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

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                          Expressions Parsing Routines                                          //
//                                                                                                //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

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
///          %volumes.*.Ebs.encrypted == true               # Ebs volume must be encrypted
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
///  rule_conjunction_clauses   = rule_clause 1*( (LWSP/comment) rule_clause )
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
///                                   assignment 1*(LWSP/comment)   /
///                                   (type_expr 1*(LWSP/comment))  /
///                                   (disjunctions_type_expr) *(LWSP/comment) "}"
///
///  expressions                = 1*( (assignment / named_rule / type_expr / disjunctions_type_expr / comment) (LWSP/comment) )
///  ```
///
///

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
pub(crate) fn var_name(input: Span) -> IResult<Span, String> {
    let (remainder, first_part) = alpha1(input)?;
    let (remainder, next_part) = take_while(|c: char| c.is_alphanumeric() || c == '_')(remainder)?;
    let mut var_name = (*first_part.fragment()).to_string();
    var_name.push_str(next_part.fragment());
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
pub(crate) fn var_name_access(input: Span) -> IResult<Span, String> {
    preceded(char('%'), var_name)(input)
}

//
// This version is the same as var_name_access
//
fn var_name_access_inclusive(input: Span) -> IResult<Span, String> {
    map(var_name_access, |s| format!("%{}", s))(input)
}

//
// Comparison operators
//
fn in_keyword(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::In, alt((tag("in"), tag("IN"))))(input)
}

fn not(input: Span) -> IResult<Span, ()> {
    match alt((preceded(tag("not"), space1), preceded(tag("NOT"), space1)))(input) {
        Ok((remainder, _not)) => Ok((remainder, ())),

        Err(nom::Err::Error(_)) => {
            let (input, _bang_char) = char('!')(input)?;
            Ok((input, ()))
        }

        Err(e) => Err(e),
    }
}

fn eq(input: Span) -> IResult<Span, (CmpOperator, bool)> {
    alt((
        value((CmpOperator::Eq, false), tag("==")),
        value((CmpOperator::Eq, true), tag("!=")),
    ))(input)
}

fn keys(input: Span) -> IResult<Span, ()> {
    value((), alt((tag("KEYS"), tag("keys"))))(input)
}

fn exists(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::Exists, alt((tag("EXISTS"), tag("exists"))))(input)
}

fn empty(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::Empty, alt((tag("EMPTY"), tag("empty"))))(input)
}

fn other_operations(input: Span) -> IResult<Span, (CmpOperator, bool)> {
    let (input, not) = opt(not)(input)?;
    let (input, operation) = alt((in_keyword, exists, empty, is_type_operations))(input)?;
    Ok((input, (operation, not.is_some())))
}

fn is_list(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::IsList, alt((tag("IS_LIST"), tag("is_list"))))(input)
}

fn is_struct(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsMap,
        alt((tag("IS_STRUCT"), tag("is_struct"))),
    )(input)
}

fn is_string(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsString,
        alt((tag("IS_STRING"), tag("is_string"))),
    )(input)
}

fn is_bool(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::IsBool, alt((tag("IS_BOOL"), tag("is_bool"))))(input)
}

fn is_int(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::IsInt, alt((tag("IS_INT"), tag("is_int"))))(input)
}

fn is_float(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsFloat,
        alt((tag("IS_FLOAT"), tag("is_float"))),
    )(input)
}

fn is_null(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::IsNull, alt((tag("IS_NULL"), tag("is_null"))))(input)
}

fn is_type_operations(input: Span) -> IResult<Span, CmpOperator> {
    alt((
        is_string, is_list, is_struct, is_bool, is_int, is_null, is_float,
    ))(input)
}

pub(crate) fn value_cmp(input: Span) -> IResult<Span, (CmpOperator, bool)> {
    //
    // This is really crappy as the earlier version used << for custom message
    // delimiter. '<' can be interpreted as Lt comparator.
    // TODO revisit the custom message delimiter
    //
    let (input, is_custom_message_start) = peek(opt(value(true, tag("<<"))))(input)?;
    if is_custom_message_start.is_some() {
        return Err(nom::Err::Error(ParserError {
            span: input,
            context: "Custom message tag detected".to_string(),
            kind: ErrorKind::Tag,
        }));
    }

    alt((
        //
        // Basic cmp checks. Order does matter, you always go from more specific to less
        // specific. '>=' before '>' to ensure that we do not compare '>' first and conclude
        //
        eq,
        value((CmpOperator::Ge, false), tag(">=")),
        value((CmpOperator::Le, false), tag("<=")),
        value((CmpOperator::Gt, false), char('>')),
        value((CmpOperator::Lt, false), char('<')),
        //
        // Other operations
        //
        // keys_keyword,
        other_operations,
    ))(input)
}

fn extract_message(input: Span) -> IResult<Span, &str> {
    match input.find_substring(">>") {
        None => Err(nom::Err::Failure(ParserError {
            span: input,
            kind: ErrorKind::Tag,
            context: "Unable to find a closing >> tag for message".to_string(),
        })),
        Some(v) => {
            let split = input.take_split(v);
            Ok((split.0, *split.1.fragment()))
        }
    }
}

fn custom_message(input: Span) -> IResult<Span, &str> {
    delimited(tag("<<"), extract_message, tag(">>"))(input)
}

pub(crate) fn does_comparator_have_rhs(op: &CmpOperator) -> bool {
    !op.is_unary()
}

fn variable_capture_in_map_or_index(input: Span) -> IResult<Span, String> {
    let (input, var) = preceded(zero_or_more_ws_or_comment, var_name)(input)?;
    let (input, _pipe) = preceded(space0, char('|'))(input)?;
    Ok((input, var))
}

fn predicate_filter_clauses(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    let (input, var) = opt(variable_capture_in_map_or_index)(input)?;
    let (input, filters) = cnf_clauses(input, clause, std::convert::identity, true)?;
    let (input, _close) = cut(close_array)(input)?;
    Ok((input, QueryPart::Filter(var, filters)))
}

fn dotted_property(input: Span) -> IResult<Span, QueryPart> {
    preceded(
        zero_or_more_ws_or_comment,
        preceded(
            char('.'),
            alt((
                map(parse_int_value, |idx| {
                    let idx = match idx {
                        Value::Int(i) => i as i32,
                        _ => unreachable!(),
                    };
                    QueryPart::Index(idx)
                }),
                map(property_name, QueryPart::Key),
                map(var_name_access_inclusive, QueryPart::Key),
                value(QueryPart::AllValues(None), char('*')),
            )), // end alt
        ), // end preceded for char '.'
    )(input)
}

fn open_array(input: Span) -> IResult<Span, ()> {
    value((), preceded(zero_or_more_ws_or_comment, char('[')))(input)
}

fn close_array(input: Span) -> IResult<Span, ()> {
    value((), preceded(zero_or_more_ws_or_comment, char(']')))(input)
}

fn all_indices(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    let (input, query_part) = alt((
        value(
            QueryPart::AllIndices(None),
            preceded(zero_or_more_ws_or_comment, char('*')),
        ),
        map(var_name, |name| QueryPart::AllIndices(Some(name))),
    ))(input)?;
    let (input, _close) = close_array(input)?;
    Ok((input, query_part))
}

fn array_index(input: Span) -> IResult<Span, QueryPart> {
    map(
        delimited(open_array, parse_int_value, cut(close_array)),
        |idx| {
            let idx = match idx {
                Value::Int(i) => i as i32,
                _ => unreachable!(),
            };
            QueryPart::Index(idx)
        },
    )(input)
}

fn map_key_lookup(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    let (input, query_part) = alt((
        map(parse_string, |idx| {
            let idx = match idx {
                Value::String(i) => i,
                _ => unreachable!(),
            };
            QueryPart::Key(idx)
        }),
        map(
            delimited(
                zero_or_more_ws_or_comment,
                var_name,
                zero_or_more_ws_or_comment,
            ),
            |name| QueryPart::AllValues(Some(name)),
        ),
    ))(input)?;
    let (input, _close) = close_array(input)?;
    Ok((input, query_part))
}

fn map_keys_match(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    let (input, var) = opt(variable_capture_in_map_or_index)(input)?;
    let (input, _keys) = preceded(zero_or_more_ws_or_comment, keys)(input)?;
    let (input, cmp) = cut(preceded(
        zero_or_more_ws_or_comment,
        alt((
            eq,
            value((CmpOperator::In, false), in_keyword),
            map(tuple((not, in_keyword)), |_m| (CmpOperator::In, true)),
        )),
    ))(input)?;
    let (input, with) = cut(preceded(
        zero_or_more_ws_or_comment,
        alt((
            map(parse_value, |value| {
                LetValue::Value(PathAwareValue::try_from(value).unwrap())
            }),
            map(
                preceded(zero_or_more_ws_or_comment, access),
                LetValue::AccessClause,
            ),
        )),
    ))(input)?;
    let (input, _close) = close_array(input)?;
    Ok((
        input,
        QueryPart::MapKeyFilter(
            var,
            MapKeyFilterClause {
                comparator: cmp,
                compare_with: with,
            },
        ),
    ))
}

fn predicate_or_index(input: Span) -> IResult<Span, QueryPart> {
    alt((
        all_indices,
        array_index,
        map_key_lookup,
        map_keys_match,
        predicate_filter_clauses,
    ))(input)
}

//
//  dotted_access              = "." (var_name / "*")
//
// This combinator does not fail. It is the responsibility of the consumer to fail based
// on error.
//
// Expected error types:
//    nom::error::ErrorKind::Char => if the start is not '.'
//
// see var_name, var_name_access for other error codes
//
fn dotted_access(input: Span) -> IResult<Span, Vec<QueryPart>> {
    fold_many1(
        alt((dotted_property, predicate_or_index)),
        Vec::new(),
        |mut acc: Vec<QueryPart>, part| {
            acc.push(part);
            acc
        },
    )(input)
}

fn property_name(input: Span) -> IResult<Span, String> {
    alt((
        var_name,
        map(parse_string, |v| match v {
            Value::String(value) => value,
            _ => unreachable!(),
        }),
    ))(input)
}

fn some_keyword(input: Span) -> IResult<Span, bool> {
    value(
        true,
        delimited(
            zero_or_more_ws_or_comment,
            alt((tag("SOME"), tag("some"))),
            one_or_more_ws_or_comment,
        ),
    )(input)
}

fn this_keyword(input: Span) -> IResult<Span, QueryPart> {
    preceded(
        zero_or_more_ws_or_comment,
        alt((
            value(QueryPart::This, tag("this")),
            value(QueryPart::This, tag("THIS")),
        )),
    )(input)
}

//
//   access     =   (var_name / var_name_access) [dotted_access]
//
pub(crate) fn access(input: Span) -> IResult<Span, AccessQuery> {
    map(
        tuple((
            opt(some_keyword),
            alt((
                this_keyword,
                map(
                    alt((var_name_access_inclusive, property_name)),
                    QueryPart::Key,
                ),
            )),
            opt(dotted_access),
        )),
        |(any, first, remainder)| {
            let query_parts = match remainder {
                Some(mut parts) => {
                    parts.insert(0, first.clone());
                    if first.is_variable() {
                        match parts.get(1) {
                            Some(QueryPart::AllIndices(_)) => {}
                            _ => {
                                parts.insert(1, QueryPart::AllIndices(None));
                            }
                        }
                    }
                    parts
                }

                None => {
                    vec![first]
                }
            };
            AccessQuery {
                query: query_parts,
                match_all: any.is_none(),
            }
        },
    )(input)
}

#[allow(clippy::redundant_closure)]
fn clause_with_map<'loc, A, M, T: 'loc>(
    input: Span<'loc>,
    access: A,
    mapper: M,
) -> IResult<Span<'loc>, T>
where
    A: Fn(Span<'loc>) -> IResult<Span<'loc>, AccessQuery<'loc>>,
    M: Fn(GuardAccessClause<'loc>) -> T + 'loc,
{
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };

    let (rest, not) = preceded(zero_or_more_ws_or_comment, opt(not))(input)?;
    let (rest, (query, cmp)) = map(tuple((
        |a| access(a),
        context("expecting one or more WS or comment blocks", zero_or_more_ws_or_comment),
        // error if there is no value_cmp, has to exist
        context("expecting comparison binary operators like >, <= or unary operators KEYS, EXISTS, EMPTY or NOT",
                value_cmp)
    )), |(query, _ign, value)| {
        (query, value)
    })(rest)?;

    if !does_comparator_have_rhs(&cmp.0) {
        let (rest, custom_message) = map(
            preceded(zero_or_more_ws_or_comment, opt(custom_message)),
            |msg| msg.map(String::from),
        )(rest)?;
        Ok((
            rest,
            mapper(GuardAccessClause {
                access_clause: AccessClause {
                    query,
                    comparator: cmp,
                    compare_with: None,
                    custom_message,
                    location,
                },
                negation: not.is_some(),
            }),
        ))
    } else {
        let (rest, (compare_with, custom_message)) =
            context("expecting either a property access \"engine.core\" or value like \"string\" or [\"this\", \"that\"]",
                    cut(alt((
                        //
                        // Order does matter here as true/false and other values can be interpreted as access
                        //
                        map(tuple((
                            parse_value, preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            move |(rhs, msg)| {
                                (Some(LetValue::Value(PathAwareValue::try_from(rhs).unwrap())), msg.map(String::from).or(None))
                            }),
                       map(tuple((
                            preceded(zero_or_more_ws_or_comment, function_expr),
                            preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            |(rhs, msg)| {
                                (Some(LetValue::FunctionCall(rhs)), msg.map(String::from).or(None))
                            }),
                        map(tuple((
                            preceded(zero_or_more_ws_or_comment, access),
                            preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            |(rhs, msg)| {
                                (Some(LetValue::AccessClause(rhs)), msg.map(String::from).or(None))
                            }),

                    ))))(rest)?;
        Ok((
            rest,
            mapper(GuardAccessClause {
                access_clause: AccessClause {
                    query,
                    comparator: cmp,
                    compare_with,
                    custom_message,
                    location,
                },
                negation: not.is_some(),
            }),
        ))
    }
}

fn clause_with<A>(input: Span, access: A) -> IResult<Span, GuardClause>
where
    A: Fn(Span) -> IResult<Span, AccessQuery>,
{
    clause_with_map(input, access, GuardClause::Clause)
}

pub(crate) fn block_clause(input: Span) -> IResult<Span, GuardClause> {
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };

    let (input, query) = access(input)?;
    let (input, not_empty) = opt(value(
        true,
        preceded(zero_or_more_ws_or_comment, tuple((not, empty))),
    ))(input)?;
    let (input, (assignments, conjunctions)) = block(clause)(input)?;
    Ok((
        input,
        GuardClause::BlockClause(BlockGuardClause {
            query,
            block: Block {
                assignments,
                conjunctions,
            },
            location,
            not_empty: not_empty.map_or(false, std::convert::identity),
        }),
    ))
}

fn function_expr(input: Span) -> IResult<Span, FunctionExpr> {
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_column() as u32,
    };
    let (input, (name, parameters)) = call_expr(input)?;

    let name = FunctionName::try_from(name.as_str()).map_err(|e| {
        nom::Err::Error(ParserError {
            context: e.to_string(),
            span: input,
            kind: ErrorKind::AlphaNumeric,
        })
    })?;

    if parameters.len() != name.get_expected_number_of_args() {
        return Err(nom::Err::Error(ParserError {
            context: format!(
                "function: {name} requires: {} parameters to be passed, but received: {}",
                name.get_expected_number_of_args(),
                parameters.len()
            ),
            span: input,
            kind: ErrorKind::AlphaNumeric,
        }));
    }

    Ok((
        input,
        FunctionExpr {
            location,
            name,
            parameters,
        },
    ))
}

pub(crate) fn let_value(input: Span) -> IResult<Span, LetValue> {
    preceded(
        zero_or_more_ws_or_comment,
        alt((
            map(parse_value, |val| {
                LetValue::Value(PathAwareValue::try_from(val).unwrap())
            }),
            map(function_expr, LetValue::FunctionCall),
            map(access, LetValue::AccessClause),
        )),
    )(input)
}

fn call_expr(input: Span) -> IResult<Span, (String, Vec<LetValue>)> {
    tuple((
        var_name,
        delimited(
            char('('),
            separated_list(char(','), delimited(multispace0, let_value, multispace0)),
            char(')'),
        ),
    ))(input)
}

pub(crate) fn parameterized_rule_call_clause(
    input: Span,
) -> IResult<Span, ParameterizedNamedRuleClause> {
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };

    let (input, not) = opt(not)(input)?;
    let (input, (rule_name, access_clauses)) = call_expr(input)?;
    let (input, custom_message) = opt(preceded(zero_or_more_ws_or_comment, custom_message))(input)?;
    Ok((
        input,
        ParameterizedNamedRuleClause {
            parameters: access_clauses,
            named_rule: GuardNamedRuleClause {
                location,
                custom_message: custom_message.map(|s| s.to_string()),
                negation: not.map_or(false, |_| true),
                dependent_rule: rule_name,
            },
        },
    ))
}

//
//  simple_unary               = "EXISTS" / "EMPTY"
//  keys_unary                 = "KEYS" 1*SP simple_unary
//  keys_not_unary             = "KEYS" 1*SP not_keyword 1*SP unary_operators
//  unary_operators            = simple_unary / keys_unary / not_keyword simple_unary / keys_not_unary
//
//
//  clause                     = access 1*SP unary_operators *(LWSP/comment) custom_message /
//                               access 1*SP binary_operators 1*(LWSP/comment) (access/value) *(LWSP/comment) custom_message
//
// Errors:
//     nom::error::ErrorKind::Alpha, if var_name_access / var_name does not work out
//     nom::error::ErrorKind::Char, if whitespace / comment does not work out for needed spaces
//
// Failures:
//     nom::error::ErrorKind::Char  if access / parse_value does not work out
//
//
fn clause(input: Span) -> IResult<Span, GuardClause> {
    alt((
        when_block(single_clauses, clause, |conds, (assigns, cls)| {
            GuardClause::WhenBlock(
                conds,
                Block {
                    assignments: assigns,
                    conjunctions: cls,
                },
            )
        }),
        block_clause,
        map(
            parameterized_rule_call_clause,
            GuardClause::ParameterizedNamedRule,
        ),
        |i| clause_with(i, access),
    ))(input)
}

fn single_clause(input: Span) -> IResult<Span, WhenGuardClause> {
    clause_with_map(input, access, WhenGuardClause::Clause)
}

//
//  rule_clause   =   (var_name (LWSP/comment)) /
//                    (var_name [1*SP << anychar >>] (LWSP/comment)
//
//
//  rule_clause get to be the most pesky of them all. It has the least
//  form and thereby can interpret partials of other forms as a rule_clause
//  To ensure we don't do that we need to peek ahead after a rule name
//  parsing to see which of these forms is present for the rule clause
//  to succeed
//
//      rule_name[ \t]*\n
//      rule_name[ \t\n]+or[ \t\n]+
//      rule_name(#[^\n]+)
//
//      rule_name\s+<<msg>>[ \t\n]+or[ \t\n]+
//
//
//

fn newline(input: Span) -> IResult<Span, Span> {
    alt((tag("\n"), tag("\r\n")))(input)
}

fn rule_clause(input: Span) -> IResult<Span, GuardClause> {
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };

    let (remaining, not) = opt(not)(input)?;
    let (remaining, ct_type) = var_name(remaining)?;

    //
    // we peek to preserve the input, if it is or, space+newline or comment
    // we return
    //
    let do_return = remaining.is_empty()
        || matches!(
            peek(alt((
                preceded(space0, value((), newline)),
                preceded(space0, value((), comment2)),
                preceded(space0, value((), char('{'))),
                value((), or_join),
            )))(remaining),
            Ok((_same, _ignored))
        );

    if do_return {
        return Ok((
            remaining,
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: ct_type,
                location,
                negation: not.is_some(),
                custom_message: None,
            }),
        ));
    }

    //
    // Else it must have a custom message
    //
    let (remaining, message) = cut(preceded(space0, custom_message))(remaining)?;
    Ok((
        remaining,
        GuardClause::NamedRule(GuardNamedRuleClause {
            dependent_rule: ct_type,
            location,
            negation: not.is_some(),
            custom_message: Some(message.to_string()),
        }),
    ))
}

//
// clauses
//
#[allow(clippy::redundant_closure)]
fn cnf_clauses<'loc, T, E, F, M>(
    input: Span<'loc>,
    f: F,
    _m: M,
    _non_empty: bool,
) -> IResult<Span<'loc>, Conjunctions<E>>
where
    F: Fn(Span<'loc>) -> IResult<Span<'loc>, E>,
    M: Fn(Vec<E>) -> T,
    E: Clone + 'loc,
    T: 'loc,
{
    let mut conjunctions = Conjunctions::new();
    let mut rest = input;
    loop {
        match disjunction_clauses(rest, |i: Span| f(i), true) {
            Err(nom::Err::Error(_)) => {
                if conjunctions.is_empty() {
                    return Err(nom::Err::Failure(ParserError {
                        span: input,
                        context: format!(
                            "There were no clauses present {}#{}@{}",
                            input.extra,
                            input.location_line(),
                            input.get_utf8_column()
                        ),
                        kind: ErrorKind::Many1,
                    }));
                }
                return Ok((rest, conjunctions));
            }

            Ok((left, disjunctions)) => {
                rest = left;
                conjunctions.push(disjunctions);
            }

            Err(e) => return Err(e),
        }
    }
}

#[allow(clippy::redundant_closure)]
fn disjunction_clauses<'loc, E, F>(
    input: Span<'loc>,
    parser: F,
    non_empty: bool,
) -> IResult<Span<'loc>, Disjunctions<E>>
where
    F: Fn(Span<'loc>) -> IResult<Span<'loc>, E>,
    E: Clone + 'loc,
{
    if non_empty {
        separated_nonempty_list(
            or_join,
            preceded(zero_or_more_ws_or_comment, |i: Span| parser(i)),
        )(input)
    } else {
        separated_list(
            or_join,
            preceded(zero_or_more_ws_or_comment, |i: Span| parser(i)),
        )(input)
    }
}

fn single_clauses(input: Span) -> IResult<Span, Conjunctions<WhenGuardClause>> {
    cnf_clauses(
        input,
        //
        // Order does matter here. Both rule_clause and access clause have the same syntax
        // for the first part e.g
        //
        // s3_encrypted_bucket  or configuration.containers.*.port == 80
        //
        // the first part is a rule clause and the second part is access clause. Consider
        // this example
        //
        // s3_encrypted_bucket or bucket_encryption EXISTS
        //
        // The first part if rule clause and second part is access. if we use the rule_clause
        // to be first it would interpret bucket_encryption as the rule_clause. Now to prevent that
        // we are using the alt form to first parse to see if it is clause and then try rules_clause
        //
        alt((
            single_clause,
            map(
                parameterized_rule_call_clause,
                WhenGuardClause::ParameterizedNamedRule,
            ),
            map(rule_clause, |g| match g {
                GuardClause::NamedRule(nr) => WhenGuardClause::NamedRule(nr),
                _ => unreachable!(),
            }),
        )),
        //
        // Mapping the GuardClause
        //
        std::convert::identity,
        false,
    )
}

#[allow(dead_code)] // TODO: investigate why this is unused
fn clauses(input: Span) -> IResult<Span, Conjunctions<GuardClause>> {
    cnf_clauses(
        input,
        //
        // Order does matter here. Both rule_clause and access clause have the same syntax
        // for the first part e.g
        //
        // s3_encrypted_bucket  or configuration.containers.*.port == 80
        //
        // the first part is a rule clause and the second part is access clause. Consider
        // this example
        //
        // s3_encrypted_bucket or bucket_encryption EXISTS
        //
        // The first part if rule clause and second part is access. if we use the rule_clause
        // to be first it would interpret bucket_encryption as the rule_clause. Now to prevent that
        // we are using the alt form to first parse to see if it is clause and then try rules_clause
        //
        alt((clause, rule_clause)),
        //
        // Mapping the GuardClause
        //
        std::convert::identity,
        false,
    )
}

fn let_assignment_expr(input: Span) -> IResult<Span, String> {
    let (input, _let_keyword) = tag("let")(input)?;
    let (input, (var_name, _eq_sign)) = tuple((
        //
        // if we have a pattern like "letproperty" that can be an access keyword
        // then there is no space in between. This will error out.
        //
        preceded(one_or_more_ws_or_comment, var_name),
        //
        // if we succeed in reading the form "let <var_name>", it must be be
        // followed with an assignment sign "=" or ":="
        //
        cut(preceded(
            zero_or_more_ws_or_comment,
            alt((tag("="), tag(":="))),
        )),
    ))(input)?;
    Ok((input, var_name))
}

fn assignment(input: Span) -> IResult<Span, LetExpr> {
    let (input, var_name) = let_assignment_expr(input)?;

    match parse_value(input) {
        Ok((input, value)) => Ok((
            input,
            LetExpr {
                var: var_name,
                value: LetValue::Value(PathAwareValue::try_from(value).unwrap()),
            },
        )),

        Err(nom::Err::Error(_)) => {
            //
            // if we did not succeed in parsing a value object, then
            // if must be an access pattern, or function call  else it is a failure
            match cut(preceded(zero_or_more_ws_or_comment, function_expr))(input) {
                Ok((input, function)) => Ok((
                    input,
                    LetExpr {
                        var: var_name,
                        value: LetValue::FunctionCall(function),
                    },
                )),
                Err(_) => {
                    let (input, access) = cut(preceded(zero_or_more_ws_or_comment, access))(input)?;

                    Ok((
                        input,
                        LetExpr {
                            var: var_name,
                            value: LetValue::AccessClause(access),
                        },
                    ))
                }
            }
        }

        Err(e) => Err(e),
    }
}

//
// when keyword
//
fn when(input: Span) -> IResult<Span, ()> {
    value((), alt((tag("when"), tag("WHEN"))))(input)
}

#[allow(clippy::redundant_closure)]
fn when_conditions<'loc, P>(
    condition_parser: P,
) -> impl Fn(Span<'loc>) -> IResult<Span<'loc>, Conjunctions<WhenGuardClause<'loc>>>
where
    P: Fn(Span<'loc>) -> IResult<Span<'loc>, Conjunctions<WhenGuardClause<'loc>>>,
{
    move |input: Span| {
        //
        // see if there is a "when" keyword
        //
        let (input, _when_keyword) = preceded(zero_or_more_ws_or_comment, when)(input)?;

        //
        // If there is "when" then parse conditions. It is an error not to have
        // clauses following it
        //
        cut(
            //
            // when keyword must be followed by a space and then clauses. Fail if that
            // is not the case
            //
            preceded(one_or_more_ws_or_comment, |s| condition_parser(s)),
        )(input)
    }
}

#[allow(clippy::redundant_closure)]
fn block<'loc, T, P>(
    clause_parser: P,
) -> impl Fn(Span<'loc>) -> IResult<Span<'loc>, (Vec<LetExpr<'loc>>, Conjunctions<T>)>
where
    P: Fn(Span<'loc>) -> IResult<Span<'loc>, T>,
    T: Clone + 'loc,
{
    move |input: Span| {
        let (input, _start_block) = preceded(zero_or_more_ws_or_comment, char('{'))(input)?;

        let mut conjunctions: Conjunctions<T> = Conjunctions::new();
        let (input, results) = fold_many1(
            alt((
                map(preceded(zero_or_more_ws_or_comment, assignment), |s| {
                    (Some(s), None)
                }),
                map(
                    |i: Span| disjunction_clauses(i, |i: Span| clause_parser(i), true),
                    |c: Disjunctions<T>| (None, Some(c)),
                ),
            )),
            Vec::new(),
            |mut acc, pair| {
                acc.push(pair);
                acc
            },
        )(input)?;

        let mut assignments = vec![];
        for each in results {
            match each {
                (Some(let_expr), None) => {
                    assignments.push(let_expr);
                }
                (None, Some(v)) => conjunctions.push(v),
                (_, _) => unreachable!(),
            }
        }

        let (input, _end_block) = cut(preceded(zero_or_more_ws_or_comment, char('}')))(input)?;

        Ok((input, (assignments, conjunctions)))
    }
}

pub(crate) fn type_name(input: Span) -> IResult<Span, TypeName> {
    match tuple((
        terminated(var_name, tag("::")),
        terminated(var_name, tag("::")),
        var_name,
    ))(input)
    {
        Ok((remaining, parts)) => {
            let (remaining, _skip_module) = opt(tag("::MODULE"))(remaining)?;
            Ok((
                remaining,
                TypeName {
                    type_name: format!("{}::{}::{}", parts.0, parts.1, parts.2),
                },
            ))
        }
        Err(nom::Err::Error(_e)) => {
            // custom resource might only have one separator
            let (remaining, parts) = tuple((terminated(var_name, tag("::")), var_name))(input)?;
            Ok((
                remaining,
                TypeName {
                    type_name: format!("{}::{}", parts.0, parts.1),
                },
            ))
        }
        Err(e) => Err(e),
    }
}
//
// Type block
//
fn type_block(input: Span) -> IResult<Span, TypeBlock> {
    //
    // Start must be a type name like "AWS::SQS::Queue"
    //
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };
    let (input, name) = type_name(input)?;

    //
    // There has to be a space following type name, else it is a failure
    //
    let (input, _space) = cut(one_or_more_ws_or_comment)(input)?;

    let (input, when_conditions) = opt(when_conditions(single_clauses))(input)?;

    let (input, (assignments, clauses)) = if when_conditions.is_some() {
        cut(block(clause))(input)?
    } else {
        match block(clause)(input) {
            Ok((input, result)) => (input, result),
            Err(nom::Err::Error(_)) => {
                let (input, conjs) = cut(preceded(
                    zero_or_more_ws_or_comment,
                    map(clause, |s| vec![s]),
                ))(input)?;
                (input, (Vec::new(), vec![conjs]))
            }
            Err(e) => return Err(e),
        }
    };

    Ok((
        input,
        TypeBlock {
            conditions: when_conditions,
            type_name: name.type_name.to_string(),
            block: Block {
                assignments,
                conjunctions: clauses,
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
                                location,
                                compare_with: Some(LetValue::Value(PathAwareValue::String((
                                    Path::root(),
                                    name.type_name,
                                )))),
                                comparator: (CmpOperator::Eq, false),
                            },
                        },
                    )])]),
                ),
            ],
        },
    ))
}

#[allow(clippy::redundant_closure)]
fn when_block<'loc, C, B, M, T, R>(
    conditions: C,
    block_fn: B,
    mapper: M,
) -> impl Fn(Span<'loc>) -> IResult<Span<'loc>, R>
where
    C: Fn(Span<'loc>) -> IResult<Span, Conjunctions<WhenGuardClause<'loc>>>,
    B: Fn(Span<'loc>) -> IResult<Span<'loc>, T>,
    T: Clone + 'loc,
    R: 'loc,
    M: Fn(Conjunctions<WhenGuardClause<'loc>>, (Vec<LetExpr<'loc>>, Conjunctions<T>)) -> R,
{
    move |input: Span| {
        map(
            preceded(
                zero_or_more_ws_or_comment,
                pair(when_conditions(|p| conditions(p)), block(|p| block_fn(p))),
            ),
            |(w, b)| mapper(w, b),
        )(input)
    }
}

fn rule_block_clause(input: Span) -> IResult<Span, RuleClause> {
    alt((
        map(
            preceded(zero_or_more_ws_or_comment, type_block),
            RuleClause::TypeBlock,
        ),
        map(
            preceded(
                zero_or_more_ws_or_comment,
                pair(
                    when_conditions(single_clauses),
                    block(alt((clause, rule_clause))),
                ),
            ),
            |(conditions, block)| {
                RuleClause::WhenBlock(
                    conditions,
                    Block {
                        assignments: block.0,
                        conjunctions: block.1,
                    },
                )
            },
        ),
        map(
            preceded(zero_or_more_ws_or_comment, alt((clause, rule_clause))),
            RuleClause::Clause,
        ),
    ))(input)
}

//
// rule block
//
fn rule_block(input: Span) -> IResult<Span, Rule> {
    //
    // rule is followed by space
    //
    let (input, _rule_keyword) = preceded(zero_or_more_ws_or_comment, tag("rule"))(input)?;
    let (input, _space) = one_or_more_ws_or_comment(input)?;

    let (input, rule_name) = cut(var_name)(input)?;
    let (input, conditions) = opt(when_conditions(single_clauses))(input)?;
    let (input, (assignments, conjunctions)) = cut(block(rule_block_clause))(input)?;

    Ok((
        input,
        Rule {
            rule_name,
            conditions,
            block: Block {
                assignments,
                conjunctions,
            },
        },
    ))
}

//
// parameter names
//
fn parameter_names(input: Span) -> IResult<Span, indexmap::IndexSet<String>> {
    delimited(
        char('('),
        map(
            separated_nonempty_list(
                char(','),
                cut(delimited(multispace0, var_name, multispace0)),
            ),
            |v| v.into_iter().collect::<indexmap::IndexSet<String>>(),
        ),
        cut(char(')')),
    )(input)
}

//
// Parameterized Rule
//
fn parameterized_rule_block(input: Span) -> IResult<Span, ParameterizedRule> {
    //
    // rule is followed by space
    //
    let (input, _rule_keyword) = delimited(
        zero_or_more_ws_or_comment,
        tag("rule"),
        one_or_more_ws_or_comment,
    )(input)?;

    let (input, rule_name) = cut(var_name)(input)?;
    let (input, parameter_names) = parameter_names(input)?;
    let (input, (assignments, conjunctions)) = cut(block(rule_block_clause))(input)?;

    Ok((
        input,
        ParameterizedRule {
            parameter_names,
            rule: Rule {
                rule_name,
                block: Block {
                    assignments,
                    conjunctions,
                },
                conditions: None,
            },
        },
    ))
}

fn default_clauses(input: Span) -> IResult<Span, Disjunctions<GuardClause>> {
    let (input, disjunctions) = disjunction_clauses(input, clause, true)?;
    Ok((input, disjunctions))
}

fn type_block_clauses(input: Span) -> IResult<Span, Disjunctions<TypeBlock>> {
    let (input, disjunctions) = disjunction_clauses(input, type_block, true)?;
    Ok((input, disjunctions))
}

#[allow(clippy::redundant_closure)]
fn remove_whitespace_comments<'loc, P, R>(
    parser: P,
) -> impl Fn(Span<'loc>) -> IResult<Span<'loc>, R>
where
    P: Fn(Span<'loc>) -> IResult<Span<'loc>, R>,
{
    move |input: Span| {
        delimited(
            zero_or_more_ws_or_comment,
            |s| parser(s),
            zero_or_more_ws_or_comment,
        )(input)
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Exprs<'loc> {
    Assignment(LetExpr<'loc>),
    DefaultTypeBlock(Disjunctions<TypeBlock<'loc>>),
    DefaultWhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
    DefaultClause(Disjunctions<GuardClause<'loc>>),
    Rule(Rule<'loc>),
    ParameterizedRule(ParameterizedRule<'loc>),
}

pub(crate) fn get_rule_name<'b>(rule_file_name: &str, rule_name: &'b str) -> &'b str {
    let prefix = format!("{file_name}/", file_name = rule_file_name);
    if rule_name.starts_with(&prefix) {
        &rule_name[prefix.len()..]
    } else {
        rule_name
    }
}

//
// Rules File
//
pub(crate) fn rules_file(input: Span) -> Result<Option<RulesFile>, Error> {
    let input = match zero_or_more_ws_or_comment(input) {
        Ok(input) => {
            if input.0.is_empty() {
                return Ok(None);
            }

            input.0
        }
        Err(_) => input,
    };

    let exprs = all_consuming(fold_many1(
        remove_whitespace_comments(alt((
            map(assignment, Exprs::Assignment),
            map(parameterized_rule_block, Exprs::ParameterizedRule),
            map(rule_block, Exprs::Rule),
            map(type_block_clauses, Exprs::DefaultTypeBlock),
            when_block(single_clauses, alt((clause, rule_clause)), |c, b| {
                Exprs::DefaultWhenBlock(
                    c,
                    Block {
                        assignments: b.0,
                        conjunctions: b.1,
                    },
                )
            }),
            map(default_clauses, Exprs::DefaultClause),
        ))),
        Vec::new(),
        |mut acc, expr| {
            acc.push(expr);
            acc
        },
    ))(input)?
    .1;

    let mut global_assignments = Vec::with_capacity(exprs.len());
    let mut default_rule_clauses = Vec::with_capacity(exprs.len());
    let mut named_rules = Vec::with_capacity(exprs.len());
    let mut parameterized_rules = Vec::with_capacity(exprs.len());

    for each in exprs {
        match each {
            Exprs::Rule(r) => named_rules.push(r),
            Exprs::ParameterizedRule(p) => parameterized_rules.push(p),
            Exprs::Assignment(l) => global_assignments.push(l),
            Exprs::DefaultClause(clause_disjunctions) => default_rule_clauses.push(
                clause_disjunctions
                    .into_iter()
                    .map(RuleClause::Clause)
                    .collect(),
            ),
            Exprs::DefaultTypeBlock(disjunctions) => default_rule_clauses.push(
                disjunctions
                    .into_iter()
                    .map(RuleClause::TypeBlock)
                    .collect(),
            ),
            Exprs::DefaultWhenBlock(w, b) => {
                default_rule_clauses.push(vec![RuleClause::WhenBlock(w, b)])
            }
        }
    }

    if !default_rule_clauses.is_empty() {
        let default_rule_name: String = if input.extra.to_string().trim().is_empty() {
            DEFAULT_RULE_NAME.to_string()
        } else {
            format!(
                "{rule_file_name}/{rule_name}",
                rule_file_name = input.extra,
                rule_name = DEFAULT_RULE_NAME
            )
        };

        let default_rule = Rule {
            conditions: None,
            rule_name: default_rule_name,
            block: Block {
                assignments: vec![],
                conjunctions: default_rule_clauses,
            },
        };
        named_rules.insert(0, default_rule);
    }

    Ok(Some(RulesFile {
        assignments: global_assignments,
        guard_rules: named_rules,
        parameterized_rules,
    }))
}

//
//  ABNF        = "or" / "OR" / "|OR|"
//
fn or_term(input: Span) -> IResult<Span, Span> {
    alt((tag("or"), tag("OR"), tag("|OR|")))(input)
}

fn or_join(input: Span) -> IResult<Span, Span> {
    delimited(
        zero_or_more_ws_or_comment,
        or_term,
        one_or_more_ws_or_comment,
    )(input)
}

impl<'a> TryFrom<&'a str> for AccessQuery<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        let access = access(span)?.1;
        Ok(access)
    }
}

impl<'a> TryFrom<&'a str> for LetExpr<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        let assign = assignment(span)?.1;
        Ok(assign)
    }
}

impl<'a> TryFrom<&'a str> for GuardClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(clause(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for TypeBlock<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(preceded(zero_or_more_ws_or_comment, type_block)(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for Rule<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(rule_block(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for ParameterizedRule<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(parameterized_rule_block(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for ParameterizedNamedRuleClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(parameterized_rule_call_clause(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for FunctionExpr<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(function_expr(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for RuleClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(preceded(zero_or_more_ws_or_comment, rule_block_clause)(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for RulesFile<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(rules_file(span)?.unwrap())
    }
}

#[derive(Ord, Eq, PartialEq, PartialOrd, Debug, Clone, Hash)]
pub(crate) struct TypeName {
    pub type_name: String,
}
impl Display for TypeName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.type_name.to_lowercase().replace("::", "_"))
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod parser_tests;
