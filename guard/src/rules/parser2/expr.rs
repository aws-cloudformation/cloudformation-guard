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
use nom::{FindSubstring, InputTake};
use nom::branch::{alt};
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::{alpha1, char, space1, newline, space0, digit1};
use nom::combinator::{cut, map, opt, value, peek, all_consuming};
use nom::error::{ParseError, context};
use nom::multi::{fold_many1, separated_nonempty_list, separated_list};
use nom::sequence::{delimited, pair, preceded, tuple, terminated};

use super::*;
use super::common::*;
use super::super::values::*;
use super::values::parse_value;
use crate::rules::exprs::*;
use crate::errors::Error;
use crate::rules::parser2::parse_string;
use serde_json::ser::CharEscape::Quote;
use std::convert::TryFrom;

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
// This version is the same as var_name_access
//
fn var_name_access_inclusive(input: Span2) -> IResult<Span2, String> {
    map(var_name_access, |s| format!("%{}", s))(input)
}

//
// Comparison operators
//
fn in_keyword(input: Span2) -> IResult<Span2, CmpOperator> {
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
        }

        Err(e) => Err(e)
    }
}

fn eq(input: Span2) -> IResult<Span2, (CmpOperator, bool)> {
    alt((
        value((CmpOperator::Eq, false), tag("==")),
        value((CmpOperator::Eq, true), tag("!=")),
    ))(input)
}

fn keys(input: Span2) -> IResult<Span2, ()> {
    value((), preceded(
        alt((
            tag("KEYS"),
            tag("keys"))), space1))(input)
}

fn keys_keyword(input: Span2) -> IResult<Span2, (CmpOperator, bool)> {
    let (input, _keys_word) = keys(input)?;
    let (input, (comparator, inverse)) = alt((
        eq,
        other_operations,
    ))(input)?;

    let comparator = match comparator {
        CmpOperator::Eq => CmpOperator::KeysEq,
        CmpOperator::In => CmpOperator::KeysIn,
        CmpOperator::Exists => CmpOperator::KeysExists,
        CmpOperator::Empty => CmpOperator::KeysEmpty,
        _ => unreachable!(),
    };

    Ok((input, (comparator, inverse)))
}

fn exists(input: Span2) -> IResult<Span2, CmpOperator> {
    value(CmpOperator::Exists, alt((tag("EXISTS"), tag("exists"))))(input)
}

fn empty(input: Span2) -> IResult<Span2, CmpOperator> {
    value(CmpOperator::Empty, alt((tag("EMPTY"), tag("empty"))))(input)
}

fn other_operations(input: Span2) -> IResult<Span2, (CmpOperator, bool)> {
    let (input, not) = opt(not)(input)?;
    let (input, operation) = alt((
        in_keyword,
        exists,
        empty
    ))(input)?;
    Ok((input, (operation, not.is_some())))
}


fn value_cmp(input: Span2) -> IResult<Span2, (CmpOperator, bool)> {
    //
    // This is really crappy as the earlier version used << for custom message
    // delimiter. '<' can be interpreted as Lt comparator.
    // TODO revisit the custom message delimiter
    //
    let (input, is_custom_message_start) = peek(opt(value(true,tag("<<"))))(input)?;
    if is_custom_message_start.is_some() {
        return Err(nom::Err::Error(ParserError {
            span: input,
            context: "Custom message tag detected".to_string(),
            kind: nom::error::ErrorKind::Tag
        }))
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
        keys_keyword,
        other_operations,
    ))(input)
}

fn extract_message(input: Span2) -> IResult<Span2, &str> {
    match input.find_substring(">>") {
        None => Err(nom::Err::Failure(ParserError {
            span: input,
            kind: nom::error::ErrorKind::Tag,
            context: format!("Unable to find a closing >> tag for message"),
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

pub(crate) fn does_comparator_have_rhs(op: &CmpOperator) -> bool {
    match op {
        CmpOperator::KeysExists |
        CmpOperator::KeysEmpty |
        CmpOperator::Empty |
        CmpOperator::Exists => false,
        _ => true
    }
}

fn predicate_filter_clauses(input: Span2) -> IResult<Span2, Conjunctions<GuardClause>> {
    let (input, filters) = cnf_clauses(
        input, clause, std::convert::identity, true)?;
    Ok((input, filters))
}

fn predicate_clause<'loc, F>(parser: F) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, (QueryPart, Option<QueryPart>)>
    where F: Fn(Span2<'loc>) -> IResult<Span2<'loc>, String>
{
    move |input: Span2| {
        let (input, first) = parser(input)?;
        let (input, is_filter) = opt(char('['))(input)?;
        let (input, filter_part) = if is_filter.is_none() { (input, None) } else {
            let (input, part) = cut(alt((
                map(predicate_filter_clauses, |clauses| QueryPart::Filter(clauses)),
                value(QueryPart::AllIndices, preceded(space0, char('*'))),
                map( preceded(space0, super::values::parse_int_value), |idx| {
                        let idx = match idx { Value::Int(i) => i as i32, _ => unreachable!() };
                    QueryPart::Index(idx)
                }),
            ))
            )(input)?;
            let (input, _ignored) = cut(terminated(zero_or_more_ws_or_comment, char(']')))(input)?;
            (input, Some(part))
        };

        if &first == "*" {
            Ok((input, (QueryPart::AllValues, filter_part)))
        }
        else {
            Ok((input, (QueryPart::Key(first), filter_part)))
        }
    }
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
fn dotted_access(input: Span2) -> IResult<Span2, Vec<QueryPart>> {
    fold_many1(
        preceded(char('.'), predicate_clause(
            alt((property_name,
                 value("*".to_string(), char('*')),
                map(digit1, |s: Span2| (*s.fragment()).to_string())
            )))
        ),
        Vec::new(),
        |mut acc: Vec<QueryPart>, part| {
            acc.push(part.0);
            part.1.map(|p| acc.push(p));
            acc
        },
    )(input)
}

fn property_name(input: Span2) -> IResult<Span2, String> {
    alt(( var_name, map(parse_string, |v| match v {
        Value::String(value) => value,
        _ => unreachable!()
    })))(input)
}

//
//   access     =   (var_name / var_name_access) [dotted_access]
//
pub(crate) fn access(input: Span2) -> IResult<Span2, AccessQuery> {
    map(pair(
        predicate_clause(
            alt((var_name_access_inclusive, property_name))),
        opt(dotted_access)), |(first, remainder)| {

        match remainder {
            Some(mut parts) => {
                parts.insert(0, first.0);
                if let Some(second) = first.1 {
                    parts.insert(1, second);
                }
                parts
            },

            None => {
                let mut parts = vec![first.0];
                if let Some(second) = first.1 {
                    parts.push(second);
                }
                parts
            }
        }
    })(input)
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
fn clause(input: Span2) -> IResult<Span2, GuardClause> {
    let location = FileLocation {
        file_name: input.extra,
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
    };

    let (rest, not) = opt(not)(input)?;

    //
    // TODO find a better way to do this. Predicate clause uses this as well which can have
    // the form *[ KEYS == ... ], where KEYS was the keyword. No other form of expression has
    // this problem.
    //
    // FIXME: clause ends up calling predicate_clause, which is fine, but we should
    // not expect the form *[ [ [] ] ]. We should dis-allows this.
    //
    let (rest, keys) = opt(peek(keys))(rest)?;

    let (rest, (lhs, cmp)) =
        if keys.is_some() {
            let (r, (_space_ign, cmp)) = tuple((
                      context("expecting one or more WS or comment blocks", zero_or_more_ws_or_comment),
                      // error if there is no value_cmp
                      context("expecting comparison binary operators like >, <= or unary operators KEYS, EXISTS, EMPTY or NOT",
                              value_cmp)
                  ))(rest)?;
            (r, (AccessQuery::from([]), cmp))
        } else {
            let (r, (access, _ign_space, cmp)) = tuple((
                access,
                // It is an error to not have a ws/comment following it
                context("expecting one or more WS or comment blocks", one_or_more_ws_or_comment),
                // error if there is no value_cmp
                context("expecting comparison binary operators like >, <= or unary operators KEYS, EXISTS, EMPTY or NOT",
                        value_cmp)
            ))(rest)?;
            (r, (access, cmp))
        };

    if !does_comparator_have_rhs(&cmp.0) {
        let remaining = rest.clone();
        let (remaining, custom_message) = cut(
            map(preceded(zero_or_more_ws_or_comment, opt(custom_message)),
                |msg| {
                    msg.map(String::from)
                }))(remaining)?;
        let rest = if custom_message.is_none() { rest } else { remaining };
        Ok((rest,
            GuardClause::Clause(
                GuardAccessClause {
                access_clause: AccessClause {
                    query: lhs,
                    comparator: cmp,
                    compare_with: None,
                    custom_message,
                    location,
                },
                negation: not.is_some() }
        )))
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
                                (Some(LetValue::Value(rhs)), msg.map(String::from).or(None))
                            }),
                        map(tuple((
                            preceded(zero_or_more_ws_or_comment, access),
                            preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            |(rhs, msg)| {
                                (Some(LetValue::AccessClause(rhs)), msg.map(String::from).or(None))
                            }),
                    ))))(rest)?;
        Ok((rest,
            GuardClause::Clause(
                GuardAccessClause {
                    access_clause: AccessClause {
                        query: lhs,
                        comparator: cmp,
                        compare_with,
                        custom_message,
                        location,
                    },
                    negation: not.is_some()
                })
        ))
    }
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
fn rule_clause(input: Span2) -> IResult<Span2, GuardClause> {
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
    if let Ok((same, _ignored)) = peek(alt((
        preceded(space0, value((), newline)),
        preceded(space0, value((), comment2)),
        preceded(space0, value((), char('{'))),
        value((), or_join),
    )))(remaining) {
        return
            Ok((same, GuardClause::NamedRule(
                GuardNamedRuleClause {
                    dependent_rule: ct_type,
                    location,
                    negation: not.is_some(),
                    comment: None
                })
            ))
    }

    //
    // Else it must have a custom message
    //
    let (remaining, message) = cut(preceded(space0, custom_message))(remaining)?;
    Ok((remaining, GuardClause::NamedRule(
        GuardNamedRuleClause {
            dependent_rule: ct_type,
            location,
            negation: not.is_some(),
            comment: Some(message.to_string()),
        })
   ))
}

//
// clauses
//
fn cnf_clauses<'loc, T, E, F, M>(input: Span2<'loc>, f: F, m: M, non_empty: bool) -> IResult<Span2<'loc>, Vec<T>>
    where F: Fn(Span2<'loc>) -> IResult<Span2<'loc>, E>,
          M: Fn(Vec<E>) -> T,
          E: Clone + 'loc,
          T: 'loc
{
    let mut result: Vec<T> = Vec::new();
    let mut remaining = input;
    let mut first = true;
    loop {
        let (rest, set) = if non_empty {
            match separated_nonempty_list(
                or_join,
                preceded(zero_or_more_ws_or_comment, |i: Span2| f(i)),
            )(remaining.clone()) {
                Err(nom::Err::Error(e)) => if first {
                    return Err(nom::Err::Error(e))
                } else {
                    return Ok((remaining, result))
                },
                Ok((r, s)) => (r, s),
                Err(e) => return Err(e),
            }
        }  else {
            separated_list(
                or_join,
                preceded(zero_or_more_ws_or_comment, |i: Span2| f(i)),
            )(remaining)?

        };

        first = false;
        remaining = rest;

        match set.len() {
            0 => return Ok((remaining, result)),
            _ => result.push(m(set)),
        }
    }
}

fn clauses(input: Span2) -> IResult<Span2, Conjunctions<GuardClause>> {
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
        std::convert::identity, false)
}

fn assignment(input: Span2) -> IResult<Span2, LetExpr> {
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
        cut(
            preceded(
                zero_or_more_ws_or_comment,
                alt((tag("="), tag(":=")))
            )
        ),
    ))(input)?;

    match parse_value(input) {
        Ok((input, value)) => Ok((input, LetExpr {
            var: var_name,
            value: LetValue::Value(value)
        })),

        Err(nom::Err::Error(_)) => {
            //
            // if we did not succeed in parsing a value object, then
            // if must be an access pattern, else it is a failure
            //
            let (input, access) = cut(
                preceded(
                    zero_or_more_ws_or_comment,
                    access
                )
            )(input)?;

            Ok((input, LetExpr {
                var: var_name,
                value: LetValue::AccessClause(access),
            }))
        },

        Err(e) => Err(e)
    }
}

//
// when keyword
//
fn when(input: Span2) -> IResult<Span2, ()> {
    value((), alt((tag("when"), tag("WHEN"))))(input)
}

fn when_conditions<'loc, P>(condition_parser: P) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, Conjunctions<GuardClause<'loc>>>
    where P: Fn(Span2<'loc>) -> IResult<Span2<'loc>, Conjunctions<GuardClause<'loc>>>
{
    move |input: Span2| {
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
            preceded(
                one_or_more_ws_or_comment,
                |s| condition_parser(s)))(input)
    }
}

fn block<'loc, T, P>(clause_parser: P) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, (Vec<LetExpr<'loc>>, Conjunctions<T>)>
    where P: Fn(Span2<'loc>) -> IResult<Span2<'loc>, T>,
          T: Clone + 'loc
{
    move |input: Span2| {
        let (input, _start_block) = preceded(zero_or_more_ws_or_comment, char('{'))
            (input)?;

        let (input, results) =
            fold_many1(
                alt((
                    map(preceded(zero_or_more_ws_or_comment, assignment), |s| (Some(s), None)),
                    map(
                        |i: Span2| cnf_clauses(i, |i: Span2| clause_parser(i), std::convert::identity, true),
                        |c: Conjunctions<T>| (None, Some(c)))
                )),
                Vec::new(),
                |mut acc, pair| {
                    acc.push(pair);
                    acc
                }
            )(input)?;

        let mut assignments = vec![];
        let mut conjunctions: Conjunctions<T> = Conjunctions::new();
        for each in results {
            match each {
                (Some(let_expr), None) => {
                    assignments.push(let_expr);
                },
                (None, Some(v)) => {
                    conjunctions.extend(v)
                },
                (_, _) => unreachable!(),
            }
        }

        let (input, _end_block) = cut(preceded(zero_or_more_ws_or_comment, char('}')))
            (input)?;


        Ok((input, (assignments, conjunctions)))
    }
}

fn type_name(input: Span2) -> IResult<Span2, String> {
    let (input, parts) = tuple((
        terminated(var_name, tag("::")),
        terminated(var_name, tag("::")),
        var_name,
    ))(input)?;

    let (input, _skip_module) = opt(tag("::MODULE"))(input)?;

    Ok((input, format!("{}::{}::{}", parts.0, parts.1, parts.2)))
}

//
// Type block
//
fn type_block(input: Span2) -> IResult<Span2, TypeBlock> {
    //
    // Start must be a type name like "AWS::SQS::Queue"
    //
    let (input, name) = type_name(input)?;

    //
    // There has to be a space following type name, else it is a failure
    //
    let (input, _space) = cut(one_or_more_ws_or_comment)(input)?;

    let (input, when_conditions) = opt(
        when_conditions(|i: Span2| cnf_clauses(i,
                                               preceded(zero_or_more_ws_or_comment, clause),
                                               std::convert::identity, true)))
        (input)?;

    let (input, (assignments, clauses)) =
        if when_conditions.is_some() {
            cut(block(clause))(input)?
        } else {
            match block(clause)(input) {
                Ok((input, result)) => (input, result),
                Err(nom::Err::Error(_)) => {
                    let (input, conjs)  = cut(preceded(
                        zero_or_more_ws_or_comment,
                        map(clause, |s| vec![s])
                    ))(input)?;
                    (input, (Vec::new(), vec![conjs]))
                },
                Err(e) => return Err(e),
            }
        };

    Ok((input, TypeBlock {
        conditions: when_conditions,
        type_name: name,
        block: Block {
            assignments: assignments,
            conjunctions: clauses,
        }
    }))
}

fn when_block<'loc, C, B, M, T, R>(conditions: C, block_fn: B, mapper: M) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, R>
    where C: Fn(Span2<'loc>) -> IResult<Span2, Conjunctions<GuardClause<'loc>>>,
          B: Fn(Span2<'loc>) -> IResult<Span2<'loc>, T>,
          T: Clone + 'loc,
          R: 'loc,
          M: Fn(Conjunctions<GuardClause<'loc>>, (Vec<LetExpr<'loc>>, Conjunctions<T>)) -> R
{
    move |input: Span2| {
        map(preceded(zero_or_more_ws_or_comment,
                     pair(
                         when_conditions(|p| conditions(p)),
                         block(|p| block_fn(p))
                     )), |(w, b)| mapper(w, b))(input)
    }
}

fn rule_block_clause(input: Span2) -> IResult<Span2, RuleClause> {
   alt((
       map(preceded(zero_or_more_ws_or_comment, type_block), RuleClause::TypeBlock),
       map(preceded(zero_or_more_ws_or_comment,
                    pair(
                        when_conditions(clauses),
                        block(alt((clause, rule_clause)))
                    )),
           |(conditions, block)| {
           RuleClause::WhenBlock(conditions, Block{ assignments: block.0, conjunctions: block.1 })
       }),
       map(preceded(zero_or_more_ws_or_comment, alt((clause, rule_clause))), RuleClause::Clause)
   ))(input)
}

//
// rule block
//
fn rule_block(input: Span2) -> IResult<Span2, Rule> {
    //
    // rule is followed by space
    //
    let (input, _rule_keyword) = preceded(zero_or_more_ws_or_comment, tag("rule"))(input)?;
    let (input, _space) = one_or_more_ws_or_comment(input)?;

    let (input, rule_name) = cut(var_name)(input)?;
    let (input, conditions) = opt(when_conditions(clauses))(input)?;
    let (input, (assignments, conjunctions)) =
        cut(block(rule_block_clause))(input)?;

    Ok((input, Rule {
        rule_name,
        conditions,
        block: Block {
            assignments,
            conjunctions,
        }
    }))
}

fn remove_whitespace_comments<'loc, P, R>(parser: P) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, R>
    where P: Fn(Span2<'loc>) -> IResult<Span2<'loc>, R>
{
    move |input: Span2| {
        delimited(
            zero_or_more_ws_or_comment,
            |s| parser(s),
            zero_or_more_ws_or_comment
        )(input)
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Exprs<'loc> {
    Assignment(LetExpr<'loc>),
    DefaultTypeBlock(TypeBlock<'loc>),

    // WhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
    DefaultWhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
    DefaultClause(GuardClause<'loc>),
    Rule(Rule<'loc>),
}

//
// Rules File
//
pub(crate) fn rules_file(input: Span2) -> std::result::Result<RulesFile, Error> {
    let exprs = all_consuming(fold_many1(
            remove_whitespace_comments(
                alt((
                    map(assignment, Exprs::Assignment),
                    map(rule_block, Exprs::Rule),
                    map(type_block, Exprs::DefaultTypeBlock),
                    when_block(clauses, alt((clause, rule_clause)), |c, b|
                        Exprs::DefaultWhenBlock(c, Block { assignments: b.0, conjunctions: b.1 })),
                    map(clause, Exprs::DefaultClause),
                ))
            ),
        Vec::new(),
        |mut acc, expr| {
            acc.push(expr);
            acc
        }
    ))(input)?.1;

    let mut global_assignments = Vec::with_capacity(exprs.len());
    let mut default_rule_clauses = Vec::with_capacity(exprs.len());
    let mut named_rules = Vec::with_capacity(exprs.len());

    for each in exprs {
        match each {
            Exprs::Rule(r) => named_rules.push(r),
            Exprs::Assignment(l) => global_assignments.push(l),
            Exprs::DefaultClause(c) => default_rule_clauses.push(RuleClause::Clause(c)),
            Exprs::DefaultTypeBlock(t) => default_rule_clauses.push(RuleClause::TypeBlock(t)),
            Exprs::DefaultWhenBlock(w, b) => default_rule_clauses.push(RuleClause::WhenBlock(w, b)),
        }
    }

    if !default_rule_clauses.is_empty(){
        let default_rule = Rule {
            conditions: None,
            rule_name: "default".to_string(),
            block: Block {
                assignments: vec![],
                conjunctions: vec![default_rule_clauses]
            }
        };
        named_rules.insert(0, default_rule);
    }

    Ok(RulesFile {
        assignments: global_assignments,
        guard_rules: named_rules
    })

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

fn or_join(input: Span2) -> IResult<Span2, Span2> {
    delimited(
        one_or_more_ws_or_comment,
        or_term,
        one_or_more_ws_or_comment
    )(input)
}

pub(crate) struct AccessQueryWrapper<'a>(pub(crate) AccessQuery<'a>);
impl<'a> TryFrom<&'a str> for AccessQueryWrapper<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        let access = access(span)?.1;
        Ok(AccessQueryWrapper(access))
    }
}

impl<'a> TryFrom<&'a str> for GuardClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(clause(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for Conjunctions<GuardClause<'a>> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(clauses(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for Rule<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(rule_block(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for RuleClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(preceded(zero_or_more_ws_or_comment, rule_block_clause)(span)?.1)
    }
}

#[cfg(test)]
#[path = "expr_tests.rs"]
mod expr_tests;

