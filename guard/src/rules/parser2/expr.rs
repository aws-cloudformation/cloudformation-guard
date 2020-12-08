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
use nom::branch::{alt, Alt};
use nom::bytes::complete::{tag, take_while, take_while1, take_while_m_n};
use nom::character::{is_digit, is_alphanumeric};
use nom::character::complete::{alpha1, char, space1, one_of, newline, space0, multispace0, digit1};
use nom::combinator::{cut, map, opt, value, peek};
use nom::error::{ParseError, context};
use nom::multi::{fold_many1, separated_nonempty_list, separated_list, fold_many_m_n, many_m_n};
use nom::sequence::{delimited, pair, preceded, tuple, terminated};

use super::*;
use super::common::*;
use super::super::values::*;
use super::values::parse_value;
use crate::rules::exprs::*;
use crate::rules::parser::parse_int_value;
use nom::number::complete::be_i32;

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

fn does_comparator_have_rhs(op: &CmpOperator) -> bool {
    match op {
        CmpOperator::KeysExists |
        CmpOperator::KeysEmpty |
        CmpOperator::Empty |
        CmpOperator::Exists => false,
        _ => true
    }
}

fn predicate_filter_clause(input: Span2) -> IResult<Span2, FilterPart> {
    let (input, (name, cmp)) = tuple((
        preceded(zero_or_more_ws_or_comment, var_name),
        cut(preceded(zero_or_more_ws_or_comment, value_cmp))))(input)?;

    let (input, value) = if does_comparator_have_rhs(&cmp.0) {
        cut(
            preceded(zero_or_more_ws_or_comment, alt((
                map(parse_value, |v| Some(VariableOrValue::Value(v))),
                map(var_name_access, |var| Some(VariableOrValue::Variable(var))),
            )))
        )(input)?
    } else {
        (input, None)
    };

    Ok((input, FilterPart {
        name,
        comparator: cmp,
        value,
    }))
}

fn predicate_filter_clauses(input: Span2) -> IResult<Span2, Vec<Vec<FilterPart>>> {
    let (input, filters) = cnf_clauses(
        input, predicate_filter_clause, std::convert::identity, true)?;
    Ok((input, filters))
}

fn predicate_clause<'loc, F>(parser: F) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, QueryPart>
    where F: Fn(Span2<'loc>) -> IResult<Span2<'loc>, String>
{
    move |input: Span2| {
        let (input, first) = parser(input)?;
        let (input, is_filter) = opt(char('['))(input)?;
        let (input, part) = if is_filter.is_some() {
            let (input, part) = cut(alt((
                map(predicate_filter_clauses, |clauses| QueryPart::Filter(first.clone(), clauses)),
                map( preceded(space0, char('*')), |_all| QueryPart::AllIndices(first.clone())),
                map( preceded(space0, super::values::parse_int_value), |idx| {
                        let idx = match idx { Value::Int(i) => i as i32, _ => unreachable!() };
                        QueryPart::Index(first.clone(), idx)
                    }
                ),
            )))(input)?;
            let (input, _ignored) = cut(terminated(zero_or_more_ws_or_comment, char(']')))(input)?;
            (input, part)
        }
        else if first.starts_with("%") {
            (input, QueryPart::Variable(first.replace("%", "")))
        }
        else if &first == "*" {
            (input, QueryPart::AllKeys)
        }
        else {
            (input, QueryPart::Key(first))
        };
        Ok((input, part))
    }
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
fn dotted_access(input: Span2) -> IResult<Span2, AccessQuery> {
    fold_many1(
        preceded(char('.'), predicate_clause(
            alt((var_name_access_inclusive,
                 var_name,
                 value("*".to_string(), char('*')),
                map(digit1, |s: Span2| (*s.fragment()).to_string())
            )))
        ),
        AccessQuery::new(),
        |mut acc: AccessQuery, part| {
            acc.push(part);
            acc
        },
    )(input)
}

//
//   access     =   (var_name / var_name_access) [dotted_access]
//
fn access(input: Span2) -> IResult<Span2, AccessQuery> {
    map(pair(
        predicate_clause(
            alt((var_name_access_inclusive, var_name))),
        opt(dotted_access)), |(first, remainder)| {
        remainder.map(|mut query| {
            query.insert(0, first.clone());
            query
        })
        .unwrap_or(vec![first.clone()])
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
    let (rest, (lhs, _ignored_space, cmp, _ignored)) = tuple((
        access,
        // It is an error to not have a ws/comment following it
        context("expecting one or more WS or comment blocks", one_or_more_ws_or_comment),
        // error if there is no value_cmp
        context("expecting comparison binary operators like >, <= or unary operators KEYS, EXISTS, EMPTY or NOT",
                value_cmp),
        // error if this isn't followed by space or comment or newline
        context("expecting one or more WS or comment blocks", one_or_more_ws_or_comment),
    ))(rest)?;

    let no_rhs_expected = match &cmp.0 {
        CmpOperator::KeysExists |
        CmpOperator::KeysEmpty |
        CmpOperator::Empty |
        CmpOperator::Exists => true,
        _ => false
    };

    if !does_comparator_have_rhs(&cmp.0) {
        let (rest, custom_message) = cut(
            map(preceded(zero_or_more_ws_or_comment, opt(custom_message)),
                |msg| {
                    msg.map(String::from)
                }))(rest)?;
        Ok((rest,
            GuardClause::Clause(AccessClause {
                query: lhs,
                comparator: cmp,
                compare_with: None,
                custom_message,
                location,
            }, not.is_some())
        ))
    } else {
        let (rest, (compare_with, custom_message)) =
            context("expecting either a property access \"engine.core\" or value like \"string\" or [\"this\", \"that\"]",
                    cut(alt((
                        map(tuple((
                            access, preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            |(rhs, msg)| {
                                (Some(LetValue::AccessClause(rhs)), msg.map(String::from).or(None))
                            }),
                        map(tuple((
                            parse_value, preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            move |(rhs, msg)| {
                                (Some(LetValue::Value(rhs)), msg.map(String::from).or(None))
                            })
                    ))))(rest)?;
        Ok((rest,
            GuardClause::Clause(AccessClause {
                query: lhs,
                comparator: cmp,
                compare_with,
                custom_message,
                location,
            }, not.is_some())
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
        value((), or_join),
    )))(remaining) {
        return Ok((same, GuardClause::NamedRule(ct_type, location, not.is_some(), None)))
    }

    //
    // Else it must have a custom message
    //
    let (remaining, message) = cut(preceded(space0, custom_message))(remaining)?;
    Ok((remaining, GuardClause::NamedRule(ct_type, location, not.is_some(), Some(message.to_string()))))
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

fn when_conditions<P>(condition_parser: P) -> impl Fn(Span2) -> IResult<Span2, Conjunctions<GuardClause>>
    where P: Fn(Span2) -> IResult<Span2, Conjunctions<GuardClause>>
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

fn block<'loc, T, P>(clause_parser: P) -> impl Fn(Span2<'loc>) -> IResult<Span2<'loc>, (Vec<LetExpr>, Conjunctions<T>)>
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
    let (input, _rule_keyword) = tag("rule")(input)?;

    let (input, _space) = cut(one_or_more_ws_or_comment)(input)?;

    let (input, rule_name) = var_name(input)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryInto;
    use crate::rules::expr::PropertyClause::Disjunction;
    use serde::de::Unexpected::Str;
    use serde_json::to_string;

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
            Err(nom::Err::Error(
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
                })),
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

    fn to_query_part(vec: Vec<&str>) -> Vec<QueryPart> {
        to_string_vec(&vec)
    }

    fn to_string_vec(list: &[&str]) -> Vec<QueryPart> {
        list.iter()
            .map(|part|
                if (*part).starts_with("%") {
                    QueryPart::Variable((*part).to_string().replace("%", ""))
                }
                else if *part == "*" {
                    QueryPart::AllKeys
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
            "engine[type==\"cfn\"].port", // 18 Ok

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
                AccessQuery::from([
                    QueryPart::Key("engine".to_string())
                ])
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
                AccessQuery::from([
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Key("type".to_string()),
                ])
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
                 AccessQuery::from([
                     QueryPart::Key("engine".to_string()),
                     QueryPart::Key("type".to_string()),
                     QueryPart::AllKeys,
                 ])
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
                 AccessQuery::from([
                     QueryPart::Key("engine".to_string()),
                     QueryPart::AllKeys,
                     QueryPart::Key("type".to_string()),
                     QueryPart::Key("port".to_string()),
                 ])
            )),
            Ok(( // "engine.*.type.%var", // 8 ok
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[8].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 AccessQuery::from([
                     QueryPart::Key("engine".to_string()),
                     QueryPart::AllKeys,
                     QueryPart::Key("type".to_string()),
                     QueryPart::Variable("var".to_string()),
                 ])
            )),
            Ok(( // "engine[0]", // 9 ok
                 unsafe {
                     Span2::new_from_raw_offset(
                         examples[9].len(),
                         1,
                         "",
                         "",
                     )
                 },
                 AccessQuery::from([
                     QueryPart::Index("engine".to_string(), 0)
                 ])
            )),
            Ok(( // 10 "engine [0]", // 10 ok engine will be property access part
                 unsafe {
                     Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[11].len(),
                        1,
                        "",
                        "",
                    )
                },
                AccessQuery::from([
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Key("ok".to_string()),
                    QueryPart::AllKeys,
                ])
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
                AccessQuery::from([
                    QueryPart::Key("engine".to_string()),
                    QueryPart::Variable("name".to_string()),
                    QueryPart::AllKeys,
                ])
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
                AccessQuery::from([
                    QueryPart::Variable("engine".to_string()),
                    QueryPart::Key("type".to_string()),
                ])
            )),


            // "%engine.*.type[0]", // 14 ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[14].len(),
                        1,
                        "",
                        "",
                    )
                },
                AccessQuery::from([
                    QueryPart::Variable("engine".to_string()),
                    QueryPart::AllKeys,
                    QueryPart::Index("type".to_string(), 0),
                ])
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
                AccessQuery::from([
                    QueryPart::Variable("engine".to_string()),
                    QueryPart::Variable("type".to_string()),
                    QueryPart::AllKeys,
                ])
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
                AccessQuery::from([
                    QueryPart::Variable("engine".to_string()),
                    QueryPart::Variable("type".to_string()),
                    QueryPart::AllKeys,
                    QueryPart::Key("port".to_string()),
                ])
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
                AccessQuery::from([
                    QueryPart::Variable("engine".to_string()),
                    QueryPart::AllKeys,
                ])
            )),

            // matches { 'engine': [{'type': 'cfn', 'position': 1, 'other': 20}, {'type': 'tf', 'position': 2, 'other': 10}] }
            // "engine[type==\"cfn\"].port", // 18 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[18].len(),
                        1,
                        "",
                        "",
                    )
                },
                AccessQuery::from([
                    QueryPart::Filter("engine".to_string(), vec![
                        vec![FilterPart {
                            name: String::from("type"),
                            comparator: (CmpOperator::Eq, false),
                            value: Some(VariableOrValue::Value(Value::String(String::from("cfn"))))
                        }]
                    ]),
                    QueryPart::Key(String::from("port")),
                ])
            )),

            // " %engine", // 18 err
            Err(nom::Err::Error(ParserError { // 19
                span: from_str2(" %engine"),
                kind: nom::error::ErrorKind::Alpha,
                context: "".to_string(),
            })),
        ];

        for (idx, each) in examples.iter().enumerate() {
            let span = Span2::new_extra(*each, "");
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                        Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
            "%engine.%port",
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

    fn testing_access_with_cmp<A, C>(separators: &[(&str, &str)],
                                     comparators: &[(&str, (CmpOperator, bool))],
                                     lhs: &str,
                                     rhs: &str,
                                     access: A,
                                     cmp_with: C)
        where A: Fn() -> AccessQuery,
              C: Fn() -> Option<LetValue>
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
                    let result = match result.unwrap().1 {
                        GuardClause::Clause(clause, _) => clause,
                        _ => unreachable!()
                    };
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
            Ok((unsafe { Span2::new_from_raw_offset(
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
            Ok((unsafe { Span2::new_from_raw_offset(
                examples[1].len(),
                1,
                "",
                ""
            )},
                to_query_part(examples[1].split(".").collect())
            )),

            // "resources.*[ type == /AWS::RDS/ ]", // 2 Ok
            Ok((unsafe { Span2::new_from_raw_offset(
                examples[2].len(),
                1,
                "",
                ""
            )},
                AccessQuery::from([
                    QueryPart::Key("resources".to_string()),
                    QueryPart::Filter("*".to_string(), Conjunctions::from([
                        Disjunctions::from([FilterPart {
                            value: Some(VariableOrValue::Value(Value::Regex("AWS::RDS".to_string()))),
                            comparator: (CmpOperator::Eq, false),
                            name: "type".to_string()
                        }]),
                    ]))
                ])
            )),


            // r#"resources.*[ type == /AWS::RDS/
            //                 deletion_policy EXISTS
            //                 deletion_policy == "RETAIN" ].properties"#
            Ok((unsafe { Span2::new_from_raw_offset(
                examples[3].len(),
                3,
                "",
                ""
            )},
                AccessQuery::from([
                    QueryPart::Key("resources".to_string()),
                    QueryPart::Filter("*".to_string(), Conjunctions::from([
                        Disjunctions::from([FilterPart {
                            value: Some(VariableOrValue::Value(Value::Regex("AWS::RDS".to_string()))),
                            comparator: (CmpOperator::Eq, false),
                            name: "type".to_string()
                        }]),
                        Disjunctions::from([FilterPart {
                            value: None,
                            comparator: (CmpOperator::Exists, false),
                            name: "deletion_policy".to_string()
                        }]),
                        Disjunctions::from([FilterPart {
                            value: Some(VariableOrValue::Value(Value::String("RETAIN".to_string()))),
                            comparator: (CmpOperator::Eq, false),
                            name: "deletion_policy".to_string()
                        }]),
                    ])),
                    QueryPart::Key("properties".to_string()),
                ])
            )),

            // r#"resources.*[]"#, // 4 err
            Err(nom::Err::Failure(ParserError {
                span: unsafe {
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
            (">", ValueOperator::Cmp(CmpOperator::Gt)),
            ("<", ValueOperator::Cmp(CmpOperator::Lt)),
            ("==", ValueOperator::Cmp(CmpOperator::Eq)),
            ("!=", ValueOperator::Not(CmpOperator::Eq)),
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
                        Span2::new_from_raw_offset(
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
                assert_eq!(clause(from_str2(&access_pattern)), error);
            }
        }

        let lhs_separator = " ";
        for each in lhs.iter() {
            for (op, _) in comparators.iter() {
                let access_pattern = format!("{lhs}{lhs_sep}{op}{rhs_sep}{rhs}{msg}",
                                             lhs = *each, rhs = rhs, op = *op, lhs_sep = lhs_separator, rhs_sep = rhs_separator, msg = "<< message >>");
                let offset = (*each).len() + (*op).len() + 1;
                let fragment = format!("{sep}{rhs}{msg}", rhs = rhs, sep = rhs_separator, msg = "<< message >>");
                let error = Err(nom::Err::Error(ParserError {
                    span: unsafe {
                        Span2::new_from_raw_offset(
                            offset,
                            1,
                            &fragment,
                            "",
                        )
                    },
                    kind: nom::error::ErrorKind::Char,
                    context: "expecting one or more WS or comment blocks".to_string(),
                }));
                assert_eq!(clause(from_str2(&access_pattern)), error);
            }
        }

        //
        // Testing for missing access part
        //
        assert_eq!(Err(nom::Err::Error(ParserError {
            span: from_str2(""),
            kind: nom::error::ErrorKind::Alpha,
            context: "".to_string(),
        })), clause(from_str2("")));

        //
        // Testing for missing access
        //
        assert_eq!(Err(nom::Err::Error(ParserError {
            span: from_str2(" > 10"),
            kind: nom::error::ErrorKind::Alpha,
            context: "".to_string(),
        })), clause(from_str2(" > 10")));

        //
        // Testing binary operator missing RHS
        //
        for each in lhs.iter() {
            for (op, _) in comparators.iter() {
                let access_pattern = format!("{lhs} {op} << message >>", lhs = *each, op = *op);
                println!("Testing for {}", access_pattern);
                let offset = (*each).len() + (*op).len() + 2; // 2 is for 2 spaces
                let error = Err(nom::Err::Failure(ParserError {
                    span: unsafe {
                        Span2::new_from_raw_offset(
                            offset,
                            1,
                            "<< message >>",
                            "",
                        )
                    },
                    kind: nom::error::ErrorKind::Char, // this comes off parse_map
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
                    Span2::new_from_raw_offset(
                        examples[1].len() - 1,
                        1,
                        "\n",
                        ""
                    )
                },
                GuardClause::NamedRule(
                    "secure".to_string(),
                    FileLocation { line: 1, column: 1, file_name: "" },
                    false,
                    None)
            )),

            // "!secure or !encrypted",        // 2 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        "!secure".len(),
                        1,
                        " or !encrypted",
                        ""
                    )
                },
                GuardClause::NamedRule(
                    "secure".to_string(),
                    FileLocation { line: 1, column: 1, file_name: "" },
                    true,
                    None)
            )),

            // "secure\n\nor\t encrypted",     // 3 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        "secure".len(),
                        1,
                        "\n\nor\t encrypted",
                        ""
                    )
                },
                GuardClause::NamedRule(
                    "secure".to_string(),
                    FileLocation { line: 1, column: 1, file_name: "" },
                    false,
                    None)
            )),

            // "let x = 10",                   // 4 err
            Err(nom::Err::Failure(
                ParserError {
                    span: unsafe {
                        Span2::new_from_raw_offset(
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
                        Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[6].len(),
                        1,
                        "",
                        "",
                    )
                },
                GuardClause::NamedRule(
                    "secure".to_string(),
                    FileLocation { line: 1, column: 1, file_name: "" },
                    false,
                    Some("this is secure ${PARAMETER.MSG}".to_string())),
            )),

            // "!secure <<this is not secure ${PARAMETER.MSG}>> or !encrypted" // 8 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[7].len() - " or !encrypted".len(),
                        1,
                        " or !encrypted",
                        ""
                    )
                },
                GuardClause::NamedRule(
                    "secure".to_string(),
                    FileLocation { line: 1, column: 1, file_name: "" },
                    true,
                    Some("this is not secure ${PARAMETER.MSG}".to_string())),
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[1].len() - 1,
                        1,
                        "\n",
                        "",
                    )
                },
                vec![
                    vec![GuardClause::NamedRule(
                        "secure".to_string(),
                        FileLocation {
                            line: 1,
                            column: 1,
                            file_name: "",
                        },
                        false,
                        None,
                    ),
                    ]
                ]
            )),

            // "!secure << was not secure ${PARAMETER.SECURE_MSG}>>", // Ok 2
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[2].len(),
                        1,
                        "",
                        "",
                    )
                },
                vec![
                    vec![GuardClause::NamedRule(
                        "secure".to_string(),
                        FileLocation {
                            line: 1,
                            column: 1,
                            file_name: "",
                        },
                        true,
                        Some(" was not secure ${PARAMETER.SECURE_MSG}".to_string()))
                    ]
                ]
            )),

            // "secure\nconfigurations.containers.*.image == /httpd:2.4/", // Ok 3
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
                        examples[3].len(),
                        2,
                        "",
                        "",
                    )
                },
                vec![
                    vec![
                        GuardClause::NamedRule(
                            "secure".to_string(),
                            FileLocation {
                                line: 1,
                                column: 1,
                                file_name: "",
                            },
                            false,
                            None)
                    ],
                    vec![
                        GuardClause::Clause(
                            AccessClause {
                                location: FileLocation {
                                    file_name: "",
                                    column: 1,
                                    line: 2,
                                },
                                compare_with: Some(LetValue::Value(Value::Regex("httpd:2.4".to_string()))),
                                query: "configurations.containers.*.image".split(".")
                                    .map(|s| if s == "*" { QueryPart::AllKeys } else { QueryPart::Key(s.to_string()) }).collect(),
                                custom_message: None,
                                comparator: (CmpOperator::Eq, false),
                            },
                            false,
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
                    Span2::new_from_raw_offset(
                        examples[4].len(),
                        4,
                        "",
                        "",
                    )
                },
                vec![
                    vec![
                        GuardClause::NamedRule("secure".to_string(), FileLocation { line: 1, column: 1, file_name: "" }, false, None),
                        GuardClause::NamedRule("exception".to_string(), FileLocation { line: 2, column: 16, file_name: "" }, true, None),
                    ],
                    vec![
                        GuardClause::Clause(
                            AccessClause {
                                location: FileLocation { file_name: "", column: 16, line: 4 },
                                compare_with: Some(LetValue::Value(Value::Regex("httpd:2.4".to_string()))),
                                query: "configurations.containers[*].image".split(".").map( |part|
                                    if part.contains('[') {
                                        QueryPart::AllIndices("containers".to_string())
                                    } else {
                                        QueryPart::Key(part.to_string())
                                    }
                                ).collect(),
                                custom_message: None,
                                comparator: (CmpOperator::Eq, false),
                            },
                            false,
                        )
                    ],
                ]
            )),

            // r#"secure or
            //    !exception
            //    let x = 10"# // Err, can not handle assignments
            Err(nom::Err::Failure(ParserError {
                span: unsafe {
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[5].len(),
                        1,
                        "",
                        ""
                    )
                },
                LetExpr {
                    var: String::from("engines"),
                    value: LetValue::AccessClause(AccessQuery::from([
                        QueryPart::Variable(String::from("engines"))]))
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
                    Span2::new_from_raw_offset(
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
                    Span2::new_from_raw_offset(
                        examples[7].len(),
                        1,
                        "",
                        ""
                    )
                },
                context: "".to_string(),
                kind: nom::error::ErrorKind::Alpha, // from access
            })),

            // "let aurora_dbs = resources.*[ type IN [/AWS::RDS::DBCluster/, /AWS::RDS::GlobalCluster/]]", // 8 Ok
            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
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
                            QueryPart::Filter(String::from("*"), Conjunctions::from(
                                [
                                    Disjunctions::from([
                                        FilterPart {
                                            name: String::from("type"),
                                            comparator: (CmpOperator::In, false),
                                            value: Some(VariableOrValue::Value(Value::List(
                                                vec![Value::Regex(String::from("AWS::RDS::DBCluster")),
                                                     Value::Regex(String::from("AWS::RDS::GlobalCluster"))]
                                            ))),
                                        }
                                    ])
                                ],
                            ))
                        ])
                    )
                }

            )),
        ];

        for (idx, each) in examples.iter().enumerate() {
            println!("Test #{}: {}", idx, *each);
            let span = Span2::new_extra(*each, "");
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
                    Span2::new_from_raw_offset(
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
                                GuardClause::Clause(AccessClause {
                                    query: AccessQuery::from([
                                        QueryPart::Variable(String::from("keyName"))
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
                                }, false),
                            ]),
                            Disjunctions::from([
                                GuardClause::Clause(AccessClause {
                                    query: AccessQuery::from([
                                        QueryPart::Variable(String::from("keyName"))
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
                                }, false),
                            ]),
                        ])
                    }
                }
            )),

            Ok((
                unsafe {
                    Span2::new_from_raw_offset(
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
                                GuardClause::Clause(AccessClause {
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
                                }, false),
                            ])
                        ])
                    }
                }
            )),

            Ok((
                unsafe {
                   Span2::new_from_raw_offset(
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
                            GuardClause::Clause(AccessClause {
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
                            }, false),
                        ]),
                    ])),
                    block: Block {
                        assignments: vec![],
                        conjunctions: Conjunctions::from([
                            Disjunctions::from([
                                GuardClause::Clause(AccessClause {
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
                                }, false),
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
          %volumes.*.Ebs.encryped == true               # Ebs volume must be encryped
          %volumes.*.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
    } or
    AWS::EC2::Instance {                   # OR a regular volume (disjunction)
        block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
    }
}"#
        ];

        println!("{:?}", rule_block(from_str2(examples[0])).unwrap());
    }

}
