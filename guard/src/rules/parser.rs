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
///  var_name                   = CHAR 1*(CHAR/_)
///  var_name_access            = "%" var_name
///
///  dotted_access              = "." (var_name / var_name_access)
///
///  property_access            = var_name *(dotted_access)
///  variable_access            = var_name_access *(dotted_access)
///
///  access                     = variable_access /
///                               property_access
///
///  not_keyword                = "NOT" / "not"
///  basic_cmp                  = "==" / ">=" / "<=" / ">" / "<"
///  other_operators            = "IN" / "EXISTS"
///  not_other_operators        = not_keyword 1*SP other_operators
///  not_cmp                    = "!=" / not_other_operators / "NOT_IN"
///  special_operators          = "KEYS" 1*SP (other_operators / not_other_operators)
///
///  cmp                        = basic_cmp / other_operators / not_cmp / special_operators
///
///  clause                     = access 1*(LWSP/comment) cmp 1*(LWSP/comment) (access/value)
///  disjunction_clauses        = clause 1*(or_term 1*(LWSP/comment) clause)
///
///  type_clause                = type_name 1*SP clause
///  type_block                 = type_name *SP "{" *(LWSP/comment) 1*clause "}"
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
///  assignment                 = "let" 1*SP var_name ("=" / ":=") 1*SP value
///  named_rule                 = "rule" 1*SP var_name "{"
///
///
///
///
///  ```
///
///
///



//
// Extern crate dependencies
//
use nom::{FindSubstring, InputTake, IResult};
use nom::branch::alt;
use nom::bytes::complete::{is_a, is_not, tag, take_while, take_while1};
use nom::character::complete::{alphanumeric1, char, digit1, one_of};
use nom::character::complete::{anychar, multispace0, multispace1, space0, space1};
use nom::combinator::{all_consuming, cut, map, map_res, opt, peek, value};
use nom::multi::{many0, many1, separated_list, separated_nonempty_list};
use nom::number::complete::double;
use nom::sequence::{delimited, preceded, separated_pair, terminated, tuple};
use nom_locate::LocatedSpan;

use crate::rules::common::*;
//
// Local crate
//
use crate::rules::values::{LOWER_INCLUSIVE, RangeType, UPPER_INCLUSIVE, Value};

use super::expr::*;
use super::values::*;
use indexmap::map::IndexMap;

pub(crate) type Span<'a> = LocatedSpan<&'a str, &'a str>;

pub(crate) fn from_str(in_str: &str) -> Span {
    Span::new_extra(in_str, "")
}

//
// Rust std crate
//

///
/// Scalar Values string, bool, int, f64
///

pub(super) fn parse_int_value(input: Span) -> IResult<Span, Value> {
    let negative = map_res(preceded(tag("-"), digit1), |s: Span| {
        s.fragment().parse::<i64>().map(|i| Value::Int(-1 * i))
    });
    let positive = map_res(digit1, |s: Span| {
        s.fragment().parse::<i64>().map(Value::Int)
    });
    alt((positive, negative))(input)
}

pub(super) fn parse_string(input: Span) -> IResult<Span, Value> {
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

pub(super) fn parse_bool(input: Span) -> IResult<Span, Value> {
    let true_parser = value(Value::Bool(true), alt((tag("true"), tag("True"))));
    let false_parser = value(Value::Bool(false), alt((tag("false"), tag("False"))));
    alt((true_parser, false_parser))(input)
}

pub(super) fn parse_float(input: Span) -> IResult<Span, Value> {
    let whole = digit1(input.clone())?;
    let fraction = opt(preceded(char('.'), digit1))(whole.0)?;
    let exponent = opt(tuple((one_of("eE"), one_of("+-"), digit1)))(fraction.0)?;
    if (fraction.1).is_some() || (exponent.1).is_some() {
        let r = double(input)?;
        return Ok((r.0, Value::Float(r.1)));
    }
    Err(nom::Err::Error((input, nom::error::ErrorKind::Float)))
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

pub(super) fn parse_regex(input: Span) -> IResult<Span, Value> {
    delimited(char('/'), parse_regex_inner, char('/'))(input)
}

pub(super) fn parse_char(input: Span) -> IResult<Span, Value> {
    map(anychar, Value::Char)(input)
}

pub(super) fn range_value(input: Span) -> IResult<Span, Value> {
    delimited(
        space0,
        alt((parse_float, parse_int_value, parse_char)),
        space0,
    )(input)
}

pub(super) fn parse_range(input: Span) -> IResult<Span, Value> {
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

        _ => return Err(nom::Err::Failure((parsed.0, nom::error::ErrorKind::IsNot))),
    };
    Ok((parsed.0, val))
}

//
// Adding the parser to return scalar values
//
pub(super) fn parse_scalar_value(input: Span) -> IResult<Span, Value> {
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

pub(super) fn parse_list(input: Span) -> IResult<Span, Value> {
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

pub(super) fn key_value(input: Span) -> IResult<Span, (String, Value)> {
    separated_pair(
        preceded(take_while_ws_or_comment, key_part),
        followed_by(':'),
        parse_value,
    )(input)
}

pub(super) fn parse_map(input: Span) -> IResult<Span, Value> {
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
                .collect::<IndexMap<String, Value>>(),
        ),
    ))
}

pub(super) fn parse_null(input: Span) -> IResult<Span, Value> {
    value(Value::Null, alt((tag("null"), tag("NULL"))))(input)
}

pub(crate) fn parse_value(input: Span) -> IResult<Span, Value> {
    preceded(
        take_while_ws_or_comment,
        alt((
            parse_null,
            parse_scalar_value,
            parse_range,
            parse_list,
            parse_map,
        )),
    )(input)
}

///
/// variable name for an assignment
///
/// var_name    ::=   [a-zA-Z0-9_]+
///
pub(crate) fn var_name(input: Span) -> IResult<Span, &str> {
    map(
        take_while1(|c: char| (c.is_alphanumeric() || c == '_') && c != ':'),
        |c: Span| *c.fragment(),
    )(input)
}

pub(crate) fn value_or_access(input: Span) -> IResult<Span, LetValue> {
    alt((
        map(parse_value, LetValue::Value),
        map(property_access, LetValue::PropertyAccess),
    ))(input)
}

fn var_terminated(input: Span) -> IResult<Span, ()> {
    //
    // It must either terminate by a newline or it must
    // be followed with a comment. We use the peek aspect
    // to not consume the '#' char if it is a comment
    //
    match is_a::<_, Span, (Span, nom::error::ErrorKind)>("\r\n")(input.clone()) {
        Ok((remainder, _ign)) => Ok((remainder, ())),
        Err(_) => match preceded::<Span, _, _, (Span, nom::error::ErrorKind), _, _>(space0, peek(char('#')))(input.clone()) {
            Ok((remainder, _ign)) => Ok((remainder, ())),
            Err(_) => Err(nom::Err::Failure((input, nom::error::ErrorKind::CrLf)))
        }
    }
}

///
/// variable assignment
///
/// var_assignment    ::=  ('let' sp+)? var_name sp1 ':=' sp* (value|%var_name)
///
pub(crate) fn var_assignment(input: Span) -> IResult<Span, LetExpr> {
    //
    //  Expressions can be of the form
    //      let var = <value>\n
    //      let var = a.b.c\n
    //      var := <value> #comment \n
    //
//    let x= preceded(tag("let"), space1);
//
//    let (input, var) =
//        delimited(space0, var_name,
//                  (preceded(space0,
//                               alt((tag(":="), tag("="))))))(input)?;
//
//    //
//    // If the above to parts passed when parsing then the remainder must succeed
//    //
//    let (input, value) =
//        cut(preceded(take_while_ws_or_comment, value_or_access))(input)?;
//
//    let terminated = |i: Span| -> IResult<Span, ()> {
//        Ok((i, ()))
//    };
//
//    //
//    // If must end in a \n or \r or # dfdfdfd \n or \r
//    //
//    let (input, _ignored_ws) = var_terminated(input)?;
//    Ok((input, LetExpr { var: var.to_string(), value }))

      map(
          tuple((
              preceded(tag("let"), space1),  // optional let keyword
              var_name, // var_name
              cut(preceded(space1, alt((tag(":="), tag("="))))), // followed by := or =
              cut(preceded(take_while_ws_or_comment, value_or_access)), // value access
              var_terminated, // already throws nom::Err::Failure(...) // terminated with newline or comment
          )),
          |(_let, var, _ign_assign_sign, value, _end)| LetExpr { var: var.to_string(), value },
      )(input)
}

///
/// variable access
///
/// var_access   ::=   '%' var_name
///
pub(crate) fn var_access(input: Span) -> IResult<Span, &str> {
    preceded(char('%'), var_name)(input)
}

pub(crate) fn property_name(input: Span) -> IResult<Span, &str> {
    map(take_while1(|c: char| c.is_alphanumeric()), |s: Span| {
        *s.fragment()
    })(input)
}

pub(crate) fn property_or_wildcard(input: Span) -> IResult<Span, &str> {
    alt((var_name, map(char('*'), |_c: char| "*")))(input)
}

pub(crate) fn map_property_access(
    var: Option<String>,
    prop: &str,
    remain: Vec<&str>,
) -> PropertyAccess {
    let mut all: Vec<String> = remain.iter().map(|s| (*s).to_string()).collect();
    all.insert(0, prop.to_string());
    PropertyAccess {
        var_access: var,
        property_dotted_notation: all,
    }
}

pub(crate) fn property_dotted_notation(input: Span) -> IResult<Span, PropertyAccess> {
    map(
        tuple((
            var_name,
            many0(preceded(char('.'), property_or_wildcard)),
        )),
        |(name, remain)| map_property_access(None, name, remain),
    )(input)
}

pub(crate) fn var_property_dotted_notation(input: Span) -> IResult<Span, PropertyAccess> {
    map(
        tuple((var_access, many1(preceded(char('.'), property_or_wildcard)))),
        |(var, prop)| PropertyAccess {
            var_access: Some(var.to_string()),
            property_dotted_notation: prop.iter().map(|s| (*s).to_string()).collect(),
        },
    )(input)
}

///
/// Property access
///
/// property_access    ::=   var_access |
///                          var_access.property_name[.property_name|.\\*]* |
///                          property_name[.property_name|\\.*]*
///
pub(crate) fn property_access(input: Span) -> IResult<Span, PropertyAccess> {
    alt((
        property_dotted_notation,
        var_property_dotted_notation,
        map(var_access, |var| PropertyAccess {
            var_access: Some(var.to_string()),
            property_dotted_notation: vec![],
        }),
    ))(input)
}

pub(crate) fn extract_message(input: Span) -> IResult<Span, &str> {
    match input.find_substring(">>") {
        None => Err(nom::Err::Failure((input, nom::error::ErrorKind::Tag))),
        Some(v) => {
            let split = input.take_split(v);
            Ok((split.0, *split.1.fragment()))
        }
    }
}

pub(crate) fn custom_message(input: Span) -> IResult<Span, &str> {
    delimited(tag("<<"), extract_message, tag(">>"))(input)
}

pub(crate) fn tag_in(input: Span) -> IResult<Span, Span> {
    alt((tag("IN"), tag("in")))(input)
}

pub(crate) fn tag_not(input: Span) -> IResult<Span, Span> {
    alt((tag("not"), tag("NOT")))(input)
}

pub(crate) fn tag_or(input: Span) -> IResult<Span, Span> {
    alt((tag("or"), tag("|OR|")))(input)
}
//
// not_in  = !IN | not in | NOT_IN
//
pub(crate) fn not_in(input: Span) -> IResult<Span, Span> {
   alt((
            preceded(char('!'), tag_in),
            preceded(tag_not, preceded(space1, tag_in)),
            tag("NOT_IN")
        ))(input)
}

pub(crate) fn value_cmp(input: Span) -> IResult<Span, ValueOperator> {
    alt((
        value(ValueOperator::Cmp(CmpOperator::Eq), tag("==")),
        value(ValueOperator::Cmp(CmpOperator::Ge), tag(">=")),
        value(ValueOperator::Cmp(CmpOperator::Le), tag("<=")),
        value(ValueOperator::Cmp(CmpOperator::Gt), char('>')),
        value(ValueOperator::Cmp(CmpOperator::Lt), char('<')),
        value(ValueOperator::Not(CmpOperator::Eq), tag("!=")),
        value(ValueOperator::Cmp(CmpOperator::In), tag_in),
        value(ValueOperator::Not(CmpOperator::In), not_in),
    ))(input)
}

///
/// clause     ::=
///
pub(crate) fn property_clause(input: Span) -> IResult<Span, Clause> {
    let location = Location {
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
        file_name: input.extra
    };
    map(
        tuple((
            property_access,
            preceded(multispace1, value_cmp),
            opt(preceded(multispace1, value_or_access)),
            opt(preceded(space0, custom_message)),
        )),
        move |(access, comparator, compare_with, custom_message)| Clause {
            access,
            comparator,
            compare_with,
            custom_message: match custom_message {
                Some(s) => Some(s.to_string()),
                None => None
            },
            location
        },
    )(input)
}

pub(crate) fn type_name(input: Span) -> IResult<Span, &str> {
    map(
        take_while1(|c: char| c.is_alphanumeric() || c == ':'),
        |s: Span| *s.fragment(),
    )(input)
}

pub(crate) fn disjunction_property_clauses_internal(input: Span) -> IResult<Span, PropertyClause> {
    map(
        separated_nonempty_list(
            delimited(space1, tag_or, take_while_ws_or_comment),
            property_clause,
        ),
        |cls| {
            if cls.len() > 1 {
                PropertyClause::Disjunction(cls)
            } else {
                PropertyClause::Clause(cls[0].clone())
            }
        },
    )(input)
}

pub(crate) fn disjunction_property_clauses(input: Span) -> IResult<Span, PropertyClause> {
    map(
        separated_nonempty_list(
            delimited(space1, tag_or, take_while_ws_or_comment),
            property_clause,
        ),
        |cls| {
            if cls.len() > 1 {
                PropertyClause::Disjunction(cls)
            } else {
                PropertyClause::Clause(cls[0].clone())
            }
        },
    )(input)
}

pub(crate) fn type_property_clause(input: Span) -> IResult<Span, TypeClauseExpr> {
    map(
        tuple((
            preceded(take_while_ws_or_comment, type_name),
            preceded(space1, property_clause),
        )),
        |(name, clause)| TypeClauseExpr {
            type_name: name.to_string(),
            type_clauses: vec![PropertyClause::Clause(clause)],
        },
    )(input)
}

pub(crate) fn type_block_var_property_clause(input: Span) -> IResult<Span, PropertyClause> {
    map(var_assignment, |assignment| {
        PropertyClause::Variable(assignment)
    })(input)
}

pub(crate) fn type_block_var_and_property_clauses(input: Span) -> IResult<Span, Vec<PropertyClause>> {
    many1(preceded(
        take_while_ws_or_comment,
        alt((type_block_var_property_clause, disjunction_property_clauses)),
    ))(input)
}

pub(crate) fn type_block_property_clause(input: Span) -> IResult<Span, TypeClauseExpr> {
    map(
        tuple((
            preceded(take_while_ws_or_comment, type_name),
            preceded(multispace0, char('{')),
            cut(type_block_var_and_property_clauses),
            cut(terminated(take_while_ws_or_comment, char('}'))),
        )),
        |(type_name, _, type_clauses, _)| TypeClauseExpr {
            type_name: type_name.to_string(),
            type_clauses,
        },
    )(input)
}

pub(crate) fn default_rule_type_clauses(input: Span) -> IResult<Span, Vec<TypeClauseExpr>> {
    preceded(
        multispace0,
        many1(terminated(type_property_clause, multispace0)),
    )(input)
}

pub(crate) fn default_rule_block_clauses(input: Span) -> IResult<Span, NamedRuleBlockExpr> {
    let location = Location {
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
        file_name: input.extra
    };
    map(default_rule_type_clauses, move |clauses| {
        let named_block = clauses
            .into_iter()
            .clone()
            .map(move |c| NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(c)))
            .collect();
        NamedRuleBlockExpr {
            rule_name: "default".to_string(),
            rule_clauses: named_block,
            location
        }
    })(input)
}

//
// Rules related
//

pub(crate) fn type_rule_clause_expr(input: Span) -> IResult<Span, NamedRuleClauseExpr> {
    alt((
        map(type_block_property_clause, |cls| {
            NamedRuleClauseExpr::TypeClause(cls)
        }),
        map(type_property_clause, |type_cls| {
            NamedRuleClauseExpr::TypeClause(type_cls)
        })
    ))(input)
}

pub(crate) fn type_named_rule_clause_expr(input: Span) -> IResult<Span, NamedRuleClauseExpr> {
    //
    // Order does matter, we attempt block type, single type or rule name
    //
    alt((
        type_rule_clause_expr,
        map(var_name, |name| NamedRuleClauseExpr::NamedRule(name.to_string())),
        map(terminated(tag_not, var_name), |name| {
            NamedRuleClauseExpr::NotNamedRule(name.to_string())
        }),
    ))(input)
}

pub(crate) fn var_assign_or_disjunction(input: Span) -> IResult<Span, NamedRuleExpr> {
    //
    // Order does matter here. There are 2 possibilities here, a variable assignment
    // or just a rule name. If we delegate to the other parser it might interpret the
    // first part of the assignment as a rule name. Yes there are ways to deal with it
    // to be super perfect, but the ordering naturally delegates without the complexity
    //
    alt((
        map(var_assignment, NamedRuleExpr::Variable),
        disjunction_rule_block_expr,
    ))(input)
}

pub(crate) fn disjunction_rule_expr(input: Span) -> IResult<Span, NamedRuleExpr> {
    map(
        separated_nonempty_list(
            delimited(
                take_while_ws_or_comment,
                tag_or,
                take_while_ws_or_comment,
            ),
            type_rule_clause_expr,
        ),
        |cls| {
            if cls.len() > 1 {
                NamedRuleExpr::DisjunctionRuleClause(cls)
            } else {
                NamedRuleExpr::RuleClause(cls[0].clone())
            }
        },
    )(input)

}

pub(crate) fn disjunction_rule_block_expr(input: Span) -> IResult<Span, NamedRuleExpr> {
    map(
        separated_nonempty_list(
            delimited(
                take_while_ws_or_comment,
                tag_or,
                take_while_ws_or_comment,
            ),
            type_named_rule_clause_expr,
        ),
        |cls| {
            if cls.len() > 1 {
                NamedRuleExpr::DisjunctionRuleClause(cls)
            } else {
                NamedRuleExpr::RuleClause(cls[0].clone())
            }
        },
    )(input)

    //    if result.1.is_empty() {
    //        Err(nom::Err::Error((input, nom::error::ErrorKind::SeparatedList)))
    //    } else {
    //        Ok((
    //            result.0,
    //            if result.1.len() > 1 {
    //                NamedRuleExpr::DisjunctionRuleClause(result.1)
    //            } else {
    //                NamedRuleExpr::RuleClause(result.1[0].clone())
    //            }
    //        ))
    //    }
}

pub(crate) fn named_rule_block_expr(input: Span) -> IResult<Span, NamedRuleBlockExpr> {
    let input = take_while_ws_or_comment(input)?.0;
    let location = Location {
        line: input.location_line(),
        column: input.get_utf8_column() as u32,
        file_name: input.extra
    };
    map(
        tuple((
            tag("rule"),
            cut(preceded(space1, var_name)), // this has to exist
            cut(preceded(take_while_ws_or_comment, char('{'))),
            many1(preceded(
                take_while_ws_or_comment,
                var_assign_or_disjunction,
            )),
            cut(preceded(take_while_ws_or_comment, char('}'))),
        )),
        move |(_, name, _, exprs, _)| NamedRuleBlockExpr {
            rule_name: name.to_string(),
            rule_clauses: exprs,
            location,
        },
    )(input)
}

pub(crate) fn rules_file_parse(input: Span) -> IResult<Span, Expr> {
    let line =  input.location_line();
    let column = input.get_utf8_column() as u32;
    //let file_name: input.extra
    alt((
        map(
            preceded(take_while_ws_or_comment,named_rule_block_expr),
            Expr::NamedRule
        ),
        map(
            preceded( take_while_ws_or_comment, disjunction_rule_expr),
            move |expr| {
                Expr::NamedRule(NamedRuleBlockExpr {
                    rule_name: "default".to_string(),
                    rule_clauses: vec![expr],
                    location: Location {
                        line,
                        column,
                        file_name: input.extra
                    }
                })
            },
        ),
        map(
            preceded(take_while_ws_or_comment, var_assignment),
            Expr::Assignment,
        )
    ))(input)
}

pub(crate) fn parse_rules(input: Span) -> IResult<Span, Rules> {
    all_consuming(many1(delimited(
        take_while_ws_or_comment,
        rules_file_parse,
        take_while_ws_or_comment)
    ))(input)
}

#[cfg(test)]
mod tests {
    use crate::rules::values::make_linked_hashmap;
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
            parse_int_value(from_str(s)),
            Ok((span, Value::Int(12670090)))
        )
    }

    #[test]
    fn test_parse_string() {
        let s = "\"Hi there\"";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_string(from_str(s)),
            Ok((cmp, Value::String("Hi there".to_string())))
        );

        // Testing embedded quotes using '' for the string
        let s = r#"'"Hi there"'"#;
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_string(from_str(s)),
            Ok((cmp, Value::String("\"Hi there\"".to_string())))
        );

        let s = r#"'Hi there'"#;
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_string(from_str(s)),
            Ok((cmp, Value::String("Hi there".to_string())))
        );
    }

    #[test]
    fn test_parse_string_rest() {
        let hi = "\"Hi there\"";
        let s = hi.to_owned() + " 1234";
        let cmp = unsafe { Span::new_from_raw_offset(hi.len(), 1, " 1234", "") };
        assert_eq!(
            parse_string(from_str(&s)),
            Ok((cmp, Value::String("Hi there".to_string())))
        );
    }

    #[test]
    fn test_parse_string_from_scalar() {
        let hi = "\"Hi there\"";
        let s = hi.to_owned() + " 1234";
        let cmp = unsafe { Span::new_from_raw_offset(hi.len(), 1, " 1234", "") };
        assert_eq!(
            parse_scalar_value(from_str(&s)),
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
            parse_bool(from_str(s)),
            Ok((cmp.clone(), Value::Bool(true)))
        );
        let s = "true";
        assert_eq!(
            parse_bool(from_str(s)),
            Ok((cmp.clone(), Value::Bool(true)))
        );
        let s = "False";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_bool(from_str(s)),
            Ok((cmp.clone(), Value::Bool(false)))
        );
        let s = "false";
        assert_eq!(
            parse_bool(from_str(s)),
            Ok((cmp, Value::Bool(false)))
        );
        let s = "1234";
        let cmp = unsafe { Span::new_from_raw_offset(0, 1, "1234", "") };
        assert_eq!(
            parse_bool(from_str(s)),
            Err(nom::Err::Error((cmp, nom::error::ErrorKind::Tag)))
        );
        let s = "true1234";
        let cmp = unsafe { Span::new_from_raw_offset(4, 1, "1234", "") };
        assert_eq!(parse_bool(from_str(s)), Ok((cmp, Value::Bool(true))));
    }

    #[test]
    fn test_parse_float() {
        let s = "12.0";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_float(from_str(s)),
            Ok((cmp, Value::Float(12.0)))
        );
        let s = "12e+2";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_float(from_str(s)),
            Ok((cmp, Value::Float(12e+2)))
        );
        let s = "error";
        let cmp = unsafe { Span::new_from_raw_offset(0, 1, "error", "") };
        assert_eq!(
            parse_float(from_str(s)),
            Err(nom::Err::Error((cmp, nom::error::ErrorKind::Digit)))
        );
    }

    #[test]
    fn test_parse_regex() {
        let s = "/.*PROD.*/";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_regex(from_str(s)),
            Ok((cmp, Value::Regex(".*PROD.*".to_string())))
        );

        let s = "/arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/";
        let cmp = unsafe {
            Span::new_from_raw_offset(11, 1, ",.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*/", "") };
        assert_eq!(
            parse_regex(from_str(s)),
            Ok((cmp, Value::Regex("arn:[\\w+=".to_string())))
        );

        let s = "/arn:[\\w+=\\/,.@-]+:[\\w+=\\/,.@-]+:[\\w+=\\/,.@-]*:[0-9]*:[\\w+=,.@-]+(\\/[\\w+=,.@-]+)*/";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_regex(from_str(s)),
            Ok((cmp, Value::Regex("arn:[\\w+=/,.@-]+:[\\w+=/,.@-]+:[\\w+=/,.@-]*:[0-9]*:[\\w+=,.@-]+(/[\\w+=,.@-]+)*".to_string())))
        );
    }

    #[test]
    fn test_parse_scalar() {
        let s = "1234";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_scalar_value(from_str(s)),
            Ok((cmp, Value::Int(1234)))
        );
        let s = "12.089";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_scalar_value(from_str(s)),
            Ok((cmp, Value::Float(12.089)))
        );
        let s = "\"String in here\"";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_scalar_value(from_str(s)),
            Ok((cmp, Value::String("String in here".to_string())))
        );
        let s = "true";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_scalar_value(from_str(s)),
            Ok((cmp, Value::Bool(true)))
        );
        let s = "false";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_scalar_value(from_str(s)),
            Ok((cmp, Value::Bool(false)))
        );
    }

    #[test]
    fn test_lists_success() {
        let s = "[]";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_list(from_str(s)),
            Ok((cmp, Value::List(vec![])))
        );
        let s = "[1, 2]";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_list(from_str(s)),
            Ok((cmp, Value::List(vec![Value::Int(1), Value::Int(2)])))
        );
        let s = "[\"hi\", \"there\"]";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_list(from_str(s)),
            Ok((
                cmp,
                Value::List(vec![Value::String("hi".to_string()), Value::String("there".to_string())])
            ))
        );
        let s = "[1,       \"hi\",\n\n3]";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 3, "", "") };
        assert_eq!(
            parse_list(from_str(s)),
            Ok((
                cmp,
                Value::List(vec![Value::Int(1), Value::String("hi".to_string()), Value::Int(3)])
            ))
        );

        let s = "[[1, 2], [3, 4]]";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_list(from_str(s)),
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
            parse_list(from_str(s)),
            Err(nom::Err::Error((cmp, nom::error::ErrorKind::Char)))
        );
        let s = "[]]";
        let cmp = unsafe { Span::new_from_raw_offset(2, 1, "]", "") };
        assert_eq!(
            parse_list(from_str(s)),
            Ok((cmp, Value::List(vec![])))
        )
    }

    #[test]
    fn test_map_key_part() {
        let s = "keyword";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            key_part(from_str(s)),
            Ok((cmp, "keyword".to_string()))
        );

        let s = r#"'keyword'"#;
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            key_part(from_str(s)),
            Ok((cmp, "keyword".to_string()))
        );

        let s = r#""keyword""#;
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            key_part(from_str(s)),
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

        assert_eq!(parse_map(from_str(s)), Ok((cmp, Value::Map(map))));
        let s = "{}";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            parse_map(from_str(s)),
            Ok((cmp, Value::Map(IndexMap::new())))
        );
        let s = "{ key:\n 1}";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        let map = make_linked_hashmap(vec![("key", Value::Int(1))]);
        assert_eq!(
            parse_map(from_str(s)),
            Ok((cmp, Value::Map(map.clone())))
        );
        let s = "{\n\n\nkey:\n\n\n1\n\t   }";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 8, "", "") };
        assert_eq!(parse_map(from_str(s)), Ok((cmp, Value::Map(map))));
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
            parse_map(from_str(s)),
            Ok((cmp.clone(), Value::Map(map.clone())))
        );
        assert_eq!(parse_value(from_str(s)), Ok((cmp, Value::Map(map))));

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
        let map = parse_map(from_str(s));
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
        let map = parse_map(from_str(s));
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
            parse_value(from_str(s)),
            Ok((cmp, Value::List(vec![map_value.clone()])))
        );
        assert_eq!(
            parse_list(from_str(s)),
            Ok((cmp, Value::List(vec![map_value])))
        );
    }

    #[test]
    fn test_range_type_success() {
        let s = "r(10,20)";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        let v = parse_range(from_str(s));
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
        let v = parse_range(from_str(s));
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
        let v = parse_range(from_str(s));
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
            parse_range(from_str(s)),
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
            parse_range(from_str(s)),
            Err(nom::Err::Error((cmp, nom::error::ErrorKind::Char)))
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
            parse_value(from_str(s)),
            Ok((cmp, Value::Int(1234i64)))
        );

        let s = "#this is a comment\n1234";
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(
            parse_value(from_str(s)),
            Ok((cmp, Value::Int(1234i64)))
        );

        let s = r###"

        # this comment is skipped
        # this one too
        [ "value1", # this one is skipped as well
          "value2" ]"###;
        let cmp = unsafe { Span::new_from_raw_offset(s.len(), 6, "", "") };
        assert_eq!(
            parse_value(from_str(s)),
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
            parse_value(from_str(s)),
            Ok((
                cmp,
                Value::Map(make_linked_hashmap(vec![("key", Value::String("Value".to_string()))]))
            ))
        )
    }

    #[test]
    fn let_value_test() {
        let s = "let kms_key_alias := [\"important1\", \"important2\"]\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(s)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "kms_key_alias".to_string(),
                    value: LetValue::Value(Value::List(vec![
                        Value::String("important1".to_string()),
                        Value::String("important2".to_string())
                    ])),
                }
            ))
        );

        let s = "let is_public := true\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(s)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "is_public".to_string(),
                    value: LetValue::Value(Value::Bool(true)),
                }
            ))
        );

        let s = r#"let complex := [
                           { vehicle: "Honda",
                             done: false
                            }]
"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 5, "", "") };
        assert_eq!(
            var_assignment(from_str(s)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "complex".to_string(),
                    value: LetValue::Value(Value::List(vec![Value::Map(make_linked_hashmap(
                        vec![
                            ("vehicle", Value::String("Honda".to_string())),
                            ("done", Value::Bool(false))
                        ]
                    ))])),
                }
            ))
        );
    }

    #[test]
    fn extract_message_test() {
        let s = "This is the \n\n message >>\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(23, 3, ">>\n", "") };
        assert_eq!(
            extract_message(from_str(s)),
            Ok((cmp_span, "This is the \n\n message "))
        );
        let s = r#"<< This is a custom message >>"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            custom_message(from_str(s)),
            Ok((cmp_span, " This is a custom message "))
        );

        let inner = r#"this is multiline custom message
                            How is this going. EOM"#;
        let s = "<<".to_owned() + inner + ">>";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(custom_message(from_str(&s)), Ok((cmp_span, inner)));

        // Failure cases
        let s = "";
        let cmp_span = unsafe { Span::new_from_raw_offset(0, 1, "", "") };
        assert_eq!(
            custom_message(from_str(s)),
            Err(nom::Err::Error((cmp_span, nom::error::ErrorKind::Tag)))
        );

        let s = "<< no ending";
        let cmp_span = unsafe { Span::new_from_raw_offset(2, 1, " no ending", "") };
        assert_eq!(
            custom_message(from_str(s)),
            Err(nom::Err::Failure((cmp_span, nom::error::ErrorKind::Tag)))
        );
    }

    #[test]
    fn var_termination_test(){
        //
        // Successful cases
        //
        let s = "\n";
        let r = var_terminated(Span::new_extra(s, ""));
        let remainder = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(r, Ok((remainder, ())));

        let s = "\r";
        let r = var_terminated(Span::new_extra(s, ""));
        let remainder = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(r, Ok((remainder, ())));

        let s = "# this is a comment\n";
        let r = var_terminated(Span::new_extra(s, ""));
        let remainder = Span::new_extra(s, "");
        assert_eq!(r, Ok((remainder, ())));

        let s = "   # this is a comment\n";
        let r = var_terminated(Span::new_extra(s, ""));
        let remainder = unsafe { Span::new_from_raw_offset(3, 1, "# this is a comment\n", "") };
        assert_eq!(r, Ok((remainder, ())));

        //
        // error cases
        //
        let s = "";
        let r = var_terminated(Span::new_extra(s, ""));
        assert_eq!(r, Err(nom::Err::Failure((Span::new_extra("", ""), nom::error::ErrorKind::CrLf))));

        let s = "property.access == \"this\"\n";
        let r = var_terminated(Span::new_extra(s, ""));
        assert_eq!(r, Err(nom::Err::Failure((Span::new_extra("property.access == \"this\"\n", ""), nom::error::ErrorKind::CrLf))));
    }

    #[test]
    fn var_access_test() {
        let s = "%var";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(var_access(from_str(s)), Ok((cmp_span, "var")));

        let s = "var";
        let cmp_span = unsafe { Span::new_from_raw_offset(0, 1, "var", "") };
        assert_eq!(
            var_access(from_str(s)),
            Err(nom::Err::Error((cmp_span, nom::error::ErrorKind::Char)))
        );
    }

    #[test]
    fn property_access_test() {
        let s = "public";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            property_access(from_str(s)),
            Ok((
                cmp_span,
                PropertyAccess {
                    var_access: None,
                    property_dotted_notation: vec!["public".to_string()],
                }
            ))
        );

        let s = "policy.statement.*.action";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            property_access(from_str(s)),
            Ok((
                cmp_span,
                PropertyAccess {
                    var_access: None,
                    property_dotted_notation: vec!["policy", "statement", "*", "action"].iter()
                        .map(|s| (*s).to_string()).collect(),
                }
            ))
        );

        let s = "%var.policy.statement";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            property_access(from_str(s)),
            Ok((
                cmp_span,
                PropertyAccess {
                    var_access: Some("var".to_string()),
                    property_dotted_notation: vec!["policy", "statement"].iter()
                        .map(|s| (*s).to_string()).collect(),
                }
            ))
        );
    }

    #[test]
    fn var_property_dotted_test() {
        let s = r#"%statement.*.action"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            var_property_dotted_notation(from_str(s)),
            Ok((
                cmp_span,
                PropertyAccess {
                    var_access: Some("statement".to_string()),
                    property_dotted_notation: vec!["*", "action"].iter()
                        .map(|s| (*s).to_string()).collect(),
                }
            ))
        )
    }

    #[test]
    fn var_assignment_test() {
        //
        // Success cases
        //
        // let var = "variable := \"that\"\\n";
        let var = r#"let variable := "that"
"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(var.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "variable".to_string(),
                    value: LetValue::Value(Value::String("that".to_string())),
                }
            ))
        );

        let var = "let variable := 10\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(var.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "variable".to_string(),
                    value: LetValue::Value(Value::Int(10)),
                }
            ))
        );

        let var = "let variable := %var2\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(var.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "variable".to_string(),
                    value: LetValue::PropertyAccess(PropertyAccess {
                        var_access: Some("var2".to_string()),
                        property_dotted_notation: vec![],
                    }),
                }
            ))
        );

        let var = "let variable := %var2  # this is comment\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(23, 1, "# this is comment\n", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "variable".to_string(),
                    value: LetValue::PropertyAccess(PropertyAccess {
                        var_access: Some("var2".to_string()),
                        property_dotted_notation: vec![],
                    }),
                }
            ))
        );

        //
        // let form testing
        //
        let var = "let variable = \"that\"\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(var.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "variable".to_string(),
                    value: LetValue::Value(Value::String("that".to_string())),
                }
            ))
        );

        let var = "let variable := \"that\"\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(var.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "variable".to_string(),
                    value: LetValue::Value(Value::String("that".to_string())),
                }
            ))
        );

        let var = "let letvariable := \"that\"\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(var.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(var)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "letvariable".to_string(),
                    value: LetValue::Value(Value::String("that".to_string())),
                }
            ))
        );

    }

    #[test]
    fn single_type_clause_test() {
        let s = r#"AWS::S3::Bucket public == true"#;
        let public_clause = Clause {
            access: PropertyAccess {
                var_access: None,
                property_dotted_notation: vec!["public".to_string()],
            },
            custom_message: None,
            compare_with: Some(LetValue::Value(Value::Bool(true))),
            comparator: ValueOperator::Cmp(CmpOperator::Eq),
            location: Location {
                line: 1,
                column: 17,
                file_name: ""
            }
        };
        let cmp = TypeClauseExpr {
            type_name: "AWS::S3::Bucket".to_string(),
            type_clauses: vec![PropertyClause::Clause(public_clause.clone())],
        };
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            type_property_clause(from_str(s)),
            Ok((cmp_span, cmp))
        );

        //
        // Multiline is fine
        //
        let s = r#"AWS::S3::Bucket public == true |OR|
                            policy == null"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        let policy_null = Clause {
            access: PropertyAccess {
                var_access: None,
                property_dotted_notation: vec!["policy".to_string()],
            },
            custom_message: None,
            compare_with: Some(LetValue::Value(Value::Null)),
            comparator: ValueOperator::Cmp(CmpOperator::Eq),
            location: Location {
                line: 2,
                column: 29,
                file_name: ""
            }
        };
        let cmp = TypeClauseExpr {
            type_name: "AWS::S3::Bucket".to_string(),
            type_clauses: vec![PropertyClause::Disjunction(vec![
                public_clause.clone(),
                policy_null.clone(),
            ])],
        };
        assert_eq!(
            type_property_clause(from_str(s)),
            Ok((cmp_span, cmp))
        );
    }

    #[test]
    fn type_var_and_property_clause() {
        let s = "let keyName := keyName\n";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 2, "", "") };
        assert_eq!(
            var_assignment(from_str(s)),
            Ok((
                cmp_span,
                LetExpr {
                    var: "keyName".to_string(),
                    value: LetValue::PropertyAccess(PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["keyName".to_string()],
                    }),
                }
            ))
        );

        let s = "";
        let cmp_span = unsafe { Span::new_from_raw_offset(0, 1, "", "") };
        assert_eq!(
            disjunction_property_clauses(from_str(s)),
            Err(nom::Err::Error((cmp_span, nom::error::ErrorKind::Char)))
        );
    }

    #[test]
    fn type_block_test() {
        let s = r#"
            AWS::EC2::Instance {
                let keyName := keyName

                %keyName        == "KeyName" or
                %keyName        == "Key2"

                image           == %latest  <<hook with latest image>>
                instanceType    == "t3.Medium"
            }"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 10, "", "") };
        let cmp = TypeClauseExpr {
            type_name: "AWS::EC2::Instance".to_string(),
            type_clauses: vec![
                PropertyClause::Variable(LetExpr {
                    var: "keyName".to_string(),
                    value: LetValue::PropertyAccess(PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["keyName".to_string()],
                    }),
                }),
                PropertyClause::Disjunction(vec![
                    Clause {
                        access: PropertyAccess {
                            var_access: Some("keyName".to_string()),
                            property_dotted_notation: vec![],
                        },
                        compare_with: Some(LetValue::Value(Value::String("KeyName".to_string()))),
                        comparator: ValueOperator::Cmp(CmpOperator::Eq),
                        custom_message: None,
                        location: Location {
                            line: 5,
                            column: 17,
                            file_name: ""
                        }
                    },
                    Clause {
                        access: PropertyAccess {
                            var_access: Some("keyName".to_string()),
                            property_dotted_notation: vec![],
                        },
                        compare_with: Some(LetValue::Value(Value::String("Key2".to_string()))),
                        comparator: ValueOperator::Cmp(CmpOperator::Eq),
                        custom_message: None,
                        location: Location {
                            line: 6,
                            column: 17,
                            file_name: ""
                        }
                    },
                ]),
                PropertyClause::Clause(Clause {
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["image".to_string()],
                    },
                    compare_with: Some(LetValue::PropertyAccess(PropertyAccess {
                        var_access: Some("latest".to_string()),
                        property_dotted_notation: vec![],
                    })),
                    comparator: ValueOperator::Cmp(CmpOperator::Eq),
                    custom_message: Some("hook with latest image".to_string()),
                    location: Location {
                        line: 8,
                        column: 17,
                        file_name: ""
                    }
                }),
                PropertyClause::Clause(Clause {
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["instanceType".to_string()],
                    },
                    compare_with: Some(LetValue::Value(Value::String("t3.Medium".to_string()))),
                    comparator: ValueOperator::Cmp(CmpOperator::Eq),
                    custom_message: None,
                    location: Location {
                        line: 9,
                        column: 17,
                        file_name: ""
                    }
                }),
            ],
        };
        assert_eq!(
            type_block_property_clause(from_str(s)),
            Ok((cmp_span, cmp))
        );
    }

    #[test]
    fn default_rule_type_clauses_test() {
        let s = r#"
        AWS::EC2::Instance securityGroups == ["InstanceSecurityGroup"]
        AWS::EC2::Instance keyName == "KeyName" or
            keyName != "Key2"

        AWS::EC2::Instance availabilityZone in ["us-east-2a", "us-east-2b"]
        AWS::EC2::Instance image == %latest

        AWS::EC2::Instance instanceType == "t3.medium""#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 9, "", "") };

        let cmp = vec![
            TypeClauseExpr {
                type_name: "AWS::EC2::Instance".to_string(),
                type_clauses: vec![PropertyClause::Clause(Clause {
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["securityGroups".to_string()],
                    },
                    custom_message: None,
                    comparator: ValueOperator::Cmp(CmpOperator::Eq),
                    compare_with: Some(LetValue::Value(Value::List(vec![Value::String(
                        "InstanceSecurityGroup".to_string(),
                    )]))),
                    location: Location {
                        line: 2,
                        column: 28,
                        file_name: ""
                    }
                })],
            },
            TypeClauseExpr {
                type_name: "AWS::EC2::Instance".to_string(),
                type_clauses: vec![PropertyClause::Disjunction(vec![
                    Clause {
                        access: PropertyAccess {
                            var_access: None,
                            property_dotted_notation: vec!["keyName".to_string()],
                        },
                        custom_message: None,
                        comparator: ValueOperator::Cmp(CmpOperator::Eq),
                        compare_with: Some(LetValue::Value(Value::String("KeyName".to_string()))),
                        location: Location {
                            line: 3,
                            column: 28,
                            file_name: ""
                        }
                    },
                    Clause {
                        access: PropertyAccess {
                            var_access: None,
                            property_dotted_notation: vec!["keyName".to_string()],
                        },
                        custom_message: None,
                        comparator: ValueOperator::Not(CmpOperator::Eq),
                        compare_with: Some(LetValue::Value(Value::String("Key2".to_string()))),
                        location: Location {
                            line: 4,
                            column: 13,
                            file_name: ""
                        }
                    },
                ])],
            },
            TypeClauseExpr {
                type_name: "AWS::EC2::Instance".to_string(),
                type_clauses: vec![PropertyClause::Clause(Clause {
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["availabilityZone".to_string()],
                    },
                    custom_message: None,
                    comparator: ValueOperator::Cmp(CmpOperator::In),
                    compare_with: Some(LetValue::Value(Value::List(vec![
                        Value::String("us-east-2a".to_string()),
                        Value::String("us-east-2b".to_string()),
                    ]))),
                    location: Location {
                        line: 6,
                        column: 28,
                        file_name: ""
                    }
                })],
            },
            TypeClauseExpr {
                type_name: "AWS::EC2::Instance".to_string(),
                type_clauses: vec![PropertyClause::Clause(Clause {
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["image".to_string()],
                    },
                    custom_message: None,
                    comparator: ValueOperator::Cmp(CmpOperator::Eq),
                    compare_with: Some(LetValue::PropertyAccess(PropertyAccess {
                        var_access: Some("latest".to_string()),
                        property_dotted_notation: vec![],
                    })),
                    location: Location {
                        line: 7,
                        column: 28,
                        file_name: ""
                    }
                })],
            },
            TypeClauseExpr {
                type_name: "AWS::EC2::Instance".to_string(),
                type_clauses: vec![PropertyClause::Clause(Clause {
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["instanceType".to_string()],
                    },
                    custom_message: None,
                    comparator: ValueOperator::Cmp(CmpOperator::Eq),
                    compare_with: Some(LetValue::Value(Value::String("t3.medium".to_string()))),
                    location: Location {
                        line: 9,
                        column: 28,
                        file_name: ""
                    }
                })],
            },
        ];
        assert_eq!(
            default_rule_type_clauses(from_str(s)),
            Ok((cmp_span, cmp))
        );
    }

    #[test]
    fn rule_block_test() {
        let s = r#"
        rule s3_secure {
            AWS::S3::Bucket {
                public != true
                policy != null
            }
        }"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 7, "", "") };
        let cmp = NamedRuleBlockExpr {
            rule_name: "s3_secure".to_string(),
            rule_clauses: vec![NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(
                TypeClauseExpr {
                    type_name: "AWS::S3::Bucket".to_string(),
                    type_clauses: vec![
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["public".to_string()],
                            },
                            custom_message: None,
                            comparator: ValueOperator::Not(CmpOperator::Eq),
                            compare_with: Some(LetValue::Value(Value::Bool(true))),
                            location: Location {
                                line: 4,
                                column: 17,
                                file_name: ""
                            }
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["policy".to_string()],
                            },
                            custom_message: None,
                            comparator: ValueOperator::Not(CmpOperator::Eq),
                            compare_with: Some(LetValue::Value(Value::Null)),
                            location: Location {
                                line: 5,
                                column: 17,
                                file_name: ""
                            }
                        }),
                    ],
                },
            ))],
            location: Location {
                line: 2,
                column: 9,
                file_name: ""
            }
        };
        assert_eq!(
            named_rule_block_expr(from_str(s)),
            Ok((cmp_span, cmp))
        );

        let s = r#"
            rule s3_secure {
                s3_policy
                AWS::S3::Bucket public != true
            }"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 5, "", "") };
        let cmp = NamedRuleBlockExpr {
            rule_name: "s3_secure".to_string(),
            rule_clauses: vec![
                NamedRuleExpr::RuleClause(NamedRuleClauseExpr::NamedRule("s3_policy".to_string())),
                NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(TypeClauseExpr {
                    type_name: "AWS::S3::Bucket".to_string(),
                    type_clauses: vec![PropertyClause::Clause(Clause {
                        access: PropertyAccess {
                            var_access: None,
                            property_dotted_notation: vec!["public".to_string()],
                        },
                        comparator: ValueOperator::Not(CmpOperator::Eq),
                        compare_with: Some(LetValue::Value(Value::Bool(true))),
                        custom_message: None,
                        location: Location {
                            line: 4,
                            column: 33,
                            file_name: ""
                        }
                    })],
                })),
            ],
            location: Location {
                line: 2,
                column: 13,
                file_name: ""
            }
        };
        assert_eq!(
            named_rule_block_expr(from_str(s)),
            Ok((cmp_span, cmp))
        );
    }

    #[test]
    fn property_block_with_comments_test() {
        let s = r###"
        # This is the property clause testing with comments
        AWS::EC2::Instance {
          # Inside comments on what we are checking
          # only allowed images are contained in latest variable
          image in %latest

          # Only allowed instance types are contained in types
          instanceType in %allowed_types

        }"###;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 11, "", "") };
        let cmp = TypeClauseExpr {
            type_name: "AWS::EC2::Instance".to_string(),
            type_clauses: vec![
                PropertyClause::Clause(Clause {
                    custom_message: None,
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["image".to_string()],
                    },
                    comparator: ValueOperator::Cmp(CmpOperator::In),
                    compare_with: Some(LetValue::PropertyAccess(PropertyAccess {
                        var_access: Some("latest".to_string()),
                        property_dotted_notation: vec![],
                    })),
                    location: Location {
                        line: 6,
                        column: 11,
                        file_name: ""
                    },
                }),
                PropertyClause::Clause(Clause {
                    custom_message: None,
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["instanceType".to_string()],
                    },
                    comparator: ValueOperator::Cmp(CmpOperator::In),
                    compare_with: Some(LetValue::PropertyAccess(PropertyAccess {
                        var_access: Some("allowed_types".to_string()),
                        property_dotted_notation: vec![],
                    })),
                    location: Location {
                        line: 9,
                        column: 11,
                        file_name: ""
                    },
                }),
            ],
        };
        assert_eq!(
            type_block_property_clause(from_str(s)),
            Ok((cmp_span, cmp))
        );

        let s = r###"
        # Okay this is without the block direct type only
        AWS::S3::Bucket public != true or policy != null"###;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 3, "", "") };
        let cmp = TypeClauseExpr {
            type_name: "AWS::S3::Bucket".to_string(),
            type_clauses: vec![PropertyClause::Disjunction(vec![
                Clause {
                    custom_message: None,
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["public".to_string()],
                    },
                    comparator: ValueOperator::Not(CmpOperator::Eq),
                    compare_with: Some(LetValue::Value(Value::Bool(true))),
                    location: Location {
                        line: 3,
                        column: 25,
                        file_name: ""
                    }
                },
                Clause {
                    custom_message: None,
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["policy".to_string()],
                    },
                    comparator: ValueOperator::Not(CmpOperator::Eq),
                    compare_with: Some(LetValue::Value(Value::Null)),
                    location: Location {
                        line: 3,
                        column: 43,
                        file_name: ""
                    }
                },
            ])],
        };
        assert_eq!(
            type_property_clause(from_str(s)),
            Ok((cmp_span, cmp.clone()))
        );
        let s = r###"
        # This is disjunction with or clauses with inline comments and joins
        AWS::S3::Bucket public != true or # ensure we are not public
            # and policy must be set
            policy != null
        "###;
        let cmp = TypeClauseExpr {
            type_name: "AWS::S3::Bucket".to_string(),
            type_clauses: vec![PropertyClause::Disjunction(vec![
                Clause {
                    custom_message: None,
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["public".to_string()],
                    },
                    comparator: ValueOperator::Not(CmpOperator::Eq),
                    compare_with: Some(LetValue::Value(Value::Bool(true))),
                    location: Location {
                        line: 3,
                        column: 25,
                        file_name: ""
                    }
                },
                Clause {
                    custom_message: None,
                    access: PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["policy".to_string()],
                    },
                    comparator: ValueOperator::Not(CmpOperator::Eq),
                    compare_with: Some(LetValue::Value(Value::Null)),
                    location: Location {
                        line: 5,
                        column: 13,
                        file_name: ""
                    }
                },
            ])],
        };
        let last = "\n        ";
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len() - last.len(), 5, last, "") };
        assert_eq!(
            type_property_clause(from_str(s)),
            Ok((cmp_span, cmp))
        )
    }

    #[test]
    fn block_type_tests() {
        let s = r#"
    AWS::EC2::Volume {
        let encrypted := %encrypted
        size in r[100, 512]
    }"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 5, "", "") };
        assert_eq!(
            type_block_property_clause(from_str(s)),
            Ok((
                cmp_span,
                TypeClauseExpr {
                    type_name: "AWS::EC2::Volume".to_string(),
                    type_clauses: vec![
                        PropertyClause::Variable(LetExpr {
                            var: "encrypted".to_string(),
                            value: LetValue::PropertyAccess(PropertyAccess {
                                var_access: Some("encrypted".to_string()),
                                property_dotted_notation: vec![]
                            })
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["size".to_string()]
                            },
                            custom_message: None,
                            compare_with: Some(LetValue::Value(Value::RangeInt(RangeType {
                                inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE,
                                lower: 100,
                                upper: 512
                            }))),
                            comparator: ValueOperator::Cmp(CmpOperator::In),
                            location: Location {
                                line: 4,
                                column: 9,
                                file_name: ""
                            }
                        })
                    ]
                }
            ))
        );
    }

    #[test]
    fn property_access_test_2() {
        let s = r#"%statement.*.action in ["deny"]"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 1, "", "") };
        assert_eq!(
            property_clause(from_str(s)),
            Ok((
                cmp_span,
                Clause {
                    custom_message: None,
                    comparator: ValueOperator::Cmp(CmpOperator::In),
                    compare_with: Some(LetValue::Value(Value::List(vec![Value::String("deny".to_string())]))),
                    access: PropertyAccess {
                        var_access: Some("statement".to_string()),
                        property_dotted_notation: vec!["*", "action"].iter()
                            .map(|s| (*s).to_string()).collect()
                    },
                    location: Location {
                        line: 1,
                        column: 1,
                        file_name: ""
                    }

                }
            ))
        )
    }

    #[test]
    fn block_type_test_2() {
        let s = r#"
    AWS::IAM::Policy {
        let statement := statement
        %statement.*.action in ["deny"]
    }"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 5, "", "") };
        assert_eq!(
            type_block_property_clause(from_str(s)),
            Ok((
                cmp_span,
                TypeClauseExpr {
                    type_name: "AWS::IAM::Policy".to_string(),
                    type_clauses: vec![
                        PropertyClause::Variable(LetExpr {
                            var: "statement".to_string(),
                            value: LetValue::PropertyAccess(PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["statement".to_string()]
                            })
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: Some("statement".to_string()),
                                property_dotted_notation: vec!["*", "action"].iter()
                                    .map(|s| (*s).to_string()).collect()
                            },
                            comparator: ValueOperator::Cmp(CmpOperator::In),
                            compare_with: Some(LetValue::Value(Value::List(vec![Value::String("deny".to_string())]))),
                            custom_message: None,
                            location: Location {
                                line: 4,
                                column: 9,
                                file_name: ""
                            }
                        })
                    ]
                }
            ))
        )
    }

    #[test]
    fn rule_block_tests() {
        let s = r###"
rule ec2_instance_checks {
    AWS::EC2::Volume {
        let encrypted := %encrypted
        size in r[100, 512]
    }
}"###;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 7, "", "") };
        let cmp = NamedRuleBlockExpr {
            rule_name: "ec2_instance_checks".to_string(),
            rule_clauses: vec![NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(
                TypeClauseExpr {
                    type_name: "AWS::EC2::Volume".to_string(),
                    type_clauses: vec![
                        PropertyClause::Variable(LetExpr {
                            var: "encrypted".to_string(),
                            value: LetValue::PropertyAccess(PropertyAccess {
                                var_access: Some("encrypted".to_string()),
                                property_dotted_notation: vec![],
                            }),
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["size".to_string()],
                            },
                            custom_message: None,
                            comparator: ValueOperator::Cmp(CmpOperator::In),
                            compare_with: Some(LetValue::Value(Value::RangeInt(RangeType {
                                lower: 100,
                                upper: 512,
                                inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE,
                            }))),
                            location: Location {
                                line: 5,
                                column: 9,
                                file_name: ""
                            }
                        }),
                    ],
                },
            ))],
            location: Location {
                line: 2,
                column: 1,
                file_name: ""
            }
        };
        assert_eq!(
            named_rule_block_expr(from_str(s)),
            Ok((cmp_span, cmp))
        );
    }

    #[test]
    fn rules_block_with_comments_test() {
        let s = r###"
rule ec2_instance_checks {

    let encrypted   := true
    let latest      := "ami-6458235"

    # EC2 Intance  Volume
    AWS::EC2::Instance {
        # SGs ^ (a or b or c) ^ az ^ image ^ insT
        securityGroups      == ["InstanceSecurityGroup"]

        keyName             == "KeyName" or
        keyName             == "Key2"

        availabilityZone    in ["us-east-2a", "us-east-2b"]
        image               == %latest
        instanceType        == "t3.medium"
    }

    AWS::EC2::Volume {
        let encrypted := %encrypted
        size in r[100, 512]
    }

    AWS::IAM::Policy {
        let statement := statement
        %statement.*.action in ["deny"]
    }
}"###;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 29, "", "") };
        let cmp = NamedRuleBlockExpr {
            rule_name: "ec2_instance_checks".to_string(),
            rule_clauses: vec![
                NamedRuleExpr::Variable(LetExpr {
                    var: "encrypted".to_string(),
                    value: LetValue::Value(Value::Bool(true)),
                }),
                NamedRuleExpr::Variable(LetExpr {
                    var: "latest".to_string(),
                    value: LetValue::Value(Value::String("ami-6458235".to_string())),
                }),
                NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(TypeClauseExpr {
                    type_name: "AWS::EC2::Instance".to_string(),
                    type_clauses: vec![
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["securityGroups".to_string()],
                            },
                            compare_with: Some(LetValue::Value(Value::List(vec![Value::String(
                                "InstanceSecurityGroup".to_string(),
                            )]))),
                            comparator: ValueOperator::Cmp(CmpOperator::Eq),
                            custom_message: None,
                            location: Location {
                                line: 10,
                                column: 9,
                                file_name: ""
                            }
                        }),
                        PropertyClause::Disjunction(vec![
                            Clause {
                                access: PropertyAccess {
                                    var_access: None,
                                    property_dotted_notation: vec!["keyName".to_string()],
                                },
                                compare_with: Some(LetValue::Value(Value::String("KeyName".to_string()))),
                                comparator: ValueOperator::Cmp(CmpOperator::Eq),
                                custom_message: None,
                                location: Location {
                                    line: 12,
                                    column: 9,
                                    file_name: ""
                                }
                            },
                            Clause {
                                access: PropertyAccess {
                                    var_access: None,
                                    property_dotted_notation: vec!["keyName".to_string()],
                                },
                                compare_with: Some(LetValue::Value(Value::String("Key2".to_string()))),
                                comparator: ValueOperator::Cmp(CmpOperator::Eq),
                                custom_message: None,
                                location: Location {
                                    line: 13,
                                    column: 9,
                                    file_name: ""
                                }
                            },
                        ]),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["availabilityZone".to_string()],
                            },
                            compare_with: Some(LetValue::Value(Value::List(vec![
                                Value::String("us-east-2a".to_string()),
                                Value::String("us-east-2b".to_string()),
                            ]))),
                            comparator: ValueOperator::Cmp(CmpOperator::In),
                            custom_message: None,
                            location: Location {
                                line: 15,
                                column: 9,
                                file_name: ""
                            }
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["image".to_string()],
                            },
                            compare_with: Some(LetValue::PropertyAccess(PropertyAccess {
                                var_access: Some("latest".to_string()),
                                property_dotted_notation: vec![],
                            })),
                            comparator: ValueOperator::Cmp(CmpOperator::Eq),
                            custom_message: None,
                            location: Location {
                                line: 16,
                                column: 9,
                                file_name: ""
                            }
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["instanceType".to_string()],
                            },
                            compare_with: Some(LetValue::Value(Value::String("t3.medium".to_string()))),
                            comparator: ValueOperator::Cmp(CmpOperator::Eq),
                            custom_message: None,
                            location: Location {
                                line: 17,
                                column: 9,
                                file_name: ""
                            }
                        }),
                    ],
                })),
                NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(TypeClauseExpr {
                    type_name: "AWS::EC2::Volume".to_string(),
                    type_clauses: vec![
                        PropertyClause::Variable(LetExpr {
                            var: "encrypted".to_string(),
                            value: LetValue::PropertyAccess(PropertyAccess {
                                var_access: Some("encrypted".to_string()),
                                property_dotted_notation: vec![],
                            }),
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["size".to_string()],
                            },
                            custom_message: None,
                            comparator: ValueOperator::Cmp(CmpOperator::In),
                            compare_with: Some(LetValue::Value(Value::RangeInt(RangeType {
                                inclusive: LOWER_INCLUSIVE | UPPER_INCLUSIVE,
                                lower: 100i64,
                                upper: 512i64,
                            }))),
                            location: Location {
                                line: 22,
                                column: 9,
                                file_name: ""
                            }
                        }),
                    ],
                })),
                NamedRuleExpr::RuleClause(NamedRuleClauseExpr::TypeClause(TypeClauseExpr {
                    type_name: "AWS::IAM::Policy".to_string(),
                    type_clauses: vec![
                        PropertyClause::Variable(LetExpr {
                            var: "statement".to_string(),
                            value: LetValue::PropertyAccess(PropertyAccess {
                                var_access: None,
                                property_dotted_notation: vec!["statement".to_string()],
                            }),
                        }),
                        PropertyClause::Clause(Clause {
                            access: PropertyAccess {
                                var_access: Some("statement".to_string()),
                                property_dotted_notation: vec!["*".to_string(), "action".to_string()],
                            },
                            comparator: ValueOperator::Cmp(CmpOperator::In),
                            compare_with: Some(LetValue::Value(Value::List(vec![Value::String("deny".to_string())]))),
                            custom_message: None,
                            location: Location {
                                line: 27,
                                column: 9,
                                file_name: ""
                            }
                        }),
                    ],
                })),
            ],
            location: Location {
                line: 2,
                column: 1,
                file_name: ""
            }
        };
        assert_eq!(
            named_rule_block_expr(from_str(s)),
            Ok((cmp_span, cmp))
        )
    }

    #[test]
    fn test_parse_rules() -> std::io::Result<()> {
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
        let rules = parse_rules(Span::new_extra(s, ""));
        println!("# number of rules {}", rules.unwrap().1.len());
        Ok(())
    }

    #[test]
    fn test_broken_syntax() {
        let s = r###"
        rule s3_secure {
            tags.*.key in ["ExternalS3Approved"] # no type specified
        }
        "###;

        let rules = parse_rules(Span::new_extra(s, ""));
        match rules {
            Err(nom::Err::Failure((i, _k))) => {
                let span = i as Span;
                assert_eq!(3, span.location_line());
                assert_eq!(17, span.get_utf8_column());
            },
            _ => assert!(false, "Should not occur")
        }
    }

    #[test]
    fn membership_test() {
        let s = r#"
            AWS::EC2::Instance {
                let keyName := keyName

                %keyName        IN ["keyName", "keyName2", "keyName3"]
                %keyName NOT_IN ["keyNameIs", "notInthis"]
            }"#;
        let cmp_span = unsafe { Span::new_from_raw_offset(s.len(), 7, "", "") };
        let cmp = TypeClauseExpr {
            type_name: "AWS::EC2::Instance".to_string(),
            type_clauses: vec![
                PropertyClause::Variable(LetExpr {
                    var: "keyName".to_string(),
                    value: LetValue::PropertyAccess(PropertyAccess {
                        var_access: None,
                        property_dotted_notation: vec!["keyName".to_string()],
                    }),
                }),
                PropertyClause::Clause(
                    Clause {
                        access: PropertyAccess {
                            var_access: Some("keyName".to_string()),
                            property_dotted_notation: vec![],
                        },
                        compare_with: Some(LetValue::Value(Value::List(vec![Value::String("keyName".to_string()),
                                                                       Value::String("keyName2".to_string()),
                                                                       Value::String("keyName3".to_string())]))),
                        comparator: ValueOperator::Cmp(CmpOperator::In),
                        custom_message: None,
                        location: Location {
                            line: 5,
                            column: 17,
                            file_name: ""
                        }
                    }),
                PropertyClause::Clause(
                    Clause {
                        access: PropertyAccess {
                            var_access: Some("keyName".to_string()),
                            property_dotted_notation: vec![],
                        },
                        compare_with: Some(LetValue::Value(Value::List(vec![Value::String("keyNameIs".to_string()), Value::String("notInthis".to_string())]))),
                        comparator: ValueOperator::Not(CmpOperator::In),
                        custom_message: None,
                        location: Location {
                            line: 6,
                            column: 17,
                            file_name: ""
                        }
                    },
                )
            ],
        };
        assert_eq!(
            type_block_property_clause(from_str(s)),
            Ok((cmp_span, cmp))
        );
    }
}
