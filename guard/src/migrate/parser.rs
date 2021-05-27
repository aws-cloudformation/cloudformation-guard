use nom::bytes::complete::{tag, take_until, take_while1};
use nom::combinator::{all_consuming, map, cut, opt, rest, peek, value};
use nom::multi::separated_nonempty_list;
use nom::branch::alt;
use crate::rules::parser::{Span, var_name, ParserError, var_name_access, IResult, parse_value, type_name};
use nom::sequence::{preceded, tuple, terminated, delimited};
use crate::rules::values::Value;
use crate::rules::errors::Error;
use nom::character::complete::{space0, space1};
use std::hash::{Hash, Hasher};
use std::fmt;
use std::fmt::Display;
use std::collections::HashMap;

#[cfg(test)]
#[path = "parser_tests.rs"]
mod parser_tests;

// Values that can be specified on the RHS of comparisons and variable assignments
#[derive(Debug, PartialEq, Clone)]
pub enum OldGuardValues {
    Value(Value),
    VariableAccess(String)
}
impl Display for OldGuardValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OldGuardValues::Value(value) => write!(f, "{}", value),
            OldGuardValues::VariableAccess(s) => write!(f, "%{}", s),
        }
    }
}

impl Hash for OldGuardValues {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            OldGuardValues::Value(v)     =>    {v.hash(state)},
            OldGuardValues::VariableAccess(s) => { s.hash(state); }
        }
    }
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct Assignment {
    pub(in crate::migrate) var_name: String,
    pub(in crate::migrate) value: OldGuardValues
}
impl Display for Assignment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "let {} = {}", self.var_name, self.value)
    }
}


#[derive(Eq, PartialEq, Debug, Clone, Hash, Copy)]
pub(crate) enum CmpOperator {
    Eq,
    Ne,
    In,
    NotIn,
    Gt,
    Lt,
    Le,
    Ge
}
impl Display for CmpOperator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CmpOperator::Eq => write!(f, "=="),
            CmpOperator::Ne => write!(f, "!="),
            CmpOperator::In => write!(f, "IN"),
            CmpOperator::NotIn => write!(f, "NOT IN"),
            CmpOperator::Gt => write!(f, ">"),
            CmpOperator::Lt => write!(f, "<"),
            CmpOperator::Le => write!(f, "<="),
            CmpOperator::Ge => write!(f, ">=")
        }
    }
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct PropertyComparison {
    pub property_path: String,
    pub operator: CmpOperator,
    pub comparison_value: OldGuardValues,
}
impl Display for PropertyComparison {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.property_path.starts_with(".") {
            write!(f, "{} {} {}", self.property_path.trim_start_matches("."), self.operator, self.comparison_value)
        } else {
            write!(f, "Properties.{} {} {}", self.property_path, self.operator, self.comparison_value)
        }

    }
}

#[derive(Ord, Eq, PartialEq, PartialOrd, Debug, Clone, Hash)]
pub(crate) struct TypeName {
    pub type_name: String
}
impl Display for TypeName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.type_name.to_lowercase().replace("::", "_"))
    }
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct BaseRule {
    pub(crate) type_name: TypeName,
    pub(crate) property_comparison: PropertyComparison,
    pub(crate) custom_message: Option<String>
}
impl Display for BaseRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.custom_message {
            Some(message) => {
                write!(f, "{} <<{}>>", self.property_comparison, message)
            },
            None => {
                write!(f, "{}", self.property_comparison)
            }
        }
    }
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct ConditionalRule {
    pub type_name: TypeName,
    pub when_condition: PropertyComparison,
    pub check_condition: PropertyComparison
}
impl Display for ConditionalRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "when %{}[ {} ] not EMPTY {{", self.type_name, self.when_condition);
        writeln!(f, "\t\t%{}[ {} ].{}", self.type_name, self.when_condition, self.check_condition);
        write!(f, "\t}}");
        writeln!(f, "when {} {{", self.when_condition);
        writeln!(f, "            {}", self.check_condition);
        writeln!(f, "        }}")
    }
}


#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum Rule {
    Conditional(ConditionalRule),
    Basic(BaseRule)
}
impl Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::Conditional(conditional) => write!(f, "{}", conditional),
            Rule::Basic(base) => write!(f, "{}", base)
        }
    }
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct Clause {
    pub(crate) rules: Vec<Rule>
}

impl Eq for Clause {}

impl Display for Clause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let result: Vec<String> = self.rules.clone().into_iter().map(|rule| format!("{}", rule)).collect();
        write!(f, "{}", result.join(" or "))
    }
}

#[derive(Debug, PartialEq, Clone, Hash)]
pub(crate) enum RuleLineType {
    Assignment(Assignment),
    Clause(Clause),
    Comment(String),
    EmptyLine
}

impl Display for RuleLineType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleLineType::Assignment(assignment) => write!(f, "{}", assignment),
            RuleLineType::Clause(clause) => write!(f, "{}", clause),
            RuleLineType::Comment(comment) => write!(f, "#{}", comment),
            RuleLineType::EmptyLine => write!(f, "")
        }
    }
}


// variable-dereference =  ("%" variable) / ("%{" variable "}" ); Regular and environment variables, respectively
pub (crate) fn parse_variable_dereference(input: Span) -> IResult<Span, String> {
    delimited(space0, alt((
        delimited(tag("%{"), var_name, tag("}")),
        var_name_access)), space0)(input)
}

// take until "<<" if a custom message exists in the rule. otherwise, take until end of rule ("|OR|" or rest of span)
pub(in crate::migrate) fn parse_complete_value(input: Span) -> IResult<Span, Span> {
    let (remaining, rule_remainder) = alt((take_until("|OR|"), rest))(input)?;
    match take_until("<<")(rule_remainder) {
        Ok(_result) => {
            take_until("<<")(input)
        },
        Err(nom::Err::Error(_e)) => {
            Ok((remaining, rule_remainder))
        },
        Err(e) => return Err(e)
    }
}

// comment = "#" vchar-sp; Comment line
pub(in crate::migrate) fn comment(input: Span) ->IResult<Span, String> {
    let (remainder, comment_contents) = preceded(space0, preceded(tag("#"), rest))(input)?;
    Ok((remainder, comment_contents.fragment().to_string()))
}

// value = json-value / variable_access / bare-string
pub (in crate::migrate) fn parse_old_guard_value(input:Span) -> IResult<Span, OldGuardValues> {
    // take entire value, then see if we can parse it as a json value/regex/VariableAccess. If not, take value as whitespace trimmed string
    let (remainder, value_span) = parse_complete_value(input)?;
    match all_consuming(alt((
        map(terminated(parse_value, space0), |v| OldGuardValues::Value(v)),
        map(parse_variable_dereference, |s| OldGuardValues::VariableAccess(s))
    )))(value_span) {
        Ok((_value_remainder, value)) => {
            Ok((remainder, value))
        },
        Err(_err) => {
            // if didnt consume completely, take full value as a bare string
            Ok((remainder, OldGuardValues::Value(Value::String(value_span.fragment().trim().to_string()))))
        }
    }
}

// assignment = %s"let" 1*WSP variable 1*WSP %s"=" 1*WSP assignment-value; Assignment rule.
pub(crate) fn assignment(input: Span) -> IResult<Span, Assignment> {
    let (input, _let_keyword) = preceded(space0,tag("let"))(input)?;
    let (input, (var_name, _eq_sign)) = tuple((
        //
        // if we have a pattern like "letproperty" that can be an access keyword
        // then there is no space in between. This will error out.
        //
        preceded(space1, var_name),
        //
        // if we succeed in reading the form "let <var_name>", it must be be
        // followed with an assignment sign "="
        //
        cut(
            preceded(
                space0,
                tag("=")
            )
        ),
    ))(input)?;
    let (remaining, value) = parse_old_guard_value(input)?;
    Ok((remaining, Assignment{
        value,
        var_name
    }))
}

// value_operator = "==" / "!=" / "<" / ">" / "<=" / ">=" / %s"IN" / %s"NOT_IN"
pub(in crate::migrate) fn value_operator(input: Span) -> IResult<Span, CmpOperator> {
    let (input, is_custom_message_start) = peek(opt(value(true,tag("<<"))))(input)?;
    if is_custom_message_start.is_some() {
        return Err(nom::Err::Error(ParserError {
            span: input,
            context: "Custom message tag detected".to_string(),
            kind: nom::error::ErrorKind::Tag
        }))
    }
    alt((
        value(CmpOperator::Eq, tag("==") ),
        value(CmpOperator::Ne, tag("!=")),
        value(CmpOperator::Ge, tag(">=") ),
        value(CmpOperator::Le, tag("<=")),
        value(CmpOperator::In, tag("IN")),
        value(CmpOperator::NotIn, tag("NOT_IN")),
        value(CmpOperator::Gt, tag(">")),
        value(CmpOperator::Lt, tag("<"))
    ))(input)
}

// returns a string representing the property path. a bit naive as it will accept empty property paths between dots and wildcards next to each other, etc.
// property-path = ["."] (1*alphanum / wildcard) *("." (1*alphanum / wildcard))
pub(in crate::migrate) fn property_path(input: Span) -> IResult<Span, String> {
    let (remaining, result) = take_while1(|c: char| c.is_alphanumeric() || c == '.' || c == '*')(input)?;
    Ok((remaining, result.fragment().to_string()))
}


// property-comparison = property-path 1*WSP value-operator 1*WSP value ; Equality comparison
pub(in crate::migrate) fn property_comparison(input: Span) -> IResult<Span, PropertyComparison> {
    // property path
    let (remaining_after_property_path, property_path) = preceded(space0,property_path)(input)?;
    // get operator
    let (remaining_for_value, operator) = cut(preceded(space1, value_operator))(remaining_after_property_path)?;

    // comparison value
    let (remaining, comparison_value) = cut(preceded(space1, parse_old_guard_value))(remaining_for_value)?;
    Ok((remaining, PropertyComparison{
        property_path,
        operator,
        comparison_value
    }))
}

// base-rule = resource-type 1*WSP property-comparison [1*WSP output-message];
// parses line and returns a BaseRule structure with given type name and property comparison
// optional output message can be specified via "<<"
pub(in crate::migrate) fn base_rule(input: Span) -> IResult<Span, BaseRule> {
    let (remaining_for_comparison, type_name) = preceded(space0, type_name)(input)?;
    let (remaining_for_message, property_comparison) = preceded(space1, property_comparison)(remaining_for_comparison)?;
    match custom_message(remaining_for_message) {
        Ok((remaining, custom_message)) => {
            Ok((remaining, BaseRule {
                type_name,
                property_comparison,
                custom_message: Some(custom_message)
            }))
        },
        Err(nom::Err::Error(_)) => {
            Ok((remaining_for_message, BaseRule {
                type_name,
                property_comparison,
                custom_message: None
            }))
        },
        Err(e) => return Err(e)
    }
}

// conditional-rule = resource-type 1*WSP %s"WHEN" 1*WSP property-comparison 1*WSP %s"CHECK" 1*WSP property-comparison; Rule that checks values if a certain condition is met.
//  returns ConditionalRule structure with given property checks and type name
pub(in crate::migrate) fn conditional_rule(input: Span) -> IResult<Span, ConditionalRule> {
    // get resource type name
    let (input, type_name) = preceded(space0, type_name)(input)?;

    // consume WHEN
    let (input, _when) = preceded(space1, tag("WHEN"))(input)?;

    //check for whitespace, then consume until CHECK for a span that should have a property comparison
    let (input, property_comparison_span) = preceded(space1, cut(take_until("CHECK")))(input)?;
    let (_property_check_remainder, when_condition) = terminated(property_comparison, space0)(property_comparison_span)?;

    //remainder input should have CHECK then property comparison
    let (remainder, check_condition) =  preceded(tag("CHECK"), property_comparison)(input)?;
    Ok((remainder, ConditionalRule{
        type_name,
        when_condition,
        check_condition
    }))
}

// output-message = "<<" vchar-sp
// returns message to be used for output
pub(in crate::migrate) fn custom_message(input: Span) -> IResult<Span, String> {
    let (remaining, message) =  preceded(tag("<<"), preceded(space0, alt((take_until("|OR|"), rest))))(input)?;
    return Ok((remaining, message.fragment().trim().to_string()))
}

// rule = (base-rule / conditional-rule)
// returns enum value with rule structure
pub(in crate::migrate) fn rule(input: Span) -> IResult<Span, Rule> {
    alt((
        map(
            conditional_rule, |cond_rule| Rule::Conditional(cond_rule)
        ),
        map(
            base_rule, |simple_rule| Rule::Basic(simple_rule)
        )
    ))(input)
}

// clause = (rule 1*(%s"|OR|" 1*WSP rule))
// returns list of rules on line
pub(in crate::migrate) fn clause(input: Span) -> IResult<Span, Clause> {
    let (remaining_for_message, rules) = separated_nonempty_list(preceded(space0, tag("|OR|")), rule )(input)?;
    Ok((remaining_for_message, Clause { rules }))
}

// empty line parser
// used in migration tool to preserve overall spacing of a migrated ruleset
pub(in crate::migrate) fn empty_line(input: Span) -> IResult<Span, RuleLineType> {
    value(RuleLineType::EmptyLine, all_consuming(space0))(input)
}

// rule-line = rule / clause / assignment / comment / empty_line
// returns enum value with underlying rule line structure
pub(in crate::migrate) fn rule_line(input: Span) ->IResult<Span, RuleLineType> {
    let (remainder, rule_line) =    alt((
            empty_line,
            map(assignment, |a| RuleLineType::Assignment(a)),
            map(clause,|c| RuleLineType::Clause(c)),
            map(comment, |c | RuleLineType::Comment(c))
        ))(input)?;
    Ok((remainder, rule_line))
}

// splits input on each new line (each old guard rule is only 1 line max) and parses each line
// this makes the nom related parsing functions a bit easier to write, as we don't have to handle the entire file as input, only each line,
// so subsequent lines are not part of the span to be parsed
// returns vector of ruleline enums
pub(crate) fn parse_rules_file(input: &String, file_name: &String) -> Result<Vec<RuleLineType>, Error> {
    let lines = input.lines();
    let mut rule_lines = vec![];
    for (i, line) in lines.enumerate() {
        let context = format!("{}:{}", file_name, i);

        let line_span = Span::new_extra(&line, context.as_str());
        let (_result, parsed_rule_line) = rule_line(line_span)?;
        rule_lines.push(parsed_rule_line);
    }
    Ok(rule_lines)
}
