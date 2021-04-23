use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt::Formatter;

use colored::Colorize;

use crate::rules::{Evaluate, EvaluationContext, EvaluationType, Result, Status};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::exprs::{GuardClause, GuardNamedRuleClause, QueryPart, RuleClause, TypeBlock, BlockGuardClause, WhenConditions, WhenGuardClause};
use crate::rules::exprs::{AccessQuery, Block, Conjunctions, GuardAccessClause, LetExpr, LetValue, Rule, RulesFile, SliceDisplay};
use crate::rules::path_value::{Path, PathAwareValue, QueryResolver};
use crate::rules::values::*;

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
//  Implementation for Guard Evaluations                                                        //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////

pub(super)
fn resolve_variable_query<'s>(all: bool,
                              variable: &str,
                              query: &[QueryPart<'_>],
                              var_resolver: &'s dyn EvaluationContext) -> Result<Vec<&'s PathAwareValue>> {
    let retrieved = var_resolver.resolve_variable(variable)?;
    let index: usize = if query.len() > 1 {
        match &query[1] {
            QueryPart::AllIndices => 2,
            _ => 1,
        }
    } else { 1 };
    let mut acc = Vec::with_capacity(retrieved.len());
    for each in retrieved {
        if query.len() > index {
            acc.extend(each.select(all, &query[index..], var_resolver)?)
        }
        else {
            acc.push(each);
        }
    }
    Ok(acc)
}

pub(super)
fn resolve_query<'s, 'loc>(all: bool,
                           query: &[QueryPart<'loc>],
                           context: &'s PathAwareValue,
                           var_resolver: &'s dyn EvaluationContext) -> Result<Vec<&'s PathAwareValue>> {
    match query[0].variable() {
        Some(var) => resolve_variable_query(all, var, query, var_resolver),
        None => context.select(all, query, var_resolver)
    }
}

fn invert_status(status: Status, not: bool) -> Status {
    if not {
        return match status {
            Status::FAIL => Status::PASS,
            Status::PASS => Status::FAIL,
            Status::SKIP => Status::SKIP,
        }
    }
    status
}

fn negation_status(r: bool, clause_not: bool, not: bool) -> Status {
    let status = if clause_not { !r } else { r };
    let status = if not { !status } else { status };
    if status { Status::PASS } else { Status::FAIL }
}

fn compare_loop<F>(lhs: &Vec<&PathAwareValue>, rhs: &Vec<&PathAwareValue>, compare: F, any_one_rhs: bool, atleast_one: bool)
    -> Result<(bool, Option<PathAwareValue>, Option<PathAwareValue>)>
    where F: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool> {
    let (cmp, from, to) = 'outer: loop {
        'lhs:
        for lhs_value in lhs {
            for rhs_value in rhs {
                let check = compare(*lhs_value, *rhs_value)?;
                if check && atleast_one {
                    break 'outer (true, Some(*lhs_value), Some(*rhs_value));
                }

                if any_one_rhs && check {
                    continue 'lhs
                }

                if !any_one_rhs && !check && !atleast_one {
                    break 'outer (false, Some(*lhs_value), Some(*rhs_value));
                }
            }
            //
            // We are only hear in the "all" case when all of them checked out. For the any case
            // it would be a failure to be here
            //
            if any_one_rhs && !atleast_one {
                break 'outer (false, Some(*lhs_value), None)
            }
        }
        if atleast_one {
            break (false, None, None)
        } else {
            break (true, None, None)
        }
    };
    Ok((cmp, match from {
        None => None,
        Some(p) => Some(p.clone()),
    }, match to {
        None => None,
        Some(p) => Some(p.clone())
    }))
}

fn elevate_inner<'a>(list_of_list: &'a Vec<&PathAwareValue>) -> Result<Vec<Vec<&'a PathAwareValue>>> {
    let mut elevated = Vec::with_capacity(list_of_list.len());
    for each_list_elem in list_of_list {
        match *each_list_elem {
            PathAwareValue::List((_path, list)) => {
                let inner_lhs = list.iter().collect::<Vec<&PathAwareValue>>();
                elevated.push(inner_lhs);
            },

            rest => {
                elevated.push(vec![rest])
            }
        }
    }
    Ok(elevated)
}

fn compare<F>(lhs: &Vec<&PathAwareValue>,
              _lhs_query: &[QueryPart<'_>],
              rhs: &Vec<&PathAwareValue>,
              _rhs_query: Option<&[QueryPart<'_>]>,
              compare: F,
              any: bool, atleast_one: bool) -> Result<(Status, Option<PathAwareValue>, Option<PathAwareValue>)>
    where F: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    if lhs.is_empty() || rhs.is_empty() {
        return Ok((Status::FAIL, None, None))
    }

    let lhs_elem = lhs[0];
    let rhs_elem = rhs[0];

    //
    // What are possible comparisons
    //
    if !lhs_elem.is_list() && !rhs_elem.is_list() {
        match compare_loop(lhs, rhs, compare, any, atleast_one) {
            Ok((true, _, _)) => Ok((Status::PASS, None, None)),
            Ok((false, from, to)) => Ok((Status::FAIL, from, to)),
            Err(e) => Err(e)
        }
    }
    else if lhs_elem.is_list() && !rhs_elem.is_list() {
        for elevated in elevate_inner(lhs)? {
            if let Ok((cmp, from, to)) = compare_loop(
                &elevated, rhs, |f, s| compare(f, s), any, atleast_one) {
                if !cmp {
                    return Ok((Status::FAIL, from, to))
                }
            }
        }
        Ok((Status::PASS, None, None))
    }
    else if !lhs_elem.is_list() && rhs_elem.is_list() {
        for elevated in elevate_inner(rhs)? {
            if let Ok((cmp, from, to)) = compare_loop(
                lhs, &elevated, |f, s| compare(f, s), any, atleast_one) {
                if !cmp {
                    return Ok((Status::FAIL, from, to))
                }
            }
        }
        Ok((Status::PASS, None, None))
    }
    else {
        for elevated_lhs in elevate_inner(lhs)? {
            for elevated_rhs in elevate_inner(rhs)? {
                if let Ok((cmp, from, to)) = compare_loop(
                    &elevated_lhs, &elevated_rhs, |f, s| compare(f, s), any, atleast_one) {
                    if !cmp {
                        return Ok((Status::FAIL, from, to))
                    }
                }

            }
        }
        Ok((Status::PASS, None, None))
    }
}

impl<'loc> std::fmt::Display for GuardAccessClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(
            format_args!(
                "Clause({}, Check: {} {} {} {})",
                self.access_clause.location,
                SliceDisplay(&self.access_clause.query.query),
                if self.access_clause.comparator.1 { "NOT" } else { "" },
                self.access_clause.comparator.0,
                match &self.access_clause.compare_with {
                    Some(v) => {
                        match v {
                            // TODO add Display for Value
                            LetValue::Value(val) => format!("{:?}", val),
                            LetValue::AccessClause(qry) => format!("{}", SliceDisplay(&qry.query)),

                        }
                    },
                    None => "".to_string()
                },
            )
        )?;
        Ok(())
    }
}

pub(super) fn invert_closure<F>(f: F, clause_not: bool, not: bool) -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
    where F: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    move |first, second| {
        let r = f(first, second)?;
        let r = if clause_not { !r } else { r };
        let r = if not { !r } else { r };
        Ok(r)
    }
}

impl<'loc> Evaluate for GuardAccessClause<'loc> {
    fn evaluate<'s>(&self,
                context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let guard_loc = format!("{}", self);
                                //SliceDisplay(&self.access_clause.query));
        let mut auto_reporter = AutoReport::new(EvaluationType::Clause, var_resolver, &guard_loc);
        //var_resolver.start_evaluation(EvaluationType::Clause, &guard_loc);
        let clause = self;

        let all = self.access_clause.query.match_all;


        let (lhs, retrieve_error) =
            match resolve_query(clause.access_clause.query.match_all,
                                &clause.access_clause.query.query,
                                context,
                                var_resolver)
            {
                Ok(v) => (Some(v), None),
                Err(Error(ErrorKind::RetrievalError(e))) |
                Err(Error(ErrorKind::IncompatibleRetrievalError(e))) => (None, Some(e)),
                Err(e) => return Err(e),
            };

        let result = match clause.access_clause.comparator {
            (CmpOperator::Empty, not) =>
                //
                // Retrieval Error is considered the same as an empty or !exists
                // When using "SOME" keyword in the clause, then IncompatibleError is trapped to be none
                // This is okay as long as the checks are for empty, exists
                //
                match &lhs {
                    None => Some(negation_status(true, not, clause.negation)),
                    Some(l) => {
                        Some(
                            if !l.is_empty() {
                                if l[0].is_list() || l[0].is_map() {
                                    'all_empty: loop {
                                        for element in l {
                                            let status = match *element {
                                                PathAwareValue::List((_, v)) =>
                                                    negation_status(v.is_empty(), not, clause.negation),
                                                PathAwareValue::Map((_, m)) =>
                                                    negation_status(m.is_empty(), not, clause.negation),
                                                _ => continue
                                            };

                                            if status == Status::FAIL {
                                                break 'all_empty Status::FAIL;
                                            }
                                        }
                                        break Status::PASS
                                    }
                                }
                                else {
                                    negation_status(false, not, clause.negation)
                                }
                            }
                            else {
                                negation_status(true, not, clause.negation)
                            })
                    }
                },

            (CmpOperator::Exists, not) =>
                match &lhs {
                    None => Some(negation_status(false, not, clause.negation)),
                    Some(_) => Some(negation_status(true, not, clause.negation)),
                },

            (CmpOperator::Eq, not) =>
                match &clause.access_clause.compare_with {
                    Some(LetValue::Value(Value::Null)) =>
                        match &lhs {
                            None => Some(negation_status(true, not, clause.negation)),
                            Some(_) => Some(negation_status(false, not, clause.negation)),
                        }
                    _ => None
                },

            (CmpOperator::IsString, not) =>
                match &lhs {
                    None => Some(negation_status(false, not, clause.negation)),
                    Some(l) => Some(
                        negation_status( l.iter().find(|p|
                            if let PathAwareValue::String(_) = **p {
                                false
                            } else {
                                true
                            }
                        ).map_or(true, |_i| false), not, clause.negation))
                },

            (CmpOperator::IsList, not) =>
                match &lhs {
                    None => Some(negation_status(false, not, clause.negation)),
                    Some(l) => Some(
                        negation_status( l.iter().find(|p|
                            if let PathAwareValue::List(_) = **p {
                                false
                            } else {
                                true
                            }
                        ).map_or(true, |_i| false), not, clause.negation))
                },

            (CmpOperator::IsMap, not) =>
                match &lhs {
                    None => Some(negation_status(false, not, clause.negation)),
                    Some(l) => Some(
                        negation_status( l.iter().find(|p|
                            if let PathAwareValue::Map(_) = **p {
                                false
                            } else {
                                true
                            }
                        ).map_or(true, |_i| false), not, clause.negation))
                },

            _ => None
        };

        if let Some(r) = result {
            let message = match &clause.access_clause.custom_message {
                Some(msg) => msg,
                None => "(DEFAULT: NO_MESSAGE)"
            };
            auto_reporter.status(r).from(
                match &lhs {
                    None => None,
                    Some(l) => if !l.is_empty() {
                        Some(l[0].clone())
                    } else { None }
                }
            ).message(message.to_string());
            return Ok(r)
        }

        let lhs = match lhs {
            None =>
                if all {
                    return Ok(auto_reporter.status(Status::FAIL)
                                  .message(retrieve_error.map_or("".to_string(), |e| e)).get_status())
                }
                else {
                    return Ok(auto_reporter.status(Status::FAIL)
                        .message(retrieve_error.map_or("".to_string(), |e| e)).get_status())
                }
            Some(l) => l,
        };

        let rhs_local = match &clause.access_clause.compare_with {
            None => return Err(Error::new(ErrorKind::IncompatibleRetrievalError(
                format!("Expecting a RHS for comparison and did not find one, clause@{}",
                        clause.access_clause.location)
            ))),

            Some(expr) => {
                match expr {
                    LetValue::Value(v) => {
                        let path = format!("{}/{}/{}/Clause/",
                            clause.access_clause.location.file_name,
                            clause.access_clause.location.line,
                            clause.access_clause.location.column);
                        let path = super::path_value::Path(path);
                        Some(vec![PathAwareValue::try_from((v, path))?])
                    },

                    _ => None,
                }
            }
        };

        let (rhs_resolved, rhs_query) = if let Some(expr) = &clause.access_clause.compare_with {
            match expr {
                LetValue::AccessClause(query) =>
                    (Some(resolve_query(query.match_all, &query.query, context, var_resolver)?), Some(query.query.as_slice())),
                _ => (None, None)
            }
        } else {
            (None, None)
        };

        let rhs = match &rhs_local {
            Some(local) => local.iter().collect::<Vec<&PathAwareValue>>(),
            None => match rhs_resolved {
                Some(resolved) => resolved,
                None => unreachable!()
            }
        };

        let (result, from, to) =
            match &clause.access_clause.comparator.0 {
            //
            // ==, !=
            //
            CmpOperator::Eq =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_eq, clause.access_clause.comparator.1, clause.negation),
                        false,
                        !all)?,

            //
            // >
            //
            CmpOperator::Gt =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_gt, clause.access_clause.comparator.1, clause.negation),
                        false,
                        !all)?,

            //
            // >=
            //
            CmpOperator::Ge =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_ge, clause.access_clause.comparator.1, clause.negation),
                        false,
                        !all)?,

            //
            // <
            //
            CmpOperator::Lt =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_lt, clause.access_clause.comparator.1, clause.negation),
                        false,
                        !all)?,

            //
            // <=
            //
            CmpOperator::Le =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_le, clause.access_clause.comparator.1, clause.negation),
                        false,
                        !all)?,

            //
            // IN, !IN
            //
            CmpOperator::In => {
                let mut result = compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        super::path_value::compare_eq,
                                         true,
                                         !all)?;
                let status = invert_status(result.0, clause.access_clause.comparator.1);
                let status = invert_status(status, clause.negation);
                result.0 = status;
                result
            },

            _ => unreachable!()

        };

        let message = match &clause.access_clause.custom_message {
            Some(msg) => msg,
            None => "(DEFAULT: NO_MESSAGE)"
        };
        auto_reporter.comparison(result, from, to).message(message.to_string());
        Ok(result)
    }
}

impl<'loc> std::fmt::Display for GuardNamedRuleClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Rule({}@{})", self.dependent_rule, self.location)
    }
}

impl<'loc> Evaluate for GuardNamedRuleClause<'loc> {
    fn evaluate<'s>(&self,
                _context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let guard_loc = format!("{}", self);
        let mut auto_reporter = AutoReport::new(EvaluationType::Clause, var_resolver, &guard_loc);
        Ok(auto_reporter.status(invert_status(
            match var_resolver.rule_status(&self.dependent_rule)? {
                Status::PASS => Status::PASS,
                _ => Status::FAIL
            },
            self.negation)).get_status())
    }
}

impl<'loc> Evaluate for GuardClause<'loc> {
    fn evaluate<'s>(&self,
                context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        match self {
            GuardClause::Clause(gac) => gac.evaluate(context, var_resolver),
            GuardClause::NamedRule(nr) => nr.evaluate(context, var_resolver),
            GuardClause::BlockClause(bc) => bc.evaluate(context, var_resolver),
            GuardClause::WhenBlock(conditions, clauses) => match conditions.evaluate(context, var_resolver)? {
                Status::PASS => clauses.evaluate(context, var_resolver),
                rest => Ok(rest)
            }
        }
    }
}

impl<'loc, T: Evaluate + 'loc> Evaluate for Block<'loc, T> {
    fn evaluate<'s>(&self,
                    context: &'s PathAwareValue,
                    var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let block = BlockScope::new(&self, context, var_resolver);
        self.conjunctions.evaluate(context, &block)
    }
}

impl<'loc, T: Evaluate + 'loc> Evaluate for Conjunctions<T> {
    fn evaluate<'s>(&self,
                    context: &'s PathAwareValue,
                    var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        Ok('outer: loop {
            let mut num_passes = 0;
            let mut num_fails = 0;
            let item_name = std::any::type_name::<T>();
            'conjunction:
            for conjunction in self {
                let mut num_of_disjunction_fails = 0;
                let mut report = if "cfn_guard::rules::exprs::GuardClause" == item_name {
                    Some(AutoReport::new(
                        EvaluationType::Conjunction,
                        var_resolver,
                        item_name
                    ))
                } else { None };
                for disjunction in conjunction {
                    match disjunction.evaluate(context, var_resolver)? {
                        Status::PASS => {
                            let _ = report.as_mut().map(|r| Some(r.status(Status::PASS).get_status()));
                            num_passes += 1;
                            continue 'conjunction; },
                        Status::SKIP => {},
                        Status::FAIL => { num_of_disjunction_fails += 1; }
                    }
                }

                if num_of_disjunction_fails > 0 {
                    let _ = report.as_mut().map(|r| Some(r.status(Status::FAIL).get_status()));
                    num_fails += 1;
                    continue;
                    //break 'outer Status::FAIL
                }
            }
            if num_fails > 0 { break Status::FAIL }
            if num_passes > 0 { break Status::PASS }
            break Status::SKIP
        })
    }
}

impl<'loc> Evaluate for BlockGuardClause<'loc> {
    fn evaluate<'s>(&self, context: &'s PathAwareValue, var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let all = self.query.match_all;
        let block_values = match resolve_query(all, &self.query.query, context, var_resolver) {
            Err(Error(ErrorKind::RetrievalError(e))) |
            Err(Error(ErrorKind::IncompatibleRetrievalError(e))) => {
                let context = format!("Block[{}]", self.location);
                let mut report = AutoReport::new(
                    EvaluationType::Clause,
                    var_resolver,
                    &context
                );
                return Ok(report.message(e).status(Status::FAIL).get_status())
            },

            Ok(v) => if v.is_empty() { // one or more
                return Ok(Status::FAIL)
            } else { v },

            Err(e) => return Err(e)
        };

        Ok(loop {
            let mut num_fail = 0;
            let mut num_pass = 0;
            for each in block_values {
                match self.block.evaluate(each, var_resolver)? {
                    Status::FAIL => { num_fail += 1; },
                    Status::SKIP => {},
                    Status::PASS => { num_pass += 1; }
                }
            }

            if all {
                if num_fail > 0 { break Status::FAIL }
                if num_pass > 0 { break Status::PASS }
                break Status::SKIP
            }
            else {
                if num_pass > 0 { break Status::PASS }
                if num_fail > 0 { break Status::FAIL }
                break Status::SKIP
            }
        })
    }
}

impl<'loc> Evaluate for WhenGuardClause<'loc> {
    fn evaluate<'s>(&self, context: &'s PathAwareValue, var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        match self {
            WhenGuardClause::Clause(gac) => gac.evaluate(context, var_resolver),
            WhenGuardClause::NamedRule(nr) => nr.evaluate(context, var_resolver)
        }
    }
}

impl<'loc> Evaluate for TypeBlock<'loc> {
    fn evaluate<'s>(&self, context: &'s PathAwareValue, var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let mut type_report = AutoReport::new(
            EvaluationType::Type,
            var_resolver,
            &self.type_name
        );

        if let Some(conditions) = &self.conditions {
            let mut type_conds = AutoReport::new(
                EvaluationType::Condition,
                var_resolver,
                ""
            );
            match type_conds.status(conditions.evaluate(context, var_resolver)?).get_status() {
                Status::PASS => {},
                _ => {
                    return Ok(type_report.status(Status::SKIP).get_status())
                }
            }
        }

        let query = format!("Resources.*[ Type == \"{}\" ]", self.type_name);
        let cfn_query = AccessQuery::try_from(query.as_str())?;
        let values = match context.select(cfn_query.match_all, &cfn_query.query, var_resolver) {
            Ok(v) => if v.is_empty() {
                return Ok(type_report.message(format!("There are no {} types present in context", self.type_name))
                    .status(Status::SKIP).get_status())
            } else { v }
            Err(_) => vec![context]
        };

        let overall = loop {
            let mut num_fail = 0;
            let mut num_pass = 0;
            for (index, each) in values.iter().enumerate() {
                let type_context = format!("{}#{}({})", self.type_name, index, (*each).self_path());
                let mut each_type_report = AutoReport::new(
                    EvaluationType::Type,
                    var_resolver,
                    &type_context
                );
                match each_type_report.status(self.block.evaluate(*each, var_resolver)?).get_status() {
                    Status::PASS => { num_pass += 1; },
                    Status::FAIL => { num_fail += 1; },
                    Status::SKIP => {},
                }
            }
            if num_fail > 0 { break Status::FAIL }
            if num_pass > 0 { break Status::PASS }
            break Status::SKIP
        };
        Ok(match overall {
            Status::SKIP =>
                type_report.status(Status::SKIP).message(
                    format!("ALL Clauses for all types {} was SKIPPED. This can be an error", self.type_name)).get_status(),
            rest => type_report.status(rest).get_status()
        })
    }
}

impl<'loc> Evaluate for RuleClause<'loc> {
    fn evaluate<'s>(&self,
                    context: &'s PathAwareValue,
                    var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        Ok(match self {
            RuleClause::Clause(gc) => gc.evaluate(context, var_resolver)?,
            RuleClause::TypeBlock(tb) => tb.evaluate(context, var_resolver)?,
            RuleClause::WhenBlock(conditions, block) => {
                let status = {
                    let mut auto_cond = AutoReport::new(
                        EvaluationType::Condition, var_resolver, "");
                    auto_cond.status(conditions.evaluate(context, var_resolver)?).get_status()
                };

                match status {
                    Status::PASS => {
                        let mut auto_block = AutoReport::new(
                            EvaluationType::ConditionBlock,
                            var_resolver,
                            ""
                        );
                        auto_block.status(block.evaluate(context, var_resolver)?).get_status()
                    },
                    _ => {
                        let mut skip_block = AutoReport::new(
                            EvaluationType::ConditionBlock,
                            var_resolver,
                            ""
                        );
                        skip_block.status(Status::SKIP).get_status()
                    }
                }
            }
        })
    }
}

impl<'loc> Evaluate for Rule<'loc> {
    fn evaluate<'s>(&self, context: &'s PathAwareValue, var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let mut auto = AutoReport::new(
            EvaluationType::Rule, var_resolver, &self.rule_name);
        if let Some(conds) = &self.conditions {
            let mut cond = AutoReport::new(
                EvaluationType::Condition, var_resolver, &self.rule_name
            );
            match cond.status(conds.evaluate(context, var_resolver)?).get_status() {
                Status::PASS => {},
                _ => return Ok(auto.status(Status::SKIP).get_status())
            }
        }
        Ok(auto.status(self.block.evaluate(context, var_resolver)?).get_status())
    }
}

impl<'loc> Evaluate for RulesFile<'loc> {
    fn evaluate<'s>(&self, context: &'s PathAwareValue, var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        let mut overall = Status::PASS;
        let mut auto_report = AutoReport::new(
            EvaluationType::File, var_resolver, "");
        for rule in &self.guard_rules {
            if Status::FAIL == rule.evaluate(context, var_resolver)? {
                overall = Status::FAIL
            }
        }
        auto_report.status(overall);
        Ok(overall)
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
// Evaluation Context implementations for scoped variables                                      //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////


fn extract_variables<'s, 'loc>(expressions: &'s Vec<LetExpr<'loc>>,
                               vars: &mut HashMap<&'s str, PathAwareValue>,
                               queries: &mut HashMap<&'s str, &'s AccessQuery<'loc>>) -> Result<()> {
    for each in expressions {
        match &each.value {
            LetValue::Value(v) => {
                vars.insert(&each.var, PathAwareValue::try_from((v, Path::try_from("rules_file/")?))?);
            },

            LetValue::AccessClause(query) => {
                queries.insert(&each.var, query);
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
pub(crate) struct RootScope<'s, 'loc> {
    rules: &'s RulesFile<'loc>,
    input_context: &'s PathAwareValue,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'loc>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s PathAwareValue>>>,
    literals: HashMap<&'s str, PathAwareValue>,
    rule_by_name: HashMap<&'s str, &'s Rule<'loc>>,
    rule_statues: std::cell::RefCell<HashMap<&'s str, Status>>,
}

impl<'s, 'loc> RootScope<'s, 'loc> {
    pub(crate) fn new(rules: &'s RulesFile<'loc>,
                      value: &'s PathAwareValue) -> Self {
        let mut literals = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&rules.assignments,
                          &mut literals,
                          &mut pending);
        let mut lookup_cache = HashMap::with_capacity(rules.guard_rules.len());
        for rule in &rules.guard_rules {
            lookup_cache.insert(rule.rule_name.as_str(), rule);
        }
        RootScope {
            rules,
            input_context: value,
            pending_queries: pending,
            literals,
            variables: std::cell::RefCell::new(HashMap::new()),
            rule_by_name: lookup_cache,
            rule_statues: std::cell::RefCell::new(HashMap::with_capacity(rules.guard_rules.len())),
        }
    }
}

impl<'s, 'loc> EvaluationContext for RootScope<'s, 'loc> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        if let Some(literal) = self.literals.get(variable) {
            return Ok(vec![literal])
        }

        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }
        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let all = (*query).match_all;
            let query: &[QueryPart<'_>] = &(*query).query;
            let values = match query[0].variable() {
                Some(var) => resolve_variable_query(all, var, query, self)?,
                None => {
                    let values = self.input_context.select(all, query, self)?;
                    self.variables.borrow_mut().insert(*key, values.clone());
                    values
                }
            };
            Ok(values)
        } else {
            Err(Error::new(ErrorKind::MissingVariable(
                format!("Could not resolve variable {}", variable)
            )))
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        if let Some(status) = self.rule_statues.borrow().get(rule_name) {
            return Ok(*status)
        }

        if let Some((name, rule)) = self.rule_by_name.get_key_value(rule_name) {
            let status = (*rule).evaluate(self.input_context, self)?;
            self.rule_statues.borrow_mut().insert(*name, status);
            return Ok(status)
        }

        Err(Error::new(ErrorKind::MissingValue(
            format!("Attempting to resolve rule_status for rule = {}, rule not found", rule_name)
        )))
    }

    fn end_evaluation(&self,
                      eval_type: EvaluationType,
                      context: &str,
                      _msg: String,
                      _from: Option<PathAwareValue>,
                      _to: Option<PathAwareValue>,
                      status: Option<Status>) {
        if EvaluationType::Rule == eval_type {
            let (name, _rule) = self.rule_by_name.get_key_value(context).unwrap();
            if let Some(status) = status {
                self.rule_statues.borrow_mut().insert(*name, status);
            }
        }
    }

    fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {
    }
}

pub(crate) struct BlockScope<'s, T> {
    block_type: &'s Block<'s, T>,
    input_context: &'s PathAwareValue,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'s>>,
    literals: HashMap<&'s str, PathAwareValue>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s PathAwareValue>>>,
    parent: &'s dyn EvaluationContext,
}

impl<'s, T> BlockScope<'s, T> {
    pub(crate) fn new(block_type: &'s Block<'s, T>, context: &'s PathAwareValue, parent: &'s dyn EvaluationContext) -> Self {
        let mut literals = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&block_type.assignments,
                          &mut literals,
                          &mut pending);
        BlockScope {
            block_type,
            input_context: context,
            literals,
            parent,
            variables: std::cell::RefCell::new(HashMap::new()),
            pending_queries: pending,
        }
    }
}

impl<'s, T> EvaluationContext for BlockScope<'s, T> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        if let Some(literal) = self.literals.get(variable) {
            return Ok(vec![literal])
        }

        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }
        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let all = (*query).match_all;
            let query: &[QueryPart<'_>] = &(*query).query;
            let values = match query[0].variable() {
                Some(var) => resolve_variable_query(all, var, query, self)?,
                None => {
                    let values = self.input_context.select(all, query, self)?;
                    self.variables.borrow_mut().insert(*key, values.clone());
                    values
                }
            };
            Ok(values)
        } else {
            self.parent.resolve_variable(variable)
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }



    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<PathAwareValue>, to: Option<PathAwareValue>, status: Option<Status>) {
        self.parent.end_evaluation(eval_type, context, msg, from, to, status)
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        self.parent.start_evaluation(eval_type, context);
    }
}

#[derive(Clone)]
pub(super) struct AutoReport<'s> {
    context: &'s dyn EvaluationContext,
    type_context: &'s str,
    eval_type: EvaluationType,
    status: Option<Status>,
    from: Option<PathAwareValue>,
    to: Option<PathAwareValue>,
    message: Option<String>
}

impl<'s> std::fmt::Debug for AutoReport<'s> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Context = {}, Type = {}, Status = {:?}",
                                 self.type_context, self.eval_type, self.status))?;
        Ok(())
    }
}

impl<'s> AutoReport<'s> {
    pub(super) fn new(eval_type: EvaluationType,
           context : &'s dyn EvaluationContext,
           type_context: &'s str) -> Self {
        context.start_evaluation(eval_type, type_context);
        AutoReport {
            eval_type,
            type_context,
            context,
            status: None,
            from: None,
            to: None,
            message: None,
        }
    }

    pub(super) fn status(&mut self, status: Status) -> &mut Self {
        self.status = Some(status);
        self
    }

    pub(super) fn comparison(&mut self, status: Status, from: Option<PathAwareValue>, to: Option<PathAwareValue>) -> &mut Self {
        self.status = Some(status);
        self.from = from;
        self.to = to;
        self
    }

    pub(super) fn from(&mut self, from: Option<PathAwareValue>) -> &mut Self {
        self.from = from;
        self
    }

    pub(super) fn to(&mut self, to: Option<PathAwareValue>) -> &mut Self {
        self.to = to;
        self
    }

    pub(super) fn message(&mut self, msg: String) -> &mut Self {
        self.message = Some(msg);
        self
    }

    pub(super) fn get_status(&self) -> Status {
        self.status.unwrap()
    }
}

impl<'s> Drop for AutoReport<'s> {
    fn drop(&mut self) {
        let status = match self.status {
            Some(status) => status,
            None => Status::SKIP
        };
        self.context.end_evaluation(
            self.eval_type,
            self.type_context,
            match &self.message {
                Some(message) => message.clone(),
                None => format!("DEFAULT MESSAGE({})", status)
            },
            self.from.clone(),
            self.to.clone(),
            Some(status)
        )
    }
}

#[cfg(test)]
#[path = "evaluate_tests.rs"]
mod evaluate_tests;
