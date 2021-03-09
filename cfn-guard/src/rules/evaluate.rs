use std::collections::{
    HashMap
};
use std::convert::TryFrom;
use colored::Colorize;

use crate::rules::{Evaluate, EvaluationContext, Result, Status, EvaluationType};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::exprs::{GuardClause, GuardNamedRuleClause, RuleClause, TypeBlock, QueryPart};
use crate::rules::exprs::{AccessQuery, Block, Conjunctions, GuardAccessClause, LetExpr, LetValue, Rule, RulesFile, SliceDisplay};
use crate::rules::values::*;
use std::fmt::Formatter;
use crate::rules::path_value::{PathAwareValue, QueryResolver, Path};

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
//  Implementation for Guard Evaluations                                                        //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////

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
            match each.select(all, &query[index..], var_resolver) {
                Ok(result) => {
                    acc.extend(result);
                },

                Err(Error(ErrorKind::RetrievalError(e))) => {
                    if all {
                        return Err(Error::new(ErrorKind::RetrievalError(e)));
                    }
                },

                Err(e) => return Err(e)
            }
        }
        else {
            acc.push(each);
        }
    }
    Ok(acc)
}

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

fn compare_loop<F>(lhs: &Vec<&PathAwareValue>, rhs: &Vec<&PathAwareValue>, compare: F, any: bool) -> Result<(bool, Option<PathAwareValue>, Option<PathAwareValue>, bool)>
    where F: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool> {
    let mut at_least_one_match = false;
    loop {
        'lhs:
        for lhs_value in lhs {
            for rhs_value in rhs {
                let check = compare(*lhs_value, *rhs_value)?;
                if check {
                    at_least_one_match = true;
                }
                if any && check {
                    continue 'lhs
                }

                if !any && !check {
                    return Ok((false, Some((*lhs_value).clone()), Some((*rhs_value).clone()), at_least_one_match))
                }
            }
            //
            // We are only hear in the "all" case when all of them checked out. For the any case
            // it would be a failure to be here
            //
            if any {
                return Ok((false, Some((*lhs_value).clone()), None, at_least_one_match))
            }
        }
        break;
    };
    Ok((true, None, None, true))
}

fn elevate_inner<'a>(list_of_list: &'a Vec<&PathAwareValue>) -> Result<Vec<Vec<&'a PathAwareValue>>> {
    let mut elevated = Vec::with_capacity(list_of_list.len());
    for each_list_elem in list_of_list {
        match *each_list_elem {
            PathAwareValue::List((_path, list)) => {
                let inner_lhs = list.iter().collect::<Vec<&PathAwareValue>>();
                elevated.push(inner_lhs);
            },

            _ => return Err(Error::new(
                ErrorKind::IncompatibleError(
                    format!("Expecting the RHS query to return a List<List>, found {}, {:?}",
                            (*each_list_elem).type_info(), *each_list_elem)
                )
            ))
        }
    }
    Ok(elevated)
}

fn compare<F>(lhs: &Vec<&PathAwareValue>,
              lhs_query: &[QueryPart<'_>],
              rhs: &Vec<&PathAwareValue>,
              rhs_query: Option<&[QueryPart<'_>]>,
              compare: F,
              any: bool) -> Result<(Status, Option<PathAwareValue>, Option<PathAwareValue>, bool)>
    where F: Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
{
    if lhs.is_empty() || rhs.is_empty() {
        return Ok((Status::SKIP, None, None, false))
    }

    let lhs_elem = lhs[0];
    let rhs_elem = rhs[0];

    //
    // What are possible comparisons
    //
    if !lhs_elem.is_list() && !rhs_elem.is_list() {
        match compare_loop(lhs, rhs, compare, any) {
            Ok((true, _, _, atleast)) => Ok((Status::PASS, None, None, atleast)),
            Ok((false, from, to, atleast)) => Ok((Status::FAIL, from, to, atleast)),
            Err(e) => Err(e)
        }
    }
    else if lhs_elem.is_list() && !rhs_elem.is_list() {
        for elevated in elevate_inner(lhs)? {
            if let Ok((cmp, from, to, atleast)) = compare_loop(
                &elevated, rhs, |f, s| compare(f, s), any) {
                if !cmp {
                    return Ok((Status::FAIL, from, to, atleast))
                }
            }
        }
        Ok((Status::PASS, None, None, true))
    }
    else if !lhs_elem.is_list() && rhs_elem.is_list() {
        for elevated in elevate_inner(rhs)? {
            if let Ok((cmp, from, to, atleast)) = compare_loop(
                lhs, &elevated, |f, s| compare(f, s), any) {
                if !cmp {
                    return Ok((Status::FAIL, from, to, atleast))
                }
            }
        }
        Ok((Status::PASS, None, None, true))
    }
    else {
        for elevated_lhs in elevate_inner(lhs)? {
            for elevated_rhs in elevate_inner(rhs)? {
                if let Ok((cmp, from, to, atleast)) = compare_loop(
                    &elevated_lhs, &elevated_rhs, |f, s| compare(f, s), any) {
                    if !cmp {
                        return Ok((Status::FAIL, from, to, atleast))
                    }
                }

            }
        }
        Ok((Status::PASS, None, None, true))
    }
}

impl<'loc> std::fmt::Display for GuardAccessClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(
            format_args!(
                "GuardAccessClause[ check = {} {} {} {}, loc = {} ]",
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
                self.access_clause.location
            )
        )?;
        Ok(())
    }
}

fn invert_closure<F>(f: F, clause_not: bool, not: bool) -> impl Fn(&PathAwareValue, &PathAwareValue) -> Result<bool>
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


        let lhs = match resolve_query(clause.access_clause.query.match_all, &clause.access_clause.query.query, context, var_resolver) {
            Ok(v) => Some(v),
            Err(Error(ErrorKind::RetrievalError(e))) => None,
            Err(e) => return Err(e),
        };

        let result = match &clause.access_clause.comparator.0 {
            CmpOperator::Empty |
            CmpOperator::KeysEmpty =>
                //
                // Retrieval Error is considered the same as an empty or !exists
                //
                match &lhs { None => Some(true), Some(l) => Some(l.is_empty()) }

            CmpOperator::Exists => match &lhs { None => Some(false), Some(_) => Some(true) }
            CmpOperator::Eq => match &clause.access_clause.compare_with {
                Some(LetValue::Value(Value::Null)) =>
                    match &lhs { None => Some(true), Some(_) => Some(false), }
                _ => None
            }

            _ => None
        };

        if let Some(r) = result {
            let status = negation_status(r, clause.access_clause.comparator.1, clause.negation);
            let message = format!("Guard@{}", self.access_clause.location);
            auto_reporter.status(status).message(message);
            return Ok(status)
        }

        let lhs = match lhs {
            None => return Err(Error::new(ErrorKind::RetrievalError(
                format!("Expecting a resolved LHS {} for comparison and did not find one, Clause@{}",
                        SliceDisplay(&clause.access_clause.query.query),
                        clause.access_clause.location)
            ))),

            Some(l) => l,
        };

        let rhs_local = match &clause.access_clause.compare_with {
            None => return Err(Error::new(ErrorKind::IncompatibleError(
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

        let mut result =
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
                        if all { false } else { true })?,

            //
            // >
            //
            CmpOperator::Gt =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_gt, clause.access_clause.comparator.1, clause.negation),
                        if all { false } else { true })?,

            //
            // >=
            //
            CmpOperator::Ge =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_ge, clause.access_clause.comparator.1, clause.negation),
                        if all { false } else { true })?,

            //
            // <
            //
            CmpOperator::Lt =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_lt, clause.access_clause.comparator.1, clause.negation),
                        if all { false } else { true })?,

            //
            // <=
            //
            CmpOperator::Le =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_le, clause.access_clause.comparator.1, clause.negation),
                        if all { false } else { true })?,

            //
            // IN, !IN
            //
            CmpOperator::KeysIn |
            CmpOperator::In => {
                let mut result = compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        super::path_value::compare_eq,
                        true)?;
                let status = invert_status(result.0, clause.access_clause.comparator.1);
                let status = invert_status(status, clause.negation);
                result.0 = status;
                result
            }

            CmpOperator::KeysEq =>
                compare(&lhs,
                        &clause.access_clause.query.query,
                        &rhs,
                        rhs_query,
                        invert_closure(super::path_value::compare_eq, clause.access_clause.comparator.1, clause.negation),
                        if all { false } else { true })?,

            _ => unreachable!()

        };

        if !all && result.3 == true {
            result.0 = Status::PASS;
        }

        let message = format!("Guard@{}, Status = {}, Clause = {}, Message = {}", clause.access_clause.location,
            match result.0 {
                Status::PASS => "PASS",
                Status::FAIL => "FAIL",
                Status::SKIP => "SKIP",
            },
            SliceDisplay(&clause.access_clause.query.query),
            match &clause.access_clause.custom_message {
                Some(msg) => msg,
                None => "(default completed evaluation)"
            }
        );
        auto_reporter.comparison(result.0, result.1, result.2).message(message);
        Ok(result.0)
    }
}

impl<'loc> Evaluate for GuardNamedRuleClause<'loc> {
    fn evaluate<'s>(&self,
                _context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        Ok(invert_status(
            var_resolver.rule_status(&self.dependent_rule)?,
            self.negation))
    }
}

impl<'loc> Evaluate for GuardClause<'loc> {
    fn evaluate<'s>(&self,
                context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        match self {
            GuardClause::Clause(gac) => gac.evaluate(context, var_resolver),
            GuardClause::NamedRule(nr) => nr.evaluate(context, var_resolver),
        }
    }
}

impl<'loc> Evaluate for Conjunctions<GuardClause<'loc>> {
    fn evaluate<'s>(&self,
                context: &'s PathAwareValue,
                var_resolver: &'s dyn EvaluationContext) -> Result<Status> {
        Ok('outer: loop {
            let mut num_of_conjunction_skips = 0;
            'conjunction:
            for conjunction in self {
                let mut num_of_fails = 0;
                for disjunction in conjunction {
                    match disjunction.evaluate(context, var_resolver) {
                        Ok(status) => {
                            match status {
                                Status::PASS => {
                                    continue 'conjunction;
                                },
                                Status::SKIP => {},
                                Status::FAIL => {
                                    num_of_fails += 1;
                                }
                            }
                        },

                        Err(Error(ErrorKind::RetrievalError(_))) => {
                            continue;
                        },

                        Err(e) => return Err(e)
                    }
                }

                if num_of_fails > 0 {
                    break 'outer Status::FAIL
                }
                num_of_conjunction_skips += 1;
            }
            if num_of_conjunction_skips > 0 {
                break Status::SKIP
            } else {
                break Status::PASS
            }
        })
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

        let overall = 'outer: loop {
            let mut type_block_skips = 0;
            for (index, each) in values.iter().enumerate() {
                let type_context = format!("{}#{}({})", self.type_name, index, (*each).self_path());
                let mut each_type_report = AutoReport::new(
                    EvaluationType::Type,
                    var_resolver,
                    &type_context
                );
                let block_scope = BlockScope::new(&self.block, *each, var_resolver);
                match each_type_report.status(self.block.conjunctions.evaluate(*each, &block_scope)?).get_status() {
                    Status::PASS => {},

                    Status::FAIL => {
                        break 'outer Status::FAIL
                    },

                    Status::SKIP => {
                        each_type_report.message(
                            format!("All Clauses WERE SKIPPED. This is usually an ERROR specifying them. Maybe we need EXISTS or !EXISTS")
                        );
                        type_block_skips += 1;
                        continue;
                    }
                }
            }
            if type_block_skips > 0 {
                break Status::SKIP
            } else {
                break Status::PASS
            }
        };
        Ok(match overall {
            Status::SKIP =>
                type_report.status(Status::SKIP).message(
                    format!("ALL Clauses for all types {} was SKIPPED. This can be an error", self.type_name)).get_status(),
            rest => type_report.status(rest).get_status()
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

        let block_scope = BlockScope::new(&self.block, context, var_resolver);
        Ok({
            let status = 'outer: loop {
                let mut conjunction_skips = 0;
                'next_conjunction:
                for each in &self.block.conjunctions {
                    let mut num_of_fails = 0;
                    for each_rule_clause in each {
                        let status = match each_rule_clause {
                            RuleClause::Clause(gc) => match gc.evaluate(context, &block_scope) {
                                Ok(status) => status,
                                Err(Error(ErrorKind::RetrievalError(_))) => Status::SKIP,
                                Err(e) => return Err(e)
                            },
                            RuleClause::TypeBlock(tb) => tb.evaluate(context, &block_scope)?,
                            RuleClause::WhenBlock(conditions, block) => {
                                let mut auto_cond = AutoReport::new(
                                    EvaluationType::Condition, &block_scope, "");
                                match auto_cond.status(conditions.evaluate(context, &block_scope)?).get_status() {
                                    Status::PASS => {
                                        let mut auto_block = AutoReport::new(
                                            EvaluationType::ConditionBlock,
                                            &block_scope,
                                            ""
                                        );
                                        let block_scope = BlockScope::new(block, context, &block_scope);
                                        auto_block.status(block.conjunctions.evaluate(context, &block_scope)?).get_status()
                                    },
                                    _ => {
                                        let mut skip_block = AutoReport::new(
                                            EvaluationType::ConditionBlock,
                                            &block_scope,
                                            ""
                                        );
                                        //
                                        // when block SKIPs in Rule clauses from a rules block's evaluation is
                                        // a PASS for the whole block, SKIP to next disjunction
                                        //
                                        skip_block.status(Status::SKIP).get_status()
                                    }
                                }
                            }
                        };
                        match status {
                            Status::PASS => continue 'next_conjunction,
                            Status::FAIL => {
                                num_of_fails += 1;
                            },
                            Status::SKIP => {}
                        }
                        //
                        // If it is a FAIL/SKIP, try to NEXT DISJUNCTION CLAUSE
                        //
                    } // for each disjunction clause
                    //
                    // Even if one FAILED, we fail overall rule, as the others skipped
                    //
                    if num_of_fails > 0 {
                        break 'outer Status::FAIL
                    }
                    //
                    // else everything skipped, so we keep track. to see if another of the
                    // other conjunction sets would fail
                    //
                    conjunction_skips += 1;
                } // for each conjunction of disjunction clauses
                //
                // Even if one conjunction set SKIPPEd and all other PASS, it is a SKIP
                //
                if conjunction_skips > 0 {
                    break Status::SKIP
                } else {
                    break Status::PASS
                }
            };
            auto.status(status).get_status()
        })
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

    pub(crate) fn rule_statues<F>(&self, mut f: F)
        where F: FnMut(&str, &Status) -> ()
    {
        for (name, status) in self.rule_statues.borrow().iter() {
            f(*name, status)
        }
    }

    pub(crate) fn summary_report(&self) {
        println!("{}", "Summary Report".underline());
        let mut longest = 0;
        for name in self.rule_statues.borrow().keys() {
            if (*name).len() > longest {
                longest = (*name).len();
            }
        }

        for each in self.rule_statues.borrow().iter() {
            let status = match *each.1 {
                Status::PASS => "PASS".green(),
                Status::FAIL => "FAIL".red(),
                Status::SKIP => "SKIP".yellow(),
            };
            print!("{}", *each.0);
            for _idx in 0..(longest + 2 - (*each.0).len()) {
                print!("{}", "    ");
            }
            println!("{}", status);
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
