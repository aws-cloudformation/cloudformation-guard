use std::collections::{
    HashMap
};
use std::convert::TryFrom;
use colored::Colorize;

use crate::rules::{Evaluate, EvaluationContext, Result, Status, EvaluationType};
use crate::rules::errors::{Error, ErrorKind};
use crate::rules::exprs::{GuardClause, GuardNamedRuleClause, RuleClause, TypeBlock, QueryPart};
use crate::rules::exprs::{AccessQuery, Block, Conjunctions, GuardAccessClause, LetExpr, LetValue, Rule, RulesFile, SliceDisplay};
use crate::rules::parser::AccessQueryWrapper;
use crate::rules::values::*;
use std::fmt::Formatter;

//////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                              //
//  Implementation for Guard Evaluations                                                        //
//                                                                                              //
//////////////////////////////////////////////////////////////////////////////////////////////////

fn resolve_query<'s, 'loc>(query: &'s AccessQuery<'loc>,
                           context: &'s Value,
                           var_resolver: &'s dyn EvaluationContext) -> Result<Vec<&'s Value>> {

    let (resolved, index) = if let Some(var) = query[0].variable() {
        (var_resolver.resolve_variable(var)?, 1 as usize)
    } else {
        (vec![context], 0 as usize)
    };

    let mut expanded = Vec::with_capacity(resolved.len());
    for each in resolved {
        expanded.extend(each.query(index, query, var_resolver)?)
    }
    Ok(expanded)
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

fn compare_loop<F>(lhs: &Vec<&Value>, rhs: &Vec<&Value>, compare: F, any: bool) -> Result<(bool, Option<Value>, Option<Value>)>
    where F: Fn(&Value, &Value) -> Result<bool> {
    loop {
        'lhs:
        for lhs_value in lhs {
            for rhs_value in rhs {
                let check = compare(*lhs_value, *rhs_value)?;
                if any && check {
                    continue 'lhs
                }

                if !any && !check {
                    return Ok((false, Some((*lhs_value).clone()), Some((*rhs_value).clone())))
                }
            }
            //
            // We are only hear in the "all" case when all of them checked out. For the any case
            // it would be a failure to be here
            //
            if any {
                return Ok((false, Some((*lhs_value).clone()), None))
            }
        }
        break;
    };
    Ok((true, None, None))
}

fn elevate_inner<'a>(list_of_list: &'a Vec<&Value>) -> Result<Vec<Vec<&'a Value>>> {
    let mut elevated = Vec::with_capacity(list_of_list.len());
    for each_list_elem in list_of_list {
        match *each_list_elem {
            Value::List(list) => {
                let inner_lhs = list.iter().collect::<Vec<&Value>>();
                elevated.push(inner_lhs);
            },

            _ => return Err(Error::new(
                ErrorKind::IncompatibleError(
                    format!("Expecting the RHS query to return a List<List>, found {}, {:?}",
                            type_info(*each_list_elem), *each_list_elem)
                )
            ))
        }
    }
    Ok(elevated)
}

fn compare<F>(lhs: &Vec<&Value>,
              lhs_query: &[QueryPart<'_>],
              rhs: &Vec<&Value>,
              rhs_query: Option<&[QueryPart<'_>]>,
              compare: F,
              any: bool) -> Result<(bool, Option<Value>, Option<Value>)>
    where F: Fn(&Value, &Value) -> Result<bool>
{
    if lhs.is_empty() || rhs.is_empty() {
        return Err(Error::new(
            ErrorKind::RetrievalError(
                format!("Expecting comparisons but have either LHS or RHS empty, LHS Query = {}, RHS Query = {}",
                    SliceDisplay(lhs_query),
                    match rhs_query {
                        Some(q) => format!("{}", SliceDisplay(q)),
                        None => "No Query".to_string()
                    }
                )
            )
        ))
    }

    let lhs_elem = lhs[0];
    let rhs_elem = rhs[0];

    //
    // What are possible comparisons
    //
    if !lhs_elem.is_list() && !rhs_elem.is_list() {
        compare_loop(lhs, rhs, compare, any)
    }
    else if lhs_elem.is_list() && !rhs_elem.is_list() {
        for elevated in elevate_inner(lhs)? {
            if let Ok((cmp, from, to)) = compare_loop(
                &elevated, rhs, |f, s| compare(f, s), any) {
                if !cmp {
                    return Ok((cmp, from, to))
                }
            }
        }
        Ok((true, None, None))
    }
    else if !lhs_elem.is_list() && rhs_elem.is_list() {
        for elevated in elevate_inner(rhs)? {
            if let Ok((cmp, from, to)) = compare_loop(
                lhs, &elevated, |f, s| compare(f, s), any) {
                if !cmp {
                    return Ok((cmp, from, to))
                }
            }
        }
        Ok((true, None, None))
    }
    else {
        for elevated_lhs in elevate_inner(lhs)? {
            for elevated_rhs in elevate_inner(rhs)? {
                if let Ok((cmp, from, to)) = compare_loop(
                    &elevated_lhs, &elevated_rhs, |f, s| compare(f, s), any) {
                    if !cmp {
                        return Ok((cmp, from, to))
                    }
                }

            }
        }
        Ok((true, None, None))
    }
}

impl<'loc> Evaluate for GuardAccessClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        let guard_loc = format!("Clause@[loc = {}, query= {}]", self.access_clause.location,
                                SliceDisplay(&self.access_clause.query));
        let mut auto_reporter = AutoReport::new(EvaluationType::Clause, var_resolver, &guard_loc);
        //var_resolver.start_evaluation(EvaluationType::Clause, &guard_loc);
        let clause = self;

        let lhs_map_keys = if let QueryPart::MapKeys = &clause.access_clause.query[0] {
            match context {
                Value::Map(index) => {
                    index.keys().map(|s| Value::String(s.to_string())).collect::<Vec<Value>>()
                },
                _ => return Err(Error::new(
                    ErrorKind::IncompatibleError(
                        format!("Attempting to access KEYS, but value type is not a map {}, Value = {:?}",
                            type_info(context),
                            context
                        )
                    )
                )),
            }
        } else {
           vec![]
        };

        let lhs = if lhs_map_keys.is_empty() {
            match resolve_query(
            &clause.access_clause.query,  context, var_resolver) {
                Ok(values) => Some(values),
                // Err(Error(ErrorKind::RetrievalError(_))) => None,
                Err(e) => return Err(e),
            }
        } else {
            Some(lhs_map_keys.iter().collect::<Vec<&Value>>())
        };

        let result = match &clause.access_clause.comparator.0 {
            CmpOperator::Empty |
            CmpOperator::KeysEmpty=>
                match &lhs { None => Some(false), Some(l) => Some(l.is_empty()) }

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
                        SliceDisplay(&clause.access_clause.query),
                        clause.access_clause.location)
            ))),

            Some(l) => l,
        };

        let (rhs, rhs_query) = match &clause.access_clause.compare_with {
            None => return Err(Error::new(ErrorKind::IncompatibleError(
                format!("Expecting a RHS for comparison and did not find one, clause@{}",
                        clause.access_clause.location)
            ))),

            Some(expr) => {
                match expr {
                    LetValue::Value(v) => {
                        (vec![v], None)
                    },
                    LetValue::AccessClause(query) =>
                        (resolve_query(query, context, var_resolver)?, Some(query.as_slice()))
                }
            }
        };

        let result = match &clause.access_clause.comparator.0 {
            //
            // ==, !=
            //
            CmpOperator::Eq =>
                compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_eq, false)?,

            //
            // >
            //
            CmpOperator::Gt =>
                compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_gt, false)?,

            //
            // >=
            //
            CmpOperator::Ge =>
                compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_ge, false)?,

            //
            // <
            //
            CmpOperator::Lt =>
                compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_lt, false)?,

            //
            // <=
            //
            CmpOperator::Le =>
                compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_le, false)?,

            //
            // IN, !IN
            //
            CmpOperator::In =>
                compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_eq, true)?,

            CmpOperator::KeysEq |
            CmpOperator::KeysIn => {
                if clause.access_clause.comparator.0 == CmpOperator::KeysIn {
                    compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_eq, true)?
                }
                else {
                    compare(&lhs, &clause.access_clause.query, &rhs, rhs_query, compare_eq, false)?
                }
            }

            _ => unreachable!()

        };

        let status = negation_status(result.0, clause.access_clause.comparator.1, clause.negation);
        let message = format!("Guard@{}, Status = {}, Clause = {}, Message = {}", clause.access_clause.location,
            match status {
                Status::PASS => "PASS",
                Status::FAIL => "FAIL",
                Status::SKIP => "SKIP",
            },
            SliceDisplay(&clause.access_clause.query),
            match &clause.access_clause.custom_message {
                Some(msg) => msg,
                None => "(default completed evaluation)"
            }
        );
        auto_reporter.status(status).message(message);
        Ok(status)
    }
}

impl<'loc> Evaluate for GuardNamedRuleClause<'loc> {
    fn evaluate(&self,
                _context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        Ok(invert_status(
            var_resolver.rule_status(&self.dependent_rule)?,
            self.negation))
    }
}

impl<'loc> Evaluate for GuardClause<'loc> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        match self {
            GuardClause::Clause(gac) => gac.evaluate(context, var_resolver),
            GuardClause::NamedRule(nr) => nr.evaluate(context, var_resolver),
        }
    }
}

impl<T: Evaluate> Evaluate for Conjunctions<T> {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status> {
        let mut aleast_one_disjunction_passed = false;
        'conjunction:
        for conjunction in self {
            let mut all_skips = true;
            for disjunction in conjunction {
                match disjunction.evaluate(context, var_resolver) {
                    Ok(status) => {
                        match status {
                            Status::PASS => {
                                aleast_one_disjunction_passed = true;
                                continue 'conjunction
                            },
                            Status::SKIP => continue,
                            Status::FAIL => {
                                all_skips = false
                            }
                        }
                    },

                    Err(Error(ErrorKind::RetrievalError(_))) => continue,

                    Err(e) => return Err(e)
                }
            }
            if !all_skips {
                return Ok(Status::FAIL)
            }
        }
        if aleast_one_disjunction_passed {
            Ok(Status::PASS)
        }
        else {
            Ok(Status::SKIP)
        }
    }
}

impl<'loc> Evaluate for TypeBlock<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
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
        let cfn_query = AccessQueryWrapper::try_from(query.as_str())?.0;
        let values = match context.query(0, &cfn_query, var_resolver) {
            Ok(v) => if v.is_empty() {
                // vec![context]
                return Ok(type_report.message(format!("There are no {} types present in context", self.type_name))
                                                  .status(Status::SKIP).get_status())

            } else { v }
            Err(_) => vec![context]
        };
        for each in values {
            let block_scope = BlockScope::new(&self.block, each, var_resolver);
            if Status::FAIL == self.block.conjunctions.evaluate(each, &block_scope)? {
                return Ok(type_report.status(Status::FAIL).get_status())
            }
        }
        Ok(type_report.status(Status::PASS).get_status())
    }
}

impl<'loc> Evaluate for RuleClause<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
        match self {
            RuleClause::Clause(gc) => gc.evaluate(context, var_resolver),
            RuleClause::TypeBlock(tb) => tb.evaluate(context, var_resolver),
            RuleClause::WhenBlock(conditions, block) => {
                let mut auto_cond = AutoReport::new(
                    EvaluationType::Condition, var_resolver, "");
                match auto_cond.status(conditions.evaluate(context, var_resolver)?).get_status() {
                    Status::PASS => {
                        let mut auto_block = AutoReport::new(
                            EvaluationType::ConditionBlock,
                            var_resolver,
                            ""
                        );
                        let block_scope = BlockScope::new(block, context, var_resolver);
                        Ok(auto_block.status(block.conjunctions.evaluate(context, &block_scope)?).get_status())
                    },
                    _ => {
                        let mut skip_block = AutoReport::new(
                            EvaluationType::ConditionBlock,
                            var_resolver,
                            ""
                        );
                        Ok(skip_block.status(Status::SKIP).get_status())
                    }
                }
            }
        }
    }
}

impl<'loc> Evaluate for Rule<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
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
        match self.block.conjunctions.evaluate(context, &block_scope) {
            Ok(status) => {
                let message = format!("Rule@{}, Status = {:?}", self.rule_name, status);

                return Ok(auto.status(status).message(message).get_status())
            },
            other => other
        }
    }
}

impl<'loc> Evaluate for RulesFile<'loc> {
    fn evaluate(&self, context: &Value, var_resolver: &dyn EvaluationContext) -> Result<Status> {
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
                               vars: &mut HashMap<&'s str, Vec<&'s Value>>,
                               queries: &mut HashMap<&'s str, &'s AccessQuery<'loc>>) {
    for each in expressions {
        match &each.value {
            LetValue::Value(v) => {
                vars.insert(&each.var, vec![v]);
            },

            LetValue::AccessClause(query) => {
                queries.insert(&each.var, query);
            }
        }
    }
}

pub(crate) struct RootScope<'s, 'loc> {
    rules: &'s RulesFile<'loc>,
    input_context: &'s Value,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'loc>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s Value>>>,
    rule_by_name: HashMap<&'s str, &'s Rule<'loc>>,
    rule_statues: std::cell::RefCell<HashMap<&'s str, Status>>,
}

impl<'s, 'loc> RootScope<'s, 'loc> {
    pub(crate) fn new(rules: &'s RulesFile<'loc>,
                      value: &'s Value) -> Self {
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
            variables: std::cell::RefCell::new(literals),
            rule_by_name: lookup_cache,
            rule_statues: std::cell::RefCell::new(HashMap::with_capacity(rules.guard_rules.len())),
        }
    }

    pub(crate) fn summary_report(&self) {
        println!("{}", "Summary Report".underline());
        for each in self.rule_statues.borrow().iter() {
            let status = match *each.1 {
                Status::PASS => "PASS".green(),
                Status::FAIL => "FAIL".red(),
                Status::SKIP => "SKIP".yellow(),
            };
            println!("{}\t\t\t\t\t\t\t{}", *each.0, status);
        }
    }
}

impl<'s, 'loc> EvaluationContext for RootScope<'s, 'loc> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }
        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let values = self.input_context.query(0, *query, self)?;
            self.variables.borrow_mut().insert(*key, values.clone());
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
                      _from: Option<Value>,
                      _to: Option<Value>,
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
    input_context: &'s Value,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'s>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s Value>>>,
    parent: &'s dyn EvaluationContext,
}

impl<'s, T> BlockScope<'s, T> {
    pub(crate) fn new(block_type: &'s Block<'s, T>, context: &'s Value, parent: &'s dyn EvaluationContext) -> Self {
        let mut literals = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&block_type.assignments,
                          &mut literals,
                          &mut pending);
        BlockScope {
            block_type,
            input_context: context,
            parent,
            variables: std::cell::RefCell::new(literals),
            pending_queries: pending,
        }
    }
}

impl<'s, T> EvaluationContext for BlockScope<'s, T> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&Value>> {
        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }

        return if let Some((key, query)) = self.pending_queries.get_key_value(variable) {
            let values = self.input_context.query(0, *query, self)?;
            self.variables.borrow_mut().insert(*key, values.clone());
            Ok(values)
        } else {
            self.parent.resolve_variable(variable)
        }
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }



    fn end_evaluation(&self, eval_type: EvaluationType, context: &str, msg: String, from: Option<Value>, to: Option<Value>, status: Option<Status>) {
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
    from: Option<Value>,
    to: Option<Value>,
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

    pub(super) fn comparison(&mut self, status: Status, from: Option<Value>, to: Option<Value>) -> &mut Self {
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
