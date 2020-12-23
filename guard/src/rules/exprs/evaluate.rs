use std::collections::hash_map::DefaultHasher;
use std::collections::hash_map::Entry;
use std::hash::{Hash, Hasher};

use crate::errors::{Error, ErrorKind};
use crate::rules::values::*;

use super::scope::Scope;
use super::types::*;
use regex::internal::Input;
use crate::rules::exprs::helper::match_map;

fn negation_status(r: bool, clause_not: bool, not: bool) -> Status {
    let status = if clause_not { !r } else { r };
    let status = if not { !status } else { status };
    if status { Status::PASS } else { Status::FAIL }
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

#[derive(PartialEq, Debug, Clone)]
enum ValueType<'c> {
    Single((Path, &'c Value)),
    Query(ResolvedValues<'c>)
}

//pub(super) fn gac_evaluate(gac: &GuardAccessClause<'_>,
//                           scope: &Scope<'_>,
//                           context: &Value,
//                           path: Path) -> Result<EvalStatus, Error> {
//
//    let lhs = match resolve_query(
//        &gac.access_clause.query, context, scope, path.clone()) {
//        Ok(r) => Some(r),
//        Err(Error(ErrorKind::RetrievalError(_))) => None,
//        Err(e) => return Err(e),
//    };
//
//    //
//    // Special case EXISTS, !EXISTS,
//    //
//    if CmpOperator::Exists == gac.access_clause.comparator.0 {
//        return Ok(EvalStatus::Unary(
//            negation_status(lhs.is_some(),
//                             gac.access_clause.comparator.1,
//                            gac.negation)));
//    }
//
//    //
//    // Special case == null or != null
//    //
//    if let Some(LetValue::Value(Value::Null)) = &gac.access_clause.compare_with {
//        if CmpOperator::Eq == gac.access_clause.comparator.0 {
//            return Ok(EvalStatus::Unary(negation_status(
//                lhs.is_none(),
//                gac.access_clause.comparator.1,
//                gac.negation)))
//        }
//    }
//
//    //
//    // FAIL if LHS wasn't there for all other comparisons
//    //
//    let lhs = match lhs {
//        Some(v) => ValueType::Query(v),
//        None => return Err(Error::new(ErrorKind::RetrievalError(
//            format!("When checking for {:?}, could for retrieve value for {:?}",
//                    gac.access_clause.comparator.0, gac.access_clause.query)
//        )))
//    };
//
//    //
//    // The 2 other unary operators
//    //
//    match &gac.access_clause.comparator {
//        (CmpOperator::Empty, negation) |
//        (CmpOperator::KeysEmpty, negation) => {
//            let empty = match &lhs {
//                ValueType::Query(r) => r.is_empty(),
//                ValueType::Single((_p, Value::List(l))) => l.is_empty(),
//                ValueType::Single((_p, v)) =>
//                    return Err(Error::new(ErrorKind::IncompatibleError(
//                        format!("Expecting a list value from a resolved query or value, found value type {}", type_info(*v))
//                    )))
//            };
//            return Ok(EvalStatus::Unary(
//                negation_status(empty, *negation, gac.negation)))
//        }
//
//        (_, _) => {}
//    }
//
//    let lhs_vec = match &lhs {
//        ValueType::Query(r) => r.iter().map(|(p, v)| (p, *v)).collect::<Vec<(&Path, &Value)>>(),
//        ValueType::Single((p, Value::List(l))) => l.iter().map(|v| (p, v)).collect::<Vec<(&Path, &Value)>>(),
//        ValueType::Single((p, v)) => vec![(p, *v)],
//    };
//
//    //
//    // Get RHS
//    //
//    let gac_path = gac_path(gac);
//    let rhs = match &gac.access_clause.compare_with {
//        Some(l) => match l {
//            LetValue::Value(v) => ValueType::Single((gac_path, v)),
//            LetValue::AccessClause(access) => {
//                let resolved= resolve_query(
//                    access, context, scope, gac_path.clone())?;
//                ValueType::Query(resolved)
//            }
//        },
//        None => return Err(Error::new(ErrorKind::MissingValue(
//            format!("When attempting to compare with {:?} RHS could not be resolved for query {:?}",
//                    gac.access_clause.comparator, gac.access_clause.query)
//        )))
//    };
//
//    let rhs_vec = match &rhs {
//        ValueType::Query(r) => r.iter().map(|(p, v)| (p, *v)).collect::<Vec<(&Path, &Value)>>(),
//        ValueType::Single((p, Value::List(l))) => l.iter().map(|v| (p, v)).collect::<Vec<(&Path, &Value)>>(),
//        ValueType::Single((p, v)) => vec![(p, *v)],
//    };
//
//
//    //
//    // Next comparison operations
//    //
//    let ((success, lhs_idx, rhs_idx), clause_not) = match &gac.access_clause.comparator {
//        //
//        // ==, !=
//        //
//        (CmpOperator::Eq, negate) =>
//            (compare(&lhs_vec, &rhs_vec, compare_eq, false)?, negate),
//
//        //
//        // >
//        //
//        (CmpOperator::Gt, negate) =>
//            (compare(&lhs_vec, &rhs_vec, compare_gt, false)?, negate),
//
//        //
//        // >=
//        //
//        (CmpOperator::Ge, negate) =>
//            (compare(&lhs_vec, &rhs_vec, compare_ge, false)?, negate),
//
//        //
//        // <
//        //
//        (CmpOperator::Lt, negate) =>
//            (compare(&lhs_vec, &rhs_vec, compare_lt, false)?, negate),
//
//        //
//        // <=
//        //
//        (CmpOperator::Le, negate) =>
//            (compare(&lhs_vec, &rhs_vec, compare_le, false)?, negate),
//
//        //
//        // IN, !IN
//        //
//        (CmpOperator::In, negate) =>
//            (compare(&lhs_vec, &rhs_vec, compare_eq, true)?, negate),
//
//
//        (_, _) => return Ok(EvalStatus::Comparison(EvalResult::status(Status::FAIL)))
//    };
//
//    let status = negation_status(success, *clause_not, gac.negation);
//    match status {
//        Status::PASS | Status::SKIP =>
//            Ok(EvalStatus::Comparison(EvalResult::status(status))),
//
//        Status::FAIL => {
//            let (lhs_path, lhs_value) = lhs_vec[lhs_idx];
//            let (rhs_path, rhs_value) = lhs_vec[rhs_idx];
//            Ok(EvalStatus::Comparison(
//                EvalResult::status_with_lhs_rhs(
//                    Status::FAIL,
//                    (lhs_path.clone(), lhs_value),
//                    (rhs_path.clone(), rhs_value)
//                )
//            ))
//        }
//    }
//}
//

fn compare<F>(lhs: &Vec<(&Path, &Value)>, rhs: &Vec<(&Path, &Value)>, compare: F, any: bool) -> Result<(bool, usize, usize), Error>
    where F: Fn(&Value, &Value) -> Result<bool, Error>
{
    for (lhs_idx, (lhs_path, lhs_value)) in lhs.iter().enumerate() {
        for (rhs_idx, (rhs_path, rhs_value)) in rhs.iter().enumerate() {
            let check = compare(*lhs_value, *rhs_value)?;
            if any && check {
                return Ok((true, lhs_idx, rhs_idx))
            }

            if !any && !check {
                return Ok((false, lhs_idx, rhs_idx))
            }
        }
    }
    Ok((true, lhs.len(), rhs.len()))
}

fn gac_path(gac: &GuardAccessClause<'_>) -> Path {
    let line = gac.access_clause.location.line.to_string();
    let col = gac.access_clause.location.column.to_string();
    Path::new(&["rule", "clause", gac.access_clause.location.file_name, &line, &col])
}


pub(super) fn named_evaluate(rule: &GuardNamedRuleClause<'_>,
                       eval_context: &EvalContext<'_>) -> Result<EvalStatus, Error> {
    match eval_context.rule_resolutions.get(&rule.dependent_rule) {
        Some(status) => Ok(
                EvalStatus::Unary(invert_status(*status, rule.negation))),
        None => Err(Error::new(ErrorKind::MissingValue(
            format!("Dependent rule name {} does not exist", rule.dependent_rule)
        )))
    }
}

//pub(super) fn guard_clause_evaluate(gc: &GuardClause<'_>,
//                                    scope: &Scope<'_>,
//                                    context: &Value,
//                                    path: Path,
//                                    eval_context: &EvalContext<'_>) -> Result<EvalStatus, Error> {
//
//    match gc {
//        GuardClause::Clause(clause) => gac_evaluate(clause, scope, context, path),
//        GuardClause::NamedRule(named) => named_evaluate(named, eval_context)
//    }
//}
//
//fn conditionally_evaluate<C>(conditions: &Conjunctions<GuardClause<'_>>,
//                             block: &Block<GuardClause<'_>>,
//                             scope: &Scope<'_>,
//                             context: &Value,
//                             path: Path,
//                             eval: &EvalContext<'_>,
//                             compare: C) -> Result<EvalStatus, Error>
//    where C: Fn(&GuardClause<'_>, &Scope<'_>, &Value, Path, &EvalContext<'_>) -> Result<EvalStatus, Error>
//{
//    match conjunction_of_clauses(
//        conditions, scope, context, eval, path.clone(),
//        guard_clause_evaluate)? {
//        EvalStatus::Comparison(EvalResult{status, from, to}) =>
//            return match status {
//                //
//                // TODO add the block level scope update  here
//                //
//                Status::PASS => {
//                    conjunction_of_clauses(
//                        &block.conjunctions,
//                        scope,
//                        context,
//                        eval,
//                        path.clone(),
//                        guard_clause_evaluate
//                    )
//                },
//
//                Status::FAIL | Status::SKIP =>
//                    Ok(EvalStatus::Comparison(EvalResult::status(Status::SKIP)))
//            },
//
//        _ => unreachable!()
//    }
//
//}
//
//pub(super) fn rule_clause_evaluate(rc: &RuleClause<'_>,
//                                   scope: &Scope<'_>,
//                                   context: &Value,
//                                   path: Path,
//                                   eval_context: &EvalContext<'_>) -> Result<EvalStatus, Error> {
//    match rc {
//        RuleClause::Clause(gc) => guard_clause_evaluate(gc, scope, context, path.clone(), eval_context),
//        RuleClause::WhenBlock(conditions, clauses) => {
//            conditionally_evaluate(conditions,
//                                   clauses,
//                                   scope,
//                                   context,
//                                   path,
//                                   eval_context,
//                                   guard_clause_evaluate)
//        },
//        RuleClause::TypeBlock(tc) => {
//            match &tc.conditions {
//                Some(conditions) =>
//                    conditionally_evaluate(conditions,
//                                           &tc.block,
//                                           scope,
//                                           context,
//                                           path,
//                                           eval_context,
//                                           guard_clause_evaluate),
//                None =>
//                    conjunction_of_clauses(
//                        &tc.block.conjunctions,
//                        scope,
//                        context,
//                        eval_context,
//                        path,
//                        guard_clause_evaluate
//                    )
//            }
//        }
//    }
//}
//
//pub(super) fn conjunction_of_clauses<T, C>(conjunctions: &Conjunctions<T>,
//                                           scope: &Scope<'_>,
//                                           value: &Value,
//                                           context: &EvalContext<'_>,
//                                           path: Path,
//                                           compare: C) -> Result<EvalStatus, Error>
//    where C: Fn(&T, &Scope<'_>, &Value, Path, &EvalContext<'_>) -> Result<EvalStatus, Error>
//{
//    'next: for disjunctions in conjunctions {
//        for disjunction in disjunctions {
//            match compare(
//                disjunction, scope, value, path.clone(), context)? {
//                EvalStatus::Unary(status) => match status {
//                    Status::PASS | Status::SKIP => continue 'next,
//                    Status::FAIL => continue
//                },
//
//                EvalStatus::Comparison(
//                    EvalResult{ status, from, to }) => match status {
//                    Status::PASS | Status::SKIP => continue 'next,
//                    Status::FAIL => continue
//                },
//            }
//        }
//        return Ok(EvalStatus::Comparison(EvalResult{
//            status: Status::FAIL,
//            from: Some((path.clone(), value.clone())),
//            to: None
//        }))
//    }
//    Ok(EvalStatus::Comparison(EvalResult::status(Status::PASS)))
//}
//
impl Evaluate for GuardClause<'_> {
    type Item = EvalStatus;

    fn evaluate(&self,
                resolver: &dyn Resolver,
                scope: &Scope<'_>,
                context: &Value,
                path: Path,
                eval_context: &EvalContext<'_>) -> Result<Self::Item, Error> {
        match self {
            GuardClause::Clause(gac) => gac.evaluate(resolver, scope, context, path, eval_context),
            GuardClause::NamedRule(r) => named_evaluate(r, eval_context)
        }
    }
}

impl Evaluate for GuardAccessClause<'_> {
    type Item = EvalStatus;

    fn evaluate(&self,
                resolver: &dyn Resolver,
                scope: &Scope<'_>,
                context: &Value,
                path: Path,
                eval: &EvalContext<'_>) -> Result<Self::Item, Error> {
        let lhs = match resolver.resolve_query(
            &self.access_clause.query, context, scope, path.clone(), eval) {
            Ok(r) => Some(r),
            Err(Error(ErrorKind::RetrievalError(_))) => None,
            Err(e) => return Err(e),
        };

        //
        // Special case EXISTS, !EXISTS,
        //
        if CmpOperator::Exists == self.access_clause.comparator.0 {
            return Ok(EvalStatus::Unary(
                negation_status(lhs.is_some(),
                                self.access_clause.comparator.1,
                                self.negation)));
        }

        //
        // Special case == null or != null
        //
        if let Some(LetValue::Value(Value::Null)) = &self.access_clause.compare_with {
            if CmpOperator::Eq == self.access_clause.comparator.0 {
                return Ok(EvalStatus::Unary(negation_status(
                    lhs.is_none(),
                    self.access_clause.comparator.1,
                    self.negation)))
            }
        }

        //
        // FAIL if LHS wasn't there for all other comparisons
        //
        let lhs = match lhs {
            Some(v) => ValueType::Query(v),
            None => return Err(Error::new(ErrorKind::RetrievalError(
                format!("When checking for {:?}, could for retrieve value for {:?}",
                        self.access_clause.comparator.0, self.access_clause.query)
            )))
        };

        //
        // The 2 other unary operators
        //
        match &self.access_clause.comparator {
            (CmpOperator::Empty, negation) |
            (CmpOperator::KeysEmpty, negation) => {
                let empty = match &lhs {
                    ValueType::Query(r) => r.is_empty(),
                    ValueType::Single((_p, Value::List(l))) => l.is_empty(),
                    ValueType::Single((_p, v)) =>
                        return Err(Error::new(ErrorKind::IncompatibleError(
                            format!("Expecting a list value from a resolved query or value, found value type {}", type_info(*v))
                        )))
                };
                return Ok(EvalStatus::Unary(
                    negation_status(empty, *negation, self.negation)))
            }

            (_, _) => {}
        }

        let lhs_vec = match &lhs {
            ValueType::Query(r) => r.iter().map(|(p, v)| (p, *v)).collect::<Vec<(&Path, &Value)>>(),
            ValueType::Single((p, Value::List(l))) => l.iter().map(|v| (p, v)).collect::<Vec<(&Path, &Value)>>(),
            ValueType::Single((p, v)) => vec![(p, *v)],
        };

        //
        // Get RHS
        //
        let self_path = gac_path(self);
        let rhs = match &self.access_clause.compare_with {
            Some(l) => match l {
                LetValue::Value(v) => ValueType::Single((self_path, v)),
                LetValue::AccessClause(access) => {
                    let resolved= resolver.resolve_query(
                        access, context, scope, self_path.clone(), eval)?;
                    ValueType::Query(resolved)
                }
            },
            None => return Err(Error::new(ErrorKind::MissingValue(
                format!("When attempting to compare with {:?} RHS could not be resolved for query {:?}",
                        self.access_clause.comparator, self.access_clause.query)
            )))
        };

        let rhs_vec = match &rhs {
            ValueType::Query(r) => r.iter().map(|(p, v)| (p, *v)).collect::<Vec<(&Path, &Value)>>(),
            ValueType::Single((p, Value::List(l))) => l.iter().map(|v| (p, v)).collect::<Vec<(&Path, &Value)>>(),
            ValueType::Single((p, v)) => vec![(p, *v)],
        };


        //
        // Next comparison operations
        //
        let ((success, lhs_idx, rhs_idx), clause_not) = match &self.access_clause.comparator {
            //
            // ==, !=
            //
            (CmpOperator::Eq, negate) =>
                (compare(&lhs_vec, &rhs_vec, compare_eq, false)?, negate),

            //
            // >
            //
            (CmpOperator::Gt, negate) =>
                (compare(&lhs_vec, &rhs_vec, compare_gt, false)?, negate),

            //
            // >=
            //
            (CmpOperator::Ge, negate) =>
                (compare(&lhs_vec, &rhs_vec, compare_ge, false)?, negate),

            //
            // <
            //
            (CmpOperator::Lt, negate) =>
                (compare(&lhs_vec, &rhs_vec, compare_lt, false)?, negate),

            //
            // <=
            //
            (CmpOperator::Le, negate) =>
                (compare(&lhs_vec, &rhs_vec, compare_le, false)?, negate),

            //
            // IN, !IN
            //
            (CmpOperator::In, negate) =>
                (compare(&lhs_vec, &rhs_vec, compare_eq, true)?, negate),

            (CmpOperator::KeysEq, negate) |
            (CmpOperator::KeysIn, negate) => {
                let mut lhs_vec_keys = Vec::with_capacity(lhs_vec.len());
                for (path, each_lhs) in &lhs_vec {
                    let map = match_map(*each_lhs, *path)?;
                    for keys in map.keys() {
                        lhs_vec_keys.push((*path, Value::String(keys.to_string())));
                    }
                }
                let lhs_vec_ref = lhs_vec_keys.iter()
                    .map(|(p, v)| (*p, v)).collect::<Vec<(&Path, &Value)>>();
                if self.access_clause.comparator.0 == CmpOperator::KeysIn {
                    (compare(&lhs_vec_ref, &rhs_vec, compare_eq, true)?, negate)
                }
                else {
                    (compare(&lhs_vec_ref, &rhs_vec, compare_eq, false)?, negate)
                }
            }


            (_, _) => return Ok(EvalStatus::Comparison(EvalResult::status(Status::FAIL)))
        };

        let status = negation_status(success, *clause_not, self.negation);
        match status {
            Status::PASS | Status::SKIP =>
                Ok(EvalStatus::Comparison(EvalResult::status(status))),

            Status::FAIL => {
                let (lhs_path, lhs_value) = lhs_vec[lhs_idx];
                let (rhs_path, rhs_value) = rhs_vec[rhs_idx];
                Ok(EvalStatus::Comparison(
                    EvalResult::status_with_lhs_rhs(
                        Status::FAIL,
                        (lhs_path.clone(), lhs_value),
                        (rhs_path.clone(), rhs_value)
                    )
                ))
            }
        }
    }
}

impl Evaluate for RuleClause<'_> {
    type Item = EvalStatus;

    fn evaluate(&self,
                resolver: &dyn Resolver,
                scope: &Scope<'_>,
                context: &Value,
                path: Path,
                eval_context: &EvalContext<'_>) -> Result<Self::Item, Error> {
        match self {
            RuleClause::Clause(gc) => gc.evaluate(resolver, scope, context, path, eval_context),
            RuleClause::WhenBlock(conditions, block) =>
                self.conditionally_evalute(
                    resolver,
                    scope,
                    context,
                    eval_context,
                    path,
                    Some(conditions),
                    block),
            RuleClause::TypeBlock(tb) =>
                self.conditionally_evalute(
                    resolver,
                    scope,
                    context,
                    eval_context,
                    path,
                    if let Some(when) = &tb.conditions { Some(when) } else { None },
                    &tb.block),
        }
    }

}

impl RuleClause<'_> {
    fn conditionally_evalute(&self,
                             resolver: &dyn Resolver,
                             scope: &Scope<'_>,
                             context: &Value,
                             eval_context: &EvalContext<'_>,
                             path: Path,
                             conditions: Option<&Conjunctions<GuardClause<'_>>>,
                             block: &Block<GuardClause<'_>>) -> Result<EvalStatus, Error> {
        let (skip, from, to) = match conditions {
            Some(when) => match when.evaluate(resolver, scope, context, path.clone(), eval_context)? {
                EvalStatus::Comparison(EvalResult{status: Status::PASS, from, to}) => (false, from, to),
                EvalStatus::Unary(Status::PASS) => (false, None, None),
                EvalStatus::Comparison(EvalResult{ status: Status::FAIL, from, to}) => (true, from, to),
                EvalStatus::Unary(Status::FAIL) => (true, None, None),
                _ => unreachable!()
            },

            None =>  (false, None, None)
        };

        if !skip {
            let mut block_scope = Scope::child(scope);
            block_scope.assignments(&block.assignments, path.clone())?;
            block_scope.assignment_queries(&block.assignments, path.clone(), context, resolver, eval_context)?;
            block.conjunctions.evaluate(resolver, &block_scope, context, path, eval_context)
        }
        else {
            Ok(EvalStatus::Comparison(EvalResult{ status: Status::SKIP, from, to}))
        }
    }

}

impl<T: Evaluate<Item=EvalStatus>> Evaluate for Conjunctions<T> {
    type Item = EvalStatus;

    fn evaluate(&self,
                resolver: &dyn Resolver,
                scope: &Scope<'_>,
                context: &Value,
                path: Path,
                eval: &EvalContext<'_>) -> Result<Self::Item, Error> {
        'conjunction:
        for conjunction in self {
            for disjunction in conjunction {
                match disjunction.evaluate(resolver, scope, context, path.clone(), eval)? {
                    EvalStatus::Unary(Status::SKIP) => unreachable!(),
                    EvalStatus::Comparison(EvalResult{ status: Status::SKIP, from, to}) =>
                        unreachable!(), // these codes should not happen

                    EvalStatus::Unary(Status::FAIL) => continue,
                    EvalStatus::Comparison(EvalResult{ status: Status::FAIL, from, to}) =>
                        continue, // try the next disjunction

                    EvalStatus::Unary(status) => continue 'conjunction,
                    EvalStatus::Comparison(r) => continue 'conjunction,
                }
            }
            // We failed all disjunction Clauses
            return Ok(EvalStatus::Comparison(EvalResult::status_with_lhs(
                Status::FAIL, (path.clone(), context))))
        }
        Ok(EvalStatus::Comparison(EvalResult::status(Status::PASS)))
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::rules::parser2::*;
    use crate::commands::files::*;
    use std::fs::File;
    use crate::rules::exprs::query::QueryResolver;

    fn create_from_json(path: &str) -> Result<Value, Error> {
        let file = File::open(path)?;
        let context = read_file_content(file)?;
        Ok(parse_value(from_str2(&context))?.1)
    }

    const OPA_LIKE_RULES: &str = r#"
    rule shell_accessible {
       servers[*].protocols[*] IN ["telnet", "ssh"]
    }

    rule app_https {
        servers[0].id == "app"
        servers[0].protocols[0] == "https"
    }

    rule k8s_exists {
        request EXISTS
        request.apiVersion == /k8s\.io/ # FAIL version
        # request.apiVersion != /k8s\.io/
    }

    rule k8s_container_images when k8s_exists {
        let images = request.object.spec.containers[*].image

        request.kind.kind == "Pod"
        not %images == /^hooli.com/ <<images does not come from trusted registry>>
    }
    "#;

    #[test]
    fn test_gac_resolve_opa_sample() -> Result<(), Error> {
        let scope = Scope::new();
        let rules = rules_file(from_str2(OPA_LIKE_RULES))?;
        let shell_rule = &rules.guard_rules[0];
        let opa_content = create_from_json("assets/opa-sample.json")?;
        let eval = EvalContext::new(&opa_content);
        let resolvers = QueryResolver{};
        let rule_clause = &shell_rule.block.conjunctions[0][0];
        if let RuleClause::Clause(gac) = rule_clause {
            let assessment = gac.evaluate(&resolvers, &scope, &opa_content, Path::new(&["/"]), &eval)?;
            println!("{:?}", assessment);
            assert_eq!(EvalStatus::Comparison(EvalResult::status(Status::PASS)), assessment);
        }

        for idx in 0 as usize..3 as usize {
            let rule_clause = &rules.guard_rules[idx];
            for each in &rule_clause.block.conjunctions {
                for disjunction in each {
                    if let RuleClause::Clause(gac) = disjunction {
                        let assessment = gac.evaluate(&resolvers, &scope, &opa_content, Path::new(&["/"]), &eval)?;
                        println!("{:?}", assessment);
                        match assessment {
                            EvalStatus::Unary(status) => assert_eq!(status, Status::PASS),
                            EvalStatus::Comparison(EvalResult{status, from, to}) =>
                                if idx < 2 { assert_eq!(status, Status::PASS) } else { assert_eq!(status, Status::FAIL )}
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
