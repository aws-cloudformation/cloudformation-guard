use crate::rules::exprs::{RulesFile, AccessQuery, Rule, LetExpr, LetValue, QueryPart, SliceDisplay, Block, GuardClause, Conjunctions, ParameterizedRule};
use crate::rules::path_value::{PathAwareValue, MapValue};
use std::collections::{HashMap, HashSet};
use crate::rules::{QueryResult, Status, EvalContext, UnResolved, RecordType, NamedStatus, TypeBlockCheck, BlockCheck, ClauseCheck, UnaryValueCheck, ValueCheck, ComparisonClauseCheck, RecordTracer};
use crate::rules::Result;
use crate::rules::errors::{Error, ErrorKind};
use lazy_static::lazy_static;
use inflector::cases::*;
use serde::Serialize;
use crate::rules::Status::SKIP;
use crate::rules::values::CmpOperator;

pub(crate) struct Scope<'value, 'loc: 'value> {
    root: &'value PathAwareValue,
    //resolved_variables: std::cell::RefCell<HashMap<&'value str, Vec<QueryResult<'value>>>>,
    resolved_variables: HashMap<&'value str, Vec<QueryResult<'value>>>,
    literals: HashMap<&'value str, &'value PathAwareValue>,
    variable_queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub(crate) struct EventRecord<'value> {
    pub(crate) context: String,
    pub(crate) container: Option<RecordType<'value>>,
    pub(crate) children: Vec<EventRecord<'value>>,
}

pub(crate) struct RootScope<'value, 'loc: 'value> {
    scope: Scope<'value, 'loc>,
    rules: HashMap<&'value str, Vec<&'value Rule<'loc>>>,
    rules_status: HashMap<&'value str, Status>,
    parameterized_rules: HashMap<&'value str, &'value ParameterizedRule<'loc>>,
    recorder: RecordTracker<'value>,
}

impl<'value, 'loc: 'value> RootScope<'value, 'loc> {
    pub fn reset_root(self, new_root: &'value PathAwareValue) -> Result<RootScope<'value, 'loc>> {
        root_scope_with(
            self.scope.literals,
            self.scope.variable_queries,
            self.rules,
            self.parameterized_rules,
            new_root)
    }

    pub(crate) fn reset_recorder(&mut self) -> RecordTracker<'value> {
        std::mem::replace(
            &mut self.recorder, RecordTracker {
                final_event: None,
                events: vec![]
            }
        )
    }
}

pub(crate) fn reset_with<'value, 'loc: 'value>(
    mut root_scope: RootScope<'value, 'loc>,
    new_value: &'value PathAwareValue) -> RootScope<'value, 'loc>
{
    let variables = std::mem::replace(
        &mut root_scope.scope.variable_queries, HashMap::new());
    let literals = std::mem::replace(
        &mut root_scope.scope.literals, HashMap::new()
    );
    let rules = std::mem::replace(
        &mut root_scope.rules, HashMap::new()
    );
    let parameterized_rules = std::mem::replace(
        &mut root_scope.parameterized_rules, HashMap::new()
    );
    let scope = Scope {
        root: new_value,
        //resolved_variables: std::cell::RefCell::new(HashMap::new()),
        resolved_variables: HashMap::new(),
        literals: literals,
        variable_queries: variables
    };
    RootScope {
        scope, rules, parameterized_rules, rules_status: HashMap::new(),
        recorder: RecordTracker {
            final_event: None,
            events: vec![]
        }
    }
}

pub(crate) struct BlockScope<'value, 'loc: 'value, 'eval> {
    scope: Scope<'value, 'loc>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

pub(crate) struct ValueScope<'value, 'eval, 'loc: 'value> {
    pub(crate) root: &'value PathAwareValue,
    pub(crate) parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

fn extract_variables<'value, 'loc: 'value>(
    expressions: &'value Vec<LetExpr<'loc>>)
    -> Result<(HashMap<&'value str, &'value PathAwareValue>,
               HashMap<&'value str, &'value AccessQuery<'loc>>)> {

    let mut literals = HashMap::with_capacity(expressions.len());
    let mut queries = HashMap::with_capacity(expressions.len());
    for each in expressions {
        match &each.value {
            LetValue::Value(v) => {
                literals.insert(each.var.as_str(), v);
            },

            LetValue::AccessClause(query) => {
                queries.insert(each.var.as_str(), query);
            },

            LetValue::FunctionCall(_) => todo!()
        }
    }
    Ok((literals, queries))
}

fn retrieve_index<'value>(parent: &'value PathAwareValue,
                          index: i32,
                          elements: &'value Vec<PathAwareValue>,
                          query: &[QueryPart<'_>]) -> QueryResult<'value> {
    let check = if index >= 0 { index } else { -index } as usize;
    if check < elements.len() {
        QueryResult::Resolved(&elements[check])
    } else {
        QueryResult::UnResolved(
            UnResolved {
                traversed_to: parent,
                remaining_query: format!("{}", SliceDisplay(query)),
                reason: Some(
                    format!("Array Index out of bounds for path = {} on index = {} inside Array = {:?}, remaining query = {}",
                            parent.self_path(), index, elements, SliceDisplay(query))
                )
            }
        )
    }

}

fn accumulate<'value, 'loc: 'value>(
    parent: &'value PathAwareValue,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    elements: &'value Vec<PathAwareValue>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>) -> Result<Vec<QueryResult<'value>>> {
    //
    // We are here when we are doing [*] for a list. It is an error if there are no
    // elements
    //
    if elements.is_empty()  {
        return to_unresolved_result(
            parent,
            format!("No more entries for value at path = {} on type = {} ",
                    parent.self_path(), parent.type_info()),
            &query[query_index..]
        );
    }

    let mut accumulated = Vec::with_capacity(elements.len());
    for (_index, each) in elements.iter().enumerate() {
        accumulated.extend(query_retrieval_with_converter(query_index+1, query, each, resolver, converter)?);
    }
    Ok(accumulated)

}

fn accumulate_map<'value, 'loc: 'value, F>(
    parent: &'value PathAwareValue,
    map: &'value MapValue,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
    func: F) -> Result<Vec<QueryResult<'value>>>
    where F: Fn(usize, &'value [QueryPart<'loc>], &'value PathAwareValue, &'value PathAwareValue, &mut dyn EvalContext<'value, 'loc>, Option<&dyn Fn(&str) -> String>) -> Result<Vec<QueryResult<'value>>>
{
    //
    // We are here when we are doing * all values for map. It is an error if there are no
    // elements in the map
    //
    if map.is_empty() {
        return to_unresolved_result(
            parent,
            format!("No more entries for value at path = {} on type = {} ",
                    parent.self_path(), parent.type_info()),
            &query[query_index..]
        );
    }

    let mut resolved = Vec::with_capacity(map.values.len());
    for (key, each) in map.keys.iter().zip(map.values.values()) {
        let mut val_resolver = ValueScope{ root: each, parent: resolver };
        resolved.extend(
            func(query_index+1, query, key, each, &mut val_resolver, converter)?)
    }
    Ok(resolved)
}

    fn to_unresolved_value<'value>(
        current: &'value PathAwareValue,
        reason: String,
        query: &[QueryPart<'_>]) -> QueryResult<'value> {
    QueryResult::UnResolved(
        UnResolved {
            traversed_to: current,
            reason: Some(reason),
            remaining_query: format!("{}", SliceDisplay(query))
        }
    )
}

fn to_unresolved_result<'value>(
    current: &'value PathAwareValue,
    reason: String,
    query: &[QueryPart<'_>]) -> Result<Vec<QueryResult<'value>>> {
    Ok(vec![to_unresolved_value(current, reason, query)])
}

fn map_resolved<'value, F>(
    _current: &'value PathAwareValue,
    query_result: QueryResult<'value>,
    func: F)
    -> Result<Vec<QueryResult<'value>>>
       where F: FnOnce(&'value PathAwareValue) -> Result<Vec<QueryResult<'value>>>
{
    match query_result {
        QueryResult::Resolved(res) => func(res),
        rest => Ok(vec![rest]),
    }
}

fn check_and_delegate<'value, 'loc: 'value>(conjunctions: &'value Conjunctions<GuardClause<'loc>>, name: &'value Option<String>)
    -> impl Fn(usize, &'value [QueryPart<'loc>], &'value PathAwareValue, &'value PathAwareValue, &mut dyn EvalContext<'value, 'loc>, Option<&dyn Fn(&str) -> String>) -> Result<Vec<QueryResult<'value>>>
{
    move |index, query, key, value, eval_context, converter| {
        let context = format!("Filter/Map#{}", conjunctions.len());
        eval_context.start_record(&context)?;
        match super::eval::eval_conjunction_clauses(
            conjunctions, eval_context, super::eval::eval_guard_clause) {
            Ok(status) => {
                eval_context.end_record(&context, RecordType::Filter(status))?;
                if let Some(key_name) = name {
                    if status == Status::PASS {
                        eval_context.add_variable_capture_key(key_name.as_ref(), key)?;
                    }
                }
                match status {
                    Status::PASS => {
                        query_retrieval_with_converter(index, query, value, eval_context, converter)
                    },
                    _ => Ok(vec![])
                }
            },

            Err(e) => {
                eval_context.end_record(&context, RecordType::Filter(Status::FAIL))?;
                Err(e)
            }
        }
    }
}

lazy_static! {
    static ref CONVERTERS: &'static [(fn(&str) -> bool, fn(&str) -> String)] =
        &[
            (camelcase::is_camel_case, camelcase::to_camel_case),
            (classcase::is_class_case, classcase::to_class_case),
            (kebabcase::is_kebab_case, kebabcase::to_kebab_case),
            (pascalcase::is_pascal_case, pascalcase::to_pascal_case),
            (snakecase::is_snake_case, snakecase::to_snake_case),
            (titlecase::is_title_case, titlecase::to_title_case),
            (traincase::is_train_case, traincase::to_train_case),
        ];
}

fn query_retrieval<'value, 'loc: 'value>(
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    current: &'value PathAwareValue,
    resolver: &mut dyn EvalContext<'value, 'loc>) -> Result<Vec<QueryResult<'value>>> {
    query_retrieval_with_converter(
        query_index, query, current, resolver, None,
    )
}

fn query_retrieval_with_converter<'value, 'loc: 'value>(
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    current: &'value PathAwareValue,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>) -> Result<Vec<QueryResult<'value>>> {

    if query_index >= query.len() {
        return Ok(vec![QueryResult::Resolved(current)])
    }

    if query_index == 0 && query[query_index].is_variable() {
        let retrieved = resolver.resolve_variable(query[query_index].variable().unwrap())?;
        let mut resolved = Vec::with_capacity(retrieved.len());
        for each in retrieved {
            match each {
                QueryResult::UnResolved(ur) => {
                    resolved.push(QueryResult::UnResolved(ur));
                },
                QueryResult::Literal(value) |
                QueryResult::Resolved(value) => {
                    let index = if query_index+1 < query.len() {
                        match &query[query_index+1] {
                            QueryPart::AllIndices(_name) => query_index+2,
                            _ => query_index+1
                        }
                    } else { query_index+1 };
                    let mut scope = ValueScope { root: value, parent: resolver };
                    resolved.extend(query_retrieval_with_converter(index, query, value, &mut scope, converter)?);
                }
            }
        }
        return Ok(resolved)
    }

    match &query[query_index] {
        QueryPart::This => {
            query_retrieval_with_converter(query_index+1, query, current, resolver, converter)
        },

        QueryPart::Key(key) => {
            match key.parse::<i32>() {
                Ok(idx) => {
                    match current {
                        PathAwareValue::List((_, list)) => {
                            map_resolved(current,
                                         retrieve_index(current, idx, list, query),
                                         |val| query_retrieval_with_converter(query_index+1, query, val, resolver, converter))
                        }

                        _ =>
                            to_unresolved_result(
                                current,
                                format!("Attempting to retrieve from index {} but type is not an array at path {}", idx, current.self_path()),
                                query)
                    }
                },

                Err(_) =>
                    if let PathAwareValue::Map((path, map)) = current {
                        if query[query_index].is_variable() {
                            let var = query[query_index].variable().unwrap();
                            let keys = resolver.resolve_variable(var)?;
                            let keys = if query.len() > query_index+1 {
                                match &query[query_index+1] {
                                    QueryPart::AllIndices(_) | QueryPart::Key(_) => keys,
                                    QueryPart::Index(index) => {
                                        let check = if *index >= 0 { *index } else { -*index } as usize;
                                        if check < keys.len() {
                                            vec![keys[check].clone()]
                                        } else {
                                            return to_unresolved_result(
                                                current,
                                                format!("Index {} on the set of values returned for variable {} on the join, is out of bounds. Length {}, Values = {:?}",
                                                        check, var, keys.len(), keys),
                                                &query[query_index..]
                                            )
                                        }
                                    },

                                    _ => return Err(Error::new(ErrorKind::IncompatibleError(
                                        format!("This type of query {} based variable interpolation is not supported {}, {}",
                                                query[1], current.type_info(), SliceDisplay(query)))))
                                }
                            } else {
                                keys
                            };


                            let mut acc = Vec::with_capacity(keys.len());
                            for each_key in keys {
                                match each_key {
                                    QueryResult::UnResolved(ur) => {
                                        acc.extend(
                                            to_unresolved_result(
                                                current,
                                                format!("Keys returned for variable {} could not completely resolve. Path traversed until {}{}",
                                                        var, ur.traversed_to.self_path(), ur.reason.map_or("".to_string(), |msg| msg)
                                                ),
                                                &query[query_index..]
                                            )?
                                        );
                                    },

                                    QueryResult::Literal(key) |
                                    QueryResult::Resolved(key) => {
                                        if let PathAwareValue::String((_, k)) = key {
                                            if let Some(next) = map.values.get(k) {
                                                acc.extend(query_retrieval_with_converter(query_index+1, query, next, resolver, converter)?);
                                            } else {
                                                acc.extend(
                                                    to_unresolved_result(
                                                        current,
                                                        format!("Could not locate key = {} inside struct at path = {}", k, path),
                                                        &query[query_index..]
                                                    )?
                                                );
                                            }
                                        } else {
                                            return Err(Error::new(
                                                ErrorKind::NotComparable(
                                                    format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                            SliceDisplay(query),
                                                            key.type_info(),
                                                            key.self_value()
                                                    )
                                                )
                                            ))
                                        }
                                    }
                                }
                            }
                            Ok(acc)
                        } else {
                            match map.values.get(key) {
                                Some(val) =>
                                    return query_retrieval_with_converter(query_index+1, query, val, resolver, converter),

                                None => {
                                    match converter {
                                        Some(func) => {
                                            let converted = func(key.as_str());
                                            if let Some(val) = map.values.get(&converted) {
                                                return query_retrieval_with_converter(query_index+1, query, val, resolver, converter)
                                            }
                                        },

                                        None => {
                                            for (_, each_converter) in CONVERTERS.iter() {
                                                if let Some(val) = map.values.get(&each_converter(key.as_str())) {
                                                    return query_retrieval_with_converter(query_index+1, query, val, resolver, Some(each_converter))
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            to_unresolved_result(
                                current,
                                format!("Could not find key {} inside struct at path {}", key, path),
                                &query[query_index..]
                            )
                        }
                    } else {
                        to_unresolved_result(
                            current,
                            format!("Attempting to retrieve from key {} but type is not an struct type at path {}, Type = {}, Value = {:?}",
                                    key, current.self_path(), current.type_info(), current),
                            &query[query_index..])
                    }
            }
        },

        QueryPart::Index(index) => {
            match current {
                PathAwareValue::List((_, list)) => {
                    map_resolved(current,
                                 retrieve_index(current, *index, list, query),
                                 |val| query_retrieval_with_converter(query_index+1, query, val, resolver, converter))
                }

                _ =>
                    to_unresolved_result(
                        current,
                        format!("Attempting to retrieve from index {} but type is not an array at path {}", index, current.self_path()),
                        &query[query_index..])
            }
        },

        QueryPart::AllIndices(name) => {
            match current {
                PathAwareValue::List((_path, elements)) => {
                    accumulate(current, query_index, query, elements, resolver, converter)
                },

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => {
                    query_retrieval_with_converter(query_index+1, query, rest, resolver, converter)
                }
            }
        },

        QueryPart::AllValues(name) => {
            match current {
                //
                // Supporting old format
                //
                PathAwareValue::List((_path, elements)) => {
                    accumulate(current, query_index, query, elements, resolver, converter)
                },

                PathAwareValue::Map((_path, map)) => {
                    let (report, name) = match name {
                        Some(n) => (true, n.as_str()),
                        None => (false, "")
                    };
                    accumulate_map(current, map, query_index, query, resolver, converter,
                                   |index,
                                    query,
                                    key,
                                    value,
                                    context,
                                    converter| {
                                    if report {
                                        context.add_variable_capture_key(name, key)?;
                                    }
                                       query_retrieval_with_converter(index, query, value, context, converter)
                                   }
                    )
                },

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => {
                    query_retrieval_with_converter(query_index+1, query, rest, resolver, converter)
                }
            }
        },

        QueryPart::Filter(name, conjunctions) => {
            match current {
                PathAwareValue::Map((_path, map)) => {
                    match &query[query_index-1] {
                        QueryPart::AllValues(_name) |
                        QueryPart::AllIndices(_name) => {
                            check_and_delegate(conjunctions, &None)(query_index+1, query, current, current, resolver, converter)
                        },

                        QueryPart::Key(_) => {
//
//                            Ideal solution, see https://github.com/rust-lang/rust/issues/41078
//
//                            accumulate_map(
//                                map, query_index, query, resolver,
//                                |index, query:&'value [QueryPart<'_>], value:&'value PathAwareValue, context: &dyn EvalContext<'value>| {
//                                    match super::eval::eval_conjunction_clauses(
//                                        conjunctions, resolver, super::eval::eval_guard_clause)? {
//                                        Status::PASS => query_retrieval_with_converter(index+1, query, current, resolver, converter),
//                                        _ => Ok(vec![])
//                                    }
//                                })
                            if !map.is_empty() {
                                accumulate_map(
                                    current, map, query_index, query, resolver, converter, check_and_delegate(conjunctions, name)
                                )
                            } else {
                                Ok(vec![])
                            }
                        },

                        _ => unreachable!()
                    }
                },

                PathAwareValue::List((_path, list)) => {
                    let mut selected = Vec::with_capacity(list.len());
                    for each in list {
                        let context = format!("Filter/List#{}", conjunctions.len());
                        resolver.start_record(&context)?;
                        let mut val_resolver = ValueScope { root: each, parent: resolver };
                        let result = match super::eval::eval_conjunction_clauses(
                            conjunctions, &mut val_resolver, super::eval::eval_guard_clause) {
                            Ok(status) => {
                                resolver.end_record(&context, RecordType::Filter(status))?;
                                match status {
                                    Status::PASS => {
                                        query_retrieval_with_converter(query_index + 1, query, each, resolver, converter)?
                                    },
                                    _ => vec![]
                                }
                            },

                            Err(e) => {
                                resolver.end_record(&context, RecordType::Filter(Status::FAIL))?;
                                return Err(e)
                            }
                        };
                        selected.extend(result);
                    }
                    Ok(selected)
                }

                _ => if let QueryPart::AllIndices(_) = &query[query_index-1] {
                    let mut val_resolver = ValueScope { root: current, parent: resolver };
                    match super::eval::eval_conjunction_clauses(
                            conjunctions, &mut val_resolver, super::eval::eval_guard_clause) {
                        Ok(status) => {
                            match status {
                                Status::PASS => {
                                    query_retrieval_with_converter(query_index + 1, query, current, resolver, converter)
                                },
                                _ => Ok(vec![])
                            }
                        },
                        Err(e) => {
                            return Err(e)
                        }
                    }
                } else {
                    to_unresolved_result(
                        current,
                        format!("Filter on value type that was not a struct or array {} {}", current.type_info(), current.self_path()),
                        &query[query_index..])
                }
            }
        },

        QueryPart::MapKeyFilter(_name, map_key_filter) => {
            match current {
                PathAwareValue::Map((_path, map)) => {
                    let mut selected = Vec::with_capacity(map.values.len());
                    let rhs = match &map_key_filter.compare_with {
                        LetValue::AccessClause(acc_query) => {
                            let values = query_retrieval_with_converter(0, &acc_query.query, current, resolver, converter)?;
                            values
                        },

                        LetValue::Value(path_value) => {
                            vec![QueryResult::Literal(path_value)]
                        },

                        LetValue::FunctionCall(_) => todo!(),
                    };

                    let lhs = map.keys.iter().map(|p| QueryResult::Resolved(p))
                        .collect::<Vec<QueryResult<'_>>>();

                    let results = super::eval::real_binary_operation(
                        &lhs,
                        &rhs,
                        map_key_filter.comparator,
                        "".to_string(),
                        None,
                        resolver
                    )?;

                    let results = match results {
                        super::eval::EvaluationResult::QueryValueResult(r) => r,
                        _ => unreachable!()
                    };

                    for each_result in results {
                        match each_result {
                            (QueryResult::Resolved(key), Status::PASS) => {
                                if let PathAwareValue::String((_, key_name))= key {
                                    selected.push(
                                        QueryResult::Resolved(
                                            map.values.get(key_name.as_str()).unwrap()));
                                }
                            },

                            (QueryResult::UnResolved(ur), _) => {
                                selected.push(QueryResult::UnResolved(ur));
                            },

                            (_, _) => {
                                continue;
                            }
                        }
                    }

                    let mut extended = Vec::with_capacity(selected.len());
                    for each in selected {
                        match each {
                            QueryResult::Literal(r) |
                            QueryResult::Resolved(r) => {
                                extended.extend(
                                    query_retrieval_with_converter(query_index+1, query, r, resolver, converter)?
                                );
                            },

                            QueryResult::UnResolved(ur) => {
                                extended.push(QueryResult::UnResolved(ur));
                            }
                        }
                    }
                    Ok(extended)
                },

                _ => to_unresolved_result(
                    current,
                    format!("Map Filter for keys was not a struct {} {}", current.type_info(), current.self_path()),
                    &query[query_index..])
            }
        }
    }
}


pub(crate) fn root_scope<'value, 'loc: 'value>(
    rules_file: &'value RulesFile<'loc>,
    root: &'value PathAwareValue) -> Result<RootScope<'value, 'loc>>
{
    let (literals, queries) =
        extract_variables(&rules_file.assignments)?;
    let mut lookup_cache = HashMap::with_capacity(rules_file.guard_rules.len());
    for rule in &rules_file.guard_rules {
        lookup_cache.entry(rule.rule_name.as_str()).or_insert(vec![]).push(rule);
    }

    let mut parameterized_rules = HashMap::with_capacity(
        rules_file.parameterized_rules.len());
    for pr in rules_file.parameterized_rules.iter(){
        parameterized_rules.insert(pr.rule.rule_name.as_str(), pr);
    }
    root_scope_with(literals, queries, lookup_cache,  parameterized_rules, root)
}

pub(crate) fn root_scope_with<'value, 'loc: 'value>(
    literals: HashMap<&'value str, &'value PathAwareValue>,
    queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
    lookup_cache: HashMap<&'value str, Vec<&'value Rule<'loc>>>,
    parameterized_rules: HashMap<&'value str,&'value ParameterizedRule<'loc>>,
    root: &'value PathAwareValue)
    -> Result<RootScope<'value, 'loc>>
{
    Ok(RootScope {
        scope: Scope {
            root,
            literals,
            variable_queries: queries,
            //resolved_variables: std::cell::RefCell::new(HashMap::new()),
            resolved_variables: HashMap::new(),
        },
        rules: lookup_cache,
        parameterized_rules,
        rules_status: HashMap::new(),
        recorder: RecordTracker {
            final_event: None,
            events: vec![]
        }
    })
}

pub(crate) fn block_scope<'value, 'block, 'loc: 'value, 'eval, T>(
    block: &'value Block<'loc, T>,
    root: &'value PathAwareValue,
    parent: &'eval mut dyn EvalContext<'value, 'loc>) -> Result<BlockScope<'value, 'loc, 'eval>> {

    let (literals, variable_queries) =
        extract_variables(&block.assignments)?;
    Ok(BlockScope {
        scope: Scope {
            literals,
            variable_queries,
            root,
            //resolved_variables: std::cell::RefCell::new(HashMap::new()),
            resolved_variables: HashMap::new(),
        },
        parent
    })
}

pub(crate) struct RecordTracker<'value> {
    pub(crate) events: Vec<EventRecord<'value>>,
    pub(crate) final_event: Option<EventRecord<'value>>,
}

impl<'value> RecordTracker<'value> {
    pub(crate) fn new() -> RecordTracker<'value> {
        RecordTracker {
            events: vec![],
            final_event: None
        }
    }
    pub(crate) fn extract(mut self) -> EventRecord<'value> {
        self.final_event.take().unwrap()
    }
}

impl<'value> RecordTracer<'value> for RecordTracker<'value> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.events.push(EventRecord {
            context: context.to_string(),
            container: None,
            children: vec![]
        });
        Ok(())
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        let matched = match self.events.pop() {
            Some(mut event) => {
                if &event.context != context {
                    return Err(Error::new(ErrorKind::IncompatibleError(
                        format!("Event Record context start and end does not match {}", context)
                    )))
                }

                event.container = Some(record);
                event
            },

            None => {
                return Err(Error::new(ErrorKind::IncompatibleError(
                    format!("Event Record end with context {} did not have a corresponding start", context)
                )))
            }
        };

        match self.events.last_mut() {
            Some(parent) => {
                parent.children.push(matched);
            },

            None => {
                self.final_event.replace(matched);
            }
        }
        Ok(())
    }
}

impl<'value, 'loc: 'value> EvalContext<'value, 'loc> for RootScope<'value, 'loc> {

    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.scope.root, self)
    }

    fn find_parameterized_rule(&mut self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        match self.parameterized_rules.get(rule_name) {
            Some(r) => Ok(*r),
            _ => Err(Error::new(ErrorKind::MissingValue(
                format!("Parameterized Rule with name {} was not found, candiate {:?}",
                        rule_name, self.parameterized_rules.keys())
            )))
        }
    }


    fn root(&mut self) -> &'value PathAwareValue {
        self.scope.root
    }

    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        if let Some(status) = self.rules_status.get(rule_name) {
            return Ok(*status)
        }

        let rule = match self.rules.get(rule_name) {
            Some(rule) => rule.clone(),
            None => return Err(Error::new(ErrorKind::MissingValue(
                format!("Rule {} by that name does not exist, Rule Names = {:?}",
                        rule_name, self.rules.keys()))))
        };

        let status = 'done: loop {
            for each_rule in rule {
                let status = super::eval::eval_rule(each_rule, self)?;
                if status != SKIP {
                    break 'done status;
                }
            }
            break SKIP
        };

        // let status = super::eval::eval_rule(rule, self)?;
        self.rules_status.insert(rule_name, status);
        Ok(status)

//        self.rules.get(rule_name).map_or_else(
//            || Err(Error::new(ErrorKind::MissingValue(
//                format!("Rule {} by that name does not exist, Rule Names = {:?}",
//                        rule_name, self.rules.keys())
//            ))),
//            |rule| super::eval::eval_rule(*rule, self)
//        )
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Literal(*val)])
        }

        if let Some(values) = self.scope.resolved_variables.get(variable_name) {
            return Ok(values.clone())
        }

        let query = match self.scope.variable_queries.get(variable_name) {
            Some(val) => val,
            None => return Err(Error::new(ErrorKind::MissingValue(
                format!("Could not resolve variable by name {} across scopes", variable_name)
            )))
        };

        let match_all = query.match_all;

        let result = query_retrieval(0, &query.query, self.scope.root, self)?;
        let result = if !match_all {
            result.into_iter().filter(|q| matches!(q, QueryResult::Resolved(_))).collect()
        } else {
            result
        };
        self.scope.resolved_variables.insert(variable_name, result.clone());
        return Ok(result);
    }

    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()> {
        self.scope.resolved_variables.entry(variable_name).or_default()
            .push(QueryResult::Resolved(key));
        Ok(())
    }
}

impl<'value, 'loc: 'value> RecordTracer<'value> for RootScope<'value, 'loc> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.recorder.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.recorder.end_record(context, record)
    }
}

impl<'value, 'loc: 'value, 'eval> EvalContext<'value, 'loc> for ValueScope<'value, 'eval, 'loc> {
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.root, self.parent)
    }

    fn find_parameterized_rule(&mut self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }


    fn root(&mut self) -> &'value PathAwareValue {
        self.root
    }

    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }


    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        self.parent.resolve_variable(variable_name)
    }

    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
    }
}

impl<'value, 'loc: 'value, 'eval> RecordTracer<'value> for ValueScope<'value, 'eval, 'loc> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }
}


impl<'value, 'loc: 'value, 'eval> EvalContext<'value, 'loc> for BlockScope<'value, 'loc, 'eval> {
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.scope.root, self)
    }

    fn find_parameterized_rule(&mut self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> &'value PathAwareValue {
        self.scope.root
    }

    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Literal(*val)])
        }

        if let Some(values) = self.scope.resolved_variables.get(variable_name) {
            return Ok(values.clone())
        }

        let query = match self.scope.variable_queries.get(variable_name) {
            Some(val) => val,
            None => return self.parent.resolve_variable(variable_name)
        };

        let match_all = query.match_all;

        let result = query_retrieval(0, &query.query, self.scope.root, self)?;
        let result = if !match_all {
            result.into_iter().filter(|q| matches!(q, QueryResult::Resolved(_))).collect()
        } else {
            result
        };
        self.scope.resolved_variables.insert(variable_name, result.clone());
        return Ok(result);
    }

    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
    }
}

impl<'value, 'loc: 'value, 'eval> RecordTracer<'value> for BlockScope<'value, 'loc, 'eval> {
    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }
}



#[derive(Clone, Debug,Serialize, Default)]
pub(crate) struct Messages {
    pub(crate) custom_message: Option<String>,
    pub(crate) error_message: Option<String>
}

pub(crate) type Metadata = HashMap<String, String>;

#[derive(Clone, Debug,Serialize, Default)]
pub(crate) struct FileReport<'value> {
   pub(crate) name: &'value str,
   pub(crate) metadata: Metadata,
   pub(crate) status: Status,
   pub(crate) not_compliant: Vec<ClauseReport<'value>>,
   pub(crate) not_applicable: HashSet<String>,
   pub(crate) compliant: HashSet<String>,
}

#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct RuleReport<'value> {
    pub(crate) name: &'value str,
    pub(crate) metadata: Metadata,
    pub(crate) messages: Messages,
    pub(crate) checks: Vec<ClauseReport<'value>>
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryComparison<'value> {
   pub(crate) value: &'value PathAwareValue,
   pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValueUnResolved<'value> {
    pub(crate) value: UnResolved<'value>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug,Serialize)]
pub(crate) enum UnaryCheck<'value> {
    UnResolved(ValueUnResolved<'value>),
    Resolved(UnaryComparison<'value>),
    UnResolvedContext(String)
}

impl<'value> ValueComparisons<'value> for UnaryCheck<'value> {
    fn value_from(&self) -> Option<&'value PathAwareValue> {
        match self {
            UnaryCheck::UnResolved(ur) => Some(ur.value.traversed_to),
            UnaryCheck::Resolved(uc) => Some(uc.value),
            UnaryCheck::UnResolvedContext(_) => None,
        }
    }
}


#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryReport<'value> {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) check: UnaryCheck<'value>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BinaryComparison<'value> {
   pub(crate) from: &'value PathAwareValue,
   pub(crate) to: &'value PathAwareValue,
   pub(crate) comparison: (CmpOperator, bool)
}

#[derive(Clone, Debug,Serialize)]
pub(crate) enum BinaryCheck<'value> {
    UnResolved(ValueUnResolved<'value>),
    Resolved(BinaryComparison<'value>),
}

impl<'value> ValueComparisons<'value> for BinaryCheck<'value> {
    fn value_from(&self) -> Option<&'value PathAwareValue> {
        match self {
            BinaryCheck::UnResolved(vur) => Some(vur.value.traversed_to),
            BinaryCheck::Resolved(res) => Some(res.from),
        }
    }
}

#[derive(Clone, Debug,Serialize)]
pub(crate) struct BinaryReport<'value> {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) check: BinaryCheck<'value>,
}

#[derive(Clone, Debug,Serialize)]
pub(crate) enum GuardClauseReport<'value> {
    Unary(UnaryReport<'value>),
    Binary(BinaryReport<'value>),
}

pub(crate) trait ValueComparisons<'from> {
    fn value_from(&self) -> Option<&'from PathAwareValue>;
    fn value_to(&self) -> Option<&'from PathAwareValue> {
        None
    }
}

impl<'value> ValueComparisons<'value> for GuardClauseReport<'value> {
    fn value_from(&self) -> Option<&'value PathAwareValue> {
        match self {
            GuardClauseReport::Binary(br) => br.check.value_from(),
            GuardClauseReport::Unary(ur) => ur.check.value_from(),
        }
    }

    fn value_to(&self) -> Option<&'value PathAwareValue> {
        match self {
            GuardClauseReport::Binary(br) => br.check.value_to(),
            GuardClauseReport::Unary(ur) => ur.check.value_to(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DisjunctionsReport<'value> {
    pub(crate) checks: Vec<ClauseReport<'value>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct GuardBlockReport<'value> {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) unresolved: Option<UnResolved<'value>>,
}

impl<'value> ValueComparisons<'value> for GuardBlockReport<'value> {
    fn value_from(&self) -> Option<&'value PathAwareValue> {
        if let Some(ur) = &self.unresolved {
            return Some(ur.traversed_to)
        }
        None
    }
}

#[derive(Clone, Debug,Serialize)]
pub(crate) enum ClauseReport<'value> {
    Rule(RuleReport<'value>),
    Block(GuardBlockReport<'value>),
    Disjunctions(DisjunctionsReport<'value>),
    Clause(GuardClauseReport<'value>),
}

impl<'value> ClauseReport<'value> {
    pub(crate) fn is_rule(&self) -> bool {
        if let Self::Rule(_) = self { true } else { false }
    }

    pub(crate) fn is_block(&self) -> bool {
        if let Self::Block(_) = self { true } else { false }
    }

    pub(crate) fn is_disjunctions(&self) -> bool {
        if let Self::Disjunctions(_) = self { true } else { false }
    }

    pub(crate) fn is_clause(&self) -> bool {
        if let Self::Clause(_) = self { true } else { false }
    }

    pub(crate) fn rule(&self) -> Option<&RuleReport> {
        if let Self::Rule(rr) = self { Some(rr) } else { None }
    }

    pub(crate) fn block(&self) -> Option<&GuardBlockReport> {
        if let Self::Block(rr) = self { Some(rr) } else { None }
    }

    pub(crate) fn disjunctions(&self) -> Option<&DisjunctionsReport> {
        if let Self::Disjunctions(rr) = self { Some(rr) } else { None }
    }

    pub(crate) fn clause(&self) -> Option<&GuardClauseReport> {
        if let Self::Clause(gc) = self { Some(gc) } else { None }
    }

    pub(crate) fn key(&self, parent: &str) -> String {
        match self {
            Self::Rule(RuleReport{name, ..}) => format!("{}/{}", parent, name),
            Self::Block(_) => format!("{}/B[{:p}]", parent, self),
            Self::Disjunctions(_) => format!("{}/Or[{:p}]", parent, self),
            Self::Clause(_) => format!("{}/C[{:p}]", parent, self)
        }
    }
}

impl<'value> ValueComparisons<'value> for ClauseReport<'value> {
    fn value_from(&self) -> Option<&'value PathAwareValue> {
        match self {
            Self::Block(b) => b.value_from(),
            Self::Clause(c) => c.value_from(),
            _ => None
        }
    }

    fn value_to(&self) -> Option<&'value PathAwareValue> {
        match self {
            Self::Block(b) => b.value_to(),
            Self::Clause(c) => c.value_to(),
            _ => None
        }
    }
}


pub(crate) fn cmp_str(cmp: (CmpOperator, bool)) -> &'static str {
    let (cmp, not) = cmp;
    if cmp.is_unary() {
        match cmp {
            CmpOperator::Exists => if not { "NOT EXISTS" } else { "EXISTS" },
            CmpOperator::Empty => if not { "NOT EMPTY" } else { "EMPTY" },
            CmpOperator::IsList => if not { "NOT LIST" } else { "IS LIST" },
            CmpOperator::IsMap => if not { "NOT STRUCT" } else { "IS STRUCT" },
            CmpOperator::IsString => if not { "NOT STRING" } else { "IS STRING" }
            _ => unreachable!()
        }
    }
    else {
        match cmp {
            CmpOperator::Eq => if not { "NOT EQUAL" } else { "EQUAL" },
            CmpOperator::Le => if not { "NOT LESS THAN EQUAL" } else { "LESS THAN EQUAL" },
            CmpOperator::Lt => if not { "NOT LESS THAN" } else { "LESS THAN" },
            CmpOperator::Ge => if not { "NOT GREATER THAN EQUAL" } else { "GREATER THAN EQUAL" },
            CmpOperator::Gt => if not { "NOT GREATER THAN" } else { "GREATER THAN" },
            CmpOperator::In => if not { "NOT IN" } else { "IN" },
            _ => unreachable!()
        }
    }
}

fn report_all_failed_clauses_for_rules<'value>(checks: &[EventRecord<'value>]) -> Vec<ClauseReport<'value>> {
    let mut clauses = Vec::with_capacity(checks.len());
    for current in checks {
        match &current.container {
            Some(RecordType::RuleCheck(NamedStatus{name, status: Status::FAIL, message})) => {
                clauses.push(ClauseReport::Rule(RuleReport {
                    name: *name,
                    checks: report_all_failed_clauses_for_rules(&current.children),
                    messages: Messages {
                        custom_message: message.clone(),
                        error_message: None
                    },
                    ..Default::default()
                }));
            },

            Some(RecordType::BlockGuardCheck(BlockCheck{status: Status::FAIL, ..})) => {
                if current.children.is_empty() {
                    clauses.push(ClauseReport::Block(GuardBlockReport{
                        context: current.context.clone(),
                        messages: Messages {
                            error_message: Some(String::from("query for block clause did not retrieve any value")),
                            custom_message: None,
                        },
                        unresolved: None,
                    }));
                }
                else {
                    clauses.extend(report_all_failed_clauses_for_rules(&current.children));
                }
            },

            Some(RecordType::Disjunction(BlockCheck{status: Status::FAIL, ..})) => {
                clauses.push(ClauseReport::Disjunctions(DisjunctionsReport {
                    checks: report_all_failed_clauses_for_rules(&current.children)
                }));
            }

            Some(RecordType::GuardClauseBlockCheck(BlockCheck{status: Status::FAIL, ..}))       |
            Some(RecordType::TypeBlock(Status::FAIL)) |
            Some(RecordType::TypeCheck(TypeBlockCheck{block: BlockCheck{status: Status::FAIL, ..}, ..})) |
            Some(RecordType::WhenCheck(BlockCheck{status: Status::FAIL, ..})) => {
                clauses.extend(report_all_failed_clauses_for_rules(&current.children));
            },

            Some(RecordType::ClauseValueCheck(clause)) => {
                match clause {
                    ClauseCheck::NoValueForEmptyCheck(msg) => {
                        let custom_message = msg.as_ref()
                            .map_or("".to_string(),
                                    |s| format!("{}", s.replace("\n", ";")));

                        let error_message = format!(
                            "Check was not compliant as variable in context [{}] was not empty",
                            current.context
                        );
                        clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport {
                            context: current.context.clone(),
                            check: UnaryCheck::UnResolvedContext(current.context.to_string()),
                            messages: Messages {
                                custom_message: Some(custom_message),
                                error_message: Some(error_message),
                            }
                        })))
                    }

                    ClauseCheck::Success => {},

                    ClauseCheck::DependentRule(missing) => {
                        let message = missing.custom_message.as_ref()
                            .map_or("", String::as_str);
                        let error_message = format!(
                            "Check was not compliant as dependent rule [{rule}] did not PASS. Context [{cxt}]",
                            rule=missing.rule,
                            cxt=current.context,
                        );
                        clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport{
                            messages: Messages {
                                custom_message: Some(message.to_string()),
                                error_message: Some(error_message),
                            },
                            context: current.context.clone(),
                            check: UnaryCheck::UnResolvedContext(missing.rule.to_string()),
                        })));
                    },

                    ClauseCheck::MissingBlockValue(missing) => {
                        let (property, far, ur) = match &missing.from {
                            QueryResult::UnResolved(ur) => {
                                (ur.remaining_query.as_str(), ur.traversed_to, ur)
                            },
                            _ => unreachable!()
                        };
                        let message = missing.custom_message.as_ref()
                            .map_or("", String::as_str);
                        let error_message = format!(
                            "Check was not compliant as property [{}] is missing. Value traversed to [{}]",
                            property,
                            far
                        );
                        clauses.push(
                            ClauseReport::Block(GuardBlockReport{
                                context: current.context.clone(),
                                messages: Messages {
                                    custom_message: Some(message.to_string()),
                                    error_message: Some(error_message),
                                },
                                unresolved: Some(ur.clone())
                            })
                        );
                    },

                    ClauseCheck::Unary(
                        UnaryValueCheck{
                            comparison: (cmp, not),
                            value: ValueCheck{
                                status: Status::FAIL,
                                from,
                                message,
                                custom_message
                            }}) => {
                        let cmp_msg = match cmp {
                            CmpOperator::Exists => if *not { "existed" } else { "did not exist" },
                            CmpOperator::Empty => if *not { "was empty"} else { "was not empty" },
                            CmpOperator::IsList => if *not { "was a list " } else { "was not list" },
                            CmpOperator::IsMap => if *not { "was a struct" } else { "was not struct" },
                            CmpOperator::IsString => if *not { "was a string " } else { "was not string" },
                            _ => unreachable!()
                        };

                        let custom_message = custom_message.as_ref()
                            .map_or("".to_string(),
                                    |s| format!("{}", s.replace("\n", ";")));

                        let error_message = message.as_ref()
                            .map_or("".to_string(),
                                    |s| format!( "Error = [{}]", s));

                        let (message, check) = match from {
                            QueryResult::Literal(_) => unreachable!(),
                            QueryResult::Resolved(res) => {
                                (
                                    format!(
                                        "Check was not compliant as property [{prop}] {cmp_msg}.{err}",
                                        prop=res.self_path(),
                                        cmp_msg=cmp_msg,
                                        err=error_message
                                    ),
                                    UnaryCheck::Resolved(UnaryComparison {
                                        comparison: (*cmp, *not),
                                        value: *res,
                                    })
                                )

                            },

                            QueryResult::UnResolved(unres) => {
                                (
                                    format!(
                                        "Check was not compliant as property [{remain}] is missing. Value traversed to [{tr}].{err}",
                                        remain=unres.remaining_query,
                                        tr=unres.traversed_to,
                                        err=error_message
                                    ),
                                    UnaryCheck::UnResolved(ValueUnResolved{
                                        value: unres.clone(),
                                        comparison: (*cmp, *not),
                                    })
                                )
                            }
                        };

                        clauses.push(
                            ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport {
                                messages: Messages {
                                    custom_message: Some(custom_message),
                                    error_message: Some(message),
                                },
                                context: current.context.clone(),
                                check
                            }))
                        );
                    },


                    ClauseCheck::Comparison(
                        ComparisonClauseCheck{
                            custom_message,
                            message,
                            comparison: (cmp, not),
                            from,
                            status: Status::FAIL,
                            to
                        }) => {
                        let custom_message = custom_message.as_ref()
                            .map_or("".to_string(),
                                    |s| format!("{}", s.replace("\n", ";")));

                        let error_message = message.as_ref()
                            .map_or("".to_string(),
                                    |s| format!( " Error = [{}]", s));

                        match from {
                            QueryResult::Literal(_) => unreachable!(),
                            QueryResult::UnResolved(to_unres) => {
                                let message = format!(
                                    "Check was not compliant as property [{remain}] to compare from is missing. Value traversed to [{to}].{err}",
                                    remain=to_unres.remaining_query,
                                    to=to_unres.traversed_to,
                                    err=error_message
                                );
                                clauses.push(ClauseReport::Clause(
                                    GuardClauseReport::Binary(BinaryReport {
                                        context: current.context.to_string(),
                                        messages: Messages {
                                            custom_message: Some(custom_message),
                                            error_message: Some(message),
                                        },
                                        check: BinaryCheck::UnResolved(ValueUnResolved{
                                            comparison: (*cmp, *not),
                                            value: to_unres.clone()
                                        })
                                    })
                                ));
                            },

                            QueryResult::Resolved(res) => {
                                if let Some(to) = to {
                                    match to {
                                        QueryResult::Literal(_) => unreachable!(),
                                        QueryResult::Resolved(to_res) => {
                                            let message = format!(
                                                "Check was not compliant as property value [{from}] {op_msg} value [{to}].{err}",
                                                from=res,
                                                to=to_res,
                                                op_msg=match cmp {
                                                    CmpOperator::Eq => if *not { "equal to" } else { "not equal to" },
                                                    CmpOperator::Le => if *not { "less than equal to" } else { "less than equal to" },
                                                    CmpOperator::Lt => if *not { "less than" } else { "not less than" },
                                                    CmpOperator::Ge => if *not { "greater than equal to" } else { "not greater than equal" },
                                                    CmpOperator::Gt => if *not { "greater than" } else { "not greater than" },
                                                    CmpOperator::In => if *not { "in" } else { "not in" },
                                                    _ => unreachable!()
                                                },
                                                err=error_message
                                            );
                                            clauses.push(
                                                ClauseReport::Clause(
                                                    GuardClauseReport::Binary(BinaryReport {
                                                        check: BinaryCheck::Resolved(
                                                            BinaryComparison{
                                                                to: *to_res,
                                                                from: res,
                                                                comparison: (*cmp, *not),
                                                            }
                                                        ),
                                                        context: current.context.to_string(),
                                                        messages: Messages {
                                                            error_message: Some(message),
                                                            custom_message: Some(custom_message)
                                                        }
                                                    })
                                                )
                                            )

                                        },

                                        QueryResult::UnResolved(to_unres) => {
                                            let message = format!(
                                                "Check was not compliant as property [{remain}] to compare to is missing. Value traversed to [{to}].{err}",
                                                remain=to_unres.remaining_query,
                                                to=to_unres.traversed_to,
                                                err=error_message
                                            );
                                            clauses.push(ClauseReport::Clause(
                                                GuardClauseReport::Binary(BinaryReport {
                                                    context: current.context.to_string(),
                                                    messages: Messages {
                                                        custom_message: Some(custom_message),
                                                        error_message: Some(message),
                                                    },
                                                    check: BinaryCheck::UnResolved(ValueUnResolved{
                                                        comparison: (*cmp, *not),
                                                        value: to_unres.clone()
                                                    })
                                                })
                                            ));
                                        },
                                    }
                                }

                            }
                        }
                    },

                    _ => {}
                }
            }

            _ => {}
        }
    }
    clauses
}

pub(crate) fn simplifed_json_from_root<'value>(root: &EventRecord<'value>) -> Result<FileReport<'value>> {
    Ok(match &root.container {
        Some(file_status) => {
            match file_status {
                RecordType::FileCheck(NamedStatus{name, status, message}) => {
                    let mut pass = HashSet::with_capacity(root.children.len());
                    let mut skip = HashSet::with_capacity(root.children.len());
                    for each in &root.children {
                        if let Some(rule) = &each.container {
                            if let RecordType::RuleCheck(NamedStatus { status, message, name }) = rule {
                                match *status {
                                    Status::PASS => { pass.insert(name.to_string()); },
                                    Status::SKIP => { skip.insert(name.to_string()); },
                                    _ => {}
                                }
                            }
                        }
                    }
                    FileReport {
                        status: *status,
                        name: *name,
                        not_compliant: report_all_failed_clauses_for_rules(&root.children),
                        not_applicable: skip,
                        compliant: pass,
                        ..Default::default()
                    }
                },

                _ => unreachable!()
            }
        },

        None => unreachable!()
    })
}

#[cfg(test)]
#[path = "eval_context_tests.rs"]
pub(super) mod eval_context_tests;

