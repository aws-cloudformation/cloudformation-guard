use crate::rules::exprs::{RulesFile, AccessQuery, Rule, LetExpr, LetValue, QueryPart, SliceDisplay, Block, GuardClause, Conjunctions, ParameterizedRule};
use crate::rules::path_value::{PathAwareValue, MapValue, compare_eq};
use std::collections::HashMap;
use crate::rules::{QueryResult, Status, EvalContext, UnResolved, RecordType};
use crate::rules::Result;
use crate::rules::errors::{Error, ErrorKind};
use lazy_static::lazy_static;
use inflector::cases::*;
use crate::rules::eval::EvaluationResult::QueryValueResult;

pub(crate) struct Scope<'value, 'loc: 'value> {
    root: &'value PathAwareValue,
    //resolved_variables: std::cell::RefCell<HashMap<&'value str, Vec<QueryResult<'value>>>>,
    resolved_variables: HashMap<&'value str, Vec<QueryResult<'value>>>,
    literals: HashMap<&'value str, &'value PathAwareValue>,
    variable_queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
}

pub(crate) struct EventRecord<'value> {
    pub(crate) context: String,
    pub(crate) container: Option<RecordType<'value>>,
    pub(crate) children: Vec<EventRecord<'value>>,
}

pub(crate) struct RootScope<'value, 'loc: 'value> {
    scope: Scope<'value, 'loc>,
    rules: HashMap<&'value str, &'value Rule<'loc>>,
    rules_status: HashMap<&'value str, Status>,
    parameterized_rules: HashMap<&'value str, &'value ParameterizedRule<'loc>>,
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
        scope, rules, parameterized_rules, rules_status: HashMap::new()
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
            }
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
    for (index, each) in elements.iter().enumerate() {
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
                            if !map.is_empty() || query_index+1 < query.len() {
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

                _ => to_unresolved_result(
                    current,
                    format!("Filter on value type that was not a struct or array {} {}", current.type_info(), current.self_path()),
                    &query[query_index..])
            }
        },

        QueryPart::MapKeyFilter(_name, map_key_filter) => {
            match current {
                PathAwareValue::Map((_path, map)) => {
                    let mut selected = Vec::with_capacity(map.values.len());
                    let (rhs, is_literal) = match &map_key_filter.compare_with {
                        LetValue::AccessClause(acc_query) => {
                            let values = query_retrieval_with_converter(0, &acc_query.query, current, resolver, converter)?;
                            (values, false)
                        },

                        LetValue::Value(path_value) => {
                            (vec![QueryResult::Resolved(path_value)], true)
                        }
                    };

                    let lhs = map.keys.iter().map(|p| QueryResult::Resolved(p))
                        .collect::<Vec<QueryResult<'_>>>();

                    let results = super::eval::real_binary_operation(
                        &lhs,
                        &rhs,
                        is_literal,
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
        lookup_cache.insert(rule.rule_name.as_str(), rule);
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
    lookup_cache: HashMap<&'value str, &'value Rule<'loc>>,
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
        rules_status: HashMap::new()
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

pub(crate) struct RecordTracker<'eval, 'value, 'loc: 'value> {
//    pub(crate) events: std::cell::RefCell<Vec<EventRecord<'value>>>,
//    pub(crate) final_event: std::cell::RefCell<Option<EventRecord<'value>>>,
    pub(crate) events: Vec<EventRecord<'value>>,
    pub(crate) final_event: Option<EventRecord<'value>>,
    pub(crate) parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

impl<'eval, 'value, 'loc: 'value> RecordTracker<'eval, 'value, 'loc> {
    pub(crate) fn new<'e, 'v, 'l: 'v>(parent: &'e mut dyn EvalContext<'v, 'l>) -> RecordTracker<'e, 'v, 'l> {
        RecordTracker {
            parent,
            events: Vec::new(),
            final_event: None
        }
    }

    pub(crate) fn extract(mut self) -> EventRecord<'value> {
        self.final_event.take().unwrap()
    }
}

impl<'eval, 'value, 'loc: 'value> EvalContext<'value, 'loc> for RecordTracker<'eval, 'value, 'loc> {
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        self.parent.query(query)
    }

    fn find_parameterized_rule(&mut self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> &'value PathAwareValue {
        self.parent.root()
    }



    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

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


    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        self.parent.resolve_variable(variable_name)
    }

    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
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
            Some(rule) => *rule,
            None => return Err(Error::new(ErrorKind::MissingValue(
                format!("Rule {} by that name does not exist, Rule Names = {:?}",
                        rule_name, self.rules.keys()))))
        };

        let status = super::eval::eval_rule(rule, self)?;
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

    fn start_record(&mut self, _context: &str) -> Result<()> { Ok(()) }

    fn end_record(&mut self, _context: &str, _record: RecordType<'value>) -> Result<()> {
        Ok(())
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Resolved(*val)])
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

    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }


    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        self.parent.resolve_variable(variable_name)
    }

    fn add_variable_capture_key(&mut self, variable_name: &'value str, key: &'value PathAwareValue) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
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

    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult<'value>>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Resolved(*val)])
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

#[cfg(test)]
#[path = "eval_context_tests.rs"]
pub(super) mod eval_context_tests;

