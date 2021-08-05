use crate::rules::exprs::{RulesFile, AccessQuery, Rule, LetExpr, LetValue, QueryPart, SliceDisplay, Block, GuardClause, Conjunctions, ParameterizedRule};
use crate::rules::path_value::{PathAwareValue, MapValue, compare_eq};
use std::collections::HashMap;
use crate::rules::{QueryResult, Status, EvalContext, UnResolved, RecordType};
use crate::rules::path_value::Path;
use crate::rules::Result;
use std::convert::TryFrom;
use crate::rules::errors::{Error, ErrorKind};

pub(crate) struct Scope<'value, 'loc: 'value> {
    root: &'value PathAwareValue,
    resolved_variables: std::cell::RefCell<HashMap<&'value str, Vec<QueryResult<'value>>>>,
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
        resolved_variables: std::cell::RefCell::new(HashMap::new()),
        literals: literals,
        variable_queries: variables
    };
    RootScope {
        scope, rules, parameterized_rules
    }
}

pub(crate) struct BlockScope<'value, 'loc: 'value, 'eval> {
    scope: Scope<'value, 'loc>,
    parent: &'eval dyn EvalContext<'value, 'loc>,
}

pub(crate) struct ValueScope<'value, 'eval, 'loc: 'value> {
    pub(crate) root: &'value PathAwareValue,
    pub(crate) parent: &'eval dyn EvalContext<'value, 'loc>,
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

fn accumulate<'value, 'loc: 'value>(parent: &'value PathAwareValue,
                      query_index: usize,
                      query: &'value [QueryPart<'loc>],
                      elements: &'value Vec<PathAwareValue>,
                      resolver: &dyn EvalContext<'value, 'loc>)
    -> Result<Vec<QueryResult<'value>>> {
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
    for each in elements {
        accumulated.extend(query_retrieval(query_index+1, query, each, resolver)?);
    }
    Ok(accumulated)

}

fn accumulate_map<'value, 'loc: 'value, F>(
    parent: &'value PathAwareValue,
    map: &'value MapValue,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    resolver: &dyn EvalContext<'value, 'loc>,
    func: F) -> Result<Vec<QueryResult<'value>>>
    where F: Fn(usize, &'value [QueryPart<'loc>], &'value PathAwareValue, &dyn EvalContext<'value, 'loc>) -> Result<Vec<QueryResult<'value>>>
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

    let values: Vec<&PathAwareValue> = map.values.values().collect();
    let mut resolved = Vec::with_capacity(values.len());
    for each in values {
        let val_resolver = ValueScope{ root: each, parent: resolver };
        resolved.extend(
            func(query_index+1, query, each, &val_resolver)?)
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

fn check_and_delegate<'value, 'loc: 'value>(conjunctions: &'value Conjunctions<GuardClause<'loc>>)
    -> impl Fn(usize, &'value[QueryPart<'loc>], &'value PathAwareValue, &dyn EvalContext<'value, 'loc>) -> Result<Vec<QueryResult<'value>>>
{
    move |index, query, value, eval_context| {
        let context = format!("Filter/Map#{}", conjunctions.len());
        eval_context.start_record(&context)?;
        match super::eval::eval_conjunction_clauses(
            conjunctions, eval_context, super::eval::eval_guard_clause) {
            Ok(status) => {
                eval_context.end_record(&context, RecordType::Filter(status))?;
                match status {
                    Status::PASS => {
                        query_retrieval(index, query, value, eval_context)
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

fn query_retrieval<'value, 'loc: 'value>(
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    current: &'value PathAwareValue,
    resolver: &dyn EvalContext<'value, 'loc>) -> Result<Vec<QueryResult<'value>>> {

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
                        match query[query_index+1] {
                            QueryPart::AllIndices => query_index+2,
                            _ => query_index+1
                        }
                    } else { query_index+1 };
                    let scope = ValueScope { root: value, parent: resolver };
                    resolved.extend(query_retrieval(index, query, value, &scope)?);
                }
            }
        }
        return Ok(resolved)
    }

    match &query[query_index] {
        QueryPart::This => {
            query_retrieval(query_index+1, query, current, resolver)
        },

        QueryPart::Key(key) => {
            match key.parse::<i32>() {
                Ok(idx) => {
                    match current {
                        PathAwareValue::List((_, list)) => {
                            map_resolved(current,
                                         retrieve_index(current, idx, list, query),
                                         |val| query_retrieval(query_index+1, query, val, resolver))
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
                                match query[query_index+1] {
                                    QueryPart::AllIndices | QueryPart::Key(_) => keys,
                                    QueryPart::Index(index) => {
                                        let check = if index >= 0 { index } else { -index } as usize;
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
                                                acc.extend(query_retrieval(query_index+1, query, next, resolver)?);
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
                        } else if let Some(val) = map.values.get(key) {
                            query_retrieval(query_index+1, query, val, resolver)
                        } else {
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
                                 |val| query_retrieval(query_index+1, query, val, resolver))
                }

                _ =>
                    to_unresolved_result(
                        current,
                        format!("Attempting to retrieve from index {} but type is not an array at path {}", index, current.self_path()),
                        &query[query_index..])
            }
        },

        QueryPart::AllIndices => {
            match current {
                PathAwareValue::List((_path, elements)) => {
                    accumulate(current, query_index, query, elements, resolver)
                },

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => {
                    query_retrieval(query_index+1, query, rest, resolver)
                }
            }
        },

        QueryPart::AllValues => {
            match current {
                //
                // Supporting old format
                //
                PathAwareValue::List((_path, elements)) => {
                    accumulate(current, query_index, query, elements, resolver)
                },

                PathAwareValue::Map((_path, map)) => {
                    accumulate_map(current, map, query_index, query, resolver, query_retrieval)
                },

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => {
                    query_retrieval(query_index+1, query, rest, resolver)
                }
            }
        },

        QueryPart::Filter(conjunctions) => {
            match current {
                PathAwareValue::Map((_path, map)) => {
                    match query[query_index-1] {
                        QueryPart::AllValues |
                        QueryPart::AllIndices => {
                            check_and_delegate(conjunctions)(query_index+1, query, current, resolver)
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
//                                        Status::PASS => query_retrieval(index+1, query, current, resolver),
//                                        _ => Ok(vec![])
//                                    }
//                                })
                            accumulate_map(
                                current, map, query_index, query, resolver, check_and_delegate(conjunctions)
                            )
                        },

                        _ => unreachable!()
                    }
                },

                PathAwareValue::List((_path, list)) => {
                    let mut selected = Vec::with_capacity(list.len());
                    for each in list {
                        let context = format!("Filter/List#{}", conjunctions.len());
                        resolver.start_record(&context)?;
                        let val_resolver = ValueScope { root: each, parent: resolver };
                        let result = match super::eval::eval_conjunction_clauses(
                            conjunctions, &val_resolver, super::eval::eval_guard_clause) {
                            Ok(status) => {
                                resolver.end_record(&context, RecordType::Filter(status))?;
                                match status {
                                    Status::PASS => {
                                        query_retrieval(query_index + 1, query, each, resolver)?
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

        QueryPart::MapKeyFilter(map_key_filter) => {
            match current {
                PathAwareValue::Map((_path, map)) => {
                    let mut selected = Vec::with_capacity(map.values.len());
                    match &map_key_filter.compare_with {
                        LetValue::AccessClause(acc_query) => {
                            let values = query_retrieval(0, &acc_query.query, current, resolver)?;
                            let values = {
                                let mut collected = Vec::with_capacity(values.len());
                                for each_value in values {
                                    match each_value {
                                        QueryResult::UnResolved(ur) => {
                                            selected.push(
                                                    to_unresolved_value(current,
                                                                         format!("Access query retrieved value was unresolved at path {} for reason {}",
                                                                                 ur.traversed_to.self_path(), match ur.reason { Some(r) => r, None => "".to_string() }),
                                                                         &query[query_index..]
                                                    ));
                                        },

                                        QueryResult::Resolved(val) => {
                                            collected.push(val);
                                        }
                                    }
                                }
                                collected
                            };
                            for each_key in &map.keys {
                                if values.contains(&each_key) {
                                    match each_key {
                                        PathAwareValue::String((_, v)) => {
                                            selected.push(QueryResult::Resolved(map.values.get(v).unwrap()));
                                        },
                                        _ => unreachable!()
                                    }
                                }
                            }
                        },

                        LetValue::Value(path_value) => {
                            for key in map.keys.iter() {
                                if compare_eq(key, path_value)? {
                                    match key {
                                        PathAwareValue::String((_, v)) => {
                                            selected.push(QueryResult::Resolved(map.values.get(v).unwrap()));
                                        },
                                        _ => unreachable!()
                                    }
                                }
                            }
                        }
                    }
                    let mut extended = Vec::with_capacity(selected.len());
                    for each in selected {
                        match each {
                            QueryResult::Resolved(r) => {
                                extended.extend(
                                    query_retrieval(query_index+1, query, r, resolver)?
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
            resolved_variables: std::cell::RefCell::new(HashMap::new()),
        },
        rules: lookup_cache,
        parameterized_rules,
    })
}

pub(crate) fn block_scope<'value, 'block, 'loc: 'value, 'eval, T>(
    block: &'value Block<'loc, T>,
    root: &'value PathAwareValue,
    parent: &'eval dyn EvalContext<'value, 'loc>) -> Result<BlockScope<'value, 'loc, 'eval>> {

    let (literals, variable_queries) =
        extract_variables(&block.assignments)?;
    Ok(BlockScope {
        scope: Scope {
            literals,
            variable_queries,
            root,
            resolved_variables: std::cell::RefCell::new(HashMap::new()),
        },
        parent
    })
}

impl<'value, 'loc: 'value> Scope<'value, 'loc> {
    fn resolve(&self, variable_name: &str, eval: &dyn EvalContext<'value, 'loc>) -> Result<Option<Vec<QueryResult<'value>>>> {
        if let Some(val) = self.literals.get(variable_name) {
            return Ok(Some(vec![QueryResult::Resolved(*val)]))
        }

        if let Some(values) = self.resolved_variables.borrow().get(variable_name) {
            return Ok(Some(values.clone()))
        }

        if let Some((key, query)) = self.variable_queries.get_key_value(variable_name) {
            let result = query_retrieval(0, &query.query, eval.root(), eval)?;
            let result = if !query.match_all {
                result.into_iter().filter(|q| matches!(q, QueryResult::Resolved(_))).collect()
            } else { result };
            self.resolved_variables.borrow_mut().insert(*key, result.clone());
            return Ok(Some(result))
        }

        Ok(None)
    }
}

pub(crate) struct RecordTracker<'eval, 'value, 'loc: 'value> {
    pub(crate) events: std::cell::RefCell<Vec<EventRecord<'value>>>,
    pub(crate) final_event: std::cell::RefCell<Option<EventRecord<'value>>>,
    pub(crate) parent: &'eval dyn EvalContext<'value, 'loc>,
}

impl<'eval, 'value, 'loc: 'value> RecordTracker<'eval, 'value, 'loc> {
    pub(crate) fn new<'e, 'v, 'l: 'v>(parent: &'e dyn EvalContext<'v, 'l>) -> RecordTracker<'e, 'v, 'l> {
        RecordTracker {
            parent,
            events: std::cell::RefCell::new(Vec::new()),
            final_event: std::cell::RefCell::new(None)
        }
    }

    pub(crate) fn extract(self) -> EventRecord<'value> {
        self.final_event.take().unwrap()
    }
}

impl<'eval, 'value, 'loc: 'value> EvalContext<'value, 'loc> for RecordTracker<'eval, 'value, 'loc> {
    fn query(&self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        self.parent.query(query)
    }

    fn find_parameterized_rule(&self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&self) -> &'value PathAwareValue {
        self.parent.root()
    }



    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn start_record(&self, context: &str) -> Result<()> {
        self.events.borrow_mut().push(EventRecord {
            context: context.to_string(),
            container: None,
            children: vec![]
        });
        Ok(())
    }

    fn end_record(&self, context: &str, record: RecordType<'value>) -> Result<()> {
        let matched = match self.events.borrow_mut().pop() {
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

        match self.events.borrow_mut().last_mut() {
            Some(parent) => {
                parent.children.push(matched);
            },

            None => {
                self.final_event.borrow_mut().replace(matched);
            }
        }
        Ok(())
    }


    fn resolve_variable(&self, variable_name: &str) -> Result<Vec<QueryResult<'value>>> {
        self.parent.resolve_variable(variable_name)
    }

}

impl<'value, 'loc: 'value> EvalContext<'value, 'loc> for RootScope<'value, 'loc> {

    fn query(&self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.scope.root, self)
    }

    fn find_parameterized_rule(&self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        match self.parameterized_rules.get(rule_name) {
            Some(r) => Ok(*r),
            _ => Err(Error::new(ErrorKind::MissingValue(
                format!("Parameterized Rule with name {} was not found, candiate {:?}",
                        rule_name, self.parameterized_rules.keys())
            )))
        }
    }


    fn root(&self) -> &'value PathAwareValue {
        self.scope.root
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.rules.get(rule_name).map_or_else(
            || Err(Error::new(ErrorKind::MissingValue(
                format!("Rule {} by that name does not exist, Rule Names = {:?}",
                        rule_name, self.rules.keys())
            ))),
            |rule| super::eval::eval_rule(*rule, self)
        )
    }

    fn start_record(&self, _context: &str) -> Result<()> { Ok(()) }

    fn end_record(&self, _context: &str, _record: RecordType<'value>) -> Result<()> {
        Ok(())
    }


    fn resolve_variable(&self, variable_name: &str) -> Result<Vec<QueryResult<'value>>> {
        match self.scope.resolve(variable_name, self) {
            Ok(Some(ret)) => Ok(ret),
            Ok(None) => Err(Error::new(ErrorKind::MissingValue(
                format!("Could not resolve variable by name {} across scopes", variable_name)
            ))),
            Err(e) => Err(e),
        }
    }
}

impl<'value, 'loc: 'value, 'eval> EvalContext<'value, 'loc> for ValueScope<'value, 'eval, 'loc> {
    fn query(&self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.root, self.parent)
    }

    fn find_parameterized_rule(&self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }


    fn root(&self) -> &'value PathAwareValue {
        self.root
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn start_record(&self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }


    fn resolve_variable(&self, variable_name: &str) -> Result<Vec<QueryResult<'value>>> {
        self.parent.resolve_variable(variable_name)
    }
}

impl<'value, 'loc: 'value, 'eval> EvalContext<'value, 'loc> for BlockScope<'value, 'loc, 'eval> {
    fn query(&self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult<'value>>> {
        query_retrieval(0, query, self.scope.root, self)
    }

    fn find_parameterized_rule(&self, rule_name: &str) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }


    fn root(&self) -> &'value PathAwareValue {
        self.scope.root
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn start_record(&self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }

    fn resolve_variable(&self, variable_name: &str) -> Result<Vec<QueryResult<'value>>> {
        match self.scope.resolve(variable_name, self) {
            Ok(Some(ret)) => Ok(ret),
            Ok(None) => self.parent.resolve_variable(variable_name),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
#[path = "eval_context_tests.rs"]
pub(super) mod eval_context_tests;

