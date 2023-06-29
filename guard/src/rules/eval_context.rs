use crate::rules::errors::Error;
use crate::rules::exprs::{
    AccessQuery, Block, Conjunctions, FunctionExpr, GuardClause, LetExpr, LetValue,
    ParameterizedRule, QueryPart, Rule, RulesFile, SliceDisplay,
};
use crate::rules::functions::collections::count;
use crate::rules::functions::strings::{
    join, json_parse, regex_replace, substring, to_lower, to_upper, url_decode,
};
use crate::rules::path_value::{MapValue, PathAwareValue};
use crate::rules::values::CmpOperator;
use crate::rules::Result;
use crate::rules::Status::SKIP;
use crate::rules::{
    BlockCheck, ClauseCheck, ComparisonClauseCheck, EvalContext, InComparisonCheck, NamedStatus,
    QueryResult, RecordTracer, RecordType, Status, TypeBlockCheck, UnResolved, UnaryValueCheck,
    ValueCheck,
};
use inflector::cases::*;
use lazy_static::lazy_static;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap};
use std::rc::Rc;

pub(crate) struct Scope<'value, 'loc: 'value> {
    root: Rc<PathAwareValue>,
    resolved_variables: HashMap<&'value str, Vec<QueryResult>>,
    literals: HashMap<&'value str, Rc<PathAwareValue>>,
    variable_queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
    function_expressions: HashMap<&'value str, &'value FunctionExpr<'loc>>,
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
    #[cfg(test)]
    pub fn reset_root(self, new_root: Rc<PathAwareValue>) -> Result<RootScope<'value, 'loc>> {
        root_scope_with(
            self.scope.literals,
            self.scope.variable_queries,
            self.rules,
            self.parameterized_rules,
            self.scope.function_expressions,
            new_root,
        )
    }

    pub(crate) fn reset_recorder(&mut self) -> RecordTracker<'value> {
        std::mem::replace(
            &mut self.recorder,
            RecordTracker {
                final_event: None,
                events: vec![],
            },
        )
    }
}

pub(crate) struct BlockScope<'value, 'loc: 'value, 'eval> {
    scope: Scope<'value, 'loc>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

pub(crate) struct ValueScope<'value, 'eval, 'loc: 'value> {
    pub(crate) root: Rc<PathAwareValue>,
    pub(crate) parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

type ExtractVariableResult<'value, 'loc> = Result<(
    HashMap<&'value str, Rc<PathAwareValue>>,
    HashMap<&'value str, &'value AccessQuery<'loc>>,
    HashMap<&'value str, &'value FunctionExpr<'loc>>,
)>;

fn extract_variables<'value, 'loc: 'value>(
    expressions: &'value Vec<LetExpr<'loc>>,
) -> ExtractVariableResult<'value, 'loc> {
    let mut literals = HashMap::with_capacity(expressions.len());
    let mut queries = HashMap::with_capacity(expressions.len());
    let mut functions = HashMap::with_capacity(expressions.len());
    for each in expressions {
        match &each.value {
            LetValue::Value(v) => {
                literals.insert(each.var.as_str(), Rc::new(v.clone()));
            }

            LetValue::AccessClause(query) => {
                queries.insert(each.var.as_str(), query);
            }
            LetValue::FunctionCall(function) => {
                functions.insert(each.var.as_str(), function);
            }
        }
    }

    Ok((literals, queries, functions))
}

fn retrieve_index(
    parent: Rc<PathAwareValue>,
    index: i32,
    elements: &Vec<PathAwareValue>,
    query: &[QueryPart<'_>],
) -> QueryResult {
    let check = if index >= 0 { index } else { -index } as usize;
    if check < elements.len() {
        QueryResult::Resolved(Rc::new(elements[check].clone()))
    } else {
        QueryResult::UnResolved(
            UnResolved {
                traversed_to: Rc::clone(&parent),
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
    parent: Rc<PathAwareValue>,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    elements: &[PathAwareValue],
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<QueryResult>> {
    //
    // We are here when we are doing [*] for a list. It is an error if there are no
    // elements
    //
    if elements.is_empty() {
        return to_unresolved_result(
            Rc::clone(&parent),
            format!(
                "No more entries for value at path = {} on type = {} ",
                parent.self_path(),
                parent.type_info()
            ),
            &query[query_index..],
        );
    }

    let mut accumulated = Vec::with_capacity(elements.len());
    for (_index, each) in elements.iter().enumerate() {
        accumulated.extend(query_retrieval_with_converter(
            query_index + 1,
            query,
            Rc::new(each.clone()),
            resolver,
            converter,
        )?);
    }
    Ok(accumulated)
}

fn accumulate_map<'value, 'loc: 'value, F>(
    parent: Rc<PathAwareValue>,
    map: &MapValue,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
    func: F,
) -> Result<Vec<QueryResult>>
where
    F: Fn(
        usize,
        &'value [QueryPart<'loc>],
        Rc<PathAwareValue>,
        Rc<PathAwareValue>,
        &mut dyn EvalContext<'value, 'loc>,
        Option<&dyn Fn(&str) -> String>,
    ) -> Result<Vec<QueryResult>>,
{
    //
    // We are here when we are doing * all values for map. It is an error if there are no
    // elements in the map
    //
    if map.is_empty() {
        return to_unresolved_result(
            Rc::clone(&parent),
            format!(
                "No more entries for value at path = {} on type = {} ",
                parent.self_path(),
                parent.type_info()
            ),
            &query[query_index..],
        );
    }

    let mut resolved = Vec::with_capacity(map.values.len());

    for (key, each) in map.keys.iter().zip(map.values.values()) {
        let mut val_resolver = ValueScope {
            root: Rc::new(each.clone()),
            parent: resolver,
        };
        resolved.extend(func(
            query_index + 1,
            query,
            Rc::new(key.clone()),
            Rc::new(each.clone()),
            &mut val_resolver,
            converter,
        )?)
    }

    Ok(resolved)
}

fn to_unresolved_value(
    current: Rc<PathAwareValue>,
    reason: String,
    query: &[QueryPart<'_>],
) -> QueryResult {
    QueryResult::UnResolved(UnResolved {
        traversed_to: Rc::clone(&current),
        reason: Some(reason),
        remaining_query: format!("{}", SliceDisplay(query)),
    })
}

fn to_unresolved_result(
    current: Rc<PathAwareValue>,
    reason: String,
    query: &[QueryPart],
) -> Result<Vec<QueryResult>> {
    Ok(vec![to_unresolved_value(current, reason, query)])
}

fn map_resolved<F>(
    _current: &PathAwareValue,
    query_result: QueryResult,
    func: F,
) -> Result<Vec<QueryResult>>
where
    F: FnOnce(Rc<PathAwareValue>) -> Result<Vec<QueryResult>>,
{
    match query_result {
        QueryResult::Resolved(res) => func(res),
        rest => Ok(vec![rest]),
    }
}

fn check_and_delegate<'value, 'loc: 'value>(
    conjunctions: &'value Conjunctions<GuardClause<'loc>>,
    name: &'value Option<String>,
) -> impl Fn(
    usize,
    &'value [QueryPart<'loc>],
    Rc<PathAwareValue>,
    Rc<PathAwareValue>,
    &mut dyn EvalContext<'value, 'loc>,
    Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<QueryResult>> {
    move |index, query, key, value, eval_context, converter| {
        let context = format!("Filter/Map#{}", conjunctions.len());
        eval_context.start_record(&context)?;
        match super::eval::eval_conjunction_clauses(
            conjunctions,
            eval_context,
            super::eval::eval_guard_clause,
        ) {
            Ok(status) => {
                eval_context.end_record(&context, RecordType::Filter(status))?;
                if let Some(key_name) = name {
                    if status == Status::PASS {
                        eval_context
                            .add_variable_capture_key(key_name.as_ref(), Rc::clone(&key))?;
                    }
                }
                match status {
                    Status::PASS => query_retrieval_with_converter(
                        index,
                        query,
                        Rc::clone(&value),
                        eval_context,
                        converter,
                    ),
                    _ => Ok(vec![]),
                }
            }

            Err(e) => {
                eval_context.end_record(&context, RecordType::Filter(Status::FAIL))?;
                Err(e)
            }
        }
    }
}

type Converters = &'static [(fn(&str) -> bool, fn(&str) -> String)];
lazy_static! {
    #[allow(clippy::type_complexity)]
    static ref CONVERTERS: Converters = &[
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
    current: Rc<PathAwareValue>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<QueryResult>> {
    query_retrieval_with_converter(query_index, query, current, resolver, None)
}

fn query_retrieval_with_converter<'value, 'loc: 'value>(
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    current: Rc<PathAwareValue>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<QueryResult>> {
    if query_index >= query.len() {
        return Ok(vec![QueryResult::Resolved(Rc::clone(&current))]);
    }

    if query_index == 0 && query[query_index].is_variable() {
        let retrieved = resolver.resolve_variable(query[query_index].variable().unwrap())?;
        let mut resolved = Vec::with_capacity(retrieved.len());
        for each in retrieved {
            match &each {
                QueryResult::UnResolved(ur) => {
                    resolved.push(QueryResult::UnResolved(ur.clone()));
                }
                QueryResult::Literal(value) | QueryResult::Resolved(value) => {
                    let index = if query_index + 1 < query.len() {
                        match &query[query_index + 1] {
                            QueryPart::AllIndices(_name) => query_index + 2,
                            _ => query_index + 1,
                        }
                    } else {
                        query_index + 1
                    };

                    if index < query.len() {
                        let mut scope = ValueScope {
                            root: Rc::clone(value),
                            parent: resolver,
                        };
                        resolved.extend(query_retrieval_with_converter(
                            index,
                            query,
                            Rc::clone(value),
                            &mut scope,
                            converter,
                        )?);
                    } else {
                        resolved.push(each)
                    }
                }
            }
        }
        return Ok(resolved);
    }

    match &query[query_index] {
        QueryPart::This => {
            query_retrieval_with_converter(query_index + 1, query, current, resolver, converter)
        }

        QueryPart::Key(key) => match key.parse::<i32>() {
            Ok(idx) => match &*current {
                PathAwareValue::List((_, list)) => map_resolved(
                    &current,
                    retrieve_index(Rc::clone(&current), idx, list, query),
                    |val| {
                        query_retrieval_with_converter(
                            query_index + 1,
                            query,
                            val,
                            resolver,
                            converter,
                        )
                    },
                ),

                _ => to_unresolved_result(
                    Rc::clone(&current),
                    format!(
                        "Attempting to retrieve from index {} but type is not an array at path {}",
                        idx,
                        (*current).self_path()
                    ),
                    query,
                ),
            },

            Err(_) => {
                if let PathAwareValue::Map((path, map)) = &*current {
                    if query[query_index].is_variable() {
                        let var = query[query_index].variable().unwrap();
                        let keys = resolver.resolve_variable(var)?;
                        let keys = if query.len() > query_index + 1 {
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

                                    _ => return Err(Error::IncompatibleError(
                                        format!("This type of query {} based variable interpolation is not supported {}, {}",
                                                query[1], current.type_info(), SliceDisplay(query))))
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
                                                Rc::clone(&current),
                                                format!("Keys returned for variable {} could not completely resolve. Path traversed until {}{}",
                                                        var, ur.traversed_to.self_path(), ur.reason.map_or("".to_string(), |msg| msg)
                                                ),
                                                &query[query_index..]
                                            )?
                                        );
                                }
                                QueryResult::Resolved(key) | QueryResult::Literal(key) => {
                                    if let PathAwareValue::String((_, k)) = &*key {
                                        if let Some(next) = map.values.get(k) {
                                            acc.extend(query_retrieval_with_converter(
                                                query_index + 1,
                                                query,
                                                Rc::new(next.clone()),
                                                resolver,
                                                converter,
                                            )?);
                                        } else {
                                            acc.extend(
                                                    to_unresolved_result(
                                                Rc::clone(&current),
                                                        format!("Could not locate key = {} inside struct at path = {}", k, path),
                                                        &query[query_index..]
                                                    )?
                                                );
                                        }
                                    } else if let PathAwareValue::List((_, inner)) = &*key {
                                        for each_key in inner {
                                            match &each_key {
                                                    PathAwareValue::String((path, key_to_match)) => {
                                                        if let Some(next) = map.values.get(key_to_match) {
                                                            acc.extend(query_retrieval_with_converter(query_index + 1, query, Rc::new(next.clone()), resolver, converter)?);
                                                        } else {
                                                            acc.extend(
                                                                to_unresolved_result(
                                                                Rc::clone(&current),
                                                                    format!("Could not locate key = {} inside struct at path = {}", key_to_match, path),
                                                                    &query[query_index..]
                                                                )?
                                                            );
                                                        }
                                                    },

                                                    _rest => {
                                                        return Err(Error
                                                            ::NotComparable(
                                                                format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                                        SliceDisplay(query),
                                                                        key.type_info(),
                                                                        key.self_value()
                                                                )

                                                        ))
                                                    }
                                                }
                                        }
                                    } else {
                                        return Err(Error
                                               ::NotComparable(
                                                    format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                            SliceDisplay(query),
                                                            key.type_info(),
                                                            key.self_value()
                                                    )

                                            ));
                                    }
                                }
                            }
                        }
                        Ok(acc)
                    } else {
                        match map.values.get(key) {
                            Some(val) => {
                                return query_retrieval_with_converter(
                                    query_index + 1,
                                    query,
                                    Rc::new(val.clone()),
                                    resolver,
                                    converter,
                                )
                            }

                            None => match converter {
                                Some(func) => {
                                    let converted = func(key.as_str());
                                    if let Some(val) = map.values.get(&converted) {
                                        return query_retrieval_with_converter(
                                            query_index + 1,
                                            query,
                                            Rc::new(val.clone()),
                                            resolver,
                                            converter,
                                        );
                                    }
                                }

                                None => {
                                    for (_, each_converter) in CONVERTERS.iter() {
                                        if let Some(val) =
                                            map.values.get(&each_converter(key.as_str()))
                                        {
                                            return query_retrieval_with_converter(
                                                query_index + 1,
                                                query,
                                                Rc::new(val.clone()),
                                                resolver,
                                                Some(each_converter),
                                            );
                                        }
                                    }
                                }
                            },
                        }

                        to_unresolved_result(
                            Rc::clone(&current),
                            format!("Could not find key {} inside struct at path {}", key, path),
                            &query[query_index..],
                        )
                    }
                } else {
                    to_unresolved_result(
                            Rc::clone(&current),
                            format!("Attempting to retrieve from key {} but type is not an struct type at path {}, Type = {}, Value = {:?}",
                                    key, current.self_path(), current.type_info(), current),
                            &query[query_index..])
                }
            }
        },

        QueryPart::Index(index) => match &*current {
            PathAwareValue::List((_, list)) => map_resolved(
                &current,
                retrieve_index(Rc::clone(&current), *index, list, query),
                |val| {
                    query_retrieval_with_converter(query_index + 1, query, val, resolver, converter)
                },
            ),

            _ => to_unresolved_result(
                Rc::clone(&current),
                format!(
                    "Attempting to retrieve from index {} but type is not an array at path {}, \
                    type {}",
                    index,
                    current.self_path(),
                    current.type_info()
                ),
                &query[query_index..],
            ),
        },

        QueryPart::AllIndices(name) => {
            match &*current {
                PathAwareValue::List((_, elements)) => accumulate(
                    Rc::clone(&current),
                    query_index,
                    query,
                    elements,
                    resolver,
                    converter,
                ),

                PathAwareValue::Map((_, map)) => {
                    if name.is_none() {
                        query_retrieval_with_converter(
                            query_index + 1,
                            query,
                            Rc::clone(&current),
                            resolver,
                            converter,
                        )
                    } else {
                        let name = name.as_ref().unwrap().as_str();
                        accumulate_map(
                            Rc::clone(&current),
                            map,
                            query_index,
                            query,
                            resolver,
                            converter,
                            |index, query, key, value, context, converter| {
                                context.add_variable_capture_key(name, Rc::clone(&key))?;
                                query_retrieval_with_converter(
                                    index,
                                    query,
                                    Rc::clone(&value),
                                    context,
                                    converter,
                                )
                            },
                        )
                    }
                }

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => query_retrieval_with_converter(
                    query_index + 1,
                    query,
                    Rc::new(rest.clone()),
                    resolver,
                    converter,
                ),
            }
        }

        QueryPart::AllValues(name) => {
            match &*current {
                //
                // Supporting old format
                //
                PathAwareValue::List((_path, elements)) => accumulate(
                    Rc::clone(&current),
                    query_index,
                    query,
                    elements,
                    resolver,
                    converter,
                ),

                PathAwareValue::Map((_path, map)) => {
                    let (report, name) = match name {
                        Some(n) => (true, n.as_str()),
                        None => (false, ""),
                    };
                    accumulate_map(
                        Rc::clone(&current),
                        map,
                        query_index,
                        query,
                        resolver,
                        converter,
                        |index, query, key, value, context, converter| {
                            if report {
                                context.add_variable_capture_key(name, Rc::clone(&key))?;
                            }
                            query_retrieval_with_converter(
                                index,
                                query,
                                Rc::clone(&value),
                                context,
                                converter,
                            )
                        },
                    )
                }

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => query_retrieval_with_converter(
                    query_index + 1,
                    query,
                    Rc::new(rest.clone()),
                    resolver,
                    converter,
                ),
            }
        }

        QueryPart::Filter(name, conjunctions) => match &*current {
            PathAwareValue::Map((_path, map)) => match &query[query_index - 1] {
                QueryPart::AllValues(_name) | QueryPart::AllIndices(_name) => {
                    check_and_delegate(conjunctions, &None)(
                        query_index + 1,
                        query,
                        Rc::clone(&current),
                        Rc::clone(&current),
                        resolver,
                        converter,
                    )
                }

                QueryPart::Key(_) => {
                    if !map.is_empty() {
                        accumulate_map(
                            Rc::clone(&current),
                            map,
                            query_index,
                            query,
                            resolver,
                            converter,
                            check_and_delegate(conjunctions, name),
                        )
                    } else {
                        Ok(vec![])
                    }
                }

                _ => unreachable!(),
            },

            PathAwareValue::List((_path, list)) => {
                let mut selected = Vec::with_capacity(list.len());
                for each in list {
                    let context = format!("Filter/List#{}", conjunctions.len());
                    resolver.start_record(&context)?;
                    let mut val_resolver = ValueScope {
                        root: Rc::new(each.clone()),
                        parent: resolver,
                    };
                    let result = match super::eval::eval_conjunction_clauses(
                        conjunctions,
                        &mut val_resolver,
                        super::eval::eval_guard_clause,
                    ) {
                        Ok(status) => {
                            resolver.end_record(&context, RecordType::Filter(status))?;
                            match status {
                                Status::PASS => query_retrieval_with_converter(
                                    query_index + 1,
                                    query,
                                    Rc::new(each.clone()),
                                    resolver,
                                    converter,
                                )?,
                                _ => vec![],
                            }
                        }

                        Err(e) => {
                            resolver.end_record(&context, RecordType::Filter(Status::FAIL))?;
                            return Err(e);
                        }
                    };
                    selected.extend(result);
                }
                Ok(selected)
            }

            _ => {
                if let QueryPart::AllIndices(_) = &query[query_index - 1] {
                    let mut val_resolver = ValueScope {
                        root: Rc::clone(&current),
                        parent: resolver,
                    };
                    match super::eval::eval_conjunction_clauses(
                        conjunctions,
                        &mut val_resolver,
                        super::eval::eval_guard_clause,
                    ) {
                        Ok(status) => match status {
                            Status::PASS => query_retrieval_with_converter(
                                query_index + 1,
                                query,
                                Rc::clone(&current),
                                resolver,
                                converter,
                            ),
                            _ => Ok(vec![]),
                        },
                        Err(e) => Err(e),
                    }
                } else {
                    to_unresolved_result(
                        Rc::clone(&current),
                        format!(
                            "Filter on value type that was not a struct or array {} {}",
                            current.type_info(),
                            current.self_path()
                        ),
                        &query[query_index..],
                    )
                }
            }
        },

        QueryPart::MapKeyFilter(_name, map_key_filter) => match &*current {
            PathAwareValue::Map((_path, map)) => {
                let mut selected = Vec::with_capacity(map.values.len());
                let rhs = match &map_key_filter.compare_with {
                    LetValue::AccessClause(acc_query) => query_retrieval_with_converter(
                        0,
                        &acc_query.query,
                        Rc::clone(&current),
                        resolver,
                        converter,
                    )?,

                    LetValue::Value(path_value) => {
                        vec![QueryResult::Literal(Rc::new(path_value.clone()))]
                    }

                    LetValue::FunctionCall(_) => todo!(),
                };

                let lhs = map
                    .keys
                    .iter()
                    .cloned()
                    .map(Rc::new)
                    .map(QueryResult::Resolved)
                    .collect::<Vec<QueryResult>>();

                let results = super::eval::real_binary_operation(
                    &lhs,
                    &rhs,
                    map_key_filter.comparator,
                    "".to_string(),
                    None,
                    resolver,
                )?;

                let results = match results {
                    super::eval::EvaluationResult::QueryValueResult(r) => r,
                    _ => unreachable!(),
                };

                for each_result in results {
                    match each_result {
                        (QueryResult::Resolved(key), Status::PASS) => {
                            if let PathAwareValue::String((_, key_name)) = &*key {
                                selected.push(QueryResult::Resolved(Rc::new(
                                    map.values.get(key_name.as_str()).unwrap().clone(),
                                )));
                            }
                        }

                        (QueryResult::UnResolved(ur), _) => {
                            selected.push(QueryResult::UnResolved(ur));
                        }

                        (_, _) => {
                            continue;
                        }
                    }
                }

                let mut extended = Vec::with_capacity(selected.len());
                for each in selected {
                    match each {
                        QueryResult::Literal(r) | QueryResult::Resolved(r) => {
                            extended.extend(query_retrieval_with_converter(
                                query_index + 1,
                                query,
                                r,
                                resolver,
                                converter,
                            )?);
                        }
                        QueryResult::UnResolved(ur) => {
                            extended.push(QueryResult::UnResolved(ur));
                        }
                    }
                }
                Ok(extended)
            }

            _ => to_unresolved_result(
                Rc::clone(&current),
                format!(
                    "Map Filter for keys was not a struct {} {}",
                    current.type_info(),
                    current.self_path()
                ),
                &query[query_index..],
            ),
        },
    }
}

pub(crate) fn root_scope<'value, 'loc: 'value>(
    rules_file: &'value RulesFile<'loc>,
    root: Rc<PathAwareValue>,
) -> Result<RootScope<'value, 'loc>> {
    let (literals, queries, function_expressions) = extract_variables(&rules_file.assignments)?;
    let mut lookup_cache = HashMap::with_capacity(rules_file.guard_rules.len());
    for rule in &rules_file.guard_rules {
        lookup_cache
            .entry(rule.rule_name.as_str())
            .or_insert(vec![])
            .push(rule);
    }

    let mut parameterized_rules = HashMap::with_capacity(rules_file.parameterized_rules.len());
    for pr in rules_file.parameterized_rules.iter() {
        parameterized_rules.insert(pr.rule.rule_name.as_str(), pr);
    }
    root_scope_with(
        literals,
        queries,
        lookup_cache,
        parameterized_rules,
        function_expressions,
        root,
    )
}

pub(crate) fn root_scope_with<'value, 'loc: 'value>(
    literals: HashMap<&'value str, Rc<PathAwareValue>>,
    queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
    lookup_cache: HashMap<&'value str, Vec<&'value Rule<'loc>>>,
    parameterized_rules: HashMap<&'value str, &'value ParameterizedRule<'loc>>,
    function_expressions: HashMap<&'value str, &'value FunctionExpr<'loc>>,
    root: Rc<PathAwareValue>,
) -> Result<RootScope<'value, 'loc>> {
    Ok(RootScope {
        scope: Scope {
            root,
            literals,
            variable_queries: queries,
            //resolved_variables: std::cell::RefCell::new(HashMap::new()),
            function_expressions,
            resolved_variables: HashMap::new(),
        },
        rules: lookup_cache,
        parameterized_rules,
        rules_status: HashMap::new(),
        recorder: RecordTracker {
            final_event: None,
            events: vec![],
        },
    })
}

pub(crate) fn block_scope<'value, 'block, 'loc: 'value, 'eval, T>(
    block: &'value Block<'loc, T>,
    root: Rc<PathAwareValue>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
) -> Result<BlockScope<'value, 'loc, 'eval>> {
    let (literals, variable_queries, function_expressions) = extract_variables(&block.assignments)?;
    Ok(BlockScope {
        scope: Scope {
            literals,
            variable_queries,
            root,
            //resolved_variables: std::cell::RefCell::new(HashMap::new()),
            resolved_variables: HashMap::new(),
            function_expressions,
        },
        parent,
    })
}

pub(crate) struct RecordTracker<'value> {
    pub(crate) events: Vec<EventRecord<'value>>,
    pub(crate) final_event: Option<EventRecord<'value>>,
}

impl<'value> RecordTracker<'value> {
    #[cfg(test)]
    pub(crate) fn new() -> RecordTracker<'value> {
        RecordTracker {
            events: vec![],
            final_event: None,
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
            children: vec![],
        });
        Ok(())
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        let matched = match self.events.pop() {
            Some(mut event) => {
                if event.context != context {
                    return Err(Error::IncompatibleError(format!(
                        "Event Record context start and end does not match {}",
                        context
                    )));
                }

                event.container = Some(record);
                event
            }

            None => {
                return Err(Error::IncompatibleError(format!(
                    "Event Record end with context {} did not have a corresponding start",
                    context
                )))
            }
        };

        match self.events.last_mut() {
            Some(parent) => {
                parent.children.push(matched);
            }

            None => {
                self.final_event.replace(matched);
            }
        }
        Ok(())
    }
}

impl<'value, 'loc: 'value> EvalContext<'value, 'loc> for RootScope<'value, 'loc> {
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        let root = self.root();
        query_retrieval(0, query, root, self)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        match self.parameterized_rules.get(rule_name) {
            Some(r) => Ok(*r),
            _ => Err(Error::MissingValue(format!(
                "Parameterized Rule with name {} was not found, candiate {:?}",
                rule_name,
                self.parameterized_rules.keys()
            ))),
        }
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.scope.root)
    }

    #[allow(clippy::never_loop)]
    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        if let Some(status) = self.rules_status.get(rule_name) {
            return Ok(*status);
        }

        let rule = match self.rules.get(rule_name) {
            Some(rule) => rule.clone(),
            None => {
                return Err(Error::MissingValue(format!(
                    "Rule {} by that name does not exist, Rule Names = {:?}",
                    rule_name,
                    self.rules.keys()
                )))
            }
        };

        let status = 'done: loop {
            for each_rule in rule {
                let status = super::eval::eval_rule(each_rule, self)?;
                if status != SKIP {
                    break 'done status;
                }
            }
            break SKIP;
        };

        self.rules_status.insert(rule_name, status);
        Ok(status)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Literal(Rc::clone(val))]);
        }

        if let Some(values) = self.scope.resolved_variables.get(variable_name) {
            return Ok(values.clone());
        }

        if let Some(FunctionExpr {
            parameters, name, ..
        }) = self.scope.function_expressions.get(variable_name)
        {
            validate_number_of_params(name, parameters.len())?;
            let args = parameters.iter().try_fold(
                vec![],
                |mut args, param| -> Result<Vec<Vec<QueryResult>>> {
                    match param {
                        LetValue::Value(value) => {
                            args.push(vec![QueryResult::Literal(Rc::new(value.clone()))])
                        }
                        LetValue::AccessClause(clause) => {
                            let resolved_query = self.query(&clause.query)?;
                            args.push(resolved_query);
                        }
                        // TODO: when we add inline function call support
                        _ => unimplemented!(),
                    }

                    Ok(args)
                },
            )?;

            let result = try_handle_function_call(name, &args)?
                .into_iter()
                .flatten()
                .map(Rc::new)
                .map(QueryResult::Resolved)
                .collect::<Vec<_>>();

            self.scope
                .resolved_variables
                .insert(variable_name, result.clone());

            return Ok(result);
        }

        let query = match self.scope.variable_queries.get(variable_name) {
            Some(val) => val,
            None => {
                return Err(Error::MissingValue(format!(
                    "Could not resolve variable by name {} across scopes",
                    variable_name
                )))
            }
        };

        let match_all = query.match_all;

        let result = query_retrieval(0, &query.query, self.root(), self)?;
        let result = if !match_all {
            result
                .into_iter()
                .filter(|q| matches!(q, QueryResult::Resolved(_)))
                .collect()
        } else {
            result
        };
        self.scope
            .resolved_variables
            .insert(variable_name, result.clone());
        Ok(result)
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.scope
            .resolved_variables
            .entry(variable_name)
            .or_default()
            .push(QueryResult::Resolved(Rc::clone(&key)));
        Ok(())
    }
}

pub(crate) fn validate_number_of_params(name: &str, num_args: usize) -> Result<()> {
    let expected_num_args = match name {
        "join" => 2,
        "substring" | "regex_replace" => 3,
        "count" | "json_parse" | "to_upper" | "to_lower" | "url_decode" => 1,
        _ => {
            return Err(Error::ParseError(format!(
                "no such function named {name} exists"
            )));
        }
    };

    if expected_num_args != num_args {
        return Err(Error::ParseError(format!(
            "{name} function requires {expected_num_args} arguments be passed, but received {num_args}"
        )));
    }

    Ok(())
}

// TODO: look into the possibility of abstracting functions into structs that all implement
pub(crate) fn try_handle_function_call(
    fn_name: &str,
    args: &[Vec<QueryResult>],
) -> Result<Vec<Option<PathAwareValue>>> {
    let value = match fn_name {
        "count" => vec![Some(count(&args[0]))],
        "json_parse" => json_parse(&args[0])?,
        "regex_replace" => {
            let substring_err_msg = |index| {
                let arg = match index {
                    2 => "second",
                    3 => "third",
                    _ => unreachable!(),
                };

                format!("regex_replace function requires the {arg} argument to be a string")
            };

            let extracted_expr = match &args[1][0] {
                QueryResult::Resolved(r) | QueryResult::Literal(r) => match &**r {
                    PathAwareValue::String((_, s)) => s,
                    _ => return Err(Error::ParseError(substring_err_msg(2))),
                },
                _ => return Err(Error::ParseError(substring_err_msg(2))),
            };

            let replaced_expr = match &args[2][0] {
                QueryResult::Resolved(r) | QueryResult::Literal(r) => match &**r {
                    PathAwareValue::String((_, s)) => s,
                    _ => return Err(Error::ParseError(substring_err_msg(3))),
                },
                _ => return Err(Error::ParseError(substring_err_msg(3))),
            };

            regex_replace(&args[0], extracted_expr, replaced_expr)?
        }
        "substring" => {
            let substring_err_msg = |index| {
                let arg = match index {
                    2 => "second",
                    3 => "third",
                    _ => unreachable!(),
                };

                format!("substring function requires the {arg} argument to be a number")
            };

            let from = match &args[1][0] {
                QueryResult::Literal(r) | QueryResult::Resolved(r) => match &**r {
                    PathAwareValue::Int((_, n)) => usize::from(*n as u16),
                    PathAwareValue::Float((_, n)) => usize::from(*n as u16),
                    _ => return Err(Error::ParseError(substring_err_msg(2))),
                },
                _ => return Err(Error::ParseError(substring_err_msg(2))),
            };

            let to = match &args[2][0] {
                QueryResult::Literal(r) | QueryResult::Resolved(r) => match &**r {
                    PathAwareValue::Int((_, n)) => usize::from(*n as u16),
                    PathAwareValue::Float((_, n)) => usize::from(*n as u16),
                    _ => return Err(Error::ParseError(substring_err_msg(3))),
                },
                _ => return Err(Error::ParseError(substring_err_msg(3))),
            };

            substring(&args[0], from, to)?
        }
        "to_upper" => to_upper(&args[0])?,
        "to_lower" => to_lower(&args[0])?,
        "join" => {
            let res = match &args[1][0] {
                QueryResult::Resolved(r) | QueryResult::Literal(r) => match &**r {
                    PathAwareValue::String((_, s)) => join(&args[0], s),
                    PathAwareValue::Char((_, c)) => join(&args[0], &c.to_string()),
                    _ => return Err(Error::ParseError(String::from(
                        "join function requires the second argument to be either a char or string",
                    ))),
                },
                _ => {
                    return Err(Error::ParseError(String::from(
                        "join function requires the second argument to be either a char or string",
                    )))
                }
            }?;

            vec![Some(res)]
        }
        "url_decode" => url_decode(&args[0])?,

        function => return Err(Error::ParseError(format!("No function named {function}"))),
    };

    Ok(value)
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
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        query_retrieval(0, query, self.root(), self.parent)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.root)
    }

    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        self.parent.resolve_variable(variable_name)
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
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
    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        query_retrieval(0, query, self.root(), self)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.scope.root)
    }

    fn rule_status(&mut self, rule_name: &'value str) -> Result<Status> {
        self.parent.rule_status(rule_name)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Literal(Rc::clone(val))]);
        }

        if let Some(values) = self.scope.resolved_variables.get(variable_name) {
            return Ok(values.clone());
        }

        if let Some(FunctionExpr {
            parameters, name, ..
        }) = self.scope.function_expressions.get(variable_name)
        {
            validate_number_of_params(name, parameters.len())?;
            let args = parameters.iter().try_fold(
                vec![],
                |mut args, param| -> Result<Vec<Vec<QueryResult>>> {
                    match param {
                        LetValue::Value(value) => {
                            args.push(vec![QueryResult::Literal(Rc::new(value.clone()))])
                        }
                        LetValue::AccessClause(clause) => {
                            let resolved_query = self.query(&clause.query)?;
                            args.push(resolved_query);
                        }
                        // TODO: when we add inline function call support
                        _ => unimplemented!(),
                    }

                    Ok(args)
                },
            )?;

            let result = try_handle_function_call(name, &args)?
                .into_iter()
                .flatten()
                .map(Rc::new)
                .map(QueryResult::Resolved)
                .collect::<Vec<_>>();

            self.scope
                .resolved_variables
                .insert(variable_name, result.clone());

            return Ok(result);
        }

        let query = match self.scope.variable_queries.get(variable_name) {
            Some(val) => val,
            None => return self.parent.resolve_variable(variable_name),
        };

        let match_all = query.match_all;

        let result = query_retrieval(0, &query.query, self.root(), self)?;
        let result = if !match_all {
            result
                .into_iter()
                .filter(|q| matches!(q, QueryResult::Resolved(_)))
                .collect()
        } else {
            result
        };
        self.scope
            .resolved_variables
            .insert(variable_name, result.clone());

        Ok(result)
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
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

#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct Messages {
    pub(crate) custom_message: Option<String>,
    pub(crate) error_message: Option<String>,
}

pub(crate) type Metadata = HashMap<String, String>;

#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct FileReport<'value> {
    pub(crate) name: &'value str,
    pub(crate) metadata: Metadata,
    pub(crate) status: Status,
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub(crate) not_compliant: Vec<ClauseReport<'value>>,
    pub(crate) not_applicable: BTreeSet<String>,
    pub(crate) compliant: BTreeSet<String>,
}

impl<'value> FileReport<'value> {
    pub(crate) fn combine(&mut self, report: FileReport<'value>) {
        if report.name != self.name {
            panic!("Incompatible to merge")
        }
        self.status = self.status.and(report.status);
        self.metadata.extend(report.metadata);
        self.not_compliant.extend(report.not_compliant);
        self.compliant.extend(report.compliant);
        self.not_applicable.extend(report.not_applicable);
    }
}

#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct RuleReport<'value> {
    pub(crate) name: &'value str,
    pub(crate) metadata: Metadata,
    pub(crate) messages: Messages,
    pub(crate) checks: Vec<ClauseReport<'value>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryComparison {
    pub(crate) value: Rc<PathAwareValue>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValueUnResolved {
    pub(crate) value: UnResolved,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum UnaryCheck {
    UnResolved(ValueUnResolved),
    Resolved(UnaryComparison),
    UnResolvedContext(String),
}

impl ValueComparisons for UnaryCheck {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            UnaryCheck::UnResolved(ur) => Some(ur.value.traversed_to.clone()),
            UnaryCheck::Resolved(uc) => Some(uc.value.clone()),
            UnaryCheck::UnResolvedContext(_) => None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryReport {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) check: UnaryCheck,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BinaryComparison {
    pub(crate) from: Rc<PathAwareValue>,
    pub(crate) to: Rc<PathAwareValue>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct InComparison {
    pub(crate) from: Rc<PathAwareValue>,
    pub(crate) to: Vec<Rc<PathAwareValue>>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum BinaryCheck {
    UnResolved(ValueUnResolved),
    Resolved(BinaryComparison),
    InResolved(InComparison),
}

impl ValueComparisons for BinaryCheck {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            BinaryCheck::UnResolved(vur) => Some(vur.value.traversed_to.clone()),
            BinaryCheck::Resolved(res) => Some(res.from.clone()),
            BinaryCheck::InResolved(inr) => Some(inr.from.clone()),
        }
    }

    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            BinaryCheck::Resolved(bc) => Some(bc.to.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BinaryReport {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) check: BinaryCheck,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum GuardClauseReport {
    Unary(UnaryReport),
    Binary(BinaryReport),
}

pub(crate) trait ValueComparisons {
    fn value_from(&self) -> Option<Rc<PathAwareValue>>;
    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        None
    }
}

impl ValueComparisons for GuardClauseReport {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            GuardClauseReport::Binary(br) => br.check.value_from(),
            GuardClauseReport::Unary(ur) => ur.check.value_from(),
        }
    }

    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
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
pub(crate) struct GuardBlockReport {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) unresolved: Option<UnResolved>,
}

impl ValueComparisons for GuardBlockReport {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        if let Some(ur) = &self.unresolved {
            return Some(ur.traversed_to.clone());
        }
        None
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum ClauseReport<'value> {
    Rule(RuleReport<'value>),
    Block(GuardBlockReport),
    Disjunctions(DisjunctionsReport<'value>),
    Clause(GuardClauseReport),
}

impl<'value> ClauseReport<'value> {
    pub(crate) fn key(&self, parent: &str) -> String {
        match self {
            Self::Rule(RuleReport { name, .. }) => format!("{}/{}", parent, name),
            Self::Block(_) => format!("{}/B[{:p}]", parent, self),
            Self::Disjunctions(_) => format!("{}/Or[{:p}]", parent, self),
            Self::Clause(_) => format!("{}/C[{:p}]", parent, self),
        }
    }
}

impl<'value> ValueComparisons for ClauseReport<'value> {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            Self::Block(b) => b.value_from(),
            Self::Clause(c) => c.value_from(),
            _ => None,
        }
    }

    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            Self::Block(b) => b.value_to(),
            Self::Clause(c) => c.value_to(),
            _ => None,
        }
    }
}

pub(crate) fn cmp_str(cmp: (CmpOperator, bool)) -> &'static str {
    let (cmp, not) = cmp;
    if cmp.is_unary() {
        match cmp {
            CmpOperator::Exists => {
                if not {
                    "NOT EXISTS"
                } else {
                    "EXISTS"
                }
            }
            CmpOperator::Empty => {
                if not {
                    "NOT EMPTY"
                } else {
                    "EMPTY"
                }
            }
            CmpOperator::IsList => {
                if not {
                    "NOT LIST"
                } else {
                    "IS LIST"
                }
            }
            CmpOperator::IsMap => {
                if not {
                    "NOT STRUCT"
                } else {
                    "IS STRUCT"
                }
            }
            CmpOperator::IsString => {
                if not {
                    "NOT STRING"
                } else {
                    "IS STRING"
                }
            }
            _ => unreachable!(),
        }
    } else {
        match cmp {
            CmpOperator::Eq => {
                if not {
                    "NOT EQUAL"
                } else {
                    "EQUAL"
                }
            }
            CmpOperator::Le => {
                if not {
                    "NOT LESS THAN EQUAL"
                } else {
                    "LESS THAN EQUAL"
                }
            }
            CmpOperator::Lt => {
                if not {
                    "NOT LESS THAN"
                } else {
                    "LESS THAN"
                }
            }
            CmpOperator::Ge => {
                if not {
                    "NOT GREATER THAN EQUAL"
                } else {
                    "GREATER THAN EQUAL"
                }
            }
            CmpOperator::Gt => {
                if not {
                    "NOT GREATER THAN"
                } else {
                    "GREATER THAN"
                }
            }
            CmpOperator::In => {
                if not {
                    "NOT IN"
                } else {
                    "IN"
                }
            }
            _ => unreachable!(),
        }
    }
}

fn report_all_failed_clauses_for_rules<'value>(
    checks: &[EventRecord<'value>],
) -> Vec<ClauseReport<'value>> {
    let mut clauses = Vec::with_capacity(checks.len());
    for current in checks {
        match &current.container {
            Some(RecordType::RuleCheck(NamedStatus {
                name,
                status: Status::FAIL,
                message,
            })) => {
                clauses.push(ClauseReport::Rule(RuleReport {
                    name,
                    checks: report_all_failed_clauses_for_rules(&current.children),
                    messages: Messages {
                        custom_message: message.clone(),
                        error_message: None,
                    },
                    ..Default::default()
                }));
            }

            Some(RecordType::BlockGuardCheck(BlockCheck {
                status: Status::FAIL,
                ..
            })) => {
                if current.children.is_empty() {
                    clauses.push(ClauseReport::Block(GuardBlockReport {
                        context: current.context.clone(),
                        messages: Messages {
                            error_message: Some(String::from(
                                "query for block clause did not retrieve any value",
                            )),
                            custom_message: None,
                        },
                        unresolved: None,
                    }));
                } else {
                    clauses.extend(report_all_failed_clauses_for_rules(&current.children));
                }
            }

            Some(RecordType::Disjunction(BlockCheck {
                status: Status::FAIL,
                ..
            })) => {
                clauses.push(ClauseReport::Disjunctions(DisjunctionsReport {
                    checks: report_all_failed_clauses_for_rules(&current.children),
                }));
            }

            Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                ..
            }))
            | Some(RecordType::TypeBlock(Status::FAIL))
            | Some(RecordType::TypeCheck(TypeBlockCheck {
                block:
                    BlockCheck {
                        status: Status::FAIL,
                        ..
                    },
                ..
            }))
            | Some(RecordType::WhenCheck(BlockCheck {
                status: Status::FAIL,
                ..
            })) => {
                clauses.extend(report_all_failed_clauses_for_rules(&current.children));
            }

            Some(RecordType::ClauseValueCheck(clause)) => match clause {
                ClauseCheck::NoValueForEmptyCheck(msg) => {
                    let custom_message = msg
                        .as_ref()
                        .map_or("".to_string(), |s| s.replace('\n', ";"));

                    let error_message = format!(
                        "Check was not compliant as variable in context [{}] was not empty",
                        current.context
                    );
                    clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                        UnaryReport {
                            context: current.context.clone(),
                            check: UnaryCheck::UnResolvedContext(current.context.to_string()),
                            messages: Messages {
                                custom_message: Some(custom_message),
                                error_message: Some(error_message),
                            },
                        },
                    )))
                }

                ClauseCheck::Success => {}

                ClauseCheck::DependentRule(missing) => {
                    let message = missing.custom_message.as_ref().map_or("", String::as_str);
                    let error_message = format!(
                            "Check was not compliant as dependent rule [{rule}] did not PASS. Context [{cxt}]",
                            rule=missing.rule,
                            cxt=current.context,
                        );
                    clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                        UnaryReport {
                            messages: Messages {
                                custom_message: Some(message.to_string()),
                                error_message: Some(error_message),
                            },
                            context: current.context.clone(),
                            check: UnaryCheck::UnResolvedContext(missing.rule.to_string()),
                        },
                    )));
                }

                ClauseCheck::MissingBlockValue(missing) => {
                    let (property, far, ur) = match &missing.from {
                        QueryResult::UnResolved(ur) => {
                            (ur.remaining_query.as_str(), ur.traversed_to.clone(), ur)
                        }
                        _ => unreachable!(),
                    };
                    let message = missing.custom_message.as_ref().map_or("", String::as_str);
                    let error_message = format!(
                            "Check was not compliant as property [{}] is missing. Value traversed to [{}]",
                            property,
                            far
                        );
                    clauses.push(ClauseReport::Block(GuardBlockReport {
                        context: current.context.clone(),
                        messages: Messages {
                            custom_message: Some(message.to_string()),
                            error_message: Some(error_message),
                        },
                        unresolved: Some(ur.clone()),
                    }));
                }

                ClauseCheck::Unary(UnaryValueCheck {
                    comparison: (cmp, not),
                    value:
                        ValueCheck {
                            status: Status::FAIL,
                            from,
                            message,
                            custom_message,
                        },
                }) => {
                    use CmpOperator::*;
                    let cmp_msg = match cmp {
                        Exists => {
                            if *not {
                                "existed"
                            } else {
                                "did not exist"
                            }
                        }
                        Empty => {
                            if *not {
                                "was empty"
                            } else {
                                "was not empty"
                            }
                        }
                        IsList => {
                            if *not {
                                "was a list "
                            } else {
                                "was not list"
                            }
                        }
                        IsMap => {
                            if *not {
                                "was a struct"
                            } else {
                                "was not struct"
                            }
                        }
                        IsString => {
                            if *not {
                                "was a string "
                            } else {
                                "was not string"
                            }
                        }
                        IsInt => {
                            if *not {
                                "was int"
                            } else {
                                "was not int"
                            }
                        }
                        IsBool => {
                            if *not {
                                "was bool"
                            } else {
                                "was not bool"
                            }
                        }
                        _ => {
                            if *not {
                                "was float"
                            } else {
                                "was not float"
                            }
                        }
                    };

                    let custom_message = custom_message
                        .as_ref()
                        .map_or("".to_string(), |s| s.replace('\n', ";"));

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!("Error = [{}]", s));

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
                                        value: res.clone(),
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

                    clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                        UnaryReport {
                            messages: Messages {
                                custom_message: Some(custom_message),
                                error_message: Some(message),
                            },
                            context: current.context.clone(),
                            check,
                        },
                    )));
                }

                ClauseCheck::Comparison(ComparisonClauseCheck {
                    custom_message,
                    message,
                    comparison: (cmp, not),
                    from,
                    status: Status::FAIL,
                    to,
                }) => {
                    let custom_message = custom_message
                        .as_ref()
                        .map_or("".to_string(), |s| s.replace('\n', ";"));

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!(" Error = [{}]", s));

                    match from {
                        QueryResult::Literal(_) => unreachable!(),
                        QueryResult::UnResolved(to_unres) => {
                            let message = format!(
                                    "Check was not compliant as property [{remain}] to compare from is missing. Value traversed to [{to}].{err}",
                                    remain=to_unres.remaining_query,
                                    to=to_unres.traversed_to,
                                    err=error_message
                                );
                            clauses.push(ClauseReport::Clause(GuardClauseReport::Binary(
                                BinaryReport {
                                    context: current.context.to_string(),
                                    messages: Messages {
                                        custom_message: Some(custom_message),
                                        error_message: Some(message),
                                    },
                                    check: BinaryCheck::UnResolved(ValueUnResolved {
                                        comparison: (*cmp, *not),
                                        value: to_unres.clone(),
                                    }),
                                },
                            )));
                        }

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
                                                    CmpOperator::Le => if *not { "less than equal to" } else { "not less than equal to" },
                                                    CmpOperator::Lt => if *not { "less than" } else { "not less than" },
                                                    CmpOperator::Ge => if *not { "greater than equal to" } else { "not greater than equal" },
                                                    CmpOperator::Gt => if *not { "greater than" } else { "not greater than" },
                                                    CmpOperator::In => if *not { "in" } else { "not in" },
                                                    _ => unreachable!()
                                                },
                                                err=error_message
                                            );
                                        clauses.push(ClauseReport::Clause(
                                            GuardClauseReport::Binary(BinaryReport {
                                                check: BinaryCheck::Resolved(BinaryComparison {
                                                    to: to_res.clone(),
                                                    from: res.clone(),
                                                    comparison: (*cmp, *not),
                                                }),
                                                context: current.context.to_string(),
                                                messages: Messages {
                                                    error_message: Some(message),
                                                    custom_message: Some(custom_message),
                                                },
                                            }),
                                        ))
                                    }

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
                                                check: BinaryCheck::UnResolved(ValueUnResolved {
                                                    comparison: (*cmp, *not),
                                                    value: to_unres.clone(),
                                                }),
                                            }),
                                        ));
                                    }
                                }
                            }
                        }
                    }
                }

                ClauseCheck::InComparison(InComparisonCheck {
                    status: Status::FAIL,
                    from,
                    to,
                    custom_message,
                    comparison,
                    ..
                }) => {
                    let error_message = format!(
                        "Check was not compliant as property [{}] was not present in [{}]",
                        from.resolved().unwrap().self_path(),
                        SliceDisplay(to)
                    );
                    clauses.push(ClauseReport::Clause(GuardClauseReport::Binary(
                        BinaryReport {
                            context: current.context.to_string(),
                            messages: Messages {
                                custom_message: custom_message.clone(),
                                error_message: Some(error_message),
                            },
                            check: BinaryCheck::InResolved(InComparison {
                                from: match from.resolved() {
                                    Some(val) => val,
                                    None => match from.unresolved_traversed_to() {
                                        Some(val) => val,
                                        None => unreachable!(),
                                    },
                                },
                                to: to
                                    .iter()
                                    .filter(|t| matches!(t, QueryResult::Resolved(_)))
                                    .map(|t| match t {
                                        QueryResult::Resolved(v) => v.clone(),
                                        _ => unreachable!(),
                                    })
                                    .collect::<Vec<_>>(),
                                comparison: *comparison,
                            }),
                        },
                    )));
                }

                _ => {}
            },

            _ => {}
        }
    }
    clauses
}

pub(crate) fn simplifed_json_from_root<'value>(
    root: &EventRecord<'value>,
) -> Result<FileReport<'value>> {
    Ok(match &root.container {
        Some(RecordType::FileCheck(NamedStatus { name, status, .. })) => {
            let mut pass: BTreeSet<String> = BTreeSet::new();
            let mut skip: BTreeSet<String> = BTreeSet::new();
            for each in &root.children {
                if let Some(RecordType::RuleCheck(NamedStatus { status, name, .. })) =
                    &each.container
                {
                    match *status {
                        Status::PASS => {
                            pass.insert(name.to_string());
                        }
                        SKIP => {
                            skip.insert(name.to_string());
                        }
                        _ => {}
                    }
                }
            }
            FileReport {
                status: *status,
                name,
                not_compliant: report_all_failed_clauses_for_rules(&root.children),
                not_applicable: skip,
                compliant: pass,
                ..Default::default()
            }
        }
        _ => unreachable!(),
    })
}

#[cfg(test)]
#[path = "eval_context_tests.rs"]
pub(super) mod eval_context_tests;
