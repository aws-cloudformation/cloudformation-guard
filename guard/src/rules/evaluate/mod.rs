use std::collections::HashMap;
use crate::rules::values::{Value, CmpOperator};
use crate::rules::exprs::{RulesFile, LetExpr, LetValue, Block, Rule, QueryPart, AccessQuery, GuardClause, Conjunctions};
use std::collections::hash_map::Entry;
use crate::errors::{Error, ErrorKind};

type Result<R> = std::result::Result<R, Error>;

trait VariableResolver {
    fn resolve(&self,
               variable: &str) -> Result<Vec<&Value>>;
}

trait QueryResolver {
    fn resolve<'r>(&self,
                   query: &[QueryPart<'_>],
                   context: &'r Value) -> Result<Vec<&'r Value>>;
}

trait Evaluate {
    fn evaluate(&self, context: &Value) -> Result<Status>;
}

#[derive(Debug, Clone)]
enum Status {
    PASS,
    FAIL(CmpOperator, Value, Value),
    SKIP(CmpOperator, Value, Value)
}

struct FileScope<'s, 'loc> {
    rules: &'s RulesFile<'loc>,
    input_context: &'s Value,
    pending_queries: HashMap<&'s str, &'s AccessQuery<'loc>>,
    variables: std::cell::RefCell<HashMap<&'s str, Vec<&'s Value>>>,
    query_resolver: &'s dyn QueryResolver,
}

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

fn resolve_variable<'s, 'loc>(variable: &str,
                              queries: &HashMap<&'s str, &'s AccessQuery<'loc>>,
                              cache: &mut HashMap<&'s str, Vec<&'s Value>>,
                              context: &'s Value,
                              resolver: &'s dyn QueryResolver) -> Result<Vec<&'s Value>> {

    return if let Some((key, query)) = queries.get_key_value(variable) {
        let values = resolver.resolve(*query, context)?;
        cache.insert(*key, values.clone());
        Ok(values)
    } else {
        Err(Error::new(ErrorKind::MissingVariable(
            format!("Could not resolve variable {}", variable)
        )))
    }
}

fn resolve_query<'s, 'loc>(query: &'s AccessQuery<'loc>,
                           query_resolver: &'s dyn QueryResolver,
                           var_resolver: &'s dyn VariableResolver,
                           context: &'s Value) -> Result<Vec<&'s Value>> {

    let resolved = if let Some(var) = query[0].variable() {
        var_resolver.resolve(var)?
    } else {
        vec![context]
    };

    let mut expanded = Vec::with_capacity(resolved.len());
    for each in resolved {
        expanded.extend(query_resolver.resolve(&query[1..], each)?)
    }
    Ok(expanded)
}

impl<'s, 'loc> FileScope<'s, 'loc> {
    pub(crate) fn new(rules: &'s RulesFile<'loc>,
                      value: &'s Value,
                      resolver: &'s dyn QueryResolver) -> Self {
        let mut variables = HashMap::new();
        let mut pending = HashMap::new();
        extract_variables(&rules.assignments,
                          &mut variables,
                          &mut pending);
        FileScope {
            rules,
            input_context: value,
            pending_queries: pending,
            variables: std::cell::RefCell::new(variables),
            query_resolver: resolver
        }
    }
}

impl<'s, 'loc> VariableResolver for FileScope<'s, 'loc> {
    fn resolve(&self, variable: &str) -> Result<Vec<&Value>> {
        if let Some(value) = self.variables.borrow().get(variable) {
            return Ok(value.clone())
        }
        resolve_variable(variable,
                         &self.pending_queries,
                         &mut self.variables.borrow_mut(),
                         self.input_context, self.query_resolver)
    }
}

struct RuleScope<'r, 'loc> {
    rule: &'r Rule<'loc>,
    input_context: &'r Value,
    variables: std::cell::RefCell<HashMap<&'r str, Vec<&'r Value>>>,
    query_resolver: &'r dyn QueryResolver,
    parent: &'r dyn VariableResolver,
}

struct GuardScope<'r, 'loc> {
    guard: &'r GuardClause<'loc>,
    input_context: &'r Value,
    query_resolver: &'r dyn QueryResolver,
    var_resolver: &'r dyn VariableResolver,
}

impl<'r, 'loc> Evaluate for GuardScope<'r, 'loc> {
    fn evaluate(&self, context: &Value) -> Result<Status> {
        if let GuardClause::Clause(clause) = &self.guard {
            let lhs = if let Some(var) = clause.access_clause.query[0].variable() {
                match self.var_resolver.resolve(var) {
                    Ok(v) => Some(v),
                    Err(Error(ErrorKind::RetrievalError(_))) => None,
                    Err(e) => return Err(e)
                }
            } else {
                match self.query_resolver.resolve(&clause.access_clause.query, &self.input_context) {
                    Ok(v) => Some(v),
                    Err(Error(ErrorKind::RetrievalError(_))) => None,
                    Err(e) => return Err(e)
                }
            };
        }
        Ok(Status::PASS)
    }
}



impl<'loc> Evaluate for RulesFile<'loc> {
    fn evaluate(&self, context: &Value) -> Result<Status> {
        struct Resolver{};
        impl QueryResolver for Resolver {
            fn resolve<'r>(&self, query: &[QueryPart<'_>], context: &'r Value) -> Result<Vec<&'r Value>> {
                Ok(vec![])
            }
        };
        let resolver = Resolver{};
        let file_scope = FileScope::new(self, context, &resolver);
        let resolved = file_scope.resolve("var")?;
        println!("{:?}", resolved);
        Ok(Status::PASS)
    }
}

