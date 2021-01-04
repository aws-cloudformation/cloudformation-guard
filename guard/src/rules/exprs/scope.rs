use crate::rules::exprs::{QueryPart, Path, LetExpr, Resolver, LetValue, Evaluate, EvalStatus, EvalContext};
use std::collections::HashMap;
use crate::rules::values::Value;
use crate::errors::{Error, ErrorKind};
use super::{ResolvedValues};

#[derive(PartialEq, Debug)]
pub(crate) struct Scope<'loc> {
    variable_cache: HashMap<String, ResolvedValues<'loc>>,
    parent: *const Scope<'loc>,
}

fn copy<'loc>(resolutions: &'loc ResolvedValues<'loc>) -> Vec<&'loc Value> {
    let mut results = Vec::with_capacity(resolutions.len());
    for (path, each) in resolutions {
        results.push(*each);
    }
    results
}

impl<'loc> Scope<'loc> {
    pub(crate) fn new() -> Self {
        Scope {
            variable_cache: HashMap::new(),
            parent: std::ptr::null()
        }
    }

    pub(crate) fn child<'p: 'loc>(parent: *const Scope<'p>) -> Self {
        Scope {
            variable_cache: HashMap::new(),
            parent,
        }
    }

    pub(crate) fn assignments(&mut self,
                              assignments: &'loc [LetExpr<'_>],
                              path: Path) -> Result<(), Error> {
        for assign in assignments {
            if let LetValue::Value(v) = &assign.value {
                let path = path.clone().append_str(&assign.var);
                let mut values = ResolvedValues::new();
                values.insert(path, v);
                self.variable_cache.insert(assign.var.clone(), values);
            }
        }
        Ok(())
    }

    pub(crate) fn assignment_queries(&mut self,
                                     queries: &[LetExpr<'_>],
                                     path: Path,
                                     value: &'loc Value,
                                     resolver: &dyn Resolver,
                                     context: &EvalContext<'_>) -> Result<(), Error> {
        for statement in queries {
            if let LetValue::AccessClause(query) = &statement.value {
                let resolved = resolver.resolve_query(
                     query, value, self, path.clone(), context)?;
                self.variable_cache.insert(statement.var.clone(), resolved);
            }
        }
        Ok(())
    }

    pub(crate) fn get_resolutions_for_variable(&self, variable: &str) -> Result<Vec<&Value>, Error> {
        match self.variable_cache.get(variable) {
            Some(v) => Ok(copy(v)),
            None => {
                match unsafe { self.parent.as_ref() } {
                    Some(parent) => parent.get_resolutions_for_variable(variable),
                    None => Err(Error::new(ErrorKind::MissingValue(
                        format!("Could not find any resolutions for variable {}", variable)
                    )))
                }
            }

        }
    }

    pub(crate) fn add_variable_resolution(
        &mut self,
        variable: &str,
        resolutions: ResolvedValues<'loc>) {
        self.variable_cache.insert(variable.to_string(), resolutions);
    }

}

