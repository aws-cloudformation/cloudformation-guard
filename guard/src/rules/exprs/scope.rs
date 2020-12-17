use crate::rules::exprs::{QueryPart, Path};
use std::collections::HashMap;
use crate::rules::values::Value;
use crate::errors::{Error, ErrorKind};
use super::{ResolvedValues};

#[derive(PartialEq, Debug)]
pub(super) struct Scope<'loc> {
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
    pub(super) fn new() -> Self {
        Scope {
            variable_cache: HashMap::new(),
            parent: std::ptr::null()
        }
    }

    pub(super) fn get_resolutions_for_variable(&self, variable: &str) -> Result<Vec<&Value>, Error> {
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

    pub(super) fn add_variable_resolution(
        &mut self,
        variable: &str,
        resolutions: ResolvedValues<'loc>) {
        self.variable_cache.insert(variable.to_string(), resolutions);
    }

}

