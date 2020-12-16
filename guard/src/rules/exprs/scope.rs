use crate::rules::exprs::{QueryPart, Path};
use nom::lib::std::collections::HashMap;
use crate::rules::values::Value;
use crate::errors::{Error, ErrorKind};

pub(super) type ResolvedValues<'loc> = Vec<(Path, &'loc Value)>;

#[derive(PartialEq, Debug, Clone)]
pub(super) struct Scope<'loc> {
    variable_cache: HashMap<String, ResolvedValues<'loc>>,
    queries_cache: QueryCache<'loc>,
    parent: *const Scope<'loc>,
}

impl<'loc> Scope<'loc> {
    pub(super) fn new() -> Self {
        Scope {
            variable_cache: HashMap::new(),
            queries_cache: QueryCache::new(),
            parent: std::ptr::null()
        }
    }

    pub(super) fn get_resolutions_for_variable(&self, variable: &str) -> Result<Vec<&Value>, Error> {
        match self.variable_cache.get(variable) {
            Some(v) => {
                let mut results = Vec::with_capacity(v.len());
                for (_path, each) in v {
                    results.push(*each);
                }
                Ok(results)
            },

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

    pub(super) fn queries_cache(&self) -> &QueryCache {
        &self.queries_cache
    }

    pub(super) fn add_query_resolution<'scope: 'loc>(
        &mut self,
        query: &'scope [QueryPart<'_>],
        resolutions: ResolvedValues<'scope>) {
        self.queries_cache.cache.insert(Key{query_key: query}, resolutions);
    }

    pub(super) fn add_variable_resolution<'scope: 'loc>(
        &mut self,
        variable: &str,
        resolutions: ResolvedValues<'scope>) {
        self.variable_cache.insert(variable.to_string(), resolutions);
    }

}

#[derive(PartialEq, Debug, Clone)]
pub(super) struct QueryCache<'loc> {
    cache: HashMap<Key<'loc>, ResolvedValues<'loc>>,
}

impl<'loc> QueryCache<'loc> {
    pub(super) fn new() -> Self {
        QueryCache {
            cache: HashMap::new()
        }
    }
}

#[derive(PartialEq, Debug, Clone, Hash)]
struct Key<'loc> {
    query_key: &'loc[QueryPart<'loc>]
}

impl<'loc> Eq for Key<'loc> {}
