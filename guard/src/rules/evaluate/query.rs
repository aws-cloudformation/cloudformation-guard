use crate::rules::evaluate::traits::{QueryResolver, Resolver};
use crate::rules::exprs::{QueryPart, SliceDisplay};
use crate::rules::values::{Value, type_info};
use super::traits::Result;
use crate::errors::{Error, ErrorKind};
use std::collections::HashMap;
use std::hash::{Hasher, Hash};
use std::collections::hash_map::DefaultHasher;

//
// Helper functions
//
fn match_list<'loc>(value: &'loc Value, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&'loc Vec<Value>> {
    return if let Value::List(list) = value {
        Ok(list)
    }
    else {
        Err(Error::new(
            ErrorKind::IncompatibleError(
                format!("Current value type is not a list, Type = {}, Value = {:?}, part = {}, remaining query = {}",
                        type_info(value), value, part, SliceDisplay(remaining))
            )))
    }
}

fn match_map<'loc>(value: &'loc Value, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&'loc indexmap::IndexMap<String, Value>> {
    return if let Value::Map(map) = value {
        Ok(map)
    }
    else {
        Err(Error::new(
            ErrorKind::IncompatibleError(
                format!("Current value type is not a Map, Type = {}, Value = {:?}, part = {}, remaining query = {}",
                        type_info(value), value, part, SliceDisplay(remaining))
            )))
    }
}

fn retrieve_key<'loc>(key: &str, value: &'loc Value, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&'loc Value> {
    let map = match_map(value, part, remaining)?;
    return if let Some(val) = map.get(key) {
        Ok(val)
    } else {
        Err(Error::new(
            ErrorKind::RetrievalError(
                format!("Could not locate Key = {} inside Value Map = {:?} part = {}, remaining query = {}",
                key, value, part, SliceDisplay(remaining))
        )))
    }
}

fn retrieve_index<'loc>(index: i32, value: &'loc Value, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&'loc Value> {
    let list = match_list(value, part, remaining)?;
    let check = if index >= 0 { index } else { -index };
    return if check < list.len() as i32 {
        Ok(&list[index as usize])
    }
    else {
        Err(Error::new(
            ErrorKind::RetrievalError(
                format!("Could not locate Index = {} inside Value List = {:?} part = {}, remaining query = {}",
                        index, value, part, SliceDisplay(remaining))
            )))
    }
}
//
//
//
pub(super) struct StdResolver {}

impl QueryResolver for StdResolver {
    fn resolve<'r>(&self,
                   index: usize,
                   query: &[QueryPart<'_>],
                   var_resolver: &dyn Resolver,
                   context: &'r Value) -> Result<Vec<&'r Value>> {
        let mut value = context;
        let mut result = Vec::new();

        for idx in index..query.len() {
            let part = &query[idx];
            if part.is_variable() {
                return Err(Error::new(ErrorKind::IncompatibleError(
                    format!("Do not support variable interpolation inside a query, part = {}, remaining query {}",
                        part, SliceDisplay(query)
                ))))
            }

            match part {
                QueryPart::Key(key) => {
                    //
                    // Support old format
                    //
                    match key.parse::<i32>() {
                        Ok(idx) => {
                            value = retrieve_index(idx, value, part, query)?;
                        },
                        Err(_) => {
                            value = retrieve_key(key, value, part, query)?;
                        }
                    }
                },

                QueryPart::Index(idx) => {
                    value = retrieve_index(*idx, value, part, query)?;
                },

                QueryPart::AllValues => {
                    //
                    // Support old format
                    //
                    match match_list(value, part, query) {
                        Err(_) => unimplemented!(),
//                            return self.handle_map(match_map(value, part, query)?,
//                                                   idx, query),

                        Ok(array) => unimplemented!(),
                            // return self.handle_array(array, idx, query),
                    }
                }

                QueryPart::AllIndices => {
                    unimplemented!()
//                    return self.handle_array(
//                        match_list(value, part, query),
//                        idx, query);
                },

                _ => unimplemented!()

            }

        }

        result.push(value);
        Ok(result)
    }
}

impl StdResolver {

}