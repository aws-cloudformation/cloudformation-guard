use crate::rules::values::{Value, type_info};
use crate::errors::{Error, ErrorKind};
use super::Path;
use std::hash::Hasher;

//
// Helper functions
//
pub(super) fn match_list<'loc>(value: &'loc Value, path: &Path) -> Result<&'loc Vec<Value>, Error> {
    return if let Value::List(list) = value {
        Ok(list)
    }
    else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying at path {} was not an array type {} to query", path, type_info(value))
        )))
    }
}

pub(super) fn match_map<'loc>(value: &'loc Value, path: &Path) -> Result<&'loc indexmap::IndexMap<String, Value>, Error> {
    return if let Value::Map(map) = value {
        Ok(map)
    }
    else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying at path {} was not a map type {}, to query", path, type_info(value))
        )))
    }
}

pub(super) fn retrieve_key<'loc>(key: &str, value: &'loc Value, path: &Path) -> Result<&'loc Value, Error> {
    let map = match_map(value, path)?;
    return if let Some(val) = map.get(key) {
        Ok(val)
    } else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying at path {}, key {} was not found", path, key)
        )))
    }
}

pub(super) fn retrieve_index<'loc>(index: i32, value: &'loc Value, path: &Path) -> Result<&'loc Value, Error> {
    let list = match_list(value, path)?;
    let check = if index >= 0 { index } else { -index };
    return if check < list.len() as i32 {
        Ok(&list[index as usize])
    }
    else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying at  path {} for index {} was not possible on array size {} to query",
                    path, index, list.len())
        )))
    }
}



