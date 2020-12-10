//
// This file implements query semantics on structure Value types
//

use crate::rules::values::*;
use crate::errors::{Error, ErrorKind};
use std::convert::TryFrom;
use std::collections::HashMap;
use super::*;

use std::hash::{Hash, Hasher};
use std::fmt::Formatter;

impl Path {
    pub(super) fn append_str(mut self, path: &str) -> Self {
        self.append(path.to_owned())
    }

    pub(super) fn append(mut self, path: String) -> Self {
        self.pointers.push(path);
        Path {
            pointers: self.pointers
        }
    }

}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.pointers.join("/");
        f.write_str(&str);
        Ok(())
    }
}

impl<'loc> QueryResult<'loc> {
    fn result(self) -> HashMap<Path, Vec<&'loc Value>> {
        self.result
    }
}

impl<'loc> Hash for QueryResult<'loc> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.query.hash(state);
    }
}

impl<'loc> Eq for QueryResult<'loc> {}

impl Evaluate for FilterPart {
    type Item = bool;

    fn evaluate(&self, context: &Value, path: &Path) -> Result<Self::Item, Error> {
        let map = match_map(context, path)?;
        let cmp = match &self.value {
            Some(VariableOrValue::Value(v)) => Some(v),
            Some(VariableOrValue::Variable(var)) =>
                return Err(Error::new(ErrorKind::NotComparable(
                    format!("Currently we do not support interpolation of variables, VAR = {}", var)
                ))),
            None => None, // The parser already ensures that the right operator has the right arguments
        };

        return if let Some(value) = map.get(&self.name) {
            let invert= |r:bool| if self.comparator.1 { !r } else { r };
            match &self.comparator.0 {
                CmpOperator::Exists => Ok(invert(true)),
                CmpOperator::Empty  => {
                    let list = match_list(value, path)?;
                    Ok(invert(list.is_empty()))
                },

                CmpOperator::Lt => Ok(invert(compare_lt(value, cmp.unwrap())?)),
                CmpOperator::Le => Ok(invert(compare_le(value, cmp.unwrap())?)),
                CmpOperator::Gt => Ok(invert(compare_gt(value, cmp.unwrap())?)),
                CmpOperator::Ge => Ok(invert(compare_ge(value, cmp.unwrap())?)),
                CmpOperator::In => {
                    let list = match_list(cmp.unwrap(), path)?;
                    let result = 'outer_in: loop {
                        for each in list {
                            if compare_eq(value, each)? {
                                break 'outer_in true
                            }
                        }
                        break false
                    };
                    Ok(invert(result))
                },
                CmpOperator::Eq => Ok(invert(compare_eq(value, cmp.unwrap())?)),

                CmpOperator::KeysEmpty => {
                    let keys = match_map(value, path)?;
                    Ok((invert(keys.is_empty())))
                },

                CmpOperator::KeysExists => {
                    let keys = match_map(value, path)?;
                    Ok((invert(!keys.is_empty())))
                },

                CmpOperator::KeysEq => {
                    let keys = match_map(value, path)?;
                    let result = 'outer_keys: loop {
                        for each in keys.keys() {
                            let val = Value::String(String::from(each));
                            if !compare_eq(cmp.unwrap(), &val)? {
                                break 'outer_keys false
                            }
                        }
                        break true
                    };
                    Ok((invert(result)))
                },

                CmpOperator::KeysIn => {
                    let keys = match_map(value, path)?;
                    let result = 'outer_keys_in: loop {
                        for each in keys.keys() {
                            let val = Value::String(String::from(each));
                            if compare_eq(cmp.unwrap(), &val)? {
                                break 'outer_keys_in true
                            }
                        }
                        break false
                    };
                    Ok(invert(result))
                }

            }
        }
        else {
            Err(Error::new(ErrorKind::RetrievalError(
                format!("Attempting to apply predicate filter for {} FAILED as NO KEY = {} was present", self, self.name)
            )))
        }
    }
}

impl std::fmt::Display for FilterPart {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Key = {}, Comparison = {:?}", self.name, self.comparator.0))?;
        Ok(())
    }
}

fn match_list<'loc>(value: &'loc Value, path: &Path) -> Result<&'loc Vec<Value>, Error> {
    return if let Value::List(list) = value {
        Ok(list)
    }
    else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying at path {} was not an array type {} to query", path, type_info(value))
        )))
    }
}

fn match_map<'loc>(value: &'loc Value, path: &Path) -> Result<&'loc indexmap::IndexMap<String, Value>, Error> {
    return if let Value::Map(map) = value {
        Ok(map)
    }
    else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying at path {} was not a map type {}, to query", path, type_info(value))
        )))
    }
}

fn retrieve_key<'loc>(key: &str, value: &'loc Value, path: &Path, query: &[QueryPart]) -> Result<&'loc Value, Error> {
    let map = match_map(value, path)?;
    return if let Some(val) = map.get(key) {
        Ok(val)
    } else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying {:?} at path {} was next key {} was not found", query, path, key)
        )))
    }
}

fn retrieve_index<'loc>(index: i32, value: &'loc Value, path: &Path, query: &[QueryPart]) -> Result<&'loc Value, Error> {
    let list = match_list(value, path)?;
    let check = if index >= 0 { index } else { -index };
    return if check < list.len() as i32 {
        Ok(&list[index as usize])
    }
    else {
        Err(Error::new(ErrorKind::RetrievalError(
            format!("Querying {:?} at path {} for index {} was not possible on array size {} to query",
                    query, path, index, list.len())
        )))
    }
}

fn select(criteria: &Conjunctions<FilterPart>, value: &Value, path: &Path) -> Result<bool, Error> {
    let selected = 'outer: loop {
        for each in criteria {
            let disjunctions = 'disjunctions: loop {
                for each_or_clause in each {
                    if each_or_clause.evaluate(value, path)? {
                        break 'disjunctions true
                    }
                }
                break false
            };
            if !disjunctions {
                break 'outer false
            }
        }
        break true
    };
    Ok(selected)
}

pub(super) fn query_value<'loc>(query: &'loc[QueryPart], value: &'loc Value, path: Path) -> Result<QueryResult<'loc>, Error> {
    let mut result: HashMap<Path, Vec<&Value>> = HashMap::new();
    let mut value_ref = value;
    let mut path_ref = path;
    for (idx, part) in query.iter().enumerate() {
        match part {
            QueryPart::Key(key) => {
                value_ref = retrieve_key(key, value_ref, &path_ref, query)?;
                path_ref = path_ref.append_str(key);
            }

            QueryPart::Index(key, index) => {
                value_ref = retrieve_key(key, value_ref, &path_ref, query)?;
                path_ref = path_ref.append_str(key);
                value_ref = retrieve_index(*index, value_ref, &path_ref, query)?;
                path_ref = path_ref.append(index.to_string())
            },

            QueryPart::Filter(name, parts) => {
                if name == "*" {
                    return if let Value::Map(current) = value_ref {
                        for (key, value) in current.iter() {
                            if select(parts, value, &path_ref)? {
                                let sub_path = path_ref.clone().append_str(key);
                                let sub_query = query_value(
                                    &query[idx + 1..], value, sub_path)?;
                                result.extend(sub_query.result());
                            }
                        }
                        Ok(QueryResult { result, query })
                    }
                    else {
                        Err(Error::new(ErrorKind::RetrievalError(
                            format!("Querying {:?} at path {} was not a map type {}, to query", query, path_ref, type_info(value))
                        )))
                    }
                }
                value_ref = retrieve_key(name, value_ref, &path_ref, query)?;
                path_ref = path_ref.append_str(name);
                for (idx, value) in match_list(value_ref, &path_ref)?.iter().enumerate() {
                    if select(parts, value, &path_ref)? {
                        let sub_path = path_ref.clone().append(idx.to_string());
                        let sub_query = query_value(
                            &query[idx + 1..], value, sub_path)?;
                        result.extend(sub_query.result());
                    }
                }
                return Ok(QueryResult{ result, query })
            },

            QueryPart::AllIndices(name) => {
                value_ref = retrieve_key(name, value_ref, &path_ref, query)?;
                path_ref = path_ref.append_str(name);
                for (idx, value) in match_list(value_ref, &path_ref)?.iter().enumerate() {
                    let sub_path = path_ref.clone().append(idx.to_string());
                    let sub_query = query_value(
                        &query[idx + 1..], value, sub_path)?;
                    result.extend(sub_query.result());
                }
                return Ok(QueryResult { result, query })
            }

            _ => unimplemented!()
        }
    }

    result.insert(path_ref, vec![value_ref]);
    Ok((QueryResult {
        query,
        result,
    }))
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::collections::HashSet;
    use crate::rules::parser2::{parse_value, from_str2};

    #[test]
    fn test_query_result_hash() {
        let values = [
            Value::String(String::from("value")),
            Value::String(String::from("next")),
            Value::String(String::from("this")),
        ];
        let path_values = [
            (Path { pointers: vec![String::from("resources"), String::from("a") ] }, vec![&values[0]]),
            (Path { pointers: vec![String::from("resources"), String::from("b") ] }, vec![&values[1]]),
            (Path { pointers: vec![String::from("resources"), String::from("c") ] }, vec![&values[2]]),
        ].to_vec().into_iter().collect::<HashMap<Path, Vec<&Value>>>();

        let query = [
            QueryPart::Key(String::from("a")),
            QueryPart::Key(String::from("b")),
            QueryPart::Key(String::from("c")),
        ];

        let mut query2 = query.to_vec();
        query2.push(QueryPart::AllIndices(String::from("tags")));


        let result1 = QueryResult { query: &query, result: path_values.clone() };
        let result2 = QueryResult { query: &query, result: path_values.clone() };
        let result3 = QueryResult { query: &query2, result: path_values };

        assert_eq!(result1, result2);
        assert_ne!(result1, result3);
        let mut set = HashSet::with_capacity(2);
        set.insert(result1);
        assert_eq!(set.contains(&result2), true);
        assert_eq!(set.insert(result3), true);
    }

    #[test]
    fn test_filter_part() -> Result<(), Error> {
        let value = parse_value(from_str2(r#"
        {
            prod-id: "prod-id",
            app-id: "app-IDxer4543634",
            env-id: "env-IDsdse34"
        }
        "#))?;
        Ok(())
    }
}
