//
// This file implements query semantics on structure Value types
//

use crate::rules::values::*;
use crate::errors::{Error, ErrorKind};
use std::collections::HashMap;
use super::*;
use super::helper::*;

use std::fmt::Formatter;

fn select(criteria: &Conjunctions<GuardClause>, value: &Value, path: &Path) -> Result<bool, Error> {
    let selected = 'outer: loop {
        for each in criteria {
            let disjunctions = 'disjunctions: loop {
                for each_or_clause in each {
                    // if each_or_clause.evaluate(value, path)? {
                        break 'disjunctions true
                    // }
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

fn handle_array<'loc>(array: &'loc Vec<Value>,
                      index: usize,
                      path: Path,
                      query: &[QueryPart<'_>],
                      scope: &Scope<'_>,
                      cache: &mut EvalContext<'_>) -> Result<ResolvedValues<'loc>, Error> {
    let mut results = ResolvedValues::new();
    for (each_idx, each_value) in array.iter().enumerate() {
        let sub_path = path.clone().append(each_idx.to_string());
        let sub_query = resolve_query(
            &query[index+1..], each_value, scope, sub_path, cache)?;
        results.extend(sub_query);
    }
    Ok(results)
}

fn handle_map<'loc>(map: &'loc indexmap::IndexMap<String, Value>,
                    index: usize,
                    path: Path,
                    query: &[QueryPart<'_>],
                    scope: &Scope<'_>,
                    cache: &mut EvalContext<'_>) -> Result<ResolvedValues<'loc>, Error> {

        let mut results = ResolvedValues::new();
    for (key, index_value) in map {
        let sub_path = path.clone().append_str(key);
        let sub_query = resolve_query(
            &query[index+1..], index_value, scope, sub_path, cache)?;
        results.extend(sub_query);
    }
    Ok(results)
}

pub(super) fn resolve_query<'loc>(query: &[QueryPart<'_>],
                                  value: &'loc Value,
                                  variables: &Scope<'_>,
                                  path: Path,
                                  cache: &mut EvalContext<'_>) -> Result<ResolvedValues<'loc>, Error> {

    let mut results = ResolvedValues::new();
    let mut value_ref = value;
    let mut path_ref = path;

    for (index, query_part) in query.iter().enumerate() {
        match query_part {

            QueryPart::Key(key) => {
                //
                // Support old format
                //
                match key.parse::<i32>() {
                    Ok(idx) => {
                        value_ref = retrieve_index(idx, value_ref, &path_ref)?;
                        path_ref = path_ref.append(idx.to_string());
                    },
                    Err(_) => {
                        value_ref = retrieve_key(key, value_ref, &path_ref)?;
                        path_ref = path_ref.append_str(key);
                    }
                }
            },

            QueryPart::Index(key, idx) => {
                value_ref = retrieve_key(key, value_ref, &path_ref)?;
                path_ref = path_ref.append_str(key);
                value_ref = retrieve_index(*idx, value_ref, &path_ref)?;
                path_ref = path_ref.append((*idx).to_string());
            },

            QueryPart::AllKeys => {
                //
                // Support old format
                //
                match match_list(value_ref, &path_ref) {
                    Err(_) =>
                        return handle_map(match_map(value_ref, &path_ref)?,
                                          index, path_ref, query, variables, cache),

                    Ok(array) =>
                        return handle_array(array, index,path_ref, query, variables, cache),
                }
            },

            QueryPart::AllIndices(key) => {
                value_ref = retrieve_key(key, value_ref, &path_ref)?;
                path_ref = path_ref.append_str(key);
                return handle_array( match_list(value_ref, &path_ref)?,
                    index, path_ref, query, variables, cache)
            },

            QueryPart::Variable(variable) => {
                let values = variables.get_resolutions_for_variable(variable)?;
                for each in values {
                    if let Value::String(key) = each {
                        let current = retrieve_key(key, value_ref, &path_ref)?;
                        let sub_path = path_ref.clone().append_str(key);
                        let sub_query = resolve_query(
                            &query[index+1..], current, variables, sub_path, cache)?;
                        results.extend(sub_query);
                    }
                    else {
                        return Err(Error::new(ErrorKind::RetrievalError(
                            format!("Resolved variable values is not a string {} for variable {}",
                                    type_info(each), variable)
                        )))
                    }
                }
                return Ok(results)
            }


            _ => unimplemented!()
        }
    }

    results.insert(path_ref, value_ref);
    Ok(results)
}

#[cfg(test)]
mod tests {

    use super::*;
    use std::collections::HashSet;
    use crate::rules::parser2::{parse_value, from_str2};
    use std::fs::File;
    use crate::commands::files::{get_files, read_file_content};
    use crate::rules::exprs::QueryCache;

    fn create_from_json() -> Result<Value, Error> {
        let file = File::open("assets/cfn-template.json")?;
        let context = read_file_content(file)?;
        Ok(parse_value(from_str2(&context))?.1)
    }

    #[test]
    fn test_resolve_query() -> Result<(), Error> {
        let root = create_from_json()?;
        let mut cache = EvalContext::new(&root);
        let scope = Scope::new();
        let path = Path::new(&["/"]);
        let map = match_map(&root, &path)?;

        //
        // Test base empty query
        //
        let values = resolve_query(&[], &root, &scope, Path::new(&["/"]), &mut cache)?;
        assert_eq!(values.len(), 1);
        assert_eq!(values.get(&Path::new(&["/"])), Some(&&root));

        //
        // Path = Resources
        //
        let query = AccessQuery::from([
            QueryPart::Key(String::from("Resources"))
        ]);
        let values = resolve_query(&query, &root, &scope, path.clone(), &mut cache)?;
        assert_eq!(values.len(), 1);
        assert_eq!(Some(values[&Path::new(&["/", "Resources"])]), map.get("Resources"));
        let from_root = map.get("Resources");
        assert!(values[&Path::new(&["/", "Resources"])] == map.get("Resources").unwrap());

        let resources_root = match_map(from_root.unwrap(), &path)?;
        //
        // Path = Resources.*
        //
        let query = AccessQuery::from([
            QueryPart::Key(String::from("Resources")),
            QueryPart::AllKeys
        ]);
        let values = resolve_query(&query, &root, &scope, path.clone(), &mut cache)?;
        assert_eq!(resources_root.len(), values.len());

        let paths = resources_root.keys().map(|s: &String| Path::new(&["/", "Resources", s.as_str()]))
            .collect::<Vec<Path>>();
        let paths_values = values.iter().map(|(path, _value)| path.clone())
            .collect::<Vec<Path>>();
        assert_eq!(paths_values, paths);

        //
        // Path = Resources.*.Type
        //
        let query = AccessQuery::from([
            QueryPart::Key(String::from("Resources")),
            QueryPart::AllKeys,
            QueryPart::Key(String::from("Type")),
        ]);
        let values = resolve_query(&query, &root, &scope, path.clone(), &mut cache)?;
        assert_eq!(resources_root.len(), values.len());
        let paths = resources_root.keys().map(|s: &String| Path::new(&["/", "Resources", s.as_str(), "Type"]))
            .collect::<Vec<Path>>();
        let paths_values = values.iter().map(|(path, _value)| path.clone())
            .collect::<Vec<Path>>();
        assert_eq!(paths_values, paths);

        let types = resources_root.values().map(|v|
            if let Value::Map(m) = v {
            m.get("Type").unwrap()
        } else { unreachable!() }).collect::<Vec<&Value>>();

        let types_values = values.iter().map(|(_path, value)| *value).collect::<Vec<&Value>>();
        assert_eq!(types_values, types);

        let mut scope = Scope::new();
        let value_literals = vec![
            Value::String(String::from("Type")),
            Value::String(String::from("Properties"))
        ];
        let value_resolutions = vec![
            (path.clone(), &value_literals[0]),
            (path.clone().append_str("/"), &value_literals[1]),
        ];
        let resolutions = value_resolutions.into_iter().collect::<ResolvedValues>();

        scope.add_variable_resolution("interested", resolutions);

        //
        // Path = Resources.*.%interested
        //
        let query = AccessQuery::from([
            QueryPart::Key(String::from("Resources")),
            QueryPart::AllKeys,
            QueryPart::Variable(String::from("interested")),
        ]);
        let values = resolve_query(&query, &root, &scope, path.clone(), &mut cache)?;
        assert_eq!(resources_root.len() * 2, values.len()); // one for types and the other for properties
        let paths = resources_root.keys().map(|s: &String| Path::new(&["/", "Resources", s.as_str(), "Type"]))
            .collect::<Vec<Path>>();
        let paths_properties = resources_root.keys().map(|s: &String| Path::new(&["/", "Resources", s.as_str(), "Properties"]))
            .collect::<Vec<Path>>();

        let mut overall: Vec<Path> = Vec::with_capacity(paths.len() * 2);
        for (first, second) in paths.iter().zip(paths_properties.iter()) {
            overall.push(first.clone());
            overall.push(second.clone());
        }

        let paths = overall;
        let paths_values = values.iter().map(|(path, _value)| path.clone())
            .collect::<Vec<Path>>();
        assert_eq!(paths_values, paths);

        let types = resources_root.values().map(|v|
            if let Value::Map(m) = v {
                m.get("Type").unwrap()
            } else { unreachable!() }).collect::<Vec<&Value>>();
        let properties = resources_root.values().map(|v|
            if let Value::Map(m) = v {
                m.get("Properties").unwrap()
            } else { unreachable!() }).collect::<Vec<&Value>>();

        let mut combined: Vec<&Value> = Vec::with_capacity(types.len() * 2);
        for (first, second) in types.iter().zip(properties.iter()) {
            combined.push(first);
            combined.push(second);
        }

        let types_values = values.iter().map(|(_path, value)| *value).collect::<Vec<&Value>>();
        assert_eq!(types_values, combined);


        Ok(())
    }

}
