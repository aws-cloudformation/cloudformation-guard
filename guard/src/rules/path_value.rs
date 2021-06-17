use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
//
// Std Libraries
//
use std::fmt::Formatter;
use std::fmt::Write;
use serde::Serialize;


use crate::rules::evaluate::{AutoReport, resolve_query};
use crate::rules::EvaluationType;

use super::{Evaluate, EvaluationContext, Status};
use super::errors::{Error, ErrorKind};
use super::exprs::{QueryPart, SliceDisplay};
//
// Local mod
//
use super::values::*;
use crate::rules::exprs::LetValue;

//
// crate level
//

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub(crate) struct Path(pub(crate) String);

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Path {
    pub fn root() -> Self {
        Path("".to_string())
    }
}

impl TryFrom<&str> for Path {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Path(value.to_string()))
    }
}

impl TryFrom<&[&str]> for Path {
    type Error = Error;

    fn try_from(value: &[&str]) -> Result<Self, Self::Error> {
        Ok(Path(value.iter().map(|s| (*s).to_string())
            .fold(String::from(""), |mut acc, part| {
                if acc.is_empty() {
                    acc.push_str(part.as_str());
                } else {
                    acc.push('/'); acc.push_str(part.as_str());
                }
                acc
            })))
    }
}

impl TryFrom<&[String]> for Path {
    type Error = Error;

    fn try_from(value: &[String]) -> Result<Self, Self::Error> {
        let vec = value.iter().map(String::as_str).collect::<Vec<&str>>();
        Path::try_from(vec.as_slice())
    }
}

impl Path {
    pub(crate) fn extend_str(&self, part: &str) -> Path {
        let mut copy = self.0.clone();
        copy.push('/');
        copy.push_str(part);
        Path(copy)
    }

    pub(crate) fn extend_string(&self, part: &String) -> Path {
        self.extend_str(part.as_str())
    }

    pub(crate) fn extend_usize(&self, part: usize) -> Path {
        let as_str = part.to_string();
        self.extend_string(&as_str)
    }

    pub(crate) fn drop_last(&mut self) -> &mut Self {
        let removed = match self.0.rfind('/') {
            Some(idx) => self.0.as_str()[0..idx].to_string(),
            None => return self
        };
        self.0 = removed;
        self
    }

    pub(crate) fn extend_with_value(&self, part: &Value) -> Result<Path, Error> {
        match part {
            Value::String(s) => Ok(self.extend_string(s)),
            _ => Err(Error::new(ErrorKind::IncompatibleError(
                format!("Value type is not String, Value = {:?}", part)
            )))
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MapValue {
    keys: Vec<PathAwareValue>,
    values: indexmap::IndexMap<String, PathAwareValue>,
}

impl PartialEq for MapValue {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl MapValue {
    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}


#[derive(Debug, Clone, Serialize)]
pub(crate) enum PathAwareValue {
    Null(Path),
    String((Path, String)),
    Regex((Path, String)),
    Bool((Path, bool)),
    Int((Path, i64)),
    Float((Path, f64)),
    Char((Path, char)),
    List((Path, Vec<PathAwareValue>)),
    Map((Path, MapValue)),
    RangeInt((Path, RangeType<i64>)),
    RangeFloat((Path, RangeType<f64>)),
    RangeChar((Path, RangeType<char>)),
}

impl PartialEq for PathAwareValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PathAwareValue::Map((_, map)), PathAwareValue::Map((_, map2))) => map == map2,

            (PathAwareValue::List((_, list)), PathAwareValue::List((_, list2))) => list == list2,

            (PathAwareValue::Bool((_, b1)), PathAwareValue::Bool((_, b2))) => b1 == b2,

            (PathAwareValue::String((_, s)), PathAwareValue::Regex((_, r))) => {
                if let Ok(regex) = regex::Regex::new(r.as_str()) {
                    regex.is_match(s.as_str())
                } else {
                    false
                }
            },
            (PathAwareValue::Regex((_, r)), PathAwareValue::String((_, s))) =>  {
                if let Ok(regex) = regex::Regex::new(r.as_str()) {
                    regex.is_match(s.as_str())
                } else {
                    false
                }
            },
            (PathAwareValue::Regex((_, r)), PathAwareValue::Regex((_, s))) => r == s,

            //
            // Range checks
            //
            (PathAwareValue::Int((_, value)), PathAwareValue::RangeInt((_, r))) => {
                value.is_within(r)
            },

            (PathAwareValue::Float((_, value)), PathAwareValue::RangeFloat((_, r))) => {
                value.is_within(r)
            },

            (PathAwareValue::Char((_, value)), PathAwareValue::RangeChar((_, r))) => {
                value.is_within(r)
            },

            (rest, rest2) => match compare_values(rest, rest2) {
                    Ok(ordering) => match ordering {
                        Ordering::Equal => true,
                        _ => false
                    },
                    Err(_) => false
                }
        }
    }
}

impl TryFrom<&str> for PathAwareValue {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let value = Value::try_from(value)?;
        PathAwareValue::try_from((&value, Path::try_from("")?))
    }
}

impl TryFrom<(&str, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(value: (&str, Path)) -> Result<Self, Self::Error> {
        let parsed = Value::try_from(value.0)?;
        PathAwareValue::try_from((&parsed, value.1))
    }
}

impl TryFrom<(&serde_json::Value, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (&serde_json::Value, Path)) -> Result<Self, Self::Error> {
        let root = incoming.0;
        let path = incoming.1;
        let value = Value::try_from(root)?;
        PathAwareValue::try_from((&value, path))
    }
}

impl TryFrom<Value> for PathAwareValue {
    type Error = Error;

    fn try_from(value: Value) -> Result<Self, Self::Error> {
        PathAwareValue::try_from((&value, Path::root()))
    }
}

impl TryFrom<serde_json::Value> for PathAwareValue {
    type Error = Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        PathAwareValue::try_from((&value, Path::root()))
    }
}

impl TryFrom<(&Value, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (&Value, Path)) -> Result<Self, Self::Error> {
        let root = incoming.0;
        let path = incoming.1;

        match root {
            Value::String(s) => Ok(PathAwareValue::String((path, s.to_owned()))),
            Value::Int(num) => Ok(PathAwareValue::Int((path, *num))),
            Value::Float(flt) => Ok(PathAwareValue::Float((path, *flt))),
            Value::Regex(s) => Ok(PathAwareValue::Regex((path, s.clone()))),
            Value::Char(c) => Ok(PathAwareValue::Char((path, *c))),
            Value::RangeChar(r) => Ok(PathAwareValue::RangeChar((path, r.clone()))),
            Value::RangeInt(r) => Ok(PathAwareValue::RangeInt((path, r.clone()))),
            Value::RangeFloat(r) => Ok(PathAwareValue::RangeFloat((path, r.clone()))),
            Value::Bool(b) => Ok(PathAwareValue::Bool((path, *b))),
            Value::Null => Ok(PathAwareValue::Null(path)),
            Value::List(v) => {
                let mut result: Vec<PathAwareValue> = Vec::with_capacity(v.len());
                for (idx, each) in v.iter().enumerate() {
                    let sub_path = path.extend_usize(idx);
                    let value = PathAwareValue::try_from((each, sub_path.clone()))?;
                    result.push(value);
                }
                Ok(PathAwareValue::List((path, result)))
            },

            Value::Map(map) => {
                let mut keys = Vec::with_capacity(map.len());
                let mut values = indexmap::IndexMap::with_capacity(map.len());
                for each_key in map.keys() {
                    let sub_path = path.extend_string(each_key);
                    let value = PathAwareValue::String((sub_path, each_key.to_string()));
                    keys.push(value);
                }

                for (each_key, each_value) in map {
                    let sub_path = path.extend_string(each_key);
                    let value = PathAwareValue::try_from((each_value, sub_path))?;
                    values.insert(each_key.to_owned(), value);
                }
                Ok(PathAwareValue::Map((path, MapValue{keys, values})))
            }
        }
    }
}

impl<'a> TryInto<(String, serde_json::Value)> for &'a PathAwareValue {
    type Error = Error;

    fn try_into(self) -> std::result::Result<(String, serde_json::Value), Self::Error> {
        let top = self.self_path().0.clone();
        match self {
            PathAwareValue::Null(_) => Ok((top, serde_json::Value::Null)),
            PathAwareValue::String((_, s)) => Ok((top, serde_json::Value::String(s.clone()))),
            PathAwareValue::Regex((_, r)) => Ok((top, serde_json::Value::String(format!("/{}/", r)))),
            PathAwareValue::Bool((_, bool_)) => Ok((top, serde_json::Value::Bool(*bool_))),
            PathAwareValue::Int((_, i64_)) => Ok((top, serde_json::Value::Number(serde_json::Number::from(*i64_)))),
            PathAwareValue::Float((_, f64_)) => Ok((top, serde_json::Value::Number(
                match serde_json::Number::from_f64(*f64_) {
                    Some(num) => num,
                    None => return Err(Error::new(ErrorKind::IncompatibleError(
                        format!("Could not convert float {} to serde::Value::Number", *f64_)
                    )))
                }))),
            PathAwareValue::Char((_, char_)) => Ok((top, serde_json::Value::String(char_.to_string()))),

            PathAwareValue::List((_, list)) => {
                let mut values = Vec::with_capacity(list.len());
                for each in list {
                    let (_, val): (String, serde_json::Value) = each.try_into()?;
                    values.push(val);
                }
                Ok((top, serde_json::Value::Array(values)))
            },

            PathAwareValue::Map((_, map)) => {
                let mut values = serde_json::Map::new();
                for (key, value) in map.values.iter() {
                    let (_, val): (String, serde_json::Value) = value.try_into()?;
                    values.insert(key.clone(), val);
                }
                Ok((top, serde_json::Value::Object(values)))
            },

            PathAwareValue::RangeFloat((_, range_)) => {
                let range_encoding = format!("{}{},{}{}",
                                             if range_.inclusive & LOWER_INCLUSIVE > 0 { "[" } else { "(" },
                                             range_.lower, range_.upper,
                                             if range_.inclusive & UPPER_INCLUSIVE > 0{ "]" } else { ")" },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            },

            PathAwareValue::RangeChar((_, range_)) => {
                let range_encoding = format!("{}{},{}{}",
                                             if range_.inclusive & LOWER_INCLUSIVE > 0 { "[" } else { "(" },
                                             range_.lower, range_.upper,
                                             if range_.inclusive & UPPER_INCLUSIVE > 0{ "]" } else { ")" },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            },

            PathAwareValue::RangeInt((_, range_)) => {
                let range_encoding = format!("{}{},{}{}",
                           if range_.inclusive & LOWER_INCLUSIVE > 0 { "[" } else { "(" },
                           range_.lower, range_.upper,
                           if range_.inclusive & UPPER_INCLUSIVE > 0{ "]" } else { ")" },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            },
        }
    }
}

pub(crate) trait QueryResolver {
    fn select(&self, all: bool, query: &[QueryPart<'_>], eval: &dyn EvaluationContext) -> Result<Vec<&PathAwareValue>, Error>;
}

impl QueryResolver for PathAwareValue {
    fn select(&self, all: bool, query: &[QueryPart<'_>], resolver: &dyn EvaluationContext) -> Result<Vec<&PathAwareValue>, Error> {
        if query.is_empty() {
            return Ok(vec![self])
        }

        match &query[0] {
            QueryPart::This => {
                self.select(all, &query[1..], resolver)
            }

            QueryPart::Key(key) => {
                match key.parse::<i32>() {
                    Ok(index) => {
                        match self {
                            PathAwareValue::List((_, list)) => {
                                PathAwareValue::retrieve_index(self, index, list, query)
                                    .map_or_else(|e| self.map_error_or_empty(all, e),
                                                 |val| val.select(all, &query[1..], resolver))
                            }

                            _ => self.map_some_or_error_all(all, query)
                        }
                    },

                    Err(_) => match self {
                        PathAwareValue::Map((path, map)) => {
                            //
                            // Variable interpolation support.
                            //
                            if query[0].is_variable() {
                                let var = query[0].variable().unwrap();
                                let keys = resolver.resolve_variable(var)?;
                                let mut acc = Vec::with_capacity(keys.len());
                                let keys = if query.len() > 1 {
                                    match query[1] {
                                        QueryPart::AllIndices | QueryPart::Key(_) => keys,
                                        QueryPart::Index(index) => {
                                            let check = if index >= 0 { index } else { -index } as usize;
                                            if check < keys.len() {
                                                vec![keys[check]]
                                            } else {
                                                self.map_some_or_error_all(all, query)?
                                            }
                                        },

                                        _ => return Err(Error::new(ErrorKind::IncompatibleError(
                                            format!("THIS type of variable interpolation is not supported {}, {}", self.type_info(), SliceDisplay(query))
                                        )))
                                    }
                                } else {
                                    keys
                                };
                                for each_key in keys {
                                    if let PathAwareValue::String((_, k)) = each_key {
                                        if let Some(next) = map.values.get(k) {
                                            acc.extend(
                                                next.select(all, &query[1..], resolver)?);
                                        }
                                        else if all {
                                            return Err(Error::new(
                                                ErrorKind::RetrievalError(
                                                    format!("Could not locate key = {} inside object/map = {:?}, Path = {}, remaining query = {}",
                                                            key, self, path, SliceDisplay(query))
                                                )))
                                        }
                                    }
                                    else {
                                       return Err(Error::new(
                                           ErrorKind::NotComparable(
                                               format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                   SliceDisplay(query),
                                                   each_key.type_info(),
                                                   each_key.self_value()
                                               )
                                           )
                                       ))
                                    }
                                }
                                Ok(acc)
                            }
                            else if let Some(next) = map.values.get(key) {
                                next.select(all, &query[1..], resolver)
                            } else {
                                self.map_some_or_error_all(all, query)
                            }
                        },

                        _ => self.map_some_or_error_all(all, query)
                    }
                }
            },

            QueryPart::Index(array_idx) => {
                match self {
                    PathAwareValue::List((_path, vec)) => {
                        PathAwareValue::retrieve_index(self, *array_idx, vec, query)
                            .map_or_else(|e| self.map_error_or_empty(all, e),
                                         |val| val.select(all, &query[1..], resolver))

                    },

                    _ => self.map_some_or_error_all(all, query)
                }
            },

            QueryPart::AllIndices => {
                match self {
                    PathAwareValue::List((_path, elements)) => {
                        PathAwareValue::accumulate(self, all, &query[1..], elements, resolver)
                    },

                    //
                    // Often in the place where a list of values is accepted
                    // single values often are accepted. So proceed to the next
                    // part of your query
                    //
                    rest => {
                        rest.select(all, &query[1..], resolver)
                    }
                }
            }

            QueryPart::AllValues => {
                match self {
                    //
                    // Supporting old format
                    //
                    PathAwareValue::List((_path, elements)) => {
                        PathAwareValue::accumulate(self, all, &query[1..], elements, resolver)
                    },

                    PathAwareValue::Map((_path, map)) => {
                        let values: Vec<&PathAwareValue> = map.values.values().collect();
                        let mut resolved = Vec::with_capacity(values.len());
                        for each in values {
                            resolved.extend(
                                each.select(all, &query[1..], resolver)?);
                        }
                        Ok(resolved)
                    },

                    //
                    // Often in the place where a list of values is accepted
                    // single values often are accepted. So proceed to the next
                    // part of your query
                    //
                    rest => {
                        rest.select(all, &query[1..], resolver)
                    }
                }
            },

            QueryPart::MapKeyFilter(filter) => {
                match self {
                    PathAwareValue::Map((path, map)) => {
                        let mut selected = Vec::with_capacity(map.values.len());
                        match &filter.compare_with {
                            LetValue::AccessClause(query) => {
                                let values = resolve_query(false, &query.query, self, resolver)?;
                                for key in map.keys.iter() {
                                    if values.contains(&key) {
                                        match key {
                                            PathAwareValue::String((_, v)) => {
                                                selected.push(map.values.get(v).unwrap());
                                            },
                                            _ => unreachable!()
                                        }
                                    }
                                }
                            },

                            LetValue::Value(v) => {
                                let path_value = PathAwareValue::try_from((v, path.clone()))?;
                                for key in map.keys.iter() {
                                    if key == &path_value {
                                        match key {
                                            PathAwareValue::String((_, v)) => {
                                                selected.push(map.values.get(v).unwrap());
                                            },
                                            _ => unreachable!()
                                        }
                                    }
                                }
                            },
                        };
                        if query.len() > 1 {
                            let mut acc = Vec::with_capacity(selected.len());
                            for each in selected {
                                acc.extend(each.select(all, &query[1..], resolver)?)
                            }
                            Ok(acc)
                        } else {
                            Ok(selected)
                        }

                    },

                    _ => self.map_some_or_error_all(all, query)
                }
            },

            QueryPart::Filter(conjunctions) => {
                match self {
                    PathAwareValue::List((path, vec)) => {
                        let mut selected = Vec::with_capacity(vec.len());
                        let context = format!("Path={},Type=Array", path);
                        for each in vec {
                            let mut filter = AutoReport::new(EvaluationType::Filter, resolver, &context);
                            match conjunctions.evaluate(each, resolver) {
                                Err(Error(ErrorKind::RetrievalError(e))) => {
                                    if all {
                                        return Err(Error::new(ErrorKind::RetrievalError(e)))
                                    }
                                    // Else treat is like a filter
                                },
                                Err(Error(ErrorKind::IncompatibleRetrievalError(e))) => {
                                    if all {
                                        return Err(Error::new(ErrorKind::IncompatibleRetrievalError(e)))
                                    }
                                    // Else treat is like a filter
                                },
                                Err(e) => return Err(e),
                                Ok(status) => {
                                    match status {
                                        Status::PASS => {
                                            filter.status(Status::PASS);
                                            let index: usize = if query.len() > 1 {
                                                match &query[1] {
                                                    QueryPart::AllIndices => 2,
                                                    _ => 1
                                                }
                                            } else { 1 };
                                            selected.extend(each.select(all, &query[index..], resolver)?);
                                        },
                                        rest => { filter.status(rest); }
                                    }
                                }
                            }
                        }
                        Ok(selected)
                    },

                    PathAwareValue::Map((path, _map)) => {
                        let context = format!("Path={},Type=MapElement", path);
                        let mut filter = AutoReport::new(EvaluationType::Filter, resolver, &context);
                        conjunctions.evaluate(self, resolver)
                            .map_or_else(
                                |e| self.map_error_or_empty(all, e),
                                |status| {
                                    match status {
                                        Status::PASS => {
                                            filter.status(Status::PASS);
                                            self.select(all, &query[1..], resolver)
                                        },
                                        rest => {
                                            filter.status(rest);
                                            Ok(vec![])
                                        }

                                    }
                                }
                            )
                    }

                    _ => self.map_some_or_error_all(all, query)
                }
            },
        }
    }
}

impl PathAwareValue {

    pub(crate) fn is_list(&self) -> bool {
        match self {
            PathAwareValue::List((_, _)) => true,
            _ => false,
        }
    }

    pub(crate) fn is_map(&self) -> bool {
        match self {
            PathAwareValue::Map((_, _)) => true,
            _ => false
        }
    }

    fn map_error_or_empty(&self, all: bool, e: Error) -> Result<Vec<&PathAwareValue>, Error> {
        if !all {
            match e {
                Error(ErrorKind::IncompatibleRetrievalError(_)) |
                Error(ErrorKind::RetrievalError(_)) => Ok(vec![]),

                rest => return Err(rest)
            }
        }
        else {
            return Err(e)
        }
    }

    fn map_some_or_error_all(&self, all: bool, query: &[QueryPart<'_>]) -> Result<Vec<&PathAwareValue>, Error> {
        if all {
            Err(Error::new(ErrorKind::IncompatibleRetrievalError(
                format!("Attempting to retrieve array index or key from map at path = {} , Type was not an array/object {}, Remaining Query = {}",
                        self.self_value().0, self.type_info(), SliceDisplay(query))
            )))
        } else {
            Ok(vec![])
        }
    }

    pub(crate) fn is_scalar(&self) -> bool {
        !self.is_list() || !self.is_map()
    }

    pub(crate) fn self_path(&self) -> &Path {
        self.self_value().0
    }

    pub(crate) fn self_value(&self) -> (&Path, &PathAwareValue) {
        match self {
            PathAwareValue::Null(path)              => (path, self),
            PathAwareValue::String((path, _))       => (path, self),
            PathAwareValue::Regex((path, _))        => (path, self),
            PathAwareValue::Bool((path, _))         => (path, self),
            PathAwareValue::Int((path, _))          => (path, self),
            PathAwareValue::Float((path, _))        => (path, self),
            PathAwareValue::Char((path, _))         => (path, self),
            PathAwareValue::List((path, _))         => (path, self),
            PathAwareValue::Map((path, _))          => (path, self),
            PathAwareValue::RangeInt((path, _))     => (path, self),
            PathAwareValue::RangeFloat((path, _))   => (path, self),
            PathAwareValue::RangeChar((path, _))    => (path, self),
        }
    }

    pub(crate) fn type_info(&self) -> &'static str {
        match self {
            PathAwareValue::Null(_path)              => "null",
            PathAwareValue::String((_path, _))       => "String",
            PathAwareValue::Regex((_path, _))        => "Regex",
            PathAwareValue::Bool((_path, _))         => "bool",
            PathAwareValue::Int((_path, _))          => "int",
            PathAwareValue::Float((_path, _))        => "float",
            PathAwareValue::Char((_path, _))         => "char",
            PathAwareValue::List((_path, _))         => "array",
            PathAwareValue::Map((_path, _))          => "map",
            PathAwareValue::RangeInt((_path, _))     => "range(int, int)",
            PathAwareValue::RangeFloat((_path, _))   => "range(float, float)",
            PathAwareValue::RangeChar((_path, _))    => "range(char, char)",
        }
    }

    pub(crate) fn retrieve_index<'v>(parent: &PathAwareValue, index: i32, list: &'v Vec<PathAwareValue>, query: &[QueryPart<'_>]) -> Result<&'v PathAwareValue, Error> {
        let check = if index >= 0 { index } else { -index } as usize;
        if check < list.len() {
            Ok(&list[check])
        } else {
            Err(Error::new(
                ErrorKind::RetrievalError(
                    format!("Array Index out of bounds for path = {} on index = {} inside Array = {:?}, remaining query = {}",
                           parent.self_path(), index, list, SliceDisplay(query))
                )))
        }

    }

    pub(crate) fn accumulate<'v>(parent: &PathAwareValue, all: bool, query: &[QueryPart<'_>], elements: &'v Vec<PathAwareValue>, resolver: &dyn EvaluationContext) -> Result<Vec<&'v PathAwareValue>, Error>{
        if elements.is_empty() && !query.is_empty() && all {
            return Err(Error::new(ErrorKind::RetrievalError(
                format!("No entries for path = {} . Remaining Query {}", parent.self_path(), SliceDisplay(query))
            )));
        }

        let mut accumulated = Vec::with_capacity(elements.len());
        for each in elements {
            if !query.is_empty() {
                accumulated.extend(each.select(all, query, resolver)?);
            }
            else {
                accumulated.push(each);
            }
        }
        Ok(accumulated)

    }
}

fn compare_values(first: &PathAwareValue, other: &PathAwareValue) -> Result<Ordering, Error> {
    match (first, other) {
        //
        // scalar values
        //
        (PathAwareValue::Null(_), PathAwareValue::Null(_)) => Ok(Ordering::Equal),
        (PathAwareValue::Int((_, i)), PathAwareValue::Int((_, o))) => Ok(i.cmp(o)),
        (PathAwareValue::String((_, s)), PathAwareValue::String((_, o))) => Ok(s.cmp(o)),
        (PathAwareValue::Float((_, f)), PathAwareValue::Float((_, s))) => match f.partial_cmp(s) {
            Some(o) => Ok(o),
            None => Err(Error::new(ErrorKind::NotComparable("Float values are not comparable".to_owned())))
        },
        (PathAwareValue::Char((_, f)), PathAwareValue::Char((_, s))) => Ok(f.cmp(s)),
        (_, _) => Err(Error::new(ErrorKind::NotComparable(
            format!("PathAwareValues are not comparable {}, {}", first.type_info(), other.type_info()))))
    }
}

pub(crate) fn compare_eq(first: &PathAwareValue, second: &PathAwareValue) -> Result<bool, Error> {
    let (reg, s) = match (first, second) {
        (PathAwareValue::String((_, s)), PathAwareValue::Regex((_, r))) => (regex::Regex::new(r.as_str())?, s.as_str()),
        (PathAwareValue::Regex((_, r)), PathAwareValue::String((_, s))) => (regex::Regex::new(r.as_str())?, s.as_str()),
        (_,_) => return Ok(first == second),
    };
    Ok(reg.is_match(s))
}

pub(crate) fn compare_lt(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Equal | Ordering::Greater => Ok(false),
            Ordering::Less => Ok(true)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_le(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(false),
            Ordering::Equal | Ordering::Less => Ok(true)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_gt(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(true),
            Ordering::Less | Ordering::Equal => Ok(false)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_ge(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater | Ordering::Equal => Ok(true),
            Ordering::Less => Ok(false)
        },
        Err(e) => Err(e)
    }
}

#[cfg(test)]
#[path = "path_value_tests.rs"]
mod path_value_tests;

