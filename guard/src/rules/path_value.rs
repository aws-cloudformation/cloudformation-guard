pub(crate) mod traversal;

use std::cmp::Ordering;
use std::convert::{TryFrom, TryInto};
//
// Std Libraries
//
use serde::{Deserialize, Serialize, Serializer};
use std::fmt::Formatter;

use crate::rules::evaluate::{resolve_query, AutoReport};
use crate::rules::EvaluationType;

use super::errors::Error;
use super::exprs::{QueryPart, SliceDisplay};
use super::{Evaluate, EvaluationContext, Status};
//
// Local mod
//
use super::values::*;
use crate::rules::exprs::LetValue;
use fancy_regex::Regex;
use serde::ser::{SerializeMap, SerializeStruct};
use std::hash::{Hash, Hasher};

//
// crate level
//
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub(crate) struct Location {
    pub(crate) line: usize,
    pub(crate) col: usize,
}

impl Location {
    #[cfg(test)]
    pub(crate) fn new(line: usize, col: usize) -> Self {
        Location { line, col }
    }
}

impl std::fmt::Display for Location {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("L:{},C:{}", self.line, self.col))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) struct Path(pub(crate) String, pub(crate) Location);

impl Path {
    #[cfg(test)]
    pub(crate) fn new(path: String, line: usize, col: usize) -> Path {
        Path(path, Location::new(line, col))
    }

    pub(crate) fn with_location(&self, loc: Location) -> Self {
        Path(self.0.clone(), loc)
    }
}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}[{}]", self.0, self.1))
    }
}

impl Path {
    pub(crate) fn root() -> Self {
        Path("".to_string(), Location::default())
    }

    pub(crate) fn relative(&self) -> &str {
        match self.0.rfind('/') {
            Some(pos) => &self.0[pos + 1..],
            None => &self.0,
        }
    }
}

impl TryFrom<&str> for Path {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(Path(value.to_string(), Location::default()))
    }
}

impl TryFrom<&[&str]> for Path {
    type Error = Error;

    fn try_from(value: &[&str]) -> Result<Self, Self::Error> {
        Ok(Path(
            value
                .iter()
                .map(|s| (*s).to_string())
                .fold(String::from(""), |mut acc, part| {
                    if acc.is_empty() {
                        acc.push_str(part.as_str());
                    } else {
                        acc.push('/');
                        acc.push_str(part.as_str());
                    }
                    acc
                }),
            Location::default(),
        ))
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
        Path(copy, self.1)
    }

    pub(crate) fn extend_string(&self, part: &str) -> Path {
        self.extend_str(part)
    }

    pub(crate) fn extend_usize(&self, part: usize) -> Path {
        let as_str = part.to_string();
        self.extend_string(&as_str)
    }
}

#[derive(Debug, Clone, Deserialize)]
pub(crate) struct MapValue {
    pub(crate) keys: Vec<PathAwareValue>,
    pub(crate) values: indexmap::IndexMap<String, PathAwareValue>,
}

impl Serialize for MapValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(Some(self.values.len()))?;
        for (key, value) in self.values.iter() {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl PartialEq for MapValue {
    fn eq(&self, other: &Self) -> bool {
        self.values == other.values
    }
}

impl Eq for MapValue {}

impl MapValue {
    pub(crate) fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

#[derive(Debug, Clone, Deserialize)]
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

impl Hash for PathAwareValue {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            PathAwareValue::String((_, s)) | PathAwareValue::Regex((_, s)) => {
                s.hash(state);
            }

            PathAwareValue::Char((_, c)) => {
                c.hash(state);
            }
            PathAwareValue::Int((_, i)) => {
                i.hash(state);
            }
            PathAwareValue::Null(_) => {
                "NULL".hash(state);
            }
            PathAwareValue::Float((_, f)) => {
                (*f as u64).hash(state);
            }

            PathAwareValue::RangeChar((_, r)) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            }

            PathAwareValue::RangeInt((_, r)) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            }

            PathAwareValue::RangeFloat((_, r)) => {
                (r.lower as u64).hash(state);
                (r.upper as u64).hash(state);
                r.inclusive.hash(state);
            }

            PathAwareValue::Bool((_, b)) => {
                b.hash(state);
            }

            PathAwareValue::List((_, l)) => {
                for each in l {
                    each.hash(state);
                }
            }

            PathAwareValue::Map((_, map)) => {
                for (key, value) in map.values.iter() {
                    key.hash(state);
                    value.hash(state);
                }
            }
        }
    }
}

impl PartialEq for PathAwareValue {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (PathAwareValue::Map((_, map)), PathAwareValue::Map((_, map2))) => map == map2,

            (PathAwareValue::List((_, list)), PathAwareValue::List((_, list2))) => list == list2,

            (PathAwareValue::Bool((_, b1)), PathAwareValue::Bool((_, b2))) => b1 == b2,

            (PathAwareValue::String((_, s)), PathAwareValue::Regex((_, r))) => {
                if let Ok(regex) = Regex::new(r.as_str()) {
                    regex.is_match(s.as_str()).unwrap() // given that we have already validated the regular expression
                } else {
                    false
                }
            }
            (PathAwareValue::Regex((_, r)), PathAwareValue::String((_, s))) => {
                if let Ok(regex) = Regex::new(r.as_str()) {
                    regex.is_match(s.as_str()).unwrap() // given that we have already validated the regular expression
                } else {
                    false
                }
            }
            (PathAwareValue::Regex((_, r)), PathAwareValue::Regex((_, s))) => r == s,

            //
            // Range checks
            //
            (PathAwareValue::Int((_, value)), PathAwareValue::RangeInt((_, r))) => {
                value.is_within(r)
            }

            (PathAwareValue::Float((_, value)), PathAwareValue::RangeFloat((_, r))) => {
                value.is_within(r)
            }

            (PathAwareValue::Char((_, value)), PathAwareValue::RangeChar((_, r))) => {
                value.is_within(r)
            }

            (rest, rest2) => match compare_values(rest, rest2) {
                Ok(ordering) => matches!(ordering, Ordering::Equal),
                Err(_) => false,
            },
        }
    }
}

impl Eq for PathAwareValue {}

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

impl TryFrom<(&serde_yaml::Value, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (&serde_yaml::Value, Path)) -> Result<Self, Self::Error> {
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

impl TryFrom<serde_yaml::Value> for PathAwareValue {
    type Error = Error;

    fn try_from(value: serde_yaml::Value) -> Result<Self, Self::Error> {
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
            }

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
                Ok(PathAwareValue::Map((path, MapValue { keys, values })))
            }
        }
    }
}

impl TryFrom<MarkedValue> for PathAwareValue {
    type Error = Error;

    fn try_from(value: MarkedValue) -> Result<Self, Self::Error> {
        Self::try_from((value, Path::root()))
    }
}
impl TryFrom<(MarkedValue, Path)> for PathAwareValue {
    type Error = Error;

    fn try_from(incoming: (MarkedValue, Path)) -> Result<Self, Self::Error> {
        let root = incoming.0;
        let path = incoming.1;

        match root {
            MarkedValue::String(s, loc) => Ok(PathAwareValue::String((path.with_location(loc), s))),
            MarkedValue::Int(num, loc) => Ok(PathAwareValue::Int((path.with_location(loc), num))),
            MarkedValue::Float(flt, loc) => {
                Ok(PathAwareValue::Float((path.with_location(loc), flt)))
            }
            MarkedValue::Regex(s, loc) => Ok(PathAwareValue::Regex((path.with_location(loc), s))),
            MarkedValue::Char(c, loc) => Ok(PathAwareValue::Char((path.with_location(loc), c))),
            MarkedValue::RangeChar(r, loc) => {
                Ok(PathAwareValue::RangeChar((path.with_location(loc), r)))
            }
            MarkedValue::RangeInt(r, loc) => {
                Ok(PathAwareValue::RangeInt((path.with_location(loc), r)))
            }
            MarkedValue::RangeFloat(r, loc) => {
                Ok(PathAwareValue::RangeFloat((path.with_location(loc), r)))
            }
            MarkedValue::Bool(b, loc) => Ok(PathAwareValue::Bool((path.with_location(loc), b))),
            MarkedValue::Null(loc) => Ok(PathAwareValue::Null(path.with_location(loc))),
            MarkedValue::List(v, _) => {
                let mut result: Vec<PathAwareValue> = Vec::with_capacity(v.len());

                for (idx, each) in v.into_iter().enumerate() {
                    let sub_path = path.extend_usize(idx);
                    let loc = *each.location();
                    let value = PathAwareValue::try_from((each, sub_path.with_location(loc)))?;
                    result.push(value);
                }

                Ok(PathAwareValue::List((path, result)))
            }

            MarkedValue::Map(map, loc) => {
                let mut keys = Vec::with_capacity(map.len());
                let mut values = indexmap::IndexMap::with_capacity(map.len());
                for ((each_key, loc), each_value) in map {
                    let sub_path = path.extend_string(&each_key);
                    let sub_path = sub_path.with_location(*each_value.location());
                    let value = PathAwareValue::try_from((each_value, sub_path))?;
                    values.insert(each_key.to_owned(), value);
                    keys.push(PathAwareValue::String((
                        path.with_location(loc),
                        each_key.to_string(),
                    )));
                }
                Ok(PathAwareValue::Map((
                    path.with_location(loc),
                    MapValue { keys, values },
                )))
            }

            MarkedValue::BadValue(val, loc) => Err(Error::ParseError(format!(
                "Bad Value encountered parsing incoming file Value = {}, Loc = {}",
                val, loc
            ))),
        }
    }
}

impl<'a> TryInto<(String, serde_json::Value)> for &'a PathAwareValue {
    type Error = Error;

    fn try_into(self) -> Result<(String, serde_json::Value), Self::Error> {
        let top = self.self_path().0.clone();
        match self {
            PathAwareValue::Null(_) => Ok((top, serde_json::Value::Null)),
            PathAwareValue::String((_, s)) => Ok((top, serde_json::Value::String(s.clone()))),
            PathAwareValue::Regex((_, r)) => {
                Ok((top, serde_json::Value::String(format!("/{}/", r))))
            }
            PathAwareValue::Bool((_, bool_)) => Ok((top, serde_json::Value::Bool(*bool_))),
            PathAwareValue::Int((_, i64_)) => Ok((
                top,
                serde_json::Value::Number(serde_json::Number::from(*i64_)),
            )),
            PathAwareValue::Float((_, f64_)) => Ok((
                top,
                serde_json::Value::Number(match serde_json::Number::from_f64(*f64_) {
                    Some(num) => num,
                    None => {
                        return Err(Error::IncompatibleError(format!(
                            "Could not convert float {} to serde::Value::Number",
                            *f64_
                        )))
                    }
                }),
            )),
            PathAwareValue::Char((_, char_)) => {
                Ok((top, serde_json::Value::String(char_.to_string())))
            }

            PathAwareValue::List((_, list)) => {
                let mut values = Vec::with_capacity(list.len());
                for each in list {
                    let (_, val): (String, serde_json::Value) = each.try_into()?;
                    values.push(val);
                }
                Ok((top, serde_json::Value::Array(values)))
            }

            PathAwareValue::Map((_, map)) => {
                let mut values = serde_json::Map::new();
                for (key, value) in map.values.iter() {
                    let (_, val): (String, serde_json::Value) = value.try_into()?;
                    values.insert(key.clone(), val);
                }
                Ok((top, serde_json::Value::Object(values)))
            }

            PathAwareValue::RangeFloat((_, range_)) => {
                let range_encoding = format!(
                    "{}{},{}{}",
                    if range_.inclusive & LOWER_INCLUSIVE > 0 {
                        "["
                    } else {
                        "("
                    },
                    range_.lower,
                    range_.upper,
                    if range_.inclusive & UPPER_INCLUSIVE > 0 {
                        "]"
                    } else {
                        ")"
                    },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            }

            PathAwareValue::RangeChar((_, range_)) => {
                let range_encoding = format!(
                    "{}{},{}{}",
                    if range_.inclusive & LOWER_INCLUSIVE > 0 {
                        "["
                    } else {
                        "("
                    },
                    range_.lower,
                    range_.upper,
                    if range_.inclusive & UPPER_INCLUSIVE > 0 {
                        "]"
                    } else {
                        ")"
                    },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            }

            PathAwareValue::RangeInt((_, range_)) => {
                let range_encoding = format!(
                    "{}{},{}{}",
                    if range_.inclusive & LOWER_INCLUSIVE > 0 {
                        "["
                    } else {
                        "("
                    },
                    range_.lower,
                    range_.upper,
                    if range_.inclusive & UPPER_INCLUSIVE > 0 {
                        "]"
                    } else {
                        ")"
                    },
                );
                Ok((top, serde_json::Value::String(range_encoding)))
            }
        }
    }
}

pub(crate) trait QueryResolver {
    fn select(
        &self,
        all: bool,
        query: &[QueryPart<'_>],
        eval: &dyn EvaluationContext,
    ) -> Result<Vec<&PathAwareValue>, Error>;
}

impl QueryResolver for PathAwareValue {
    fn select(
        &self,
        all: bool,
        query: &[QueryPart<'_>],
        resolver: &dyn EvaluationContext,
    ) -> Result<Vec<&PathAwareValue>, Error> {
        if query.is_empty() {
            return Ok(vec![self]);
        }

        match &query[0] {
            QueryPart::This => self.select(all, &query[1..], resolver),

            QueryPart::Key(key) => {
                match key.parse::<i32>() {
                    Ok(index) => match self {
                        PathAwareValue::List((_, list)) => {
                            PathAwareValue::retrieve_index(self, index, list, query).map_or_else(
                                |e| self.map_error_or_empty(all, e),
                                |val| val.select(all, &query[1..], resolver),
                            )
                        }

                        _ => self.map_some_or_error_all(all, query),
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
                                        QueryPart::AllIndices(_) | QueryPart::Key(_) => keys,
                                        QueryPart::Index(index) => {
                                            let check = if index >= 0 { index } else { -index } as usize;
                                            if check < keys.len() {
                                                vec![keys[check]]
                                            } else {
                                                self.map_some_or_error_all(all, query)?
                                            }
                                        },

                                        _ => return Err(Error::IncompatibleError(
                                            format!("THIS type of variable interpolation is not supported {}, {}", self.type_info(), SliceDisplay(query))
                                        ))
                                    }
                                } else {
                                    keys
                                };
                                for each_key in keys {
                                    if let PathAwareValue::String((_, k)) = each_key {
                                        if let Some(next) = map.values.get(k) {
                                            acc.extend(next.select(all, &query[1..], resolver)?);
                                        } else if all {
                                            return Err(Error::
                                                RetrievalError(
                                                    format!("Could not locate key = {} inside object/map = {:?}, Path = {}, remaining query = {}",
                                                            key, self, path, SliceDisplay(query))
                                                ));
                                        }
                                    } else {
                                        return Err(Error
                                            ::NotComparable(
                                                format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                        SliceDisplay(query),
                                                        each_key.type_info(),
                                                        each_key.self_value()
                                               )

                                        ));
                                    }
                                }
                                Ok(acc)
                            } else if let Some(next) = map.values.get(key) {
                                next.select(all, &query[1..], resolver)
                            } else {
                                self.map_some_or_error_all(all, query)
                            }
                        }

                        _ => self.map_some_or_error_all(all, query),
                    },
                }
            }

            QueryPart::Index(array_idx) => match self {
                PathAwareValue::List((_path, vec)) => {
                    PathAwareValue::retrieve_index(self, *array_idx, vec, query).map_or_else(
                        |e| self.map_error_or_empty(all, e),
                        |val| val.select(all, &query[1..], resolver),
                    )
                }

                _ => self.map_some_or_error_all(all, query),
            },

            QueryPart::AllIndices(_name) => {
                match self {
                    PathAwareValue::List((_path, elements)) => {
                        PathAwareValue::accumulate(self, all, &query[1..], elements, resolver)
                    }

                    //
                    // Often in the place where a list of values is accepted
                    // single values often are accepted. So proceed to the next
                    // part of your query
                    //
                    rest => rest.select(all, &query[1..], resolver),
                }
            }

            QueryPart::AllValues(_name) => {
                match self {
                    //
                    // Supporting old format
                    //
                    PathAwareValue::List((_path, elements)) => {
                        PathAwareValue::accumulate(self, all, &query[1..], elements, resolver)
                    }

                    PathAwareValue::Map((_path, map)) => {
                        let values: Vec<&PathAwareValue> = map.values.values().collect();
                        let mut resolved = Vec::with_capacity(values.len());
                        for each in values {
                            resolved.extend(each.select(all, &query[1..], resolver)?);
                        }
                        Ok(resolved)
                    }

                    //
                    // Often in the place where a list of values is accepted
                    // single values often are accepted. So proceed to the next
                    // part of your query
                    //
                    rest => rest.select(all, &query[1..], resolver),
                }
            }

            QueryPart::MapKeyFilter(_name, filter) => match self {
                PathAwareValue::Map((_, map)) => {
                    let mut selected = Vec::with_capacity(map.values.len());
                    match &filter.compare_with {
                        LetValue::AccessClause(query) => {
                            let values = resolve_query(false, &query.query, self, resolver)?;
                            for key in map.keys.iter() {
                                if values.contains(&key) {
                                    match key {
                                        PathAwareValue::String((_, v)) => {
                                            selected.push(map.values.get(v).unwrap());
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                            }
                        }

                        LetValue::Value(path_value) => {
                            for key in map.keys.iter() {
                                if key == path_value {
                                    match key {
                                        PathAwareValue::String((_, v)) => {
                                            selected.push(map.values.get(v).unwrap());
                                        }
                                        _ => unreachable!(),
                                    }
                                }
                            }
                        }

                        LetValue::FunctionCall(_) => unreachable!(),
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
                }

                _ => self.map_some_or_error_all(all, query),
            },

            QueryPart::Filter(_name, conjunctions) => {
                match self {
                    PathAwareValue::List((path, vec)) => {
                        let mut selected = Vec::with_capacity(vec.len());
                        let context = format!("Path={},Type=Array", path);
                        for each in vec {
                            let mut filter =
                                AutoReport::new(EvaluationType::Filter, resolver, &context);
                            match conjunctions.evaluate(each, resolver) {
                                Err(Error::RetrievalError(e)) => {
                                    if all {
                                        return Err(Error::RetrievalError(e));
                                    }
                                    // Else treat is like a filter
                                }
                                Err(Error::IncompatibleRetrievalError(e)) => {
                                    if all {
                                        return Err(Error::IncompatibleRetrievalError(e));
                                    }
                                    // Else treat is like a filter
                                }
                                Err(e) => return Err(e),
                                Ok(status) => match status {
                                    Status::PASS => {
                                        filter.status(Status::PASS);
                                        let index: usize = if query.len() > 1 {
                                            match &query[1] {
                                                QueryPart::AllIndices(_) => 2,
                                                _ => 1,
                                            }
                                        } else {
                                            1
                                        };
                                        selected.extend(each.select(
                                            all,
                                            &query[index..],
                                            resolver,
                                        )?);
                                    }
                                    rest => {
                                        filter.status(rest);
                                    }
                                },
                            }
                        }
                        Ok(selected)
                    }

                    PathAwareValue::Map((path, _map)) => {
                        let context = format!("Path={},Type=MapElement", path);
                        let mut filter =
                            AutoReport::new(EvaluationType::Filter, resolver, &context);
                        conjunctions.evaluate(self, resolver).map_or_else(
                            |e| self.map_error_or_empty(all, e),
                            |status| match status {
                                Status::PASS => {
                                    filter.status(Status::PASS);
                                    self.select(all, &query[1..], resolver)
                                }
                                rest => {
                                    filter.status(rest);
                                    Ok(vec![])
                                }
                            },
                        )
                    }

                    _ => self.map_some_or_error_all(all, query),
                }
            }
        }
    }
}

impl Serialize for PathAwareValue {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let result: crate::rules::Result<(String, serde_json::Value)> = self.try_into();
        match result {
            Ok((path, value)) => {
                let mut struct_ser = serializer.serialize_struct("PathAwareValue", 2)?;
                struct_ser.serialize_field("path", &path)?;
                struct_ser.serialize_field("value", &value)?;
                struct_ser.end()
            }
            Err(e) => Err(serde::ser::Error::custom(e)),
        }
    }
}

impl PartialOrd for PathAwareValue {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.self_path().0.partial_cmp(&other.self_path().0)
    }
}

impl PathAwareValue {
    pub(crate) fn merge(mut self, other: PathAwareValue) -> crate::rules::Result<PathAwareValue> {
        match (&mut self, other) {
            (PathAwareValue::List((_path, vec)), PathAwareValue::List((_p2, other_vec))) => {
                vec.extend(other_vec)
            }

            (PathAwareValue::Map((_, map)), PathAwareValue::Map((path, other_map))) => {
                for (key, value) in other_map.values {
                    if map.values.contains_key(&key) {
                        return Err(Error::MultipleValues(format!(
                            "Key {}, already exists in map",
                            key
                        )));
                    }

                    map.values.insert(key.clone(), value);
                    map.keys
                        .push(PathAwareValue::String((path.extend_str(&key), key)));
                }
            }

            (this, that) => {
                return Err(Error::IncompatibleError(format!(
                    "Types are not compatible for merges {}, {}",
                    this.type_info(),
                    that.type_info()
                )))
            }
        }
        Ok(self)
    }

    pub(crate) fn is_list(&self) -> bool {
        matches!(self, PathAwareValue::List((_, _)))
    }

    pub(crate) fn is_map(&self) -> bool {
        matches!(self, PathAwareValue::Map((_, _)))
    }

    pub(crate) fn is_null(&self) -> bool {
        matches!(self, PathAwareValue::Null(_))
    }

    fn map_error_or_empty(&self, all: bool, e: Error) -> Result<Vec<&PathAwareValue>, Error> {
        if !all {
            match e {
                Error::IncompatibleRetrievalError(_) | Error::RetrievalError(_) => Ok(vec![]),

                rest => Err(rest),
            }
        } else {
            Err(e)
        }
    }

    fn map_some_or_error_all(
        &self,
        all: bool,
        query: &[QueryPart<'_>],
    ) -> Result<Vec<&PathAwareValue>, Error> {
        if all {
            Err(Error::IncompatibleRetrievalError(
                format!("Attempting to retrieve array index or key from map at path = {} , Type was not an array/object {}, Remaining Query = {}",
                        self.self_value().0, self.type_info(), SliceDisplay(query))
            ))
        } else {
            Ok(vec![])
        }
    }

    pub(crate) fn is_scalar(&self) -> bool {
        !self.is_list() && !self.is_map()
    }

    pub(crate) fn self_path(&self) -> &Path {
        self.self_value().0
    }

    pub(crate) fn self_value(&self) -> (&Path, &PathAwareValue) {
        match self {
            PathAwareValue::Null(path) => (path, self),
            PathAwareValue::String((path, _)) => (path, self),
            PathAwareValue::Regex((path, _)) => (path, self),
            PathAwareValue::Bool((path, _)) => (path, self),
            PathAwareValue::Int((path, _)) => (path, self),
            PathAwareValue::Float((path, _)) => (path, self),
            PathAwareValue::Char((path, _)) => (path, self),
            PathAwareValue::List((path, _)) => (path, self),
            PathAwareValue::Map((path, _)) => (path, self),
            PathAwareValue::RangeInt((path, _)) => (path, self),
            PathAwareValue::RangeFloat((path, _)) => (path, self),
            PathAwareValue::RangeChar((path, _)) => (path, self),
        }
    }

    pub(crate) fn type_info(&self) -> &'static str {
        match self {
            PathAwareValue::Null(_path) => "null",
            PathAwareValue::String((_path, _)) => "String",
            PathAwareValue::Regex((_path, _)) => "Regex",
            PathAwareValue::Bool((_path, _)) => "bool",
            PathAwareValue::Int((_path, _)) => "int",
            PathAwareValue::Float((_path, _)) => "float",
            PathAwareValue::Char((_path, _)) => "char",
            PathAwareValue::List((_path, _)) => "array",
            PathAwareValue::Map((_path, _)) => "map",
            PathAwareValue::RangeInt((_path, _)) => "range(int, int)",
            PathAwareValue::RangeFloat((_path, _)) => "range(float, float)",
            PathAwareValue::RangeChar((_path, _)) => "range(char, char)",
        }
    }

    pub(crate) fn retrieve_index<'v>(
        parent: &PathAwareValue,
        index: i32,
        list: &'v Vec<PathAwareValue>,
        query: &[QueryPart<'_>],
    ) -> Result<&'v PathAwareValue, Error> {
        let check = if index >= 0 { index } else { -index } as usize;
        if check < list.len() {
            Ok(&list[check])
        } else {
            Err(Error::
                RetrievalError(
                    format!("Array Index out of bounds for path = {} on index = {} inside Array = {:?}, remaining query = {}",
                            parent.self_path(), index, list, SliceDisplay(query))
                ))
        }
    }

    pub(crate) fn accumulate<'v>(
        parent: &PathAwareValue,
        all: bool,
        query: &[QueryPart<'_>],
        elements: &'v Vec<PathAwareValue>,
        resolver: &dyn EvaluationContext,
    ) -> Result<Vec<&'v PathAwareValue>, Error> {
        if elements.is_empty() && !query.is_empty() && all {
            return Err(Error::RetrievalError(format!(
                "No entries for path = {} . Remaining Query {}",
                parent.self_path(),
                SliceDisplay(query)
            )));
        }

        let mut accumulated = Vec::with_capacity(elements.len());
        for each in elements {
            if !query.is_empty() {
                accumulated.extend(each.select(all, query, resolver)?);
            } else {
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
            None => Err(Error::NotComparable(
                "Float values are not comparable".to_owned(),
            )),
        },
        (PathAwareValue::Char((_, f)), PathAwareValue::Char((_, s))) => Ok(f.cmp(s)),
        (_, _) => Err(Error::NotComparable(format!(
            "PathAwareValues are not comparable {}, {}",
            first.type_info(),
            other.type_info()
        ))),
    }
}

#[allow(clippy::never_loop)]
pub(crate) fn compare_eq(first: &PathAwareValue, second: &PathAwareValue) -> Result<bool, Error> {
    let (reg, s) = match (first, second) {
        (PathAwareValue::String((_, s)), PathAwareValue::Regex((_, r))) => {
            (Regex::new(r.as_str())?, s.as_str())
        }
        (PathAwareValue::Regex((_, r)), PathAwareValue::String((_, s))) => {
            (Regex::new(r.as_str())?, s.as_str())
        }

        (PathAwareValue::String((_, s1)), PathAwareValue::String((_, s2))) => return Ok(s1 == s2),

        (PathAwareValue::Map((_, map)), PathAwareValue::Map((_, map2))) => {
            return Ok('result: loop {
                if map.values.len() == map2.values.len() {
                    for (key, value) in map.values.iter() {
                        match map2.values.get(key) {
                            Some(value2) => {
                                if !compare_eq(value, value2)? {
                                    break 'result false;
                                }
                            }

                            None => {
                                break 'result false;
                            }
                        }
                    }
                    break 'result true;
                }
                break 'result false;
            })
        }

        (PathAwareValue::List((_, list)), PathAwareValue::List((_, list2))) => {
            return Ok('result: loop {
                //
                // Order does matter
                //
                if list.len() == list2.len() {
                    for (left, right) in list.iter().zip(list2.iter()) {
                        if !compare_eq(left, right)? {
                            break 'result false;
                        }
                    }
                    break 'result true;
                }
                break 'result false;
            });
        }

        (PathAwareValue::Bool((_, b1)), PathAwareValue::Bool((_, b2))) => return Ok(b1 == b2),

        (PathAwareValue::Regex((_, r)), PathAwareValue::Regex((_, s))) => return Ok(r == s),

        //
        // Range checks
        //
        (PathAwareValue::Int((_, value)), PathAwareValue::RangeInt((_, r))) => {
            return Ok(value.is_within(r))
        }

        (PathAwareValue::Float((_, value)), PathAwareValue::RangeFloat((_, r))) => {
            return Ok(value.is_within(r))
        }

        (PathAwareValue::Char((_, value)), PathAwareValue::RangeChar((_, r))) => {
            return Ok(value.is_within(r))
        }

        (_, _) => {
            return match compare_values(first, second)? {
                Ordering::Equal => Ok(true),
                _ => Ok(false),
            }
        }
    };
    let match_result = reg.is_match(s);
    match match_result {
        Ok(is_match) => Ok(is_match),
        Err(error) => Err(Error::from(error)),
    }
}

pub(crate) fn compare_lt(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Equal | Ordering::Greater => Ok(false),
            Ordering::Less => Ok(true),
        },
        Err(e) => Err(e),
    }
}

pub(crate) fn compare_le(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(false),
            Ordering::Equal | Ordering::Less => Ok(true),
        },
        Err(e) => Err(e),
    }
}

pub(crate) fn compare_gt(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(true),
            Ordering::Less | Ordering::Equal => Ok(false),
        },
        Err(e) => Err(e),
    }
}

pub(crate) fn compare_ge(first: &PathAwareValue, other: &PathAwareValue) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater | Ordering::Equal => Ok(true),
            Ordering::Less => Ok(false),
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
#[path = "path_value_tests.rs"]
mod path_value_tests;
