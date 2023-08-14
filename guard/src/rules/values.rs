use std::{
    convert::TryFrom,
    fmt,
    fmt::Display,
    hash::{Hash, Hasher},
};

use indexmap::map::IndexMap;
use nom::lib::std::fmt::Formatter;

use crate::rules::{
    errors::Error, libyaml::loader::Loader, parser::Span, path_value::Location, short_form_to_long,
    SEQUENCE_VALUE_FUNC_REF, SINGLE_VALUE_FUNC_REF,
};

use serde::{Deserialize, Serialize};

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash, Copy)]
pub enum CmpOperator {
    Eq,
    In,
    Gt,
    Lt,
    Le,
    Ge,
    Exists,
    Empty,

    IsString,
    IsList,
    IsMap,
    IsBool,
    IsInt,
    IsNull,
    IsFloat,
}

impl CmpOperator {
    pub(crate) fn is_unary(&self) -> bool {
        matches!(
            self,
            CmpOperator::Exists
                | CmpOperator::Empty
                | CmpOperator::IsString
                | CmpOperator::IsBool
                | CmpOperator::IsList
                | CmpOperator::IsInt
                | CmpOperator::IsMap
                | CmpOperator::IsFloat
                | CmpOperator::IsNull
        )
    }
}

impl Display for CmpOperator {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            CmpOperator::Eq => f.write_str("EQUALS")?,
            CmpOperator::In => f.write_str("IN")?,
            CmpOperator::Gt => f.write_str("GREATER THAN")?,
            CmpOperator::Lt => f.write_str("LESS THAN")?,
            CmpOperator::Ge => f.write_str("GREATER THAN EQUALS")?,
            CmpOperator::Le => f.write_str("LESS THAN EQUALS")?,
            CmpOperator::Exists => f.write_str("EXISTS")?,
            CmpOperator::Empty => f.write_str("EMPTY")?,
            CmpOperator::IsString => f.write_str("IS STRING")?,
            CmpOperator::IsBool => f.write_str("IS BOOL")?,
            CmpOperator::IsInt => f.write_str("IS INT")?,
            CmpOperator::IsList => f.write_str("IS LIST")?,
            CmpOperator::IsMap => f.write_str("IS MAP")?,
            CmpOperator::IsNull => f.write_str("IS NULL")?,
            CmpOperator::IsFloat => f.write_str("IS FLOAT")?,
        }
        Ok(())
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Value {
    Null,
    String(String),
    Regex(String),
    Bool(bool),
    Int(i64),
    Float(f64),
    Char(char),
    List(Vec<Value>),
    Map(indexmap::IndexMap<String, Value>),
    RangeInt(RangeType<i64>),
    RangeFloat(RangeType<f64>),
    RangeChar(RangeType<char>),
}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::String(s) | Value::Regex(s) => {
                s.hash(state);
            }

            Value::Char(c) => {
                c.hash(state);
            }
            Value::Int(i) => {
                i.hash(state);
            }
            Value::Null => {
                "NULL".hash(state);
            }
            Value::Float(f) => {
                (*f as u64).hash(state);
            }

            Value::RangeChar(r) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            }

            Value::RangeInt(r) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            }

            Value::RangeFloat(r) => {
                (r.lower as u64).hash(state);
                (r.upper as u64).hash(state);
                r.inclusive.hash(state);
            }

            Value::Bool(b) => {
                b.hash(state);
            }

            Value::List(l) => {
                for each in l {
                    each.hash(state);
                }
            }

            Value::Map(map) => {
                for (key, value) in map.iter() {
                    key.hash(state);
                    value.hash(state);
                }
            }
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Regex(s) => write!(f, "/{}/", s),
            Value::Int(int) => write!(f, "{}", int),
            Value::Float(float) => write!(f, "{}", float),
            Value::Bool(bool) => write!(f, "{}", bool),
            Value::List(list) => {
                let result: Vec<String> = list.iter().map(|item| format!("{}", item)).collect();
                write!(f, "[{}]", result.join(", "))
            }
            Value::Map(map) => {
                let key_values: Vec<String> = map
                    .into_iter()
                    .map(|(key, value)| format!("\"{}\": {}", key, value))
                    .collect();
                write!(f, "{{{}}}", key_values.join(", "))
            }
            Value::Null => {
                write!(f, "null")
            }
            Value::RangeChar(range) => {
                if (range.inclusive & LOWER_INCLUSIVE) == LOWER_INCLUSIVE {
                    write!(f, "[")?;
                } else {
                    write!(f, "(")?;
                }
                write!(f, "{},{}", range.lower, range.upper)?;

                if (range.inclusive & UPPER_INCLUSIVE) == UPPER_INCLUSIVE {
                    write!(f, "]")
                } else {
                    write!(f, ")")
                }
            }
            Value::RangeFloat(range) => {
                if (range.inclusive & LOWER_INCLUSIVE) == LOWER_INCLUSIVE {
                    write!(f, "[")?;
                } else {
                    write!(f, "(")?;
                }
                write!(f, "{},{}", range.lower, range.upper)?;

                if (range.inclusive & UPPER_INCLUSIVE) == UPPER_INCLUSIVE {
                    write!(f, "]")
                } else {
                    write!(f, ")")
                }
            }
            Value::RangeInt(range) => {
                if (range.inclusive & LOWER_INCLUSIVE) == LOWER_INCLUSIVE {
                    write!(f, "[")?;
                } else {
                    write!(f, "(")?;
                }
                write!(f, "{},{}", range.lower, range.upper)?;

                if (range.inclusive & UPPER_INCLUSIVE) == UPPER_INCLUSIVE {
                    write!(f, "]")
                } else {
                    write!(f, ")")
                }
            }
            Value::Char(c) => {
                write!(f, "\"{}\"", c)
            }
        }
    }
}

//
//    .X > 10
//    .X <= 20
//
//    .X in r(10, 20]
//    .X in r(10, 20)
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct RangeType<T: PartialOrd> {
    pub upper: T,
    pub lower: T,
    pub inclusive: u8,
}

pub const LOWER_INCLUSIVE: u8 = 0x01;
pub const UPPER_INCLUSIVE: u8 = 0x01 << 1;

pub(crate) trait WithinRange<RHS: PartialOrd = Self> {
    fn is_within(&self, range: &RangeType<RHS>) -> bool;
}

impl WithinRange for i64 {
    fn is_within(&self, range: &RangeType<i64>) -> bool {
        is_within(range, self)
    }
}

impl WithinRange for f64 {
    fn is_within(&self, range: &RangeType<f64>) -> bool {
        is_within(range, self)
    }
}

impl WithinRange for char {
    fn is_within(&self, range: &RangeType<char>) -> bool {
        is_within(range, self)
    }
}

//impl WithinRange for

fn is_within<T: PartialOrd>(range: &RangeType<T>, other: &T) -> bool {
    let lower = if (range.inclusive & LOWER_INCLUSIVE) > 0 {
        range.lower.le(other)
    } else {
        range.lower.lt(other)
    };
    let upper = if (range.inclusive & UPPER_INCLUSIVE) > 0 {
        range.upper.ge(other)
    } else {
        range.upper.gt(other)
    };
    lower && upper
}

impl<'a> TryFrom<&'a serde_yaml::Value> for Value {
    type Error = Error;

    fn try_from(value: &'a serde_yaml::Value) -> Result<Self, Self::Error> {
        match value {
            serde_yaml::Value::String(s) => Ok(Value::String(s.to_owned())),
            serde_yaml::Value::Number(num) => {
                if num.is_i64() {
                    Ok(Value::Int(num.as_i64().unwrap()))
                } else if num.is_u64() {
                    //
                    // Yes we are losing precision here. TODO fix this
                    //
                    Ok(Value::Int(num.as_u64().unwrap() as i64))
                } else {
                    Ok(Value::Float(num.as_f64().unwrap()))
                }
            }
            serde_yaml::Value::Bool(b) => Ok(Value::Bool(*b)),
            serde_yaml::Value::Sequence(sequence) => Ok(Value::List(sequence.iter().try_fold(
                vec![],
                |mut res, val| -> Result<Vec<Self>, Self::Error> {
                    res.push(Value::try_from(val)?);
                    Ok(res)
                },
            )?)),
            serde_yaml::Value::Mapping(mapping) => Ok(Value::Map(mapping.iter().try_fold(
                IndexMap::with_capacity(mapping.len()),
                |mut res, (key, val)| -> Result<IndexMap<String, Self>, Self::Error> {
                    res.insert(key.as_str().unwrap().to_owned(), Value::try_from(val)?);
                    Ok(res)
                },
            )?)),
            serde_yaml::Value::Tagged(tag) => {
                let prefix = tag.tag.to_string();
                let value = tag.value.clone();

                match prefix.matches('!').count() {
                    1 => {
                        let stripped_prefix = prefix.strip_prefix('!').unwrap();
                        Ok(handle_tagged_value(value, stripped_prefix)?)
                    }
                    _ => Ok(Value::try_from(value)?),
                }
            }
            serde_yaml::Value::Null => Ok(Value::Null),
        }
    }
}

impl<'a> TryFrom<&'a serde_json::Value> for Value {
    type Error = Error;

    fn try_from(value: &'a serde_json::Value) -> Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(Value::String(s.to_owned())),
            serde_json::Value::Number(num) => {
                if num.is_i64() {
                    Ok(Value::Int(num.as_i64().unwrap()))
                } else if num.is_u64() {
                    //
                    // Yes we are losing precision here. TODO fix this
                    //
                    Ok(Value::Int(num.as_u64().unwrap() as i64))
                } else {
                    Ok(Value::Float(num.as_f64().unwrap()))
                }
            }
            serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
            serde_json::Value::Null => Ok(Value::Null),
            serde_json::Value::Array(v) => {
                let mut result: Vec<Value> = Vec::with_capacity(v.len());
                for each in v {
                    result.push(Value::try_from(each)?)
                }
                Ok(Value::List(result))
            }
            serde_json::Value::Object(map) => {
                let mut result = IndexMap::with_capacity(map.len());
                for (key, value) in map.iter() {
                    result.insert(key.to_owned(), Value::try_from(value)?);
                }
                Ok(Value::Map(result))
            }
        }
    }
}

impl TryFrom<serde_json::Value> for Value {
    type Error = Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Value::try_from(&value)
    }
}

impl TryFrom<serde_yaml::Value> for Value {
    type Error = Error;

    fn try_from(value: serde_yaml::Value) -> Result<Self, Self::Error> {
        Value::try_from(&value)
    }
}

impl<'a> TryFrom<&'a str> for Value {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Ok(super::parser::parse_value(Span::new_extra(value, ""))?.1)
    }
}

#[derive(PartialEq, Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum MarkedValue {
    Null(Location),
    BadValue(String, Location),
    String(String, Location),
    Regex(String, Location),
    Bool(bool, Location),
    Int(i64, Location),
    Float(f64, Location),
    Char(char, Location),
    List(Vec<MarkedValue>, Location),
    Map(
        indexmap::IndexMap<(String, Location), MarkedValue>,
        Location,
    ),
    RangeInt(RangeType<i64>, Location),
    RangeFloat(RangeType<f64>, Location),
    RangeChar(RangeType<char>, Location),
}

impl MarkedValue {
    pub(crate) fn location(&self) -> &Location {
        match self {
            Self::Null(loc)
            | Self::BadValue(_, loc)
            | Self::String(_, loc)
            | Self::Regex(_, loc)
            | Self::Bool(_, loc)
            | Self::Int(_, loc)
            | Self::Float(_, loc)
            | Self::Char(_, loc)
            | Self::List(_, loc)
            | Self::Map(_, loc)
            | Self::RangeInt(_, loc)
            | Self::RangeFloat(_, loc)
            | Self::RangeChar(_, loc) => loc,
        }
    }
}

pub(crate) fn read_from(from_reader: &str) -> crate::rules::Result<MarkedValue> {
    let mut loader = Loader::new();
    match loader.load(from_reader.to_string()) {
        Ok(doc) => Ok(doc),
        Err(e) => Err(Error::ParseError(format!("{}", e))),
    }
}

#[cfg(test)]
pub(super) fn make_linked_hashmap<'a, I>(values: I) -> IndexMap<String, Value>
where
    I: IntoIterator<Item = (&'a str, Value)>,
{
    values.into_iter().map(|(s, v)| (s.to_owned(), v)).collect()
}

fn handle_tagged_value(val: serde_yaml::Value, fn_ref: &str) -> crate::rules::Result<Value> {
    if SINGLE_VALUE_FUNC_REF.contains(fn_ref) || SEQUENCE_VALUE_FUNC_REF.contains(fn_ref) {
        let mut map = indexmap::IndexMap::new();
        let fn_ref = short_form_to_long(fn_ref);
        map.insert(fn_ref.to_string(), Value::try_from(val)?);

        return Ok(Value::Map(map));
    }

    Value::try_from(val)
}

#[cfg(test)]
#[path = "values_tests.rs"]
mod values_tests;
