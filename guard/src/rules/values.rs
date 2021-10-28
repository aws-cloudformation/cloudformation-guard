use std::convert::TryFrom;
use std::hash::{Hash, Hasher};

use indexmap::map::IndexMap;
use nom::lib::std::fmt::Formatter;

use crate::rules::errors::{Error, ErrorKind};
use crate::rules::parser::Span;

use serde::{Serialize, Deserialize};
use std::fmt;
use std::fmt::Display;
use yaml_rust::parser::{MarkedEventReceiver, Parser};
use yaml_rust::{Event, Yaml};
use yaml_rust::scanner::{Marker, TScalarStyle, TokenType};
use crate::rules::path_value::Location;

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
}

impl CmpOperator {
    pub(crate) fn is_unary(&self) -> bool {
        match self {
            CmpOperator::Exists     |
            CmpOperator::Empty      |
            CmpOperator::IsString   |
            CmpOperator::IsList     |
            CmpOperator::IsMap          => true,
            _                           => false
        }
    }

    pub(crate) fn is_binary(&self) -> bool { !self.is_unary() }
}

impl std::fmt::Display for CmpOperator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            CmpOperator::Eq => f.write_str("EQUALS")?,
            CmpOperator::In => f.write_str("IN")?,
            CmpOperator::Gt=> f.write_str("GREATER THAN")?,
            CmpOperator::Lt=> f.write_str("LESS THAN")?,
            CmpOperator::Ge => f.write_str("GREATER THAN EQUALS")?,
            CmpOperator::Le => f.write_str("LESS THAN EQUALS")?,
            CmpOperator::Exists => f.write_str("EXISTS")?,
            CmpOperator::Empty => f.write_str("EMPTY")?,
            CmpOperator::IsString => f.write_str("IS STRING")?,
            CmpOperator::IsList => f.write_str("IS LIST")?,
            CmpOperator::IsMap => f.write_str("IS MAP")?,
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
            Value::String(s)        |
            Value::Regex(s)        => { s.hash(state); },

            Value::Char(c)          => { c.hash(state); },
            Value::Int(i)            => { i.hash(state); },
            Value::Null                     => { "NULL".hash(state); },
            Value::Float(f)          => { (*f as u64).hash(state); }

            Value::RangeChar(r) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            },

            Value::RangeInt(r) => {
                r.lower.hash(state);
                r.upper.hash(state);
                r.inclusive.hash(state);
            },

            Value::RangeFloat(r) => {
                (r.lower as u64).hash(state);
                (r.upper as u64).hash(state);
                r.inclusive.hash(state);
            },

            Value::Bool(b) => { b.hash(state); },

            Value::List(l) => {
                for each in l {
                    each.hash(state);
                }
            },

            Value::Map(map) => {
                for (key, value) in map.iter() {
                    key.hash(state);
                    value.hash(state);
                }
            },
        }
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::String(s) => write!(f, "\"{}\"", s),
            Value::Regex(s) => write!(f, "/{}/", s),
            Value::Int(int) => write!(f, "{}", int),
            Value::Float(float) =>  write!(f, "{}", float),
            Value::Bool(bool) => write!(f, "{}", bool),
            Value::List(list) => {

                let result: Vec<String> = list.into_iter().map(|item| format!("{}", item)).collect();
                write!(f, "[{}]", result.join(", "))
            },
            Value::Map(map) => {
                let key_values: Vec<String> = map.into_iter().map(|(key, value)| {
                    format!("\"{}\": {}", key, value)
                }).collect();
                write!(f, "{{{}}}", key_values.join(", "))
            },
            Value::Null => {
                write!(f, "null")
            },
            Value::RangeChar(range) => {
                if (range.inclusive & LOWER_INCLUSIVE) == LOWER_INCLUSIVE {
                    write!(f, "[")?;
                } else {
                    write!(f, "(")?;
                }
                write!(f, "{},{}", range.lower, range.upper);

                if (range.inclusive & UPPER_INCLUSIVE) == UPPER_INCLUSIVE {
                    write!(f, "]")
                } else {
                    write!(f, ")")
                }
            },
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
            },
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
            },
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

impl <'a> TryFrom<&'a serde_json::Value> for Value {
    type Error = Error;

    fn try_from(value: &'a serde_json::Value) -> std::result::Result<Self, Self::Error> {
        match value {
            serde_json::Value::String(s) => Ok(Value::String(s.to_owned())),
            serde_json::Value::Number(num) => {
                if num.is_i64() {
                    Ok(Value::Int(num.as_i64().unwrap()))
                }
                else if num.is_u64() {
                    //
                    // Yes we are losing precision here. TODO fix this
                    //
                    Ok(Value::Int(num.as_u64().unwrap() as i64))
                }
                else {
                    Ok(Value::Float(num.as_f64().unwrap()))
                }
            },
            serde_json::Value::Bool(b) => Ok(Value::Bool(*b)),
            serde_json::Value::Null => Ok(Value::Null),
            serde_json::Value::Array(v) => {
                let mut result: Vec<Value> = Vec::with_capacity(v.len());
                for each in v {
                    result.push(Value::try_from(each)?)
                }
                Ok(Value::List(result))
            },
            serde_json::Value::Object(map) => {
                let mut result = IndexMap::with_capacity(map.len());
                for (key, value) in map.iter() {
                    result.insert(key.to_owned(),Value::try_from(value)?);
                }
                Ok(Value::Map(result))
            }

        }
    }
}

impl TryFrom<serde_json::Value> for Value {
    type Error = Error;

    fn try_from(value: serde_json::Value) -> std::result::Result<Self, Self::Error> {
        Value::try_from(&value)
    }
}

impl <'a> TryFrom<&'a str> for Value {
    type Error = Error;

    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
        Ok(super::parser::parse_value(Span::new_extra(value, ""))?.1)
    }
}

#[derive(PartialEq, Debug, Clone)]
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
    Map(indexmap::IndexMap<(String, Location), MarkedValue>, Location),
    RangeInt(RangeType<i64>, Location),
    RangeFloat(RangeType<f64>, Location),
    RangeChar(RangeType<char>, Location)
}

impl MarkedValue {
    pub(crate) fn location(&self) -> &Location {
        match self {
           Self::Null(loc)	|
           Self::BadValue(_, loc)	|
           Self::String(_, loc)	|
           Self::Regex(_, loc)	|
           Self::Bool(_, loc)	|
           Self::Int(_, loc)	|
           Self::Float(_, loc)	|
           Self::Char(_, loc)	|
           Self::List(_, loc)	|
           Self::Map(_, loc)     |
           Self::RangeInt(_, loc)	|
           Self::RangeFloat(_, loc)	|
           Self::RangeChar(_, loc) => {
               loc
           }
        }
    }
}

#[derive(Debug, Default)]
struct StructureReader {
    stack: Vec<MarkedValue>,
    documents: Vec<MarkedValue>,
    last_container_index: Vec<usize>
}

impl StructureReader {
    fn new() -> StructureReader {
        StructureReader::default()
    }
}

impl MarkedEventReceiver for StructureReader {
    fn on_event(&mut self, ev: Event, mark: Marker) {
        match ev {
            Event::StreamStart |
            Event::StreamEnd   |
            Event::DocumentStart => {},

            Event::DocumentEnd => {
                self.documents.push(self.stack.pop().unwrap());
                self.stack.clear();
                self.last_container_index.clear();
            },

            Event::MappingStart(..) => {
                self.stack.push(
                        MarkedValue::Map(
                            indexmap::IndexMap::new(),
                            Location::new(mark.line(), mark.col()))
                );
                self.last_container_index.push(self.stack.len()-1);
            },

            Event::MappingEnd => {
                let map_index = self.last_container_index.pop().unwrap();
                let mut key_values: Vec<MarkedValue> = self.stack.drain(map_index+1..).collect();
                let map = match self.stack.last_mut().unwrap() {
                    MarkedValue::Map(map, _) => map,
                    _ => unreachable!()
                };
                while !key_values.is_empty() {
                    let key = key_values.remove(0);
                    let value = key_values.remove(0);
                    let key_str = match key {
                        MarkedValue::String(val, loc) => (val, loc),
                        _ => unreachable!()
                    };
                    map.insert(key_str, value);
                }
            },

            Event::SequenceStart(..) => {
                self.stack.push(
                    MarkedValue::List(vec![], Location::new(mark.line(), mark.col()))
                );
                self.last_container_index.push(self.stack.len()-1);
            },

            Event::SequenceEnd => {
                let array_idx = self.last_container_index.pop().unwrap();
                let values: Vec<MarkedValue> = self.stack.drain(array_idx+1..).collect();
                let array = self.stack.last_mut().unwrap();
                match array {
                    MarkedValue::List(vec, _) => vec.extend(values),
                    _ => unreachable!()
                }
            }

            Event::Scalar(val, stype, _, token) => {
                //let path = self.create_path(mark);
                let location = Location::new(mark.line(), mark.col());
                let path_value =
                    if stype != TScalarStyle::Plain {
                        MarkedValue::String(val, location)
                    }
                    else if let Some(TokenType::Tag(ref handle, ref suffix)) = token {
                        if handle == "!!" {
                            Self::handle_type_ref(val, location, suffix.as_ref())
                        }
                        else if handle == "!" {
                            Self::handle_func_ref(val, location, suffix.as_ref())
                        }
                        else {
                            MarkedValue::String(val, location)
                        }
                    }
                    else {
                        match Yaml::from_str(&val) {
                            Yaml::Integer(i) => MarkedValue::Int(i, location),
                            Yaml::Real(_) => val.parse::<f64>().ok().map_or(
                                MarkedValue::BadValue(val, location.clone()),
                                |f| MarkedValue::Float(f, location)
                            ),
                            Yaml::Boolean(b) => MarkedValue::Bool(b, location),
                            Yaml::String(s) => MarkedValue::String(s, location),
                            Yaml::Null => MarkedValue::Null(location),
                            _ => MarkedValue::String(val, location)
                        }
                    };
                self.stack.push(path_value);
            },

            _ => todo!()
        }
    }
}

impl StructureReader {

    fn handle_func_ref(
        val: String,
        loc: Location,
        fn_ref: &str) -> MarkedValue
    {
        match fn_ref {
            "Ref" | "Base64" | "Sub" => {
                let mut map = indexmap::IndexMap::new();
                map.insert((fn_ref.to_string(), loc.clone()), MarkedValue::String(val, loc.clone()));
                MarkedValue::Map(map, loc)
            },

            _ => todo!()
        }
    }

    fn handle_type_ref(
        val: String,
        loc: Location,
        type_ref: &str) -> MarkedValue
    {
        match type_ref {
            "bool" => {
                // "true" or "false"
                match val.parse::<bool>() {
                    Err(_) => MarkedValue::String(val, loc),
                    Ok(v) => MarkedValue::Bool(v, loc)
                }
            }
            "int" => match val.parse::<i64>() {
                Err(_) => MarkedValue::BadValue(val, loc),
                Ok(v) => MarkedValue::Int(v, loc),
            },
            "float" => match val.parse::<f64>() {
                Err(_) => MarkedValue::BadValue(val, loc),
                Ok(v) => MarkedValue::Float(v, loc),
            },
            "null" => match val.as_ref() {
                "~" | "null" => MarkedValue::Null(loc),
                _ => MarkedValue::BadValue(val, loc)
            },
            _ => MarkedValue::String(val, loc)
        }
    }
}

pub(crate) fn read_from(from_reader: &str) -> crate::rules::Result<MarkedValue> {
    let mut reader = StructureReader::new();
    let mut parser = Parser::new(from_reader.chars());
    match parser.load(&mut reader, false) {
        Err(s) => return Err(Error::new(ErrorKind::ParseError(
            format!("{}", s)
        ))),

        Ok(e) => {}
    }
    return Ok(reader.documents.pop().unwrap())
}

pub(super) fn make_linked_hashmap<'a, I>(values: I) -> IndexMap<String, Value>
    where
        I: IntoIterator<Item = (&'a str, Value)>,
{
    values.into_iter().map(|(s, v)| (s.to_owned(), v)).collect()
}



#[cfg(test)]
#[path = "values_tests.rs"]
mod values_tests;
