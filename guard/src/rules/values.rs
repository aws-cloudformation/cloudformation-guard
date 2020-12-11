use std::convert::TryFrom;
use std::str::FromStr;

use std::cmp::Ordering;

use crate::errors::{Error, ErrorKind};
use indexmap::map::IndexMap;
use std::hash::{Hash, Hasher};

#[derive(PartialEq, Debug, Clone, Hash)]
pub enum CmpOperator {
    Eq,
    In,
    Gt,
    Lt,
    Le,
    Ge,
    Exists,
    Empty,
    KeysIn,
    KeysEq,
    KeysExists,
    KeysEmpty,
}

#[derive(PartialEq, Debug, Clone)]
pub enum ValueOperator {
    Not(CmpOperator),
    Cmp(CmpOperator),
}


#[derive(PartialEq, Debug, Clone)]
pub enum Value {
    Null,
    String(String),
    Regex(String),
    Bool(bool),
    Int(i64),
    Float(f64),
    Char(char),
    List(Vec<Value>),
    Map(IndexMap<String, Value>),
    Variable(String),
    RangeInt(RangeType<i64>),
    RangeFloat(RangeType<f64>),
    RangeChar(RangeType<char>),
}

impl Hash for Value {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            Value::String(s)        |
            Value::Variable(s)      |
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

//
//    .X > 10
//    .X <= 20
//
//    .X in r(10, 20]
//    .X in r(10, 20)
#[derive(PartialEq, Debug, Clone)]
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

pub fn make_linked_hashmap<'a, I>(values: I) -> IndexMap<String, Value>
    where
        I: IntoIterator<Item = (&'a str, Value)>,
{
    values.into_iter().map(|(s, v)| (s.to_owned(), v)).collect()
}


impl <'a> TryFrom<&'a serde_json::Value> for Value {
    type Error = crate::errors::Error;

    fn try_from(value: &'a serde_json::Value) -> Result<Self, Self::Error> {
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
    type Error = crate::errors::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        Value::try_from(&value)
    }
}

impl <'a> TryFrom<&'a str> for Value {
    type Error = crate::errors::Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        Ok(super::parser::parse_value(super::parser::Span::new_extra(value, ""))?.1)
    }
}

pub(crate) fn type_info(type_: &Value) -> &'static str {
    match type_ {
        Value::Null             => "null",
        Value::Regex(_r)        => "Regex",
        Value::Bool(_r)         => "bool",
        Value::Char(_c)         => "char",
        Value::Float(_f)        => "float",
        Value::String(_s)       => "string",
        Value::Int(_i)          => "int",
        Value::Variable(_v)     => "var",
        Value::RangeInt(_r)     => "range(int, int)",
        Value::RangeFloat(_f)   => "range(float, float)",
        Value::RangeChar(_r)    => "range(char, char)",
        Value::List(_v)         => "array",
        Value::Map(_mp)         => "map"
    }
}

fn compare_values(first: &Value, other: &Value) -> Result<Ordering, Error> {
    match (first, other) {
        //
        // scalar values
        //
        (Value::Null, Value::Null) => Ok(Ordering::Equal),
        (Value::Int(i), Value::Int(o)) => Ok(i.cmp(o)),
        (Value::String(s), Value::String(o)) => Ok(s.cmp(o)),
        (Value::Float(f), Value::Float(s)) => match f.partial_cmp(s) {
            Some(o) => Ok(o),
            None => Err(Error::new(ErrorKind::NotComparable("Float values are not comparable".to_owned())))
        },
        (Value::Char(f), Value::Char(s)) => Ok(f.cmp(s)),
        (Value::Bool(_b), Value::Bool(_b2)) => Ok(Ordering::Equal),
        (Value::Regex(_r), Value::Regex(_r2)) => Ok(Ordering::Equal),
        (_, _) => Err(Error::new(ErrorKind::NotComparable(
            format!("Values are not comparable {}, {}", type_info(first), type_info(other)))))
    }
}

pub(crate) fn compare_eq(first: &Value, second: &Value) -> Result<bool, Error> {
    let (reg, s) = match (first, second) {
        (Value::String(s), Value::Regex(r)) => (regex::Regex::new(r.as_str())?, s.as_str()),
        (Value::Regex(r), Value::String(s)) => (regex::Regex::new(r.as_str())?, s.as_str()),
        (_,_) => return Ok(first == second),
    };
    Ok(reg.is_match(s))
}

pub(crate) fn compare_lt(first: &Value, other: &Value) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Equal | Ordering::Greater => Ok(false),
            Ordering::Less => Ok(true)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_le(first: &Value, other: &Value) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(false),
            Ordering::Equal | Ordering::Less => Ok(true)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_gt(first: &Value, other: &Value) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(true),
            Ordering::Less | Ordering::Equal => Ok(false)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_ge(first: &Value, other: &Value) -> Result<bool, Error> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater | Ordering::Equal => Ok(true),
            Ordering::Less => Ok(false)
        },
        Err(e) => Err(e)
    }
}

#[cfg(test)]
mod test {
    use std::convert::TryInto;

    use crate::errors;

    use super::*;

    #[test]
    fn test_convert_from_to_value() -> Result<(), errors::Error> {
        let val = r#"
        {
            "first": {
                "block": [{
                    "number": 10,
                    "hi": "there"
                }, {
                    "number": 20,
                    "hi": "hello"
                }],
                "simple": "desserts"
            },
            "second": 50
        }
        "#;
        let json: serde_json::Value = serde_json::from_str(val)?;
        let value = Value::try_from(&json)?;
        //
        // serde_json uses a BTree for the value which preserves alphabetical
        // order for the keys
        //
        assert_eq!(value, Value::Map(
            make_linked_hashmap(vec![
                ("first", Value::Map(make_linked_hashmap(vec![
                    ("block", Value::List(vec![
                        Value::Map(make_linked_hashmap(vec![
                            ("hi", Value::String("there".to_string())),
                            ("number", Value::Int(10)),
                        ])),
                        Value::Map(make_linked_hashmap(vec![
                            ("hi", Value::String("hello".to_string())),
                            ("number", Value::Int(20)),
                        ]))
                    ])),
                    ("simple", Value::String("desserts".to_string())),
                ]))),
                ("second", Value::Int(50))
            ])
        ));
        Ok(())
    }

    #[test]
    fn test_convert_into_json() -> Result<(), errors::Error> {
        let value = r#"
        {
             first: {
                 block: [{
                     hi: "there",
                     number: 10
                 }, {
                     hi: "hello",
                     # comments in here for the value
                     number: 20
                 }],
                 simple: "desserts"
             }, # now for second value
             second: 50
        }
        "#;

        let value_str = r#"
        {
            "first": {
                "block": [{
                    "number": 10,
                    "hi": "there"
                }, {
                    "number": 20,
                    "hi": "hello"
                }],
                "simple": "desserts"
            },
            "second": 50
        }
        "#;

        let json: serde_json::Value = serde_json::from_str(value_str)?;
        let type_value = Value::try_from(value)?;
        assert_eq!(type_value, Value::Map(
            make_linked_hashmap(vec![
                ("first", Value::Map(make_linked_hashmap(vec![
                    ("block", Value::List(vec![
                        Value::Map(make_linked_hashmap(vec![
                            ("hi", Value::String("there".to_string())),
                            ("number", Value::Int(10)),
                        ])),
                        Value::Map(make_linked_hashmap(vec![
                            ("hi", Value::String("hello".to_string())),
                            ("number", Value::Int(20)),
                        ]))
                    ])),
                    ("simple", Value::String("desserts".to_string())),
                ]))),
                ("second", Value::Int(50))
            ])
        ));

        let converted: Value = (&json).try_into()?;
        assert_eq!(converted, type_value);
        Ok(())
    }
}

