use std::convert::TryFrom;

use std::cmp::Ordering;

use super::errors::{Error, ErrorKind};
use indexmap::map::IndexMap;
use std::hash::{Hash, Hasher};
use super::exprs::{QueryPart, SliceDisplay};
use super::{EvaluationContext, Result, Status, Evaluate};
use nom::lib::std::fmt::Formatter;

#[derive(PartialEq, Debug, Clone, Hash, Copy)]
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

impl std::fmt::Display for CmpOperator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Eq => f.write_str("EQUALS")?,
            In => f.write_str("IN")?,
            Gt=> f.write_str("GREATER THAN")?,
            Lt=> f.write_str("LESS THAN")?,
            Ge => f.write_str("GREATER THAN EQUALS")?,
            Le => f.write_str("LESS THAN EQUALS")?,
            Exists => f.write_str("EXISTS")?,
            Empty => f.write_str("EMPTY")?,
            _ => {}
        }
        Ok(())
    }
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

/////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                         //
//   Value Query Support for projecting views over the given value object                  //
//                                                                                         //
/////////////////////////////////////////////////////////////////////////////////////////////
impl Value {

    pub(crate) fn query(&self,
                        index: usize,
                        query: &[QueryPart<'_>],
                        var_resolver: &dyn EvaluationContext) -> Result<Vec<&Value>> {
        if index < query.len() {
            let part = &query[index];
            if part.is_variable() {
                return Err(Error::new(ErrorKind::IncompatibleError(
                    "Do not support variable interpolation inside a query".to_string()
                )))
            }
            match part {
                QueryPart::Key(key) => {
                    return match key.parse::<i32>() {
                        Ok(array_idx) =>
                            self.retrieve_index(array_idx, part, &query)?
                                .query(index + 1, query, var_resolver),

                        Err(_) =>
                            self.retrieve_key(key.as_str(), part, query)?
                                .query(index + 1, query, var_resolver),
                    }
                },

                QueryPart::Index(array_idx) =>
                    return self.retrieve_index(*array_idx, part, query)?
                        .query(index + 1, query, var_resolver),

                QueryPart::AllIndices => return self.all_indices(index + 1, part, query, var_resolver),

                QueryPart::AllValues =>
                    return match self.all_indices(index + 1, part, query, var_resolver) {
                        Ok(v) => Ok(v),
                        Err(Error(ErrorKind::IncompatibleError(_))) => self.all_map_values(index + 1, part, query, var_resolver),
                        Err(err) => Err(err)
                    },

                QueryPart::Filter(conjunctions) => {
                    //
                    // There are two possibilities here, either this was a directly a list value
                    // of structs and we need filter, OR we are part of all_map_values.
                    //
                    // TODO: this is special cased here as the parser today treat 'tags[*]' as
                    // for all values in the collection, and 'tag[ key == /PROD/ ]' as just directly
                    // the collection itself. It should technically translate to 'AllValues', 'Filter'
                    //
                    if let Value::List(l) = self {
                        let mut collected = Vec::with_capacity(l.len());
                        for each in l {
                            if Status::PASS == conjunctions.evaluate(each, var_resolver)? {
                                collected.extend(each.query(index + 1, query, var_resolver)?)
                            }
                        }
                        return Ok(collected)
                    }

                    //
                    // Being called from all_map_values
                    //
                    if Status::PASS == conjunctions.evaluate(self, var_resolver)? {
                        return self.query(index+1, query, var_resolver)
                    }

                    //
                    // else not selected
                    //
                    return Ok(vec![])
                },

                _ => unimplemented!()
            }
        }
        let mut collected = Vec::new();
        collected.push(self);
        Ok(collected)
    }

    fn all_indices(&self,
                   index: usize,
                   part: &QueryPart<'_>,
                   query: &[QueryPart<'_>],
                   var_resolver: &dyn EvaluationContext) -> Result<Vec<&Value>> {
        let list = self.match_list(part, query)?;
        let mut collected = Vec::with_capacity(list.len());
        for each in list {
            collected.extend(each.query(index, query, var_resolver)?)
        }
        return Ok(collected)
    }

    fn all_map_values(&self,
                      index: usize,
                      part: &QueryPart<'_>,
                      query: &[QueryPart<'_>],
                      var_resolver: &dyn EvaluationContext) -> Result<Vec<&Value>> {
        let index_map = self.match_map(part, query)?;
        let mut collected = Vec::with_capacity(index_map.len());
        for each in index_map.values() {
            collected.extend(each.query(index, query, var_resolver)?)
        }
        Ok(collected)
    }

    fn match_list(&self, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&Vec<Value>> {
        return if let Value::List(list) = self {
            Ok(list)
        }
        else {
            Err(Error::new(
                ErrorKind::IncompatibleError(
                    format!("Current value type is not a list, Type = {}, Value = {:?}, part = {}, remaining query = {}",
                            type_info(self), self, part, SliceDisplay(remaining))
                )))
        }
    }

    fn match_map(&self, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&indexmap::IndexMap<String, Value>> {
        return if let Value::Map(map) = self {
            Ok(map)
        }
        else {
            Err(Error::new(
                ErrorKind::IncompatibleError(
                    format!("Current self type is not a Map, Type = {}, Value = {:?}, part = {}, remaining query = {}",
                            type_info(self), self, part, SliceDisplay(remaining))
                )))
        }
    }

    fn retrieve_key(&self, key: &str, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&Value> {
        let map = self.match_map(part, remaining)?;
        return if let Some(val) = map.get(key) {
            Ok(val)
        } else {
            Err(Error::new(
                ErrorKind::RetrievalError(
                    format!("Could not locate Key = {} inside Value Map = {:?} part = {}, remaining query = {}",
                            key, self, part, SliceDisplay(remaining))
                )))
        }
    }

    fn retrieve_index(&self, index: i32, part:&QueryPart<'_>, remaining: &[QueryPart<'_>]) -> Result<&Value> {
        let list = self.match_list(part, remaining)?;
        let check = if index >= 0 { index } else { -index } as usize;
        return if check < list.len() {
            Ok(&list[check])
        }
        else {
            Err(Error::new(
                ErrorKind::RetrievalError(
                    format!("Could not locate Index = {} inside Value List = {:?} part = {}, remaining query = {}",
                            index, self, part, SliceDisplay(remaining))
                )))
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//  Useful function to perform quick traversal for testing. Recommend using the query API instead //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

//
// ```
//    let query = AccessQueryWrapper::try_from(
//        "Resource.*[ Type == "AWS::EC2::Instance" ].Volumes")?.0
//    let views = values.query(....)
// ```
//
impl Value {

    pub(crate) fn traverse(&self, path: &str) -> Result<&Value> {
        let mut value = self;
        for each in path.split(".") {
            match each.parse::<i32>() {
                Ok(index) => if let Value::List(list) = value {
                    let index = if index < 0 { list.len() as i32 + index } else { index };
                    if index < 0 || index >= list.len() as i32 {
                        return Err(Error::new(ErrorKind::RetrievalError(
                            format!("Querying for an out of band index = {}, list len = {}", index, list.len()))))
                    }
                    value = &list[index as usize];
                } else {
                    return Err(Error::new(ErrorKind::RetrievalError(
                        format!("Querying for index = {}, value type is not list {}", index, type_info(value)))))
                },

                Err(_) => if let Value::Map(map) = value {
                    if let Some(v) = map.get(each) {
                        value = v;
                    }
                    else {
                        return Err(Error::new(ErrorKind::RetrievalError(
                            format!("Querying for key = {}, did not find in map {:?}", each, value))))
                    }
                } else {
                    return Err(Error::new(ErrorKind::RetrievalError(
                        format!("Querying for key = {}, value type is not map {}", each, type_info(value)))))

                }
            }
        }
        Ok(value)
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
    type Error = super::errors::Error;

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
    type Error = super::errors::Error;

    fn try_from(value: serde_json::Value) -> std::result::Result<Self, Self::Error> {
        Value::try_from(&value)
    }
}

impl <'a> TryFrom<&'a str> for Value {
    type Error = super::errors::Error;

    fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
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

fn compare_values(first: &Value, other: &Value) -> Result<Ordering> {
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

pub(crate) fn compare_eq(first: &Value, second: &Value) -> Result<bool> {
    let (reg, s) = match (first, second) {
        (Value::String(s), Value::Regex(r)) => (regex::Regex::new(r.as_str())?, s.as_str()),
        (Value::Regex(r), Value::String(s)) => (regex::Regex::new(r.as_str())?, s.as_str()),
        (_,_) => return Ok(first == second),
    };
    Ok(reg.is_match(s))
}

pub(crate) fn compare_lt(first: &Value, other: &Value) -> Result<bool> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Equal | Ordering::Greater => Ok(false),
            Ordering::Less => Ok(true)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_le(first: &Value, other: &Value) -> Result<bool> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(false),
            Ordering::Equal | Ordering::Less => Ok(true)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_gt(first: &Value, other: &Value) -> Result<bool> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater => Ok(true),
            Ordering::Less | Ordering::Equal => Ok(false)
        },
        Err(e) => Err(e)
    }
}

pub(crate) fn compare_ge(first: &Value, other: &Value) -> Result<bool> {
    match compare_values(first, other) {
        Ok(o) => match o {
            Ordering::Greater | Ordering::Equal => Ok(true),
            Ordering::Less => Ok(false)
        },
        Err(e) => Err(e)
    }
}

#[cfg(test)]
#[path = "values_tests.rs"]
mod values_tests;
