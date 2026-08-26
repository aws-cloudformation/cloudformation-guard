use std::{
    convert::TryFrom,
    fmt,
    fmt::Display,
    hash::{Hash, Hasher},
};

use indexmap::map::IndexMap;
use nom::lib::std::fmt::Formatter;

use crate::rules::{
    errors::{Error, InternalError},
    libyaml::loader::Loader,
    long_form_of,
    parser::Span,
    path_value::Location,
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
    IsFloat,
    IsNull,
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
                    // Reached only for a positive integer above `i64::MAX`, since `is_i64` takes
                    // everything that fits. This was `num.as_u64().unwrap() as i64`, under a comment
                    // reading "Yes we are losing precision here. TODO fix this". It was not losing
                    // precision: `as i64` reinterprets the bit pattern, so the sign flipped.
                    // `u64::MAX` read as exactly -1 and `i64::MAX + 1` as exactly `i64::MIN`, which
                    // inverts every numeric guard in the language -- `A < 0` passed, `A > 0` failed,
                    // and `MaxSize <= 1000` passed for an input of 18446744073709551615, at exit 0
                    // with nothing on either channel.
                    //
                    // The digits are kept instead. `u64::to_string` is exact, so nothing is invented,
                    // and a comparison against a number then refuses rather than answering from a
                    // number the input does not contain. It is also the answer the libyaml loader
                    // already gives an integer this wide, so the two agree.
                    Ok(Value::String(num.as_u64().unwrap().to_string()))
                } else {
                    let float = num.as_f64().unwrap();

                    // The finiteness gate the libyaml loader has and this conversion did not.
                    // `PathAwareValue` asserts `Eq` and hashes its own contents, and `Float(NaN)` is
                    // not equal to itself, so admitting one made `A == A` report FAIL under
                    // `guard test` on a document that PASSed under `validate`. `.inf` was worse than
                    // inert: `A > 9223372036854775807` passed under `test` where the same document
                    // refused under `validate`.
                    //
                    // These are the two entry points rule authors prove their rules with -- the
                    // `test` subcommand and the public `run_checks` -- so the divergence ran in the
                    // worst direction available.
                    if float.is_finite() {
                        Ok(Value::Float(float))
                    } else {
                        Ok(Value::String(non_finite_spelling(float)))
                    }
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
                    match key {
                        serde_yaml::Value::String(key) => {
                            res.insert(key.to_string(), Value::try_from(val)?);
                        }
                        _ => {
                            // NOTE: can't provide a location for our error here since serde_yaml
                            // doesn't provide that for us
                            return Err(Error::InternalError(InternalError::InvalidKeyType(
                                String::default(),
                            )));
                        }
                    }
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
        Err(e) => match e {
            // All three are passed through rather than flattened into a `ParseError`, because the
            // caller decides how to word them and needs to be able to tell them apart. Flattening
            // `UnsupportedDocument` would lose the distinction the caller uses to decide whether the
            // message is worth printing on its own or needs the file's first bytes attached.
            Error::InternalError(..) | Error::MissingDocument | Error::UnsupportedDocument(..) => {
                Err(e)
            }
            _ => Err(Error::ParseError(format!("{}", e))),
        },
    }
}

#[cfg(test)]
pub(super) fn make_linked_hashmap<'a, I>(values: I) -> IndexMap<String, Value>
where
    I: IntoIterator<Item = (&'a str, Value)>,
{
    values.into_iter().map(|(s, v)| (s.to_owned(), v)).collect()
}

/// YAML's own spelling of a non-finite float, which is what the libyaml loader leaves behind.
///
/// That loader keeps the literal the document wrote, and `serde_yaml` only resolves a float from
/// `.nan`, `.inf` and `-.inf` -- bare `NaN` and `inf` stay strings in both, being outside the YAML
/// 1.2 core schema. So returning the canonical spelling here makes the two loaders agree exactly on
/// every input that can reach this function, rather than approximately.
///
/// `f64::to_string` was the alternative and it would have produced "NaN" and "inf", which no YAML
/// document writes and neither loader would then match.
fn non_finite_spelling(float: f64) -> String {
    if float.is_nan() {
        ".nan".to_string()
    } else if float.is_sign_positive() {
        ".inf".to_string()
    } else {
        "-.inf".to_string()
    }
}

/// Wraps a `!Foo`-tagged value as `{ "Fn::Foo": payload }`.
///
/// This is the serde-backed loader's half of the same two fixes the libyaml loader carries, and it has
/// to move with it: `guard test` and the public `run_checks` read documents through here, so a
/// disagreement means a rule proved correct under `guard test` behaves differently under `validate` on
/// the same bytes.
///
/// It used to check the union of two hand-written name sets and, on a miss, discard the tag and keep
/// only the payload -- so the short form of Cidr, ForEach, GetStackOutput, Length, ToJsonString,
/// Transform or ValueOfAll became something else. `long_form_of` supplies the name for any `!Foo`
/// instead, by CloudFormation's own rule that `!Foo` is `Fn::Foo`.
///
/// `GetAtt` also gets its dotted payload split, for the reason given on `libyaml::loader::getatt_payload`:
/// AWS documents `!GetAtt Resource.Attr` as the short form of the two-element list, and JSON has no
/// other shape for it, so leaving the dotted form a string gives one reference two incomparable shapes.
fn handle_tagged_value(val: serde_yaml::Value, fn_ref: &str) -> crate::rules::Result<Value> {
    let payload = Value::try_from(val)?;
    let payload = match (fn_ref, &payload) {
        ("GetAtt", Value::String(reference)) => match reference.split_once('.') {
            Some((resource, attribute)) => Value::List(vec![
                Value::String(resource.to_string()),
                Value::String(attribute.to_string()),
            ]),
            None => payload,
        },
        _ => payload,
    };

    let mut map = indexmap::IndexMap::new();
    map.insert(long_form_of(fn_ref).into_owned(), payload);

    Ok(Value::Map(map))
}

#[cfg(test)]
#[path = "values_tests.rs"]
mod values_tests;
