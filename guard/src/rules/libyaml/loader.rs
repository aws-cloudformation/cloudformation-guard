use lazy_static::lazy_static;
use std::borrow::Cow;

use crate::rules::{
    self,
    errors::Error,
    libyaml::{
        event::{Event, Scalar, ScalarStyle, SequenceStart},
        parser::Parser,
    },
    path_value::Location,
    values::MarkedValue,
};

use std::collections::{HashMap, HashSet};

lazy_static! {
    static ref SHORT_FORM_TO_LONG_MAPPING: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Ref", "Ref");
        m.insert("GetAtt", "Fn::GetAtt");
        m.insert("Base64", "Fn::Base64");
        m.insert("Sub", "Fn::Sub");
        m.insert("GetAZs", "Fn::GetAZs");
        m.insert("ImportValue", "Fn::ImportValue");
        m.insert("Condition", "Condition");
        m.insert("RefAll", "Fn::RefAll");
        m.insert("Select", "Fn::Select");
        m.insert("Split", "Fn::Split");
        m.insert("Join", "Fn::Join");
        m.insert("FindInMap", "Fn::FindInMap");
        m.insert("And", "Fn::And");
        m.insert("Equals", "Fn::Equals");
        m.insert("Contains", "Fn::Contains");
        m.insert("EachMemberIn", "Fn::EachMemberIn");
        m.insert("EachMemberEquals", "Fn::EachMemberEquals");
        m.insert("ValueOf", "Fn::ValueOf");
        m.insert("If", "Fn::If");
        m.insert("Not", "Fn::Not");
        m.insert("Or", "Fn::Or");
        m
    };
    static ref SINGLE_VALUE_FUNC_REF: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("Ref");
        set.insert("Base64");
        set.insert("Sub");
        set.insert("GetAZs");
        set.insert("ImportValue");
        set.insert("GetAtt");
        set.insert("Condition");
        set.insert("RefAll");
        set
    };
    static ref SEQUENCE_VALUE_FUNC_REF: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("GetAtt");
        set.insert("Sub");
        set.insert("Select");
        set.insert("Split");
        set.insert("Join");
        set.insert("FindInMap");
        set.insert("And");
        set.insert("Equals");
        set.insert("Contains");
        set.insert("EachMemberIn");
        set.insert("EachMemberEquals");
        set.insert("ValueOf");
        set.insert("If");
        set.insert("Not");
        set.insert("Or");
        set
    };
}

const TYPE_REF_PREFIX: &str = "tag:yaml.org,2002:";

#[derive(Debug, Default)]
pub struct Loader {
    stack: Vec<MarkedValue>,
    documents: Vec<MarkedValue>,
    last_container_index: Vec<usize>,
    func_support_index: Vec<(usize, (String, Location))>,
}

impl Loader {
    pub fn new() -> Loader {
        Loader::default()
    }

    pub(crate) fn load(&mut self, content: String) -> rules::Result<MarkedValue> {
        let mut parser = Parser::new(Cow::Borrowed(content.as_bytes()));

        loop {
            match parser.next()? {
                (event, location) => {
                    match event {
                        Event::StreamStart | Event::StreamEnd | Event::DocumentStart => {}
                        Event::DocumentEnd => {
                            self.documents.push(self.stack.pop().unwrap());
                            self.stack.clear();
                            self.last_container_index.clear();
                            return Ok(self.documents.pop().unwrap());
                        }
                        Event::MappingStart(..) => self.handle_mapping_start(location),
                        Event::MappingEnd => self.handle_mapping_end(),
                        Event::SequenceStart(sequence_start) => {
                            self.handle_sequence_start(sequence_start, location)
                        }
                        Event::SequenceEnd => self.handle_sequence_end(),
                        Event::Scalar(scalar) => self.handle_scalar_event(scalar, location),
                        Event::Alias(_) => {
                            return Err(Error::ParseError(String::from(
                                "Guard does not currently support aliases",
                            )))
                        }
                    };
                }
            };
        }
    }

    fn handle_scalar_event(&mut self, event: Scalar, location: Location) {
        let Scalar {
            tag, value, style, ..
        } = event;
        let val = match std::str::from_utf8(&value) {
            Ok(s) => s.to_string(),
            Err(_) => "".to_string(),
        };

        let path_value = if let Some(tag) = tag {
            let handle = tag.get_handle();
            let suffix = tag.get_suffix(handle.len());

            if handle == "!" {
                handle_single_value_func_ref(val.clone(), location.clone(), suffix.as_ref())
                    .map_or(MarkedValue::String(val, location), std::convert::identity)
            } else if suffix.starts_with(TYPE_REF_PREFIX) {
                handle_type_ref(val, location, suffix.as_ref())
            } else {
                MarkedValue::String(val, location)
            }
        } else if style != ScalarStyle::Plain {
            MarkedValue::String(val, location)
        } else {
            match val.parse::<i64>() {
                Ok(i) => MarkedValue::Int(i, location),
                Err(_) => match val.parse::<f64>() {
                    Ok(f) => MarkedValue::Float(f, location),
                    Err(_) => match val.parse::<bool>() {
                        Ok(b) => MarkedValue::Bool(b, location),
                        Err(_) => MarkedValue::String(val, location),
                    },
                },
            }
        };

        self.stack.push(path_value);
    }

    fn handle_sequence_end(&mut self) {
        let array_idx = self.last_container_index.pop().unwrap();
        let values: Vec<MarkedValue> = self.stack.drain(array_idx + 1..).collect();
        let array = self.stack.last_mut().unwrap();
        match array {
            MarkedValue::List(vec, _) => vec.extend(values),
            _ => unreachable!(),
        }

        if self
            .func_support_index
            .last()
            .map_or(false, |(idx, _)| *idx == array_idx - 1)
        {
            let (_, fn_ref) = self.func_support_index.pop().unwrap();
            let array = self.stack.pop().unwrap();
            let map = self.stack.last_mut().unwrap();
            match map {
                MarkedValue::Map(map, _) => {
                    let _ = map.insert(fn_ref, array);
                }
                MarkedValue::BadValue(..) => {}
                _ => unreachable!(),
            }
        }
    }

    fn handle_sequence_start(&mut self, event: SequenceStart, location: Location) {
        if let Some(tag) = &event.tag {
            let handle = tag.get_handle();
            let suffix = tag.get_suffix(handle.len());
            if handle == "!" {
                match handle_sequence_value_func_ref(location.clone(), &suffix) {
                    Some(value) => {
                        self.stack.push(value);
                        let fn_ref = short_form_to_long(&suffix);
                        self.func_support_index
                            .push((self.stack.len() - 1, (fn_ref.to_owned(), location.clone())));
                    }
                    None => {}
                }
            }
        }
        self.stack.push(MarkedValue::List(vec![], location));
        self.last_container_index.push(self.stack.len() - 1);
    }

    fn handle_mapping_end(&mut self) {
        let map_index = self.last_container_index.pop().unwrap();
        let mut key_values: Vec<MarkedValue> = self.stack.drain(map_index + 1..).collect();
        let map = match self.stack.last_mut().unwrap() {
            MarkedValue::Map(map, _) => map,
            _ => unreachable!(),
        };
        while !key_values.is_empty() {
            let key = key_values.remove(0);
            let value = key_values.remove(0);
            let key_str = match key {
                MarkedValue::String(val, loc) => (val, loc),
                _ => unreachable!(),
            };
            map.insert(key_str, value);
        }
    }

    fn handle_mapping_start(&mut self, location: Location) {
        self.stack
            .push(MarkedValue::Map(indexmap::IndexMap::new(), location));
        self.last_container_index.push(self.stack.len() - 1);
    }
}

fn short_form_to_long(fn_ref: &str) -> &'static str {
    match SHORT_FORM_TO_LONG_MAPPING.get(fn_ref) {
        Some(fn_ref) => fn_ref,
        _ => unreachable!(),
    }
}

fn handle_single_value_func_ref(val: String, loc: Location, fn_ref: &str) -> Option<MarkedValue> {
    if SINGLE_VALUE_FUNC_REF.contains(fn_ref) {
        let mut map = indexmap::IndexMap::new();
        let fn_ref = short_form_to_long(fn_ref);
        map.insert(
            (fn_ref.to_string(), loc.clone()),
            MarkedValue::String(val, loc.clone()),
        );

        return Some(MarkedValue::Map(map, loc));
    }

    None
}

fn handle_sequence_value_func_ref(loc: Location, fn_ref: &str) -> Option<MarkedValue> {
    if SEQUENCE_VALUE_FUNC_REF.contains(fn_ref) {
        let mut map = indexmap::IndexMap::new();
        let fn_ref = short_form_to_long(fn_ref);
        map.insert(
            (fn_ref.to_string(), loc.clone()),
            MarkedValue::Null(loc.clone()),
        );

        return Some(MarkedValue::Map(map, loc));
    }

    None
}

fn handle_type_ref(val: String, loc: Location, type_ref: &str) -> MarkedValue {
    match type_ref {
        "tag:yaml.org,2002:bool" => match val.parse::<bool>() {
            Err(_) => MarkedValue::String(val, loc),
            Ok(v) => MarkedValue::Bool(v, loc),
        },
        "tag:yaml.org,2002:int" => match val.parse::<i64>() {
            Err(_) => MarkedValue::BadValue(val, loc),
            Ok(v) => MarkedValue::Int(v, loc),
        },
        "tag:yaml.org,2002:float" => match val.parse::<f64>() {
            Err(_) => MarkedValue::BadValue(val, loc),
            Ok(v) => MarkedValue::Float(v, loc),
        },
        "tag:yaml.org,2002:null" => match val.as_ref() {
            "~" | "null" => MarkedValue::Null(loc),
            _ => MarkedValue::BadValue(val, loc),
        },
        _ => MarkedValue::String(val, loc),
    }
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod loader_tests;
