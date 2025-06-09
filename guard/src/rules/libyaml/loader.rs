use std::borrow::Cow;

use crate::rules::{
    self,
    errors::{Error, InternalError::InvalidKeyType},
    libyaml::{
        event::{Event, Scalar, ScalarStyle, SequenceStart},
        parser::Parser,
    },
    path_value::Location,
    short_form_to_long,
    values::MarkedValue,
    SEQUENCE_VALUE_FUNC_REF, SINGLE_VALUE_FUNC_REF,
};

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
            let (event, location) = parser.next()?;
            {
                match event {
                    Event::StreamStart | Event::StreamEnd | Event::DocumentStart => {}
                    Event::DocumentEnd => {
                        self.documents.push(self.stack.pop().unwrap());
                        self.stack.clear();
                        self.last_container_index.clear();
                        return Ok(self.documents.pop().unwrap());
                    }
                    Event::MappingStart(..) => self.handle_mapping_start(location),
                    Event::MappingEnd => self.handle_mapping_end()?,
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
                    Err(_) => match self.parse_bool(&val) {
                        Some(b) => MarkedValue::Bool(b, location),
                        None => match val.to_lowercase().as_str() {
                            "~" | "null" => MarkedValue::Null(location),
                            _ => MarkedValue::String(val, location),
                        },
                    },
                },
            }
        };

        self.stack.push(path_value);
    }
    fn is_bool_true(&self, s: &str) -> bool {
        matches!(s, "true" | "yes" | "on" | "y")
    }

    fn is_bool_false(&self, s: &str) -> bool {
        matches!(s, "false" | "no" | "off" | "n")
    }

    fn parse_bool(&self, val: &str) -> Option<bool> {
        if self.is_bool_true(val) {
            Some(true)
        } else if self.is_bool_false(val) {
            Some(false)
        } else {
            None
        }
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
                if let Some(value) = handle_sequence_value_func_ref(location.clone(), &suffix) {
                    self.stack.push(value);
                    let fn_ref = short_form_to_long(&suffix);
                    self.func_support_index
                        .push((self.stack.len() - 1, (fn_ref.to_owned(), location.clone())));
                }
            }
        }
        self.stack.push(MarkedValue::List(vec![], location));
        self.last_container_index.push(self.stack.len() - 1);
    }

    fn handle_mapping_end(&mut self) -> crate::rules::Result<()> {
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
                val => {
                    return Err(Error::InternalError(InvalidKeyType(
                        val.location().to_string(),
                    )));
                }
            };

            map.insert(key_str, value);
        }

        Ok(())
    }

    fn handle_mapping_start(&mut self, location: Location) {
        self.stack
            .push(MarkedValue::Map(indexmap::IndexMap::new(), location));
        self.last_container_index.push(self.stack.len() - 1);
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
        "tag:yaml.org,2002:null" => MarkedValue::Null(loc),
        _ => MarkedValue::String(val, loc),
    }
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod loader_tests;
