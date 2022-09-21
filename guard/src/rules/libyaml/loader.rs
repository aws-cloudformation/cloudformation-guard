use std::borrow::Cow;
use crate::{
    rules::{
        self,
        path_value::Location,
        values::MarkedValue,
        libyaml::{
            event::{Event, Scalar, SequenceStart, ScalarStyle},
            parser::Parser,
        },
        errors::{Error, ErrorKind}
    }
};

#[derive(Debug, Default)]
pub struct Loader {
    stack: Vec<MarkedValue>,
    documents: Vec<MarkedValue>,
    last_container_index: Vec<usize>,
    func_support_index: Vec<(usize, (String, Location))>,
}

impl Loader {
    pub fn new() -> Loader { Loader::default() }

    pub(crate) fn load(&mut self, content: String) -> rules::Result<MarkedValue> {
        let mut parser = Parser::new(Cow::Borrowed(content.as_bytes()));

        loop {
            match parser.next() {
                Ok((event, location)) => {
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
                        Event::SequenceStart(sequence_start) => self.handle_sequence_start(sequence_start, location),
                        Event::SequenceEnd => self.handle_sequence_end(),
                        Event::Scalar(scalar) => self.handle_scalar_event(scalar, location),
                        Event::Alias(_) => return Err(Error(ErrorKind::ParseError(String::from("Guard does not currently support aliases")))),
                        _ => todo!()
                    };
                }
                Err(e) => return Err(Error(ErrorKind::ParseError(format!("{}", e)))),
            };
        }
    }

    fn handle_scalar_event(&mut self, event: Scalar, location: Location) {
        let Scalar { tag, value, style, .. } = event;
        let val = match std::str::from_utf8(&value) {
            Ok(s) => s.to_string(),
            Err(_) => "".to_string(),
        };
        let path_value =
            if let Some(tag) = tag {
                let handle = tag.get_handle();
                let suffix = tag.get_suffix(handle.len());
                if handle == "!!" {
                    Self::handle_type_ref(val, location, suffix.as_ref())
                } else if handle == "!" {
                    Self::handle_single_value_func_ref(val.clone(), location.clone(), suffix.as_ref())
                        .map_or(
                            MarkedValue::String(val, location),
                            std::convert::identity,
                        )
                } else {
                    MarkedValue::String(val, location)
                }
            } else if style != ScalarStyle::Plain {
                MarkedValue::String(val, location)
            } else {
                if !val.is_empty() && Self::is_number(&val) {
                    match val.parse::<i64>() {
                        Ok(i) => MarkedValue::Int(i, location),
                        Err(_) => {
                            val.parse::<f64>().ok().map_or(
                                MarkedValue::BadValue(val, location.clone()),
                                |f| MarkedValue::Float(f, location),
                            )
                        }
                    }
                } else {
                    match val.parse::<bool>() {
                        Ok(b) => MarkedValue::Bool(b, location),
                        Err(_) => MarkedValue::String(val, location)
                    }
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
            _ => unreachable!()
        }

        if self.func_support_index.last().map_or(false, |(idx, _)| *idx == array_idx - 1) {
            let (_, fn_ref) = self.func_support_index.pop().unwrap();
            let array = self.stack.pop().unwrap();
            let map = self.stack.last_mut().unwrap();
            match map {
                MarkedValue::Map(map, _) => {
                    let _ = map.insert(fn_ref, array);
                }
                MarkedValue::BadValue(..) => {}
                _ => unreachable!()
            }
        }
    }

    fn handle_sequence_start(&mut self, event: SequenceStart, location: Location) {
        // let a = event.anchor.unwrap();
        if let Some(tag) = &event.tag {
            let handle = tag.get_handle();
            let suffix = tag.get_suffix(handle.len());
            if handle == "!" {
                match Self::handle_sequence_value_func_ref(location.clone(), &suffix) {
                    Some(value) => {
                        self.stack.push(value);
                        let fn_ref = Self::short_form_to_long(&suffix);
                        self.func_support_index.push((self.stack.len() - 1, (fn_ref.to_owned(), location.clone())));
                    }
                    None => {}
                }
            }
        }
        self.stack.push(
            MarkedValue::List(vec![], location)
        );
        self.last_container_index.push(self.stack.len() - 1);
    }

    fn handle_mapping_end(&mut self) {
        let map_index = self.last_container_index.pop().unwrap();
        let mut key_values: Vec<MarkedValue> = self.stack.drain(map_index + 1..).collect();
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
    }

    fn handle_mapping_start(&mut self, location: Location) {
        self.stack.push(
            MarkedValue::Map(
                indexmap::IndexMap::new(),
                location,
            )
        );
        self.last_container_index.push(self.stack.len() - 1);
    }

    fn is_number(val: &str) -> bool {
        for c in val.chars() {
            if !c.is_numeric() {
                return false;
            }
        }
        return true;
    }

    fn short_form_to_long(fn_ref: &str) -> &'static str {
        match fn_ref {
            "Ref" => "Ref",
            "GetAtt" => "Fn::GetAtt",
            "Base64" => "Fn::Base64",
            "Sub" => "Fn::Sub",
            "GetAZs" => "Fn::GetAZs",
            "ImportValue" => "Fn::ImportValue",
            "Condition" => "Condition",
            "RefAll" => "Fn::RefAll",
            "Select" => "Fn::Select",
            "Split" => "Fn::Split",
            "Join" => "Fn::Join",
            "FindInMap" => "Fn::FindInMap",
            "And" => "Fn::And",
            "Equals" => "Fn::Equals",
            "Contains" => "Fn::Contains",
            "EachMemberIn" => "Fn::EachMemberIn",
            "EachMemberEquals" => "Fn::EachMemberEquals",
            "ValueOf" => "Fn::ValueOf",
            "If" => "Fn::If",
            "Not" => "Fn::Not",
            "Or" => "Fn::Or",
            _ => unreachable!()
        }
    }

    fn handle_single_value_func_ref(
        val: String,
        loc: Location,
        fn_ref: &str) -> Option<MarkedValue>
    {
        match fn_ref {
            "Ref" |
            "Base64" |
            "Sub" |
            "GetAZs" |
            "ImportValue" |
            "GetAtt" |
            "Condition" |
            "RefAll" => {
                let mut map = indexmap::IndexMap::new();
                let fn_ref = Self::short_form_to_long(fn_ref);
                map.insert((fn_ref.to_string(), loc.clone()), MarkedValue::String(val, loc.clone()));
                Some(MarkedValue::Map(map, loc))
            }

            _ => None,
        }
    }

    fn handle_sequence_value_func_ref(
        loc: Location,
        fn_ref: &str) -> Option<MarkedValue> {
        match fn_ref {
            "GetAtt" |
            "Sub" |
            "Select" |
            "Split" |
            "Join" |
            "FindInMap" |
            "And" |
            "Equals" |
            "Contains" |
            "EachMemberIn" |
            "EachMemberEquals" |
            "ValueOf" |
            "If" |
            "Not" |
            "Or" => {
                let mut map = indexmap::IndexMap::new();
                let fn_ref = Self::short_form_to_long(fn_ref);
                map.insert((fn_ref.to_string(), loc.clone()), MarkedValue::Null(loc.clone()));
                Some(MarkedValue::Map(map, loc))
            }

            _ => None,
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