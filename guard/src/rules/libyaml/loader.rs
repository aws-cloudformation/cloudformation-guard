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
    last_container_index: Vec<usize>,
    func_support_index: Vec<(usize, (String, Location))>,
}

impl Loader {
    pub fn new() -> Loader {
        Loader::default()
    }

    pub(crate) fn load(&mut self, content: String) -> rules::Result<MarkedValue> {
        let mut parser = Parser::new(Cow::Borrowed(content.as_bytes()));
        let mut document: Option<MarkedValue> = None;

        loop {
            let (event, location) = parser.next()?;
            {
                match event {
                    Event::StreamStart => {}
                    // A second `DocumentStart` means the file holds a stream rather than a
                    // document, and cfn-guard has one slot to put a document in: `DataFile` carries
                    // a single `path_value`, and every reporter, the summary and the exit code are
                    // written against one document per file.
                    //
                    // This used to return at the first `DocumentEnd`, which answered an n-document
                    // stream with the first document and said nothing. Prefixing a template with a
                    // compliant document and a `---` therefore suppressed every finding in the real
                    // one at exit 0. Worse, returning there dropped the parser, so the bytes after
                    // the first document were never handed to libyaml at all and a stream whose
                    // later document was not YAML also passed.
                    //
                    // Refusing the file is the answer here rather than evaluating every document,
                    // because evaluating all of them is a feature and not a bug fix: it needs
                    // `DataFile` to hold a list, every reporter to name which document a finding
                    // came from, and a rule for combining n verdicts into one exit code. Refusing
                    // is contained in the loader and cannot report compliance for bytes it did not
                    // read, which is the actual defect. Neither corpus contains a multi-document
                    // file, so nothing that works today stops working.
                    Event::DocumentStart => {
                        if document.is_some() {
                            return Err(Error::UnsupportedDocument(format!(
                                "cfn-guard evaluates one document per file, and this file holds \
                                 more than one: a second document starts at {location}. Split the \
                                 documents into separate files."
                            )));
                        }
                    }
                    // Reaching the end of the stream with a document in hand is the ordinary exit.
                    // With none, no document was ever started -- a file of nothing but comments is
                    // the ordinary way to get here. Treating it as a no-op left the loop pulling
                    // events past the end of the stream, where libyaml answers with
                    // `YAML_NO_EVENT`, and that used to abort the process in `convert_event`.
                    Event::StreamEnd => return document.ok_or(Error::MissingDocument),
                    Event::DocumentEnd => {
                        document = Some(self.stack.pop().unwrap());
                        self.stack.clear();
                        self.last_container_index.clear();
                        self.func_support_index.clear();
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
                    // `f64::from_str` also accepts `nan`, `inf` and `infinity`, none of which
                    // YAML resolves to a float. YAML spells the non-finite floats `.nan` and
                    // `.inf`, and those spellings already fall through to `String` here, so
                    // accepting the Rust-only ones made the two halves disagree.
                    //
                    // Keeping `NaN` out of the value space is the part that matters:
                    // `PathAwareValue` asserts `Eq` and hashes its own contents, and
                    // `Float(NaN)` is not equal to itself. A NaN-keyed entry can never be
                    // found again, and no comparison against one can be answered, so a clause
                    // that guards on it cannot decide either way.
                    Ok(f) if f.is_finite() => MarkedValue::Float(f, location),
                    _ => match parse_bool(&val) {
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

/// The spellings a plain scalar is read as boolean, which is the set YAML 1.1 defines at
/// <https://yaml.org/type/bool.html>:
///
/// ```text
/// y|Y|yes|Yes|YES|n|N|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF
/// ```
///
/// Three casings of each word and no others, so `tRuE` is a string. Matching case-insensitively
/// instead would have been shorter and would have accepted spellings no schema makes boolean.
///
/// `true`, `True`, `TRUE` and the three matching spellings of false are boolean under the YAML 1.2
/// core schema as well, whose whole set is `true | True | TRUE | false | False | FALSE`
/// (<https://yaml.org/spec/1.2.2/#103-core-schema>, which resolves everything else here to `str`).
/// So those four were missing whichever version the loader meant. `yes`, `on` and the single
/// letters are boolean only under 1.1, and the loader was already reading them that way, which is
/// what settles the version question: the vocabulary was 1.1's with the capitalised spellings left
/// out of it, not 1.2's with extras. Dropping `yes` and `on` to reach the 1.2 set instead would
/// take a string a document writes today and start comparing it as a boolean, so it is a separate
/// argument from this one.
///
/// This is the same defect `rules::parser::parse_bool` carries for the rules language, and it has
/// the same consequences. The two sets need not be equal: that one parses a literal in cfn-guard's
/// own grammar, this one resolves a scalar in someone else's document.
fn parse_bool(val: &str) -> Option<bool> {
    if is_bool_true(val) {
        Some(true)
    } else if is_bool_false(val) {
        Some(false)
    } else {
        None
    }
}

fn is_bool_true(s: &str) -> bool {
    matches!(
        s,
        "y" | "Y" | "yes" | "Yes" | "YES" | "true" | "True" | "TRUE" | "on" | "On" | "ON"
    )
}

fn is_bool_false(s: &str) -> bool {
    matches!(
        s,
        "n" | "N" | "no" | "No" | "NO" | "false" | "False" | "FALSE" | "off" | "Off" | "OFF"
    )
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
        // Through the same set as a plain scalar. This read `str::parse::<bool>`, which takes
        // `true` and `false` and nothing else, so an explicit tag was stricter than the untagged
        // resolution it should agree with: `!!bool yes` was the string "yes" while a bare `yes` was
        // already a boolean. The fallback to a string for a value outside the set is unchanged.
        "tag:yaml.org,2002:bool" => match parse_bool(&val) {
            None => MarkedValue::String(val, loc),
            Some(v) => MarkedValue::Bool(v, loc),
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
