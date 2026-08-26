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
            match resolve_int(&val) {
                IntScalar::Resolved(i) => MarkedValue::Int(i, location),
                // Short-circuits the float resolver on purpose. `"0755".parse::<f64>()` is 755.0,
                // so falling through would swap one wrong number for another.
                IntScalar::Unresolvable => MarkedValue::String(val, location),
                IntScalar::NotAnInteger => match val.parse::<f64>() {
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
                        // The empty scalar belongs in this set. It is the value of a key written
                        // with nothing after the colon, and both the YAML 1.1 and 1.2 schemas
                        // resolve it to the null node; leaving it out made the loader unable to
                        // tell `k:` from `k: ""`, which YAML says are null and the empty string.
                        //
                        // Only a *plain* scalar reaches here -- the `style != Plain` arm above
                        // takes every quoted one -- so `k: ""` is still the empty string, which is
                        // the whole reason this can be decided on emptiness alone.
                        None => match val.to_lowercase().as_str() {
                            "" | "~" | "null" => MarkedValue::Null(location),
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

/// What `resolve_int` decided about a plain scalar.
enum IntScalar {
    /// An integer, and this is its value.
    Resolved(i64),
    /// Integer-shaped, but not a number this loader will commit to. It stays a string, and the float
    /// resolver does not get a turn -- most of these parse as floats, so handing them on would swap
    /// one wrong number for another.
    Unresolvable,
    /// Not integer-shaped. The float resolver gets its turn.
    NotAnInteger,
}

/// Integer resolution for a plain scalar: the YAML 1.2 core schema
/// (<https://yaml.org/spec/1.2.2/#103-core-schema>), which is `[-+]?[0-9]+` decimal, `0o[0-7]+`
/// octal and `0x[0-9a-fA-F]+` hex, with two deliberate departures noted below.
///
/// This was `str::parse::<i64>`, which takes an optional sign and decimal digits and nothing else.
/// So no radix prefix resolved as a number at all -- `0x1F` and `0o17` were strings, and a rule
/// comparing a netmask or a permission bitmask to a number could not match -- while `0755` was read
/// as decimal 755.
///
/// **A leading sign is accepted on the radix forms** even though the 1.2 regexes do not carry one, so
/// `-0x10` is -16. No YAML version reads that text as a *different* number, and `serde_yaml` -- the
/// loader `guard test` and `run_checks` reach on the same bytes -- resolves it too, so accepting it
/// removes a divergence and cannot introduce a wrong value.
///
/// **A decimal integer with a redundant leading zero stays a string**, so `0755` is the text "0755".
/// This is the one spelling where the two YAML versions assign *different values* to the same
/// characters: 1.1 reads it as octal 493 (<https://yaml.org/type/int.html>), 1.2 core's decimal
/// regex reads it as 755. A file mode or a netmask written `0755` almost certainly means 493, so
/// resolving it either way silently produces a number the author did not write; keeping the literal
/// is the only answer that cannot be quietly wrong, and it is also what `serde_yaml` does.
///
/// The prefixes are lowercase only, which is 1.2 core's regex exactly and what `serde_yaml` does:
/// `0X1F` and `0O17` are strings. One divergence from `serde_yaml` is left standing on purpose:
/// `0b101` is a string here and an integer there. YAML 1.2 core has no binary form -- it is 1.1's --
/// and following the extension would mean re-adding a 1.1-ism of exactly the kind the boolean set
/// dropped.
fn resolve_int(val: &str) -> IntScalar {
    let (negative, magnitude) = match val.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, val.strip_prefix('+').unwrap_or(val)),
    };

    let (radix, digits) = match magnitude.strip_prefix("0x") {
        Some(rest) => (16, rest),
        None => match magnitude.strip_prefix("0o") {
            Some(rest) => (8, rest),
            None => (10, magnitude),
        },
    };

    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return IntScalar::NotAnInteger;
    }

    if radix == 10 && digits.len() > 1 && digits.starts_with('0') {
        return IntScalar::Unresolvable;
    }

    let signed = if negative {
        Cow::Owned(format!("-{digits}"))
    } else {
        Cow::Borrowed(digits)
    };

    match i64::from_str_radix(&signed, radix) {
        Ok(i) => IntScalar::Resolved(i),
        Err(_) => IntScalar::NotAnInteger,
    }
}

/// The spellings a plain scalar is read as boolean: the YAML 1.2 core schema's set, which is the
/// whole of `true | True | TRUE | false | False | FALSE`
/// (<https://yaml.org/spec/1.2.2/#103-core-schema>, which resolves every other spelling to `str`).
///
/// Three casings of each word and no others, so `tRuE` is a string. Matching case-insensitively
/// would have been shorter and would have accepted spellings no schema makes boolean.
///
/// This used to be YAML 1.1's set of 22 (<https://yaml.org/type/bool.html>), which adds `y`, `Y`,
/// `n`, `N`, `yes`, `no`, `on`, `off` and their casings. Three separate readers of the same document
/// disagreed with that:
///
///   - `rules::parser::parse_bool`, which reads a boolean literal in cfn-guard's own grammar,
///     accepts exactly the six spellings above. So `Enabled == true` and a document writing
///     `Enabled: yes` were being compared across two different vocabularies.
///   - `serde_yaml`, which is the loader `guard test` and the public `run_checks` reach on the same
///     bytes, is 1.2 core. A rule proved correct under `guard test` could fail under `validate`.
///   - libyaml, whose parser this file wraps, does not resolve the single letters either; neither
///     does PyYAML, the other widely used 1.1 implementation. The 1.1 *type page* lists them, but
///     the implementations do not.
///
/// The concrete harm was not hypothetical. `AttributeType: N` is what the DynamoDB documentation
/// shows for a numeric attribute, unquoted, and it resolved to `false`: a rule asserting
/// `AttributeType IN ["S","N","B"]` failed, and the same value inside a filter selected nothing and
/// skipped the rule at exit 0. Every GitHub Actions workflow in this repository was unreadable for
/// the same reason -- `on:` resolved to a boolean, and a boolean is not a valid mapping key, so the
/// whole file was refused.
///
/// The cost of the change is the other direction: a document that writes `Encrypted: yes` meaning
/// true now yields the string "yes", and a clause comparing it to `true` reports the type mismatch
/// instead of passing. That is the trade, and it is the right way round -- the tool now says it
/// cannot decide, where it used to decide by a rule none of its other three readers shared. No
/// `.guard` file in the rules registry or this repository writes a bare 1.1-only spelling as a
/// literal, and no data fixture in either writes one as a value.
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
    matches!(s, "true" | "True" | "TRUE")
}

fn is_bool_false(s: &str) -> bool {
    matches!(s, "false" | "False" | "FALSE")
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
