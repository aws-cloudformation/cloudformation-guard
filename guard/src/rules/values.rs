use std::{
    convert::TryFrom,
    fmt,
    fmt::Display,
    hash::{Hash, Hasher},
};

use indexmap::map::IndexMap;
use nom::lib::std::fmt::Formatter;
use std::collections::HashMap;

// Re-exported for `commands::test`, which renders a non-string expectation the way the loader renders
// a non-string mapping key when no spelling was recorded for it; `libyaml` itself is private to
// `rules`.
pub(crate) use crate::rules::libyaml::loader::stringify_scalar_key;
use crate::rules::{
    errors::{Error, InternalError},
    libyaml::loader::{Loader, MERGE_KEY},
    long_form_of,
    parser::Span,
    path_value::Location,
};
use crate::utils::break_width;

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

/// Whether a `<<` key carries YAML's merge semantics or is an ordinary key spelled `<<`.
///
/// Only the caller knows which format the text was written in, so this is threaded through the whole
/// conversion rather than read off the value: a `<<` nested at any depth gets the same reading as the
/// document's root, because the format does not change partway down.
#[derive(Copy, Clone)]
enum MergeKey {
    /// YAML. Fold each `<<` value into the mapping that wrote it, per `merge_into`.
    Resolve,
    /// JSON. `<<` is an ordinary member name.
    Literal,
}

impl<'a> TryFrom<&'a serde_yaml::Value> for Value {
    type Error = Error;

    fn try_from(value: &'a serde_yaml::Value) -> Result<Self, Self::Error> {
        convert_yaml(value, MergeKey::Resolve)
    }
}

impl Value {
    /// Converts a value that was parsed from JSON text, reading `<<` as an ordinary member name.
    ///
    /// JSON has no merge keys, and every JSON member name is quoted, so there is no plain scalar for
    /// YAML's merge rule to apply to -- which is the style distinction `merge_into`'s comment says has
    /// to be made where the text is still text. For a JSON document the format settles it outright, so
    /// no style needs recovering.
    ///
    /// The parser is still `serde_yaml`, so the input it accepts is unchanged. Swapping in `serde_json`
    /// was the alternative and is not used: it accepts a duplicate member name where `serde_yaml`
    /// refuses one, which is the refusal
    /// `guard/resources/validate/functions/data/embedded_json_the_parser_rejects.yaml` exists to pin;
    /// it reaches `TryFrom<&serde_json::Value>`, which has parsed an integer past `u64::MAX` as a
    /// float before the conversion can see the digits, where `serde_yaml` refuses it; and it refuses
    /// every YAML-only spelling that reaches `json_parse` successfully today, which is a narrowing no
    /// caller asked for.
    pub(crate) fn try_from_json(value: &serde_yaml::Value) -> crate::rules::Result<Value> {
        convert_yaml(value, MergeKey::Literal)
    }
}

fn convert_yaml(value: &serde_yaml::Value, merge_key: MergeKey) -> crate::rules::Result<Value> {
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
                // At the time those were the two entry points rule authors prove their rules with
                // -- the `test` subcommand and the public `run_checks` -- so the divergence ran in
                // the worst direction available. Both read through the libyaml loader now, and the
                // one production route left through this arm is `json_parse`, whose argument is
                // JSON and has no non-finite number; the gate stays because the conversion is
                // public and the value model's `Eq` still depends on it.
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
            |mut res, val| -> crate::rules::Result<Vec<Value>> {
                res.push(convert_yaml(val, merge_key)?);
                Ok(res)
            },
        )?)),
        serde_yaml::Value::Mapping(mapping) => {
            let mut res = IndexMap::with_capacity(mapping.len());
            let mut merges: Vec<&serde_yaml::Value> = vec![];
            // The kind each held name was written as, so `merge_into` can tell a same-key override
            // from a collision with a key of another kind.
            let mut kinds: std::collections::HashMap<String, KeyKind> =
                std::collections::HashMap::with_capacity(mapping.len());

            for (key, val) in mapping {
                // Held back until every explicit key is in, for the precedence reason recorded on
                // `libyaml::loader::apply_merges`. `serde_yaml` refuses a duplicate key, so this
                // can only ever collect one -- but it is collected rather than applied in place so
                // the ordering guarantee does not depend on that.
                //
                // Under `MergeKey::Literal` the branch is not taken at all, so `<<` falls through to
                // `scalar_key_name` and becomes an ordinary key of that name.
                if matches!(merge_key, MergeKey::Resolve)
                    && matches!(key, serde_yaml::Value::String(name) if name == MERGE_KEY)
                {
                    merges.push(val);
                    continue;
                }

                // `serde_yaml` has already refused two keys whose resolved values are equal by the
                // time this runs ("duplicate entry with key ...": `1` beside `1`, but also `0x1F`
                // beside `31`, or `true` beside `True`), so the only pair that can arrive here under
                // one name is two scalars whose resolved values differ and whose text is the same:
                // the integer `1` beside the string `"1"`, or `true` beside `"true"`. An insert that
                // replaced the first silently would have the author's `%p."1"` answer from whichever
                // came last.
                //
                // Refusing is the consistent answer on this route, not a substitute for a warning:
                // the one caller, `json_parse`, already reports a duplicate whose resolved values
                // are equal as a refusal of the embedded string (`serde_yaml` does that for it, so
                // `{"1": a, "1": b}` never reaches here), and a pair that reads as one key is the same
                // mistake spelled two ways. The libyaml loader keeps the last value and reports the
                // pair as a duplicate key instead, because a data file's author gets that notice on
                // stderr with both positions; an embedded string has neither.
                //
                // The advice says remove or rename, not quote: quoting the number makes it the very
                // string it collides with.
                let name = scalar_key_name(key)?;
                let value = convert_yaml(val, merge_key)?;
                if res.insert(name.clone(), value).is_some() {
                    return Err(colliding_key_error(&name));
                }
                kinds.insert(name, KeyKind::of(key));
            }

            merge_into(&mut res, merges, &mut kinds)?;

            Ok(Value::Map(res))
        }
        serde_yaml::Value::Tagged(tag) => {
            let prefix = tag.tag.to_string();
            let value = tag.value.clone();

            match prefix.matches('!').count() {
                1 => {
                    let stripped_prefix = prefix.strip_prefix('!').unwrap();
                    Ok(handle_tagged_value(value, stripped_prefix, merge_key)?)
                }
                _ => Ok(convert_yaml(&value, merge_key)?),
            }
        }
        serde_yaml::Value::Null => Ok(Value::Null),
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
                    // Reached only for a positive integer above `i64::MAX`. This was
                    // `num.as_u64().unwrap() as i64`, under a comment reading "Yes we are losing
                    // precision here. TODO fix this", and it was not losing precision: `as i64`
                    // reinterprets the bit pattern, so `u64::MAX` read as exactly -1 and
                    // `i64::MAX + 1` as exactly `i64::MIN`, and `A < 0` passed for a positive input.
                    // The digits are kept instead, which is what the `serde_yaml` arm above and the
                    // libyaml loader already do for an integer this wide.
                    //
                    // An integer past `u64::MAX` is not recoverable here: `serde_json` has parsed it
                    // as a float before this conversion runs, and the digits are gone with the text.
                    // Keeping them needs `serde_json`'s `arbitrary_precision` feature, which changes
                    // how every `serde_json::Value` number in this crate serializes through other
                    // formats, so it is not turned on for this arm. The entry points that read a
                    // document from text -- `validate`, `test` and `run_checks` -- all read it
                    // through the libyaml loader, which keeps the digits, so none of them reaches
                    // this conversion. `rules` is a private module, so no caller outside the crate
                    // reaches it either: what is left are in-crate tests building fixtures from
                    // JSON, and this keeps a fixture and a document holding the same integer
                    // meaning the same thing.
                    Ok(Value::String(num.as_u64().unwrap().to_string()))
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

/// Why a `BadValue`'s payload could not be read as its tag's type, for the one case where the text
/// alone does not say. Carried beside the text rather than inside it, so the text stays the scalar's
/// own as written, which is what a test-case field message and a document comparison render; the
/// error built from a `BadValue`, and a key refusal, render the reason from this data.
///
/// `Copy` data with no heap of its own, on purpose: an alias is a copy of its anchored node, and the
/// alias-expansion budget charges a `BadValue` the bytes of its text (see the loader's `size_of`).
/// Sentences held here as strings would be copied with every alias and charged to nothing, so the
/// reason holds the readings and renders the sentences where the value is reported.
#[derive(PartialEq, Debug, Clone, Copy)]
pub(crate) enum BadValueReason {
    /// A decimal integer with a redundant leading zero under `!!int`, `0755`, which YAML 1.1 reads as
    /// octal and YAML 1.2 as decimal: the readings of the digits after the zeros.
    LeadingZero(LeadingZeroReadings),
}

/// The two readings of a leading-zero integer's digits, in exactly the combinations the loader can
/// produce. The signed integers carry the payload's sign. There is no variant for a decimal reading
/// that fits beside an octal one that does not: with the leading zeros gone, two or more digits
/// read strictly smaller as octal than as decimal, so an octal overflow is always a decimal
/// overflow too. The other way round does occur, and `OctalOnlyFits` holds it.
#[derive(PartialEq, Debug, Clone, Copy)]
pub(crate) enum LeadingZeroReadings {
    /// Both readings fit an `i64`: `0755` is decimal 755 or octal 493.
    BothFit { decimal: i64, octal: i64 },
    /// The octal reading fits and the decimal one is too wide: twenty-one sevens are `i64::MAX` as
    /// octal.
    OctalOnlyFits { octal: i64 },
    /// Neither reading fits an `i64`.
    BothTooWide,
    /// A digit 8 or 9 leaves YAML 1.1's octal no reading; the decimal one fits, or is `None` when
    /// too wide.
    NoOctalReading { decimal: Option<i64> },
}

impl BadValueReason {
    /// The sentence that says what made the payload unreadable.
    pub(crate) fn why(&self) -> &'static str {
        match self {
            Self::LeadingZero(..) => {
                "a leading zero reads as octal in YAML 1.1 and as decimal in YAML 1.2"
            }
        }
    }

    /// The spellings that settle it, for a value: what to write in the scalar's place, as the
    /// plain-decimal integer each reading means.
    ///
    /// Both readings are offered as decimals, 493 and 755 for `0755`, and nothing else: a YAML 1.1
    /// reader, which is what CloudFormation is, has no `0o` form and reads `0o755` as a string, so
    /// that spelling is not named at all. A digit 8 or 9 leaves YAML 1.1 no reading, which is said
    /// instead. A reading too wide for an `i64` is named as such rather than offered.
    pub(crate) fn fix(&self) -> String {
        self.render(Place::Value)
    }

    /// The spellings that settle it, for a mapping key. A key is text, so what is offered is the
    /// quoted string of each integer: "Quote it to make it a string", the advice every other
    /// unreadable key gets, would quote the text "0755", which is neither reading, and writing the
    /// digits without the tag keeps that same string, since an untagged `0755` is text. The tag has
    /// no work to do once the quoted integer is written, which is said right after the spelling and
    /// before any note on a reading that could not be offered. Where no spelling can be offered, the
    /// note stands alone.
    pub(crate) fn key_fix(&self) -> String {
        self.render(Place::Key)
    }

    /// The advice as one sentence for a value or for a key. A key's sentence opens the clause after
    /// the key refusal's own, so it is capitalized; a value's follows a semicolon.
    fn render(&self, place: Place) -> String {
        let mut text = match (self.advice(), place) {
            (Advice::Spelling(spelling), Place::Value) => spelling.for_value(),
            (Advice::SpellingAndNote(spelling, note), Place::Value) => {
                format!("{}; {note}", spelling.for_value())
            }
            (Advice::Spelling(spelling), Place::Key) => {
                format!("{}; the tag can then be dropped", spelling.for_key())
            }
            (Advice::SpellingAndNote(spelling, note), Place::Key) => {
                format!(
                    "{}; the tag can then be dropped; {note}",
                    spelling.for_key()
                )
            }
            (Advice::Note(note), _) => String::from(note),
        };
        if place == Place::Key {
            if let Some(first) = text.get(..1) {
                text.replace_range(..1, &first.to_ascii_uppercase());
            }
        }
        text
    }

    /// What each reading has to say: a spelling for a reading that fits an `i64`, and a note for one
    /// that does not. One match over the variants, each giving the shape it has, so that there is no
    /// pairing to rule out afterwards.
    fn advice(&self) -> Advice {
        match *self {
            Self::LeadingZero(readings) => {
                // The digits after the zeros, recovered from the octal reading: they are octal
                // digits with no leading zero, so the octal form of the magnitude is that text, and
                // the reading's sign is the payload's.
                let digits = |o: i64| {
                    let sign = if o < 0 { "-" } else { "" };
                    format!("{sign}{:o}", o.unsigned_abs())
                };
                match readings {
                    LeadingZeroReadings::BothFit { decimal, octal } => {
                        Advice::Spelling(Spelling::Both {
                            octal,
                            digits: digits(octal),
                            decimal,
                        })
                    }
                    LeadingZeroReadings::OctalOnlyFits { octal } => Advice::SpellingAndNote(
                        Spelling::Octal {
                            octal,
                            digits: digits(octal),
                        },
                        "the decimal reading is too wide for a 64-bit integer",
                    ),
                    LeadingZeroReadings::BothTooWide => {
                        Advice::Note("both readings are too wide for a 64-bit integer")
                    }
                    LeadingZeroReadings::NoOctalReading { decimal: Some(d) } => {
                        Advice::SpellingAndNote(
                            Spelling::Decimal(d),
                            "YAML 1.1 reads no integer in a leading-zero number with a digit 8 or 9",
                        )
                    }
                    LeadingZeroReadings::NoOctalReading { decimal: None } => Advice::Note(
                        "the decimal reading is too wide for a 64-bit integer, and YAML 1.1 reads \
                         no integer in a leading-zero number with a digit 8 or 9",
                    ),
                }
            }
        }
    }
}

/// Where a reason is rendered: beside a value's error, or in a mapping key's refusal.
#[derive(PartialEq, Clone, Copy)]
enum Place {
    Value,
    Key,
}

/// What a `BadValueReason` renders as: a spelling to write, a spelling with a note on the reading
/// that could not be offered, or a note alone. Every reading has one of the three, by construction.
enum Advice {
    Spelling(Spelling),
    SpellingAndNote(Spelling, &'static str),
    Note(&'static str),
}

/// The integers a reading offers, rendered as a value (the integer itself) or as a key (the integer
/// quoted, since a key is text). `digits` are the payload's digits after the zeros, with the sign,
/// so that the octal offer names the number the author wrote: "if octal 755 was meant".
enum Spelling {
    /// Both readings fit: the octal reading as an integer, and the decimal one.
    Both {
        octal: i64,
        digits: String,
        decimal: i64,
    },
    /// Only the octal reading fits.
    Octal { octal: i64, digits: String },
    /// Only the decimal reading exists and fits.
    Decimal(i64),
}

impl Spelling {
    fn for_value(&self) -> String {
        match self {
            Self::Both {
                octal,
                digits,
                decimal,
            } => format!(
                "write {octal} if octal {digits} was meant, or {decimal} if decimal was meant"
            ),
            Self::Octal { octal, digits } => format!("write {octal} if octal {digits} was meant"),
            Self::Decimal(decimal) => format!("write {decimal} if decimal was meant"),
        }
    }

    fn for_key(&self) -> String {
        match self {
            Self::Both {
                octal,
                digits,
                decimal,
            } => format!(
                "write \"{octal}\" if octal {digits} was meant, or \"{decimal}\" if decimal was meant"
            ),
            Self::Octal { octal, digits } => {
                format!("write \"{octal}\" if octal {digits} was meant")
            }
            Self::Decimal(decimal) => format!("write \"{decimal}\" if decimal was meant"),
        }
    }
}

#[derive(PartialEq, Debug, Clone)]
#[allow(dead_code)]
pub(crate) enum MarkedValue {
    Null(Location),
    /// A `!!int`, `!!float` or `!!bool` whose payload is not one, carrying the payload's text as
    /// written, tag included, and a reason where the text alone would not explain the refusal.
    BadValue(String, Option<BadValueReason>, Location),
    /// A node the libyaml loader refused and read past, under its `RefusalPolicy::MarkBadValue`,
    /// carrying the refusal's message: an alias it could not resolve, or a mapping it could not
    /// model. Its own variant, because the text is a refusal and `BadValue`'s is a scalar's, and the
    /// two are forwarded differently where a key or a merge source is read.
    Refused(String, Location),
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
            | Self::BadValue(_, _, loc)
            | Self::Refused(_, loc)
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

pub(crate) use crate::rules::libyaml::loader::UnreadTag;

/// A document as the loader read it, with what a `test` spec file needs beside the value.
///
/// `scalar_texts` is the source spelling of every scalar the loader resolved to an integer, a float
/// or a boolean, by the scalar's position. `MarkedValue` keeps no spelling, and the `test` command
/// reports a case's `name` as the author wrote it, so `1.50` has to be recoverable after the loader
/// has made it `Float(1.5)`. Empty for a data file, whose loader does not record them.
///
/// `collisions` is the merged keys that collided with a held key of another form
/// (`libyaml::loader::Loader::collisions`), by the position of the mapping that merged and the held
/// key's position, for `PathAwareValue::try_from_marked_reporting` to report where each value lands in
/// that mapping. The loader drops the merged entry of a collision from the mapping, so this map is the
/// only record of the pair. Positions are the source's, like every other position in the document: the
/// JSON route restores them with the rest.
pub(crate) struct LoadedDocument {
    pub(crate) value: MarkedValue,
    pub(crate) scalar_texts: HashMap<Location, String>,
    pub(crate) collisions: crate::rules::path_value::KeyCollisions,
}

/// Which loader a document is read with; the two differ in what `libyaml::loader::Loader::for_spec_file`
/// names and in nothing else. Both resolve aliases, within the same budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentKind {
    /// A template or other data file: a refused node refuses the document, no scalar spelling is
    /// recorded, and the expansion budget is one for the document.
    Data,
    /// A `test` spec file: a refused node costs its own case, scalar spellings are recorded for case
    /// names, and the expansion budget is spent per case (per item of the root sequence) under the
    /// document's ceiling.
    Spec,
}

/// Reads one document, YAML or JSON, as a data file: through the libyaml loader, with aliases
/// resolved within the budget every route shares.
///
/// JSON is read as the YAML it is, with two corrections made on the text before the loader reads it.
/// Both are confined to text `serde_json` accepts as a complete document, because the rewriter tracks
/// JSON string syntax, which is exact for JSON and not for YAML.
///
/// The first is for a surrogate-pair escape. libyaml refuses a `\uD800`-`\uDFFF` escape inside a
/// double-quoted scalar, which is right for YAML and wrong for JSON: a surrogate pair is the only way
/// JSON can spell a character outside the BMP, and Python's `json.dumps` writes every such character
/// that way by default. Each pair is rewritten as the one escape YAML has for the same code point,
/// `\U0001F600`. The same six characters in a YAML double-quoted scalar are not valid JSON and stay
/// refused, as they always were. This rewrite only matters once the loader has refused the text, so
/// it is tried after a failed load.
///
/// The second is for a raw U+0085, U+2028 or U+2029 inside a string. JSON permits all three
/// unescaped, and libyaml reads each as a line break: inside a double-quoted scalar a break is folded,
/// so `"a<NEL>b"` loaded as `a b` and `"a <LS> b"` as `a<LS>b`, and the load succeeded, so nothing
/// reported the changed value. Each is rewritten as its JSON escape, `\u0085`, which libyaml reads
/// back as the character. This rewrite has to happen before the first load, since that load does not
/// fail; a text holding none of the three is loaded as it is, and `contains` is what keeps the
/// `serde_json` pass off every ordinary document.
///
/// Positions are the source text's, numbered as the loader numbers them. A pair's escape is two
/// characters shorter than the pair and a break's escape five longer than the character, so the
/// loader's columns after either on the same line are off by that much; and the loader counts a raw
/// break as a line break, so in the source the text after it is on the next line. The rewrite records
/// each change with its position in the rewritten text and [`restore_positions`] puts every loaded
/// position back where the loader would put it on the source, lines included. A finding's column, a
/// duplicate-key warning and a SARIF region on such a line therefore agree with the report's excerpt,
/// which numbers the source's lines the same way (`utils::break_width`), and that matters on exactly
/// the files this is for, since `json.dumps` puts a whole document on one line.
///
/// Three more shapes are rewritten on the same retry, because libyaml's scanner refuses them where
/// JSON permits them, and all three read through `serde_json` before the readers were made one: a raw
/// U+007F-U+009F (other than U+0085), U+FFFE or U+FFFF inside a string, which libyaml's reader rejects
/// as a control character, is written as its `\u` escape, as the three breaks are; a line break
/// between a member name and its `:`, which a simple key may not span, is written as a space; and a
/// member name that spans more than [`LIBYAML_SIMPLE_KEY_BYTES`] from its opening quote to its `:`,
/// which the scanner stops treating as a key, is written as an explicit key, `? "name"`, which the
/// scanner does not measure. Each is a rewrite a YAML emitter could have made, and each is recorded
/// so that the positions come back on the source.
///
/// Valid JSON that libyaml refuses after that is refused with a message that says so and names the
/// cause, because libyaml's own failure says where it stopped and not why JSON would allow it;
/// [`json_limit_hit`] knows one such cause, the lone surrogate escape, which is not a character and
/// has no rewrite. A refusal of the loader's own on
/// the rewritten text -- a document nested past the bound, a key with no text -- is returned as it
/// is, with the positions in its message restored the same way.
pub(crate) fn read_from(from_reader: &str) -> crate::rules::Result<MarkedValue> {
    read_from_with_warnings(from_reader, &mut Vec::new())
}

/// [`read_from`], with the `!!` tags the loader read past (see [`UnreadTag`]) appended to `warnings`,
/// the way `PathAwareValue::try_from_marked` appends to its duplicate-key list. They are appended
/// whether or not the load succeeds: a tag read before the loader refused the document was still read
/// past. `read_from` is for a caller with nowhere to put them, and drops them.
pub(crate) fn read_from_with_warnings(
    from_reader: &str,
    warnings: &mut Vec<UnreadTag>,
) -> crate::rules::Result<MarkedValue> {
    read_with(from_reader, DocumentKind::Data, warnings).map(|loaded| loaded.value)
}

/// [`read_from_with_warnings`], returning beside the document the merged keys that collided with a
/// held key of another form (`LoadedDocument::collisions`), by the position of the mapping that merged
/// and the held key's position, for the caller to hand to `PathAwareValue::try_from_marked_reporting`,
/// which emits the duplicate-key notice for each where the value lands.
///
/// `validate` reads through this and prints both lists through its writer. `read_from` is for a
/// caller with nowhere to report either: the `test` command and `run_checks` print no duplicate-key
/// notice, and drop the collisions.
pub(crate) fn read_from_reporting(
    from_reader: &str,
    warnings: &mut Vec<UnreadTag>,
) -> crate::rules::Result<(MarkedValue, crate::rules::path_value::KeyCollisions)> {
    read_with(from_reader, DocumentKind::Data, warnings)
        .map(|loaded| (loaded.value, loaded.collisions))
}

/// Reads one document as a `test` spec file: the same loader, with the three differences
/// `libyaml::loader::Loader::for_spec_file` names, and the scalar spellings the spec reader needs.
/// The differences are selected here so that the two routes cannot drift apart on anything else.
///
/// The `test` command reads through [`read_spec_from_with_warnings`], which also hands over the `!!`
/// tags the loader read past; this form drops them and is the tests' shorthand for the same reading.
#[cfg(test)]
pub(crate) fn read_spec_from(from_reader: &str) -> crate::rules::Result<LoadedDocument> {
    read_spec_from_with_warnings(from_reader, &mut Vec::new())
}

/// Reads one document as a `test` spec file, as `read_spec_from` describes, with the `!!` tags the
/// loader read past appended to `warnings` as [`read_from_with_warnings`] appends them: the `test`
/// command renders them into its diagnostics.
pub(crate) fn read_spec_from_with_warnings(
    from_reader: &str,
    warnings: &mut Vec<UnreadTag>,
) -> crate::rules::Result<LoadedDocument> {
    read_with(from_reader, DocumentKind::Spec, warnings)
}

/// `warnings` collects the `!!` tags the loader read past (see [`UnreadTag`]). A document the loader
/// refuses still leaves the tags it read before the refusal; a JSON document the YAML reader refused
/// and that is then read again rewritten leaves only the second reading's, since the two readings
/// are of one document.
fn read_with(
    text: &str,
    kind: DocumentKind,
    warnings: &mut Vec<UnreadTag>,
) -> crate::rules::Result<LoadedDocument> {
    // A byte order mark is not part of the document: libyaml consumes it before it counts a position,
    // and the JSON reader refuses it, so it is dropped here once for both readers. The file readers
    // keep it, since `read_to_string` keeps every character, and a caller of `run_checks` may hand
    // one in.
    let text = text.strip_prefix('\u{FEFF}').unwrap_or(text);

    // A raw NEL, LS or PS loads without an error and with a changed value, so this rewrite cannot
    // wait for a failure. The `contains` is what keeps the `serde_json` pass off every other document.
    if text.contains(JSON_RAW_BREAKS) && json_shape(text).is_ok() {
        if let Some(rewritten) = rewrite_json_for_yaml(text) {
            return load_rewritten(&rewritten, kind, warnings);
        }
    }

    let warnings_before = warnings.len();
    let refused = match load(text, kind, warnings) {
        Ok(loaded) => return Ok(loaded),
        Err(refused) => refused,
    };
    // Only libyaml's own failure is worth a second look, because it says where the YAML reader
    // stopped and nothing about what the text was meant to be. The loader's refusals already say
    // what is wrong, at positions that are the source's since nothing was rewritten.
    let Error::ParseError(message) = refused else {
        return Err(refused);
    };
    if let Err(not_json) = json_shape(text) {
        return Err(json_readers_refusal(text, message, &not_json));
    }

    match rewrite_json_for_yaml(text) {
        Some(rewritten) => {
            // The first reading's tags are the same document's, read once more below.
            warnings.truncate(warnings_before);
            load_rewritten(&rewritten, kind, warnings)
        }
        None => Err(valid_json_the_yaml_reader_cannot_read(
            text,
            &PositionMap::new(&[]),
            &message,
        )),
    }
}

/// libyaml's refusal of text that is not JSON either, with the JSON reader's own refusal appended
/// when the text begins like JSON and that reader got at least as far.
///
/// libyaml's message and position are what every route reports, because they name where the YAML
/// reader stopped in text that is YAML to it; YAML flow style begins with `{` or `[` as JSON does, so
/// nothing about the first character says which the author meant. When the text is not valid JSON
/// either -- a missing comma between two members, say -- [`json_limit_hit`] has nothing to say,
/// because it describes valid JSON that libyaml will not read, and the JSON reader's own refusal,
/// which `json_shape` produced while deciding that the text is not JSON, is appended as a second line
/// if the text begins with `{` or `[` once a byte order mark and whitespace are passed over, and the
/// JSON reader read at least as far into the text as libyaml did. Text that begins any other way was
/// not written as JSON, and the JSON reader's "expected value at line 1 column 1" on a YAML document
/// that fails at its first character (an `@`, a backtick, a directive it will not take) says nothing
/// about the mistake. A JSON reader that stopped earlier stopped at something that is valid YAML
/// (an unquoted key, say), and its position would point at a place that is not the mistake, so
/// nothing of it is shown either. The two readers count positions differently: libyaml counts every
/// line break and columns in characters, `serde_json` counts line feeds and columns in bytes, so
/// each is compared as a byte offset into the text and each is shown in its own terms, labeled.
///
/// The variant is `ParseError`, because the variant follows what the error means: the text is
/// malformed, which is what `ParseError` means to the library's callers (FFI code 5), where
/// `UnsupportedDocument` (code 25) is a construct cfn-guard will not model in a document that parses,
/// as [`valid_json_the_yaml_reader_cannot_read`] reports. `validate::build_data_file` reports a
/// `ParseError` that names a position as it is.
fn json_readers_refusal(text: &str, message: String, not_json: &serde_json::Error) -> Error {
    let begins_like_json = text
        .trim_start_matches('\u{FEFF}')
        .trim_start()
        .starts_with(['{', '[']);
    if !begins_like_json {
        return Error::ParseError(message);
    }
    let Some(yaml_stop) = yaml_failure_offset(text, &message) else {
        return Error::ParseError(message);
    };
    if json_failure_offset(text, not_json) < yaml_stop {
        return Error::ParseError(message);
    }
    Error::ParseError(format!(
        "{message}\nRead as JSON as well, the text fails with: {not_json} (the JSON reader's line \
         and column, which count line feeds and bytes; the YAML reader's above count every line \
         break and characters)"
    ))
}

/// The byte offset into `text` of the position libyaml's failure names, read back from the loader's
/// rendering of it (` at L:<line>,C:<column>`, the first one in the message), or `None` for a
/// failure that names no position. Lines end where libyaml ends them (`break_width`) and columns
/// count characters, as the loader's positions do; a position past the end of the text is the text's
/// length.
fn yaml_failure_offset(text: &str, message: &str) -> Option<usize> {
    let at = message.find(" at L:")?;
    let (loc, _) = rendered_location_at(&message[at + " at ".len()..])?;
    let bytes = text.as_bytes();
    let mut line = 1usize;
    let mut col = 1usize;
    let mut index = 0usize;
    while index < bytes.len() {
        if line == loc.line && col == loc.col {
            return Some(index);
        }
        if let Some(width) = break_width(bytes, index) {
            line += 1;
            col = 1;
            index += width;
            continue;
        }
        if line == loc.line {
            col += 1;
        }
        // Step over one character, continuation bytes included.
        index += 1;
        while index < bytes.len() && bytes[index] & 0xC0 == 0x80 {
            index += 1;
        }
    }
    Some(bytes.len())
}

/// The byte offset into `text` of the JSON reader's failure: `serde_json` numbers lines by line feeds
/// and columns by bytes, from one, and its column is the byte after the one it stopped at.
fn json_failure_offset(text: &str, not_json: &serde_json::Error) -> usize {
    let line_start = text
        .match_indices('\n')
        .nth(not_json.line().saturating_sub(2))
        .map_or(
            0,
            |(index, _)| if not_json.line() > 1 { index + 1 } else { 0 },
        );
    (line_start + not_json.column().saturating_sub(1)).min(text.len())
}

/// Loads rewritten JSON text and puts every position in the result, or in the refusal, back on the
/// source text.
///
/// A `ParseError` here is libyaml refusing the rewritten text for a reason the rewrite did not
/// address, so the limits are measured on the rewritten text -- the text libyaml measured -- and the
/// positions named are mapped back. The loader's own refusal is returned as it is apart from that
/// mapping.
fn load_rewritten(
    rewritten: &RewrittenJson,
    kind: DocumentKind,
    warnings: &mut Vec<UnreadTag>,
) -> crate::rules::Result<LoadedDocument> {
    let positions = PositionMap::new(&rewritten.rewrites);
    let warnings_before = warnings.len();
    let loaded = load(&rewritten.text, kind, warnings);
    // The tags this reading appended are at the rewritten text's positions, like everything else it
    // read; put back on the source whether the reading succeeded or not. JSON has no tags, so the
    // list is empty in practice, and this keeps the rule that nothing leaves here on rewritten
    // coordinates.
    for warning in &mut warnings[warnings_before..] {
        warning.location = positions.source_position(warning.location);
    }
    match loaded {
        Ok(loaded) => Ok(restore_positions(loaded, &positions)),
        Err(Error::ParseError(message)) => Err(valid_json_the_yaml_reader_cannot_read(
            &rewritten.text,
            &positions,
            &message,
        )),
        Err(other) => Err(restore_positions_in_error(other, &positions)),
    }
}

/// Whether the text is a complete JSON document, with the JSON reader's refusal when it is not. Only
/// the shape is checked; nothing is built.
///
/// `serde_json` stops at 128 nested containers of its own accord, which is the loader's own bound
/// ([`crate::rules::libyaml::loader`]) and would leave text at the bound without the rewrite the
/// loader's reading needs, so its limit is lifted here and the depth is checked first by
/// [`json_nesting_within`]: text nested deeper than the loader accepts is refused by the loader, and
/// never reaches the recursive check without a bound.
fn json_shape(text: &str) -> Result<(), serde_json::Error> {
    if !json_nesting_within(text, JSON_SHAPE_DEPTH) {
        return Err(serde::de::Error::custom(format!(
            "nested more than {JSON_SHAPE_DEPTH} levels deep"
        )));
    }
    let mut deserializer = serde_json::Deserializer::from_str(text);
    deserializer.disable_recursion_limit();
    <serde::de::IgnoredAny as Deserialize>::deserialize(&mut deserializer)?;
    deserializer.end()
}

/// The deepest nesting [`json_shape`] follows: the loader's bound plus one, so that text at the bound
/// is checked and text one past it is refused by the loader's depth refusal, which names the position.
const JSON_SHAPE_DEPTH: usize = 129;

/// Whether `text`'s brackets, outside its strings, nest no deeper than `limit`. A scan of the bytes,
/// not a parse: a `"` opens or closes a string and a backslash inside one skips the next character.
fn json_nesting_within(text: &str, limit: usize) -> bool {
    let mut depth = 0usize;
    let mut in_string = false;
    let mut bytes = text.bytes();
    while let Some(byte) = bytes.next() {
        if in_string {
            match byte {
                b'"' => in_string = false,
                b'\\' => {
                    bytes.next();
                }
                _ => {}
            }
            continue;
        }
        match byte {
            b'"' => in_string = true,
            b'[' | b'{' => {
                depth += 1;
                if depth > limit {
                    return false;
                }
            }
            b']' | b'}' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    true
}

/// The refusal for valid JSON that libyaml would not read: it says the text is valid JSON and names
/// the limit it hit, or carries libyaml's own message when no known limit explains the refusal, with
/// the positions in either put back on the source through `positions`. `yaml_message` is libyaml's
/// message for the text libyaml was given, which after a rewrite is the rewritten text.
///
/// Called for a `ParseError` only, because that is libyaml's own failure, which says where its scanner
/// stopped and nothing about why JSON allows the text. `UnsupportedDocument` is the variant because
/// that is what the refusal means: the text is valid JSON, so it is not malformed, and what it holds
/// is a construct cfn-guard will not model (a lone surrogate escape is not a character), which is
/// what that variant means to the library's callers (FFI code 25) and how `validate::build_data_file`
/// words it, under the file's name with no excerpt.
fn valid_json_the_yaml_reader_cannot_read(
    text: &str,
    positions: &PositionMap<'_>,
    yaml_message: &str,
) -> Error {
    match json_limit_hit(text) {
        Some(limit) => Error::UnsupportedDocument(format!(
            "this text is valid JSON that cfn-guard's YAML reader cannot read: {}. JSON is read as \
             the YAML it is, and this is one of the few shapes of JSON that YAML does not accept.",
            restore_positions_in_message(&limit, positions)
        )),
        None => Error::UnsupportedDocument(format!(
            "this text is valid JSON that cfn-guard's YAML reader cannot read: {}. JSON is read as the \
             YAML it is; rewrite the document the way a YAML emitter would and read it again.",
            restore_positions_in_message(yaml_message, positions)
        )),
    }
}

/// How many bytes a mapping key may span, from its opening quote to its `:`, before libyaml stops
/// treating it as a key. libyaml's scanner calls this the simple-key limit and measures it on the
/// byte index, so a long member name fails with "did not find expected ',' or '}'" rather than with
/// anything naming the name. An explicit key, `? "name"`, is not a simple key and is not measured,
/// which is how [`rewrite_json_for_yaml`] gets a long member name past the scanner.
const LIBYAML_SIMPLE_KEY_BYTES: usize = 1024;

/// The first thing in valid JSON text that libyaml refuses and the rewrite cannot help, named with
/// its position, or `None`.
///
/// One shape is left: a lone surrogate escape, `\uD800` with no low surrogate after it, which is not
/// a character, so there is nothing to rewrite it as; a surrogate pair is rewritten before this runs.
/// The other shapes libyaml's scanner refuses and JSON permits -- a member name past the simple-key
/// limit, a line break between a member name and its `:`, a raw control character inside a string --
/// are rewritten by [`rewrite_json_for_yaml`] and never reach here on text that holds them alone.
/// Positions count lines and characters from one, as the loader's do, and a line ends where libyaml
/// ends one (`utils::break_width`: CR, LF, CRLF as one, NEL, LS, PS), so a position named here is one
/// the loader would name. Only valid for text `json_shape` accepted, because the scanner knows
/// JSON strings and nothing else, and meant for the text libyaml was given: after a rewrite that is
/// the rewritten text.
fn json_limit_hit(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut line = 1usize;
    let mut col = 1usize;
    let mut in_string = false;
    let mut chars = text.char_indices();

    while let Some((index, c)) = chars.next() {
        let here = Location { line, col };
        let line_break = break_width(bytes, index);
        if in_string {
            match c {
                '"' => in_string = false,
                '\\' => {
                    let rest = &text[index..];
                    if surrogate_pair_at(rest).is_some() {
                        for _ in 0..11 {
                            chars.next();
                        }
                        col += 11;
                    } else if let Some(escaped) = rest.get(0..6).and_then(unicode_escape_at) {
                        if (0xD800..=0xDFFF).contains(&escaped) {
                            return Some(format!(
                                "a lone surrogate escape `\\u{escaped:04X}` at {here}, which is \
                                 half of a character; a surrogate pair is read as the character it \
                                 spells, a lone surrogate is not"
                            ));
                        }
                        for _ in 0..5 {
                            chars.next();
                        }
                        col += 5;
                    } else {
                        chars.next();
                        col += 1;
                    }
                }
                _ => {}
            }
        } else if c == '"' {
            in_string = true;
        }

        match line_break {
            Some(width) => {
                // CRLF is one break: step over the LF with the CR. Inside a string no raw break
                // reaches here, because JSON requires one to be escaped and the rewrite has taken
                // the three it permits raw.
                if width == 2 && c == '\r' {
                    chars.next();
                }
                line += 1;
                col = 1;
            }
            None => col += 1,
        }
    }

    None
}

/// The code point a `\uXXXX` escape at the start of `escape` spells, if that is what it is.
fn unicode_escape_at(escape: &str) -> Option<u32> {
    let digits = escape.strip_prefix("\\u")?;
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(digits, 16).ok()
}

/// Whether libyaml's reader rejects the character as a control character where JSON permits it raw.
///
/// libyaml accepts U+0009, U+000A, U+000D, U+0020-U+007E, U+0085, U+00A0-U+D7FF, U+E000-U+FFFD and
/// the supplementary planes. JSON requires only U+0000-U+001F to be escaped, so the characters JSON
/// allows raw and libyaml does not are U+007F-U+0084, U+0086-U+009F, U+FFFE and U+FFFF.
///
/// U+0085 is outside this set because libyaml does not reject it, and that is not the same as reading
/// it as JSON does: to libyaml it is a line break, folded inside a double-quoted scalar, as U+2028 and
/// U+2029 are. None of the three is a refusal, so none belongs here. All of them, this set and the
/// three breaks, are rewritten as their `\u` escape by `rewrite_json_for_yaml` before the loader reads
/// the text; the difference is that a break moves the text after it to the next line in the loader's
/// numbering of the source, and a control character does not.
fn is_control_for_libyaml(c: char) -> bool {
    let code = c as u32;
    ((0x7F..=0x9F).contains(&code) && code != 0x85) || code == 0xFFFE || code == 0xFFFF
}

/// The three characters JSON permits raw inside a string and libyaml reads as line breaks: NEL, LS
/// and PS. CR and LF are breaks too, but JSON requires those to be escaped inside a string.
const JSON_RAW_BREAKS: [char; 3] = ['\u{0085}', '\u{2028}', '\u{2029}'];

/// One change the rewrite made to the text, placed where it sits in the rewritten text.
///
/// `line` and `col` are the position of the escape's first character in the rewritten text, counted
/// from one as the loader counts, and `rewritten_chars` its length there; `source_chars` is the
/// length of what it replaced. `breaks_line` says the source character was a line break to libyaml,
/// so in the loader's numbering of the source the text after it is on the next line, at column one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Rewrite {
    line: usize,
    col: usize,
    rewritten_chars: usize,
    source_chars: usize,
    breaks_line: bool,
}

/// JSON text rewritten for the loader, and the record of each change, in document order, so
/// positions read off the rewritten text can be put back on the source.
struct RewrittenJson {
    text: String,
    rewrites: Vec<Rewrite>,
}

/// A string the rewriter has read or is reading, while it may turn out to be a member name: where its
/// opening quote sits in the rewritten text, as a byte offset into `out` and as the loader's position,
/// and how many rewrites had been recorded when it opened, so that a `? ` inserted before the quote
/// can move the records made inside the string.
#[derive(Debug, Clone, Copy)]
struct QuotedName {
    out_offset: usize,
    line: usize,
    col: usize,
    rewrites_before: usize,
}

/// Rewrites JSON text the way a YAML emitter would write it, where libyaml's scanner or reader would
/// otherwise refuse or misread it, leaving every other byte as it is. `None` when nothing needed
/// rewriting, so the caller does not reload a document nothing changed in. Only valid for text
/// `looks_like_json` accepted, because the scanner knows JSON strings and nothing else; that also
/// means no raw break can sit outside a string except as JSON's whitespace, which is space, tab, CR
/// and LF, and that a string followed by `:` is a member name.
///
/// Inside a string: every `\uD8xx\uDCxx` surrogate pair becomes YAML's `\UXXXXXXXX` escape for the
/// same code point; every raw NEL, LS or PS becomes its `\uXXXX` escape, recorded as a line break,
/// since that is what it is to the loader; and every raw character of [`is_control_for_libyaml`]'s
/// set becomes its `\uXXXX` escape, recorded as no break. Between a member name and its `:`: a line
/// break becomes one space, recorded as a break, and the whitespace around it is kept; and a name
/// whose opening quote sits more than [`LIBYAML_SIMPLE_KEY_BYTES`] before its `:` in the rewritten
/// text gets `? ` inserted before the quote, which makes it an explicit key, recorded as two
/// characters that replace none. The span is measured on the rewritten text, since that is the text
/// libyaml measures.
///
/// Each rewrite is recorded with its position in the rewritten text, which is where the loader will
/// report positions from, in document order. Lines are counted the way the loader counts them,
/// through `utils::break_width`, so that a CRLF between members is one line and a bare CR is a line
/// too; a break replaced by a space is not a line in the rewritten text, and its record carries the
/// line it ends in the source.
fn rewrite_json_for_yaml(text: &str) -> Option<RewrittenJson> {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut rewrites: Vec<Rewrite> = vec![];
    let mut line = 1usize;
    // The column the next character written to `out` will have.
    let mut col = 1usize;
    // The string being read, and the string that just closed while the next non-blank character
    // has yet to say whether it was a member name.
    let mut open: Option<QuotedName> = None;
    let mut closed: Option<QuotedName> = None;
    let mut chars = text.char_indices();

    while let Some((index, c)) = chars.next() {
        if let Some(name) = open {
            match c {
                '"' => {
                    open = None;
                    closed = Some(name);
                    out.push(c);
                    col += 1;
                }
                '\\' => {
                    let rest = &text[index..];
                    match surrogate_pair_at(rest) {
                        Some(decoded) => {
                            let escape = format!("\\U{:08X}", decoded as u32);
                            rewrites.push(Rewrite {
                                line,
                                col,
                                rewritten_chars: escape.len(),
                                source_chars: 12,
                                breaks_line: false,
                            });
                            col += escape.len();
                            out.push_str(&escape);
                            // The pair is twelve ASCII characters: `\uXXXX\uXXXX`. One was consumed
                            // by `next`, so skip the other eleven.
                            for _ in 0..11 {
                                chars.next();
                            }
                        }
                        None => {
                            // Any other escape is copied through with the character it escapes, so
                            // a `\"` cannot be read as the end of the string.
                            out.push(c);
                            col += 1;
                            if let Some((_, escaped)) = chars.next() {
                                out.push(escaped);
                                col += 1;
                            }
                        }
                    }
                }
                raw if JSON_RAW_BREAKS.contains(&raw) || is_control_for_libyaml(raw) => {
                    let escape = format!("\\u{:04X}", raw as u32);
                    rewrites.push(Rewrite {
                        line,
                        col,
                        rewritten_chars: escape.len(),
                        source_chars: 1,
                        breaks_line: JSON_RAW_BREAKS.contains(&raw),
                    });
                    col += escape.len();
                    out.push_str(&escape);
                }
                other => {
                    out.push(other);
                    col += 1;
                }
            }
            continue;
        }

        let line_break = break_width(bytes, index);
        if let Some(name) = closed {
            match c {
                ' ' | '\t' => {}
                ':' => {
                    closed = None;
                    if out.len() - name.out_offset > LIBYAML_SIMPLE_KEY_BYTES {
                        out.insert_str(name.out_offset, "? ");
                        for rewrite in &mut rewrites[name.rewrites_before..] {
                            rewrite.col += 2;
                        }
                        rewrites.insert(
                            name.rewrites_before,
                            Rewrite {
                                line: name.line,
                                col: name.col,
                                rewritten_chars: 2,
                                source_chars: 0,
                                breaks_line: false,
                            },
                        );
                        col += 2;
                    }
                }
                _ if line_break.is_some() => {
                    // A break between a member name and its `:`, when a `:` is what follows the
                    // whitespace: one space in the rewritten text, a line break in the source.
                    let width = line_break.unwrap_or(1);
                    if text[index + width..]
                        .trim_start_matches([' ', '\t', '\r', '\n'])
                        .starts_with(':')
                    {
                        rewrites.push(Rewrite {
                            line,
                            col,
                            rewritten_chars: 1,
                            source_chars: width,
                            breaks_line: true,
                        });
                        out.push(' ');
                        col += 1;
                        if width == 2 {
                            chars.next();
                        }
                        continue;
                    }
                    closed = None;
                }
                _ => closed = None,
            }
        }

        if c == '"' {
            open = Some(QuotedName {
                out_offset: out.len(),
                line,
                col,
                rewrites_before: rewrites.len(),
            });
        }
        // A tab outside a string is JSON whitespace, and at the start of a line libyaml's scanner
        // refuses it as indentation; one space is the same whitespace to both. Recorded as a
        // rewrite of one character by one, so that a document this is the only change to is reloaded.
        if c == '\t' {
            rewrites.push(Rewrite {
                line,
                col,
                rewritten_chars: 1,
                source_chars: 1,
                breaks_line: false,
            });
            out.push(' ');
            col += 1;
            continue;
        }
        out.push(c);
        match line_break {
            Some(width) => {
                // CRLF is one break; carry the LF over with the CR.
                if width == 2 && c == '\r' {
                    if let Some((_, lf)) = chars.next() {
                        out.push(lf);
                    }
                }
                line += 1;
                col = 1;
            }
            None => col += 1,
        }
    }

    (!rewrites.is_empty()).then_some(RewrittenJson {
        text: out,
        rewrites,
    })
}

/// The rewrites of one document, indexed so that any position the loader reported on the rewritten
/// text can be put back on the source in logarithmic time.
///
/// A position's source line is its rewritten line plus the breaks among the rewrites before it, and
/// its source column is its rewritten column counted from the last break before it on its own line
/// (or from the line's start), moved by the difference between what every other rewrite in between
/// replaced and wrote. The rewrites are in document order, so "before" is a binary search, and the
/// counts are prefix sums over the rewrites, built once: a document of N nodes with M rewrites costs
/// M to index and N log M to restore, where restoring each node by walking the rewrites from the
/// start cost N times M, which on a one-line document of a few hundred thousand nodes and tens of
/// thousands of surrogate pairs was on the order of a billion steps.
struct PositionMap<'a> {
    rewrites: &'a [Rewrite],
    /// `breaks_before[i]` is how many of `rewrites[..i]` were line breaks in the source.
    breaks_before: Vec<usize>,
    /// `shift_before[i]` is the sum over the non-break rewrites in `rewrites[..i]` of the characters
    /// each replaced minus the characters it wrote.
    shift_before: Vec<isize>,
    /// `last_break_before[i]` is the index of the last line-break rewrite in `rewrites[..i]`.
    last_break_before: Vec<Option<usize>>,
}

/// Steps the position restorer takes, for the test that pins its cost: one per rewrite indexed and
/// one per position restored, counting a binary search as one step.
#[cfg(test)]
pub(crate) static POSITION_STEPS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

impl<'a> PositionMap<'a> {
    fn new(rewrites: &'a [Rewrite]) -> PositionMap<'a> {
        let mut breaks_before = Vec::with_capacity(rewrites.len() + 1);
        let mut shift_before = Vec::with_capacity(rewrites.len() + 1);
        let mut last_break_before = Vec::with_capacity(rewrites.len() + 1);
        let (mut breaks, mut shift, mut last_break) = (0usize, 0isize, None);
        for (index, rewrite) in rewrites.iter().enumerate() {
            breaks_before.push(breaks);
            shift_before.push(shift);
            last_break_before.push(last_break);
            if rewrite.breaks_line {
                breaks += 1;
                last_break = Some(index);
            } else {
                shift += rewrite.source_chars as isize - rewrite.rewritten_chars as isize;
            }
            #[cfg(test)]
            POSITION_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        breaks_before.push(breaks);
        shift_before.push(shift);
        last_break_before.push(last_break);
        PositionMap {
            rewrites,
            breaks_before,
            shift_before,
            last_break_before,
        }
    }

    /// Where the loader would put a position it reported on the rewritten text if it had read the
    /// source.
    ///
    /// Every rewrite on an earlier line that was a line break in the source adds a line. On the
    /// position's own line, the rewrites before it count in order: a break adds a line and restarts
    /// the column at one just after the escape, and any other rewrite moves the column by the
    /// difference between what it replaced and what it wrote. A position before the first rewrite on
    /// its line, or on a line that held none, is untouched; a position can never fall inside an
    /// escape, because a scalar's position is its opening quote. `Location::default()`, line zero,
    /// means no position and is left alone by the same test.
    fn source_position(&self, loc: Location) -> Location {
        #[cfg(test)]
        POSITION_STEPS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // The rewrites before the position: on an earlier line, or on its line at a lower column.
        let before = self
            .rewrites
            .partition_point(|rewrite| (rewrite.line, rewrite.col) < (loc.line, loc.col));
        let line = loc.line + self.breaks_before[before];
        // The rewritten column the count starts at, and the shift the non-break rewrites since then
        // add: from the last break on the position's own line, or from the line's first rewrite.
        let (counted_from, shift) = match self.last_break_before[before] {
            Some(last) if self.rewrites[last].line == loc.line => (
                self.rewrites[last].col + self.rewrites[last].rewritten_chars,
                self.shift_before[before] - self.shift_before[last + 1],
            ),
            _ => {
                let first_on_line = self
                    .rewrites
                    .partition_point(|rewrite| rewrite.line < loc.line);
                (
                    1,
                    self.shift_before[before] - self.shift_before[first_on_line],
                )
            }
        };
        let col = loc.col as isize + 1 - counted_from as isize + shift;
        Location {
            line,
            col: col as usize,
        }
    }
}

/// Puts a loaded document back on the source text's positions: every value's, every mapping key's,
/// every recorded scalar spelling's, and every position named inside a `BadValue`'s message.
///
/// Mapping keys carry positions too and the map is keyed on them, so a mapping is rebuilt rather than
/// edited in place. A `Refused` node, written by the loader for a node it refused, carries the
/// refusal, which names positions, and those are mapped as the message of a refused document is; a
/// `BadValue` from a `!!int` tag carries the scalar's own text, which is left as it is.
fn restore_positions(loaded: LoadedDocument, positions: &PositionMap<'_>) -> LoadedDocument {
    LoadedDocument {
        value: restore_value_positions(loaded.value, positions),
        scalar_texts: loaded
            .scalar_texts
            .into_iter()
            .map(|(loc, text)| (positions.source_position(loc), text))
            .collect(),
        // Empty on this route in practice, since every JSON key is a quoted string and so of one
        // form and JSON has no anchors; mapped anyway, so that nothing in a `LoadedDocument` is ever on
        // rewritten coordinates.
        collisions: loaded
            .collisions
            .with_positions(|loc| positions.source_position(loc)),
    }
}

fn restore_value_positions(value: MarkedValue, positions: &PositionMap<'_>) -> MarkedValue {
    let restored = |loc: Location| positions.source_position(loc);
    match value {
        MarkedValue::Null(loc) => MarkedValue::Null(restored(loc)),
        MarkedValue::BadValue(text, reason, loc) => {
            MarkedValue::BadValue(text, reason, restored(loc))
        }
        MarkedValue::Refused(refusal, loc) => MarkedValue::Refused(
            restore_positions_in_message(&refusal, positions),
            restored(loc),
        ),
        MarkedValue::String(text, loc) => MarkedValue::String(text, restored(loc)),
        MarkedValue::Regex(text, loc) => MarkedValue::Regex(text, restored(loc)),
        MarkedValue::Bool(b, loc) => MarkedValue::Bool(b, restored(loc)),
        MarkedValue::Int(i, loc) => MarkedValue::Int(i, restored(loc)),
        MarkedValue::Float(f, loc) => MarkedValue::Float(f, restored(loc)),
        MarkedValue::Char(c, loc) => MarkedValue::Char(c, restored(loc)),
        MarkedValue::RangeInt(r, loc) => MarkedValue::RangeInt(r, restored(loc)),
        MarkedValue::RangeFloat(r, loc) => MarkedValue::RangeFloat(r, restored(loc)),
        MarkedValue::RangeChar(r, loc) => MarkedValue::RangeChar(r, restored(loc)),
        MarkedValue::List(items, loc) => MarkedValue::List(
            items
                .into_iter()
                .map(|item| restore_value_positions(item, positions))
                .collect(),
            restored(loc),
        ),
        MarkedValue::Map(entries, loc) => MarkedValue::Map(
            entries
                .into_iter()
                .map(|((key, key_loc), value)| {
                    (
                        (key, restored(key_loc)),
                        restore_value_positions(value, positions),
                    )
                })
                .collect(),
            restored(loc),
        ),
    }
}

/// Puts the positions a refusal names back on the source text, for the two variants whose message can
/// name one. `MissingDocument` names none, and a `ParseError` never reaches here.
fn restore_positions_in_error(error: Error, positions: &PositionMap<'_>) -> Error {
    match error {
        Error::UnsupportedDocument(message) => {
            Error::UnsupportedDocument(restore_positions_in_message(&message, positions))
        }
        Error::InternalError(InternalError::InvalidKeyType(message)) => Error::InternalError(
            InternalError::InvalidKeyType(restore_positions_in_message(&message, positions)),
        ),
        other => other,
    }
}

/// Rewrites every `L:n,C:m` in a message -- `Location`'s one rendering -- as the source position.
///
/// The loader's refusals carry their positions inside their text, so this is how a position reported
/// on rewritten text reaches the reader as a source position. The rendering is matched exactly, both
/// numbers required, and anything else is copied through.
fn restore_positions_in_message(message: &str, positions: &PositionMap<'_>) -> String {
    let mut out = String::with_capacity(message.len());
    let mut rest = message;
    while let Some(at) = rest.find("L:") {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        match rendered_location_at(tail) {
            Some((loc, len)) => {
                out.push_str(&positions.source_position(loc).to_string());
                rest = &tail[len..];
            }
            None => {
                out.push_str("L:");
                rest = &tail[2..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// The `Location` rendered at the start of `text`, with how many bytes it took, if one starts there.
fn rendered_location_at(text: &str) -> Option<(Location, usize)> {
    let digits = |s: &str| s.bytes().take_while(u8::is_ascii_digit).count();
    let after_line = text.strip_prefix("L:")?;
    let line_digits = digits(after_line);
    let line: usize = after_line.get(..line_digits)?.parse().ok()?;
    let after_col = after_line[line_digits..].strip_prefix(",C:")?;
    let col_digits = digits(after_col);
    let col: usize = after_col.get(..col_digits)?.parse().ok()?;
    Some((Location { line, col }, 2 + line_digits + 3 + col_digits))
}

/// The character a `\uD8xx\uDCxx` pair at the start of `rest` encodes, if that is what starts it.
fn surrogate_pair_at(rest: &str) -> Option<char> {
    let hex = |escape: &str| -> Option<u32> {
        let digits = escape.strip_prefix("\\u")?;
        if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(digits, 16).ok()
    };
    let high = hex(rest.get(0..6)?)?;
    if !(0xD800..=0xDBFF).contains(&high) {
        return None;
    }
    let low = hex(rest.get(6..12)?)?;
    if !(0xDC00..=0xDFFF).contains(&low) {
        return None;
    }
    char::from_u32(0x10000 + ((high - 0xD800) << 10) + (low - 0xDC00))
}

/// `warnings` takes the `!!` tags the loader read past, whether or not the load succeeded: a tag read
/// before the loader refused the document was still read past.
fn load(
    from_reader: &str,
    kind: DocumentKind,
    warnings: &mut Vec<UnreadTag>,
) -> crate::rules::Result<LoadedDocument> {
    let mut loader = match kind {
        DocumentKind::Data => Loader::new(),
        DocumentKind::Spec => Loader::for_spec_file(),
    };
    let loaded = loader.load(from_reader.to_string());
    warnings.append(&mut loader.take_warnings());
    match loaded {
        Ok(value) => Ok(LoadedDocument {
            value,
            scalar_texts: loader.take_scalar_texts(),
            collisions: loader.collisions().clone(),
        }),
        Err(e) => match e {
            // All three are passed through rather than flattened into a `ParseError`, because the
            // caller is what decides how each is worded, and it can only do that while it can tell
            // them apart: `validate` reports a `MissingDocument` as an empty file and prints an
            // `UnsupportedDocument` and an `InvalidKeyType` as they are, where a `ParseError` gets
            // the file's first bytes attached. What this guarantees is that the variants reach the
            // caller; a caller that folds them into one variant does so itself, where that choice
            // can be seen.
            Error::InternalError(..) | Error::MissingDocument | Error::UnsupportedDocument(..) => {
                Err(e)
            }
            // libyaml's own failure is already a `ParseError`; rewrapping its display put a second
            // "Parser Error when parsing" inside the first, and every caller's wrapper added a third.
            Error::ParseError(..) => Err(e),
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

/// The name a mapping key stands for, or `InvalidKeyType` for a key that has no name.
///
/// This is the serde-backed loader's half of `libyaml::loader::stringify_scalar_key`, and it has to
/// move with it: refusing an unquoted account id, port or file mode under `Mappings` refuses templates
/// CloudFormation accepts, since a template is converted to JSON before deployment and JSON has no key
/// but a string. Until this landed, a `Mappings` block written that way loaded under `validate` and was
/// refused outright under `guard test` at exit 255 -- the shape of divergence the two loaders exist
/// under a pin to prevent.
///
/// The spellings the two readers agree on are checked against each other in
/// `both_loaders_resolve_the_same_document_to_the_same_value`: `0x1F` is 31, `0755` stays the string
/// "0755", `.nan` is a float on the serde side and the text ".nan" on the libyaml side, and for those
/// agreeing on the *rendering* is all that is left, which is why the float and non-finite arms are
/// spelled the way they are rather than through `to_string`.
///
/// They do not agree on every scalar, and that test deliberately leaves the others out. `serde_yaml`
/// resolves `0b101` to 5, where the libyaml loader keeps the string "0b101" (YAML 1.2 core has no
/// binary form), and what it makes of the literals that loader keeps as text (`.Inf`, `1e-400`,
/// `1e400`, an integer wider than `i64`) differs by spelling; the four cases are listed on
/// `libyaml::loader::KeyForm`. The one production route through this function is
/// `functions::strings::json_parse`, whose argument is JSON and has none of those spellings; fed a
/// YAML-only spelling anyway it reads them as listed there, and that is a documented divergence from
/// the three document routes, not a pinned agreement.
///
/// `Null`, the containers and a tagged key are refused, for the reasons on `stringify_scalar_key`: a
/// null has no text either convention agrees on, and `? [a, b]` has no JSON representation at all.
/// The message names the key's type, since `serde_yaml` has no position to name instead.
fn scalar_key_name(key: &serde_yaml::Value) -> crate::rules::Result<String> {
    match key {
        serde_yaml::Value::String(name) => Ok(name.to_string()),
        serde_yaml::Value::Bool(b) => Ok(b.to_string()),
        serde_yaml::Value::Number(num) => Ok(number_key_name(num)),
        other => Err(Error::InternalError(InternalError::InvalidKeyType(
            format!(
                "an unrecorded position, where the key is {}. Quote it to make it a string",
                match other {
                    serde_yaml::Value::Null => "null".to_string(),
                    serde_yaml::Value::Sequence(..) => "a sequence".to_string(),
                    serde_yaml::Value::Mapping(..) => "a mapping".to_string(),
                    serde_yaml::Value::Tagged(tagged) => format!("tagged {}", tagged.tag),
                    // Covered by the arms above; naming the variant is as specific as this can be.
                    _ => format!("{other:?}"),
                }
            ),
        ))),
    }
}

/// The text a numeric key stands for, rendered as `stringify_scalar_key` renders the same number.
///
/// Written as a chain of `as_*` rather than the `is_*`/`as_*.unwrap()` pair the value arm above uses,
/// so there is no arm that can hand back a default: a key silently rendered "0" is a lookup that
/// misses, which is the class of defect this function exists to close. `serde_yaml::Number`'s own
/// `Display` is the last resort and is exact for all three of its variants.
fn number_key_name(num: &serde_yaml::Number) -> String {
    if let Some(int) = num.as_i64() {
        return int.to_string();
    }

    if let Some(uint) = num.as_u64() {
        // Above `i64::MAX`. The libyaml loader keeps the literal for an integer this wide, and
        // `u64::to_string` is the same digits.
        return uint.to_string();
    }

    let Some(float) = num.as_f64() else {
        return num.to_string();
    };

    if !float.is_finite() {
        non_finite_spelling(float)
    } else {
        // A whole float keeps a fractional part, so `1.0` is "1.0" and not Rust's "1". That is what a
        // YAML-to-JSON conversion produces and what `PathAwareValue`'s own `serde_json` rendering
        // produces, and it is what `stringify_scalar_key` and `parse_string` produce: all three go
        // through the one renderer.
        crate::rules::functions::converters::float_to_string(float)
    }
}

/// Folds each `<<` value into the mapping that wrote it.
///
/// The serde-backed loader's half of `libyaml::loader::apply_merges`, and the precedence is that
/// function's: a key the mapping writes for itself wins over a merged one, which is why this runs once
/// every explicit key is in, and within a sequence of mappings an earlier entry wins over a later one.
///
/// Nothing here resolved the merge key at all, so `<<` became an ordinary key of that name and
/// everything under it was hidden -- a silent wrong SKIP on the shape essentially every real rule uses,
/// still live through the public `run_checks` and therefore through `guard-ffi` and `guard-lambda`
/// after the libyaml loader had been fixed. `serde_yaml::Value::apply_merge` was the alternative and is
/// not used: it would have to be called at every site that reaches this conversion, so a new one would
/// silently miss it, and it resolves a *quoted* `"<<"` as a merge because `Value` keeps no scalar
/// style -- the defect `libyaml::loader` carries `merge_key_index` to avoid.
///
/// A quoted `"<<"` is therefore merged on this side, and resolving the merge key here is what starts
/// that: before it, nothing on this side resolved `<<` at all, so a quoted `"<<"` was an ordinary key of
/// that name -- which is the correct reading, and the one `libyaml::loader` was fixed to give in the same
/// round this was written. The two loaders did not converge on that shape; they swapped, and the case
/// this side had right is the price of the case it had wrong. Measured on `"<<": { a: kept }`, this
/// loader went from `{"<<":{"a":"kept"}}` to `{"a":"kept"}` while libyaml went the other way.
///
/// The trade is deliberate and it is the right way round, because the two cases are not the same size. A
/// plain `<<` is the shape essentially every real template that merges uses, and it was hidden entirely
/// -- a silent wrong SKIP. A quoted `"<<"` is a key someone wrote to mean the literal characters, and
/// neither corpus contains one.
///
/// The third option: resolve the plain `<<` only where the style is known, and leave the quoted key
/// alone. That is what keeps the two loaders agreeing, and it cannot be decided from here.
/// `serde_yaml::Value` keeps no scalar style -- `<<` and `"<<"` are both `Value::String("<<")` by the
/// time any of this runs -- so the distinction has to be made where the text is still text. Three entry
/// points reached this conversion, and they divided by whether the format leaves any style to recover:
///
///   - `functions::strings::json_parse`, which parses **JSON**. It no longer reaches this function at
///     all: it converts through `Value::try_from_json`, which reads `<<` as an ordinary member name.
///     No style needs recovering there, because JSON has none to lose -- every JSON member name is
///     quoted, so a `<<` in JSON is always the literal key and never YAML's merge key. Until that was
///     split out, `json_parse` on the valid JSON `{"<<": {"hoisted": "yes"}, "b": "kept"}` dropped the
///     `"<<"` member and hoisted its contents, so `%p["<<"] exists` FAILed while `%p.hoisted == "yes"`
///     PASSed -- a member every other JSON reader in a pipeline keeps.
///   - `commands::helper::validate_and_return_json`, which has the bytes. It reads them through
///     `libyaml::loader` now, the loader `validate` uses, so a quoted `"<<"` is literal there.
///   - `TestSpec::input`: `commands::test::parse_test_specs` reads the spec file through
///     `libyaml::loader` as well and keeps each `input:` as the loader left it, so the quoted key is
///     literal there too.
///
/// So the divergence was closed by replacing the loader at the two YAML entry points, as this comment
/// said it would have to be, and no document a user supplies reaches this conversion any more:
/// `rules` is a private module, so nothing outside the crate can name it either. Its remaining callers
/// are in-crate tests, which build fixtures through `TryFrom<serde_yaml::Value>` and hold the two
/// conversions against each other in `both_loaders_resolve_the_same_document_to_the_same_value`. The
/// quoted `"<<"` still merges on this side for the reason above, recorded with that pin's other cases
/// in `values_tests`; `try_from_json`, which `json_parse` does reach, shares the mapping arm under
/// `MergeKey::Literal`, holds no key back, and so reaches this function only with an empty list of
/// sources: it never merged the quoted key.
fn merge_into(
    map: &mut IndexMap<String, Value>,
    merges: Vec<&serde_yaml::Value>,
    kinds: &mut std::collections::HashMap<String, KeyKind>,
) -> crate::rules::Result<()> {
    for source in merges {
        let sources = match source {
            serde_yaml::Value::Mapping(entries) => vec![entries],
            serde_yaml::Value::Sequence(entries) => entries
                .iter()
                .map(|entry| match entry {
                    serde_yaml::Value::Mapping(entries) => Ok(entries),
                    _ => Err(merge_value_error()),
                })
                .collect::<crate::rules::Result<Vec<_>>>()?,
            _ => return Err(merge_value_error()),
        };

        for entries in sources {
            // A collision is two keys that read as one name but are not the same YAML key: the
            // integer `1` beside the string `"1"`, wherever the two sit -- in this source, across
            // two sources, or a merged key under an explicit one. A collision is refused on this
            // route, which has no warning channel, and warns on the libyaml route, which has one;
            // the value a route produces is the same on both. A same-key override -- a merged plain
            // `Type` under an explicit plain `Type`, which is what the merge key is for -- is
            // neither, and the explicit (or earlier-source) value stands silently on every route.
            //
            // Three checks against the live map, in this order: a name this source has already
            // inserted is a repeat and refused (`serde_yaml` has refused the same-kind repeat
            // already, so a repeat here is always two kinds); a name the map holds is an override
            // when the held key was written as the same kind and a collision otherwise; anything
            // else is this source's first entry of that name and is inserted. `kinds` is the kind
            // each held name was written as, by the explicit entries and by the sources before this
            // one. Spelling is not kind: a plain `x`, a quoted `"x"` and a `!!str x` are one string
            // key here and on the libyaml loader alike, and so is `0755`, a string on both sides, so
            // `0755` beside `"0755"` is a silent override everywhere. The one form the two sides read
            // differently is a plain literal the libyaml loader keeps as text though YAML resolves
            // it, which that loader reports beside its quoted spelling. `serde_yaml` has no such
            // form, and what reaches this conversion instead goes four ways by spelling; the four
            // cases are listed once, on `libyaml::loader::KeyForm`, and each is measured in
            // `values_tests`.
            let mut seen_in_source: std::collections::HashSet<String> =
                std::collections::HashSet::with_capacity(entries.len());
            for (key, value) in entries {
                let name = scalar_key_name(key)?;
                let kind = KeyKind::of(key);
                if seen_in_source.contains(&name) {
                    return Err(colliding_key_error(&name));
                }
                if let Some(held) = kinds.get(&name) {
                    if *held == kind {
                        continue;
                    }
                    return Err(colliding_key_error(&name));
                }
                seen_in_source.insert(name.clone());
                kinds.insert(name.clone(), kind);
                map.insert(name, Value::try_from(value)?);
            }
        }
    }

    Ok(())
}

/// The kind a mapping key was written as, which is what tells a same-key override from a collision
/// once the key has been rendered to text.
///
/// `serde_yaml::Value` keeps the resolved kind -- string, number, boolean -- which is what YAML
/// compares keys by: a plain `x`, a quoted `"x"` and a `!!str x` are one string key, here and on the
/// libyaml loader, as is `0755`, a string on both sides. The libyaml loader has one form this side
/// does not, a plain literal it keeps as text though YAML resolves it, and it warns when such a key
/// sits beside its quoted spelling; what reaches this conversion instead differs by spelling. The
/// four cases are listed once, on `libyaml::loader::KeyForm`, and each is pinned in `values_tests`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyKind {
    Str,
    Number,
    Bool,
    Other,
}

impl KeyKind {
    fn of(key: &serde_yaml::Value) -> KeyKind {
        match key {
            serde_yaml::Value::String(..) => KeyKind::Str,
            serde_yaml::Value::Number(..) => KeyKind::Number,
            serde_yaml::Value::Bool(..) => KeyKind::Bool,
            _ => KeyKind::Other,
        }
    }
}

/// The refusal for two keys of one mapping, or of one merge source, that read as the same name.
///
/// `serde_yaml` has already refused two keys whose resolved values are equal by the time either caller
/// runs (`0x1F` beside `31` is a duplicate to it, as is `true` beside `True`), so the pair this names is
/// always two scalars whose resolved values differ and whose text is the same: the integer `1` beside
/// the string `"1"`, or `true` beside `"true"`. The advice says remove or rename, not quote: quoting the
/// number makes it the very string it collides with.
fn colliding_key_error(name: &str) -> Error {
    Error::ParseError(format!(
        "two keys of one mapping both read as the key `{name}`, one written as a string and one as a \
         number or boolean, so one value would silently replace the other. Remove or rename one of \
         them; quoting both makes them the same key"
    ))
}

/// The libyaml loader's merge-value refusal without the position, which `serde_yaml` does not carry.
fn merge_value_error() -> Error {
    Error::ParseError(format!(
        "the merge key `{MERGE_KEY}` must be given a mapping, or a sequence of mappings, because its \
         value's keys become keys of the mapping that carries it (https://yaml.org/type/merge.html)"
    ))
}

/// YAML's canonical spelling of a non-finite float, as the string it becomes in the value model.
///
/// The libyaml loader keeps a non-finite float out of the value model as the literal text the document
/// wrote, whatever its casing. This conversion has no text left by the time it runs -- `serde_yaml`
/// resolves `.inf`, `.Inf`, `.INF`, `+.inf`, `.nan`, `.NaN` and `.NAN` to the same two floats -- so
/// the canonical spelling is the best it can do, and it matches the libyaml loader only for a document
/// that wrote `.inf`, `-.inf` or `.nan` in lower case. Bare `NaN` and `inf` stay strings on both
/// sides, being outside the YAML 1.2 core schema.
///
/// The only production route that reaches this is `functions::strings::json_parse`, whose argument is
/// JSON, which has no spelling for a non-finite number at all; the `test` command and the public
/// `run_checks` read documents through the libyaml loader. So the casing gap is reachable only by a
/// YAML-only spelling passed to `json_parse`, and it is recorded as a documented divergence rather
/// than closed: `json_parse` reads `.Inf` as the string ".inf" where the three document routes read
/// it as ".Inf", alongside `0b101` as 5 and a `1e-400` key as "0.0" (see `scalar_key_name`). The
/// tests pin the three document routes to each other and leave `json_parse` to this comment.
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
/// This is the serde-backed conversion's half of the same two fixes the libyaml loader carries, and it
/// has to move with it. The one production route that reaches it is `functions::strings::json_parse`,
/// whose string is parsed by `serde_yaml` and so may carry a `!Foo` tag; the `test` command and the
/// public `run_checks` read documents through the libyaml loader. A disagreement here would mean a tag
/// inside a `json_parse` argument reads differently from the same tag in the template around it.
///
/// `long_form_of` supplies the name for any `!Foo`, by CloudFormation's own rule that `!Foo` is
/// `Fn::Foo`, rather than a hand-written name set that discards the tag on a miss and keeps only the
/// payload -- which would turn the short form of Cidr, ForEach, GetStackOutput, Length, ToJsonString,
/// Transform or ValueOfAll into something else.
///
/// `GetAtt` also gets its dotted payload split, for the reason given on `libyaml::loader::getatt_payload`:
/// AWS documents `!GetAtt Resource.Attr` as the short form of the two-element list, and JSON has no
/// other shape for it, so leaving the dotted form a string gives one reference two incomparable shapes.
fn handle_tagged_value(
    val: serde_yaml::Value,
    fn_ref: &str,
    merge_key: MergeKey,
) -> crate::rules::Result<Value> {
    let payload = convert_yaml(&val, merge_key)?;
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
