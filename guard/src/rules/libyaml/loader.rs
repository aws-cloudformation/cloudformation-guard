use std::borrow::Cow;
use std::collections::HashSet;

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

/// YAML's merge key. Its value's keys belong to the mapping that carries it, rather than to a key of
/// this name. See `apply_merges`.
const MERGE_KEY: &str = "<<";

/// How many mappings and sequences may be nested inside one another.
///
/// There has to be a bound, because `PathAwareValue::try_from_marked` -- which every loaded document
/// is handed to -- recurses once per level and overflows the stack. Measured on this repository's
/// release build: depth 5281 converts, depth 5375 aborts with SIGABRT and
/// "thread 'main' has overflowed its stack" on stderr, no diagnostic from cfn-guard and an exit code
/// outside the set the tool documents. `Loader::load` itself is iterative and survives depth 20000,
/// and so does dropping the resulting `MarkedValue`, so the bound belongs where the deep value is
/// *built* rather than where it is consumed -- refusing here means no deep `MarkedValue` is ever
/// constructed for anything downstream to recurse over.
///
/// The same recursion is also why depth is expensive well before it is fatal. Every node rebuilds its
/// full path string from its parent's, so the bytes allocated grow with the square of the depth:
/// depth 800 took 4.9 seconds, depth 1600 took 39, depth 2000 took 76, and a 40 KB file of nothing
/// but brackets killed the process. Bounding the depth bounds that cost too, which is why this is one
/// change and not two.
///
/// 128 is not arbitrary. It is the recursion limit serde already enforces on the *other* loader in
/// this product, and at this value the two agree level for level: on files of `a: ` followed by n
/// brackets, `validate` and `rulegen` both accept n = 127 and both refuse n = 128, the second with
/// "recursion limit exceeded". So no document this loader refuses could have reached `run_checks` or
/// `guard test` either. And it is far above anything real -- the deepest data file in the rules
/// registry snapshot is 15 levels, and the deepest in this repository is 24
/// (`guard/resources/parse-tree/output-dir/test_rule_with_this_keyword.yaml`).
///
/// A non-recursive conversion was the alternative. It would remove the crash but not the quadratic
/// path-string cost, which is inherent to storing a full path at every node and reaches into `Path`,
/// `PathAwareValue` and every reporter that prints one. A bound fixes both, in the loader, and leaves
/// that refactor free to happen on its own terms.
const MAX_NESTING_DEPTH: usize = 128;

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
                    Event::MappingStart(..) => {
                        self.enter_container(&location)?;
                        self.handle_mapping_start(location)
                    }
                    Event::MappingEnd => self.handle_mapping_end()?,
                    Event::SequenceStart(sequence_start) => {
                        self.enter_container(&location)?;
                        self.handle_sequence_start(sequence_start, location)
                    }
                    Event::SequenceEnd => self.handle_sequence_end(),
                    Event::Scalar(scalar) => self.handle_scalar_event(scalar, location),
                    // `UnsupportedDocument` rather than `ParseError` so the message survives:
                    // `build_data_file` replaces a `ParseError` with the file's first hundred bytes,
                    // which meant the one diagnostic that says what to change was thrown away and an
                    // alias file reported only "Error encountered while parsing data file".
                    //
                    // The merge key gets a mention because `<<: *base` is how a merge is usually
                    // written, so a template using one arrives here rather than at `apply_merges`,
                    // and "does not support aliases" alone does not connect the two.
                    Event::Alias(_) => {
                        return Err(Error::UnsupportedDocument(format!(
                            "cfn-guard does not support YAML aliases, and this file uses one at \
                             {location}. Write the value out where it is used. A merge key written \
                             `{MERGE_KEY}: *anchor` is an alias too; the inline form \
                             `{MERGE_KEY}: {{ ... }}` is supported."
                        )))
                    }
                };
            };
        }
    }

    /// Refuses a container that would nest deeper than [`MAX_NESTING_DEPTH`].
    ///
    /// `last_container_index` holds one entry per mapping or sequence currently open, so its length
    /// is the depth this container is about to be nested inside.
    fn enter_container(&mut self, location: &Location) -> rules::Result<()> {
        if self.last_container_index.len() >= MAX_NESTING_DEPTH {
            return Err(Error::UnsupportedDocument(format!(
                "cfn-guard reads documents nested at most {MAX_NESTING_DEPTH} levels deep, and this \
                 file goes deeper: the container at {location} is at level {}. The deepest \
                 CloudFormation template in AWS's own rules registry is 15 levels.",
                self.last_container_index.len() + 1
            )));
        }

        Ok(())
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
        let mut merges: Vec<MarkedValue> = vec![];
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
                    return Err(Error::InternalError(InvalidKeyType(format!(
                        "{}, where the key is {}. Quote it to make it a string",
                        val.location(),
                        describe_key(&val)
                    ))));
                }
            };

            // Held back rather than inserted. The keys it brings must not override the ones this
            // mapping writes for itself, so they can only be added once every explicit key is in.
            if key_str.0 == MERGE_KEY {
                merges.push(value);
                continue;
            }

            map.insert(key_str, value);
        }

        apply_merges(map, merges)
    }

    fn handle_mapping_start(&mut self, location: Location) {
        self.stack
            .push(MarkedValue::Map(indexmap::IndexMap::new(), location));
        self.last_container_index.push(self.stack.len() - 1);
    }
}

/// Folds each `<<` value into the mapping that wrote it.
///
/// `<<` is YAML's merge key (<https://yaml.org/type/merge.html>): its value is a mapping, or a
/// sequence of mappings, whose keys belong to the mapping that carries it. Nothing here resolved it,
/// so `<<` became an ordinary key named `<<` and everything under it was hidden. libyaml is a parser
/// rather than a composer, so nothing upstream resolves it either.
///
/// The consequence was a silent wrong SKIP on the shape essentially every real rule uses. A template
/// whose `Type` arrives through a merge was invisible to `Resources[ Type == "AWS::S3::Bucket" ]`, so
/// the filter selected nothing, the rule was skipped, and a wide-open bucket exited 0 unchecked.
/// Writing the same `Type` inline made the same file exit 19 and FAIL.
///
/// Precedence follows the spec: a key the mapping writes for itself always wins over a merged one,
/// which is why this runs after every explicit key is in, and within a sequence of mappings an earlier
/// entry wins over a later one, which is what iterating in order and skipping names already present
/// gives. Two `<<` keys in one mapping are not something the spec defines; earlier wins, for the same
/// reason.
///
/// The merged keys are appended after the explicit ones. The spec does not say where they go, and the
/// position only affects the order `PathAwareValue`'s `keys` are iterated in -- so which resource a
/// report names first, not which verdict it reaches.
///
/// Only the inline spellings are reachable. `<<: *base`, which is how a merge key is usually written,
/// contains an alias, and `Loader::load` refuses every alias before this runs. That refusal is loud
/// and stays; this closes the spelling that was quietly misread.
fn apply_merges(
    map: &mut indexmap::IndexMap<(String, Location), MarkedValue>,
    merges: Vec<MarkedValue>,
) -> rules::Result<()> {
    if merges.is_empty() {
        return Ok(());
    }

    // By name, because the map is keyed on `(name, location)` and a merged key has a different
    // location than the explicit key it must not displace.
    let mut present: HashSet<String> = map.keys().map(|(name, _)| name.clone()).collect();

    for source in merges {
        let location = *source.location();
        let sources = match source {
            MarkedValue::Map(entries, ..) => vec![entries],
            MarkedValue::List(entries, ..) => entries
                .into_iter()
                .map(|entry| match entry {
                    MarkedValue::Map(entries, ..) => Ok(entries),
                    other => Err(merge_value_error(other.location())),
                })
                .collect::<rules::Result<Vec<_>>>()?,
            _ => return Err(merge_value_error(&location)),
        };

        for entries in sources {
            for (key, value) in entries {
                if present.insert(key.0.clone()) {
                    map.insert(key, value);
                }
            }
        }
    }

    Ok(())
}

fn merge_value_error(location: &Location) -> Error {
    Error::UnsupportedDocument(format!(
        "the merge key `{MERGE_KEY}` at {location} must be given a mapping, or a sequence of \
         mappings, because its value's keys become keys of the mapping that carries it \
         (https://yaml.org/type/merge.html)"
    ))
}

/// Names the type of a key that is not a string, and its value where it has a short one.
///
/// The refusal used to carry the location and nothing else, which in a run over a directory of
/// templates tells the reader neither which key nor -- since the location is all it has -- which of
/// several thousand lines in which of N files. The location alone also cannot be searched for: a
/// reader who sees `L:2,C:4` cannot grep for it.
///
/// The value is included for the scalars whose rendering is short and unambiguous. It is deliberately
/// *not* used to accept the key: `MarkedValue` holds the resolved value and not the text the document
/// wrote, so rendering an `Int` back gives "31" for a key written `0x1F`, a `Float` gives "1" for
/// `1.0`, and a `Bool` gives "true" for `True`. Turning any of those into a key name would invent a
/// name the document does not contain, which is the same shape of defect as the ones this file has
/// been fixing. Accepting non-string keys properly means carrying the scalar's original text through
/// the value model, which is a larger change than a diagnostic.
fn describe_key(key: &MarkedValue) -> String {
    match key {
        MarkedValue::Null(..) => "null".to_string(),
        MarkedValue::Bool(b, ..) => format!("the boolean {b}"),
        MarkedValue::Int(i, ..) => format!("the integer {i}"),
        MarkedValue::Float(f, ..) => format!("the float {f}"),
        MarkedValue::Char(c, ..) => format!("the character {c}"),
        MarkedValue::List(..) => "a sequence".to_string(),
        MarkedValue::Map(..) => "a mapping".to_string(),
        MarkedValue::BadValue(val, ..) => format!("an unreadable value, {val}"),
        // Every remaining variant is produced by the rules parser rather than by this loader, so
        // naming the variant is as specific as this can honestly be.
        other => format!("a {other:?}"),
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
        // An integer literal too wide for `i64`. This used to fall through to the float resolver,
        // which accepted it, so `9223372036854775809` became `Float(9.223372036854776e18)` -- and so
        // did `9223372036854775810`, which is a different integer. The two then compared *equal*,
        // and a clause asserting they differ was reported non-compliant. That is a wrong answer
        // about identity, produced silently.
        //
        // The literal is kept instead. `MarkedValue::Int` is an `i64`, so there is no arm here that
        // can hold the value: widening it reaches `PathAwareValue::Int` and from there every
        // comparison operator, the serializers and SARIF, which is a change of a different size and
        // shape than this one. `serde_yaml` holds `i64::MAX + 1` as an integer and refuses anything
        // past `u64`; keeping the text agrees with neither, but it is the only option here that
        // never reports two distinct integers as one.
        Err(_) => IntScalar::Unresolvable,
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
        let payload = if fn_ref == "GetAtt" {
            getatt_payload(val, &loc)
        } else {
            MarkedValue::String(val, loc.clone())
        };
        let fn_ref = short_form_to_long(fn_ref);
        map.insert((fn_ref.to_string(), loc.clone()), payload);

        return Some(MarkedValue::Map(map, loc));
    }

    None
}

/// The payload of a `!GetAtt`, normalised to the list shape the other two spellings produce.
///
/// CloudFormation documents `!GetAtt logicalNameOfResource.attributeName` as the short form of
/// `{ "Fn::GetAtt": [ "logicalNameOfResource", "attributeName" ] }`
/// (<https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/intrinsic-function-reference-getatt.html>),
/// and the dotted spelling is YAML-only -- JSON has the list and nothing else. Nothing here split on
/// the dot, so `!GetAtt SecretResource.Arn` was a *string* while `!GetAtt [SecretResource, Arn]` and
/// the long form were both a *list*. One reference had two incompatible shapes depending on how the
/// template happened to be written, so a rule authored against JSON templates silently declined to
/// check YAML ones: a filter reaching `"Fn::GetAtt"[0]` selected nothing, the rule was skipped, and
/// the run exited 0 with an empty stderr.
///
/// The split is on the **first** dot only, because the attribute name may contain dots of its own.
/// AWS's own example is `!GetAtt myELB.SourceSecurityGroup.OwnerAlias`, which it gives as
/// `["myELB", "SourceSecurityGroup.OwnerAlias"]`.
///
/// A payload with no dot is left as a string. It is not a valid `Fn::GetAtt` -- the function takes a
/// resource and an attribute -- and inventing a one-element list would produce a shape neither the
/// long form nor JSON can produce.
///
/// Both halves carry the location of the scalar they were written as, which is where they are: they
/// came from one token, and the alternative is to derive a column by counting from a start mark whose
/// relationship to the tag has not been established here.
fn getatt_payload(val: String, loc: &Location) -> MarkedValue {
    match val.split_once('.') {
        Some((resource, attribute)) => MarkedValue::List(
            vec![
                MarkedValue::String(resource.to_string(), loc.clone()),
                MarkedValue::String(attribute.to_string(), loc.clone()),
            ],
            loc.clone(),
        ),
        None => MarkedValue::String(val, loc.clone()),
    }
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
