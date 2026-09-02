use std::borrow::Cow;
use std::collections::HashSet;

use crate::rules::{
    self,
    errors::{Error, InternalError::InvalidKeyType},
    libyaml::{
        event::{Event, MappingStart, Scalar, ScalarStyle, SequenceStart},
        parser::Parser,
        tag::Tag,
    },
    long_form_of,
    path_value::Location,
    values::MarkedValue,
};

const TYPE_REF_PREFIX: &str = "tag:yaml.org,2002:";

/// YAML's merge key. Its value's keys belong to the mapping that carries it, rather than to a key of
/// this name. See `apply_merges`.
///
/// Shared with `values::merge_into`, the serde-backed loader's half of the same resolution, so the two
/// cannot drift apart on the spelling.
pub(crate) const MERGE_KEY: &str = "<<";

/// How many mappings and sequences may be nested inside one another.
///
/// There has to be a bound, because `PathAwareValue::try_from_marked` -- which every loaded document is
/// handed to -- recurses once per level and overflows the stack: SIGABRT and "thread 'main' has overflowed
/// its stack" on stderr, no diagnostic from cfn-guard, and an exit code outside the set the tool documents.
/// The bound belongs where the deep value is *built* rather than where it is consumed, so that no deep
/// `MarkedValue` is ever constructed for anything downstream to recurse over.
///
/// Every figure below is rustc 1.77.2 on x86_64 Linux and carries its profile, because an unlabeled release
/// figure in the parser's half of this bound hid a `cargo test` that aborted on three CI platforms. Which
/// build each one needs differs: the figures at 128 are observable on the stock binary, the ones above it
/// need this constant raised, the corpus depths below it need it lowered, and the serde boundary does not
/// depend on this constant at all.
///
/// **The stack.** The conversion costs **1.493 KB per level optimized, 7.881 KB unoptimized**. Bisect an
/// explicit `stack_size` at a fixed depth rather than the depth at a fixed stack; it is the same measurement
/// two orders of magnitude more precisely. A Rust thread's default 2 MB therefore reaches roughly twice this
/// bound unoptimized, and `main`'s 8 MB roughly eight times it. Stated as a ratio because there is a
/// fixed overhead of a few tens of KB besides the per-level cost, so scaling the per-level figure alone
/// overestimates by a handful of levels. That comparison is the load-bearing one: unlike the parser's bound,
/// whose unoptimized ceiling of 67 sits *below* its 128, nothing here is refused by a stack before it is
/// refused by the count.
///
/// `Loader::load` is iterative and survives depth 20000 on a **16 KB** thread in both profiles, which is the
/// smallest glibc will honour. Dropping the resulting `MarkedValue` is recursive drop glue and is where the
/// stack actually goes: linear at 0.2349 KB per level unoptimized, so load-plus-drop at depth 20000 needs
/// 4699 KB and a 2 MB libtest thread aborts on it. At this bound it is about 30 KB, so none of it reaches
/// the shipped path.
///
/// **The cost before it is fatal**, which is the other half of why bounding depth mattered. There are two
/// costs and only one of them is inherent.
///
/// The **bytes** are the conversion, and they are structural: every node's `Path` is built from its parent's
/// by `extend_usize` for sequence children, `extend_string` for mapping children -- the dominant case in a
/// template -- and `with_location` on both, so n nodes each hold a path of length up to n and the bytes grow
/// with the square of the depth. Read `try_from_marked` to check it; no measurement required.
///
/// The **time** was cubic, and it is not the conversion. It is one `format!` whose output is discarded.
/// `Traversal::at` renders `self.nodes.range(pointer..)` with `{:?}` to build the `RetrievalError` for a
/// path that misses, and `CfnAware::report_eval` probes `at("/Resources", root).is_ok()` on every data file
/// to decide whether to report it as a CloudFormation template. A document with no `Resources` section
/// therefore renders every node whose path sorts at or after `/Resources`, each entry printing its whole
/// subtree and each subtree node its full path, and `is_ok()` throws the string away. One `format!` per
/// probe: the cube is the size of what gets rendered, not the number of calls.
///
/// The control is one character. With 1600 brackets in both documents and the rule verdict held constant,
/// `a: [[[ ... ]]]` takes 36.818 s and `A: [[[ ... ]]]` takes 0.023 s, optimized. Uppercase sorts before
/// `/Resources` and lowercase after it, so the only difference is whether the top-level key falls inside the
/// probe's range -- same depth, same bracket count, same bytes. The conversion is 0.017 s on either.
///
/// A second, independent cost appears only when a rule fails: about 2.3 s on that same document, unaffected
/// by the probe, with a stack sample in `GenericSummary::report_eval` -> `simplified_json_from_root` ->
/// `report_all_failed_clauses_for_rules` -> `PathAwareValue::clone`, each cloned node copying its full path
/// `String`. Medium confidence on that attribution: one stack sample, and no control isolating the clone.
///
/// **Do not chase either from here.** Every factor -- range size, subtree size, path length -- scales with
/// depth, and depth is bounded at 128, where the same `validate` run finishes in under a tenth of a second.
/// A bound rather than a figure, deliberately: at a few hundredths of a second the measurement moves by tens
/// of percent with whatever else the host is running, so an exact one reproduces only where it was taken.
/// A wide, shallow document has short paths and small subtrees and stays cheap as well. So this is the
/// historical justification for the bound rather than a live cost on the shipped binary, and the
/// discarded-message waste is filed in the known-defects write-up instead of fixed here.
///
/// **Why 128.** It is the limit serde already enforces on the other loader in this product, and at this
/// value the two agree exactly: both accept a document nested 128 containers deep and both refuse 129,
/// measured on the live serde path, which is a `test` spec's `input:` block. Witness it with a JSON spec,
/// which refuses 129 with `recursion limit exceeded`; a YAML one reports `invalid number at line 1 column 2`
/// instead, because `parse_test_specs` discards serde_yaml's error and serde_json then fails on the YAML
/// syntax rather than the depth. Not `rulegen`, which is no longer a second witness: `load_template` reads
/// through this loader now, so its agreement is tautological.
///
/// **And it is far above anything real.** Set this constant to N, rebuild, and run `validate --data` over
/// every `.yaml`, `.yml`, `.json` and `.template` file in both corpora; a file's level count is the smallest
/// N that accepts it.
///
/// ```text
/// rules registry snapshot            14   kms_no_wildcard_principal_tests.yml, and two others
///   its embedded `input:` templates  12
/// this repository                    23   parse-tree/output-dir/test_rule_with_this_keyword.yaml
///   excluding `output-dir/` fixtures 11   apigateway-restapi-tests.yaml, and two others
/// ```
///
/// Depths only, deliberately: no file counts, here or in `rules::parser::MAX_NESTING_DEPTH`, because a count
/// of the files in a repository does not survive being written down inside it -- adding a fixture is the
/// most ordinary change there is and nothing connects the two. The commits that removed those counts record
/// what went wrong with them.
///
/// The 23 is not a template. Every file here deeper than 11 levels is under an `output-dir/`, which is
/// cfn-guard's own serialized parse trees and validate reports, and this loader never reads those. Nothing
/// in either corpus shaped like a CloudFormation template passes 12, and most of the registry's data files
/// are `test` specs whose `input:` blocks carry the templates, read by the serde loader rather than this
/// one. So the bound clears real input by an order of magnitude and clears even this repository's serialized
/// output several times over, which is the form of the claim that does not move when a fixture gains a level.
///
/// A non-recursive conversion was the alternative. It would remove the crash but not the quadratic bytes,
/// and not the clone on the failure path either, which is the same property showing up as time: both are
/// inherent to storing a full path at every node, and both reach into `Path`, `PathAwareValue` and every
/// reporter that prints one. It would not touch the dominant cost at all, because a discarded `{:?}` of a
/// `BTreeMap` range is not a property of the path representation and is removable on its own terms. A bound
/// caps all three, in the loader, and leaves either refactor free to happen separately.
const MAX_NESTING_DEPTH: usize = 128;

#[derive(Debug, Default)]
pub struct Loader {
    stack: Vec<MarkedValue>,
    last_container_index: Vec<usize>,
    func_support_index: Vec<(usize, (String, Location))>,
    /// Stack indices of the scalars that are merge keys, recorded by `handle_scalar_event`.
    ///
    /// The merge type is resolved from the **plain** scalar only: `tag:yaml.org,2002:merge` is an
    /// implicit resolution, and implicit resolution applies to the plain style. So `"<<"` is an
    /// ordinary key whose name happens to be `<<`, which is the documented way to write one.
    ///
    /// It has to be recorded here because the style is gone by `handle_mapping_end`: a non-plain
    /// scalar becomes `MarkedValue::String` and so does a plain `<<`, so both spellings arrive there
    /// as the same `String("<<")` and testing the resolved name cannot tell them apart.
    merge_key_index: Vec<usize>,
}

impl Loader {
    pub fn new() -> Loader {
        Loader::default()
    }

    pub(crate) fn load(&mut self, content: String) -> rules::Result<MarkedValue> {
        let mut parser = Parser::new(Cow::Borrowed(content.as_bytes()));
        let mut document: Option<MarkedValue> = None;
        // Whether the document in hand holds only the empty node, and the running answer for the
        // document being read: how many events it has held, and whether any of them was something
        // other than the empty node. The same three values `count_remaining_documents` keeps for the
        // documents after the first, kept here for the first as well, because the two ends of the file
        // have to agree on what "holds nothing" means.
        let mut held_is_empty = false;
        let mut events = 0;
        let mut empty = true;

        loop {
            let (event, location) = parser.next()?;

            // Decided before the match rather than inside its arms so that no event kind can be
            // missed: anything that is not stream or document bookkeeping is content, except the empty
            // node standing alone as a document's only event.
            match &event {
                Event::StreamStart
                | Event::StreamEnd
                | Event::DocumentStart
                | Event::DocumentEnd => {}
                Event::Scalar(scalar) if events == 0 && is_empty_node(scalar) => events += 1,
                _ => {
                    events += 1;
                    empty = false;
                }
            }

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
                        // `document.is_some() && !held_is_empty`: a document holding only the empty
                        // node does not occupy the one slot, so it does not make the next document a
                        // second one. `---\n---\nResources: {}` is a template behind two separators,
                        // which is the same shape as `Resources: {}\n---\n` is in front of one, and a
                        // header comment in its own document ahead of the template is the reachable
                        // spelling of it. Counting the leading one reproduced, at the other end of the
                        // file, exactly the defect the trailing `---` fix had closed: the count said 2
                        // where one document held anything, and the position it named as where "the
                        // second" starts was the start of the only document in the file, so the advice
                        // -- split them into separate files -- put the template in file two and left
                        // file one holding a `---`.
                        if document.is_some() && !held_is_empty {
                            match count_remaining_documents(&mut parser, location) {
                                // Every document after the first holds nothing, so the file holds
                                // one document and some separators. libyaml emits a whole document
                                // -- start, empty scalar, end -- for a `---` with nothing after it,
                                // so a template followed by a trailing separator was a two-document
                                // stream by this test, and the refusal asked the reader to split out
                                // a document that is not there. The scan drained the stream, so
                                // returning here cannot report compliance for bytes libyaml never
                                // read, which is what the refusal exists to prevent.
                                Remaining::Separators => {
                                    return document.ok_or(Error::MissingDocument)
                                }
                                Remaining::Documents { count, exact, at } => {
                                    return Err(Error::UnsupportedDocument(format!(
                                        "cfn-guard evaluates one document per file, and this file \
                                         holds {}{count} -- the second starts at {at}. Split them \
                                         into separate files.",
                                        if exact { "" } else { "at least " },
                                    )));
                                }
                            }
                        }

                        events = 0;
                        empty = true;
                    }
                    // Reaching the end of the stream with a document in hand is the ordinary exit.
                    // With none, no document was ever started -- a file of nothing but comments is
                    // the ordinary way to get here. Treating it as a no-op left the loop pulling
                    // events past the end of the stream, where libyaml answers with
                    // `YAML_NO_EVENT`, and that used to abort the process in `convert_event`.
                    Event::StreamEnd => return document.ok_or(Error::MissingDocument),
                    Event::DocumentEnd => {
                        // Always replaces what is in hand, and that is not a loss: the only way to
                        // reach a second `DocumentEnd` is for the first document to have been empty,
                        // because a non-empty one in hand returns at the `DocumentStart` above. An
                        // empty document is still kept when nothing else turns up, so a file that is
                        // nothing but separators loads as null exactly as `---` alone always has.
                        held_is_empty = empty;
                        document = Some(self.stack.pop().unwrap());
                        self.stack.clear();
                        self.last_container_index.clear();
                        self.func_support_index.clear();
                        self.merge_key_index.clear();
                    }
                    Event::MappingStart(mapping_start) => {
                        self.enter_container(&location)?;
                        self.handle_mapping_start(mapping_start, location)
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
                 file goes deeper: the container at {location} is at level {}. Real CloudFormation \
                 templates nest a handful of levels; nothing in AWS's own rules registry comes close \
                 to this.",
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
        // See `merge_key_index`. Decided here because this is the last place the style is known.
        let is_merge_key = tag.is_none() && style == ScalarStyle::Plain && val == MERGE_KEY;

        let path_value = if let Some(tag) = tag {
            let handle = tag.get_handle();
            let suffix = tag.get_suffix(handle.len());

            if handle == "!" && !suffix.is_empty() {
                wrap_tagged_scalar(val, location, suffix.as_ref())
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
                    //
                    // `underflowed_to_zero` is the other half of the same rule, and it was
                    // missing. `is_finite` rejects the overflow -- `1e400` is infinite and falls
                    // through to a string -- but it accepts the underflow, because `1e-400`
                    // parses to a perfectly finite `0.0`. So the value the author wrote as
                    // positive answered `== 0` with a PASS, silently, where the overflow at the
                    // other end of the same exponent range refused. Both ends now keep the
                    // literal, which is what `rules::parser`'s float parser already claims the
                    // document side does.
                    Ok(f) if f.is_finite() && !underflowed_to_zero(&val, f) => {
                        MarkedValue::Float(f, location)
                    }
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
                        //
                        // The cost, which is not on the `k:` versus `k: ""` axis this was decided
                        // on. `empty` is refused on every non-container scalar, `Null` included, so
                        // moving the empty node here moved the most common spelling of a null out
                        // of the one scalar shape `empty` could answer. `empty` and `!empty` over a
                        // `k:` are now both FAIL, with "Attempting EMPTY operation on type null
                        // that does not support it" -- which an explicit `null` already did, so
                        // this widened an inconsistency rather than creating one.
                        //
                        // Where that is visible is a filter. `Resources[ Properties.Foo !empty ]`
                        // used to select nothing and SKIP at exit 0; the refusal is an error rather
                        // than a verdict, so it now bails and the rule FAILs at exit 19, with no
                        // edit to the template or the rule. Measured against `9fee1a2` on a
                        // one-property template, with `Foo: ""` as the control, which still SKIPs.
                        //
                        // Denominator, both sides of it: 79 empty-valued keys in 13 of 246 rules
                        // registry data files and 5 in 4 of 115 here, against `empty` at bracket
                        // depth in a `.guard` source -- which is a filter, since neither an index
                        // nor an `IN` list can hold the word -- 8 times in 7 of 210 registry files
                        // and once in 1 of 108 here.
                        //
                        // The direction is safe -- every arm moves toward FAIL -- and the three
                        // states still have three predicates: `not exists` for an absent key,
                        // `is_null` or `== null` for a key with no value, `empty` for an empty
                        // string, list or map. Making `empty` hold for a null would make null the
                        // one scalar it answers for and would convert refusals into verdicts
                        // wherever a rule writes `!empty` over a property that happens to be null.
                        None => match val.to_lowercase().as_str() {
                            "" | "~" | "null" => MarkedValue::Null(location),
                            _ => MarkedValue::String(val, location),
                        },
                    },
                },
            }
        };

        self.stack.push(path_value);
        if is_merge_key {
            self.merge_key_index.push(self.stack.len() - 1);
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

        self.forget_merge_keys_above(array_idx);
        self.close_tagged_container(array_idx);
    }

    /// Drops the recorded merge-key indices for a container that has just closed.
    ///
    /// Everything the container held has left the stack, so an index above its own is no longer live
    /// and would otherwise be read as a merge key of whichever mapping next occupies that index. A
    /// `<<` written as a *sequence item* rather than as a key is the shape that leaves one behind.
    fn forget_merge_keys_above(&mut self, container_idx: usize) {
        self.merge_key_index.retain(|idx| *idx <= container_idx);
    }

    /// Moves a container that a `!Foo` tag wrapped under its long function name.
    ///
    /// `push_tag_wrapper` left a single-entry map immediately below the container it tagged, so the
    /// wrapper is at `container_idx - 1` and the finished container is on top. Shared by the sequence
    /// and mapping ends, which differ only in how they built the container.
    fn close_tagged_container(&mut self, container_idx: usize) {
        // `container_idx > 0` before the subtraction. A wrapper is only ever pushed below a
        // container, so index 0 cannot have one, and reading it as an invariant rather than
        // checking it is how an underflow becomes a panic when the set of wrapped shapes grows.
        let wrapped = container_idx > 0
            && self
                .func_support_index
                .last()
                .map_or(false, |(idx, _)| *idx == container_idx - 1);

        if !wrapped {
            return;
        }

        let (_, fn_ref) = self.func_support_index.pop().unwrap();
        let container = self.stack.pop().unwrap();
        let map = self.stack.last_mut().unwrap();
        match map {
            MarkedValue::Map(map, _) => {
                let _ = map.insert(fn_ref, container);
            }
            MarkedValue::BadValue(..) => {}
            _ => unreachable!(),
        }
    }

    /// Pushes the wrapper for a `!Foo`-tagged sequence or mapping, so its contents end up under the
    /// long function name once the container closes.
    ///
    /// A bare `!` is skipped. It is YAML's non-specific tag rather than a function name, and
    /// `long_form_of("")` would name the key "Fn::".
    fn push_tag_wrapper(&mut self, tag: Option<&Tag>, location: &Location) {
        let Some(tag) = tag else { return };

        let handle = tag.get_handle();
        if handle != "!" {
            return;
        }

        let suffix = tag.get_suffix(handle.len());
        if suffix.is_empty() {
            return;
        }

        let fn_ref = long_form_of(&suffix).into_owned();
        self.stack
            .push(tagged_container_wrapper(location.clone(), &fn_ref));
        self.func_support_index
            .push((self.stack.len() - 1, (fn_ref, location.clone())));
    }

    fn handle_sequence_start(&mut self, event: SequenceStart, location: Location) {
        self.push_tag_wrapper(event.tag.as_ref(), &location);
        self.stack.push(MarkedValue::List(vec![], location));
        self.last_container_index.push(self.stack.len() - 1);
    }

    fn handle_mapping_end(&mut self) -> crate::rules::Result<()> {
        let map_index = self.last_container_index.pop().unwrap();
        let mut key_values: Vec<MarkedValue> = self.stack.drain(map_index + 1..).collect();
        // Which of this mapping's entries are merge keys, as offsets into `key_values`: its element
        // `i` was at stack index `map_index + 1 + i`. Read out before `map` borrows the stack.
        let merge_key_offsets: HashSet<usize> = self
            .merge_key_index
            .iter()
            .filter_map(|idx| idx.checked_sub(map_index + 1))
            .filter(|offset| *offset < key_values.len())
            .collect();
        self.forget_merge_keys_above(map_index);

        let mut merges: Vec<MarkedValue> = vec![];
        let map = match self.stack.last_mut().unwrap() {
            MarkedValue::Map(map, _) => map,
            _ => unreachable!(),
        };
        let mut offset = 0;
        while !key_values.is_empty() {
            let key = key_values.remove(0);
            let value = key_values.remove(0);
            let key_offset = offset;
            offset += 2;
            let key_str = match key {
                MarkedValue::String(val, loc) => (val, loc),
                // A scalar key becomes the text CloudFormation would give it. A template is
                // converted to JSON before it is deployed and JSON has no key but a string, so
                // `Mappings: { AccountToEnv: { 123456789012: ... } }` -- an account id written the
                // way a person writes one -- is a template CloudFormation accepts, and the same
                // content written in JSON already loaded here.
                //
                // `stringify_scalar_key` covers the integer, float and boolean scalars, whose
                // canonical text is the text CloudFormation's own conversion produces. Null and the
                // container keys are not in it: a null has no text either convention agrees on, and
                // `? [a, b]` has no JSON representation at all.
                val => match stringify_scalar_key(&val) {
                    Some(text) => (text, *val.location()),
                    None => {
                        return Err(Error::InternalError(InvalidKeyType(format!(
                            "{}, where the key is {}. Quote it to make it a string",
                            val.location(),
                            describe_key(&val)
                        ))));
                    }
                },
            };

            // Held back rather than inserted. The keys it brings must not override the ones this
            // mapping writes for itself, so they can only be added once every explicit key is in.
            //
            // Tested by position rather than by name: `merge_key_index` records the scalars the
            // *document* wrote as a plain `<<`, and `key_str.0 == MERGE_KEY` was also true of a
            // quoted `"<<"`, which YAML says is an ordinary key.
            if merge_key_offsets.contains(&key_offset) {
                merges.push(value);
                continue;
            }

            map.insert(key_str, value);
        }

        apply_merges(map, merges)?;
        self.close_tagged_container(map_index);

        Ok(())
    }

    fn handle_mapping_start(&mut self, event: MappingStart, location: Location) {
        // The tag was never read here, so a tagged *mapping* lost it unconditionally -- including for
        // names the loader did support. `!ToJsonString { a: 1 }` and `!Transform { Name: ... }` are
        // mappings, and both arrived as bare maps with no function around them.
        self.push_tag_wrapper(event.tag.as_ref(), &location);
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
/// Precedence follows the spec where the spec has a rule: a key the mapping writes for itself always
/// wins over a merged one, which is why this runs after every explicit key is in, and within a
/// sequence of mappings an earlier entry wins over a later one, which is what iterating a source in
/// order and skipping names already claimed gives.
///
/// **Two `<<` keys in one mapping is a duplicate key**, and the spec does not define it. It used to
/// resolve earlier-wins here, by analogy with the sequence rule. The closer analogy is the one
/// cfn-guard applies to every other duplicated key -- `path_value::try_from_marked` keeps the last
/// value and warns -- so the sources are applied in reverse document order and a later `<<` wins.
/// PyYAML agrees. `serde_yaml` does not settle it: measured, `from_str` refuses a duplicate key
/// outright ("duplicate entry with key `<<`"), so it never reaches its own merge handling, and the
/// two loaders differ on duplicate keys generally rather than on merges.
///
/// **A name duplicated inside one merge source is left for `try_from_marked` to collapse.** The map
/// is keyed on `(name, location)`, so two same-named entries of one source are two entries and both
/// survive to there, where they resolve last-wins with a warning -- the same convention, and the same
/// warning, a plain mapping gets. Claiming names per source rather than per entry is what allows that:
/// updating `present` inside a source would have made the *first* of the two win, silently, so one
/// malformed shape had two answers depending on whether the duplicate arrived through `<<`.
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

    for source in merges.into_iter().rev() {
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
            let mut claimed: Vec<String> = vec![];
            for (key, value) in entries {
                if !present.contains(&key.0) {
                    claimed.push(key.0.clone());
                    map.insert(key, value);
                }
            }
            present.extend(claimed);
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

/// The text a non-string scalar key stands for, or `None` for a key that has no text.
///
/// This exists because refusing these keys refuses templates CloudFormation accepts. A template is
/// converted to JSON before deployment and JSON has no key but a string, so an unquoted account id,
/// port or status code under `Mappings` is ordinary -- and the same document written in JSON already
/// loaded here, which is the inconsistency. `path_value::list_index_of`'s doc comment describes the
/// retrieval half of this as fixed; it was, and the template half was unreachable, because a document
/// writing the key the natural way never got as far as retrieval.
///
/// **This reverses the reasoning recorded when the diagnostic was improved**, which was that
/// rendering a resolved value "invents a name the document does not contain" because an `Int` from
/// `0x1F` renders as "31". The premise was wrong: a template is converted to JSON before deployment,
/// and the conversion resolves the scalar first, so "31" is what a `0x1F` key becomes on the way to
/// deployment. Rendering the resolved value models that; rendering the source text would not.
///
/// **The convention is one rule: the key is the text of the value this loader resolved the scalar to.**
/// It reads as three because the resolutions differ. A `String` key never reaches this function --
/// `handle_mapping_end` has its own arm for one -- so `0755` is the key "0755" because `resolve_int`
/// deliberately leaves that spelling as the *string* "0755", not because a second convention prefers
/// source text. `0x1F` is "31" because it resolved to an `Int`.
///
/// So this does not implement "the key CloudFormation sees" in general, and claiming it did was too
/// strong. YAML 1.2 core reads `0755` as decimal 755; this loader keeps the literal instead, because
/// 1.1 reads the same characters as octal 493 and resolving either way silently produces a number the
/// author did not write. The key inherits that trade rather than contradicting it: `0755` compares as
/// the string "0755" as a value and looks up as "0755" as a key, which is the property a rule author
/// needs. The departure from 1.2 core is `resolve_int`'s, deliberate, and recorded there.
///
/// A float keeps a fractional part when it is whole, so `1.0` is "1.0" rather than Rust's "1". That is
/// what a YAML-to-JSON conversion produces and what `PathAwareValue`'s own `serde_json` rendering
/// produces, so `-o json` and `-o yaml` print the value `1.0` beside the key `"1.0"`.
///
/// One renderer disagrees, and it is not this one: `display::ValueOnlyDisplay` formats a float with
/// Rust's `Display`, so the human text report prints `Value = {"v":1,"Mappings":{"1.0":...}}` -- a
/// reader who takes the key spelling from that line writes `Mappings."1"` and gets nothing. Left
/// alone here on measurement rather than on principle: whole-float *values* number 6 across both
/// corpora (2 in this repository, 4 in one registry test spec) and non-string *keys* 0, so changing
/// the report's float rendering would alter human output in the reporters' code to fix a collision no
/// file in either corpus can reach.
///
/// `Null` is deliberately absent. There is no text the two conventions agree on -- Python's
/// yaml-then-json round trip gives "null", JSON has no such key at all -- and a document writing `~:`
/// or a bare `:` is far more likely to have lost a key than to want one named after nothing, so the
/// refusal is the more useful answer. The container and `BadValue` keys are absent for the stronger
/// reason that they have no scalar text to render.
///
/// `values::scalar_key_name` is the serde-backed loader's half of this, and
/// `both_loaders_resolve_the_same_document_to_the_same_value` holds the two to the same rendering.
fn stringify_scalar_key(key: &MarkedValue) -> Option<String> {
    match key {
        MarkedValue::Int(i, ..) => Some(i.to_string()),
        MarkedValue::Bool(b, ..) => Some(b.to_string()),
        MarkedValue::Float(f, ..) if f.fract() == 0.0 && f.is_finite() => Some(format!("{f:.1}")),
        MarkedValue::Float(f, ..) => Some(f.to_string()),
        _ => None,
    }
}

/// Names the type of a key that is not a string, and its value where it has a short one.
///
/// The refusal used to carry the location and nothing else, which in a run over a directory of
/// templates tells the reader neither which key nor -- since the location is all it has -- which of
/// several thousand lines in which of N files. The location alone also cannot be searched for: a
/// reader who sees `L:2,C:4` cannot grep for it.
///
/// Only the keys `stringify_scalar_key` has no text for reach this, so in practice it names a null, a
/// sequence, a mapping or a `BadValue`. The value is still rendered for the scalars it has one for,
/// because the enum is total and a variant added to `MarkedValue` should not silently lose its name.
///
/// This used to carry the opposite position -- that rendering a resolved value would "invent a name the
/// document does not contain", so non-string keys could not be accepted without carrying the source
/// text through the value model. `stringify_scalar_key` reversed that and gives the reasons; the two
/// comments sat twenty lines apart contradicting each other, with this one the stale half and the one
/// the compiler sends a reader chasing the refusal message to.
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

/// What the stream holds after the document already in hand.
enum Remaining {
    /// Nothing but separators. Every document from the second onwards holds only the empty node, so
    /// there is one document in the file however many `---` lines it carries.
    Separators,
    /// A document with something in it, so the file really is a stream.
    Documents {
        /// How many documents hold something, the one in hand included.
        count: usize,
        /// False when libyaml stopped early, making `count` a lower bound.
        exact: bool,
        /// Where the *second* document that holds something starts.
        at: Location,
    },
}

/// Counts the documents that hold something, from the second `DocumentStart` onwards.
///
/// The refusal is worth more if it says what the tool saw, because "more than one" leaves the reader
/// to find out whether they have two documents or twenty. Counting means draining the rest of the
/// stream, and the rest of the stream may not parse -- a file whose *later* document is not YAML is
/// one of the shapes this refusal exists for -- so the count is reported as a lower bound when
/// libyaml stops early. Returning "at least n" is better than either abandoning the count or
/// replacing a message about document structure with a syntax error from further down the file.
///
/// A document holding only the empty node is not counted, and is why this returns
/// [`Remaining::Separators`] rather than a count of zero further documents. libyaml emits a full
/// document for a bare `---`, so counting every `DocumentStart` made a file of one template plus a
/// trailing `---` "hold 2" -- a count wrong by one, attached to advice that cannot be carried out,
/// because there is nothing at the `---` to split into a second file. A trailing separator is what a
/// generator or a concatenation leaves behind.
///
/// The position reported is the start of the second document that holds something, which is not
/// necessarily the second `DocumentStart`: `a\n---\n---\nb\n` has an empty document between the two
/// real ones.
///
/// Called only with a document in hand that holds something, which is what makes the count start at 1
/// rather than at 0. `load` will not call this for an empty document in hand; when it did, the same
/// off-by-one this function exists to prevent came back at the other end of the file -- a leading
/// separator pair made a one-document file "hold 2".
fn count_remaining_documents(parser: &mut Parser, second: Location) -> Remaining {
    // The document the caller already holds, which holds something; see above.
    let mut documents = 1;
    let mut first_with_content: Option<Location> = None;
    // The document being scanned: where it started, how many events it has held, and whether any of
    // them was something other than the empty node.
    let mut start = second;
    let mut events = 0;
    let mut empty = true;

    loop {
        match parser.next() {
            Ok((Event::DocumentStart, location)) => {
                start = location;
                events = 0;
                empty = true;
            }
            Ok((Event::DocumentEnd, _)) => {
                if !empty {
                    documents += 1;
                    first_with_content = first_with_content.or(Some(start));
                }
                events = 0;
                empty = true;
            }
            Ok((Event::StreamEnd, _)) => {
                return match first_with_content {
                    None => Remaining::Separators,
                    Some(at) => Remaining::Documents {
                        count: documents,
                        exact: true,
                        at,
                    },
                }
            }
            // The empty node, and only as a document's sole event -- a document whose *first* event
            // is an empty scalar and whose second is anything else holds something.
            Ok((Event::Scalar(scalar), _)) if events == 0 && is_empty_node(&scalar) => events += 1,
            Ok(_) => {
                events += 1;
                empty = false;
            }
            Err(_) => {
                let partial = usize::from(!empty);

                return Remaining::Documents {
                    // At least the one in hand, the second the caller was told about, and any
                    // complete one the scan reached.
                    count: (documents + partial).max(2),
                    exact: false,
                    at: first_with_content.unwrap_or(start),
                };
            }
        }
    }
}

/// Whether a scalar event is YAML's empty node: no tag, plain style, no characters.
///
/// This is what libyaml emits for a `---` with nothing after it, and for a key written with nothing
/// after the colon. Deliberately narrower than the set `handle_scalar_event` resolves to
/// `MarkedValue::Null`, which also holds `~` and `null`: those are written, so a document containing
/// one holds something, and only a document containing *nothing* is a separator.
fn is_empty_node(scalar: &Scalar) -> bool {
    scalar.tag.is_none() && scalar.style == ScalarStyle::Plain && scalar.value.is_empty()
}

/// Whether a float literal reached zero only because it was too small to represent.
///
/// `f64::from_str` signals overflow by returning an infinity, which `is_finite` catches. It signals
/// underflow by returning zero and saying nothing, so `1e-400` and `0` are indistinguishable by
/// value: the scalar the author wrote as a small positive number answered `== 0` with a PASS while
/// `> 0` failed. The overflow at the other end of the same exponent range already refused, so the
/// two ends of one rule disagreed.
///
/// The discriminator is the mantissa, not the whole literal. A zero result is genuine when every
/// significant digit is zero -- `0`, `0.0`, `-0.0`, `0.000` -- and an underflow when one of them is
/// not. The exponent has to be excluded from the test, or `0e400` would be read as an underflow on
/// account of the `4`.
fn underflowed_to_zero(literal: &str, parsed: f64) -> bool {
    if parsed != 0.0 {
        return false;
    }

    let mantissa = literal
        .split_once(['e', 'E'])
        .map_or(literal, |(mantissa, _)| mantissa);

    mantissa.chars().any(|c| c.is_ascii_digit() && c != '0')
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

/// Wraps a `!Foo`-tagged scalar as `{ "Fn::Foo": payload }`.
///
/// This used to consult `SINGLE_VALUE_FUNC_REF` and, on a miss, discard the tag and keep only the
/// payload. So the short form of any intrinsic the set did not list became something else entirely:
/// `!Transform { ... }` was indistinguishable from a plain mapping and a rule forbidding the macro
/// passed at exit 0, where the long `Fn::Transform` spelling of the same template failed. That is the
/// opposite of how `!!`-tags behave -- `!!int abc` becomes a `BadValue` and is reported -- so a bad
/// type tag was loud and an unknown function tag was silent.
///
/// Every `!Foo` is wrapped now, and `long_form_of` supplies the name. The two hand-written sets no
/// longer gate this, which also removes the position trap they created: `GetAtt` was in both sets but
/// `GetAZs` was in only the scalar one and `Select` in only the sequence one, so a name used in the
/// other position lost its tag even though the loader knew it.
fn wrap_tagged_scalar(val: String, loc: Location, short: &str) -> MarkedValue {
    let mut map = indexmap::IndexMap::new();
    let payload = if short == "GetAtt" {
        getatt_payload(val, &loc)
    } else {
        MarkedValue::String(val, loc.clone())
    };
    map.insert((long_form_of(short).into_owned(), loc.clone()), payload);

    MarkedValue::Map(map, loc)
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

/// The wrapper a `!Foo`-tagged sequence or mapping is nested under.
///
/// The payload is a placeholder: the container is still being read when this is pushed, and
/// `close_tagged_container` replaces the entry once it closes. `fn_ref` is the long name, already
/// resolved by the caller.
fn tagged_container_wrapper(loc: Location, fn_ref: &str) -> MarkedValue {
    let mut map = indexmap::IndexMap::new();
    map.insert(
        (fn_ref.to_string(), loc.clone()),
        MarkedValue::Null(loc.clone()),
    );

    MarkedValue::Map(map, loc)
}

fn handle_type_ref(val: String, loc: Location, type_ref: &str) -> MarkedValue {
    match type_ref {
        // Through the same set as a plain scalar, and refused when the payload is outside it.
        //
        // This read `str::parse::<bool>`, which takes `true` and `false` and nothing else, so an
        // explicit tag was stricter than the untagged resolution it should have agreed with. Moving
        // it to `parse_bool` fixed that half but left the other one: a payload outside the set fell
        // back to a *string*, which is the one answer that neither reads the node as the boolean the
        // author asked for nor says it could not be read as one. `!!bool yes` became the string
        // "yes", silently, where `!!int abc` next door is a loud `BadValue`.
        //
        // Measured, `serde_yaml` -- the loader `guard test` and the public `run_checks` reach on the
        // same bytes -- accepts exactly these six spellings under `!!bool` and refuses every other
        // payload outright, `y`, `on`, `off`, `no`, `0`, `1` and `tRuE` included. So refusing here is
        // what makes the two agree. PyYAML errors on an out-of-set payload too, though it takes the
        // YAML 1.1 words: it is a 1.1 implementation, and following it would put the boolean
        // vocabulary of a document under the control of whether a tag was written.
        "tag:yaml.org,2002:bool" => match parse_bool(&val) {
            None => MarkedValue::BadValue(val, loc),
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
