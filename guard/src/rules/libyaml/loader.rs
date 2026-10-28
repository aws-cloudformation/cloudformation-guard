use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use crate::rules::{
    self,
    errors::{Error, InternalError::InvalidKeyType},
    libyaml::{
        event::{Anchor, Event, MappingStart, Scalar, ScalarStyle, SequenceStart},
        parser::Parser,
        tag::Tag,
    },
    long_form_of,
    path_value::{KeyCollisions, Location},
    values::{BadValueReason, LeadingZeroReadings, MarkedValue},
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
/// `a_document_nested_past_the_limit_is_refused` in `loader_tests.rs` records the crash and the placement
/// rationale. Read it as a note rather than a pinned claim: its cases assert the boundary and the error kind,
/// and none of them fails if that prose is wrong, because the deep cases are refused at this bound and so no
/// test here ever runs the conversion.
///
/// Two properties of the bound are not visible from there. Unlike the parser's half of this bound, whose
/// unoptimized stack ceiling sits *below* its 128, nothing here is refused by a stack before the count
/// refuses it. `load` is iterative; the recursion is in what happens to a loaded value afterwards -- the
/// conversion, `MarkedValue`'s own drop glue, `Traversal::from`, and every derived `Debug` and `Clone` on the
/// tree. And depth was expensive well before it was fatal, from costs a bound caps together: the path stored
/// at every node, which grows with the square of the depth, and a `format!` in `Traversal::at` rendering a
/// `BTreeMap` range that `CfnAware::report_eval` then discards, which grows faster still. Neither is fixed;
/// the bound is what keeps either from mattering, because every factor they scale with scales with depth. A
/// wide, shallow document is cheap for the same reason -- though a document both wide *and* deep is not
/// covered by that argument. Any figure quoted for these must carry its profile and its host, and say how
/// loaded that host was -- an unlabeled release figure in the parser's half hid a `cargo test` that aborted
/// on three CI platforms.
///
/// If you go measure any of it: the cost at the bound is visible on the stock binary, the crash needs this
/// constant raised, the corpus depths below need it lowered, and the serde boundary does not depend on this
/// constant at all. Bisect an explicit `stack_size` at a fixed depth rather than the depth at a fixed stack.
/// And do not chase either cost from here.
///
/// Raising this constant above the deep cases in that test does not just fail them. They load successfully,
/// fail their assertion, and then render the loaded value with `{:?}` to build the failure message; derived
/// `Debug` on `MarkedValue` recurses once per level, so that render overflows the test thread and aborts the
/// whole target instead of reporting a failed assertion. The recursive drop of the same value would do it
/// too, if the render did not get there first. The parser's half documents the same hazard for its own
/// invited experiment.
///
/// **Why 128.** It is the limit serde enforced on the other loader in this product while that loader read
/// user input. The same number, counted over different documents, so they did not both accept and refuse the
/// same one. This bound counts the containers in the document: `a:` plus 127 `[` is 128 levels and loads,
/// 128 `[` is refused. A `test` spec is read through this loader too now, and its `input:` block sits under
/// two containers -- the sequence of cases and the case mapping -- so the deepest `input:` payload accepted
/// is 126 and 127 is refused, which is the figure serde's own limit gave the same spec. One document shows
/// both halves: `a:` plus 127 `[` is accepted as a `--data` file and refused as that same text under an
/// `input:` key. Not `rulegen`, which is no longer a second witness: `load_template` reads through this
/// loader now, so its agreement is tautological.
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
/// A non-recursive conversion was the alternative. It would remove the crash, but not the quadratic bytes,
/// and not the `PathAwareValue::clone` that `validate` takes of every data file before evaluating it -- once
/// for the file and again for the scope root -- which copies every node's path on a passing run as much as on
/// a failing one. Both are inherent to storing a full path at every node, and both reach into `Path`,
/// `PathAwareValue` and every reporter that prints one. It would not touch the `Traversal::at` waste at all,
/// because a discarded `{:?}` of a `BTreeMap` range is not a property of the path representation and is
/// removable on its own terms. A bound caps all of them, in the loader, and leaves either refactor free to
/// happen separately.
const MAX_NESTING_DEPTH: usize = 128;

/// How many nodes one document may copy through anchors and aliases.
///
/// An alias is resolved by copying the finished node its anchor named, so the copies have to be
/// bounded: a chain of anchors that each alias the one before them ten times is a million-fold
/// expansion of ten scalars after six levels, which is the billion-laughs shape. Every copy is counted
/// against this budget before it is made, and the refusal names the alias that crossed the line.
///
/// The budget counts the copies aliases make, and nothing else. Recording an anchor clones the
/// anchored node into the anchor table so that a later alias has a finished node to copy, and that
/// clone is not charged: an anchor nothing aliases is not a copy of anything the document evaluates,
/// so a template whose anchored content is larger than the budget loads as long as nothing aliases
/// it, and its first alias is the first copy charged. What the anchor table holds is bounded on its
/// own: nested anchors (`&a [&b [&c [...]]]`) clone each subtree once per enclosing anchor, so a
/// document with no alias at all could make the loader hold up to `MAX_NESTING_DEPTH` copies of its
/// content while it reads, and a 70 KiB file of a hundred nested anchors around a thousand aliases of
/// a 64 KiB scalar would have held 6.4 GiB. The anchors a document declares may hold together at most
/// this budget plus the input's length in nodes, and [`MAX_ALIAS_EXPANSION_BYTES`] plus the input's
/// length in bytes, over the whole document ([`Loader::record_anchor`]); an anchor that would take the
/// table past either is refused by name, like an alias past the budget. The input's length is in the
/// bound because a document with no nesting holds each anchored node once, which is never more than
/// the document itself. A node is more than a count: a scalar is one node whatever its length, so the
/// node budget alone let a 64 KiB string aliased a million times stay inside it while the copies came
/// to 64 GiB. The bytes of scalar text and key names copied are bounded separately by
/// [`MAX_ALIAS_EXPANSION_BYTES`], a key's bytes charged once for every node under it, so what a
/// document can take through aliases is at most this many nodes and that many bytes on top of the
/// document itself.
///
/// What the budget is spent over is the loader's [`BudgetScope`]. A data file is one document and
/// spends one budget whatever its root is: a JSON array handed to `validate` or to the library entry
/// point is a document of N items, not N documents. A `test` spec file is a sequence of cases, and a
/// suite shares one template by anchoring it in the first case and aliasing it in the rest, so a
/// budget counted over the whole file made the number of cases the limit: a 10,000-node input
/// anchored once and aliased by a hundred cases crossed this budget at the hundredth, that case
/// alone was reported unreadable, and which case failed moved when the cases were reordered. The
/// spec loader resets both counts each time an item of the root sequence is finished
/// (`reset_budget_at_top_level_item_boundary`); the anchor table and [`MAX_NESTING_DEPTH`] stay per
/// document, because an item may alias what an earlier item anchored and a copy's depth is a
/// property of where it lands. The billion-laughs chain inside one case is stopped where it was,
/// with the same message, which names the case as what the budget is spent over.
///
/// A budget that resets is not a bound on the file: N cases that each alias a chain's fifth level
/// nine times are N million nodes from a few hundred bytes a case, every case inside its own budget.
/// So a second bound covers the whole document and nothing resets it: at most
/// [`MAX_ALIAS_EXPANSION_NODES_PER_EVENT`] copied nodes for every event libyaml has parsed of the
/// document so far, and [`MAX_ALIAS_EXPANSION_BYTES_PER_INPUT_BYTE`] copied bytes for every byte of
/// the input, never fewer than the figures here. A document of a few hundred events copies at most one
/// case's budget in all, however many cases it holds, and a larger one at most a thousand nodes per
/// event. The refusal names the ceiling and says that it does not reset.
///
/// A spec file in AWS's own rules registry shares a template of a few hundred nodes across a few tens
/// of cases, so real suites sit three orders of magnitude under either figure.
const MAX_ALIAS_EXPANSION_NODES: usize = 1_000_000;

/// How many bytes of scalar text and key names one document may copy through anchors and aliases;
/// the other half of [`MAX_ALIAS_EXPANSION_NODES`]. 64 MiB: a 64 KiB scalar may be copied a thousand
/// times, a 1 MiB one sixty-four, and a registry suite that shares a template of a few kilobytes
/// across tens of cases uses a few hundredths of a percent of it.
///
/// A mapping key's bytes count once for every node under the key, not once per copy, because that is
/// how many times the converted document carries them: `PathAwareValue` stores a full path at every
/// node, so a 1,000-byte key over a hundred nodes is a hundred thousand bytes of path once the copy
/// is converted. Charged once per copy, a hundred nested mappings with one such key each were 100 KB
/// to this budget and about 670 aliases of them fit, which converted to gigabytes of path strings in
/// a caller that converts the result, and the promise above, that a document takes at most this many
/// bytes on top of itself, did not hold. Charged per descendant, the same shape is 5,150,000 bytes a
/// copy and thirteen copies fit.
const MAX_ALIAS_EXPANSION_BYTES: usize = 64 * 1024 * 1024;

/// The ceiling over the whole document on nodes copied through anchors and aliases: at most this many
/// for every event of the input other than an alias, or [`MAX_ALIAS_EXPANSION_NODES`], whichever is
/// more. Nothing resets it; see [`MAX_ALIAS_EXPANSION_NODES`] for why a per-case budget needs it.
///
/// Events rather than bytes, because the count of events does not change with layout: the same suite
/// written in flow style is a third of the bytes and the same events, and a bound in bytes would let a
/// formatter that compacts YAML turn a passing suite into a failing one.
///
/// The events are counted over the whole input in a parse-only pass ([`count_ceiling_events`]), so
/// the ceiling is one number for the file and every alias is held to it wherever it sits: a count
/// taken as the document is read gives an alias near the top of a file a lower ceiling than the same
/// alias near the bottom, and the order of the cases decides which load, which is what the per-case
/// budget exists to rule out. The pass runs only under [`BudgetScope::RootSequenceItem`], the one
/// scope where the ceiling can bind, and only once a copy is charged: under `BudgetScope::Document`
/// the budget and the ceiling count the same copies and the ceiling is never the lower of the two, so
/// a data file is parsed once, and a spec file with no alias is parsed once too. The pass is linear in
/// the input, which is small next to the copies it bounds.
///
/// Aliases are not counted. An alias is one event, and counting it raised the ceiling by a thousand
/// nodes for a copy that may be a thousand nodes, so an anchor of that size or less could be aliased
/// without limit and the ceiling never stopped it; `[*a, *a, *a, ...]` made its own room. What is
/// counted is what the text spells out: scalars and the starts and ends of sequences and mappings,
/// which an alias does not add to.
///
/// A thousand per event is set by the shape real suites take: a registry suite shares one input of
/// some ten thousand nodes across a hundred cases, and that input is itself written with aliases (a
/// row anchored once and aliased ninety-seven times), so the file is about 1,200 events other than
/// aliases and a million copied nodes, a factor of about 830; the billion-laughs flood is about a
/// hundred such events and is refused at the floor. No second bound in bytes sits beside this one: it
/// would bring back the layout dependence the event count removes.
///
/// This bounds the copies relative to the document's own size, which is what the per-case budget does
/// not. It is not an absolute cap: a document of a hundred thousand events may copy a hundred million
/// nodes, and the loaded document, the text's own nodes plus every copy, is what sits in memory,
/// because `load` builds the whole document before any caller reads a case off it.
const MAX_ALIAS_EXPANSION_NODES_PER_EVENT: usize = 1_000;

/// The ceiling over the whole document on bytes of scalar text and key names copied through anchors
/// and aliases: at most this many for every byte of the input, or [`MAX_ALIAS_EXPANSION_BYTES`],
/// whichever is more. Nothing resets it. The bytes a copy holds are the bytes the text wrote, so the
/// input's length is the right measure here, where for nodes it is not.
const MAX_ALIAS_EXPANSION_BYTES_PER_INPUT_BYTE: usize = 100;

/// What the expansion budget is spent over; see [`MAX_ALIAS_EXPANSION_NODES`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BudgetScope {
    /// One budget for the document, whatever its root is. The data-file loader.
    #[default]
    Document,
    /// The budget starts over each time an item of the root sequence is finished, so each `test`
    /// case has the whole of it. A document whose root is not a sequence keeps one budget. The spec
    /// loader, chosen in [`Loader::for_spec_file`].
    RootSequenceItem,
}

/// What the loader does with a node it refuses inside a document that otherwise reads: a mapping whose
/// key is null or a sequence, a merge key given a scalar, an alias to a name no earlier node anchors,
/// a copy that would cross the expansion budget, or a sequence or mapping tagged with an intrinsic's
/// name under `!!` (`!!If [IsProd, a, b]`, a typo of `!If`).
///
/// A data file is refused whole, because `validate` evaluates one document and a document it cannot
/// read in full is not one it can report on. A `test` spec file is a sequence of cases, each with its
/// own `input:`, and a case the author got wrong is that case's mistake: under `MarkBadValue` the
/// refused node is replaced by a `MarkedValue::Refused` carrying the refusal, the conversion of that
/// one `input:` fails with it, and the other cases keep their verdicts. The refusals that make the
/// document itself unreadable -- nesting past `MAX_NESTING_DEPTH`, whether written inline or reached
/// through an alias, and a second document in the file -- are not nodes and are refused under both
/// policies.
///
/// The marker is its own variant and not `MarkedValue::BadValue`, which `handle_type_ref` writes for
/// a `!!int`, `!!float` or `!!bool` whose payload is not one. That mark carries the scalar's own
/// text, and when the two shared a variant a `<<: !!int abc` was refused as "abc", the text forwarded
/// as though it were a refusal, where a plain `<<: abc` says the merge key must be given a mapping.
/// `fill_mapping` and `apply_merges` forward a `Refused` node's message and give a `BadValue` the key
/// and merge refusals every other scalar gets.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RefusalPolicy {
    /// Refuse the document at the first such node.
    #[default]
    RefuseDocument,
    /// Replace the refused node with a `MarkedValue::Refused` holding the refusal's message and read
    /// on.
    MarkBadValue,
}

/// Why an alias could not be resolved, and what it costs: the node, or the document.
enum AliasRefusal {
    /// The alias alone cannot be resolved, so `RefusalPolicy` decides what it costs: an anchor no
    /// earlier node declares, or a copy past the budget or the ceiling.
    Node(String),
    /// The copy would nest past `MAX_NESTING_DEPTH`. The bound is the document's, as it is for a
    /// container written inline, so the document is refused under both policies: a `MarkedValue`
    /// nested past it is the thing the bound exists to keep from being built, whichever node asked.
    Document(String),
}

/// What a load cost, in units the loader counts for itself. Test-only: the width test in
/// `loader_tests` asserts all three counts exactly for documents of known shape, the index visits
/// (`index_visits`), the scalars the kept-literal index received (`kept_literals_recorded`) and the
/// key forms recorded (`forms_recorded`), which a clock cannot say on one machine. The cost of taking
/// a closed mapping's entries is not counted: the type `fill_mapping` takes them through rules out a
/// shifting take from the storage itself, and a consumer that copied them out first would not be
/// caught by any count here (see `fill_mapping`). The writes `fill_mapping` makes into the map are
/// counted (`map_changes`, `map_rebuilds`), so a loader that moved an entry on every repeat, the
/// quadratic shape a mapping of anchored keys and their aliases once had, reads over its distinct-key
/// count in the ordering rows.
#[cfg(test)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Work {
    /// Entries of `merge_key_index` and `kept_literal_index` visited: popped by
    /// `forget_scalars_above`, or read by `handle_mapping_end` to find a closing mapping's own
    /// scalars. Linear in the document when both walks stop at the closing container's slot;
    /// quadratic when either scans the whole index on every close.
    pub(crate) index_visits: usize,
    /// Scalars `handle_scalar_event` recorded in `kept_literal_index`, and the copies of them aliases
    /// pushed. The width test asserts it so that the shape meant to exercise that index is known to
    /// have filled it.
    pub(crate) kept_literals_recorded: usize,
    /// Positions `handle_mapping_end` added to `key_forms`: only the forms that are not `Text`, so a
    /// document whose keys are all strings records none, and only positions seen for the first time.
    /// An alias's copy keeps the anchor's position, so whichever of the anchored key and its copies
    /// closes first records the position and the rest add nothing, in whatever mapping each sits. It
    /// counts the map's growth, not the keys of a form other than `Text`.
    pub(crate) forms_recorded: usize,
    /// Writes `fill_mapping` made to the maps it filled: one per key the document wrote (a repeat is one
    /// write, replacing its value in place), plus one per entry put back by a rebuild (`map_rebuilds`).
    /// A mapping whose document writes N keys costs exactly N unless a repeat moves an entry; a loader
    /// that removed and re-inserted an entry on every repeat would count two more per repeat, which is
    /// how the ordering rows in `loader_tests` keep that shape from coming back.
    pub(crate) map_changes: usize,
    /// Mappings `fill_mapping` rebuilt in last-write order because a repeat had to move an entry to
    /// the end (a plain spelling of the name was written after the entry's slot). A mapping with no
    /// repeat, and one whose repeats all replace in place, costs none.
    pub(crate) map_rebuilds: usize,
}

/// What filling one mapping cost, returned by `fill_mapping` for `Work`.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
struct FillWork {
    /// Writes into the map: one per key the document wrote, plus one per entry a rebuild put back.
    changes: usize,
    /// One when the map was rebuilt in last-write order, else none.
    rebuilds: usize,
}

#[derive(Debug, Default)]
pub struct Loader {
    /// The work this loader has done, for the width tests. See `Work`.
    #[cfg(test)]
    pub(crate) work: Work,
    stack: Vec<MarkedValue>,
    last_container_index: Vec<usize>,
    func_support_index: Vec<(usize, (String, Location))>,
    /// Containers the loader will not model because of the `!!` tag written on them, by the stack
    /// index each occupies while it is open, each with the refusal's message. Only ever filled under
    /// `RefusalPolicy::MarkBadValue`: `push_tag_wrapper` records the refusal when the container opens,
    /// and `refuse_pending_tag` applies it once the container has closed, so the document reads on and
    /// a `Refused` node stands where the container was. Under `RefuseDocument` the refusal is returned
    /// where it is found and nothing is recorded. In stack order, as `func_support_index` is, so the
    /// container closing is always the last entry if it has one.
    ///
    /// The refusal is applied when the container closes, so everything written inside it is read
    /// first: its mappings are filled and merged, the aliases in it are charged to the expansion budget
    /// and to the document's ceiling, and the anchors declared in it stay in the anchor table for later
    /// aliases, exactly as inside a mapping `fill_mapping` refuses. The contents are then dropped with
    /// the container. Nothing skips the events of a refused container.
    pending_tag_refusals: Vec<(usize, String)>,
    refusals: RefusalPolicy,
    /// The source text of every scalar resolved to an integer, a float or a boolean, by position,
    /// when the caller asked for it. The loader resolves a plain scalar as it reads it and
    /// `MarkedValue` keeps no spelling, so `1.50` and `1.5` are the same `Float` by the time a
    /// `test` spec's case name is read off the document; this is how that command gets the
    /// spelling back without a second reading of the file. `None` means not recording, which is the
    /// data-file loader: nothing there reads a scalar's spelling.
    scalar_texts: Option<HashMap<Location, String>>,
    /// Finished anchored nodes of the document in hand, by anchor name, for `Event::Alias`, each with
    /// its `Size` as measured when it was recorded and what the scalar handler knew about it (see
    /// `Anchored` and `ScalarFacts`).
    ///
    /// Every route resolves aliases, within the budget: a template under `validate` or `rulegen`, a
    /// `test` spec file, and the data handed to the library entry point `run_checks`. One policy on
    /// every route is what keeps a spec from proving a rule against a document the template route
    /// would not read, and CloudFormation's own YAML reader resolves aliases too, so a template that
    /// uses one is evaluated as the document CloudFormation will see.
    ///
    /// The size is kept so that `resolve_alias` can check the depth and the budget without walking
    /// the node, and clone it only once the charge is accepted: an alias the budget refuses then costs
    /// nothing but its message, however large the anchored node.
    ///
    /// A name anchored twice keeps the later node, which is what an alias after the second anchor
    /// refers to under YAML's rules; an alias between the two saw the first.
    anchors: HashMap<String, Anchored>,
    /// The nodes and the bytes the anchor table holds, summed over its entries, which `record_anchor`
    /// bounds at the budget plus the input's length ([`MAX_ALIAS_EXPANSION_NODES`]) over the whole
    /// document: nested anchors hold their content once per enclosing anchor, and the table is memory
    /// the loader holds while it reads, which no alias budget counts. Reset with the table.
    anchored_nodes: usize,
    anchored_bytes: usize,
    /// Stack indices of the open containers that carry an anchor, with the anchor's name, so the
    /// container can be recorded under its name once it is finished.
    anchor_index: Vec<(usize, String)>,
    /// Nodes copied through anchors and aliases so far in the document in hand, and the bytes of
    /// scalar text and key names those copies held, within the `budget` scope: reset at every item
    /// of the root sequence under `BudgetScope::RootSequenceItem`.
    expanded: usize,
    expanded_bytes: usize,
    budget: BudgetScope,
    /// The same two counts over the whole document, which no item resets, and what their ceiling is
    /// measured against: the input's events other than aliases, for the nodes
    /// ([`MAX_ALIAS_EXPANSION_NODES_PER_EVENT`]), counted once at the first charge under
    /// `BudgetScope::RootSequenceItem` and `None` until then, and the input's length, for the bytes
    /// ([`MAX_ALIAS_EXPANSION_BYTES_PER_INPUT_BYTE`]). `input` is the text being loaded, kept for
    /// that count; `load` sets both.
    expanded_in_document: usize,
    expanded_bytes_in_document: usize,
    ceiling_events: Option<usize>,
    input_bytes: usize,
    input: Option<Rc<str>>,
    /// How many times the loader has run libyaml over the input, for the test that pins one parse per
    /// data-file load and at most two per spec load.
    #[cfg(test)]
    pub(super) parses: usize,
    /// How many times the alias machinery cloned a node, and how many times it measured one, for the
    /// tests that pin that a refused alias costs neither: the anchored node's size is read from the
    /// anchor table and the clone is made only once the charge is accepted.
    #[cfg(test)]
    pub(super) copies_made: usize,
    #[cfg(test)]
    pub(super) nodes_measured: usize,
    /// Stack indices of the scalars that are merge keys, recorded by `handle_scalar_event`.
    ///
    /// The merge type is resolved from the **plain** scalar only: `tag:yaml.org,2002:merge` is an
    /// implicit resolution, and implicit resolution applies to the plain style. So `"<<"` is an
    /// ordinary key whose name happens to be `<<`, which is the documented way to write one. The
    /// explicit tag is the exception: `!!merge <<` is the type said out loud and is a merge key in any
    /// style.
    ///
    /// It has to be recorded here because the style is gone by `handle_mapping_end`: a non-plain
    /// scalar becomes `MarkedValue::String` and so does a plain `<<`, so both spellings arrive there
    /// as the same `String("<<")` and testing the resolved name cannot tell them apart. An alias's copy
    /// of an anchored merge key goes in it too (`handle_alias_event`, from `ScalarFacts`): it is the
    /// same merge-typed node, and left out it was an ordinary key named `<<` hiding the merged mapping.
    merge_key_index: Vec<usize>,
    /// Stack indices of the plain scalars this loader kept as text though YAML would resolve them (see
    /// `KeyForm::Literal`), recorded by `handle_scalar_event` for the same reason as `merge_key_index`:
    /// by `handle_mapping_end` a kept `.Inf` and a quoted `".Inf"` are both `MarkedValue::String`, and
    /// which one was the literal is what tells a same-key override from a collision when a merged key
    /// reads as a held one (see `apply_merges`). Only kept literals go in it, never quoted or
    /// resolved scalars, and a copy an alias pushes of an anchored kept literal goes in it too
    /// (`handle_alias_event`): the alias is the literal, so as a key it is of the literal's form
    /// wherever the anchor was written. Recording the written scalar alone left the copy to be read
    /// as text unless the anchor happened to be a key of a mapping that had already closed, whose
    /// form `key_forms` held at the position the copy shares with it, so one pair of keys collided
    /// or did not by the anchor's placement. In stack order, so a container close prunes it by popping
    /// from the end and a closing mapping finds its own entries by walking from the end; a scan of the
    /// whole index on every close made a document of N kept-literal keys whose values are mappings cost
    /// about N^2 / 2 visits.
    kept_literal_index: Vec<usize>,
    /// Stack indices of the copies aliases pushed, each with the alias's own position, recorded by
    /// `handle_alias_event`. A copy keeps its anchor's position, so a key an alias wrote has no position
    /// of its own in the loaded map; `handle_mapping_end` reads this index back by slot for the copies
    /// that are its keys and hands the sites to `fill_mapping`, which records them beside the entry
    /// (`KeyCollisions::add_key_write`) for the duplicate-key notice to name the line the author
    /// wrote the key at. In stack order, pruned and read like the two indices above; not counted in
    /// `Work::index_visits`, which pins the cost of those two.
    alias_key_index: Vec<(usize, Location)>,
    /// The form a mapping key was written in, by the key scalar's position, for every key whose form is
    /// not `Text`. The position names the scalar as written, not one entry: an alias copy of a mapping
    /// carries its keys at the anchored mapping's positions, and the copy's key has the same form, so
    /// one entry serves every copy. Filled by `handle_mapping_end` as it renders keys to text and
    /// read by `apply_merges`, which takes a missing entry as `Text` for a held key and a merged key
    /// alike, so a document whose keys are all strings records nothing. Cleared at `DocumentEnd`.
    key_forms: std::collections::HashMap<Location, KeyForm>,
    /// Merged keys that collided with a held key of another form, by the position of the mapping that
    /// merged and the held key's position (see `apply_merges` and `collisions`). The merged entry
    /// itself is dropped from the mapping, so this is the only record of the pair;
    /// `PathAwareValue::try_from_marked_reporting` turns it into the duplicate-key notice when its walk
    /// of the finished document reaches the held key in that mapping. A key written twice at one
    /// position, an anchored key beside an alias of it, is recorded here too, as its own kind of record
    /// (`KeyCollisions::add_key_write`, from `fill_mapping`, one record holding the repeat count and the
    /// aliases' sites): the map holds one entry for the pair, so the conversion's own duplicate
    /// detection never sees it.
    collisions: KeyCollisions,
    /// The `!!` tags this load read past without refusing, in document order. See [`UnreadTag`].
    ///
    /// Carried here, and handed to the caller by `take_warnings`, because library code writes nothing
    /// to the process's stderr: `validate` and `test` print these through the command writer beside
    /// the duplicate-key warnings, and the library entry points can expose them the same way they
    /// expose that list. An `eprintln!` here reached every caller's stderr, library callers included,
    /// and could not be captured, suppressed or carried in a report.
    warnings: Vec<UnreadTag>,
}

/// A `!!` tag the loader did not read and did not refuse: the node under it was loaded as if it had
/// no tag. One per tagged node, so three such nodes give three warnings, each carrying its own
/// position; that is what makes a line actionable in a file tagged throughout.
///
/// A tag from another YAML dialect's namespace, `!!python/name:x` say, is not a typo of anything
/// cfn-guard reads, and a `-d .` walk over a directory holding such a file should not stop on it, so it
/// is reported rather than refused. A tag that spells an intrinsic is refused instead (see
/// `looks_like_an_intrinsic_name`), and the yaml.org collection types say nothing.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct UnreadTag {
    /// The tag's suffix as the document wrote it, `python/name:x` for `!!python/name:x`.
    pub(crate) tag: String,
    pub(crate) location: Location,
}

impl UnreadTag {
    /// The warning line with the file named, which is the form `validate` and `test` print: a position
    /// alone identifies nothing to a reader of a run over several files. The tag is document text and
    /// the file name a path, so each is escaped as its kind is.
    pub(crate) fn in_file(&self, name: &str) -> String {
        crate::utils::writer::warning(format_args!(
            "cfn-guard does not read the YAML tag `!!{}` at {} in {}; the node is read as if it had \
             no tag.",
            crate::utils::writer::escaped_for_display(&self.tag),
            self.location,
            crate::utils::writer::escaped_controls_for_display(name)
        ))
    }
}

impl std::fmt::Display for UnreadTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&crate::utils::writer::warning(format_args!(
            "cfn-guard does not read the YAML tag `!!{}` at {}; the node is read as if it had no tag.",
            crate::utils::writer::escaped_for_display(&self.tag),
            self.location
        )))
    }
}

/// The kind a mapping key resolved to, which is what tells two keys that read as one name apart.
///
/// `1` and `"1"` both render to the key "1"; the loader keeps the last value for an explicit pair and
/// reports a duplicate. A merged key that reads as a held key is a same-key override when the two are
/// the same YAML key and a collision otherwise, and only the form can say which. Spelling is not form:
/// a plain `x`, a quoted `"x"` and a `!!str x` all resolve to the string and are one `Text` key, which
/// is how YAML compares them and how the serde conversion reads them.
///
/// `Literal` is the one form that is not a resolved kind: a plain scalar this loader kept as text
/// though YAML would resolve it, by `resolve_int`'s `OutOfRange` (an integer wider than `i64`) or by
/// the float resolver refusing it (`1e-400`, `1e400`, and the non-finite spellings `.inf`, `.Inf`,
/// `.INF` with an optional sign, `.nan`, `.NaN`, `.NAN`, matched exactly, so `.iNf` is a plain `Text`
/// key here as it is to YAML and to `serde_yaml`). `0755` is not one: `resolve_int` keeps a decimal
/// with a redundant leading zero as the string "0755" on purpose, which is what `serde_yaml` does
/// too, so it is an ordinary `Text` key and `0755` beside `"0755"` is a silent override on both
/// routes. Beside its quoted spelling a `Literal` key is a collision here, and the loader warns on it.
///
/// The serde conversion (`values::merge_into`, keyed by `values::KeyKind`) has no kept-literal form,
/// and what it does with the same pair differs by spelling. The four cases are kept here, once; the
/// comments on that side point to this list, and each row is measured in `values_tests`:
///
/// - `.inf`, and an integer in `(i64::MAX, u64::MAX]`: resolve and render as written, so the pair
///   is a number beside a string of one name and is refused there, as it warns here.
/// - `.Inf` and `1e-400`: resolve to floats rendered `.inf` and `0.0`, differently named keys, so
///   nothing collides there and this loader alone warns.
/// - `1e400`: stays a string there, a silent override; this loader alone warns.
/// - A key wider than `u64`: refused by `serde_yaml::from_str` before the conversion runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyForm {
    Text,
    Literal,
    Int,
    Float,
    Bool,
}

impl Loader {
    /// Hands over the `!!` tags this load read past (see [`UnreadTag`]), leaving the list empty.
    pub(crate) fn take_warnings(&mut self) -> Vec<UnreadTag> {
        std::mem::take(&mut self.warnings)
    }

    pub fn new() -> Loader {
        Loader::default()
    }

    /// A loader with the given refusal policy; `new` is `RefusalPolicy::RefuseDocument`.
    pub(crate) fn with_refusals(mut self, refusals: RefusalPolicy) -> Loader {
        self.refusals = refusals;
        self
    }

    /// A loader that records the source text of every integer, float and boolean scalar it resolves,
    /// for [`Loader::take_scalar_texts`]; `new` records nothing.
    pub(crate) fn recording_scalar_texts(mut self) -> Loader {
        self.scalar_texts = Some(HashMap::new());
        self
    }

    /// A loader that spends the expansion budget per item of the root sequence; `new` spends it per
    /// document. See [`BudgetScope`].
    pub(crate) fn spending_the_budget_per_root_item(mut self) -> Loader {
        self.budget = BudgetScope::RootSequenceItem;
        self
    }

    /// The loader a `test` spec file is read with: a refused node costing its own case, scalar
    /// spellings kept for case names, and the expansion budget spent per case rather than per
    /// document. `values::read_spec_from` is the one caller, and the three settings are named here so
    /// that a spec file and a data file differ in exactly these. Aliases are resolved on both, within
    /// the same budget.
    pub(crate) fn for_spec_file() -> Loader {
        Loader::new()
            .with_refusals(RefusalPolicy::MarkBadValue)
            .recording_scalar_texts()
            .spending_the_budget_per_root_item()
    }

    /// The source text of each integer, float and boolean scalar the last `load` resolved, by the
    /// scalar's position, when this loader records them; empty otherwise. An aliased copy keeps the
    /// anchored scalar's position, so it is found under the same entry.
    pub(crate) fn take_scalar_texts(&mut self) -> HashMap<Location, String> {
        self.scalar_texts
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    pub(crate) fn load(&mut self, content: String) -> rules::Result<MarkedValue> {
        let content: Rc<str> = Rc::from(content);
        self.input_bytes = content.len();
        self.input = Some(Rc::clone(&content));
        self.ceiling_events = None;
        self.expanded_in_document = 0;
        self.expanded_bytes_in_document = 0;
        #[cfg(test)]
        {
            self.parses += 1;
        }

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
                    // Returning at the first `DocumentEnd` would answer an n-document stream with
                    // the first document and say nothing: prefixing a template with a compliant
                    // document and a `---` would suppress every finding in the real one at exit 0.
                    // Worse, returning there drops the parser, so the bytes after the first document
                    // would never be handed to libyaml at all and a stream whose later document was
                    // not YAML would pass too.
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
                    // the ordinary way to get here. Treating it as a no-op would leave the loop
                    // pulling events past the end of the stream, where libyaml answers with
                    // `YAML_NO_EVENT`, which `convert_event` refuses.
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
                        self.pending_tag_refusals.clear();
                        self.merge_key_index.clear();
                        // Anchors are scoped to their document; so are the expansion budget and
                        // its ceiling. The scalar texts are not cleared: they belong to the one
                        // document that holds anything, and a second one that does is refused above.
                        self.anchors.clear();
                        self.anchored_nodes = 0;
                        self.anchored_bytes = 0;
                        self.anchor_index.clear();
                        self.expanded = 0;
                        self.expanded_bytes = 0;
                        self.expanded_in_document = 0;
                        self.expanded_bytes_in_document = 0;
                        self.kept_literal_index.clear();
                        self.alias_key_index.clear();
                        self.key_forms.clear();
                    }
                    Event::MappingStart(mapping_start) => {
                        self.enter_container(&location)?;
                        self.handle_mapping_start(mapping_start, location)?
                    }
                    Event::MappingEnd => self.handle_mapping_end()?,
                    Event::SequenceStart(sequence_start) => {
                        self.enter_container(&location)?;
                        self.handle_sequence_start(sequence_start, location)?
                    }
                    Event::SequenceEnd => self.handle_sequence_end()?,
                    Event::Scalar(scalar) => self.handle_scalar_event(scalar, location)?,
                    // The alias is replaced by a copy of the anchored node, on every route; see
                    // `handle_alias_event`, and the `anchors` field for why no route refuses one.
                    // What a refusal there says is an `UnsupportedDocument`, the variant for a
                    // construct the loader will not model in a document that parses, which
                    // `build_data_file` reports under the file's name with no excerpt; `ParseError`
                    // is libyaml's own failure, and means malformed text to the library's callers.
                    Event::Alias(anchor) => self.handle_alias_event(anchor, location)?,
                };
                self.reset_budget_at_top_level_item_boundary();
            };
        }
    }

    /// Resets the expansion budget when the event just handled finished an item of a root sequence,
    /// under `BudgetScope::RootSequenceItem`; see [`MAX_ALIAS_EXPANSION_NODES`] for why the spec
    /// loader spends the budget per item and the data-file loader does not.
    ///
    /// `last_container_index` holds one entry per open container, so exactly one entry means the
    /// only open container is the root, and the node the event finished -- a scalar, an alias's copy
    /// or its refusal, or a container that just closed, its anchor recorded -- was one of the root's
    /// items; or the root itself just opened, when there is nothing to reset. A root mapping's
    /// entries are not items, so a document whose root is a mapping keeps the budget for the whole
    /// document. Nothing is walked: two counters are zeroed. The counts over the whole document are
    /// not among them.
    fn reset_budget_at_top_level_item_boundary(&mut self) {
        if self.last_container_index.len() != 1 || !self.spends_the_budget_per_root_item() {
            return;
        }
        self.expanded = 0;
        self.expanded_bytes = 0;
    }

    /// Whether the document in hand has the budget reset at each item: the loader is a spec loader
    /// and the root container is a sequence. Asked at any depth, so a refusal inside an item can say
    /// what the budget is spent over.
    fn spends_the_budget_per_root_item(&self) -> bool {
        self.budget == BudgetScope::RootSequenceItem
            && self.last_container_index.first().map_or(false, |root| {
                matches!(self.stack[*root], MarkedValue::List(..))
            })
    }

    /// What the budget is spent over, for the refusal: the case, or the document.
    fn budget_words(&self) -> &'static str {
        if self.spends_the_budget_per_root_item() {
            "in one test case (one item of the root sequence)"
        } else {
            "in one document"
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

    /// Replaces a `*alias` with a copy of the node its anchor named.
    ///
    /// libyaml is a parser rather than a composer, so it hands over the alias event and checks
    /// nothing: an alias to a name no earlier node anchored is this function's to refuse, and so is
    /// the growth. The copy is bounded three ways before it is made, by `charge_copy` and here. Its
    /// node count and its bytes go against [`MAX_ALIAS_EXPANSION_NODES`] and
    /// [`MAX_ALIAS_EXPANSION_BYTES`] for the document, which is what stops an alias chain from growing
    /// by a factor per level and a long scalar from being copied without limit. Its container depth is
    /// added to the depth it is being copied into and held under [`MAX_NESTING_DEPTH`], because
    /// `enter_container` bounded the anchored node where it was written and a copy placed deeper would
    /// otherwise be the one deep `MarkedValue` that bound exists to keep from ever being built.
    ///
    /// The copy keeps the anchored node's positions. A finding inside an aliased input then points at
    /// the line the value is written on, which is where an author has to go to change it.
    ///
    /// A refusal here is usually a refusal of one node, so `RefusalPolicy` decides what it costs: the
    /// document, or a `Refused` node in the alias's place carrying the message. Under `MarkBadValue`
    /// a copy that crossed the budget is not charged, so every later alias of the same size is
    /// refused the same way rather than the budget being spent on refusals. That makes the cost of
    /// a refusal matter: `resolve_alias` reads the anchored node's size from the anchor table, where
    /// it was measured when the anchor was recorded, and clones nothing until the charge is accepted,
    /// so ten thousand refused aliases of a 111,111-node anchor are ten thousand messages and no
    /// copies. The depth refusal is the exception, and `AliasRefusal` says why: it costs the
    /// document under both policies.
    fn handle_alias_event(&mut self, anchor: Anchor, location: Location) -> rules::Result<()> {
        let name = anchor.name();
        match self.resolve_alias(&name, location) {
            Ok((copy, facts)) => {
                self.stack.push(copy);
                // The copy is the anchored scalar, so it is the merge key, or the kept literal, the
                // anchor is, as a key or as a value; see `merge_key_index` and `kept_literal_index`.
                // Both indices are by stack slot and the written scalar's slot names the written
                // scalar, not this copy, so the copy is recorded on its own. A `<<` the alias copies
                // is otherwise an ordinary key named `<<` with the merged mapping hidden under it.
                if facts.merge_key {
                    self.merge_key_index.push(self.stack.len() - 1);
                }
                if facts.kept_literal {
                    self.note_kept_literal();
                }
                // The alias's own position, which the copy does not carry: a copy keeps its anchor's.
                // If the copy turns out to be a key, the closing mapping reads it back by slot so the
                // duplicate-key record can name the line the key was written at (see `alias_key_index`).
                self.alias_key_index.push((self.stack.len() - 1, location));
            }
            Err(AliasRefusal::Node(refusal)) => {
                self.refuse_node(Error::UnsupportedDocument(refusal), location, None)?
            }
            Err(AliasRefusal::Document(refusal)) => {
                return Err(Error::UnsupportedDocument(refusal));
            }
        }
        Ok(())
    }

    /// The copy an alias stands for, with what the scalar handler knew about the anchored scalar (see
    /// `ScalarFacts`), or the refusal and what it costs.
    ///
    /// The depth and the budget are checked from the size recorded with the anchor, and the clone is
    /// made last, once the charge is accepted, so a refused copy is neither measured nor built: under
    /// `MarkBadValue`, where a refused copy is not charged, every alias after the budget is spent is
    /// refused the same way, and ten thousand of them cost ten thousand messages and no node walks.
    fn resolve_alias(
        &mut self,
        name: &str,
        location: Location,
    ) -> Result<(MarkedValue, ScalarFacts), AliasRefusal> {
        let Some(anchored) = self.anchors.get(name) else {
            return Err(AliasRefusal::Node(format!(
                "the alias `*{name}` at {location} names an anchor that no node before it declares. \
                 An alias refers back to an `&{name}` written earlier in the document."
            )));
        };
        let size = anchored.size;

        let depth_here = self.last_container_index.len();
        if depth_here + size.depth > MAX_NESTING_DEPTH {
            return Err(AliasRefusal::Document(format!(
                "cfn-guard reads documents nested at most {MAX_NESTING_DEPTH} levels deep, and the \
                 alias `*{name}` at {location} would place a node {} levels deep at level \
                 {depth_here}.",
                size.depth
            )));
        }

        self.charge_copy(&size, &format!("the alias `*{name}` at {location}"))
            .map_err(AliasRefusal::Node)?;
        #[cfg(test)]
        {
            self.copies_made += 1;
        }
        let anchored = &self.anchors[name];
        Ok((anchored.node.clone(), anchored.facts))
    }

    /// Counts a copy of `size` against the expansion budget and the document's ceiling, or says which
    /// bound it crossed.
    ///
    /// Every bound is checked before any is charged, so a refused copy costs nothing: under
    /// `RefusalPolicy::MarkBadValue` the loader reads on, and the budget has to still be there for
    /// the copies that fit. `what` names the alias or anchor for the message. The budget is checked
    /// first, so the ceiling's message appears only where the budget has been reset, which is the
    /// one situation it exists for.
    fn charge_copy(&mut self, size: &Size, what: &str) -> Result<(), String> {
        let scope = self.budget_words();
        let expanded = self.expanded + size.nodes;
        if expanded > MAX_ALIAS_EXPANSION_NODES {
            return Err(format!(
                "cfn-guard copies at most {MAX_ALIAS_EXPANSION_NODES} nodes through aliases {scope}, \
                 and {what} would take this one to {expanded}. A chain of anchors that each alias the \
                 one before them grows by a factor per level; anchor the shared value once and alias \
                 it directly."
            ));
        }
        let expanded_bytes = self.expanded_bytes + size.bytes;
        if expanded_bytes > MAX_ALIAS_EXPANSION_BYTES {
            return Err(format!(
                "cfn-guard copies at most {MAX_ALIAS_EXPANSION_BYTES} bytes of scalar text and key \
                 names through anchors and aliases {scope}, and {what} would take this one to \
                 {expanded_bytes} bytes. Every alias copies the anchored value whole, and a mapping \
                 key's bytes count once for every node under it; alias a large value fewer times, or \
                 write it out where it is used."
            ));
        }
        // The ceilings bind only where the budget resets. Under `BudgetScope::Document` the budget
        // and the ceiling count the same copies and the ceiling is never the lower bound, so neither
        // the count nor the checks run there.
        if self.budget != BudgetScope::RootSequenceItem {
            self.expanded = expanded;
            self.expanded_bytes = expanded_bytes;
            return Ok(());
        }
        let ceiling_events = match self.ceiling_events {
            Some(events) => events,
            None => {
                let events = count_ceiling_events(self.input.as_deref().map_or(b"", str::as_bytes));
                #[cfg(test)]
                {
                    self.parses += 1;
                }
                self.ceiling_events = Some(events);
                events
            }
        };
        let in_document = self.expanded_in_document + size.nodes;
        let node_ceiling = ceiling_events
            .saturating_mul(MAX_ALIAS_EXPANSION_NODES_PER_EVENT)
            .max(MAX_ALIAS_EXPANSION_NODES);
        if in_document > node_ceiling {
            return Err(format!(
                "cfn-guard copies at most {node_ceiling} nodes through aliases across the whole \
                 document ({MAX_ALIAS_EXPANSION_NODES_PER_EVENT} for each of its {} events other than \
                 aliases, and never fewer than {MAX_ALIAS_EXPANSION_NODES}), and {what} would take it \
                 to {in_document}. The budget of {MAX_ALIAS_EXPANSION_NODES} nodes is one test case's \
                 and starts over at each; this ceiling covers the whole document and does not. Anchor \
                 the shared value once and alias it fewer times.",
                ceiling_events
            ));
        }
        let bytes_in_document = self.expanded_bytes_in_document + size.bytes;
        let byte_ceiling = self
            .input_bytes
            .saturating_mul(MAX_ALIAS_EXPANSION_BYTES_PER_INPUT_BYTE)
            .max(MAX_ALIAS_EXPANSION_BYTES);
        if bytes_in_document > byte_ceiling {
            return Err(format!(
                "cfn-guard copies at most {byte_ceiling} bytes of scalar text and key names through \
                 anchors and aliases across the whole document \
                 ({MAX_ALIAS_EXPANSION_BYTES_PER_INPUT_BYTE} for each of its {} bytes, and never fewer \
                 than {MAX_ALIAS_EXPANSION_BYTES}), and {what} would take it to {bytes_in_document} \
                 bytes. The budget of {MAX_ALIAS_EXPANSION_BYTES} bytes is one test case's and starts \
                 over at each; this ceiling covers the whole document and does not. Alias a large value \
                 fewer times, or write it out where it is used.",
                self.input_bytes
            ));
        }
        self.expanded = expanded;
        self.expanded_bytes = expanded_bytes;
        self.expanded_in_document = in_document;
        self.expanded_bytes_in_document = bytes_in_document;
        Ok(())
    }

    /// Applies `RefusalPolicy` to a node the loader will not model: refuse the document with the
    /// error as it is, or put a `Refused` node carrying the error's message where the node is.
    ///
    /// The error keeps its variant under `RefuseDocument`, because the callers tell the variants
    /// apart: `validate` prints an `InvalidKeyType` and an `UnsupportedDocument` as they are and the
    /// FFI gives each its own code. `replace` is the stack index of the node to replace, for a
    /// container that has already been pushed; `None` pushes the `Refused` node as a new node, which
    /// is what an alias needs since nothing was pushed for it. The `Refused` node reaches
    /// `PathAwareValue::try_from_marked`, which fails the conversion with the message, so the refusal
    /// is reported where the value would have been used, which for a `test` spec is the one case
    /// holding it.
    fn refuse_node(
        &mut self,
        refusal: Error,
        location: Location,
        replace: Option<usize>,
    ) -> rules::Result<()> {
        match self.refusals {
            RefusalPolicy::RefuseDocument => Err(refusal),
            RefusalPolicy::MarkBadValue => {
                let refused = MarkedValue::Refused(refusal.to_string(), location);
                match replace {
                    Some(index) => self.stack[index] = refused,
                    None => self.stack.push(refused),
                }
                Ok(())
            }
        }
    }

    /// Records the finished node on top of the stack under `anchor`, for later aliases.
    ///
    /// Recording is a clone into the anchor table and is not charged to the expansion budget, which
    /// counts the copies aliases make ([`MAX_ALIAS_EXPANSION_NODES`]); the node itself stays where it
    /// was read, and whatever it already holds -- an alias refused earlier inside it, say -- is
    /// reported where it is. What the table holds is bounded by `record_anchor`. `facts` is what the
    /// scalar handler knew about the scalar beyond its value (a merge key, a kept literal; see
    /// `ScalarFacts`), so that an alias of it is recorded the same way.
    fn remember_anchor(&mut self, anchor: Option<Anchor>, facts: ScalarFacts) -> rules::Result<()> {
        if let Some(anchor) = anchor {
            let top = self.stack.len() - 1;
            self.record_anchor(anchor.name(), top, facts)?;
        }
        Ok(())
    }

    /// Clones the node at stack index `at` into the anchor table under `name`, with its size, so that
    /// an alias has a finished node to copy and a size to be charged for. The clone itself is not
    /// charged to the expansion budget: that budget counts the copies aliases make, and an anchor
    /// nothing aliases is not one ([`MAX_ALIAS_EXPANSION_NODES`]).
    ///
    /// The table is bounded on its own, over the whole document, at the budget plus the input's
    /// length in nodes and in bytes. Every anchored node is held whole for the aliases that may
    /// follow it, and an anchor nested inside another is held once on its own and once inside each
    /// anchor around it, so a hundred nested anchors around 64 MiB of aliased scalars would hold
    /// 6.4 GiB from a 70 KiB file; the bound is what stops that, and nothing the alias budget counts
    /// does. A document with no nesting holds each anchored node once, which is never more than the
    /// document, so the input's length in the bound keeps every such document inside it. The refusal
    /// names the anchor, and under `RefusalPolicy::MarkBadValue` the anchor is recorded as the
    /// refusal, so that each alias of it fails the case holding the alias, as an alias past the budget
    /// does. A name anchored again gives back what its earlier node held. `facts` is carried with the
    /// node for the aliases (see `Anchored`); a container has none.
    fn record_anchor(&mut self, name: String, at: usize, facts: ScalarFacts) -> rules::Result<()> {
        let node = &self.stack[at];
        let location = *node.location();
        let size = size_of(node);
        #[cfg(test)]
        {
            self.nodes_measured += 1;
        }
        let replaced = self
            .anchors
            .get(&name)
            .map_or(Size::default(), |anchored| anchored.size);
        let nodes = self.anchored_nodes - replaced.nodes + size.nodes;
        let bytes = self.anchored_bytes - replaced.bytes + size.bytes;
        let node_bound = MAX_ALIAS_EXPANSION_NODES + self.input_bytes;
        let byte_bound = MAX_ALIAS_EXPANSION_BYTES + self.input_bytes;
        let refusal = if nodes > node_bound {
            Some(format!(
                "cfn-guard holds at most {node_bound} nodes of anchored content while it reads one \
                 document ({MAX_ALIAS_EXPANSION_NODES} plus one for each of the document's {} bytes), \
                 and recording the anchor `&{name}` at {location} would take what this document's \
                 anchors hold to {nodes}. An anchor is kept whole for the aliases that may follow it, \
                 and an anchor nested inside another is kept once on its own and once inside each \
                 anchor around it; anchor the shared value once, outside the others.",
                self.input_bytes
            ))
        } else if bytes > byte_bound {
            Some(format!(
                "cfn-guard holds at most {byte_bound} bytes of anchored scalar text and key names \
                 while it reads one document ({MAX_ALIAS_EXPANSION_BYTES} plus the document's {} \
                 bytes), and recording the anchor `&{name}` at {location} would take what this \
                 document's anchors hold to {bytes} bytes. An anchor is kept whole for the aliases \
                 that may follow it, and an anchor nested inside another is kept once on its own and \
                 once inside each anchor around it; anchor the shared value once, outside the others.",
                self.input_bytes
            ))
        } else {
            None
        };
        if let Some(refusal) = refusal {
            return match self.refusals {
                RefusalPolicy::RefuseDocument => Err(Error::UnsupportedDocument(refusal)),
                RefusalPolicy::MarkBadValue => {
                    let refused = MarkedValue::Refused(refusal, location);
                    let size = size_of(&refused);
                    self.anchored_nodes = self.anchored_nodes - replaced.nodes + size.nodes;
                    self.anchored_bytes = self.anchored_bytes - replaced.bytes + size.bytes;
                    self.anchors.insert(
                        name,
                        Anchored {
                            node: refused,
                            size,
                            facts: ScalarFacts::default(),
                        },
                    );
                    Ok(())
                }
            };
        }
        let copy = self.stack[at].clone();
        #[cfg(test)]
        {
            self.copies_made += 1;
        }
        self.anchored_nodes = nodes;
        self.anchored_bytes = bytes;
        self.anchors.insert(
            name,
            Anchored {
                node: copy,
                size,
                facts,
            },
        );
        Ok(())
    }

    /// The bytes the anchor table holds, for the test that pins its bound.
    #[cfg(test)]
    pub(super) fn anchored_bytes(&self) -> usize {
        self.anchored_bytes
    }

    /// Notes that the container at `container_idx` carries an anchor, so that
    /// `remember_anchored_container` records it once it is finished.
    fn note_anchored_container(&mut self, anchor: Option<Anchor>, container_idx: usize) {
        if let Some(anchor) = anchor {
            self.anchor_index.push((container_idx, anchor.name()));
        }
    }

    /// Records the container that just closed at `container_idx` under its anchor, if it has one.
    ///
    /// Runs after `close_tagged_container`, so the node on top of the stack is the finished node
    /// whether or not a `!Foo` tag wrapped it: the anchor names the tagged node, as YAML has it. The
    /// clone is not charged to the budget, as `remember_anchor` describes.
    fn remember_anchored_container(&mut self, container_idx: usize) -> rules::Result<()> {
        let anchored_here = self
            .anchor_index
            .last()
            .map_or(false, |(idx, _)| *idx == container_idx);
        if !anchored_here {
            return Ok(());
        }

        let (_, name) = self.anchor_index.pop().unwrap();
        let top = self.stack.len() - 1;
        self.record_anchor(name, top, ScalarFacts::default())
    }

    fn handle_scalar_event(&mut self, event: Scalar, location: Location) -> rules::Result<()> {
        let Scalar {
            anchor,
            tag,
            value,
            style,
            ..
        } = event;
        let val = match std::str::from_utf8(&value) {
            Ok(s) => s.to_string(),
            Err(_) => "".to_string(),
        };
        // See `merge_key_index`. Decided here because this is the last place the style is known. A
        // plain `<<` is the merge type implicitly; an explicit `!!merge` is the same type said out
        // loud, whatever the style, and is the one spelling that makes a quoted `<<` a merge key.
        // Deciding on `tag.is_none()` alone would leave `!!merge <<` a literal key named `<<` with
        // everything under it hidden.
        let explicitly_merge = tag.as_ref().is_some_and(|tag| {
            let handle = tag.get_handle();
            tag.get_suffix(handle.len()) == "tag:yaml.org,2002:merge"
        });
        let is_merge_key = val == MERGE_KEY
            && (explicitly_merge || (tag.is_none() && style == ScalarStyle::Plain));
        // The spelling, for `scalar_texts`, taken before the resolution below consumes it. Only a
        // recording loader pays for the copy.
        let spelling = self.scalar_texts.as_ref().map(|_| val.clone());
        // See `kept_literal_index`: set below by the plain-scalar arms that keep a literal as text
        // where YAML would resolve it, the only place the reason for a `String` is still known.
        let mut kept_literal = false;

        let path_value = if let Some(tag) = tag {
            let handle = tag.get_handle();
            let suffix = tag.get_suffix(handle.len());

            if handle == "!" && !suffix.is_empty() {
                wrap_tagged_scalar(val, location, suffix.as_ref())
            } else if suffix.starts_with(TYPE_REF_PREFIX) {
                handle_type_ref(val, location, suffix.as_ref(), &mut self.warnings)
            } else {
                MarkedValue::String(val, location)
            }
        } else if style != ScalarStyle::Plain {
            MarkedValue::String(val, location)
        } else {
            match resolve_int(&val) {
                IntScalar::Resolved(i) => MarkedValue::Int(i, location),
                // Both short-circuit the float resolver on purpose: `"0755".parse::<f64>()` is
                // 755.0, so falling through would swap one wrong number for another. Only the
                // too-wide integer is a kept literal (see `KeyForm::Literal`); `0755` is the string
                // this loader and `serde_yaml` both mean by it, so as a key it is ordinary text.
                IntScalar::LeadingZero { .. } => MarkedValue::String(val, location),
                IntScalar::OutOfRange => {
                    kept_literal = true;
                    MarkedValue::String(val, location)
                }
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
                    // A numeral the resolver refused -- overflowed to infinity, or underflowed to
                    // zero -- is a literal kept as text where YAML would resolve it, so it is a key
                    // of its own form (see `KeyForm::Literal`). Rust's own `inf` and `nan`
                    // spellings parse too but hold no digit; YAML never resolves them, so they are
                    // ordinary strings and fall through.
                    Ok(_) if val.bytes().any(|b| b.is_ascii_digit()) => {
                        kept_literal = true;
                        MarkedValue::String(val, location)
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
                        // What `empty` says about the null this produces is decided in the
                        // evaluator, not here: a null is empty, the same answer an absent key gets,
                        // so `k:` and a missing `k` read alike under `empty`, `!empty` and a filter
                        // such as `Resources[ Properties.Foo !empty ]`, which deselects a resource
                        // whose `Foo` is written with nothing after the colon. The three states
                        // still have three predicates: `not exists` for an absent key, `is_null` or
                        // `== null` for a key with no value, `exists` to tell the second from the
                        // first. See `element_empty_operation` in `rules/eval.rs` and the `empty`
                        // section of docs/CLAUSES.md.
                        //
                        // By exact spelling. This lowercased the scalar first, so `nUlL` and `NuLL`
                        // were null, while the boolean arm above had been narrowed to three casings
                        // with the note that matching case-insensitively would accept spellings no
                        // schema makes boolean. Null was the one scalar still resolved that way.
                        // YAML 1.2 core resolves `null | Null | NULL | ~` and nothing else, and
                        // `is_null_spelling` is the set the `!!null` arm reads, so the two agree.
                        None if is_null_spelling(&val) => MarkedValue::Null(location),
                        // YAML's non-finite spellings, which this loader keeps as text (see the
                        // float arm above): a literal kept where YAML would resolve it, so a key
                        // of its own form (`KeyForm::Literal`). Matched exactly, not case-folded:
                        // YAML 1.2 core resolves `.inf`, `.Inf` and `.INF` (with an optional sign)
                        // and `.nan`, `.NaN` and `.NAN`, and nothing else, so `.iNf` is a plain
                        // string to YAML and to `serde_yaml`, and here; case-folding would make it
                        // a kept literal and its pair with `".iNf"` a false collision warning.
                        None if is_non_finite_spelling(&val) => {
                            kept_literal = true;
                            MarkedValue::String(val, location)
                        }
                        None => MarkedValue::String(val, location),
                    },
                },
            }
        };

        // Recorded for the scalars whose rendering can differ from their spelling: an integer, a
        // float or a boolean. A string is its own spelling, and a null has none worth keeping.
        if let (Some(texts), Some(spelling)) = (self.scalar_texts.as_mut(), spelling) {
            if matches!(
                path_value,
                MarkedValue::Int(..) | MarkedValue::Float(..) | MarkedValue::Bool(..)
            ) {
                texts.insert(location, spelling);
            }
        }

        self.stack.push(path_value);
        if is_merge_key {
            self.merge_key_index.push(self.stack.len() - 1);
        }
        if kept_literal {
            self.note_kept_literal();
        }
        self.remember_anchor(
            anchor,
            ScalarFacts {
                kept_literal,
                merge_key: is_merge_key,
            },
        )
    }

    /// Records the scalar on top of the stack in `kept_literal_index`: a plain scalar this loader kept
    /// as text where YAML would resolve it, or an alias's copy of an anchored one.
    fn note_kept_literal(&mut self) {
        self.kept_literal_index.push(self.stack.len() - 1);
        #[cfg(test)]
        {
            self.work.kept_literals_recorded += 1;
        }
    }

    fn handle_sequence_end(&mut self) -> rules::Result<()> {
        let array_idx = self.last_container_index.pop().unwrap();
        let values: Vec<MarkedValue> = self.stack.drain(array_idx + 1..).collect();
        // An item of this sequence is not a key of anything; its index would otherwise be read as the
        // form of whichever key next occupies it.
        self.forget_scalars_above(array_idx);
        let array = self.stack.last_mut().unwrap();
        match array {
            MarkedValue::List(vec, _) => vec.extend(values),
            _ => unreachable!(),
        }

        self.refuse_pending_tag(array_idx)?;
        self.close_tagged_container(array_idx);
        self.remember_anchored_container(array_idx)
    }

    /// Applies the refusal `push_tag_wrapper` recorded for the container at `container_idx`, if it
    /// recorded one, now that the container has closed and is the node on top of the stack.
    ///
    /// The container's contents have been read and dropped into it, and are dropped again with it: the
    /// `Refused` node that replaces it carries the message, and `close_tagged_container` and the anchor
    /// bookkeeping after it run on that node as they would on the container, so an anchor written on
    /// the container names the refusal and an alias to it copies the refusal. A mapping `fill_mapping`
    /// refused a moment earlier is replaced again here, so when a `!!`-tagged mapping is refused for
    /// its keys as well, the tag refusal is the one kept, on every load: the tag sits on the container
    /// that holds the keys, so it is the outer mistake, and the message that names it is the one the
    /// author needs first. Nothing is recorded under `RefuseDocument`, so this is a no-op there.
    fn refuse_pending_tag(&mut self, container_idx: usize) -> rules::Result<()> {
        let pending = self
            .pending_tag_refusals
            .last()
            .map_or(false, |(idx, _)| *idx == container_idx);
        if !pending {
            return Ok(());
        }

        let (_, refusal) = self.pending_tag_refusals.pop().unwrap();
        let location = *self.stack[container_idx].location();
        self.refuse_node(
            Error::UnsupportedDocument(refusal),
            location,
            Some(container_idx),
        )
    }

    /// Drops the recorded merge-key and kept-literal indices for a container that has just closed.
    ///
    /// Everything the container held has left the stack, so an index above its own is no longer live
    /// and would otherwise be read as a merge key, or a kept literal, of whichever scalar next
    /// occupies that index. A `<<` written as a *sequence item* rather than as a key is the shape that
    /// leaves one behind.
    fn forget_scalars_above(&mut self, container_idx: usize) {
        // Both indices are in stack order, so everything above the container is at the end: pop it
        // rather than scan the whole list. A `retain` over the whole index on every close cost each
        // close the length of the index, which on a document of N kept-literal keys whose values are
        // mappings is about N^2 / 2 visits in all; the width test counts them.
        while matches!(self.merge_key_index.last(), Some(idx) if *idx > container_idx) {
            self.merge_key_index.pop();
            #[cfg(test)]
            {
                self.work.index_visits += 1;
            }
        }
        while matches!(self.kept_literal_index.last(), Some(idx) if *idx > container_idx) {
            self.kept_literal_index.pop();
            #[cfg(test)]
            {
                self.work.index_visits += 1;
            }
        }
        while matches!(self.alias_key_index.last(), Some((idx, _)) if *idx > container_idx) {
            self.alias_key_index.pop();
        }
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
            MarkedValue::BadValue(..) | MarkedValue::Refused(..) => {}
            _ => unreachable!(),
        }
    }

    /// Pushes the wrapper for a `!Foo`-tagged sequence or mapping, so its contents end up under the
    /// long function name once the container closes.
    ///
    /// A bare `!` is skipped. It is YAML's non-specific tag rather than a function name, and
    /// `long_form_of("")` would name the key "Fn::".
    fn push_tag_wrapper(&mut self, tag: Option<&Tag>, location: &Location) -> rules::Result<()> {
        let Some(tag) = tag else { return Ok(()) };

        let handle = tag.get_handle();
        let suffix = tag.get_suffix(handle.len());

        // A `!!` type tag on a container. The yaml.org collection types -- `!!seq`, `!!map`, `!!set`
        // and the rest -- pass through as they always have; the container is what it is. An intrinsic
        // name under `!!` is `!Name` with one `!` too many, `!!If [IsProd, a, b]`; reading `!` handles
        // only would drop the tag, load the sequence as a bare list, and leave a rule reading `Fn::If`
        // finding nothing. A scalar under the same typo becomes a `BadValue` that the
        // file-level report names; a container has no such slot, so the refusal names the tag and its
        // position itself.
        //
        // The container is one node, so `RefusalPolicy` decides what the refusal costs, as it does for
        // a mapping `fill_mapping` will not model. This returned the error under either policy and the
        // start handlers passed it up with `?`, so `refuse_node` was never reached: a
        // `!!If [IsProd, a, b]` inside one case's `input:` refused the whole `test` spec file, every
        // other case lost with it, where `!!Ref Foo` in the same position fails only its case. The
        // `Refused` node cannot be put down here, because the container's contents are about to be
        // read onto the stack above it, so under `MarkBadValue` the refusal is recorded against the
        // index the container will occupy and `refuse_pending_tag` applies it when the container
        // closes. Under `RefuseDocument` the document is refused here, as before.
        if let Some(short) = suffix.strip_prefix(TYPE_REF_PREFIX) {
            if looks_like_an_intrinsic_name(short) {
                let refusal = format!(
                    "cfn-guard does not read the tag `!!{short}` at {location}. An intrinsic function \
                     is written with one `!`, as `!{short}`."
                );
                return match self.refusals {
                    RefusalPolicy::RefuseDocument => Err(Error::UnsupportedDocument(refusal)),
                    RefusalPolicy::MarkBadValue => {
                        self.pending_tag_refusals.push((self.stack.len(), refusal));
                        Ok(())
                    }
                };
            }
            // A foreign namespace on a container -- `!!python/dict { ... }` -- gets the same warning
            // its scalar form gets, so the two shapes of one tag are not one loud and one silent. The
            // yaml.org collection types are the container's own type and say nothing.
            if !matches!(short, "seq" | "map" | "set" | "omap" | "pairs") {
                self.warnings.push(UnreadTag {
                    tag: short.to_string(),
                    location: *location,
                });
            }
            return Ok(());
        }

        if handle != "!" || suffix.is_empty() {
            return Ok(());
        }

        let fn_ref = long_form_of(&suffix).into_owned();
        self.stack
            .push(tagged_container_wrapper(location.clone(), &fn_ref));
        self.func_support_index
            .push((self.stack.len() - 1, (fn_ref, location.clone())));

        Ok(())
    }

    fn handle_sequence_start(
        &mut self,
        event: SequenceStart,
        location: Location,
    ) -> rules::Result<()> {
        self.push_tag_wrapper(event.tag.as_ref(), &location)?;
        self.stack.push(MarkedValue::List(vec![], location));
        self.last_container_index.push(self.stack.len() - 1);
        self.note_anchored_container(event.anchor, self.stack.len() - 1);

        Ok(())
    }

    fn handle_mapping_end(&mut self) -> crate::rules::Result<()> {
        let map_index = self.last_container_index.pop().unwrap();
        let key_values: Vec<MarkedValue> = self.stack.drain(map_index + 1..).collect();
        // Which of this mapping's entries are merge keys, and which are literals kept as text (see
        // `KeyForm::Literal`), as offsets into `key_values`: its element `i` was at stack index
        // `map_index + 1 + i`. Read out before `map` borrows the stack, and read from the end of each
        // index, which is in stack order: everything above this mapping's own slot is this mapping's,
        // so each walk stops at the first index at or below it and visits only this mapping's
        // scalars, never an open ancestor's. A scan of the whole index here cost each close the
        // length of the index; the width test counts the visits.
        let mut merge_key_offsets: HashSet<usize> = HashSet::new();
        for idx in self.merge_key_index.iter().rev() {
            #[cfg(test)]
            {
                self.work.index_visits += 1;
            }
            if *idx <= map_index {
                break;
            }
            merge_key_offsets.insert(idx - (map_index + 1));
        }
        let mut literal_offsets: HashSet<usize> = HashSet::new();
        for idx in self.kept_literal_index.iter().rev() {
            #[cfg(test)]
            {
                self.work.index_visits += 1;
            }
            if *idx <= map_index {
                break;
            }
            literal_offsets.insert(idx - (map_index + 1));
        }
        // The aliases among this mapping's keys and values, by the same offsets, each with its own
        // position: `fill_mapping` records the ones that are keys, so a duplicate-key record can name
        // the line an alias wrote a key at. Read from the end, like the two indices above.
        let mut alias_sites: HashMap<usize, Location> = HashMap::new();
        for (idx, site) in self.alias_key_index.iter().rev() {
            if *idx <= map_index {
                break;
            }
            alias_sites.insert(idx - (map_index + 1), *site);
        }
        self.forget_scalars_above(map_index);

        // Read before the mapping is borrowed for filling: `fill_mapping` keys each collision it
        // records by it, so the record names this mapping and not every mapping that holds a copy of
        // the same keys, and a refusal is placed at it.
        let location = *self.stack[map_index].location();
        let map = match self.stack.last_mut().unwrap() {
            MarkedValue::Map(map, _) => map,
            _ => unreachable!(),
        };
        // `fill_mapping` records the key forms into `key_forms`, one entry per position whose form is
        // not `Text`. A position names one scalar's value: an alias's copy keeps its anchor's position
        // and is the same scalar, so whichever of the anchored key and its copies closes first records
        // the position, and the rest rewrite the same form and the map does not grow (the copy's
        // mapping may close before the anchor's, and an anchor written as a value is never a key at
        // all). So the growth counted here is the number of positions this mapping recorded for the
        // first time, not the number of its keys whose form is not `Text`; see `Work::forms_recorded`.
        #[cfg(test)]
        let forms_before = self.key_forms.len();

        // A mapping the loader will not model is one node, so `RefusalPolicy` decides what it costs.
        // The entries it held have been drained and are dropped with the refusal; the `Refused` node
        // that replaces the mapping carries the message, and `close_tagged_container` and the anchor
        // bookkeeping below run on it as they would on the mapping. A collision `apply_merges`
        // recorded in a mapping that is then refused stays in `collisions` as a position nothing
        // reaches: `PathAwareValue::try_from_marked_reporting` reports a collision only when its
        // walk arrives at the held key, and the `Refused` node has no keys to walk.
        match fill_mapping(
            map,
            location,
            key_values.into_iter(),
            &merge_key_offsets,
            &literal_offsets,
            &alias_sites,
            &mut self.key_forms,
            &mut self.collisions,
        ) {
            Err(error) => self.refuse_node(error, location, Some(map_index))?,
            Ok(_filled) => {
                #[cfg(test)]
                {
                    self.work.map_changes += _filled.changes;
                    self.work.map_rebuilds += _filled.rebuilds;
                }
            }
        }
        #[cfg(test)]
        {
            self.work.forms_recorded += self.key_forms.len() - forms_before;
        }

        self.refuse_pending_tag(map_index)?;
        self.close_tagged_container(map_index);
        self.remember_anchored_container(map_index)
    }

    /// The merged keys that collided with a held key of another form while the document loaded, by
    /// the position of the mapping that merged and the held key's position. Empty for a document with
    /// no collision. A caller that reports duplicate keys hands this to
    /// `PathAwareValue::try_from_marked_reporting`, which emits the notice for each when its walk
    /// reaches the held key in that mapping, with the path the value finally has; the merged entries
    /// themselves were dropped, so nothing else records them. A record carried into an enclosing merge
    /// is held once per level: the source's own entry stays, for an alias of the source that is walked
    /// on its own, and each enclosing mapping gets a copy. The walk reports each held key it reaches
    /// once, so the map's size is not the notice count. See `apply_merges`.
    pub(crate) fn collisions(&self) -> &KeyCollisions {
        &self.collisions
    }

    fn handle_mapping_start(
        &mut self,
        event: MappingStart,
        location: Location,
    ) -> rules::Result<()> {
        // The tag was never read here, so a tagged *mapping* lost it unconditionally -- including for
        // names the loader did support. `!ToJsonString { a: 1 }` and `!Transform { Name: ... }` are
        // mappings, and both arrived as bare maps with no function around them.
        self.push_tag_wrapper(event.tag.as_ref(), &location)?;
        self.stack
            .push(MarkedValue::Map(indexmap::IndexMap::new(), location));
        self.last_container_index.push(self.stack.len() - 1);
        self.note_anchored_container(event.anchor, self.stack.len() - 1);

        Ok(())
    }
}

/// Puts a closed mapping's entries into `map`, resolving its keys and folding its merge keys.
///
/// `key_values` alternates key and value as the loader pushed them; `merge_key_offsets` are the
/// offsets into it of the keys the document wrote as a plain `<<`; `alias_sites` are the offsets of
/// the entries an alias pushed, each to the alias's own position, for the duplicate-key record of a
/// key an alias wrote; `mapping_at` is the mapping's own
/// position, which keys every collision `apply_merges` records for it. The errors are the two refusals
/// a mapping can earn: a key with no text, and a merge key given something that is not a mapping. On
/// either, the entries not yet taken are dropped with the iterator.
///
/// The entries arrive as a `std::vec::IntoIter`, whose `next` hands out the front element and moves
/// nothing else, so a mapping of N entries costs N moves to consume. Taking them two at a time from a
/// `Vec` with `remove(0)`, which shifts the whole remainder on every call, loads a flat mapping of
/// 40,000 keys in about 4 s and one of 160,000 in 108 s, the verdict never affected, only the wait.
/// The parameter type rules out a shifting take from the storage itself, and changing it means editing
/// this signature on purpose. It is not a regression guard for the
/// body: a consumer that copied the entries out into a `Vec` first and shifted them there would
/// compile, and no count the loader keeps would catch it. The shape test in `loader_tests` pins the
/// result of this walk, not its cost.
///
/// A key written twice at one position (an anchored key beside its alias) keeps the slot the anchor
/// put it in and takes the last value, unless a plain spelling of the name was written after that slot,
/// in which case the entry moves to the end so that the value written last stands over the plain one.
/// Entries go straight into the map, one `insert_full` each, which is the whole cost of a mapping with
/// no repeat; the map itself tells a repeat (`insert_full` hands the old value back). On the first repeat
/// the function builds, once, a write stamp per entry and the latest stamp of each name, and from then on
/// a repeat either replaces the value in place or, when the name has a later stamp, re-stamps the entry
/// and marks the map for one rebuild at the end, where the entries are put back in stamp order. Moving
/// the entry inside the map on each repeat instead, with `shift_remove` and a fresh `insert`, shifted
/// every entry behind it: a mapping of N anchored keys followed by their N aliases in the same order
/// repeated from the front every time and loaded in O(N^2), 11 s at 40,000 keys and 46 s at 80,000 where
/// a flat mapping of the same size loads in a tenth of a second. Collecting every entry into a side
/// buffer first and filling the map at the end fixed that, but made every mapping pay a second buffer
/// and a cloned name per key; the stamps are built only for a mapping that repeats a key.
///
/// The map has to arrive empty: a repeat is told by the map, so an entry seeded before the call would
/// be written over in its old slot with no record. The one caller makes the map fresh, and a debug
/// build asserts it; `Work::map_changes` and `Work::map_rebuilds` count what this function did.
fn fill_mapping(
    map: &mut indexmap::IndexMap<(String, Location), MarkedValue>,
    mapping_at: Location,
    mut key_values: std::vec::IntoIter<MarkedValue>,
    merge_key_offsets: &HashSet<usize>,
    literal_offsets: &HashSet<usize>,
    alias_sites: &HashMap<usize, Location>,
    key_forms: &mut HashMap<Location, KeyForm>,
    collisions: &mut KeyCollisions,
) -> rules::Result<FillWork> {
    debug_assert!(
        map.is_empty(),
        "fill_mapping fills a fresh map: a repeat is told by the map itself, so an entry seeded before \
         the call would be written over in its old slot with no record"
    );
    let mut merges: Vec<MarkedValue> = vec![];
    let mut work = FillWork::default();
    // Built at the first repeat, never for a mapping without one: a write stamp per map index, and the
    // latest stamp among the entries of each name, which decides whether a repeat moves its entry to the
    // end (the name has a later entry) or replaces the value where it sits. `next_stamp` counts on from
    // the entries already in the map when the stamps are built.
    let mut stamps: Vec<usize> = vec![];
    let mut last_stamp_of_name: HashMap<String, usize> = HashMap::new();
    let mut next_stamp = 0;
    let mut stamped = false;
    let mut moved = false;
    let mut offset = 0;
    while let (Some(key), Some(value)) = (key_values.next(), key_values.next()) {
        let key_offset = offset;
        offset += 2;
        // Recorded before the key is rendered to text, which is the last moment its form is known;
        // `apply_merges` reads it back by position for this mapping's keys and for the keys of every
        // merge source, whose own mapping recorded them when it closed. Only a form other than `Text`
        // is stored: `apply_merges` reads a missing entry as `Text`, for a held key and a merged key
        // alike, so a document whose keys are all strings records nothing and an entry that is
        // missing is the ordinary case rather than a broken invariant.
        let form = match &key {
            MarkedValue::String(..) if literal_offsets.contains(&key_offset) => KeyForm::Literal,
            MarkedValue::String(..) => KeyForm::Text,
            MarkedValue::Int(..) => KeyForm::Int,
            MarkedValue::Float(..) => KeyForm::Float,
            MarkedValue::Bool(..) => KeyForm::Bool,
            // Refused below as a key with no text, or forwarded as the refusal it carries; the form
            // is never read.
            _ => KeyForm::Text,
        };
        if form != KeyForm::Text {
            key_forms.insert(*key.location(), form);
        }
        let key_str = match key {
            MarkedValue::String(val, loc) => (val, loc),
            // An alias the loader refused, or a mapping it refused, standing where a key should be.
            // The refusal it carries is why the key has no text, so it is what this mapping is
            // refused with, as `apply_merges` does for a `<<` whose alias was refused. Reading it as
            // one more key without text wrapped that refusal in `InvalidKeyType`'s "Quote it to make
            // it a string", advice that does not apply: quoting `*later` makes a key named `*later`.
            //
            // A `BadValue` is not forwarded the same way. It is a `!!int abc`, a tagged scalar whose
            // payload is not its type, and its text is the scalar's own; the key refusal below, with
            // its position and its advice, is the right answer for it, and forwarding the text as
            // the refusal reported "abc" and nothing else.
            MarkedValue::Refused(refusal, _) => return Err(Error::UnsupportedDocument(refusal)),
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
                    // Quoting makes a null, a container or a plain tagged payload the string it
                    // spells. A tagged scalar refused for a reason is the one key that advice does
                    // not fix: `!!int "0755"` is refused the same way, and quoting the whole key
                    // gives a text neither YAML version would make of it. Its reason carries the
                    // advice for a key instead.
                    let advice = match &val {
                        MarkedValue::BadValue(_, Some(reason), _) => reason.key_fix(),
                        _ => String::from("Quote it to make it a string"),
                    };
                    return Err(Error::InternalError(InvalidKeyType(format!(
                        "{}, where the key is {}. {}",
                        val.location(),
                        describe_key(&val),
                        advice
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

        // The map is keyed on `(name, position)`, so two keys of this mapping that share a position
        // are one entry to it: an anchored key beside an alias of it (`&k x: 1` then `*k: 2`), or two
        // aliases of one anchor, since a copy keeps its anchor's position. The pair the conversion
        // detects by name over the mapping's entries cannot be seen when the two are folded into one,
        // so the extra write is counted here, as a repeat of the position, and the conversion reports
        // it with the duplicate-key notice when its walk reaches the entry. The entry moves to the end
        // only when a plain spelling of the name sits after its slot: the conversion gives a name the
        // value of its last entry, so a plain `x: 2` written between `&k x: 1` and `*k: 3` would
        // otherwise stand over the `3` written last. When nothing of the name follows, the value is
        // replaced where the entry sits, so `&k x: 1`, `y: 2`, `*k: 3` keeps the keys `x, y` as the
        // plain `x: 1`, `y: 2`, `x: 3` does; a move on every repeat put `x` behind `y`, and that order
        // reached `keys`, a capture over the map and a `.*` enumeration. A plain `insert` kept the
        // earlier slot and dropped its return, so the pair loaded in silence and the value written
        // last could lose. Whether a later entry of the name exists is read from `last_stamp_of_name`,
        // the latest write stamp among the name's entries, so a repeat costs one lookup whatever the
        // mapping's size, and a mapping with no repeat never builds the stamps at all.
        //
        // A key an alias wrote is recorded with the alias's own position, every write of it, so the
        // notice can name the line the author wrote the key at: the copy carries the anchor's position,
        // and a record built from that alone named one line twice, or a line in another mapping. The
        // repeat and the site go into one record by one call, after the write, so a repeat with no
        // site, a shape no document makes, is refused there rather than read past by the conversion.
        let position = key_str.1;
        let (index, replaced) = map.insert_full(key_str, value);
        work.changes += 1;
        let repeated = replaced.is_some();
        if repeated {
            if !stamped {
                // The first repeat of this mapping: stamp every entry with its index, the order it holds,
                // and record the latest stamp of each name once.
                stamps = (0..map.len()).collect();
                for (stamp, (name, _)) in map.keys().enumerate() {
                    last_stamp_of_name.insert(name.clone(), stamp);
                }
                next_stamp = map.len();
                stamped = true;
            }
            let name = &map.get_index(index).expect("the entry just written").0 .0;
            let later_entry_of_the_name = last_stamp_of_name
                .get(name)
                .map_or(false, |last| *last > stamps[index]);
            if later_entry_of_the_name {
                stamps[index] = next_stamp;
                last_stamp_of_name.insert(name.clone(), next_stamp);
                next_stamp += 1;
                moved = true;
            }
        } else if stamped {
            let name = &map.get_index(index).expect("the entry just written").0 .0;
            stamps.push(next_stamp);
            last_stamp_of_name.insert(name.clone(), next_stamp);
            next_stamp += 1;
        }
        collisions.add_key_write(
            mapping_at,
            position,
            alias_sites.get(&key_offset).copied(),
            repeated,
        );
    }
    if moved {
        // One rebuild in stamp order: a moved entry sits where its last write put it, every other entry
        // keeps the order it was written in.
        let mut entries: Vec<(usize, (String, Location), MarkedValue)> = map
            .drain(..)
            .zip(stamps)
            .map(|((key, value), stamp)| (stamp, key, value))
            .collect();
        entries.sort_by_key(|(stamp, _, _)| *stamp);
        for (_, key, value) in entries {
            map.insert(key, value);
            work.changes += 1;
        }
        work.rebuilds += 1;
    }

    apply_merges(map, mapping_at, merges, key_forms, collisions)?;
    Ok(work)
}

/// What a copy of a loaded value costs: its nodes, the bytes of text it holds, and its depth.
#[derive(Debug, Default, Clone, Copy)]
struct Size {
    /// Scalars and containers; a mapping's keys are stored beside their values and are not nodes.
    nodes: usize,
    /// The bytes of every string, regex and unreadable scalar, plus every mapping key's name counted
    /// once for the key and once more for every node under it, which is how many times the converted
    /// document carries the name in its paths. A number, boolean or null is a fixed-size node and
    /// adds nothing here.
    bytes: usize,
    /// How many containers deep the value goes: zero for a scalar, one more than its deepest entry
    /// for a container.
    depth: usize,
}

/// A node the anchor table holds for the aliases that may follow it (see `Loader::anchors`).
#[derive(Debug)]
struct Anchored {
    node: MarkedValue,
    /// What a copy of it costs, measured once when it was recorded.
    size: Size,
    /// What the scalar handler knew about the node when it was a plain scalar, for the copies; none for
    /// a container or a refusal.
    facts: ScalarFacts,
}

/// What `handle_scalar_event` knows about a plain scalar that its `MarkedValue` cannot say, and records
/// by stack slot: whether it is a merge key (`merge_key_index`) and whether it is a literal this loader
/// kept as text where YAML would resolve it (`kept_literal_index`, see `KeyForm::Literal`). By then a
/// plain `<<` and a quoted `"<<"` are the same `String("<<")`, and the kept `9223372036854775808` and
/// the quoted `"9223372036854775808"` the same `String` too. An alias's copy is the same scalar, so it
/// is the merge key, or the literal, the anchor is; but the slot recorded names the written scalar and
/// the copy has a slot of its own, so the anchor table carries these and `handle_alias_event` records
/// the copy from them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ScalarFacts {
    kept_literal: bool,
    merge_key: bool,
}

/// How many nodes a loaded value holds, how many bytes of text, and how many containers deep it goes.
///
/// A scalar is one node at depth zero; a container is one node plus its contents, one level deeper
/// than the deepest of them. The bytes are what makes a copy expensive beyond its node count: a
/// 64 KiB string is one node, and a budget counting nodes alone let it be copied a million times.
/// A mapping key is charged `len * (1 + nodes under it)` bytes, because `PathAwareValue` stores a
/// full path at every node and every node under the key carries the key's name in its path; see
/// [`MAX_ALIAS_EXPANSION_BYTES`] for the shape that charging the key once let through.
fn size_of(value: &MarkedValue) -> Size {
    let contents = |sizes: &mut dyn Iterator<Item = Size>| {
        let inner = sizes.fold(Size::default(), |acc, size| Size {
            nodes: acc.nodes + size.nodes,
            bytes: acc.bytes + size.bytes,
            depth: acc.depth.max(size.depth),
        });
        Size {
            nodes: inner.nodes + 1,
            bytes: inner.bytes,
            depth: inner.depth + 1,
        }
    };
    match value {
        MarkedValue::List(items, _) => contents(&mut items.iter().map(size_of)),
        MarkedValue::Map(entries, _) => contents(&mut entries.iter().map(|((name, _), value)| {
            let value = size_of(value);
            Size {
                nodes: value.nodes,
                bytes: value.bytes + name.len() * (1 + value.nodes),
                depth: value.depth,
            }
        })),
        MarkedValue::String(text, _)
        | MarkedValue::Regex(text, _)
        | MarkedValue::BadValue(text, _, _)
        | MarkedValue::Refused(text, _) => Size {
            nodes: 1,
            bytes: text.len(),
            depth: 0,
        },
        _ => Size {
            nodes: 1,
            bytes: 0,
            depth: 0,
        },
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
/// Precedence: a key the mapping writes for itself always wins over a merged one, which is why this
/// runs after every explicit key is in, and within a sequence of mappings an earlier entry wins over a
/// later one, which is what iterating a source in order and skipping names already claimed gives.
///
/// **A same-key override is not a collision, and a collision is not an override.** A merged key that
/// reads as a held key -- explicit, or from an earlier source -- is one of two things. The same YAML
/// key as the held one (both the string `Type`, however spelled: plain, quoted or `!!str`), it is the
/// merge key's documented use, the held value stands, and nothing is said. A different key (the
/// integer `1` under a string `"1"`, a kept literal `.Inf` under a string `".Inf"`), it is a collision:
/// two YAML keys that only this loader's text rendering folds into one. The held value stands and the
/// merged entry is dropped either way; what differs is that the collision is recorded, in
/// `collisions`, under this mapping's position and the held key's, mapped to the merged key's. The
/// record carries no path and no notice: `PathAwareValue::try_from_marked_reporting` emits the
/// duplicate-key notice when its walk of the finished document reaches the held key in this mapping,
/// which is how the notice gets the path the value has after every merge is applied, names the entry
/// whose value stands (the last of the name) as the one evaluated, and stays silent for a source a
/// later merge drops. A source that is itself a mapping that merged is taken apart here and never
/// walked, so the records it holds are copied over to this mapping as its entries are inserted, and
/// the walk meets them here. That is the one answer per document
/// across the routes: a collision warns here, where the route has a stderr, and is refused on the
/// serde conversion, which has none; a same-key override is neither, anywhere. `KeyForm` is how the
/// two are told apart; the forms are recorded by `handle_mapping_end` and looked up by the key's
/// position, since a merge source's keys are text by the time they get here.
///
/// **Two `<<` keys in one mapping is a duplicate key**, and the spec does not define it. The analogy
/// that applies is the one cfn-guard applies to every other duplicated key --
/// `path_value::try_from_marked` keeps the last value and warns -- rather than the sequence rule's
/// earlier-wins, so the sources are applied in reverse document order and a later `<<` wins.
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
/// `<<: *base`, which is how a merge key is usually written, contains an alias, and the alias has
/// been replaced by a copy of the anchored mapping by the time this runs, on every route, so it
/// arrives here as the inline form does. When the alias could not be resolved -- a misspelled anchor,
/// or a copy past the expansion budget -- a data file was refused at the alias, and under
/// `MarkBadValue` a `Refused` node carrying that refusal stands in its place, and the refusal is what
/// the mapping is refused with. Treating that node as a value that is not a mapping reported "must be
/// given a mapping" instead, which hid the one message that said what to fix, on the spelling every
/// shared base uses.
/// A `BadValue` is the other way around: it is a `!!int abc`, whose text is the scalar's own and not
/// a refusal, and the merge error is the right answer for it, as it is for a plain `<<: abc`.
fn apply_merges(
    map: &mut indexmap::IndexMap<(String, Location), MarkedValue>,
    mapping_at: Location,
    merges: Vec<MarkedValue>,
    forms: &std::collections::HashMap<Location, KeyForm>,
    collisions: &mut KeyCollisions,
) -> rules::Result<()> {
    if merges.is_empty() {
        return Ok(());
    }

    // By name, because the map is keyed on `(name, location)` and a merged key has a different
    // location than the explicit key it must not displace. Each name carries the forms it is held
    // in, so telling an override from a collision is one lookup; a mapping rarely holds a name in
    // more than one form, so a small vector is the right set. Every explicit name is present by
    // construction: `forms` holds only the forms that are not `Text`, and a missing entry is read as
    // `Text` here exactly as it is for a merged key below, so the two lookups cannot disagree.
    let mut present: std::collections::HashMap<String, (Location, Vec<KeyForm>)> =
        std::collections::HashMap::new();
    for (name, loc) in map.keys() {
        let form = forms.get(loc).copied().unwrap_or(KeyForm::Text);
        present
            .entry(name.clone())
            .or_insert_with(|| (*loc, vec![]))
            .1
            .push(form);
    }

    for source in merges.into_iter().rev() {
        let location = *source.location();
        // Each source keeps its own position beside its entries: a source that is itself a mapping
        // that merged holds its collision records under that position, and they have to follow the
        // entries into this mapping (below), because the source is taken apart here and is never
        // walked as a mapping of its own.
        let sources = match source {
            MarkedValue::Map(entries, source_at) => vec![(entries, source_at)],
            MarkedValue::List(entries, ..) => entries
                .into_iter()
                .map(|entry| match entry {
                    MarkedValue::Map(entries, source_at) => Ok((entries, source_at)),
                    MarkedValue::Refused(refusal, ..) => Err(Error::UnsupportedDocument(refusal)),
                    other => Err(merge_value_error(other.location())),
                })
                .collect::<rules::Result<Vec<_>>>()?,
            MarkedValue::Refused(refusal, ..) => return Err(Error::UnsupportedDocument(refusal)),
            _ => return Err(merge_value_error(&location)),
        };

        for (entries, source_at) in sources {
            let mut claimed: Vec<(String, Location, KeyForm)> = vec![];
            for (key, value) in entries {
                let form = forms.get(&key.1).copied().unwrap_or(KeyForm::Text);
                let Some((held_at, held_forms)) = present.get_mut(&key.0) else {
                    // A record the source holds against this entry, from a merge the source itself
                    // applied, is carried over to this mapping, where the entry now lives and where the
                    // walk will meet it. Copied rather than moved: a source that is also walked on its
                    // own, an anchored mapping written as a value elsewhere, keeps its record for that
                    // walk. An entry the mapping already holds is dropped below and carries nothing
                    // over, so a collision inside a source a later merge drops stays silent.
                    //
                    // A merged position is added once. The vector keeps document order, which is the
                    // record's meaning, so it is not a set; a position it already holds is skipped,
                    // because the same merged key can reach this mapping twice: carried in with a
                    // source that merged it, and again when this mapping lists that source's input
                    // beside the source (`<<: [*s, *b]` where `*s` already merged `*b`), which would
                    // report one collision twice.
                    if let Some(carried) = collisions.merged_against(source_at, key.1).cloned() {
                        let record = collisions.merged_against_mut(mapping_at, key.1);
                        for merged_at in carried {
                            if !record.contains(&merged_at) {
                                record.push(merged_at);
                            }
                        }
                    }
                    // A key the source wrote twice at one position (an anchored key beside an alias of
                    // it) is carried the same way, its count and its alias sites as the one record they
                    // are, so the extra write is reported where the entry lands; the source itself is
                    // never walked.
                    collisions.carry_key_writes(source_at, mapping_at, key.1);
                    claimed.push((key.0.clone(), key.1, form));
                    map.insert(key, value);
                    continue;
                };

                // Held already, so the held value stands either way and the merged entry is dropped.
                // A held key of the same form is a same-key override: silent. Another form is a
                // collision, recorded against the position of a held entry of the name -- the first
                // one, which is in the mapping like any other -- for `try_from_marked_reporting` to
                // report when its walk reaches that entry. Recording a position rather than a notice
                // is what gives the notice the path the value has after every merge, the entry whose
                // value stands when the name is written twice, and silence for a subtree a later
                // merge drops.
                //
                // Keyed by this mapping's position too, because the held key's position alone names
                // more than one entry when it came through an alias. A copy of an anchored mapping
                // keeps the anchor's positions, so the anchored mapping and every mapping that merges
                // it hold the same key at the same position, and a record keyed by the position alone
                // attached to all of them: one collision under one `<<: [*base, ...]` was reported for
                // the anchor and for each other `<<: *base` as well, each pointing at a "repeated"
                // position inside the mapping that merged.
                if held_forms.contains(&form) {
                    continue;
                }
                held_forms.push(form);
                // Once per merged position (see the carry above): the same merged key may already be
                // on the record, carried in with a source that merged it before this mapping met it
                // again as an input of its own.
                let record = collisions.merged_against_mut(mapping_at, *held_at);
                if !record.contains(&key.1) {
                    record.push(key.1);
                }
            }
            for (name, loc, form) in claimed {
                present
                    .entry(name)
                    .or_insert_with(|| (loc, vec![]))
                    .1
                    .push(form);
            }
        }
    }

    Ok(())
}

/// Whether a plain scalar is one of the spellings YAML 1.2 core resolves to a non-finite float
/// (<https://yaml.org/spec/1.2.2/#103-core-schema>): `.inf`, `.Inf` or `.INF`, with an optional sign,
/// or `.nan`, `.NaN` or `.NAN`. Exact: `.iNf` is a plain string in core, and this loader and
/// `serde_yaml` read it as one.
fn is_non_finite_spelling(val: &str) -> bool {
    let unsigned = val
        .strip_prefix('-')
        .or_else(|| val.strip_prefix('+'))
        .unwrap_or(val);
    matches!(unsigned, ".inf" | ".Inf" | ".INF")
        || (unsigned.len() == val.len() && matches!(val, ".nan" | ".NaN" | ".NAN"))
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
pub(crate) fn stringify_scalar_key(key: &MarkedValue) -> Option<String> {
    match key {
        MarkedValue::Int(i, ..) => Some(i.to_string()),
        MarkedValue::Bool(b, ..) => Some(b.to_string()),
        MarkedValue::Float(f, ..) => Some(crate::rules::functions::converters::float_to_string(*f)),
        _ => None,
    }
}

/// Names the type of a key that is not a string, and its value where it has a short one.
///
/// A refusal carrying the location and nothing else would, in a run over a directory of templates,
/// tell the reader neither which key nor -- since the location is all it has -- which of several
/// thousand lines in which of N files. The location alone also cannot be searched for: a reader who
/// sees `L:2,C:4` cannot grep for it.
///
/// Only the keys `stringify_scalar_key` has no text for reach this, so in practice it names a null, a
/// sequence, a mapping or a tagged scalar that is not its type; a `Refused` key is refused with the
/// message it carries before this is reached. The value is still rendered for the scalars it has one
/// for, and the `Refused` arm is kept, because the enum is total and a variant added to
/// `MarkedValue` should not silently lose its name.
fn describe_key(key: &MarkedValue) -> String {
    match key {
        MarkedValue::Null(..) => "null".to_string(),
        MarkedValue::Bool(b, ..) => format!("the boolean {b}"),
        MarkedValue::Int(i, ..) => format!("the integer {i}"),
        MarkedValue::Float(f, ..) => format!("the float {f}"),
        MarkedValue::Char(c, ..) => format!("the character {c}"),
        MarkedValue::List(..) => "a sequence".to_string(),
        MarkedValue::Map(..) => "a mapping".to_string(),
        // The text alone, then the reason's `why` when there is one. The advice that follows is the
        // caller's, and for a key with a reason it is the reason's own (see `key_fix`): quoting a
        // tagged key gives neither reading, so "Quote it to make it a string" is not the fix there.
        MarkedValue::BadValue(val, None, ..) => format!("an unreadable value, {val}"),
        MarkedValue::BadValue(val, Some(reason), ..) => {
            format!("an unreadable value, {val}: {}", reason.why())
        }
        MarkedValue::Refused(refusal, ..) => format!("a refused value, {refusal}"),
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
enum IntScalar<'a> {
    /// An integer, and this is its value.
    Resolved(i64),
    /// A decimal with a redundant leading zero, `0755`. It stays a string by this loader's own rule
    /// (below), the same string `serde_yaml` gives it, so as a key it is ordinary text. The float
    /// resolver does not get a turn: `"0755".parse::<f64>()` is 755.0. The sign and the digits after
    /// the leading zeros are carried so that the `!!int` arm, which has to decide what the spelling
    /// means under the tag, reads them from here rather than parsing the text a second time; the
    /// range is not checked, so `significant` may be too wide for an `i64`.
    LeadingZero {
        negative: bool,
        significant: &'a str,
    },
    /// Integer-shaped and in a radix this loader resolves, but wider than `i64`. It stays a string
    /// because there is no integer to give it, a literal kept where YAML would resolve it (see
    /// `KeyForm::Literal`). The float resolver does not get a turn -- these parse as floats, and
    /// handing them on would swap one wrong number for another.
    OutOfRange,
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
/// `-0x10` is -16. No YAML version reads that text as a *different* number, and `serde_yaml` resolves it
/// too, so accepting it closes a divergence rather than opening one and cannot introduce a wrong value.
///
/// **A decimal integer with a redundant leading zero stays a string**, so `0755` is the text "0755".
/// This is the class of spellings where the two YAML versions can assign *different values* to the
/// same characters: 1.1 reads `0755` as octal 493 (<https://yaml.org/type/int.html>), 1.2 core's
/// decimal regex reads it as 755 (`007` is 7 to both, and `08` is no integer at all to 1.1). A file
/// mode or a netmask written `0755` almost certainly means 493, so resolving it either way silently
/// produces a number the author did not write; keeping the literal is the only answer that cannot be
/// quietly wrong, it is one rule for the whole class rather than a spelling at a time, and it is also
/// what `serde_yaml` does.
///
/// The prefixes are lowercase only, which is 1.2 core's regex exactly and what `serde_yaml` does:
/// `0X1F` and `0O17` are strings. One divergence from `serde_yaml` is left standing on purpose:
/// `0b101` is a string here and an integer there. YAML 1.2 core has no binary form -- it is 1.1's --
/// and following the extension would mean re-adding a 1.1-ism of exactly the kind the boolean set
/// dropped.
fn resolve_int(val: &str) -> IntScalar<'_> {
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
        return IntScalar::LeadingZero {
            negative,
            significant: digits.trim_start_matches('0'),
        };
    }

    let signed = if negative {
        Cow::Owned(format!("-{digits}"))
    } else {
        Cow::Borrowed(digits)
    };

    match i64::from_str_radix(&signed, radix) {
        Ok(i) => IntScalar::Resolved(i),
        // An integer literal too wide for `i64`. Falling through to the float resolver, which
        // accepts it, would turn `9223372036854775809` into `Float(9.223372036854776e18)` -- and
        // `9223372036854775810`, a different integer, into the same float. The two would then
        // compare *equal*, and a clause asserting they differ would be reported non-compliant: a
        // wrong answer about identity, produced silently.
        //
        // The literal is kept instead. `MarkedValue::Int` is an `i64`, so there is no arm here that
        // can hold the value: widening it reaches `PathAwareValue::Int` and from there every
        // comparison operator, the serializers and SARIF, which is a change of a different size and
        // shape than this one. `serde_yaml` holds `i64::MAX + 1` as an integer and refuses anything
        // past `u64`; keeping the text agrees with neither, but it is the only option here that
        // never reports two distinct integers as one.
        Err(_) => IntScalar::OutOfRange,
    }
}

/// The spellings a plain scalar is read as boolean: the YAML 1.2 core schema's set, which is the
/// whole of `true | True | TRUE | false | False | FALSE`
/// (<https://yaml.org/spec/1.2.2/#103-core-schema>, which resolves every other spelling to `str`).
///
/// Three casings of each word and no others, so `tRuE` is a string. Matching case-insensitively
/// would have been shorter and would have accepted spellings no schema makes boolean.
///
/// YAML 1.1's set of 22 (<https://yaml.org/type/bool.html>) adds `y`, `Y`, `n`, `N`, `yes`, `no`,
/// `on`, `off` and their casings; those are strings here. Three separate readers of the same document
/// agree with the 1.2 set and not with 1.1's:
///
///   - `rules::parser::parse_bool`, which reads a boolean literal in cfn-guard's own grammar,
///     accepts exactly the six spellings above. Reading `yes` as a boolean here would compare
///     `Enabled == true` and a document writing `Enabled: yes` across two different vocabularies.
///   - `serde_yaml`, which was the loader `guard test` and the public `run_checks` reached on the same
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
/// The cost runs the other direction: a document that writes `Encrypted: yes` meaning true yields
/// the string "yes", and a clause comparing it to `true` reports the type mismatch instead of
/// passing. That is the trade, and it is the right way round -- the tool says it cannot decide
/// rather than deciding by a rule none of its other three readers share. No
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

/// The spellings that resolve to the null node: the YAML 1.2 core schema's `null | Null | NULL | ~`
/// (<https://yaml.org/spec/1.2.2/#103-core-schema>) and the empty scalar, which both YAML versions
/// resolve to null. Three casings of the word and no others, as for the booleans above.
fn is_null_spelling(s: &str) -> bool {
    matches!(s, "" | "~" | "null" | "Null" | "NULL")
}

/// Wraps a `!Foo`-tagged scalar as `{ "Fn::Foo": payload }`.
///
/// Every `!Foo` is wrapped, and `long_form_of` supplies the name; no hand-written set of known
/// intrinsics gates this. Gating on one and discarding the tag on a miss would turn the short form of
/// any intrinsic the set did not list into something else entirely: `!Transform { ... }` would be
/// indistinguishable from a plain mapping and a rule forbidding the macro would pass at exit 0, where
/// the long `Fn::Transform` spelling of the same template fails. That is the opposite of how `!!`-tags
/// behave -- `!!int abc` becomes a `BadValue` and is reported -- so a bad type tag would be loud and an
/// unknown function tag silent. A set per position would also set a trap: a name listed for scalars
/// but not for sequences, or the reverse, would lose its tag in the other position even though the
/// loader knew it.
///
/// The payload is the text the document wrote, on purpose: a node with a specific tag is not
/// implicitly resolved, the tag being its type, so `!Ref 123` carries "123" and a bare `!GetAZs` the
/// empty text, as cfn-lint and cfn-flip read them. `!GetAtt` is the one payload read further.
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

/// `warnings` is the loader's list: a tag read past (see `UnreadTag`) is pushed there for the caller
/// to print, since library code writes nothing to stderr.
fn handle_type_ref(
    val: String,
    loc: Location,
    type_ref: &str,
    warnings: &mut Vec<UnreadTag>,
) -> MarkedValue {
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
        // Measured, `serde_yaml` accepts exactly these six spellings under `!!bool` and refuses every
        // other payload outright, `y`, `on`, `off`, `no`, `0`, `1` and `tRuE` included. So refusing here is
        // what makes the two agree. PyYAML errors on an out-of-set payload too, though it takes the
        // YAML 1.1 words: it is a 1.1 implementation, and following it would put the boolean
        // vocabulary of a document under the control of whether a tag was written.
        "tag:yaml.org,2002:bool" => match parse_bool(&val) {
            None => refused_type_ref(type_ref, &val, loc),
            Some(v) => MarkedValue::Bool(v, loc),
        },
        // Through `resolve_int`, the resolver a plain scalar gets, and refused when it does not resolve.
        //
        // This read `str::parse::<i64>`, decimal only, after the plain arm had moved to the YAML 1.2
        // core forms. So `Mode: !!int 0o755` was a `BadValue` and the whole file was refused at exit
        // 5, while the same document with the tag removed loaded as 493 and the rules ran: making the
        // type explicit is what broke a valid document. `serde_yaml` resolves the tagged radix forms,
        // so this also closes a divergence with the loaders the other routes reached.
        //
        // A payload `resolve_int` will not commit to is a `BadValue`, as `!!int abc` always was: an
        // explicit type tag has no string to fall back to. That covers `abc`, `1.5` and an integer
        // wider than `i64`.
        //
        // A decimal with a redundant leading zero is the one answer the tag changes. Untagged,
        // `resolve_int` keeps every such spelling as text, one rule for the class, because YAML 1.1
        // reads `0755` as octal 493 and 1.2 core as decimal 755, and a file mode or a netmask written
        // with the zero almost always means the octal reading. Under `!!int` the author has said the
        // node is an integer, but not which radix the digits are in, so the two readings are taken
        // and compared (see `tagged_leading_zero_int`): where they are the same number, `007` and
        // `00`, that number is the answer; where they differ, `0755`, or where YAML 1.1 has no
        // reading at all, `08`, the payload is refused with a reason that names both readings and the
        // plain-decimal integer each one means, because a string of digits refused as "not an
        // integer" would otherwise explain nothing.
        //
        // This arm once handed every answer other than `Resolved` to `str::parse::<i64>`, so
        // `!!int 0755` loaded as 755 with nothing said; `OutOfRange` and `NotAnInteger` never passed
        // that read, so the fallback was the leading-zero rule's one escape. It then refused the
        // whole class, `007` included. Under both refusal policies the answer here is a value or a
        // `BadValue`, never a `Refused` node, so `RefusalPolicy` does not change it.
        "tag:yaml.org,2002:int" => match resolve_int(&val) {
            IntScalar::Resolved(i) => MarkedValue::Int(i, loc),
            IntScalar::LeadingZero {
                negative,
                significant,
            } => tagged_leading_zero_int(type_ref, &val, negative, significant, loc),
            IntScalar::OutOfRange | IntScalar::NotAnInteger => {
                refused_type_ref(type_ref, &val, loc)
            }
        },
        // The plain arm's gate, applied here too: finite, and not an underflow to zero.
        //
        // This read `str::parse::<f64>` and took whatever it answered. `f64::from_str` accepts `nan`,
        // `inf` and `infinity`, so `!!float nan` built a `Float(NaN)`, which `PathAwareValue` cannot
        // hold -- it asserts `Eq` and hashes its contents -- and no reporter can serialize: the run
        // printed its verdict and then exited 255 on "Could not convert float NaN to
        // serde::Value::Number", with `-o json` cut off mid-document. `!!float inf` passed `!= 1.0`.
        // And `1e-400` parses to a silent `0.0`, so `!!float 1e-400` answered `== 0` with a PASS for a
        // literal the author wrote as positive: the defect `underflowed_to_zero` was written for,
        // reached through the one arm it was not applied to.
        //
        // A payload that fails the gate is a `BadValue`, not a string. The untagged arm falls back to
        // the literal text; under an explicit `!!float` there is nothing to fall back to. YAML's own
        // `.inf` and `.nan` spellings already came out as `BadValue` here, because `f64::from_str`
        // does not read them, so a non-finite float is now refused under the tag however it is
        // spelled. `serde_yaml` refuses `!!float nan` and `!!float inf` outright as well.
        "tag:yaml.org,2002:float" => match val.parse::<f64>() {
            Ok(v) if v.is_finite() && !underflowed_to_zero(&val, v) => MarkedValue::Float(v, loc),
            _ => refused_type_ref(type_ref, &val, loc),
        },
        // The YAML 1.2 core null set, and refused outside it.
        //
        // This returned `Null` without reading the payload, so `IsLogging: !!null false` was a null
        // and the `false` was gone with no diagnostic, where `!!bool abc` and `!!int abc` next door are
        // both `BadValue`s. A rule `IsLogging == false` then reported "not comparable null, bool" for
        // a document whose author had written `false`, and nothing in any output said why. PyYAML
        // answers None for any `!!null` payload, which is where the old behavior came from; the core
        // schema's own regex for the type does not resolve a payload outside the set, and refusing
        // matches what every other type tag here does with text it cannot read.
        "tag:yaml.org,2002:null" if is_null_spelling(&val) => MarkedValue::Null(loc),
        "tag:yaml.org,2002:null" => refused_type_ref(type_ref, &val, loc),
        // The yaml.org types whose scalar is a string. `!!str` is the common one. `!!binary` and
        // `!!timestamp` are YAML 1.1 types this loader does not decode, and the text is the honest
        // reading of both; `!!value` is the `=` key.
        "tag:yaml.org,2002:str"
        | "tag:yaml.org,2002:binary"
        | "tag:yaml.org,2002:timestamp"
        | "tag:yaml.org,2002:value" => MarkedValue::String(val, loc),
        // `!!merge` is the merge key's own type. Over `<<` it is a merge key, which
        // `handle_scalar_event` records (the index is decided there, where the style is known) and
        // `handle_mapping_end` folds; the scalar itself is the key's text. Over anything else it names
        // a type the payload cannot be, as `!!bool maybe` does, and is refused the same way.
        "tag:yaml.org,2002:merge" if val == MERGE_KEY => MarkedValue::String(val, loc),
        "tag:yaml.org,2002:merge" => refused_type_ref(type_ref, &val, loc),
        // Any other `!!` tag: refused if it spells an intrinsic, read as text with a warning if not.
        //
        // This arm was `_ => String`, so a `!!`-spelled tag the loader did not know was dropped and
        // its payload evaluated as a plain string: `RoleName: !!Ref Foo`, a typo of `!Ref Foo`, loaded
        // as "Foo", a rule `RoleName == "Foo"` passed at exit 0, and nothing named the tag. An unknown
        // `!Foo` is kept as `Fn::Foo` (see `wrap_tagged_scalar`) and a known `!!` tag over a bad
        // payload is a `BadValue`, so this was the one silent route left.
        //
        // Refusing every unknown `!!` tag would stop a `-d .` walk on an ordinary YAML file from
        // another dialect, `!!python/name:x` say, which is not a typo of anything cfn-guard reads. So
        // only a tag that spells an intrinsic is refused (see `looks_like_an_intrinsic_name`); the rest
        // load as text, and the warning the caller prints is what keeps that from being silent.
        _ => {
            let short = type_ref.strip_prefix(TYPE_REF_PREFIX).unwrap_or(type_ref);
            if looks_like_an_intrinsic_name(short) {
                refused_type_ref(type_ref, &val, loc)
            } else {
                warnings.push(UnreadTag {
                    tag: short.to_string(),
                    location: loc,
                });
                MarkedValue::String(val, loc)
            }
        }
    }
}

/// The events of `input` that the node ceiling counts, read in a pass of their own: every event other
/// than stream and document bookkeeping and aliases ([`MAX_ALIAS_EXPANSION_NODES_PER_EVENT`] says why
/// those two are left out, and when the pass runs).
///
/// A failure to parse ends the count where it happened and is not reported here; the loading pass
/// meets the same failure at the same place and reports it, so this pass never has to say anything.
fn count_ceiling_events(input: &[u8]) -> usize {
    let mut parser = Parser::new(Cow::Borrowed(input));
    let mut events = 0;
    loop {
        match parser.next() {
            Ok((Event::StreamEnd, _)) | Err(_) => return events,
            Ok((
                Event::StreamStart | Event::DocumentStart | Event::DocumentEnd | Event::Alias(..),
                _,
            )) => {}
            Ok(_) => events += 1,
        }
    }
}

/// Whether a `!!` suffix reads as a CloudFormation intrinsic written with one `!` too many.
///
/// `!!Ref Foo` and `!!If [...]` are typos of `!Ref` and `!If`, and the tag is what the author got
/// wrong, so they are refused with the tag named. Tags from another YAML dialect's namespace --
/// `!!python/name:x`, `!!binary`'s cousins -- are not typos of anything cfn-guard reads and load as
/// text instead. Intrinsics are capitalized and every name in the short-form table is, so a leading
/// ASCII uppercase letter is the test, with the table consulted too so a listed name is refused even
/// if it ever gained a lowercase spelling.
fn looks_like_an_intrinsic_name(short: &str) -> bool {
    short.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        || rules::SHORT_FORM_TO_LONG_MAPPING.contains_key(short)
}

/// The `BadValue` for a payload a `!!` type tag cannot read: the node as the document wrote it, tag
/// included, so `!!bool maybe` rather than `maybe`.
///
/// A refusal carrying the payload alone would build the report "Bad Value encountered parsing
/// incoming file Value = maybe", which does not say that a tag is what made the text unreadable. A
/// payload that is empty gives just the tag.
fn refused_type_ref(type_ref: &str, val: &str, loc: Location) -> MarkedValue {
    MarkedValue::BadValue(type_ref_as_written(type_ref, val), None, loc)
}

/// The node as the document wrote it, tag included: `!!bool maybe`, or just `!!bool` for an empty
/// payload.
fn type_ref_as_written(type_ref: &str, val: &str) -> String {
    let short = type_ref.strip_prefix(TYPE_REF_PREFIX).unwrap_or(type_ref);
    if val.is_empty() {
        format!("!!{short}")
    } else {
        format!("!!{short} {val}")
    }
}

/// What `!!int` makes of a decimal with a redundant leading zero: the integer, when YAML 1.1's octal
/// reading and YAML 1.2's decimal reading of the digits are the same number, and otherwise a
/// `BadValue` holding the node as written, with a reason beside it that carries both readings for
/// the message to name, each as the plain-decimal integer it means.
///
/// `negative` and `significant` are what `resolve_int` read: the sign, and the digits after the
/// leading zeros (empty for `00`). The two readers agree only when at most one significant digit
/// remains and it is an octal digit: `00` is 0 and `007` is 7 under both. A digit 8 or 9 is no octal
/// digit, so YAML 1.1 reads no integer there at all, and two or more significant digits are two
/// different numbers.
///
/// Each reading the reason carries is the result of reading a candidate spelling back through
/// `resolve_int`, the resolver the author's rewrite will meet, so nothing is offered that would not
/// load; a reading too wide for an `i64` is carried as such and named instead of offered. The octal
/// reading is offered as a plain decimal, 493 for `0755`, and the `0o` spelling is not named at all,
/// because a YAML 1.1 reader, CloudFormation among them, has no `0o` form and would read `0o755` as
/// a string.
fn tagged_leading_zero_int(
    type_ref: &str,
    val: &str,
    negative: bool,
    significant: &str,
    loc: Location,
) -> MarkedValue {
    let octal_digits = significant.chars().all(|c| c.is_digit(8));
    if octal_digits && significant.len() <= 1 {
        let digit = significant
            .chars()
            .next()
            .and_then(|c| c.to_digit(8))
            .map_or(0, i64::from);
        return MarkedValue::Int(if negative { -digit } else { digit }, loc);
    }

    let sign = if negative { "-" } else { "" };
    // The candidates are a signed run of decimal digits and a signed `0o` run of octal digits, which
    // `resolve_int` reads as an integer or finds too wide; nothing else can come back. The octal
    // candidate is read first: where it is too wide the decimal one is too, since with the zeros
    // gone two or more digits read strictly smaller as octal than as decimal, so that case needs no
    // decimal read and has no state of its own.
    let reads_as = |candidate: String| match resolve_int(&candidate) {
        IntScalar::Resolved(i) => Some(i),
        _ => None,
    };
    let readings = if !octal_digits {
        LeadingZeroReadings::NoOctalReading {
            decimal: reads_as(format!("{sign}{significant}")),
        }
    } else {
        match reads_as(format!("{sign}0o{significant}")) {
            None => LeadingZeroReadings::BothTooWide,
            Some(octal) => match reads_as(format!("{sign}{significant}")) {
                Some(decimal) => LeadingZeroReadings::BothFit { decimal, octal },
                None => LeadingZeroReadings::OctalOnlyFits { octal },
            },
        }
    };

    MarkedValue::BadValue(
        type_ref_as_written(type_ref, val),
        Some(BadValueReason::LeadingZero(readings)),
        loc,
    )
}

#[cfg(test)]
#[path = "loader_tests.rs"]
mod loader_tests;
