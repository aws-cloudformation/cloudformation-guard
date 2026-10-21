use crate::rules::values::*;

use crate::rules::display::ValueOnlyDisplay;
use crate::rules::path_value::PathAwareValue;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt::Formatter;
use std::hash::Hash;
use std::rc::Rc;

use super::eval_context::FunctionName;

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct FileLocation<'loc> {
    pub(crate) line: u32,
    pub(crate) column: u32,
    #[serde(skip_serializing, skip_deserializing)]
    pub(crate) file_name: &'loc str,
}

impl<'loc> std::fmt::Display for FileLocation<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!(
            "Location[file:{}, line:{}, column:{}]",
            self.file_name, self.line, self.column
        ))?;
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) enum LetValue<'loc> {
    Value(PathAwareValue),
    AccessClause(AccessQuery<'loc>),
    FunctionCall(FunctionExpr<'loc>),
}

///
/// This expression encapsulates assignment expressions inside a block expression
/// or at the file let. An assignment can either be a direct Value object or access
/// from incoming context. Access expressions support **predicate** queries to help
/// match specific selections.
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct LetExpr<'loc> {
    pub(crate) var: String,
    pub(crate) value: LetValue<'loc>,
}

///
/// Access is defined using a predicate query model. The query is defined using a simple
/// dotted expression starting from the root to the each node that we want to select. Each
/// query part can map to one of the following
///
/// * Key = String that specifies the key that must be mapped to. This is an actual exact match
/// and it is expected to be map to a struct with type defined usually with `{` and `}`. Use the
/// key to be '*' to indicate selecting all fields for an object. `*` returns an array and is therefore
/// eligible for predicate based selection
/// * Predicate query, which selects instances from an array of structure. If we need to
/// select all entries in the array use the `[*]` syntax. To select specific elements in the array
/// use the structural key matches. E.g. to select all resources from an CFN template that match the
/// DynamoDB Table we can use the following `resources.*[type=/AWS::Dynamo/]`
///
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) enum QueryPart<'loc> {
    This,
    Key(String),
    /// A variable reference, `%name`, holding the name without its `%`.
    ///
    /// Only the parser's `%name` production builds this variant, so a `Key` is always the key it spells.
    /// A quoted key that happens to begin with `%` -- `."%foo"`, `["%foo"]` -- is a `Key("%foo")` and
    /// nothing else. Were a variable a `Key` whose text kept the `%`, with `is_variable` reading the
    /// prefix, such a key would be interpolated as the variable `foo`, the run would exit 5 with "Could
    /// not resolve variable by name foo across scopes", and no spelling could reach it as a key.
    ///
    /// `Display` writes the `%` back, so every rendered query and `Context=` line is byte for byte what
    /// it was. The serialized tree is not: `parse-tree` prints `Variable: name` where it printed
    /// `Key: '%name'`, and the goldens moved with it.
    Variable(String),
    MapKeyFilter(Option<String>, MapKeyFilterClause<'loc>),
    AllValues(Option<String>),
    AllIndices(Option<String>),
    /// The author's own bare `[*]`, standing where `access_query` would otherwise have reserved a slot.
    ///
    /// Behaves as `AllIndices(None)` everywhere: it renders `[*]`, it expands a list, and it is a
    /// pass-through on a map. The one thing it says that `AllIndices(None)` cannot is **who wrote it**.
    ///
    /// That distinction is the whole reason this variant exists. `access_query` reserves slot 1 of every
    /// variable-rooted query with a remainder, and declines to insert when a bare `[*]` already occupies
    /// the position -- so the part it inserts is byte-identical to the part it declines to displace.
    /// Once the insert was made, nothing in the AST said which had happened, and the root-variable arm of
    /// `query_retrieval_with_converter` had to re-derive it from the shape of slot **2**: a bare `[*]`
    /// there could only come from the author having written one at slot 1 as well, because the insert
    /// would not have fired in front of it. That proxy is sound in one direction only, and four spellings
    /// fell in the gap, each pair parsing to the same parts:
    ///
    /// - `%v[*].*` and `%v.*`
    /// - `%v[*][ n ]` and `%v[ n ]`
    /// - `%v[0]` and `%v[*][0]`
    /// - `%v[-1]` and `%v[*][-1]`
    ///
    /// The `Index` pairs were the severe ones, and they broke the plain spelling rather than the rare
    /// one. `expansion_at` excludes `Index` by design, so the proxy read `%v[0]` as "nothing enumerates
    /// after the slot", walked the slot, and applied the index to each member of the collection instead
    /// of to the collection. Measured over `Outer: {Tags: [{Key: Name, Value: alpha}]}` with
    /// `let g = Outer.Tags`, both at exit 19 and differing only in message, so an exit-code comparison
    /// reports them as agreeing:
    ///
    /// ```text
    /// Outer.Tags[0] == 'zzz'   PathAwareValues are not comparable map, String
    /// %g[0] == 'zzz'           Attempting to retrieve from index 0 but type is not an array
    /// ```
    ///
    /// Over a list of lists the same fault is a silent pass rather than a different message: with
    /// `Deep: {Groups: [[1,2],[1,3]]}`, `%g[0] == 1` exits 0 where `Deep.Groups[0] == 1` exits 19.
    ///
    /// Marking the author's `[*]` rather than the parser's slot, which is the same bit read the other
    /// way round, is deliberate. The reserved slot appears in every `%v.X` query and so in `parse-tree`
    /// output and in the rendered `Context=` of every verbose report; giving *it* a distinct tag would
    /// move those goldens. The author's `[*]` at slot 1 appears in no fixture in this repository, so
    /// this spelling of the same fact leaves every rendered query and every serialized tree byte for
    /// byte as it was. `Display` emits `[*]` for exactly that reason.
    AuthoredIndices,
    /// An array index as written in the rule, kept at the width the parser reads.
    ///
    /// An `i32` here, with the parsed value narrowed by `as i32`, wraps instead of rejecting:
    /// `Items[4294967296]` becomes `Items[0]` and the clause then compares the wrong element and
    /// passes. Retrieval reports an out-of-range index as unresolved, so the width is all that has to
    /// be right -- the bounds check does the rejecting.
    Index(i64),
    Filter(Option<String>, Conjunctions<GuardClause<'loc>>),
}

impl<'loc> QueryPart<'loc> {
    pub(crate) fn is_variable(&self) -> bool {
        matches!(self, QueryPart::Variable(_))
    }

    pub(crate) fn variable(&self) -> Option<&str> {
        match self {
            QueryPart::Variable(name) => Some(name),
            _ => None,
        }
    }
}

impl<'loc> std::fmt::Display for QueryPart<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryPart::Key(s) => {
                f.write_str(s.as_str())?;
            }

            // With its `%`, which is how the text spelled it and what every rendered query showed.
            QueryPart::Variable(name) => {
                write!(f, "%{}", name)?;
            }

            // Byte-identical to `AllIndices`, which is what keeps every rendered query and every
            // verbose `Context=` unchanged by this variant existing. See its declaration.
            QueryPart::AllIndices(..) | QueryPart::AuthoredIndices => {
                f.write_str("[*]")?;
            }

            QueryPart::AllValues(_name) => {
                f.write_str("*")?;
            }

            QueryPart::Index(idx) => {
                write!(f, "{}", idx)?;
            }

            // The space separates a capture name from the parenthetical (`p (filter-clauses)`) and is
            // kept when there is no name (` (filter-clauses)`): it is the part's own separator, and the
            // query join (`SliceDisplay`, by `SeamPart`: the part's kind, not this text) adds no `.`
            // before an unnamed filter, so it renders `Resources.* (filter-clauses)` after the part it
            // follows. Dropping the space here instead would move every text that BEGINS with a filter
            // part (a binding's remaining query, the console's `MissingProperty` line), which the join
            // never touches.
            QueryPart::Filter(name, _c) => {
                f.write_fmt(format_args!(
                    "{} (filter-clauses)",
                    name.as_ref().map_or("", String::as_str)
                ))?;
            }

            QueryPart::MapKeyFilter(name, _clause) => {
                f.write_fmt(format_args!(
                    "{} (map-key-filter-clauses)",
                    name.as_ref().map_or("", String::as_str)
                ))?;
            }

            QueryPart::This => {
                f.write_str("_")?;
            }
        }
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct AccessQuery<'loc> {
    pub(crate) query: Vec<QueryPart<'loc>>,
    pub(crate) match_all: bool,
}

//pub(crate) type AccessQuery<'loc> = Vec<QueryPart<'loc>>;

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct AccessClause<'loc> {
    pub(crate) query: AccessQuery<'loc>,
    pub(crate) comparator: (CmpOperator, bool),
    pub(crate) compare_with: Option<LetValue<'loc>>,
    pub(crate) custom_message: Option<String>,
    pub(crate) location: FileLocation<'loc>,
}

impl<'loc> Default for AccessClause<'loc> {
    fn default() -> Self {
        AccessClause {
            query: AccessQuery {
                query: vec![],
                match_all: true,
            },
            custom_message: None,
            location: FileLocation {
                file_name: "",
                line: 0,
                column: 0,
            },
            compare_with: None,
            comparator: (CmpOperator::Eq, false),
        }
    }
}

pub(crate) type Disjunctions<T> = Vec<T>;
pub(crate) type Conjunctions<T> = Vec<Disjunctions<T>>;

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct GuardAccessClause<'loc> {
    pub(crate) access_clause: AccessClause<'loc>,
    pub(crate) negation: bool,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct MapKeyFilterClause<'loc> {
    pub(crate) comparator: MapKeyComparator,
    pub(crate) compare_with: LetValue<'loc>,
    /// Where the filter's `keys` keyword sits in the rules file: the site a notice about this filter
    /// is recorded once for, and names.
    pub(crate) location: FileLocation<'loc>,
}

/// The comparators a map key filter can be written with.
///
/// This field held a `(CmpOperator, bool)`, which can express every operator in the language while
/// `map_keys_match` parses exactly these four. The gap was not free. `real_binary_operation` -- whose
/// only caller is the map key filter -- carried arms for `Ge`, `Gt`, `Lt` and `Le` that no rules
/// file could reach, and they recorded zero executions against a 288-clause matrix using those very
/// operators. Dead code that looks live is worse than dead code that looks dead: the arms duplicate
/// the comparison logic, so someone fixing a comparison bug would naturally edit the one calling
/// `compare_ge` and see no effect anywhere.
///
/// Narrowing the type is what makes those arms impossible rather than merely unused, which is why
/// this is an enum here instead of a comment there.
#[derive(Eq, PartialEq, Debug, Clone, Copy, Serialize, Deserialize, Hash)]
pub(crate) enum MapKeyComparator {
    Eq,
    NotEq,
    In,
    NotIn,
}

impl MapKeyComparator {
    /// The wider pair, for the comparison records the reporters render.
    pub(crate) fn as_cmp_operator(self) -> (CmpOperator, bool) {
        match self {
            MapKeyComparator::Eq => (CmpOperator::Eq, false),
            MapKeyComparator::NotEq => (CmpOperator::Eq, true),
            MapKeyComparator::In => (CmpOperator::In, false),
            MapKeyComparator::NotIn => (CmpOperator::In, true),
        }
    }

    /// Equality against a set of right-hand values is membership.
    ///
    /// `keys == %several` reads as "each key equals" and is evaluated as "is among", which is what
    /// the `Eq`-with-multiple-values promotion has always done. Deciding WHEN the right-hand side is a
    /// set is `eval::key_filter::key_comparator`'s, the one caller; this is the promotion itself, kept
    /// as a method so the rule is stated once rather than inline in the evaluator. `In` and `NotIn`
    /// are already membership and are returned as they are.
    pub(crate) fn as_membership(self) -> Self {
        match self {
            MapKeyComparator::Eq => MapKeyComparator::In,
            MapKeyComparator::NotEq => MapKeyComparator::NotIn,
            membership => membership,
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct GuardNamedRuleClause<'loc> {
    pub(crate) dependent_rule: String,
    pub(crate) negation: bool,
    pub(crate) custom_message: Option<String>,
    pub(crate) location: FileLocation<'loc>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct BlockGuardClause<'loc> {
    pub(crate) query: AccessQuery<'loc>,
    pub(crate) block: Block<'loc, GuardClause<'loc>>,
    pub(crate) location: FileLocation<'loc>,
    pub(crate) not_empty: bool,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct WhenGuardBlockClause<'loc> {
    pub(crate) conditions: WhenConditions<'loc>,
    pub(crate) block: Block<'loc, GuardClause<'loc>>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct ParameterizedNamedRuleClause<'loc> {
    pub(crate) parameters: Vec<LetValue<'loc>>,
    pub(crate) named_rule: GuardNamedRuleClause<'loc>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct FunctionExpr<'loc> {
    pub(crate) parameters: Vec<LetValue<'loc>>,
    pub(crate) name: FunctionName,
    pub(crate) location: FileLocation<'loc>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) enum GuardClause<'loc> {
    Clause(GuardAccessClause<'loc>),
    NamedRule(GuardNamedRuleClause<'loc>),
    ParameterizedNamedRule(ParameterizedNamedRuleClause<'loc>),
    BlockClause(BlockGuardClause<'loc>),
    WhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) enum WhenGuardClause<'loc> {
    Clause(GuardAccessClause<'loc>),
    NamedRule(GuardNamedRuleClause<'loc>),
    ParameterizedNamedRule(ParameterizedNamedRuleClause<'loc>),
}

pub(crate) type WhenConditions<'loc> = Conjunctions<WhenGuardClause<'loc>>;

/// Read the filter capture names a clause declares out of the rule text.
///
/// A block has to know these *before* it evaluates anything, because the case that needs them is an
/// iteration that captured nothing: it has no key to show, and "was this name meant to hold one?"
/// cannot be answered from what happened at runtime. Learning names as keys are captured would make the
/// verdict depend on document order -- the same two buckets give FAIL in one order and a file-fatal
/// error in the other, because whichever bucket runs first is the one that teaches the engine the name
/// exists at all.
///
/// Named rules are deliberately not followed. A capture made inside one does not resolve outside it,
/// so a name it declares is not a name the calling block can answer for.
pub(crate) trait CaptureNames<'value> {
    fn collect_capture_names(&'value self, into: &mut BTreeSet<&'value str>);
}

/// Every capture name a block could populate, including the ones in its nested blocks.
///
/// Nested blocks are included because they hand their captures up when they exit, so the outer block
/// is where a name a nested block failed to capture is read.
pub(crate) fn block_capture_names<'value, 'loc: 'value, T>(
    block: &'value Block<'loc, T>,
) -> BTreeSet<&'value str>
where
    T: CaptureNames<'value>,
{
    let mut names = BTreeSet::new();
    for assignment in &block.assignments {
        collect_let_value_capture_names(&assignment.value, &mut names);
    }
    collect_conjunctions_capture_names(&block.conjunctions, &mut names);
    names
}

/// A name one scope both assigns and declares as a filter capture, with a description of the scope.
///
/// The same root cause as a name assigned twice in one scope, which `first_duplicate_assignment`
/// refuses, reaching the one map that check does not look at. A scope's runtime object files an
/// assignment's value under its kind -- literal, query or function call -- and holds a capture's keys in
/// a map of their own, and `resolve_variable` consults them in a fixed order with the captures between
/// the literals and the queries. So a name in both resolves by the *kind* of the assignment rather than
/// by anything the author wrote: over a bucket whose enabled config is named `alpha`, in one block,
///
/// ```text
/// let cfg = "fromlet"          + Properties.Config[ cfg | Enabled == true ]   ->  %cfg is "fromlet"
/// let cfg = Properties.Name    + Properties.Config[ cfg | Enabled == true ]   ->  %cfg is "alpha"
/// ```
///
/// and writing the `let` after the capturing clause instead of before it changes neither.
///
/// The line is drawn on *lexical* nesting: a scope's captures are the ones declared by the text written
/// directly in it, and a capture written inside a nested `{ ... }` belongs to that nested scope. So an
/// assignment in an enclosing scope with a capture in a nested block is ordinary shadowing and is
/// accepted -- the more local declaration wins, which is what every other pair of nested bindings in
/// this language does and is the one rule an author can carry between them.
///
/// Drawing the line on where a block's keys land at runtime instead, with `block_capture_names`, which
/// descends into nested blocks because that is where their merged keys arrive, makes two files an author
/// cannot tell apart disagree: a rule-body `let` with a capture in a block inside the rule is refused,
/// while the same capture with the `let` moved out to the file level is accepted. Both are "an
/// assignment outside, a capture in a block inside".
///
/// What that costs is one case, and it is a real one rather than a theoretical one. A rule-body
/// assignment still decides by kind against the keys a nested block merges up, for a clause reading the
/// name at rule-body level *after* the block:
///
/// ```text
/// rule r {
///     let cfg = <value>
///     Resources.*[ Type == 'AWS::S3::Bucket' ] { Properties.Config[ cfg | Enabled == true ] !empty }
///     %cfg == ...
/// }
/// ```
///
/// with `let cfg = "fromlet"` the read is `"fromlet"` and with `let cfg = Properties.Name` it is the
/// captured key. Accepted anyway, because refusing it is what made the check unexplainable, and because
/// the reading that matters -- `%cfg` from inside the block -- is the capture's under both spellings.
///
/// The file level is a scope too, and a rule's `when` conditions are written at the rule's head, outside
/// the body's braces, so they are lexically part of it. Measured rather than assumed, since the
/// conditions could have belonged to the rule's own scope: see
/// `a_name_both_assigned_and_captured_in_one_scope_is_rejected` for the two spellings and what each
/// resolved to. A rule *body* is its own scope, so a capture inside one is not the file level's.
///
/// The captures that reach past the braces they open are refused against an assignment in *any*
/// enclosing scope, not only their own, and there is one rule for every such site: the condition of a
/// nested `when`, a block clause's own query, and a type block's condition (and its query, should the
/// grammar ever let one carry a name). Each is written on a construct that opens braces, and each binds
/// outside them: the `when` condition and the block clause's query are evaluated in the block the
/// construct is written in, so the capture lands in that block's own capture map and is read ahead of
/// every enclosing binding by every clause in the block, including a sibling that never wrote the name;
/// the type block's condition runs in the per-resource scope, which hands its captures up to the rule's
/// scope as merged keys that a rule-level clause after the block reads the same way. With a file-level
/// `let buckets = Resources.*[ ... ]`, a block over the roles holding
/// `when Properties.Props[ buckets | Enabled == true ] !empty { ... }` and a sibling
/// `when Properties exists { %buckets[ b | ... ] ... }`, the sibling read the captured key `buckets`
/// where the projection was meant, and nothing in the sibling's text says so; the block-clause spelling
/// `Properties.Props[ buckets | Enabled == true ] { ... }` and the type-block spelling
/// `AWS::IAM::Role when Properties.Props[ buckets | ... ] !empty { ... }` with the read after the block
/// did the same. That is the hazard the same-scope check refuses, one nesting level down, so it is
/// refused the same way. A capture in a nested block's *body* reaches only that body and stays
/// shadowing. `a_nested_when_condition_capturing_the_name_of_an_enclosing_let_is_refused_at_load` and
/// `a_block_clause_query_or_type_block_condition_capturing_an_enclosing_let_is_refused_at_load` hold
/// the three sites and the body spelling.
pub(crate) fn first_name_assigned_and_captured(file: &RulesFile<'_>) -> Option<(String, String)> {
    let rules = || {
        file.guard_rules
            .iter()
            .chain(file.parameterized_rules.iter().map(|p| &p.rule))
    };

    let mut file_captures = BTreeSet::new();
    for assignment in &file.assignments {
        collect_let_value_capture_names(&assignment.value, &mut file_captures);
    }
    for rule in rules() {
        if let Some(conditions) = &rule.conditions {
            collect_conjunctions_capture_names(conditions, &mut file_captures);
        }
    }
    if let Some(name) = first_assigned_and_captured(&file.assignments, &file_captures) {
        return Some((name, "at the file level".to_string()));
    }

    let file_names: Vec<&str> = assignment_names(&file.assignments).collect();
    for rule in rules() {
        if let Some(name) = first_in_rule_block(&rule.block, &file_names) {
            return Some((name, format!("in rule {}", rule.rule_name)));
        }
    }

    None
}

/// The first parameter of a parameterized rule that a filter capture in the rule's own `when`
/// condition is also written under, with the rule's name, in file order; `None` when no rule has one.
///
/// A parameter is a variable of the rule, bound at each call, and `%p` anywhere in the rule reads it:
/// the call scope answers for its parameters before any capture of the rule's condition, as
/// `resolve_variable` always did, so a capture written under a parameter's name can never be read. The
/// same shape as a name both assigned and captured in one scope (`first_name_assigned_and_captured`),
/// refused for the same reason: the author wrote a binding that does nothing, and a file that reads
/// one of its two bindings by a precedence rule is rejected rather than guessed at. A capture of the
/// parameter's name inside the rule's body is not this case: it binds in the body's block, which reads
/// its own captures ahead of the call scope, so it shadows the parameter there as a body capture shadows
/// an enclosing `let`.
pub(crate) fn first_parameter_captured_in_conditions(
    file: &RulesFile<'_>,
) -> Option<(String, String)> {
    for parameterized in &file.parameterized_rules {
        let Some(conditions) = &parameterized.rule.conditions else {
            continue;
        };
        let mut captures = BTreeSet::new();
        collect_conjunctions_capture_names(conditions, &mut captures);
        if let Some(name) = parameterized
            .parameter_names
            .iter()
            .find(|name| captures.contains(name.as_str()))
        {
            return Some((name.clone(), parameterized.rule.rule_name.clone()));
        }
    }
    None
}

/// A filter capture written in a block body under the name of a `let` in an enclosing scope.
///
/// Accepted as shadowing (see `first_name_assigned_and_captured`), and announced, because the move is
/// otherwise silent: the clauses of the block read the captured values where they read the assignment
/// before captures bound on that path. `site` is the clause the capture is written on, and `None` for a
/// capture inside an assignment's own right-hand side or a parameterized rule's argument, which carry
/// no position of their own.
pub(crate) struct ShadowedAssignment<'value, 'loc> {
    pub(crate) name: &'value str,
    pub(crate) rule_name: &'value str,
    pub(crate) site: Option<&'value FileLocation<'loc>>,
}

/// Every body capture in `file` that shadows an enclosing scope's `let`, in file order.
///
/// The counterpart of `first_name_assigned_and_captured`'s walk for the captures that walk accepts: a
/// plain clause's filter, a `let`'s right-hand side, a parameterized rule's argument, each written in
/// the block it binds in. The captures that bind outside their braces are refused by that walk and do
/// not appear here. A `let` of the same block is a refusal too, so `enclosing` here is strictly the
/// scopes around the block.
pub(crate) fn shadowing_body_captures<'value, 'loc: 'value>(
    file: &'value RulesFile<'loc>,
) -> Vec<ShadowedAssignment<'value, 'loc>> {
    let file_names: Vec<&str> = assignment_names(&file.assignments).collect();
    let mut found = Vec::new();
    for rule in file
        .guard_rules
        .iter()
        .chain(file.parameterized_rules.iter().map(|p| &p.rule))
    {
        shadowing_in_rule_block(&rule.block, &file_names, &rule.rule_name, &mut found);
    }
    found
}

fn shadowing_in_rule_block<'value, 'loc: 'value>(
    block: &'value Block<'loc, RuleClause<'loc>>,
    enclosing: &[&str],
    rule_name: &'value str,
    into: &mut Vec<ShadowedAssignment<'value, 'loc>>,
) {
    shadowing_in_assignments(&block.assignments, enclosing, rule_name, into);
    let enclosing = with_own_assignments(enclosing, &block.assignments);
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            match clause {
                RuleClause::Clause(guard_clause) => {
                    shadowing_in_guard_clause(guard_clause, &enclosing, rule_name, into)
                }
                RuleClause::WhenBlock(_, inner) => {
                    shadowing_in_guard_block(inner, &enclosing, rule_name, into)
                }
                RuleClause::TypeBlock(type_block) => {
                    shadowing_in_guard_block(&type_block.block, &enclosing, rule_name, into)
                }
            }
        }
    }
}

fn shadowing_in_guard_block<'value, 'loc: 'value>(
    block: &'value Block<'loc, GuardClause<'loc>>,
    enclosing: &[&str],
    rule_name: &'value str,
    into: &mut Vec<ShadowedAssignment<'value, 'loc>>,
) {
    shadowing_in_assignments(&block.assignments, enclosing, rule_name, into);
    let enclosing = with_own_assignments(enclosing, &block.assignments);
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            shadowing_in_guard_clause(clause, &enclosing, rule_name, into);
        }
    }
}

/// The captures in a block's own `let` right-hand sides, held against the scopes around the block.
///
/// `enclosing` is the names outside the block: a `let` in the same block as the capture is the refusal
/// `first_name_assigned_and_captured` makes, not a shadow.
fn shadowing_in_assignments<'value, 'loc: 'value>(
    assignments: &'value [LetExpr<'loc>],
    enclosing: &[&str],
    rule_name: &'value str,
    into: &mut Vec<ShadowedAssignment<'value, 'loc>>,
) {
    for assignment in assignments {
        let mut names = BTreeSet::new();
        collect_let_value_capture_names(&assignment.value, &mut names);
        for name in names {
            if enclosing.contains(&name) {
                into.push(ShadowedAssignment {
                    name,
                    rule_name,
                    site: None,
                });
            }
        }
    }
}

fn shadowing_in_guard_clause<'value, 'loc: 'value>(
    clause: &'value GuardClause<'loc>,
    enclosing: &[&str],
    rule_name: &'value str,
    into: &mut Vec<ShadowedAssignment<'value, 'loc>>,
) {
    let mut names = BTreeSet::new();
    let site = match clause {
        GuardClause::Clause(clause) => {
            collect_access_clause_capture_names(&clause.access_clause, &mut names);
            Some(&clause.access_clause.location)
        }
        GuardClause::ParameterizedNamedRule(clause) => {
            for parameter in &clause.parameters {
                collect_let_value_capture_names(parameter, &mut names);
            }
            None
        }
        // The query's and the condition's captures bind outside the braces and are the refusal's;
        // what is inside the braces is its own block.
        GuardClause::BlockClause(block_clause) => {
            shadowing_in_guard_block(&block_clause.block, enclosing, rule_name, into);
            return;
        }
        GuardClause::WhenBlock(_, block) => {
            shadowing_in_guard_block(block, enclosing, rule_name, into);
            return;
        }
        GuardClause::NamedRule(_) => return,
    };
    for name in names {
        if enclosing.contains(&name) {
            into.push(ShadowedAssignment {
                name,
                rule_name,
                site,
            });
        }
    }
}

fn assignment_names<'a>(assignments: &'a [LetExpr<'_>]) -> impl Iterator<Item = &'a str> {
    assignments.iter().map(|assignment| assignment.var.as_str())
}

/// The first of `captures` that an enclosing scope assigns; see `first_name_assigned_and_captured` for
/// why a nested `when`'s condition captures are held against enclosing assignments.
fn first_captured_from_enclosing(captures: &BTreeSet<&str>, enclosing: &[&str]) -> Option<String> {
    captures
        .iter()
        .find(|name| enclosing.contains(name))
        .map(|name| name.to_string())
}

/// `enclosing` plus this block's own assignment names, for the blocks nested in it.
fn with_own_assignments<'a>(enclosing: &[&'a str], assignments: &'a [LetExpr<'_>]) -> Vec<&'a str> {
    enclosing
        .iter()
        .copied()
        .chain(assignment_names(assignments))
        .collect()
}

fn first_assigned_and_captured(
    assignments: &[LetExpr<'_>],
    captures: &BTreeSet<&str>,
) -> Option<String> {
    assignments
        .iter()
        .find(|assignment| captures.contains(assignment.var.as_str()))
        .map(|assignment| assignment.var.clone())
}

/// This block, then every block nested inside it. Each is its own scope, so each is checked against its
/// own assignments and its own captures rather than against an outer scope's, with the one exception
/// `first_name_assigned_and_captured` describes: the captures written on the brace-opening constructs
/// here (a nested `when`'s condition, a block clause's query, a type block's condition and query) are also
/// held against `enclosing`, the assignment names of every scope around this one.
fn first_in_rule_block<'value, 'loc: 'value>(
    block: &'value Block<'loc, RuleClause<'loc>>,
    enclosing: &[&str],
) -> Option<String> {
    let mut captures = BTreeSet::new();
    let mut reaching_captures = BTreeSet::new();
    for assignment in &block.assignments {
        collect_let_value_capture_names(&assignment.value, &mut captures);
    }
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            match clause {
                RuleClause::Clause(guard_clause) => {
                    collect_own_guard_clause_capture_names(guard_clause, &mut captures);
                    collect_reaching_guard_clause_capture_names(
                        guard_clause,
                        &mut reaching_captures,
                    );
                }

                // The conditions are written outside the braces, so they are this scope's; the block
                // they guard is its own.
                RuleClause::WhenBlock(conditions, _) => {
                    collect_conjunctions_capture_names(conditions, &mut captures);
                    collect_conjunctions_capture_names(conditions, &mut reaching_captures);
                }

                // Likewise, and the type block's query selects the resources at this level.
                RuleClause::TypeBlock(type_block) => {
                    collect_query_capture_names(&type_block.query, &mut captures);
                    collect_query_capture_names(&type_block.query, &mut reaching_captures);
                    if let Some(conditions) = &type_block.conditions {
                        collect_conjunctions_capture_names(conditions, &mut captures);
                        collect_conjunctions_capture_names(conditions, &mut reaching_captures);
                    }
                }
            }
        }
    }
    if let Some(name) = first_assigned_and_captured(&block.assignments, &captures) {
        return Some(name);
    }
    if let Some(name) = first_captured_from_enclosing(&reaching_captures, enclosing) {
        return Some(name);
    }

    let enclosing = with_own_assignments(enclosing, &block.assignments);
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            let found = match clause {
                RuleClause::Clause(guard_clause) => first_in_guard_clause(guard_clause, &enclosing),
                RuleClause::WhenBlock(_, inner) => first_in_guard_block(inner, &enclosing),
                RuleClause::TypeBlock(type_block) => {
                    first_in_guard_block(&type_block.block, &enclosing)
                }
            };
            if found.is_some() {
                return found;
            }
        }
    }

    None
}

fn first_in_guard_block<'value, 'loc: 'value>(
    block: &'value Block<'loc, GuardClause<'loc>>,
    enclosing: &[&str],
) -> Option<String> {
    let mut captures = BTreeSet::new();
    let mut reaching_captures = BTreeSet::new();
    for assignment in &block.assignments {
        collect_let_value_capture_names(&assignment.value, &mut captures);
    }
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            collect_own_guard_clause_capture_names(clause, &mut captures);
            collect_reaching_guard_clause_capture_names(clause, &mut reaching_captures);
        }
    }
    if let Some(name) = first_assigned_and_captured(&block.assignments, &captures) {
        return Some(name);
    }
    if let Some(name) = first_captured_from_enclosing(&reaching_captures, enclosing) {
        return Some(name);
    }

    let enclosing = with_own_assignments(enclosing, &block.assignments);
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            if let Some(name) = first_in_guard_clause(clause, &enclosing) {
                return Some(name);
            }
        }
    }

    None
}

/// The capture names a clause declares in the scope it is *written* in, without descending into a block
/// it opens.
///
/// The counterpart of `GuardClause::collect_capture_names`, which does descend, because the two answer
/// different questions: that one asks which names a block might have to answer for, this one asks which
/// names share a scope with an assignment. A `[ cfg | ... ]` filter written on a block clause's query is
/// this scope's, since the query is evaluated here; the clauses inside that block's braces are not.
fn collect_own_guard_clause_capture_names<'value, 'loc: 'value>(
    clause: &'value GuardClause<'loc>,
    into: &mut BTreeSet<&'value str>,
) {
    match clause {
        GuardClause::Clause(clause) => {
            collect_access_clause_capture_names(&clause.access_clause, into)
        }

        GuardClause::BlockClause(block_clause) => {
            collect_query_capture_names(&block_clause.query.query, into)
        }

        GuardClause::WhenBlock(conditions, _) => {
            collect_conjunctions_capture_names(conditions, into)
        }

        GuardClause::ParameterizedNamedRule(clause) => {
            for parameter in &clause.parameters {
                collect_let_value_capture_names(parameter, into);
            }
        }

        GuardClause::NamedRule(_) => {}
    }
}

/// The subset of `collect_own_guard_clause_capture_names` written on a construct that opens braces: a
/// block clause's query and a nested `when`'s condition. These bind in the scope the clause is written in
/// and are read by every sibling there, so they are the captures held against the enclosing scopes'
/// assignments; see `first_name_assigned_and_captured`. A plain clause's capture opens no braces and
/// stays the shadowing the lexical rule describes.
fn collect_reaching_guard_clause_capture_names<'value, 'loc: 'value>(
    clause: &'value GuardClause<'loc>,
    into: &mut BTreeSet<&'value str>,
) {
    match clause {
        GuardClause::BlockClause(block_clause) => {
            collect_query_capture_names(&block_clause.query.query, into)
        }
        GuardClause::WhenBlock(conditions, _) => {
            collect_conjunctions_capture_names(conditions, into)
        }
        GuardClause::Clause(_)
        | GuardClause::NamedRule(_)
        | GuardClause::ParameterizedNamedRule(_) => {}
    }
}

fn first_in_guard_clause<'value, 'loc: 'value>(
    clause: &'value GuardClause<'loc>,
    enclosing: &[&str],
) -> Option<String> {
    match clause {
        GuardClause::BlockClause(block_clause) => {
            first_in_guard_block(&block_clause.block, enclosing)
        }
        GuardClause::WhenBlock(_, block) => first_in_guard_block(block, enclosing),
        GuardClause::Clause(_)
        | GuardClause::NamedRule(_)
        | GuardClause::ParameterizedNamedRule(_) => None,
    }
}

fn collect_conjunctions_capture_names<'value, T>(
    conjunctions: &'value Conjunctions<T>,
    into: &mut BTreeSet<&'value str>,
) where
    T: CaptureNames<'value>,
{
    for disjunctions in conjunctions {
        for clause in disjunctions {
            clause.collect_capture_names(into);
        }
    }
}

/// Every query part that populates a capture counts: `Filter`, `MapKeyFilter`, and a named `AllIndices`.
///
/// A `Filter` directly after a wildcard counts too. The filter runs at the expansion site with the key
/// in hand, so such a name is a real capture and has to be counted -- leaving it out reopens the
/// cross-iteration fallthrough: `Properties.Config[*][ cfg | Enabled == true ]` in a per-resource block,
/// read as `%cfg`, would answer with a previous resource's key at exit 0.
///
/// `AllIndices` was omitted on the reading that its `Option<String>` was collected through an arm of its
/// own. There is no such arm; this is the only walk over query parts. It calls `add_variable_capture_key`
/// when the name is `Some` -- with each key when the value under it is a map, with each element when it
/// is a list -- so a name written there is a capture on the same footing as a filter's.
///
/// Omitting it left an entire spelling undeclared rather than an unusual corner of one. `all_indices`
/// is the first branch of `predicate_or_index` and it accepts a bare `var_name`, so the pipe-less
/// `Properties.Tags[ tk ]` parses to `AllIndices(Some("tk"))` and never reaches `Filter` at all. Read as
/// `%tk` from a sibling `when` block that only a resource without `Tags` entered, it answered with a
/// previous resource's key: that resource alone exited 255, a compliant resource ahead of it exited 0,
/// and the reverse order exited 255. Document order decided the verdict and the leaking order was the
/// one that passed. Scoping capture names is not what opens this -- the three exit codes are the same
/// with scoping and without it -- because no scope holds the name to begin with.
///
/// A filter over a *list* -- `Tags[ t | Key == 'Name' ]`, or `Tags[*][ t | ... ]` once `accumulate` has
/// rebased onto each element -- has no key to bind, so it binds the element the predicate selected. For
/// a while it bound nothing: the name was counted here and resolved empty, which failed `%t !empty`
/// with a message blaming the selection and let `%t exists` skip, so a rule that selected a tag and
/// then read it passed at exit 0 without reading anything.
///
/// `AllValues` was collected here too, on the same footing, and no longer is: nothing the parser reads
/// builds a named one. See the arm below for what restoring that would take.
pub(crate) fn collect_query_capture_names<'value, 'loc: 'value>(
    query: &'value [QueryPart<'loc>],
    into: &mut BTreeSet<&'value str>,
) {
    for part in query {
        match part {
            QueryPart::Filter(name, conjunctions) => {
                if let Some(name) = name {
                    into.insert(name.as_str());
                }
                collect_conjunctions_capture_names(conjunctions, into);
            }

            QueryPart::MapKeyFilter(name, clause) => {
                if let Some(name) = name {
                    into.insert(name.as_str());
                }
                collect_let_value_capture_names(&clause.compare_with, into);
            }

            QueryPart::AllIndices(name) => {
                if let Some(name) = name {
                    into.insert(name.as_str());
                }
            }

            // `AllValues` was collected alongside `AllIndices` here while both could carry a name. Its
            // `Some` half is unreachable now: the only production that built one was `map_key_lookup`'s
            // named branch, shadowed by `all_indices` and deleted. Pinned by
            // `no_query_spelling_produces_a_named_all_values`. Making `AllValues` nameable again means
            // restoring that branch, this arm, and the capture in
            // `eval_context::query_retrieval_with_converter` together.
            //
            // `AuthoredIndices` sits here rather than with `AllIndices`: it is the bare `[*]` spelling,
            // which has no syntax for a name, so there is never one to collect.
            QueryPart::This
            | QueryPart::Key(_)
            | QueryPart::Variable(_)
            | QueryPart::Index(_)
            | QueryPart::AllValues(_)
            | QueryPart::AuthoredIndices => {}
        }
    }
}

fn collect_access_clause_capture_names<'value, 'loc: 'value>(
    clause: &'value AccessClause<'loc>,
    into: &mut BTreeSet<&'value str>,
) {
    collect_query_capture_names(&clause.query.query, into);
    if let Some(compare_with) = &clause.compare_with {
        collect_let_value_capture_names(compare_with, into);
    }
}

pub(crate) fn collect_let_value_capture_names<'value, 'loc: 'value>(
    value: &'value LetValue<'loc>,
    into: &mut BTreeSet<&'value str>,
) {
    match value {
        LetValue::AccessClause(query) => collect_query_capture_names(&query.query, into),
        LetValue::FunctionCall(function) => {
            for parameter in &function.parameters {
                collect_let_value_capture_names(parameter, into);
            }
        }
        LetValue::Value(_) => {}
    }
}

impl<'value, 'loc: 'value> CaptureNames<'value> for GuardClause<'loc> {
    fn collect_capture_names(&'value self, into: &mut BTreeSet<&'value str>) {
        match self {
            GuardClause::Clause(clause) => {
                collect_access_clause_capture_names(&clause.access_clause, into)
            }

            GuardClause::BlockClause(block_clause) => {
                collect_query_capture_names(&block_clause.query.query, into);
                collect_conjunctions_capture_names(&block_clause.block.conjunctions, into);
            }

            GuardClause::WhenBlock(conditions, block) => {
                collect_conjunctions_capture_names(conditions, into);
                collect_conjunctions_capture_names(&block.conjunctions, into);
            }

            GuardClause::ParameterizedNamedRule(clause) => {
                for parameter in &clause.parameters {
                    collect_let_value_capture_names(parameter, into);
                }
            }

            GuardClause::NamedRule(_) => {}
        }
    }
}

impl<'value, 'loc: 'value> CaptureNames<'value> for RuleClause<'loc> {
    fn collect_capture_names(&'value self, into: &mut BTreeSet<&'value str>) {
        match self {
            RuleClause::Clause(clause) => clause.collect_capture_names(into),

            RuleClause::WhenBlock(conditions, block) => {
                collect_conjunctions_capture_names(conditions, into);
                collect_conjunctions_capture_names(&block.conjunctions, into);
            }

            // The type block's own query is where a filter on the resource selection sits. Its
            // conditions are evaluated in the per-resource scope its body uses, and that scope hands
            // their captures up to this one when the resource is done, so a clause here after the
            // block reads them under these names.
            RuleClause::TypeBlock(type_block) => {
                collect_query_capture_names(&type_block.query, into);
                if let Some(conditions) = &type_block.conditions {
                    collect_conjunctions_capture_names(conditions, into);
                }
                collect_conjunctions_capture_names(&type_block.block.conjunctions, into);
            }
        }
    }
}

impl<'value, 'loc: 'value> CaptureNames<'value> for WhenGuardClause<'loc> {
    fn collect_capture_names(&'value self, into: &mut BTreeSet<&'value str>) {
        match self {
            WhenGuardClause::Clause(clause) => {
                collect_access_clause_capture_names(&clause.access_clause, into)
            }

            WhenGuardClause::ParameterizedNamedRule(clause) => {
                for parameter in &clause.parameters {
                    collect_let_value_capture_names(parameter, into);
                }
            }

            WhenGuardClause::NamedRule(_) => {}
        }
    }
}

/// Where a name sits in the walk looking for a cycle.
enum Visit {
    /// On the path the walk is currently down. Reaching it again is the cycle.
    OnPath,
    /// Walked to completion with no cycle under it.
    Done,
}

/// The names in the first cycle reachable from `starts`, in the order they read each other, or `None`
/// if there is no cycle.
///
/// Shared by [`first_let_cycle`] and [`first_rule_reference_cycle`], which differ only in what an edge
/// is. Both crashes have one shape -- a resolver that memoizes after it returns, so a second visit to a
/// name already in progress finds no marker and recurses -- and one answer, so one walk. Written out
/// twice it would be two subtle iterative depth-first searches to keep in step.
///
/// Iterative rather than recursive, because the whole point of both checks is that a recursion with no
/// cycle guard exhausted the stack. A walk deep enough to overflow is exactly the input this function
/// has to survive in order to report on it.
fn first_cycle<'value>(
    starts: &[&'value str],
    edges: &BTreeMap<&'value str, Vec<&'value str>>,
) -> Option<Vec<&'value str>> {
    let mut visited = BTreeMap::new();
    for start in starts.iter().copied() {
        if visited.contains_key(start) {
            continue;
        }

        let mut path = vec![start];
        let mut stack = vec![(start, 0_usize)];
        visited.insert(start, Visit::OnPath);

        while let Some((name, next)) = stack.last().copied() {
            let read = edges.get(name).map(Vec::as_slice).unwrap_or_default();
            if next == read.len() {
                visited.insert(name, Visit::Done);
                path.pop();
                stack.pop();
                continue;
            }
            stack.last_mut().expect("just read the last entry").1 = next + 1;

            match visited.get(read[next]) {
                Some(Visit::OnPath) => {
                    let closes_at = path
                        .iter()
                        .position(|on_path| *on_path == read[next])
                        .expect("a name on the path is in the path");
                    return Some(path.split_off(closes_at));
                }

                Some(Visit::Done) => {}

                None => {
                    visited.insert(read[next], Visit::OnPath);
                    path.push(read[next]);
                    stack.push((read[next], 0));
                }
            }
        }
    }

    None
}

/// The names in the first cycle among a scope's own `let` right-hand sides, in the order they read
/// each other, or `None` if there is no cycle.
///
/// A right-hand side that reads a name the same scope declares makes `resolve_variable` recurse with
/// nothing to stop it. The memo write in `RootScope::resolve_variable` happens *after* the query it
/// is memoizing completes, so there is no in-progress marker for the second visit to find, and
/// `BlockScope::resolve_variable` has the same shape. Every spelling of it exhausted the stack and
/// aborted the process at exit 134 with a core dump, which is outside the documented exit codes
/// entirely -- 0, 5 and 19 -- so a caller could read it as neither a pass nor a failure it could act
/// on:
///
/// ```text
/// let a = %a                             at file level
/// rule r { let a = %a ... }              in a rule body
/// let a = %b / let b = %a                a mutual pair
/// let a = %b / let b = %c / let c = %a   a three-deep ring
/// let a = Resources.*[ Type == %a ]      through a filter clause
/// let a = Resources.%a.Type              through an interpolated key
/// let a = json_parse(%a)                 through a function argument
/// ```
///
/// Edges point only at names *this* scope declares, and that restriction is what makes the check
/// exact. Resolution starts in the scope holding the declaration and only ever walks outwards:
/// `BlockScope::resolve_variable` reads its own `variable_queries` first and defers to the parent
/// only for a name it does not declare, and the parent then resolves with itself as the resolver. So
/// a chain can leave a scope and never re-enter it, which confines every cycle to one scope's own
/// declarations. An acyclic chain is untouched however long it is, and an inner `let x` shadowing an
/// outer one is two nodes in two scopes rather than one node reading itself.
///
/// A named rule's body is deliberately not followed. `RootScope::rule_status` evaluates it with the
/// root scope as its parent whatever the reference site, so a `%name` inside one cannot resolve to a
/// block-level `let`; and a ring that closes through a rule body is rule recursion rather than a
/// variable cycle -- `rule a { a }` aborts the same way with no `let` in the file at all. That one is
/// [`first_rule_reference_cycle`], and this one is the variable resolver.
pub(crate) fn first_let_cycle<'value, 'loc: 'value>(
    assignments: &'value [LetExpr<'loc>],
) -> Option<Vec<&'value str>> {
    let declared = assignments
        .iter()
        .map(|assignment| assignment.var.as_str())
        .collect::<BTreeSet<&str>>();

    let mut reads = BTreeMap::new();
    for assignment in assignments {
        let mut names = BTreeSet::new();
        collect_let_value_variable_refs(&assignment.value, &mut names);
        reads.insert(
            assignment.var.as_str(),
            names
                .into_iter()
                .filter(|name| declared.contains(name))
                .collect::<Vec<&str>>(),
        );
    }

    let starts = assignments
        .iter()
        .map(|assignment| assignment.var.as_str())
        .collect::<Vec<&str>>();
    first_cycle(&starts, &reads)
}

/// The rule names in the first cycle among a file's rule references, in the order they reference each
/// other, or `None` if there is no cycle.
///
/// The other half of the crash [`first_let_cycle`] describes, and the half that needs no `let` in the
/// file at all. `RootScope::rule_status` writes its memo after `eval_rule` returns, so a reference
/// reaching a rule already in progress finds no marker and evaluates it again; every spelling of it
/// exhausted the stack and aborted the process at exit 134:
///
/// ```text
/// rule loop { loop }                              a plain self-reference
/// rule a { b } / rule b { a }                     a plain mutual pair
/// rule loop(n) { loop(%n) }                       the parameterized spelling of the first
/// rule a(n) { b(%n) } / rule b(n) { a(%n) }       and of the second
/// ```
///
/// One graph over both spellings, which is the property worth keeping. A parameterized rule shares the
/// rule namespace -- `rules_file` rejects `rule r` beside `rule r(x)` for that reason -- so a cycle can
/// close through either form, or through one of each. The two spellings also do not share an evaluation
/// path: `eval_parameterized_rule_call` calls `eval_rule` directly rather than going through
/// `rule_status`, so a guard placed in `rule_status` would have caught the plain spelling and missed the
/// parameterized one, leaving two mechanisms to keep in step. Here they are the same edges.
///
/// A rule's `when` conditions count as well as its body. Both are evaluated by `eval_rule`, and a
/// condition referencing the rule it guards recurses exactly as a body reference does.
///
/// Edges point only at names the file declares, which is what keeps this from overlapping the
/// undeclared-name path: a reference to a rule that does not exist is `Error::MissingValue` from
/// `rule_status` or `find_parameterized_rule`, already reported as a rules-file error, and it is not a
/// cycle.
///
/// A rule's own `let` right-hand sides are edges, because a filter on one can name a rule and
/// `rule a { let x = Resources.*[ a(1) ] ... }` is then `a` reaching `a`. The file's are not, and cannot
/// be: an edge here runs from a rule name to a rule name, a file-level assignment carries no rule name to
/// run from, and nothing can run back to it -- a rule reference resolves in the rule namespace and a
/// file-level `let` is in the variable one. A ring closing through two `let`s is [`first_let_cycle`].
///
/// A static check rather than a recursion depth limit, for the reason [`first_let_cycle`] gives: an
/// acyclic chain of references resolves at any length, so a limit would have to guess a length no legal
/// file exceeds, and `rule loop { loop }` is a cycle at depth one that no useful limit catches.
///
/// Known limitation, and the one case this rejects that runs today. A self-reference behind a `when`
/// whose condition does not hold terminates, because the guarded block never runs:
///
/// ```text
/// rule a { when Resources.Nope exists { a } }
/// ```
///
/// It is rejected anyway. Nothing in a rules file can make a recursion terminate: the root value is
/// fixed for the whole run, `rule_status` keys its memo on `(name, role)` so there are two states rather
/// than a changing one, and a parameterized rule's arguments are re-resolved against that same root. So
/// a guarded self-reference either never recurses at all or recurses forever, decided by the document
/// rather than by the file -- the same "left to the data" case `first_let_cycle` rejects for a `let`
/// whose name is also a capture, and for the same reason.
pub(crate) fn first_rule_reference_cycle<'value, 'loc: 'value>(
    file: &'value RulesFile<'loc>,
) -> Option<Vec<&'value str>> {
    let rules = || {
        file.guard_rules
            .iter()
            .chain(file.parameterized_rules.iter().map(|each| &each.rule))
    };

    let declared = rules()
        .map(|rule| rule.rule_name.as_str())
        .collect::<BTreeSet<&str>>();

    let mut references = BTreeMap::new();
    for rule in rules() {
        references.insert(
            rule.rule_name.as_str(),
            rule_refs_in(rule)
                .iter()
                .map(RuleReference::name)
                .filter(|name| declared.contains(name))
                .collect::<BTreeSet<&str>>()
                .into_iter()
                .collect::<Vec<&str>>(),
        );
    }

    let starts = rules()
        .map(|rule| rule.rule_name.as_str())
        .collect::<Vec<&str>>();
    first_cycle(&starts, &references)
}

/// A call site whose argument list does not agree with the definition it names.
pub(crate) enum CallSiteMismatch<'value> {
    /// A parameterized rule called with the wrong number of arguments.
    Arity {
        rule_name: &'value str,
        expected: usize,
        got: usize,
    },
    /// A rule declared without a parameter list, called as though it had one.
    NotParameterized { rule_name: &'value str },
    /// A rule declared with a parameter list, referenced as though it had none.
    ///
    /// The mirror of `NotParameterized`, and a variant of its own rather than a reuse of it, because the
    /// two need opposite advice. That arm's message ends "Write {name} on its own to reference it", which
    /// is what the author of this mistake already wrote; the fix here is to add the argument list.
    /// Reusing the variant would print a diagnostic that describes the input as the remedy, which is the
    /// same class of self-contradicting report the arm was added to remove.
    MissingArguments {
        rule_name: &'value str,
        expected: usize,
    },
    /// A built-in function called as a clause, in a file that declares no rule by that name.
    ///
    /// `call_expr` reads `count(%x)` the same way in every position. Only `function_expr` maps the name
    /// through `FunctionName`, and it is reached through `let_value` -- a `let` right-hand side, a
    /// comparison's right side, a key filter's right side, a call argument -- never from clause
    /// position, where the same text was a call to a parameterized rule named `count`. The file parsed,
    /// `parse-tree` printed that rule call, and evaluation refused it as "Parameterized Rule with name
    /// count was not found", a message about a rule the author never meant. A rule that does declare
    /// the name keeps it: `rule count(items)` is a rule, and a call to it is a clause, which is why this
    /// is decided here against the file's declarations rather than in `parameterized_rule_call_clause`
    /// where they are not yet known.
    BuiltinFunction { name: &'value str },
}

/// The first call site in the file that does not agree with the definition it names, or `None` if
/// every one does.
///
/// Both conditions are decidable from the text, which is the whole argument for answering them here.
/// The arity check in `eval_parameterized_rule_call` reaches the same conclusion at evaluation time,
/// but only for a call something evaluates, and with an exit code that blames the tool; how that check
/// exited before this one existed, and what it does today, is in the comment above this function's
/// call in `rules_file`. `parameter_names` makes the same argument in its own doc comment about the
/// duplicate-parameter case: the mistake is "a rule-authoring mistake the parser was holding in its
/// hand".
///
/// Answering at parse time also settles a call site that is never reached: the mistake in
/// `rule MAIN { check(1, 2) }`, written instead inside a rule nothing references or behind a `when` that
/// does not match, is refused here, where evaluation would exit 0 with nothing said. And it keeps the
/// mistake out of the evaluator's report, so
/// stdout never lists the calling rule under "FAILED rules" while stderr says cfn-guard has broken.
///
/// Only names the file declares are checked, with one exception. A call to a rule that does not exist
/// stays `find_parameterized_rule`'s `Error::MissingValue`, which `is_rules_file_mistake` classifies
/// as a rules-file error at exit 5 already; taking that over here would widen this check into
/// rejecting a file for a reference that a `when` might never reach, which is a different decision
/// from this one.
///
/// The exception is a call whose name is a built-in function and which no rule declares. The argument
/// for leaving an undeclared name to evaluation is that nothing decidable from the text says the
/// reference is wrong: a `when` may keep it from running, and a later file could declare it. Neither
/// holds here. In clause position the only thing `count(...)` can resolve to is a parameterized rule,
/// the file declares none, and the function the author meant is not reachable from a clause in any
/// evaluation order -- so the call is wrong on every path, including the ones a `when` skips, and the
/// evaluation-time message ("Parameterized Rule with name count was not found") describes a rule the
/// author never wrote. Refusing it here costs nothing a `when` could have made valid. One exit code
/// follows from it: `count(%x)` behind a `when` the document does not satisfy exits 5 like the
/// unguarded spelling, rather than 0 as SKIP with the mistake never reached.
///
/// The file's own `let` right-hand sides are read as well as its rules'. A file-level
/// `let sel = Resources.*[ check(1) ]` belongs to no rule, so iterating the two rule lists misses it, and
/// it would reach the evaluator's own count check, which answers for the tool, not for the file.
pub(crate) fn first_call_site_mismatch<'value, 'loc: 'value>(
    file: &'value RulesFile<'loc>,
) -> Option<CallSiteMismatch<'value>> {
    let declared_parameters = file
        .parameterized_rules
        .iter()
        .map(|each| (each.rule.rule_name.as_str(), each.parameter_names.len()))
        .collect::<BTreeMap<&str, usize>>();
    let declared_plain = file
        .guard_rules
        .iter()
        .map(|rule| rule.rule_name.as_str())
        .collect::<BTreeSet<&str>>();

    let mut file_level = vec![];
    for assignment in &file.assignments {
        collect_let_value_rule_refs(&assignment.value, &mut file_level);
    }

    let rules = file
        .guard_rules
        .iter()
        .chain(file.parameterized_rules.iter().map(|each| &each.rule));
    for references in std::iter::once(file_level).chain(rules.map(rule_refs_in)) {
        for reference in references {
            let call = match reference {
                RuleReference::Parameterized(call) => call,

                // A bare name for a rule that has parameters. Skipped before, which left the same
                // self-contradicting report the `NotParameterized` arm below was written to remove:
                // `rule check(t)` referenced as `check` printed "dependent rule [check] did not PASS"
                // on stdout and "Rule check by that name does not exist, Rule Names = [\"main\"]" on
                // stderr, about a rule two lines above. The name list omits it because `rule_status`
                // consults `guard_rules` only, and a parameterized rule is not in that map.
                //
                // A name declared nowhere still falls through, and has to: that stays
                // `Error::MissingValue`, which is already a rules-file error at exit 5, and deciding it
                // here would reject a file for a reference a `when` might never reach.
                RuleReference::Plain(name) => {
                    if let Some(expected) = declared_parameters.get(name) {
                        return Some(CallSiteMismatch::MissingArguments {
                            rule_name: name,
                            expected: *expected,
                        });
                    }
                    continue;
                }
            };
            let name = call.named_rule.dependent_rule.as_str();

            if let Some(expected) = declared_parameters.get(name) {
                if *expected != call.parameters.len() {
                    return Some(CallSiteMismatch::Arity {
                        rule_name: name,
                        expected: *expected,
                        got: call.parameters.len(),
                    });
                }
            } else if declared_plain.contains(name) {
                return Some(CallSiteMismatch::NotParameterized { rule_name: name });
            } else if FunctionName::try_from(name).is_ok() {
                return Some(CallSiteMismatch::BuiltinFunction { name });
            }
        }
    }

    None
}

/// Every rule reference in one rule, its `when` conditions and its `let` right-hand sides included.
///
/// The conditions are evaluated by `eval_rule` just as the body is, so a reference in either reaches the
/// same machinery. The assignments were missed: this walked `rule.block.conjunctions` and not
/// `rule.block.assignments`, so a call inside a filter on a `let` right-hand side was invisible to both
/// checks that read this. `collect_block_rule_refs` reads both halves of a block, which is what the two
/// sibling walks over the same tree already do -- `block_capture_names` and `collect_block_variable_refs`
/// each read the assignments before the conjunctions.
fn rule_refs_in<'value, 'loc: 'value>(
    rule: &'value Rule<'loc>,
) -> Vec<RuleReference<'value, 'loc>> {
    let mut references = vec![];
    if let Some(conditions) = &rule.conditions {
        collect_conjunctions_rule_refs(conditions, &mut references);
    }
    collect_block_rule_refs(&rule.block, &mut references);
    references
}

/// One rule reference, as the text spells it.
///
/// The parameterized arm carries the whole clause rather than just the name, because
/// [`first_call_site_mismatch`] needs its argument list and [`first_rule_reference_cycle`] needs only
/// the name. One walk answering both is the point: enumerating where a reference can appear twice
/// would leave two lists to keep in step, and a place missing from either is a defect its check
/// cannot see.
pub(crate) enum RuleReference<'value, 'loc: 'value> {
    /// `dependent_rule`, with no argument list.
    Plain(&'value str),
    /// `dependent_rule(...)`.
    Parameterized(&'value ParameterizedNamedRuleClause<'loc>),
}

impl<'value, 'loc: 'value> RuleReference<'value, 'loc> {
    fn name(&self) -> &'value str {
        match self {
            RuleReference::Plain(name) => name,
            RuleReference::Parameterized(call) => call.named_rule.dependent_rule.as_str(),
        }
    }
}

/// Every rule a clause references, at any nesting depth.
///
/// Unlike the capture-name and variable walks, nothing here shadows: rule names are one flat namespace
/// for the whole file, so a nested block cannot redeclare one and every reference means the same rule
/// wherever it sits.
///
/// Every arm that recurses carries a reference today, this file's own bodies included, so none of them is
/// a tripwire for a hypothetical grammar change. A rule body reaches one directly, through a rule-level
/// `when`, through a nested `when` block, and through a type block's `when` conditions. The *bodies* of a
/// type block and of a block clause reach one in two spellings: both take `block(clause)`, and `clause`
/// reads more than access clauses -- a nested block clause, which it reaches through
/// `access_clause_or_block`, a `when_block`, and `parameterized_rule_call_clause`. So
///
/// ```text
/// rule a(t) { Resources { a(%t) } }                  the call, directly in the body
/// rule a { Resources { when a { Type exists } } }    the plain name, as a nested `when`'s condition
/// ```
///
/// are both reported as cycles, and `rule a { Resources { when b { .. } } }` for some other rule `b`
/// parses. What those bodies cannot hold is a `GuardClause::NamedRule` *directly*, because `clause` has
/// no arm for it: `rule a { Resources { a } }` and `rule a { AWS::EC2::Volume { a } }` are syntax errors,
/// at the `{`. That one absent spelling is the whole of it, and folding either recursing arm into the
/// `Clause(_)` catch-all as unreachable would lose both live cases above.
///
/// A query is walked wherever one appears, and it was not. `Clause(_) => {}` read as "a comparison
/// clause holds no reference", which is true of the clause and false of its *query*:
/// `predicate_filter_clauses` parses a full `clause` between the brackets, and `clause` includes
/// `parameterized_rule_call_clause`, so `Resources.*[ check(1) ] exists` is a call site sitting inside a
/// comparison clause. The same reasoning had already been applied to the two sibling walks over this
/// tree -- `collect_query_capture_names` and `collect_query_variable_refs` each carry a
/// `QueryPart::Filter` arm -- and this walk was the one that did not, which is what makes it an omission
/// rather than a decision.
///
/// A parameterized call's arguments are walked for the same reason, and the earlier note here said they
/// need not be "because a `LetValue` holds a value, a query or a function call and none of the three can
/// name a rule". The first half is right and the conclusion does not follow: a query holds query parts,
/// and one of them is a filter. `check(Resources.*[ other(1) ])` names `other`.
///
/// What that leaves unwalked is `LetValue::Value`, which is a resolved `PathAwareValue` and holds no
/// syntax at all.
trait RuleRefs<'value, 'loc: 'value> {
    fn collect_rule_refs(&'value self, into: &mut Vec<RuleReference<'value, 'loc>>);
}

fn collect_conjunctions_rule_refs<'value, 'loc: 'value, T>(
    conjunctions: &'value Conjunctions<T>,
    into: &mut Vec<RuleReference<'value, 'loc>>,
) where
    T: RuleRefs<'value, 'loc>,
{
    for disjunctions in conjunctions {
        for clause in disjunctions {
            clause.collect_rule_refs(into);
        }
    }
}

/// A block's `let` right-hand sides as well as its clauses.
///
/// Both halves, at every nesting level, which is what the two sibling walks already do:
/// `block_capture_names` and `collect_block_variable_refs` each read `block.assignments` before
/// `block.conjunctions`. Nothing is subtracted the way `collect_block_variable_refs` subtracts the names a
/// block declares -- rule names are one flat namespace, so a nested block has nothing to shadow.
fn collect_block_rule_refs<'value, 'loc: 'value, T>(
    block: &'value Block<'loc, T>,
    into: &mut Vec<RuleReference<'value, 'loc>>,
) where
    T: RuleRefs<'value, 'loc>,
{
    for assignment in &block.assignments {
        collect_let_value_rule_refs(&assignment.value, into);
    }
    collect_conjunctions_rule_refs(&block.conjunctions, into);
}

/// Every rule a `let` right-hand side, a comparison's right-hand side, or a call argument references.
///
/// All three are one type, `LetValue`, and reach a rule name the same way: through a query, through a
/// query part that is a filter, through the clauses inside it. `LetValue::Value` is a resolved
/// `PathAwareValue` and holds no syntax, so it terminates.
pub(crate) fn collect_let_value_rule_refs<'value, 'loc: 'value>(
    value: &'value LetValue<'loc>,
    into: &mut Vec<RuleReference<'value, 'loc>>,
) {
    match value {
        LetValue::AccessClause(query) => collect_query_rule_refs(&query.query, into),
        LetValue::FunctionCall(function) => {
            for parameter in &function.parameters {
                collect_let_value_rule_refs(parameter, into);
            }
        }
        LetValue::Value(_) => {}
    }
}

/// Every rule the filters in one query reference.
///
/// The third walk over query parts, beside [`collect_query_capture_names`] and
/// [`collect_query_variable_refs`], and the three have to agree on which parts hold something: a part
/// that can hold a clause and is missed here is a call site neither [`first_call_site_mismatch`] nor
/// [`first_rule_reference_cycle`] can see.
///
/// Mutually recursive with the `RuleRefs` impls, because a filter's clauses are `GuardClause`s and one of
/// those can carry a query with another filter. The depth is bounded by the parser: every filter opens a
/// `NestingGuard` level, so a file that reached this walk nests at most `MAX_NESTING_DEPTH` deep, and the
/// two sibling walks already recurse over the same shape at the same bound.
fn collect_query_rule_refs<'value, 'loc: 'value>(
    query: &'value [QueryPart<'loc>],
    into: &mut Vec<RuleReference<'value, 'loc>>,
) {
    for part in query {
        match part {
            // `predicate_filter_clauses` parses a full `clause`, and `clause` includes
            // `parameterized_rule_call_clause` and `when_block` -- so a filter holds a call site directly,
            // and a plain reference through a nested `when`'s conditions.
            QueryPart::Filter(_, conjunctions) => {
                collect_conjunctions_rule_refs(conjunctions, into)
            }

            // A map key filter's right-hand side is a `LetValue`, so it reaches a query and its filters.
            QueryPart::MapKeyFilter(_, clause) => {
                collect_let_value_rule_refs(&clause.compare_with, into)
            }

            QueryPart::This
            | QueryPart::Key(_)
            | QueryPart::Variable(_)
            | QueryPart::Index(_)
            | QueryPart::AllValues(_)
            | QueryPart::AllIndices(_)
            | QueryPart::AuthoredIndices => {}
        }
    }
}

fn collect_access_clause_rule_refs<'value, 'loc: 'value>(
    clause: &'value AccessClause<'loc>,
    into: &mut Vec<RuleReference<'value, 'loc>>,
) {
    collect_query_rule_refs(&clause.query.query, into);
    if let Some(compare_with) = &clause.compare_with {
        collect_let_value_rule_refs(compare_with, into);
    }
}

impl<'value, 'loc: 'value> RuleRefs<'value, 'loc> for GuardClause<'loc> {
    fn collect_rule_refs(&'value self, into: &mut Vec<RuleReference<'value, 'loc>>) {
        match self {
            GuardClause::NamedRule(named) => {
                into.push(RuleReference::Plain(named.dependent_rule.as_str()))
            }

            GuardClause::ParameterizedNamedRule(call) => {
                into.push(RuleReference::Parameterized(call));
                for parameter in &call.parameters {
                    collect_let_value_rule_refs(parameter, into);
                }
            }

            // The query as well as the body. The query is where the `[ .. ]` on
            // `Resources.*[ check(1) ] { .. }` sits, and it was the position that reached
            // `Error::IncompatibleError` at exit 255 rather than 19.
            GuardClause::BlockClause(block_clause) => {
                collect_query_rule_refs(&block_clause.query.query, into);
                collect_block_rule_refs(&block_clause.block, into);
            }

            GuardClause::WhenBlock(conditions, block) => {
                collect_conjunctions_rule_refs(conditions, into);
                collect_block_rule_refs(block, into);
            }

            GuardClause::Clause(clause) => {
                collect_access_clause_rule_refs(&clause.access_clause, into)
            }
        }
    }
}

impl<'value, 'loc: 'value> RuleRefs<'value, 'loc> for RuleClause<'loc> {
    fn collect_rule_refs(&'value self, into: &mut Vec<RuleReference<'value, 'loc>>) {
        match self {
            RuleClause::Clause(clause) => clause.collect_rule_refs(into),

            RuleClause::WhenBlock(conditions, block) => {
                collect_conjunctions_rule_refs(conditions, into);
                collect_block_rule_refs(block, into);
            }

            // The type block's own query is walked for uniformity rather than for a reachable case.
            // `type_block` constructs it -- `Resources.*[ Type == <name> ]`, with one
            // `GuardClause::Clause` comparing `Type` to a literal -- so no author text reaches its filter
            // today. Skipping it on that ground is how a walk over a class ends up covering all but one
            // member, and the call costs one line.
            RuleClause::TypeBlock(type_block) => {
                collect_query_rule_refs(&type_block.query, into);
                if let Some(conditions) = &type_block.conditions {
                    collect_conjunctions_rule_refs(conditions, into);
                }
                collect_block_rule_refs(&type_block.block, into);
            }
        }
    }
}

impl<'value, 'loc: 'value> RuleRefs<'value, 'loc> for WhenGuardClause<'loc> {
    fn collect_rule_refs(&'value self, into: &mut Vec<RuleReference<'value, 'loc>>) {
        match self {
            WhenGuardClause::NamedRule(named) => {
                into.push(RuleReference::Plain(named.dependent_rule.as_str()))
            }

            WhenGuardClause::ParameterizedNamedRule(call) => {
                into.push(RuleReference::Parameterized(call));
                for parameter in &call.parameters {
                    collect_let_value_rule_refs(parameter, into);
                }
            }

            WhenGuardClause::Clause(clause) => {
                collect_access_clause_rule_refs(&clause.access_clause, into)
            }
        }
    }
}

/// Every `%name` a `let` right-hand side reads.
///
/// The parallel of [`collect_let_value_capture_names`] over the same tree, and the two have to grow
/// together: a query part that can hold a `%name` and is missed here is a cycle the check does not
/// see, which is a crash rather than a wrong answer.
fn collect_let_value_variable_refs<'value, 'loc: 'value>(
    value: &'value LetValue<'loc>,
    into: &mut BTreeSet<&'value str>,
) {
    match value {
        LetValue::AccessClause(query) => collect_query_variable_refs(&query.query, into),
        LetValue::FunctionCall(function) => {
            for parameter in &function.parameters {
                collect_let_value_variable_refs(parameter, into);
            }
        }
        LetValue::Value(_) => {}
    }
}

/// A `%name` in any position counts, not only the first.
///
/// `query_retrieval_with_converter` resolves a variable at index 0, and the map arm resolves one
/// further along as an interpolated key, so `let a = Resources.%a.Type` recurses just as
/// `let a = %a` does.
fn collect_query_variable_refs<'value, 'loc: 'value>(
    query: &'value [QueryPart<'loc>],
    into: &mut BTreeSet<&'value str>,
) {
    for part in query {
        if let Some(name) = part.variable() {
            into.insert(name);
        }

        match part {
            // A filter's clauses are evaluated with the resolver that is retrieving the query, so a
            // `%name` inside one resolves in the scope holding the `let`.
            QueryPart::Filter(_, conjunctions) => {
                collect_conjunctions_variable_refs(conjunctions, into)
            }

            QueryPart::MapKeyFilter(_, clause) => {
                collect_let_value_variable_refs(&clause.compare_with, into)
            }

            QueryPart::This
            | QueryPart::Key(_)
            | QueryPart::Variable(_)
            | QueryPart::Index(_)
            | QueryPart::AllValues(_)
            | QueryPart::AllIndices(_)
            | QueryPart::AuthoredIndices => {}
        }
    }
}

fn collect_access_clause_variable_refs<'value, 'loc: 'value>(
    clause: &'value AccessClause<'loc>,
    into: &mut BTreeSet<&'value str>,
) {
    collect_query_variable_refs(&clause.query.query, into);
    if let Some(compare_with) = &clause.compare_with {
        collect_let_value_variable_refs(compare_with, into);
    }
}

fn collect_conjunctions_variable_refs<'value, T>(
    conjunctions: &'value Conjunctions<T>,
    into: &mut BTreeSet<&'value str>,
) where
    T: VariableRefs<'value>,
{
    for disjunctions in conjunctions {
        for clause in disjunctions {
            clause.collect_variable_refs(into);
        }
    }
}

/// A nested block's references, minus the ones it answers itself.
///
/// A name the nested block declares resolves to that declaration rather than to ours, so it is not
/// an edge out of the block: `BlockScope::resolve_variable` defers to the parent only for a name it
/// does not hold. Everything left over does reach us and is an edge.
fn collect_block_variable_refs<'value, 'loc: 'value, T>(
    block: &'value Block<'loc, T>,
    into: &mut BTreeSet<&'value str>,
) where
    T: VariableRefs<'value>,
{
    let mut inside = BTreeSet::new();
    for assignment in &block.assignments {
        collect_let_value_variable_refs(&assignment.value, &mut inside);
    }
    collect_conjunctions_variable_refs(&block.conjunctions, &mut inside);

    for declared in block.assignments.iter().map(|each| each.var.as_str()) {
        inside.remove(declared);
    }
    into.extend(inside);
}

trait VariableRefs<'value> {
    fn collect_variable_refs(&'value self, into: &mut BTreeSet<&'value str>);
}

impl<'value, 'loc: 'value> VariableRefs<'value> for GuardClause<'loc> {
    fn collect_variable_refs(&'value self, into: &mut BTreeSet<&'value str>) {
        match self {
            GuardClause::Clause(clause) => {
                collect_access_clause_variable_refs(&clause.access_clause, into)
            }

            // The block's own query is retrieved with the enclosing resolver
            // (`eval_guard_block_clause`) and its body is not, so only the body is shadowed.
            GuardClause::BlockClause(block_clause) => {
                collect_query_variable_refs(&block_clause.query.query, into);
                collect_block_variable_refs(&block_clause.block, into);
            }

            // Same split: `eval_when_condition_block` evaluates the conditions with the enclosing
            // resolver, before the block's scope exists, so what the block declares does not shadow
            // them.
            GuardClause::WhenBlock(conditions, block) => {
                collect_conjunctions_variable_refs(conditions, into);
                collect_block_variable_refs(block, into);
            }

            // The arguments are resolved at the call site, in this scope. The rule's body is not
            // followed; see [`first_let_cycle`].
            GuardClause::ParameterizedNamedRule(clause) => {
                for parameter in &clause.parameters {
                    collect_let_value_variable_refs(parameter, into);
                }
            }

            GuardClause::NamedRule(_) => {}
        }
    }
}

impl<'value, 'loc: 'value> VariableRefs<'value> for WhenGuardClause<'loc> {
    fn collect_variable_refs(&'value self, into: &mut BTreeSet<&'value str>) {
        match self {
            WhenGuardClause::Clause(clause) => {
                collect_access_clause_variable_refs(&clause.access_clause, into)
            }

            WhenGuardClause::ParameterizedNamedRule(clause) => {
                for parameter in &clause.parameters {
                    collect_let_value_variable_refs(parameter, into);
                }
            }

            WhenGuardClause::NamedRule(_) => {}
        }
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct Block<'loc, T> {
    pub(crate) assignments: Vec<LetExpr<'loc>>,
    pub(crate) conjunctions: Conjunctions<T>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct TypeBlock<'loc> {
    pub(crate) type_name: String,
    pub(crate) conditions: Option<WhenConditions<'loc>>,
    pub(crate) block: Block<'loc, GuardClause<'loc>>, // only contains access clauses
    pub(crate) query: Vec<QueryPart<'loc>>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) enum RuleClause<'loc> {
    Clause(GuardClause<'loc>),
    WhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
    TypeBlock(TypeBlock<'loc>),
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Rule<'loc> {
    pub(crate) rule_name: String,
    pub(crate) conditions: Option<WhenConditions<'loc>>,
    pub(crate) block: Block<'loc, RuleClause<'loc>>,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub(crate) struct ParameterizedRule<'loc> {
    pub(crate) parameter_names: indexmap::IndexSet<String>,
    pub(crate) rule: Rule<'loc>,
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct RulesFile<'loc> {
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub(crate) assignments: Vec<LetExpr<'loc>>,
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub(crate) guard_rules: Vec<Rule<'loc>>,
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub(crate) parameterized_rules: Vec<ParameterizedRule<'loc>>,
}

/// What a query join reads at the seam before an element: whether the element brings its own
/// separator and follows its predecessor directly, or takes a `.`. Decided by the element's KIND,
/// never by the text it renders: a key is a key whatever its text, so `"[x"` and `" x"` keep their
/// `.` (`M.[x`, `M. x`), where a join that read the rendered text's first byte dropped it and named a
/// path the template does not hold, the same rewrite that once turned `a.[b` into `a[b`. The kind
/// answers for what its `Display` prints: only a variant whose text opens with its own separator
/// (`[*]`, ` (filter-clauses)`) follows directly.
pub(crate) trait SeamPart {
    fn follows_directly(&self) -> bool;
}

impl SeamPart for QueryPart<'_> {
    /// A wildcard index (`[*]`, whose `Display` brings its brackets) and an unnamed filter
    /// (` (filter-clauses)`, the space being the separator its `Display` keeps between a capture name
    /// and the parenthetical) follow their predecessor directly: `Resources.*.Tags[*].Key`,
    /// `Resources.* (filter-clauses)`. Every other part takes its `.`: a key, a wildcard, a variable,
    /// `_`, a named filter (`Tags.p (filter-clauses)`), and a NUMBERED index, whose `Display` prints
    /// the bare number with no brackets of its own, so `Tags[0].Key` renders `Tags.0.Key` as it always
    /// has; listed here as following directly it would render `Tags0.Key`, a key the template does not
    /// hold. The rule is read against each variant's
    /// own `Display`: a part follows directly only when the text it prints opens with its own
    /// separator. The match is exhaustive, as the sibling renderer's (`QueryWithFilters`) is, so a
    /// new part has to be placed here by the reading of its own `Display`, never by the default a
    /// `matches!` would have given it.
    fn follows_directly(&self) -> bool {
        match self {
            QueryPart::AllIndices(_)
            | QueryPart::AuthoredIndices
            | QueryPart::Filter(None, _)
            | QueryPart::MapKeyFilter(None, _) => true,
            QueryPart::This
            | QueryPart::Key(_)
            | QueryPart::Variable(_)
            | QueryPart::AllValues(_)
            | QueryPart::Index(_)
            | QueryPart::Filter(Some(_), _)
            | QueryPart::MapKeyFilter(Some(_), _) => false,
        }
    }
}

impl SeamPart for crate::rules::QueryResult {
    /// A value is never a part: the `to=` list of a membership check's record joins every element with
    /// `.` (each renders `literal, ...`, `(resolved, ...)` or `(unresolved, ...)`, none of which opens
    /// with `[`, so a text rule that dropped the `.` before a `[` would not reach them either).
    fn follows_directly(&self) -> bool {
        false
    }
}

pub(crate) struct SliceDisplay<'a, T: 'a>(pub(crate) &'a [T]);
impl<'a, T: std::fmt::Display + SeamPart + 'a> std::fmt::Display for SliceDisplay<'a, T> {
    /// The parts joined by `.`, except before a part that brings its own separator ([`SeamPart`]): a
    /// wildcard index follows its predecessor directly, `Resources.*.Tags[*].Key`, and an unnamed
    /// filter follows it with the space its own `Display` opens with, `Resources.* (filter-clauses)`;
    /// a numbered index prints bare and takes its `.`, `Tags.0.Key`. The join reads only the KIND of
    /// the part at each seam, never a part's text, so a key renders byte for byte whatever it holds
    /// (`a.[b`, `.[x`, `. x`). Joining every part with `.` and then dropping the `.` before every `[`
    /// in the whole string would rewrite the key `a.[b` to `a[b`, a key the template does not hold;
    /// deciding the seam from the next part's first byte would push a `.` before an unnamed filter
    /// (`Resources.*. (filter-clauses)`, a stray `. ` in every remaining-query and context text that
    /// spelled it) and drop it before a key whose text opens with `[` (`M[x` for the key `"[x"`), the
    /// same class of rewrite.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut query = String::new();
        for (position, item) in self.0.iter().enumerate() {
            if position > 0 && !item.follows_directly() {
                query.push('.');
            }
            query.push_str(&format!("{}", item));
        }
        f.write_str(&query)?;
        Ok(())
    }
}

/// A query rendered with its filters spelled out, for a message whose subject is the query.
///
/// [`SliceDisplay`] stands in the parser's own name for a filter, `(filter-clauses)`, which is what
/// every `Context=` line and every query-naming message prints, and those stay as they are. A message
/// that names a query as *what was tested* needs more than that: two clauses that filter the same
/// collection differently are different tests, and a subject that reads `Items (filter-clauses)`
/// for both of them tells the reader nothing about which filter selected nothing.
///
/// A filter prints inside the brackets the author wrote it in, as the grammar spells it: a capture
/// as `[ name | ... ]`, each predicate clause as `not <query> <comparator> <value>` with the
/// comparator's word, disjunctions joined by ` or ` and conjunctions by a space, and a key filter as
/// `[ keys <comparator> <value> ]`. Every shape the `clause` production admits inside a predicate
/// renders through this same renderer, so no level falls back to the placeholder: a query inside a
/// clause, a `some` written there, a filter inside a function argument, a block clause (`query { ..
/// }`, with `not empty` when written), a `when` block with its conditions, a named rule, and a
/// parameterized rule call with its arguments. Every other part prints as the grammar reads it: a
/// key bare when `var_name` would accept it and quoted otherwise, so `"a.b"` and `a.b` print apart;
/// an index as `[n]`, so `[0]` and `."0"` print apart; `this`, `%name`, `*`, `[*]`, and a named index
/// capture as `[ name ]`. Parts are joined by `.` except before a bracketed one. The match over the
/// parts is exhaustive, as is `is_bracketed`, so a new part has to be placed in both. A query of keys
/// and wildcards alone renders as [`SliceDisplay`] renders it.
///
/// A variable-rooted query is printed without the slot the parser reserves after the variable.
/// `access_query` inserts `AllIndices(None)` at slot 1 of every `%v.rest` query, and keeps an author's
/// own `[*]` there as `AuthoredIndices`, the variant that exists to record who wrote it; so the
/// inserted slot is skipped and the authored one is printed. Only slot 1 of a variable-rooted query is
/// read this way, so `%v.Tags[*]` keeps its `[*]` as written.
///
/// Literals print in the rule language rather than through the value renderer, whose spelling is
/// not reversible: it wrote a regex and a string holding slashes both as `"/prod/"`, a range and a
/// two-element list both as `[1,5]`, `null` and the string `'NULL'` both as `"NULL"`, and left
/// quotes unescaped. Here a string is `'...'` with `\` and `'` escaped and any control character or
/// line or paragraph separator written as `\u{...}`, a regex is `/.../` with `/`
/// escaped, a range is `r[..]`, `r(..]`, `r[..)` or `r(..)` as its bounds were, `null` is `null`, a
/// list is `[a, b]` (its first five items and a count of the rest when it is longer, see
/// `LIST_ITEMS_SHOWN`), a map is `{ key: value }` with a key quoted when the grammar would need it,
/// a float keeps its point (`1.0`, apart from the int `1`), and ints and booleans print as written.
/// The join and the spacing are decided part by part and
/// clause by clause, not by a pass over the finished string: a global `.[` to `[` replacement would
/// turn the regex `/^arn:.[0-9]+/` into `/^arn:[0-9]+/`, and collapsing whitespace would print
/// `'a  b'` as `'a b'`, and either way two different filters would print one subject, which is the
/// collision this renderer exists to remove.
///
/// This renders the parts of a query. [`AccessQueryWithFilters`] renders a whole [`AccessQuery`],
/// `some` included, and is what a clause record carries.
pub(crate) struct QueryWithFilters<'a, 'loc: 'a>(pub(crate) &'a [QueryPart<'loc>]);
impl<'a, 'loc: 'a> std::fmt::Display for QueryWithFilters<'a, 'loc> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let reserved_slot = self.0.len() > 1
            && self.0[0].is_variable()
            && matches!(self.0[1], QueryPart::AllIndices(None));
        for (index, part) in self.0.iter().enumerate() {
            if index == 1 && reserved_slot {
                continue;
            }
            if index > 0 && !is_bracketed(part) {
                f.write_str(".")?;
            }
            match part {
                QueryPart::This => f.write_str("this")?,
                QueryPart::Key(key) => write_key(f, key)?,
                QueryPart::Variable(name) => write!(f, "%{}", name)?,
                QueryPart::AllValues(_) => f.write_str("*")?,
                QueryPart::AllIndices(None) | QueryPart::AuthoredIndices => f.write_str("[*]")?,
                QueryPart::AllIndices(Some(name)) => write!(f, "[ {} ]", name)?,
                QueryPart::Index(index) => write!(f, "[{}]", index)?,
                QueryPart::Filter(capture, conjunctions) => {
                    f.write_str("[ ")?;
                    if let Some(name) = capture {
                        write!(f, "{} | ", name)?;
                    }
                    let mut first_conjunction = true;
                    for disjunction in conjunctions {
                        if !first_conjunction {
                            f.write_str(" ")?;
                        }
                        first_conjunction = false;
                        for (position, clause) in disjunction.iter().enumerate() {
                            if position > 0 {
                                f.write_str(" or ")?;
                            }
                            write_predicate_clause(f, clause)?;
                        }
                    }
                    f.write_str(" ]")?;
                }
                QueryPart::MapKeyFilter(capture, clause) => {
                    f.write_str("[ ")?;
                    if let Some(name) = capture {
                        write!(f, "{} | ", name)?;
                    }
                    write!(
                        f,
                        "keys {} ",
                        display_comparator(clause.comparator.as_cmp_operator()).trim_end()
                    )?;
                    write_let_value_with_filters(f, &clause.compare_with)?;
                    f.write_str(" ]")?;
                }
            }
        }
        Ok(())
    }
}

/// Whether a part is written in brackets, so that no `.` precedes it. Exhaustive, as the renderer's
/// own match is, so a new part has to say which it is.
fn is_bracketed(part: &QueryPart<'_>) -> bool {
    match part {
        QueryPart::Filter(..)
        | QueryPart::MapKeyFilter(..)
        | QueryPart::AllIndices(..)
        | QueryPart::AuthoredIndices
        | QueryPart::Index(_) => true,
        QueryPart::This | QueryPart::Key(_) | QueryPart::Variable(_) | QueryPart::AllValues(_) => {
            false
        }
    }
}

/// A key as the grammar spells it: bare when `var_name` would read it (an ASCII letter, then
/// letters, digits and underscores), quoted otherwise, so `"a.b"` and `a.b`, or `"0"` and `[0]`,
/// print apart.
fn write_key(f: &mut std::fmt::Formatter, key: &str) -> std::fmt::Result {
    let mut chars = key.chars();
    let bare = matches!(chars.next(), Some(c) if c.is_ascii_alphabetic())
        && chars.all(|c| c.is_alphanumeric() || c == '_');
    if bare {
        f.write_str(key)
    } else {
        write_quoted(f, key)
    }
}

/// An [`AccessQuery`] rendered through [`QueryWithFilters`], with the `some` the author wrote.
///
/// `Display for AccessQuery` keeps the modifier visible for the same reason, and so does this: a
/// `some` clause and its `match_all` twin are different tests, and a subject that drops the word
/// names a test the author did not write.
pub(crate) struct AccessQueryWithFilters<'a, 'loc: 'a>(pub(crate) &'a AccessQuery<'loc>);
impl<'a, 'loc: 'a> std::fmt::Display for AccessQueryWithFilters<'a, 'loc> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        if !self.0.match_all {
            f.write_str("some ")?;
        }
        write!(f, "{}", QueryWithFilters(&self.0.query))
    }
}

/// One clause of a filter predicate, in the grammar's spelling with single spaces.
///
/// Written here rather than through `Display for GuardClause` because that renderer leaves a space
/// where an absent `not` or right-hand side would go, and renders its queries through
/// [`SliceDisplay`]. Every variant the `clause` production can put in a predicate is spelled: an
/// access clause as `not <query> <comparator> <value>`, a block clause as `query not empty { body }`,
/// a `when` block as `when conditions { body }`, a named rule as `not name`, and a parameterized call
/// as `not name(args)`. A body is its `let` assignments then its clauses, each disjunction as `a or
/// b`, the groups separated by `; `.
fn write_predicate_clause(
    f: &mut std::fmt::Formatter,
    clause: &GuardClause<'_>,
) -> std::fmt::Result {
    match clause {
        GuardClause::Clause(access) => write_access_clause_with_filters(f, access),
        GuardClause::BlockClause(block) => {
            write!(f, "{}", AccessQueryWithFilters(&block.query))?;
            if block.not_empty {
                f.write_str(" not empty")?;
            }
            f.write_str(" { ")?;
            write_block_with_filters(f, &block.block)?;
            f.write_str(" }")
        }
        GuardClause::WhenBlock(conditions, block) => {
            f.write_str("when ")?;
            let mut first_conjunction = true;
            for disjunction in conditions {
                if !first_conjunction {
                    f.write_str(" ")?;
                }
                first_conjunction = false;
                for (position, condition) in disjunction.iter().enumerate() {
                    if position > 0 {
                        f.write_str(" or ")?;
                    }
                    match condition {
                        WhenGuardClause::Clause(access) => {
                            write_access_clause_with_filters(f, access)?
                        }
                        WhenGuardClause::NamedRule(named) => write_named_rule(f, named)?,
                        WhenGuardClause::ParameterizedNamedRule(call) => {
                            write_parameterized_call_with_filters(f, call)?
                        }
                    }
                }
            }
            f.write_str(" { ")?;
            write_block_with_filters(f, block)?;
            f.write_str(" }")
        }
        GuardClause::NamedRule(named) => write_named_rule(f, named),
        GuardClause::ParameterizedNamedRule(call) => write_parameterized_call_with_filters(f, call),
    }
}

/// `not <query> <comparator> <value>`, the query with its filters and the value in rule syntax.
fn write_access_clause_with_filters(
    f: &mut std::fmt::Formatter,
    access: &GuardAccessClause<'_>,
) -> std::fmt::Result {
    if access.negation {
        f.write_str("not ")?;
    }
    write!(
        f,
        "{} {}",
        AccessQueryWithFilters(&access.access_clause.query),
        display_comparator(access.access_clause.comparator).trim_end()
    )?;
    if let Some(value) = &access.access_clause.compare_with {
        f.write_str(" ")?;
        write_let_value_with_filters(f, value)?;
    }
    Ok(())
}

/// `not name(a, b)`, each argument rendered as a right-hand side is.
fn write_parameterized_call_with_filters(
    f: &mut std::fmt::Formatter,
    call: &ParameterizedNamedRuleClause<'_>,
) -> std::fmt::Result {
    if call.named_rule.negation {
        f.write_str("not ")?;
    }
    write!(f, "{}(", call.named_rule.dependent_rule)?;
    for (position, parameter) in call.parameters.iter().enumerate() {
        if position > 0 {
            f.write_str(", ")?;
        }
        write_let_value_with_filters(f, parameter)?;
    }
    f.write_str(")")
}

/// A block body inside a predicate: `let v = value; a or b; c`, every query with its filters.
fn write_block_with_filters(
    f: &mut std::fmt::Formatter,
    block: &Block<'_, GuardClause<'_>>,
) -> std::fmt::Result {
    let mut first = true;
    for assignment in &block.assignments {
        if !first {
            f.write_str("; ")?;
        }
        first = false;
        write!(f, "let {} = ", assignment.var)?;
        write_let_value_with_filters(f, &assignment.value)?;
    }
    for disjunction in &block.conjunctions {
        if !first {
            f.write_str("; ")?;
        }
        first = false;
        for (position, clause) in disjunction.iter().enumerate() {
            if position > 0 {
                f.write_str(" or ")?;
            }
            write_predicate_clause(f, clause)?;
        }
    }
    Ok(())
}

/// A right-hand side inside a predicate: a query renders with its filters, a literal in rule syntax,
/// a function call as `name(args)` with each argument rendered the same way.
fn write_let_value_with_filters(
    f: &mut std::fmt::Formatter,
    value: &LetValue<'_>,
) -> std::fmt::Result {
    match value {
        LetValue::AccessClause(query) => write!(f, "{}", AccessQueryWithFilters(query)),
        LetValue::Value(literal) => write_rule_literal(f, literal),
        LetValue::FunctionCall(call) => {
            write!(f, "{}(", call.name)?;
            for (position, parameter) in call.parameters.iter().enumerate() {
                if position > 0 {
                    f.write_str(", ")?;
                }
                write_let_value_with_filters(f, parameter)?;
            }
            f.write_str(")")
        }
    }
}

/// A literal in the rule language, as the parser would read it back.
///
/// Strings are single-quoted with `\` and `'` escaped, which is what `parse_string` undoes, and with
/// control characters and the line and paragraph separators as `\u{...}` (see `write_quoted`); a regex
/// is `/.../` with `/` escaped, which is what `parse_regex` undoes; a range is `r` plus its bounds
/// with the bracket each end was written with; a list is `[a, b]`; a map is `{ key: value }`, the key
/// bare when it is the letters, digits, `-` and `_` the grammar reads bare and quoted otherwise; a
/// char prints as itself, which is how it is written inside a range's bounds. `null`, numbers and
/// booleans print as written.
fn write_rule_literal(f: &mut std::fmt::Formatter, literal: &PathAwareValue) -> std::fmt::Result {
    match literal {
        PathAwareValue::Null(_) => f.write_str("null"),
        PathAwareValue::String((_, s)) => write_quoted(f, s),
        PathAwareValue::Regex((_, r)) => write!(f, "/{}/", r.replace('/', "\\/")),
        PathAwareValue::Bool((_, b)) => write!(f, "{}", b),
        PathAwareValue::Int((_, i)) => write!(f, "{}", i),
        // `{:?}`, which keeps the point on a whole number: `1.0` prints as `1.0`, so a float literal
        // and the int literal `1` print apart, as the grammar reads them apart.
        PathAwareValue::Float((_, x)) => write!(f, "{:?}", x),
        PathAwareValue::Char((_, c)) => write!(f, "{}", c),
        PathAwareValue::List((_, items)) => {
            f.write_str("[")?;
            for (position, item) in items.iter().take(LIST_ITEMS_SHOWN).enumerate() {
                if position > 0 {
                    f.write_str(", ")?;
                }
                write_rule_literal(f, item)?;
            }
            if items.len() > LIST_ITEMS_SHOWN {
                write!(f, ", \u{2026} {} more", items.len() - LIST_ITEMS_SHOWN)?;
            }
            f.write_str("]")
        }
        PathAwareValue::Map((_, map)) => {
            f.write_str("{ ")?;
            for (position, (key, value)) in map.values.iter().enumerate() {
                if position > 0 {
                    f.write_str(", ")?;
                }
                let bare = !key.is_empty()
                    && key
                        .chars()
                        .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
                if bare {
                    f.write_str(key)?;
                } else {
                    write_quoted(f, key)?;
                }
                f.write_str(": ")?;
                write_rule_literal(f, value)?;
            }
            f.write_str(" }")
        }
        PathAwareValue::RangeInt((_, range)) => {
            write_range_literal(f, range, |bound| bound.to_string())
        }
        // `{:?}` for the same reason as a float literal: `r[1.0,5.0]` and `r[1,5]` print apart.
        PathAwareValue::RangeFloat((_, range)) => {
            write_range_literal(f, range, |bound| format!("{:?}", bound))
        }
        PathAwareValue::RangeChar((_, range)) => {
            write_range_literal(f, range, |bound| bound.to_string())
        }
    }
}

/// How many items of a list literal the subject prints before a count of the rest.
///
/// The subject travels in one-line channels, and the CloudFormation reporter cuts a message at 320
/// characters, so a list printed in full (a denylist of five hundred names) would run to kilobytes
/// and two long filters would be cut to one identical line. Five is the cap the CloudFormation
/// reporter already applies to a long `IN` comparison. Two lists of different length still print
/// apart through the count; two of one length that differ only past the fifth item print alike,
/// which is the cap's cost.
const LIST_ITEMS_SHOWN: usize = 5;

/// `'...'` with `\` and `'` escaped, and every control character and line or paragraph separator
/// written as `\u{...}`.
///
/// The subject travels in single-line channels: the summary line, a structured report's
/// `error_message`, a tree line. A string literal may hold a character that breaks a line there
/// without being a line feed: a vertical tab, a form feed, NEL (U+0085), LINE SEPARATOR (U+2028) or
/// PARAGRAPH SEPARATOR (U+2029), which libyaml and most terminals break at, and the other C0 and C1
/// controls, which a terminal may act on. Each is written as its code point in the `\u{...}` form
/// the rest of the crate uses for the same purpose, so the line stays one line and the reader can
/// tell `'a<U+2028>b'` from `'a b'`. The grammar has no `\u` escape, so the written form does not
/// read back as the character; it is a report spelling, as the escapes in `escaped_for_display` are.
fn write_quoted(f: &mut std::fmt::Formatter, s: &str) -> std::fmt::Result {
    f.write_str("'")?;
    for c in s.chars() {
        match c {
            '\\' => f.write_str("\\\\")?,
            '\'' => f.write_str("\\'")?,
            c if c.is_control() || c == '\u{2028}' || c == '\u{2029}' => {
                write!(f, "\\u{{{:x}}}", c as u32)?
            }
            other => write!(f, "{}", other)?,
        }
    }
    f.write_str("'")
}

/// `r[lower,upper]`, each bracket as the bound was written: `[`/`]` for an inclusive end and
/// `(`/`)` for an exclusive one. `bound` spells one end the way its kind is written.
fn write_range_literal<T: PartialOrd>(
    f: &mut std::fmt::Formatter,
    range: &RangeType<T>,
    bound: impl Fn(&T) -> String,
) -> std::fmt::Result {
    let open = if range.inclusive & LOWER_INCLUSIVE == LOWER_INCLUSIVE {
        '['
    } else {
        '('
    };
    let close = if range.inclusive & UPPER_INCLUSIVE == UPPER_INCLUSIVE {
        ']'
    } else {
        ')'
    };
    write!(
        f,
        "r{}{},{}{}",
        open,
        bound(&range.lower),
        bound(&range.upper),
        close
    )
}

/// Renders every variant the `clause` production can build.
///
/// Every arm is rendered, with no `_ => unimplemented!()` fallback. A `when` block and a parameterized
/// rule call are two shapes `clause` builds, bare or as the body of a `Properties { .. }` block, and
/// `Display for BlockGuardClause` below forwards each body clause here, so an arm that panicked with
/// "not implemented" would panic the whole render of any body holding that shape. A `NamedRule` is built
/// by `rule_clause` rather than `clause`, so it is not reachable through a block body, but it is the same
/// enum and renders here too, as its bare spelling.
///
/// The spellings are the grammar's: `not name`, `not name(a, b)`, `when conds { body }`. The
/// conditions are written as the grammar reads them, disjunctions joined by ` or ` and conjunctions by
/// a space, with nothing after the last one before the `{`; the body is rendered the same way
/// `Display for BlockGuardClause` renders its own.
impl<'loc> std::fmt::Display for GuardClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardClause::Clause(individual) => individual.fmt(f)?,
            GuardClause::BlockClause(block) => block.fmt(f)?,
            GuardClause::NamedRule(named) => write_named_rule(f, named)?,
            GuardClause::ParameterizedNamedRule(call) => call.fmt(f)?,
            GuardClause::WhenBlock(conditions, block) => {
                f.write_str("when ")?;
                write_conditions(f, conditions)?;
                f.write_str(" { ")?;
                write_block_body(f, block)?;
                f.write_str(" }")?;
            }
        }
        Ok(())
    }
}

/// `when` conditions as the grammar spells them: `a or b c`, each disjunction's terms joined by
/// ` or ` and the conjunctions by a space, with no terminator, so that the `{` that follows reads as
/// the grammar's.
fn write_conditions<T: std::fmt::Display>(
    f: &mut Formatter<'_>,
    conjunctions: &Conjunctions<T>,
) -> std::fmt::Result {
    let mut first_conjunction = true;
    for each in conjunctions {
        if let Some((last, rest)) = each.split_last() {
            if !first_conjunction {
                f.write_str(" ")?;
            }
            first_conjunction = false;
            for clause in rest {
                write!(f, "{} or ", clause)?;
            }
            write!(f, "{}", last)?;
        }
    }
    Ok(())
}

impl<'loc> std::fmt::Display for WhenGuardClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            WhenGuardClause::Clause(individual) => individual.fmt(f),
            WhenGuardClause::NamedRule(named) => write_named_rule(f, named),
            WhenGuardClause::ParameterizedNamedRule(call) => call.fmt(f),
        }
    }
}

/// `not name(a, b)`, the spelling `parameterized_rule_call_clause` reads.
impl<'loc> std::fmt::Display for ParameterizedNamedRuleClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if self.named_rule.negation {
            f.write_str("not ")?;
        }
        let params = self
            .parameters
            .iter()
            .map(|each| each.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}({})", self.named_rule.dependent_rule, params)
    }
}

/// `not name`, the spelling `rule_clause` reads for a reference to another rule.
///
/// A free function rather than `Display for GuardNamedRuleClause`: that impl exists in `evaluate.rs` and
/// renders `Rule(name@location)` for the evaluation report, and the two cannot share one trait impl.
fn write_named_rule(f: &mut Formatter<'_>, named: &GuardNamedRuleClause<'_>) -> std::fmt::Result {
    if named.negation {
        f.write_str("not ")?;
    }
    f.write_str(&named.dependent_rule)
}

/// A block body's clauses: each disjunction as `a or b`, each conjunction closed with `; `, which is
/// how `Display for BlockGuardClause` has always rendered a body.
fn write_conjunctions<T: std::fmt::Display>(
    f: &mut Formatter<'_>,
    conjunctions: &Conjunctions<T>,
) -> std::fmt::Result {
    for each in conjunctions {
        if let Some((last, rest)) = each.split_last() {
            for clause in rest {
                write!(f, "{} or ", clause)?;
            }
            write!(f, "{}; ", last)?;
        }
    }
    Ok(())
}

/// A block's `let` assignments, then its clauses.
fn write_block_body<T: std::fmt::Display>(
    f: &mut Formatter<'_>,
    block: &Block<'_, T>,
) -> std::fmt::Result {
    for assignment in &block.assignments {
        write!(f, "let {} = {}; ", assignment.var, assignment.value)?;
    }
    write_conjunctions(f, &block.conjunctions)
}

/// Renders a block clause as `query { let v = value; ... clause or clause; ... }`: the block's `let`
/// assignments first, each closed with `; `, then its clauses the same way.
///
/// Written with `split_last` rather than an index and a length because both numbers were wrong, in
/// opposite directions, and neither could be right at once. `for idx in 0..len - 2` skipped the
/// second-to-last term of a disjunction and underflowed outright for `len == 1` -- the length every
/// ordinary `q { .. }` produces -- and `each[len]` is one past the end for every length, so no input
/// rendered. A one-clause block panicked with "attempt to subtract with overflow" and a two-clause
/// block panicked on the index.
///
/// `split_last` carries no arithmetic and no indexing, so the impl cannot underflow or run off the end
/// for any length, including the empty disjunction that `separated_list1` cannot currently build. That
/// is the reason for the shape: patching the two numbers would leave a construct whose correctness
/// depends on a length invariant enforced somewhere else in the file.
///
/// This had no call site in the library or the binary when the defect was found, which is why it was
/// latent rather than live -- `rendering_a_block_clause_does_not_panic` and
/// `rendering_every_clause_variant_does_not_panic` in `parser_regression_repros` are the only callers in
/// the workspace, and they exist to keep this rendering exercised.
///
/// The body is written by `write_block_body`, shared with the `when` block arm of `Display for
/// GuardClause`, so the two block shapes cannot drift apart.
impl<'loc> std::fmt::Display for BlockGuardClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {{ ", self.query)?;
        write_block_body(f, &self.block)?;
        write!(f, " }}")?;
        Ok(())
    }
}

impl<'loc> std::fmt::Display for GuardAccessClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}",
            if self.negation { "not" } else { "" },
            self.access_clause
        )?;
        Ok(())
    }
}

impl<'loc> std::fmt::Display for AccessClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {} {}",
            self.query,
            display_comparator(self.comparator),
            match &self.compare_with {
                Some(value) => format!("{}", value),
                None => "".to_string(),
            }
        )?;
        Ok(())
    }
}

impl<'loc> std::fmt::Display for AccessQuery<'loc> {
    /// With its modifier. This is the text a clause is recorded and printed under, and a `some` the
    /// author wrote has to be visible there to be told apart from one the evaluator ignored. Rendered
    /// here rather than at any one use, so a left-hand query, a right-hand one, and a query passed to a
    /// function or a parameterized rule all print it alike.
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        if !self.match_all {
            f.write_str("some ")?;
        }
        write!(f, "{}", SliceDisplay(&self.query))?;
        Ok(())
    }
}

impl<'loc> std::fmt::Display for FunctionExpr<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let params = self
            .parameters
            .iter()
            .map(|each| each.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        write!(f, "{}({})", &self.name, params)
    }
}

impl<'loc> std::fmt::Display for LetValue<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LetValue::AccessClause(acc) => acc.fmt(f)?,
            LetValue::Value(v) => write!(f, "{}", ValueOnlyDisplay(Rc::new(v.clone())))?,
            LetValue::FunctionCall(call_expr) => write!(f, "{}", call_expr)?,
        }
        Ok(())
    }
}

pub(crate) fn display_comparator(cmp: (CmpOperator, bool)) -> String {
    let (op, not) = cmp;
    format!("{}{} ", if not { "not " } else { "" }, op)
}
