use crate::rules::values::*;

use crate::rules::display::ValueOnlyDisplay;
use crate::rules::path_value::PathAwareValue;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
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
/// match specific selections [crate::rules::common::walk_type]
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
/// * Predicate query, which is used to select instances from an array of structure. If we need to
/// select all entries in the array use the `[*]` syntax. To select specific elements in the array
/// use the structural key matches. E.g. to select all resources from an CFN template that match the
/// DynamoDB Table we can use the following `resources.*[type=/AWS::Dynamo/]`
///
///
#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) enum QueryPart<'loc> {
    This,
    Key(String),
    MapKeyFilter(Option<String>, MapKeyFilterClause<'loc>),
    AllValues(Option<String>),
    AllIndices(Option<String>),
    /// An array index as written in the rule, kept at the width the parser reads.
    ///
    /// `i32` before, narrowed with `as i32` at both parse sites, which wrapped instead of rejecting:
    /// `Items[4294967296]` became `Items[0]` and the clause then compared the wrong element and
    /// passed. Retrieval already reports an out-of-range index as unresolved, so widening is all that
    /// is needed -- the bounds check does the rejecting.
    Index(i64),
    Filter(Option<String>, Conjunctions<GuardClause<'loc>>),
}

impl<'loc> QueryPart<'loc> {
    pub(crate) fn is_variable(&self) -> bool {
        let name = match self {
            QueryPart::Key(name) => name,
            _ => return false,
        };
        name.starts_with('%')
    }

    pub(crate) fn variable(&self) -> Option<&str> {
        let name = match self {
            QueryPart::Key(name) => name,
            _ => return None,
        };
        if name.starts_with('%') {
            name.strip_prefix('%')
        } else {
            None
        }
    }
}

impl<'loc> std::fmt::Display for QueryPart<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryPart::Key(s) => {
                f.write_str(s.as_str())?;
            }

            QueryPart::AllIndices(_name) => {
                f.write_str("[*]")?;
            }

            QueryPart::AllValues(_name) => {
                f.write_str("*")?;
            }

            QueryPart::Index(idx) => {
                write!(f, "{}", idx)?;
            }

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

    /// Equality against more than one right-hand value is membership.
    ///
    /// `keys == %several` reads as "each key equals" and is evaluated as "is among", which is what
    /// the `Eq`-with-multiple-values promotion has always done. Kept as a method so the rule is
    /// stated once rather than inline in the evaluator.
    pub(crate) fn widened_for(self, rhs_count: usize) -> Self {
        match self {
            MapKeyComparator::Eq if rhs_count > 1 => MapKeyComparator::In,
            MapKeyComparator::NotEq if rhs_count > 1 => MapKeyComparator::NotIn,
            unchanged => unchanged,
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
/// cannot be answered from what happened at runtime. An earlier version of this fix learned names as
/// keys were captured, which made the verdict depend on document order -- the same two buckets gave
/// FAIL in one order and a file-fatal error in the other, because whichever bucket ran first was the
/// one that taught the engine the name existed at all.
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
/// An earlier version of this check drew the line on where a block's keys land at runtime instead, using
/// `block_capture_names`, which descends into nested blocks because that is where their merged keys
/// arrive. It made two files an author cannot tell apart disagree: a rule-body `let` with a capture in a
/// block inside the rule was refused, while the same capture with the `let` moved out to the file level
/// was accepted. Both are "an assignment outside, a capture in a block inside".
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

    for rule in rules() {
        if let Some(name) = first_in_rule_block(&rule.block) {
            return Some((name, format!("in rule {}", rule.rule_name)));
        }
    }

    None
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
/// own assignments and its own captures rather than against an outer scope's.
fn first_in_rule_block<'value, 'loc: 'value>(
    block: &'value Block<'loc, RuleClause<'loc>>,
) -> Option<String> {
    let mut captures = BTreeSet::new();
    for assignment in &block.assignments {
        collect_let_value_capture_names(&assignment.value, &mut captures);
    }
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            match clause {
                RuleClause::Clause(guard_clause) => {
                    collect_own_guard_clause_capture_names(guard_clause, &mut captures)
                }

                // The conditions are written outside the braces, so they are this scope's; the block
                // they guard is its own.
                RuleClause::WhenBlock(conditions, _) => {
                    collect_conjunctions_capture_names(conditions, &mut captures)
                }

                // Likewise, and the type block's query selects the resources at this level.
                RuleClause::TypeBlock(type_block) => {
                    collect_query_capture_names(&type_block.query, &mut captures);
                    if let Some(conditions) = &type_block.conditions {
                        collect_conjunctions_capture_names(conditions, &mut captures);
                    }
                }
            }
        }
    }
    if let Some(name) = first_assigned_and_captured(&block.assignments, &captures) {
        return Some(name);
    }

    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            let found = match clause {
                RuleClause::Clause(guard_clause) => first_in_guard_clause(guard_clause),
                RuleClause::WhenBlock(_, inner) => first_in_guard_block(inner),
                RuleClause::TypeBlock(type_block) => first_in_guard_block(&type_block.block),
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
) -> Option<String> {
    let mut captures = BTreeSet::new();
    for assignment in &block.assignments {
        collect_let_value_capture_names(&assignment.value, &mut captures);
    }
    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            collect_own_guard_clause_capture_names(clause, &mut captures);
        }
    }
    if let Some(name) = first_assigned_and_captured(&block.assignments, &captures) {
        return Some(name);
    }

    for disjunctions in &block.conjunctions {
        for clause in disjunctions {
            if let Some(name) = first_in_guard_clause(clause) {
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

fn first_in_guard_clause<'value, 'loc: 'value>(
    clause: &'value GuardClause<'loc>,
) -> Option<String> {
    match clause {
        GuardClause::BlockClause(block_clause) => first_in_guard_block(&block_clause.block),
        GuardClause::WhenBlock(_, block) => first_in_guard_block(block),
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

/// Every query part that populates a capture counts: `Filter`, `MapKeyFilter`, and a named `AllValues`
/// or `AllIndices`.
///
/// A `Filter` directly after a wildcard used to be skipped, because the wildcard expanded the map
/// before the filter ran and the name was dropped rather than captured. Now that the filter runs at the
/// expansion site with the key in hand, such a name is a real capture and has to be counted -- leaving
/// it out reopened the cross-iteration fallthrough for exactly the spelling that had just been fixed:
/// `Properties.Config[*][ cfg | Enabled == true ]` in a per-resource block, read as `%cfg`, went back to
/// answering with a previous resource's key at exit 0.
///
/// `AllValues` and `AllIndices` were omitted on the reading that their `Option<String>` was collected
/// through arms of their own. There are no such arms; this is the only walk over query parts. Both
/// arms call `add_variable_capture_key` when the name is `Some` and the value under them is a map, so a
/// name written there is a capture on the same footing as a filter's.
///
/// Omitting them left an entire spelling undeclared rather than an unusual corner of one. `all_indices`
/// is the first branch of `predicate_or_index` and it accepts a bare `var_name`, so the pipe-less
/// `Properties.Tags[ tk ]` parses to `AllIndices(Some("tk"))` and never reaches `Filter` at all. Read as
/// `%tk` from a sibling `when` block that only a resource without `Tags` entered, it answered with a
/// previous resource's key: that resource alone exited 255, a compliant resource ahead of it exited 0,
/// and the reverse order exited 255. Document order decided the verdict and the leaking order was the
/// one that passed. Pre-existing rather than introduced by scoping capture names -- `origin/main` at
/// ef17f36 gives the same three exit codes -- because no scope ever held the name to begin with.
///
/// One shape still cannot capture: a wildcard over a *list*, where `accumulate` has an index rather
/// than a key. A name declared there is counted anyway and resolves empty rather than erroring, which
/// costs a less precise message on a rule that cannot work either way. That is the right side to err
/// on -- an imprecise failure is recoverable for the reader, and a silent pass is not.
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

            QueryPart::AllValues(name) | QueryPart::AllIndices(name) => {
                if let Some(name) = name {
                    into.insert(name.as_str());
                }
            }

            QueryPart::This | QueryPart::Key(_) | QueryPart::Index(_) => {}
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

            // The type block's own query is where a filter on the resource selection sits, and its
            // conditions are evaluated in this scope too.
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
}

/// The first call site in the file that does not agree with the definition it names, or `None` if
/// every one does.
///
/// Both conditions are decidable from the text, which is the whole argument for answering them here.
/// The arity check in `eval_parameterized_rule_call` reached the same conclusion at evaluation time
/// and returned `Error::IncompatibleError`, which no command classifies, so it propagated to `main`
/// and exited -1 -- the code `guard/tests/utils.rs` names `INTERNAL_FAILURE` -- for a rule-authoring
/// mistake. `parameter_names` already says so in its own doc comment about the duplicate-parameter
/// case it fixed: the mistake was "a rule-authoring mistake the parser was holding in its hand".
///
/// Answering at parse time also settles a call site that is never reached. `rule MAIN { check(1, 2) }`
/// only reported because something evaluated `MAIN`; the same mistake inside a rule nobody references,
/// or behind a `when` that does not match, exited 0 with nothing said. And it removes the
/// self-contradicting report the runtime error produced: stdout said `Status = FAIL` and listed the
/// calling rule under "FAILED rules" while stderr said cfn-guard had broken.
///
/// Only names the file declares are checked. A call to a rule that does not exist stays
/// `find_parameterized_rule`'s `Error::MissingValue`, which a4440ff classified as a rules-file error
/// at exit 5 already; taking that over here would widen this check into rejecting a file for a
/// reference that a `when` might never reach, which is a different decision from this one.
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

    let rules = file
        .guard_rules
        .iter()
        .chain(file.parameterized_rules.iter().map(|each| &each.rule));
    for rule in rules {
        for reference in rule_refs_in(rule) {
            let call = match reference {
                RuleReference::Parameterized(call) => call,
                RuleReference::Plain(_) => continue,
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
            }
        }
    }

    None
}

/// Every rule reference in one rule, its `when` conditions included.
///
/// Both are evaluated by `eval_rule`, so a reference in either reaches the same machinery.
fn rule_refs_in<'value, 'loc: 'value>(
    rule: &'value Rule<'loc>,
) -> Vec<RuleReference<'value, 'loc>> {
    let mut references = vec![];
    if let Some(conditions) = &rule.conditions {
        collect_conjunctions_rule_refs(conditions, &mut references);
    }
    collect_conjunctions_rule_refs(&rule.block.conjunctions, &mut references);
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
/// A parameterized call's arguments are not walked, because a `LetValue` holds a value, a query or a
/// function call and none of the three can name a rule.
///
/// Every arm that recurses carries a reference today, this file's own bodies included, so none of them is
/// a tripwire for a hypothetical grammar change. A rule body reaches one directly, through a rule-level
/// `when`, through a nested `when` block, and through a type block's `when` conditions. The *bodies* of a
/// type block and of a block clause reach one in two spellings: both take `block(clause)`, and `clause`
/// is an alternation of five arms of which three are not access clauses -- a nested `block_clause`, a
/// `when_block`, and `parameterized_rule_call_clause`. So
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

impl<'value, 'loc: 'value> RuleRefs<'value, 'loc> for GuardClause<'loc> {
    fn collect_rule_refs(&'value self, into: &mut Vec<RuleReference<'value, 'loc>>) {
        match self {
            GuardClause::NamedRule(named) => {
                into.push(RuleReference::Plain(named.dependent_rule.as_str()))
            }

            GuardClause::ParameterizedNamedRule(call) => {
                into.push(RuleReference::Parameterized(call))
            }

            GuardClause::BlockClause(block_clause) => {
                collect_conjunctions_rule_refs(&block_clause.block.conjunctions, into)
            }

            GuardClause::WhenBlock(conditions, block) => {
                collect_conjunctions_rule_refs(conditions, into);
                collect_conjunctions_rule_refs(&block.conjunctions, into);
            }

            GuardClause::Clause(_) => {}
        }
    }
}

impl<'value, 'loc: 'value> RuleRefs<'value, 'loc> for RuleClause<'loc> {
    fn collect_rule_refs(&'value self, into: &mut Vec<RuleReference<'value, 'loc>>) {
        match self {
            RuleClause::Clause(clause) => clause.collect_rule_refs(into),

            RuleClause::WhenBlock(conditions, block) => {
                collect_conjunctions_rule_refs(conditions, into);
                collect_conjunctions_rule_refs(&block.conjunctions, into);
            }

            RuleClause::TypeBlock(type_block) => {
                if let Some(conditions) = &type_block.conditions {
                    collect_conjunctions_rule_refs(conditions, into);
                }
                collect_conjunctions_rule_refs(&type_block.block.conjunctions, into);
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
                into.push(RuleReference::Parameterized(call))
            }

            WhenGuardClause::Clause(_) => {}
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
            | QueryPart::Index(_)
            | QueryPart::AllValues(_)
            | QueryPart::AllIndices(_) => {}
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

pub(crate) struct SliceDisplay<'a, T: 'a>(pub(crate) &'a [T]);
impl<'a, T: std::fmt::Display + 'a> std::fmt::Display for SliceDisplay<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut first = true;
        let mut query = String::new();
        for item in self.0 {
            if !first {
                query = format!("{}.{}", query, item);
            } else {
                query = format!("{}", item);
            }
            first = false;
        }
        let query = query.replace(".[", "[");
        f.write_str(&query)?;
        Ok(())
    }
}

impl<'loc> std::fmt::Display for GuardClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardClause::Clause(individual) => individual.fmt(f)?,
            GuardClause::BlockClause(block) => block.fmt(f)?,
            _ => unimplemented!(),
        }
        Ok(())
    }
}

#[allow(clippy::needless_range_loop)]
impl<'loc> std::fmt::Display for BlockGuardClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {{ ", self.query)?;
        for each in &self.block.conjunctions {
            let len = each.len();
            for idx in 0..len - 2 {
                write!(f, "{} or ", each[idx])?;
            }
            write!(f, "{}; ", each[len])?;
        }
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
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
