use crate::rules::values::*;

use crate::rules::display::ValueOnlyDisplay;
use crate::rules::path_value::PathAwareValue;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
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

/// Only `Filter` and `MapKeyFilter` names count, and not even every `Filter`.
///
/// `AllValues` and `AllIndices` carry an `Option<String>` of the same shape, but a `Filter` sitting
/// directly after either of them has its name dropped rather than captured -- the
/// `check_and_delegate(conjunctions, &None)` branch of `query_retrieval`, because the wildcard has
/// already expanded the map and the key the filter would capture is no longer in scope there.
///
/// Claiming such a name here would turn that dropped capture from a loud unresolved-variable error
/// into a silently empty selection, which reads to the author as "your template had no matching
/// entries" for entries the engine discarded itself. So the two stay in step: when that branch starts
/// threading the key through, `preceded_by_wildcard` comes out with it.
fn collect_query_capture_names<'value, 'loc: 'value>(
    query: &'value [QueryPart<'loc>],
    into: &mut BTreeSet<&'value str>,
) {
    for (index, part) in query.iter().enumerate() {
        match part {
            QueryPart::Filter(name, conjunctions) => {
                let preceded_by_wildcard = matches!(
                    index
                        .checked_sub(1)
                        .and_then(|previous| query.get(previous)),
                    Some(QueryPart::AllValues(_)) | Some(QueryPart::AllIndices(_))
                );
                match name {
                    Some(name) if !preceded_by_wildcard => {
                        into.insert(name.as_str());
                    }
                    _ => {}
                }
                collect_conjunctions_capture_names(conjunctions, into);
            }

            QueryPart::MapKeyFilter(name, clause) => {
                if let Some(name) = name {
                    into.insert(name.as_str());
                }
                collect_let_value_capture_names(&clause.compare_with, into);
            }

            QueryPart::This
            | QueryPart::Key(_)
            | QueryPart::Index(_)
            | QueryPart::AllValues(_)
            | QueryPart::AllIndices(_) => {}
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

fn collect_let_value_capture_names<'value, 'loc: 'value>(
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
