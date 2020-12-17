use crate::rules::values::*;

use std::hash::{Hash};
use std::collections::HashMap;
use std::fmt::Formatter;
//use super::scope::Scope;

#[derive(PartialEq, Debug, Clone, Copy, Hash)]
pub(crate) struct FileLocation<'loc> {
    pub(crate) line: u32,
    pub(crate) column: u32,
    pub(crate) file_name: &'loc str,
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum LetValue<'loc> {
    Value(Value),
    AccessClause(AccessQuery<'loc>),
}

///
/// This expression encapsulates assignment expressions inside a block expression
/// or at the file let. An assignment can either be a direct Value object or access
/// from incoming context. Access expressions support **predicate** queries to help
/// match specific selections [crate::rules::common::walk_type]
///
#[derive(PartialEq, Debug, Clone)]
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
/// * Variable = %<String>, this maps to an assigned variable [LetExpr] that must resolve to a "string'
/// when accessing a key in  struct or an index when accessing an array
/// * Predicate query, which is used to select instances from an array of structure. If we need to
/// select all entries in the array use the `[*]` syntax. To select specific elements in the array
/// use the structural key matches. E.g. to select all resources from an CFN template that match the
/// DynamoDB Table we can use the following `resources.*[type=/AWS::Dynamo/]`
///
///
#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum QueryPart<'loc> {
    Variable(String),
    Key(String),
    AllKeys,
    AllIndices(String),
    Index(String, i32),
    Filter(String, Conjunctions<GuardClause<'loc>>),
}


#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum VariableOrValue {
    Variable(String),
    Value(Value),
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct FilterPart {
    pub(crate) name: String,
    pub(crate) comparator: (CmpOperator, bool),
    pub(crate) value: Option<VariableOrValue>,
}

pub(crate) type AccessQuery<'loc> = Vec<QueryPart<'loc>>;

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct AccessClause<'loc> {
    pub(crate) query: AccessQuery<'loc>,
    pub(crate) comparator: (CmpOperator, bool),
    pub(crate) compare_with: Option<LetValue<'loc>>,
    pub(crate) custom_message: Option<String>,
    pub(crate) location: FileLocation<'loc>,
}

pub(crate) type Disjunctions<T> = Vec<T>;
pub(crate) type Conjunctions<T> = Vec<Disjunctions<T>>;

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct GuardAccessClause<'loc> {
    pub(crate) access_clause: AccessClause<'loc>,
    pub(crate) negation: bool
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct GuardNamedRuleClause<'loc> {
    pub(crate) dependent_rule: String,
    pub(crate) negation: bool,
    pub(crate) comment: Option<String>,
    pub(crate) location: FileLocation<'loc>
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum GuardClause<'loc> {
    Clause(GuardAccessClause<'loc>),
    NamedRule(GuardNamedRuleClause<'loc>)
}

pub(crate) type WhenConditions<'loc> = Conjunctions<GuardClause<'loc>>;

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Block<'loc, T> {
    pub(crate) assignments: Vec<LetExpr<'loc>>,
    pub(crate) conjunctions: Conjunctions<T>,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct TypeBlock<'loc> {
    pub(crate) type_name: String,
    pub(crate) conditions: Option<WhenConditions<'loc>>,
    pub(crate) block: Block<'loc, GuardClause<'loc>>, // only contains access clauses
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum RuleClause<'loc> {
    Clause(GuardClause<'loc>),
    WhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
    TypeBlock(TypeBlock<'loc>)
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Rule<'loc> {
    pub(crate) rule_name: String,
    pub(crate) conditions: Option<WhenConditions<'loc>>,
    pub(crate) block: Block<'loc, RuleClause<'loc>>,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct RulesFile<'loc> {
    pub(crate) assignments: Vec<LetExpr<'loc>>,
    pub(crate) guard_rules: Vec<Rule<'loc>>,
}

#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Hash, Debug)]
pub(crate) struct Path {
    pointers: Vec<String>
}

#[derive(Clone, PartialEq, Debug, Copy, Hash)]
pub(crate) enum Status {
    SKIP,
    PASS,
    FAIL
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ComparisonResult<'loc> {
    status: Status,
    from: Option<(&'loc Path, &'loc Value)>,
    with: Option<(&'loc Path, &'loc Value)>,
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(super) struct Key<'loc> {
    // pub(super) query_key: u64, // hash of query part
    pub(super) query_key: &'loc[QueryPart<'loc>], // hash of query part
    pub(super) context: &'loc Value
}

impl<'loc> Eq for Key<'loc> {}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(super) struct ResolutionKey<'loc> {
    pub(super) clause: &'loc GuardClause<'loc>
}

impl Eq for ResolutionKey<'_> {}

pub(super) type ResolvedValues<'loc> = indexmap::IndexMap<Path, &'loc Value>;
pub(super) type QueryCache<'loc> = HashMap<Key<'loc>, ResolvedValues<'loc>>;
pub(super) type Resolutions<'loc> = indexmap::IndexMap<ResolutionKey<'loc>, EvalStatus<'loc>>;

#[derive(PartialEq, Debug, Clone, Hash)]
pub(super) enum EvalStatus<'c> {
    Comparison(EvalResult<'c>),
    Unary(Status),
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(super) struct EvalResult<'c> {
    pub(super) status: Status,
    pub(super) from: (Path, &'c Value),
    pub(super) to: (Path, &'c Value)
}

pub(super) struct EvalContext<'c> {
    pub(super) query_cache: QueryCache<'c>,
    pub(super) root: &'c Value,
    pub(super) resolutions: Resolutions<'c>,
    pub(super) rule_resolutions: HashMap<String, Status>,
}

impl<'c> EvalContext<'c> {
    pub(super) fn new(root:&'c Value) -> Self {
        EvalContext {
            query_cache: QueryCache::new(),
            root,
            resolutions: Resolutions::new(),
            rule_resolutions: HashMap::new(),
        }
    }
}

impl<'loc> ComparisonResult<'loc> {
    pub(crate) fn new(status: Status,
                      from: Option<(&'loc Path, &'loc Value)>,
                      with: Option<(&'loc Path, &'loc Value)>) -> Self {
        ComparisonResult {
            status, from, with
        }
    }

    pub(crate) fn status(&self) -> Status {
        self.status
    }

    pub(crate) fn from(&self) -> Option<(&'loc Path, &'loc Value)> {
        self.from
    }

    pub(crate) fn with(&self) -> Option<(&'loc Path, &'loc Value)> {
        self.with
    }
}

impl Path {

    pub fn new(pointers: &[&str]) -> Path {
        Path {
            pointers: pointers.iter().map(|s| String::from(*s)).collect()
        }
    }

    pub(super) fn append_str(self, path: &str) -> Self {
        self.append(path.to_owned())
    }

    pub(super) fn append(mut self, path: String) -> Self {
        self.pointers.push(path);
        Path {
            pointers: self.pointers
        }
    }

}

impl std::fmt::Display for Path {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let str = self.pointers.join("/");
        f.write_str(&str)?;
        Ok(())
    }
}

