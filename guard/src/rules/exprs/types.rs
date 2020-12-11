use crate::rules::values::*;
use crate::errors::Error;

use std::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::fmt::Formatter;

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
pub(crate) enum GuardClause<'loc> {
    Clause(AccessClause<'loc>, bool),
    NamedRule(String, FileLocation<'loc>, bool, Option<String>),
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

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct QueryResult<'loc> {
    results: HashMap<Path, Vec<&'loc Value>>,
    query: &'loc[QueryPart<'loc>],
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct Scope {
}

pub(crate) trait Evaluate {
    type Item;
    fn evaluate(&self, context: &Value, path: &Path, scope: &Scope) -> Result<Self::Item, Error>;
}

impl Path {

    pub fn new(pointers: &[&str]) -> Path {
        Path {
            pointers: pointers.iter().map(|s| String::from(*s)).collect()
        }
    }

    pub(super) fn append_str(mut self, path: &str) -> Self {
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
        f.write_str(&str);
        Ok(())
    }
}

impl<'loc> QueryResult<'loc> {

    pub(crate) fn new(query: &'loc [QueryPart<'loc>], results: HashMap<Path, Vec<&'loc Value>>) -> Self {
        QueryResult {
            query,
            results,
        }
    }

    pub(crate) fn result(self) -> HashMap<Path, Vec<&'loc Value>> {
        self.results
    }
}

impl<'loc> Hash for QueryResult<'loc> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.query.hash(state);
    }
}

impl<'loc> Eq for QueryResult<'loc> {}


