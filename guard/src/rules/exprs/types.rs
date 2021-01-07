use crate::rules::values::*;

use std::hash::{Hash, Hasher};
use std::collections::HashMap;
use std::fmt::Formatter;
use super::scope::Scope;
use crate::errors::Error;
use std::collections::hash_map::DefaultHasher;

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
/// * Predicate query, which is used to select instances from an array of structure. If we need to
/// select all entries in the array use the `[*]` syntax. To select specific elements in the array
/// use the structural key matches. E.g. to select all resources from an CFN template that match the
/// DynamoDB Table we can use the following `resources.*[type=/AWS::Dynamo/]`
///
///
#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum QueryPart<'loc> {
    Key(String),
    AllKeys,
    AllIndices,
    Index(i32),
    Filter(Conjunctions<GuardClause<'loc>>),
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
            _ => return None
        };
        if name.starts_with('%') {
            name.strip_prefix('%')
        } else {
            None
        }
    }
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

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct Key<'loc> {
    // pub(crate) query_key: u64, // hash of query part
    pub(crate) query_key: &'loc[QueryPart<'loc>], // hash of query part
    pub(crate) context: &'loc Value
}

impl<'loc> Eq for Key<'loc> {}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct ResolutionKey<'loc> {
    pub(crate) clause: &'loc GuardClause<'loc>
}

impl Eq for ResolutionKey<'_> {}

pub(crate) type ResolvedValues<'loc> = indexmap::IndexMap<Path, &'loc Value>;
//pub(crate) type QueryCache<'loc> = HashMap<Key<'loc>, ResolvedValues<'loc>>;
pub(crate) type Resolutions = indexmap::IndexMap<u64, EvalStatus>;

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) enum EvalStatus {
    Comparison(EvalResult),
    Unary(Status),
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct EvalResult {
    pub(crate) status: Status,
    pub(crate) from: Option<(Path, Value)>,
    pub(crate) to: Option<(Path, Value)>,
}

impl EvalResult {

    pub(crate) fn status(status: Status) -> Self {
        EvalResult {
            status,
            from: None,
            to: None
        }
    }

    pub(crate) fn status_with_lhs(status: Status,
                                  from: (Path, &Value)) -> Self {
        EvalResult {
            status,
            from: Some((from.0, from.1.clone())),
            to: None,
        }
    }

    pub(crate) fn status_with_lhs_rhs(status: Status,
                                      from: (Path, &Value),
                                      to: (Path, &Value)) -> EvalResult {
        EvalResult {
            status,
            from: Some((from.0, from.1.clone())),
            to: Some((to.0, to.1.clone()))
        }
    }
}

pub(crate) trait Resolver {
    fn resolve_query<'r>(&self,
                         query: &[QueryPart<'_>],
                         value: &'r  Value,
                         variables: &Scope<'_>,
                         path: Path,
                         eval: &EvalContext<'_>) -> Result<ResolvedValues<'r>, Error>;
}

pub(crate) trait Evaluate {
    type Item;

    fn evaluate(&self,
                resolver: &dyn Resolver,
                scope: &Scope<'_>,
                context: &Value,
                path: Path,
                eval_context: &EvalContext<'_>) -> Result<Self::Item, Error>;
}

#[derive(PartialEq, Debug, Clone, Hash)]
pub(crate) struct StdHasher {}

impl StdHasher {
    pub(crate) fn new() -> Self {
        StdHasher {}
    }

    pub(crate) fn hash<T: Hash>(&self, to_hash: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        to_hash.hash(&mut hasher);
        hasher.finish()
    }
}




#[derive(PartialEq, Debug, Clone)]
pub(crate) struct EvalContext<'c> {
    //pub(crate) query_cache: QueryCache<'c>,
    pub(crate) root: Value,
    pub(crate) resolutions: std::cell::RefCell<Resolutions>,
    pub(crate) rule_resolutions: std::cell::RefCell<HashMap<String, Status>>,
    pub(crate) rules: &'c RulesFile<'c>,
    pub(crate) rule_cache: HashMap<String, &'c Rule<'c>>,
    pub(crate) hasher: StdHasher,
}

impl<'c> EvalContext<'c> {
    pub(crate) fn new(root: Value, rules: &'c RulesFile<'c>) -> Self {
        let mut rule_cache = HashMap::with_capacity(rules.guard_rules.len());
        for rule in &rules.guard_rules {
            rule_cache.insert(rule.rule_name.to_string(), rule);
        }

        EvalContext {
            //query_cache: QueryCache::new(),
            root,
            rule_cache,
            rules,
            resolutions: std::cell::RefCell::new(Resolutions::new()),
            rule_resolutions: std::cell::RefCell::new(HashMap::new()),
            hasher: StdHasher::new(),
        }
    }
}

impl Path {

    pub fn new(pointers: &[&str]) -> Path {
        Path {
            pointers: pointers.iter().map(|s| String::from(*s)).collect()
        }
    }

    pub(crate) fn append_str(self, path: &str) -> Self {
        self.append(path.to_owned())
    }

    pub(crate) fn append(mut self, path: String) -> Self {
        self.pointers.push(path);
        Path {
            pointers: self.pointers
        }
    }

    pub(crate) fn prepend_str(mut self, path: &str) -> Self {
        self.prepend(path.to_string())
    }

    pub(crate) fn prepend(mut self, path: String) -> Self {
        self.pointers.insert(0, path);
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

