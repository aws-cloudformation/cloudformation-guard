use crate::rules::values::*;

use std::hash::Hash;
use std::fmt::Formatter;
use serde::{Serialize, Deserialize};
use crate::rules::path_value::PathAwareValue;

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct FileLocation<'loc> {
    pub(crate) line: u32,
    pub(crate) column: u32,
    #[serde(skip_serializing, skip_deserializing)]
    pub(crate) file_name: &'loc str,
}

impl<'loc> std::fmt::Display for FileLocation<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("Location[file:{}, line:{}, column:{}]", self.file_name, self.line, self.column))?;
        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) enum LetValue<'loc> {
    Value(PathAwareValue),
    AccessClause(AccessQuery<'loc>),
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
    MapKeyFilter(MapKeyFilterClause<'loc>),
    AllValues,
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

impl<'loc> std::fmt::Display for QueryPart<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryPart::Key(s) => {
                f.write_str(s.as_str())?;
            },

            QueryPart::AllIndices => {
                f.write_str("[*]")?;
            }

            QueryPart::AllValues => {
                f.write_str("*")?;
            },

            QueryPart::Index(idx) => {
                write!(f, "{}", idx.to_string())?;
            },

            QueryPart::Filter(_c) => {
                f.write_str("(filter-clauses)")?;
            },

            QueryPart::MapKeyFilter(_clause) => {
                f.write_str("(map-key-filter-clause)")?;
            },

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
                column: 0
            },
            compare_with: None,
            comparator: (CmpOperator::Eq, false)
        }
    }
}

pub(crate) type Disjunctions<T> = Vec<T>;
pub(crate) type Conjunctions<T> = Vec<Disjunctions<T>>;

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct GuardAccessClause<'loc> {
    pub(crate) access_clause: AccessClause<'loc>,
    pub(crate) negation: bool
}


#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct MapKeyFilterClause<'loc> {
    pub(crate) comparator: (CmpOperator, bool),
    pub(crate) compare_with: LetValue<'loc>,
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
pub(crate) struct GuardNamedRuleClause<'loc> {
    pub(crate) dependent_rule: String,
    pub(crate) negation: bool,
    pub(crate) custom_message: Option<String>,
    pub(crate) location: FileLocation<'loc>
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
    TypeBlock(TypeBlock<'loc>)
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
pub(crate) struct RulesFile<'loc> {
    pub(crate) assignments: Vec<LetExpr<'loc>>,
    pub(crate) guard_rules: Vec<Rule<'loc>>,
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
            _ => unimplemented!()
        }
        Ok(())
    }
}

impl<'loc> std::fmt::Display for BlockGuardClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {{ ", self.query)?;
        for each in &self.block.conjunctions {
            let len = each.len();
            for idx in 0..len-2 {
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
        write!(f, "{} {}",
            if self.negation { "not" } else { "" },
            self.access_clause
        )?;
        Ok(())
    }
}

impl<'loc> std::fmt::Display for AccessClause<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}",
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

impl<'loc> std::fmt::Display for LetValue<'loc> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            LetValue::AccessClause(acc) => acc.fmt(f)?,
            LetValue::Value(v) => write!(f, "{:?}", v)?
        }
        Ok(())
    }
}

pub(crate) fn display_comparator(cmp: (CmpOperator, bool)) -> String {
    let (op, not) = cmp;
    format!("{}{} ", if not { "not "} else { "" }, op)
}