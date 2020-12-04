use crate::rules::values::*;

///
/// Guard Language Syntax
///
/// ```
/// # Rule blocks
/// rule s3_secure {
///     AWS::S3::Bucket {
///         BucketName == /Encrypted/
///         BucketEncryption EXISTS
///     }
/// }
///
/// rule s3_secure_sse {
///     s3_secure
///     AWS::S3::Bucket {
///         let algo =
///             BucketEncryption.ServerSideEncryptionConfiguration.*.ServerSideEncryptionByDefault
///
///         %algo.Algorithm == "aws"
///     }
/// }
///
/// rule s3_secure_kms {
///     s3_secure
///     AWS::S3::Bucket {
///         let algo =
///             BucketEncryption.ServerSideEncryptionConfiguration.*.ServerSideEncryptionByDefault
///
///         %algo.Algorithm == "aws:kms",
///         %algo.KmsKeyArn IN [/kms-XXX/, 'kms-YYY/]
///     }
/// }
///
/// rule s3_is_secured {
///     s3_secure
///     s3_secure_kms or s3_secure_sse
/// }
///
/// # When guards
/// rule contains_production_tags {
///     let tags = resources.*.properties.Tags
///     %tags.key == /PROD/
///     %tags.value == /prod/
/// }
///
/// rule DDB_in_production when contains_production_tags {
///     # select all DDB tables
///     let ddb_tables = resources[type=/AWS::Dynamo/]
///     %ddb_tables.SSE_Specification.SSEEnabled == true or
///     %ddb_tables.KMSMasterKeyId EXISTS
/// }
/// ```
///
///

#[derive(PartialEq, Debug, Clone, Copy)]
pub(crate) struct FileLocation<'loc> {
    pub(crate) line: u32,
    pub(crate) column: u32,
    pub(crate) file_name: &'loc str,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum LetValue {
    Value(Value),
    AccessClause(AccessQuery),
}

///
/// This expression encapsulates assignment expressions inside a block expression
/// or at the file let. An assignment can either be a direct Value object or access
/// from incoming context. Access expressions support **predicate** queries to help
/// match specific selections [crate::rules::common::walk_type]
///
#[derive(PartialEq, Debug, Clone)]
pub(crate) struct LetExpr {
    pub(crate) var: String,
    pub(crate) value: LetValue,
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
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum QueryPart {
    Variable(String),
    Key(String),
    AllKeys,
    AllIndices(String),
    Index(String, i32),
    Filter(String, Conjunctions<FilterPart>),
}


#[derive(PartialEq, Debug, Clone)]
pub(crate) enum VariableOrValue {
    Variable(String),
    Value(Value),
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct FilterPart {
    pub(crate) name: String,
    pub(crate) comparator: (CmpOperator, bool),
    pub(crate) value: Option<VariableOrValue>,
}

pub(crate) type AccessQuery = Vec<QueryPart>;

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct AccessClause<'loc> {
    pub(crate) query: AccessQuery,
    pub(crate) comparator: (CmpOperator, bool),
    pub(crate) compare_with: Option<LetValue>,
    pub(crate) custom_message: Option<String>,
    pub(crate) location: FileLocation<'loc>,
}

pub(crate) type Disjunctions<T> = Vec<T>;
pub(crate) type Conjunctions<T> = Vec<Disjunctions<T>>;

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum GuardClause<'loc> {
    Clause(AccessClause<'loc>, bool),
    NamedRule(String, FileLocation<'loc>, bool, Option<String>),
}

pub(crate) type WhenConditions<'loc> = Conjunctions<GuardClause<'loc>>;

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Block<T> {
    pub(crate) assignment: Vec<LetExpr>,
    pub(crate) conjunctions: Conjunctions<T>,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct TypeBlock<'loc> {
    pub(crate) type_name: String,
    pub(crate) conditions: Option<WhenConditions<'loc>>,
    pub(crate) block: Block<GuardClause<'loc>>, // only contains access clauses
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum RuleClause<'loc> {
    Clauses(Conjunctions<GuardClause<'loc>>),
    WhenBlock(WhenConditions<'loc>, Block<RuleClause<'loc>>),
    TypeBlock(TypeBlock<'loc>)
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Rule<'loc> {
    pub(crate) rule_name: String,
    pub(crate) conditions: Option<WhenConditions<'loc>>,
    pub(crate) block: Block<RuleClause<'loc>>,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct RulesFile<'loc> {
    pub(crate) assignments: Vec<LetExpr>,
    pub(crate) guard_rules: Vec<Rule<'loc>>,
}




