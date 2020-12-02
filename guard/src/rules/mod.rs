///
/// This represents the rules language syntax for parsing and how it maps into Rule
/// clauses that will be evaluated. By default all clauses have an implicit AND conjunction
/// between all clauses specified. All clauses that are not included as a part of a named
/// rule block will automatically belong to the default rule block. The naming conventions
/// to reference these are standardized as follows in the grammar show
///
/// rule_clause         ::= type_part property_part value_clause '\n'
/// rule_block_clause   ::= type_part '{' '\n' (property_part value_clause '\n')+ '}' '\n'
/// value_clause        ::= in_clause | not_clause | eq_clause
/// in_clause           ::= IN (var|list_value)
/// eq_clause           ::= EQ (var|value)
///
/// var                 ::= IDENT
/// IDENT               ::= [a-zA-Z0-9_]+
/// let_clause          ::= let IDENT = value
///
/// **Scalar Values**
///
/// scalar_value        ::= string | int | float | bool
/// string              ::= '"'[^"]+'"'
/// int                 ::= [0-9]+
/// float               ::= int.int
/// bool                ::= true | false
///
/// **General Value**
///
/// value               ::= scalar_value | list_value | map_value
/// list_value          ::= '[' value ']'
/// map_value           ::= '{' (string: value)+, '}'
///
///
/// Grammar in ABNF form
///
///
/// rules               ::=     expr+
/// expr                ::=     rule       |
///                             var_assignment
///
/// alphanumeric        ::=     [a-ZA-Z0-9_]
///
/// value               ::=     scalar |
///                             list   |
///                             map
///
/// ws                  ::=     [' \n\r\t']
/// sp                  ::=     [' \t']
///
/// **Scalar Values**
/// scalar              ::=     string      |
///                             integer     |
///                             bool        |
///                             float       |
///                             char        |
///                             range
///
/// string              ::=     '"' [^"]* '"'
/// integer             ::=     [0-9]+
/// bool                ::=     'true' | 'True' | 'false' | 'False'
/// float               ::=     integer '.' integer ([eE]['+'|'-']integer))?
///
/// range               ::=     r ['[('] allowed_range_types sp* ',' sp* allowed_range_types [')]'
/// allowed_range_type  ::=     integer | float | char
///
/// **List Value**
///
/// list                ::=     '[' ws* value* ws* ']'
///
/// **Map Values**
///
/// map                 ::=     '{' ws* (keyword ws* ':' ws* value)* ws* '}'
/// keyword             ::=     alphanumeric+  # might be restrictive
///
/// **Expressions**
///
/// var_assignment      ::=     var_name  ":="  value
/// var_name            ::=     alphanumeric+
/// var_access          ::=     '%' var_access
///
/// rule                ::=     named_rule |
///                             clause
///
/// named_rules         ::=     'rule' var_name sp* '{' ws* type_clause+ ws* '}'
/// type_clause         ::=     type_block | clause
///
/// clause_check        ::=     property_access sp+ op sp+ (value|var_access) ('<<' string '>>')?
/// clause              ::=     type_name sp+ clause_check
/// property_access     ::=     (var_access.)? ([property_name|'*'])(.[property_name|'*'])*
/// op                  ::=     eq | not_eq | in | not_in
/// eq                  ::=     '=='
/// not_eq              ::=     '!='
/// in                  ::=     'in' | 'IN'
/// not_in              ::=     'not' in
///
/// type_block          ::=     type_name sp* '{' ws*
///                                 (var_assigned)* (var_property_assignment)*
///                                 clause_check+ ws* '}'
///
///
///
///
///
///
///
///
/// AWS::S3::Bucket {
///    .public NOT true
///    .policy NOT null
/// }
///
/// rule secure_bucket {
///     AWS::S3::Bucket {
///         .public NOT true
///         .policy NOT null
///     }
/// }
///
/// let list = [1, 2, 3,]
/// let maps = [{s: 1}, {b: 2},]
/// let multiline = [
///   {
///      a:
///          2,
///      b:
///          3,
///    }]
/// let mapvalue =
///    {
///       a: 1, }
///
/// import (
///     "file-path" as X
/// )
///
/// AWS::S3::Bucket {
///    .public == true
///    .policy != NULL
///    .policy.statement[*].action != "DENY"
/// }
///
/// rule secure_s3 {
///     AWS::S3::Bucket {
///        .policy != null
///        .public != true
///     }
///     AWS::S3::BucketPolicy {
///     }
///     AWS::S3::Bucket .policy IN { Id: '...', Statement: [{ Principal: ["ec2.amazonaws.com"] }] }
///     AWS::S3::Bucket {
///         .policy.Id = '...'
///         .policy.Statement[*].Principal IN ["ec2.amazonaws.com"]
///     }
/// }
///
/// secure_s3 and ....
///
/// rule XXYYY {
///     secure_s3
///     ...
///     ...
/// }
///
/// secure_s3
/// XXYYY
///
/// secure_s3 OR XXYYY
///
///
///
///
///
mod common;
mod scope;

pub(crate) mod dependency;
pub(crate) mod values;
pub(crate) mod parser;
pub(crate) mod expr;
mod parser2;
pub(in crate::rules) mod exprs;

#[derive(Clone, Debug, PartialEq)]
pub enum EvalStatus {
    PASS,
    FAIL,
    FAIL_WITH_MESSAGE(String),
    SKIP
}

