use std::collections::HashMap;
use std::convert::TryFrom;

//
// extern crates
//
use crate::errors::{Error, ErrorKind};
use crate::rules::common::walk_value;
use crate::rules::dependency::rules_execution_order_itr;
use crate::rules::EvalStatus;
use crate::rules::scope::BlockScope;
//
// crate level
//
use crate::rules::values::*;

///
/// Named Rule model
/// CONTEXT = { Resources.*.Type: Resources.*.Properties } # TODO
/// rule s3_secure {
///     AWS::S3::Bucket {
///         statements := .policy.statement
///
///         public != true
///         policy != null
///         %statements.*.action == "DENY" or %statements.*.action == "TRACE"
///     }
/// }
///
/// rule augmented_s3_secure {
///     s3_secure
/// }
///
/// public != true && policy != null && (po
///
///
#[derive(PartialEq, Debug, Clone)]
pub(crate) enum LetValue {
    Value(Value),
    PropertyAccess(PropertyAccess),
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

#[derive(PartialEq, Eq, Debug, Clone, Hash)]
pub(crate) struct PropertyAccess {
    pub(crate) var_access: Option<String>,
    pub(crate) property_dotted_notation: Vec<String>,
}

#[derive(PartialEq, Debug, Clone, Copy)]
pub(crate) struct Location<'loc> {
    pub(crate) line: u32,
    pub(crate) column: u32,
    pub(crate) file_name: &'loc str,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct Clause<'loc> {
    pub(crate) access: PropertyAccess,
    pub(crate) comparator: ValueOperator,
    pub(crate) compare_with: Option<LetValue>,
    pub(crate) custom_message: Option<String>,
    pub(crate) location: Location<'loc>,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum PropertyClause<'loc> {
    Clause(Clause<'loc>),
    // single clause
    Disjunction(Vec<Clause<'loc>>),
    // list of ORs
    Variable(LetExpr),
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct TypeClauseExpr<'loc> {
    pub(crate) type_name: String,
    pub(crate) type_clauses: Vec<PropertyClause<'loc>>, // conjunction of clauses
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum NamedRuleClauseExpr<'loc> {
    // s3_secure
    NamedRule(String),
    // not s3_secure
    NotNamedRule(String),
    // Type clause
    TypeClause(TypeClauseExpr<'loc>),
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum NamedRuleExpr<'loc> {
    // Single rule clause
    RuleClause(NamedRuleClauseExpr<'loc>),
    // ORs of clauses
    DisjunctionRuleClause(Vec<NamedRuleClauseExpr<'loc>>),
    // or a rules
    // assigned variable
    Variable(LetExpr),
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) struct NamedRuleBlockExpr<'loc> {
    pub(crate) rule_name: String,
    pub(crate) rule_clauses: Vec<NamedRuleExpr<'loc>>,
    // conjunction of clauses
    pub(crate) location: Location<'loc>,
}

#[derive(PartialEq, Debug, Clone)]
pub(crate) enum Expr<'loc> {
    Assignment(LetExpr),
    NamedRule(NamedRuleBlockExpr<'loc>), // everything goes into a default rule block
}

pub(crate) type Rules<'loc> = Vec<Expr<'loc>>;

#[derive(PartialEq, Clone, Debug)]
pub(crate) struct Resolutions {
    resolved_values: HashMap<String, Vec<Value>>,
    resolved_status: HashMap<String, EvalStatus>
}

pub(crate) trait Evaluate {
    fn evaluate(&self, context: &serde_json::Value) -> Result<Resolutions, Error>;
}

fn dependent_var(value: &LetValue) -> Option<&str> {
    match value {
        LetValue::PropertyAccess(access) =>
            if let Some(name) = &access.var_access {
                Some(name.as_str())
            } else {
                None
            },

        _ => None
    }
}

fn literal(value: &LetValue) -> Option<&Value> {
    if let LetValue::Value(literal) = value {
        return Some(literal);
    }
    None
}

//
// LetExpr evaluation methods to project from literal values or from incoming dynamic
// context.
//
impl LetExpr {
    pub(crate) fn dependent_var(&self) -> Option<&str> {
        dependent_var(&self.value)
    }

    pub(crate) fn literal(&self) -> Option<&Value> {
        literal(&self.value)
    }

    pub(crate) fn dynamic(&self) -> Option<&PropertyAccess> {
        if let LetValue::PropertyAccess(access) = &self.value {
            Some(access)
        } else {
            None
        }
    }
}

//
// This expression encodes if we access a property from an assigned variable or
// directly from the incoming dynamic context.
//
impl PropertyAccess {
    pub(crate) fn has_dependent_variable(&self) -> bool {
        self.var_access != None
    }

    pub(crate) fn variable(&self) -> Option<&str> {
        if let Some(name) = &self.var_access {
            return Some(name.as_str());
        }
        None
    }

    pub(crate) fn property_access(&self) -> &[String] {
        &self.property_dotted_notation
    }

    pub(crate) fn project_dynamic(&self,
                                  context: &serde_json::Value,
                                  hierarchy: String) -> Result<Vec<Value>, Error> {
        let walk = walk_value(context, &self.property_dotted_notation, hierarchy.clone())?;
        let mut result = Vec::with_capacity(walk.len());
        for each in walk {
            let value = Value::try_from(each)?;
            result.push(value);
        }
        Ok(result)
    }

    pub(crate) fn dotted_access(&self) -> String {
        (&self.property_dotted_notation).join(".")
    }
}

impl<'loc> Clause<'loc> {
    pub(crate) fn evaluate(&self,
                           context: &serde_json::Value,
                           scope: &BlockScope,
                           resolutions: &mut Resolutions,
                           hierarchy: String) -> Result<EvalStatus, Error> {
        let is_inverse = if let ValueOperator::Not(_) = &self.comparator {
            true
        } else {
            false
        };

        let inverse_status_for_not = |eval| {
            if is_inverse {
                if eval == EvalStatus::PASS {
                    EvalStatus::FAIL
                } else {
                    EvalStatus::PASS
                }
            } else {
                eval
            }
        };

        let rhs = if let Some(value) = &self.compare_with {
            match value {
                LetValue::Value(v) => vec![v.clone()],

                LetValue::PropertyAccess(access) =>
                    Self::property_access(
                        access, scope, context, &self.location, resolutions,hierarchy.clone())?,
            }
        } else {
            vec![]
        };

        let rhs = Self::flatten_list(rhs);

        //
        // Special case NULL checks
        //
        if rhs.len() == 1 {
            if let Some(v) = rhs.get(0) {
                if Value::Null == *v {
                    //
                    // if we can retrieve the values successfully then the check passes if
                    // it is != null and fails for == null. The consequence of this is when
                    // accessing a value if an intermediate level entity does not exist then
                    // == null is considered a success.
                    //
                    // This is reason why the status is inverted below, it returns FAIL if we
                    // did succeed retrieving the value. the inverse of that is !=
                    //
                    let status = if let Ok(_values) = Self::property_access(
                        &self.access, scope, context, &self.location, resolutions, hierarchy.clone()) {
                        EvalStatus::FAIL
                    } else {
                        EvalStatus::PASS
                    };
                    return Ok(inverse_status_for_not(status));

                }
            }
        }

        let lhs = Self::property_access(
            &self.access, scope, context, &self.location, resolutions, hierarchy.clone())?;

        let lhs = Self::flatten_list(lhs);

        match &self.comparator {
            ValueOperator::Cmp(cmp) | ValueOperator::Not(cmp) => {
                match cmp {
                    CmpOperator::Eq => {
                        let eval = if lhs == rhs {
                            EvalStatus::PASS
                        } else {
                            //
                            // if the lists aren't equal then there must be only one size comparison
                            // between LHS/RHS
                            //
                            if rhs.len() == 1 {
                                'outer: loop {
                                    for each in &lhs {
                                        if !compare_eq(each, &rhs[0])? {
                                            break 'outer EvalStatus::FAIL
                                        }
                                    }
                                    break EvalStatus::PASS
                                }
                            }
                            else {
                                return Err(Error::new(ErrorKind::IncompatibleError(
                                    format!("Checking for quality between lists that can not be compared LHS = {:?}, RHS = {:?}", lhs, rhs)
                                )))
                            }
                        };
                        Ok(inverse_status_for_not(eval))
                    },
                    CmpOperator::Lt => Self::compute(lhs, rhs, compare_lt, is_inverse),
                    CmpOperator::Le => Self::compute(lhs, rhs, compare_le, is_inverse),
                    CmpOperator::Gt => Self::compute(lhs, rhs, compare_gt, is_inverse),
                    CmpOperator::Ge => Self::compute(lhs, rhs, compare_ge, is_inverse),
                    CmpOperator::In => {
                        let eval = 'outer_in: loop {
                            'next: for each_lhs in &lhs {
                                for each_rhs in &rhs {
                                    if compare_eq(each_lhs, each_rhs)? {
                                        continue 'next;
                                    }
                                }
                                break 'outer_in EvalStatus::FAIL;
                            }
                            break EvalStatus::PASS;
                        };
                        Ok(inverse_status_for_not(eval))
                    },

                    CmpOperator::Exists => {
                        let status = if lhs.is_empty() { EvalStatus::FAIL } else { EvalStatus::PASS };
                        Ok(inverse_status_for_not(status))
                    },

                    CmpOperator::Empty => {
                        let status = if lhs.is_empty() { EvalStatus::PASS } else { EvalStatus::FAIL };
                        Ok(inverse_status_for_not(status))
                    }

                    _ => unimplemented!()
                }
            }
        }
    }

    fn compute<F>(lhs: Vec<Value>,
                  rhs: Vec<Value>,
                  cmp: F,
                  is_inverse: bool) -> Result<EvalStatus, Error>
        where F: Fn(&Value, &Value) -> Result<bool, Error> {
        for each_lhs in &lhs {
            for each_rhs in &rhs {
                let eval = cmp(each_lhs, each_rhs)?;
                let eval = if is_inverse { !eval } else { eval };
                if !eval {
                    return Ok(EvalStatus::FAIL);
                }
            }
        }
        Ok(EvalStatus::PASS)
    }

    fn property_access(access: &PropertyAccess,
                       scope: &BlockScope,
                       context: &serde_json::Value,
                       location: &Location,
                       resolutions: &mut Resolutions,
                       hierarchy: String) -> Result<Vec<Value>, Error> {
        if let Some(variable) = access.variable() {
            return scope.expand_variable_values(variable, access, resolutions);
        }
        let scope_path = format!("{}/{}", scope.scope(), access.dotted_access());
        let result = if let Some(values) = resolutions.get_resolved_values(&scope_path) {
            values.clone()
        } else {
            let r = access.project_dynamic(context, hierarchy.clone())?;
            resolutions.set_resolved_values(&scope_path, r.clone());
            r
        };
        Ok(result)
    }

    fn flatten_list(vec: Vec<Value>) -> Vec<Value> {
        if vec.len() == 1 {
            if let Value::List(inner) = &vec[0] {
                return inner.clone()
            }
        }
        return vec
    }
}

impl<'loc> TypeClauseExpr<'loc> {
    pub(crate) fn evaluate(&self,
                           context: &serde_json::Value,
                           scope: &BlockScope,
                           evaluate: &mut Resolutions,
                           hierarchy: String) -> Result<EvalStatus, Error> {

        //
        // If the type name was present in the context, then use it. This is to keep the
        // incoming expectation for the previous version that expected a "type-name": {...}
        // structure to evaluate against
        //

        let context = if let Some(cxt) = context.get(&self.type_name) {
            cxt
        } else { context };

        let scope = BlockScope::type_block(&self, context, scope)?;
        let hierarchy = format!("{}/{}", hierarchy, self.type_name);

        'outer: for each in &self.type_clauses {
            match each {
                PropertyClause::Clause(single) => {
                    let status = single.evaluate(context, &scope, evaluate, hierarchy.clone())?;
                    let scope = format!("{}/Clause@{}#{}", scope.scope(), single.location.file_name, single.location.line);
                    evaluate.set_resolved_status(&scope, status.clone());
                    if EvalStatus::FAIL == status {
                        if let Some(msg) = &single.custom_message {
                            evaluate.set_resolved_status(&scope, EvalStatus::FAIL_WITH_MESSAGE(msg.to_string()))
                        }
                        return Ok(EvalStatus::FAIL);
                    }
                }

                PropertyClause::Disjunction(any) => {
                    for each in any {
                        let status = each.evaluate(context, &scope, evaluate, hierarchy.clone())?;
                        let scope = format!("{}/Claue@{}#{}", scope.scope(), each.location.file_name, each.location.line);
                        evaluate.set_resolved_status(&scope, status.clone());
                        if EvalStatus::FAIL == status {
                            if let Some(msg) = &each.custom_message {
                                evaluate.set_resolved_status(&scope, EvalStatus::FAIL_WITH_MESSAGE(msg.to_string()))
                            }
                        }
                        if EvalStatus::PASS == status {
                            continue 'outer;
                        }
                    }
                    return Ok(EvalStatus::FAIL);
                }

                _ => {
                    continue 'outer;
                }
            }
        }

        Ok(EvalStatus::PASS)
    }
}

impl<'loc> NamedRuleBlockExpr<'loc> {
    pub(crate) fn evaluate(&self,
                           context: &serde_json::Value,
                           scope: &BlockScope,
                           evaluated: &mut Resolutions,
                           hierarchy: String) -> Result<EvalStatus, Error> {

        let scope = BlockScope::rule(&self, context, scope)?;
        let hierarchy = format!("{}/{}", hierarchy, self.rule_name);

        'outer: for each in &self.rule_clauses {
            match each {
                NamedRuleExpr::RuleClause(single) => {
                    let status = Self::evaluate_named_expr(
                            context, single, evaluated, &scope, hierarchy.clone())?;
                    evaluated.set_resolved_status(scope.scope(), status.clone());
                    if EvalStatus::PASS == status {
                        continue 'outer;
                    } else {
                        return Ok(EvalStatus::FAIL);
                    }
                }

                NamedRuleExpr::DisjunctionRuleClause(any) => {
                    for each_rule in any {
                        let status = Self::evaluate_named_expr(
                            context, each_rule, evaluated, &scope, hierarchy.clone())?;
                        evaluated.set_resolved_status(scope.scope(), status.clone());
                        if EvalStatus::PASS == status {
                            continue 'outer;
                        }
                    }
                }

                _ => {}
            }
        }

        Ok(EvalStatus::PASS)
    }

    fn evaluate_named_expr(context: &serde_json::Value,
                           named: &NamedRuleClauseExpr,
                           evaluated: &mut Resolutions,
                           scope: &BlockScope,
                           hierarchy: String) -> Result<EvalStatus, Error> {
        match named {
            NamedRuleClauseExpr::NamedRule(r) | NamedRuleClauseExpr::NotNamedRule(r) => {
                if let Some(result) = evaluated.get_resolved_status(r.as_str()) {
                    if let NamedRuleClauseExpr::NotNamedRule(_) = named {
                        match result {
                            EvalStatus::FAIL => Ok(EvalStatus::PASS),
                            EvalStatus::FAIL_WITH_MESSAGE(_ign) => Ok(EvalStatus::PASS),
                            EvalStatus::PASS => Ok(EvalStatus::FAIL),
                            EvalStatus::SKIP => Ok(EvalStatus::SKIP)
                        }
                    } else {
                        Ok(result.clone())
                    }
                } else {
                    return Err(Error::new(ErrorKind::MissingVariable(
                        format!("Named rule {} for evaluation was not present ", r))));
                }
            }

            NamedRuleClauseExpr::TypeClause(single) =>
                single.evaluate(context, scope, evaluated, hierarchy.clone())
        }
    }
}

impl<'loc> Evaluate for Rules<'loc> {
    fn evaluate(&self, context: &serde_json::Value) -> Result<Resolutions, Error> {
        let mut resolution = Resolutions::new();
        let root = BlockScope::root(&self, context)?;
        let mut non_default = Vec::with_capacity(self.len());
        let mut defaults = Vec::with_capacity(self.len());
        for each in self {
            if let Expr::NamedRule(rule) = each {
                if rule.rule_name == "default" {
                    defaults.push(each);
                } else {
                    non_default.push(each);
                }
            }
        }
        //let order_of_evaluation = rules_execution_order(&self)?;
        let order_of_evaluation = rules_execution_order_itr(non_default)?;
        for (name, rule) in order_of_evaluation {
            let status = rule.evaluate(context, &root, &mut resolution, "".to_owned())?;
            resolution.set_resolved_status(name, status);
        }

        if !defaults.is_empty() {
            let default_status = 'outer: loop {
                for expr in defaults {
                    if let Expr::NamedRule(rule) = expr {
                        if EvalStatus::FAIL == rule.evaluate(context, &root, &mut resolution, "".to_owned())? {
                            break 'outer EvalStatus::FAIL;
                        }
                    }
                }
                break EvalStatus::PASS;
            };
            resolution.set_resolved_status("/default", default_status);
        }
        Ok(resolution)
    }
}

impl Resolutions {

    fn new() -> Resolutions {
        Resolutions {
            resolved_status: HashMap::new(),
            resolved_values: HashMap::new()
        }
    }

    pub(super) fn get_resolved_values(&self, scope: &str) -> Option<&Vec<Value>> {
        self.resolved_values.get(scope)
    }

    pub(super) fn set_resolved_values(&mut self, scope: &str, values: Vec<Value>) -> Option<Vec<Value>> {
        self.resolved_values.insert(scope.to_owned(), values)
    }

    fn set_resolved_status(&mut self, scope: &str, status: EvalStatus) {
        self.resolved_status.insert(scope.to_owned(), status);
    }

    pub(crate) fn get_resolved_status(&self, scope: &str) -> Option<&EvalStatus> {
        self.resolved_status.get(scope)
    }

    pub(crate) fn get_resolved_statuses(&self) -> &HashMap<String, EvalStatus> {
        &self.resolved_status
    }
}


#[cfg(test)]
mod tests {
    use crate::rules::parser::*;

    use super::*;

//
    // Testing default rule
    //

    const DEFAULT_RULE_CLAUSES: &str = r###"
        # assign from incoming context to variable, this is  one of needed
        # support that Config needed
        let latest := latest

        AWS::EC2::Instance securityGroups == ["InstanceSecurityGroup"]
        AWS::EC2::Instance keyName == "KeyName" or keyName == "Key2"

        AWS::EC2::Instance availabilityZone in ["us-east-2a", "us-east-2b"]
        AWS::EC2::Instance imageId == %latest

        AWS::EC2::Instance instanceType == "t3.medium"
    "###;

    const EASY_CLAUSE: &str = r###"
        AWS::EC2::Instance keyName == "KeyName" or keyName == "Key2"
        AWS::EC2::Instance instanceType == "t3.medium"
    "###;

    const VARIABLE_ASSIGNMENT_LITERAL: &str = r###"
       let latest := "ami-123456"

       AWS::EC2::Instance availabilityZone in ["us-east-2a", "us-east-2b"]
       AWS::EC2::Instance imageId == %latest

    "###;

    const VARIABLE_ASSIGNMENT_DYN_VARS: &str = r###"
       # assign from incoming context to variable, this is the
       # support that Config needed
       let latest := latest
       let zones  := allowedZones

       AWS::EC2::Instance availabilityZone in %zones
       AWS::EC2::Instance imageId == %latest

    "###;

    const LHS_RHS_DYNAMIC_DIRECT_NO_TYPE: &str = r###"
       AWS::EC2::Instance availabilityZone in allowedZones
       AWS::EC2::Instance imageId == latest
    "###;

    fn simple_context() -> serde_json::Value {
        serde_json::json!({
            "latest": "ami-123456",
            "allowedZones": ["us-west-2a", "us-west-2b"],
            "AWS::EC2::Instance": {
                "keyName": "Key2",
                "availabilityZone": "us-east-2a",
                "instanceType": "t3.medium",
                "imageId": "ami-123456",
                "securityGroups": ["InstanceSecurityGroup"]
            }
        })
    }

    fn simple_context_2() -> serde_json::Value {
        serde_json::json!({
            "latest": "ami-123450",
            "allowedZones": ["us-west-2a", "us-west-2b"],
            "keyName": "Key2",
            "availabilityZone": "us-east-2a",
            "instanceType": "t3.medium",
            "imageId": "ami-123450"
        })
    }

    fn simple_context_3() -> serde_json::Value {
        serde_json::json!({
            "latest": "ami-123450",
            "allowedZones": ["us-east-2a", "us-west-2b"],
            "keyName": "Key2",
            "availabilityZone": "us-east-2a",
            "instanceType": "t3.medium",
            "imageId": "ami-123450"
        })
    }

    #[test]
    fn test_clause_evaluate() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(EASY_CLAUSE, ""))?;
        let context = simple_context();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/default"), Some(&EvalStatus::PASS));

        let context = simple_context_2();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/default"), Some(&EvalStatus::PASS));
        Ok(())
    }

    #[test]
    fn test_var_literal_substitution() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(VARIABLE_ASSIGNMENT_LITERAL, ""))?;
        let context = simple_context();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/default"), Some(&EvalStatus::PASS));
        Ok(())
    }

    #[test]
    fn test_var_dynamic_substitution() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(VARIABLE_ASSIGNMENT_DYN_VARS, ""))?;
        let context = simple_context();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/default"), Some(&EvalStatus::FAIL));
        Ok(())
    }

    #[test]
    fn test_var_dynamic_lhs_rhs() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(LHS_RHS_DYNAMIC_DIRECT_NO_TYPE, ""))?;
        let context = simple_context_3();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/default"), Some(&EvalStatus::PASS));
        Ok(())
    }

    #[test]
    fn test_var_default_rule_clauses() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(DEFAULT_RULE_CLAUSES, ""))?;
        let context = simple_context();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/default"), Some(&EvalStatus::PASS));
        Ok(())
    }

    //
    // Testing named rules and types
    //
    const NAMED_RULES: &str = r###"
        rule s3_encrypted_buckets {
            AWS::S3::Bucket {
                BucketName == /Encrypted/
                BucketEncryption != null
            }
        }

        rule s3_with_kms {
            s3_encrypted_buckets
            AWS::S3::Bucket {
                let algo := BucketEncryption.ServerSideEncryptionConfiguration.*.ServerSideEncryptionByDefault
                %algo.SSEAlgorithm == "aws:kms"
                %algo.KMSMasterKeyID in [/kms-xxx/, /kms-yyy/]
            }
        }

    "###;

    fn create_context() -> serde_json::Value {
        serde_json::json!({
            "AWS::S3::Bucket": {
                 "BucketName": "This-Is-Encrypted",
                 "BucketEncryption": {
                      "ServerSideEncryptionConfiguration": [
                          {
                             "ServerSideEncryptionByDefault": {
                                 "SSEAlgorithm": "aws:kms",
                                 "KMSMasterKeyID": "kms-xxx-1234"
                             }
                          },
                          {
                             "ServerSideEncryptionByDefault": {
                                 "SSEAlgorithm": "aws:kms",
                                 "KMSMasterKeyID": "kms-yyy-1234"
                             }
                          }
                      ]
                 }
            }
        })
    }

    #[test]
    fn test_named_rules() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(NAMED_RULES, ""))?;
        let context = create_context();
        let resolutions= rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(statuses.get("/s3_encrypted_buckets"), Some(&EvalStatus::PASS));
        assert_eq!(statuses.get("/s3_with_kms"), Some(&EvalStatus::PASS));
        Ok(())
    }

    const DEFAULT_RULE_CLAUSES_WITH_VARIABLE_FROM_CXT: &str = r###"
         AWS::EC2::Instance {
             securityGroups IN %ALLOWED_GROUPS
             keyName == "KeyName" or keyName == "Key2"
             availabilityZone in %ALLOWED_ZONES
             instanceType == %INS_TYPE
         }
     "###;


    fn create_context_with_variables() -> serde_json::Value {
        serde_json::json!({
             "ALLOWED_GROUPS": ["sg-123456", "sg-123546"],
             "INS_TYPE": "t3.medium",
             "ALLOWED_ZONES": ["us-east-2a", "us-west-2b"],
             "AWS::EC2::Instance": {
                 "keyName": "Key2",
                 "availabilityZone": "us-east-2a",
                 "instanceType": "t3.medium",
                 "imageId": "ami-123456",
                 "securityGroups": ["sg-123456"]
             }
         })
    }

    #[test]
    fn test_named_rules_with_variable() -> Result<(), Error> {
        let (_span, rules) = parse_rules(Span::new_extra(DEFAULT_RULE_CLAUSES_WITH_VARIABLE_FROM_CXT, ""))?;
        let context = create_context_with_variables();
        let resolutions = rules.evaluate(&context)?;
        let statuses = resolutions.get_resolved_statuses();
        assert_eq!(*statuses.get("/default").unwrap(), EvalStatus::PASS);
        Ok(())
    }

}

