use std::collections::HashMap;
use crate::rules::expr::*;
use crate::errors::{Error, ErrorKind};
use crate::rules::dependency::make_dependency_order;
use crate::rules::values::Value;
use crate::rules::common::{walk_type_value, walk_value};
use std::convert::TryFrom;

#[derive(Clone, Debug)]
pub(crate) struct BlockScope<'r> {
    scope: String,
    parent: *const BlockScope<'r>,
    variables: HashMap<&'r str, &'r LetExpr>,
    context: &'r serde_json::Value,
}

impl <'r> BlockScope<'r> {

    pub(crate) fn root(rules: &'r Rules<'r>, context: &'r serde_json::Value) -> Result<BlockScope<'r>, Error> {
        let mut variables = HashMap::with_capacity(rules.len());
        for each in rules {
            if let Expr::Assignment(expr) = each {
                Self::insert(expr, &mut variables)?;
            }
        }

        Ok(BlockScope {
            scope: "".to_owned(),
            parent: std::ptr::null(),
            variables,
            context
        })
    }

    pub(crate) fn rule(rule: &'r NamedRuleBlockExpr<'r>,
                       context: &'r serde_json::Value,
                       parent: *const BlockScope<'r>) -> Result<BlockScope<'r>, Error> {
        let mut variables = HashMap::with_capacity(rule.rule_clauses.len());
        for each in &rule.rule_clauses {
            match each {
                NamedRuleExpr::Variable(expr) => Self::insert(expr, &mut variables)?,
                NamedRuleExpr::RuleClause(single) => Self::rule_clause(single, &mut variables)?,
                NamedRuleExpr::DisjunctionRuleClause(multiple) => {
                    for each in multiple {
                        Self::rule_clause(each, &mut variables)?;
                    }
                }
            }
        }

        let scope = unsafe {
            match parent.as_ref() {
                Some(p) => &p.scope,
                None => ""
            }
        };
        let scope = format!("{}/{}", scope, rule.rule_name);

        Ok(BlockScope {
            scope,
            parent,
            variables,
            context,
        })
    }

    pub(crate) fn type_block(clause: &'r TypeClauseExpr<'r>,
                             context: &'r serde_json::Value,
                             parent: *const BlockScope<'r>) -> Result<BlockScope<'r>, Error> {
        let mut variables = HashMap::with_capacity(clause.type_clauses.len());
        for each in &clause.type_clauses {
            if let PropertyClause::Variable(expr) = each {
                Self::insert(expr, &mut variables)?;
            }
        }

        let scope = unsafe {
            match parent.as_ref() {
                Some(p) => &p.scope,
                None => "/"
            }
        };
        let scope = format!("{}/{}", scope, clause.type_name);
        Ok(BlockScope { scope, parent, variables, context, })
    }

    pub(crate) fn scope(&self) -> &str {
        &self.scope
    }

    pub(crate) fn expand_variable_values(&self, name: &str, access: &PropertyAccess, resolutions: &mut Resolutions)
        -> Result<Vec<Value>, Error> {
        let scope_path = format!("{}/{}", self.scope(), name);
        if let Some(assign_expr) = self.variables.get(name) {
            if let Some(var) = &access.var_access {
                if assign_expr.var.as_str() == var.as_str() {
                    return Ok(match &assign_expr.value {
                        LetValue::Value(literal) => {
                            if let Some(values) = resolutions.get_resolved_values(&scope_path) {
                                values.clone()
                            } else {
                                let walk = walk_type_value(
                                    literal, access.property_access(), self.scope.to_owned())?;
                                let mut result: Vec<Value> = Vec::with_capacity(walk.len());
                                for each in walk {
                                    result.push(each.clone());
                                }
                                resolutions.set_resolved_values(&scope_path, result.clone());
                                result
                            }
                        },

                        LetValue::PropertyAccess(dyn_access) => {
                            let scope_path_projection = format!("{}/{}", scope_path, access.dotted_access());
                            if let Some(values) = resolutions.get_resolved_values(&scope_path_projection) {
                                values.clone()
                            } else {
                                let flattened = if let Some(values) = resolutions.get_resolved_values(&scope_path) {
                                    values.clone()
                                }
                                else {
                                    let result = dyn_access.project_dynamic(self.context, self.scope.clone())?;
                                    //
                                    // Stash the variable level resolution
                                    //
                                    resolutions.set_resolved_values(&scope_path, result.clone());
                                    result
                                };
                                let mut result = Vec::with_capacity(flattened.len());
                                for each in flattened {
                                    let values = walk_type_value(
                                        &each, access.property_access(), scope_path.clone())?;
                                    let values = values.iter().map(|s| (*s).clone())
                                        .collect::<Vec<Value>>();
                                    result.extend(values)
                                }
                                resolutions.set_resolved_values(&scope_path_projection, result.clone());
                                result
                            }
                        }
                    })
                }
                return Err(Error::new(ErrorKind::IncompatibleError(
                    format!("Property access variable {} does not match assignment variable {}", var, assign_expr.var)
                )));
            }
            Err(Error::new(ErrorKind::IncompatibleError(
                format!("Property access is based on dynamic context not on this variable {}", assign_expr.var)
            )))

        }
        else if let Some(parent) = unsafe { self.parent.as_ref() } {
            parent.expand_variable_values(name, access, resolutions)
        }
        else if let Some(json) = self.context.get(name) {
            //
            // See if we can get this off the incoming context at the root level.
            //
            let result = access.project_dynamic(json, self.scope.clone())?;
            resolutions.set_resolved_values(&scope_path, result.clone());
            Ok(result)
        }
        else {
            Err(Error::new(ErrorKind::MissingVariable(
                format!("Could not find a variable {}, in any parent and this scope {}", name, self.scope))))
        }
    }


    fn insert(expr: &'r LetExpr, variables: &mut HashMap<&'r str, &'r LetExpr>) -> Result<(), Error> {
        if let Some(existing) = variables.insert(expr.var.as_str(), expr) {
            return Err(Error::new(ErrorKind::MultipleValues(
                format!("There are clashing variable definitions for {}", existing.var)
            )));
        }
        Ok(())
    }

    fn rule_clause(expr: &'r NamedRuleClauseExpr<'r>,
                   variables: &mut HashMap<&'r str, &'r LetExpr>) -> Result<(), Error> {
        if let NamedRuleClauseExpr::TypeClause(type_clause) = expr {
            for each in &type_clause.type_clauses {
                if let PropertyClause::Variable(var) = each {
                    Self::insert(var, variables)?;
                }
            }
        }
        Ok(())
    }


}
