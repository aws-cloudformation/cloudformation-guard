use crate::rules::expr::*;
use std::collections::HashMap;
use crate::errors::{Error, ErrorKind};
use nom::lib::std::collections::HashSet;

fn dependency_order<'r, T: ?Sized>(current: &'r str,
                                   visited: &mut HashSet<&'r str>,
                                   dependencies: &HashMap<&'r str, (Vec<&'r str>, &'r T)>,
                                   order: &mut Vec<&'r str>) -> Result<(), Error> {
    visited.insert(current);
    if let Some((deps, obj)) = dependencies.get(current) {
        for each in deps {
            if !visited.contains(*each) {
                dependency_order(*each, visited, dependencies, order)?;
            }
        }
    } else {
        return Err(Error::new(ErrorKind::MissingVariable(
            format!("Attempting to resolve {}, is missing the dependencies {:?}",
                current, dependencies.keys()))));
    }
    order.push(current);
    Ok(())
}

pub(in crate::rules) fn make_dependency_order<'r, T: ?Sized>(dependencies: HashMap<&'r str, (Vec<&'r str>, &'r T)>)
                                                             -> Result<Vec<(&'r str, &'r T)>, Error> {
    let mut ordered = Vec::with_capacity(dependencies.len());
    let mut visited = HashSet::with_capacity(dependencies.len());
    for each in dependencies.keys() {
        if !visited.contains(*each) {
            dependency_order(*each, &mut visited, &dependencies, &mut ordered)?;
        }
    }

    let mut pairs = Vec::with_capacity(ordered.len());
    for each in ordered {
        pairs.push((each, dependencies[each].1));
    }
    Ok(pairs)
}

fn named_rule<'r>(rule_expr: &'r NamedRuleClauseExpr<'r>,
                  rule: &'r NamedRuleBlockExpr<'r>,
                  tuples: &mut HashMap<&'r str, (Vec<&'r str>, &'r NamedRuleBlockExpr<'r>)>) {

    match rule_expr {
        NamedRuleClauseExpr::NamedRule(name) | NamedRuleClauseExpr::NotNamedRule(name) => {
            tuples.get_mut(rule.rule_name.as_str()).unwrap().0.push(name.as_str());
        }
        _ => {}
    }
}

pub(crate) fn rules_execution_order_itr<'r>(rules: Vec<&'r Expr<'r>>)
    -> Result<Vec<(&'r str, &'r NamedRuleBlockExpr<'r>)>, Error>
{
    let mut rules_tuples: HashMap<&str, (Vec<&str>, &NamedRuleBlockExpr)> = HashMap::with_capacity(rules.len());
    for each in rules {
        if let Expr::NamedRule(rule) = each {
            if rules_tuples.contains_key(rule.rule_name.as_str()) {
                return Err(Error::new(ErrorKind::MultipleValues(
                    format!("Rule name happens multiple times {}", rule.rule_name)
                )));
            }
            rules_tuples.entry(&rule.rule_name).or_insert_with(|| (Vec::with_capacity(2), rule));
            for every in &rule.rule_clauses {
                if let NamedRuleExpr::RuleClause(clause) = every {
                    named_rule(clause, rule, &mut rules_tuples);
                }

                if let NamedRuleExpr::DisjunctionRuleClause(disjunct) = every {
                    for each in disjunct {
                        named_rule(each, rule, &mut rules_tuples);
                    }
                }
            }
        }
    }
    Ok(make_dependency_order(rules_tuples)?)
}

pub(crate) fn rules_execution_order<'r>(rules: &'r Rules<'r>) -> Result<Vec<(&'r str, &'r NamedRuleBlockExpr<'r>)>, Error> {
    let mut rules_tuples: HashMap<&str, (Vec<&str>, &NamedRuleBlockExpr)> = HashMap::with_capacity(rules.len());
    for each in rules {
        if let Expr::NamedRule(rule) = each {
            if rules_tuples.contains_key(rule.rule_name.as_str()) {
                return Err(Error::new(ErrorKind::MultipleValues(
                    format!("Rule name happens multiple times {}", rule.rule_name)
                )));
            }
            rules_tuples.entry(&rule.rule_name).or_insert_with(|| (Vec::with_capacity(2), rule));
            for every in &rule.rule_clauses {
                if let NamedRuleExpr::RuleClause(clause) = every {
                    named_rule(clause, rule, &mut rules_tuples);
                }

                if let NamedRuleExpr::DisjunctionRuleClause(disjunct) = every {
                    for each in disjunct {
                        named_rule(each, rule, &mut rules_tuples);
                    }
                }
            }
        }
    }
    Ok(make_dependency_order(rules_tuples)?)
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::rules::parser::*;

    #[test]
    fn dep_order() {
        let mut deps = HashMap::with_capacity(3);
        deps.insert("a", (vec!["b", "c"], "a-value"));
        deps.insert("b", (vec![], "b-value"));
        deps.insert("c", (vec!["b"], "c-value"));

        let order = make_dependency_order(deps).unwrap();
        assert_eq!(order, vec![("b", "b-value"), ("c", "c-value"), ("a", "a-value")])
    }

    #[test]
    fn dep_order_rules() -> Result<(), Error> {
        let source = r###"
#
#  this is the set of rules for secure S3 bucket
#  it must not be public AND
#  it must have a policy associated
#
rule s3_secure {
    AWS::S3::Bucket {
        public != true
        policy != null
    }
}

#
# must be s3_secure or
# there must a tag with a key ExternalS3Approved as an exception
#
rule s3_secure_exception {
    s3_secure or
    AWS::S3::Bucket tags.*.key in ["ExternalS3Approved"]
}

let kms_keys := [
    "arn:aws:kms:123456789012:alias/allowed-primary",
    "arn:aws:kms:123456789012:alias/allowed-secondary"
]

let encrypted := false
let latest := "ami-6458235"

        "###;
        let input = Span::new_extra(source, "");
        let rules = parse_rules(input)?.1;
        let deps = rules_execution_order(&rules)?;
        let expected = vec!["s3_secure", "s3_secure_exception"];
        let ordered = deps.iter().map(|(name, _)| *name).collect::<Vec<&str>>();
        assert_eq!(expected, ordered);
        Ok(())
    }
}