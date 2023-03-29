use super::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::eval_context::EventRecord;
use crate::rules::exprs::{AccessQuery, GuardClause, RulesFile};
use crate::rules::values::Value;
use crate::rules::RecordType;
use crate::rules::{EvalContext, NamedStatus, Status};
use std::convert::TryFrom;

const RESOURCES: &str = r###"
Resources:
  s3:
    Type: AWS::S3::Bucket
    Properties:
      Name: my-bucket
  s32:
    Type: AWS::S3::Bucket
    Properties:
      Name: my-bucket-2
  s3Policy:
    Type: AWS::S3::BucketPolicy
    Properties:
      Bucket: !Ref s3
  iam:
    Type: AWS::IAM::Role
    Properties:
      Policy:
        Statement:
          - Effect: Allow
            Action: '*'
            Principal: '*'
            Resource: ['s3*', 'ec2*']
  iam2:
    Type: AWS::IAM::Role
    Properties:
      Policy:
        Statement:
          - Effect: Allow
            Action: '*'
            Principal: ['123456789012', 'ec2.amazonaws.com']
            Resource: '*'
  custom:
    Type: Custom::Resource
    Properties:
      ge: [10, 20, 30]
      le: 10
  custom2:
    Type: Custom::Resource
    Properties:
      ge: 10
      le: [10, 20, 30]
  custom3:
    Type: Custom::Data
    Properties:
      ge: [10, 20, 30]
      le: 10
"###;

const RULES_EQ: &str = r###"
let literal1 = [10, 20, 30]
let literal2 = [10, 20]

rule check_eq_literals_fail {
    %literal1 == %literal2
}

rule check_in_literals_pass {
    %literal2 in %literal1
}

let s3s         = Resources[ s3_id | Type == "AWS::S3::Bucket" ]
let s3Policies  = some Resources[ Type == "AWS::S3::BucketPolicy" ].Bucket.Ref
rule check_eq_queries_fail when %s3s not empty {
   %s3Policies == %s3_id
}

rule check_query_to_rhs_literal_fail {
    Resources[ Type == "AWS::IAM::Role" ].Properties.Policy.Statement[*] {
        Principal != '*'
    }
}
"###;

#[test]
fn test_operator_eq_literal() -> crate::rules::Result<()> {
    let query = AccessQuery::try_from(
        r#"Resources[ Type == "AWS::IAM::Role" ].Properties.Policy.Statement[*].Principal"#,
    )?;
    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: &value,
        recorder: None,
    };
    let answers = evaluator.query(&query.query)?;
    assert_eq!(answers.len(), 2);
    let literal = PathAwareValue::String((Path::root(), "*".to_string()));
    let literal_string = vec![QueryResult::Literal(&literal)];

    //
    // != '*'
    //

    let result = (CmpOperator::Eq, true).compare(&answers, &literal_string)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 3);
    let count = result
        .iter()
        .filter(|r| {
            if let ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_)) = r {
                true
            } else {
                false
            }
        })
        .count();
    assert_eq!(count, 1);

    //
    // == '*'
    //
    let result = (CmpOperator::Eq, false).compare(&answers, &literal_string)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 3);
    let count = result
        .iter()
        .filter(|r| {
            if let ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_)) = r {
                true
            } else {
                false
            }
        })
        .count();
    assert_eq!(count, 2);

    Ok(())
}

#[test]
fn test_operator_eq_queries() -> crate::rules::Result<()> {
    let s3_keys = [
        PathAwareValue::String((Path::root(), "s3".to_string())),
        PathAwareValue::String((Path::root(), "s32".to_string())),
    ];

    let s3_bucket_refs = [PathAwareValue::String((
        Path::new(
            "/Resources/s3Policy/Properties/Bucket/Ref".to_string(),
            0,
            0,
        ),
        String::from("s3"),
    ))];

    let s3_keys_query_results: Vec<QueryResult<'_>> =
        s3_keys.iter().map(QueryResult::Resolved).collect();
    let s3_bucket_policy_results: Vec<QueryResult<'_>> =
        s3_bucket_refs.iter().map(QueryResult::Resolved).collect();
    let result =
        (CmpOperator::Eq, false).compare(&s3_keys_query_results, &s3_bucket_policy_results)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    let eval_result = &result[0];
    assert_eq!(
        matches!(
            eval_result,
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
        ),
        true
    );

    Ok(())
}

#[test]
fn test_operator_eq_query_to_scalar_literal_ok() -> crate::rules::Result<()> {
    let lhs_prefix = "/LHS";
    let lhs_scalar = PathAwareValue::String((
        Path::new(format!("{}/Scalar", lhs_prefix), 1, 1),
        "*".to_string(),
    ));
    let lhs_list = PathAwareValue::List((
        Path::new(format!("{}/List", lhs_prefix), 2, 1),
        vec![
            PathAwareValue::String((
                Path::new(format!("{}/List/0", lhs_prefix), 3, 1),
                "ec2:*".to_string(),
            )),
            PathAwareValue::String((
                Path::new(format!("{}/List/1", lhs_prefix), 4, 1),
                "*".to_string(),
            )),
            PathAwareValue::String((
                Path::new(format!("{}/List/2", lhs_prefix), 5, 1),
                "s3:*".to_string(),
            )),
        ],
    ));

    let lhs_queries = [
        QueryResult::Resolved(&lhs_scalar),
        QueryResult::Resolved(&lhs_list),
    ];

    let rhs_scalar = PathAwareValue::String((Path::root(), "*".to_string()));
    let rhs_queries = [QueryResult::Literal(&rhs_scalar)];

    //
    // Checking something like Resources[ Type == "AWS::IAM::Role" ].Properties.Policy.Statement[*].Action != '*'
    //
    let eval = match (CmpOperator::Eq, true).compare(&lhs_queries, &rhs_queries)? {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    //
    // List is flatten for this use case
    //
    assert_eq!(eval.len(), 4);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.rhs, &rhs_scalar), true);
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    let path = p.0.as_str();
                    assert_eq!(path == "/LHS/List/0" || path == "/LHS/List/2", true);
                    assert_eq!(v.as_str() == "ec2:*" || v.as_str() == "s3:*", true);
                }
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.rhs, &rhs_scalar), true);
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    let path = p.0.as_str();
                    assert_eq!(path == "/LHS/List/1" || path == "/LHS/Scalar", true);
                    assert_eq!(v.as_str(), "*");
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    //
    // Checking something like '*' != Resources[ Type == "AWS::IAM::Role" ].Properties.Policy.Statement[*].Action
    //
    let eval = match (CmpOperator::Eq, true).compare(&rhs_queries, &lhs_queries)? {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    //
    // List is flatten for this use case
    //
    assert_eq!(eval.len(), 4);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.lhs, &rhs_scalar), true);
                assert_eq!(matches!(pair.rhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.rhs {
                    let path = p.0.as_str();
                    assert_eq!(path == "/LHS/List/0" || path == "/LHS/List/2", true);
                    assert_eq!(v.as_str() == "ec2:*" || v.as_str() == "s3:*", true);
                }
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.lhs, &rhs_scalar), true);
                assert_eq!(matches!(pair.rhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.rhs {
                    let path = p.0.as_str();
                    assert_eq!(path == "/LHS/List/1" || path == "/LHS/Scalar", true);
                    assert_eq!(v.as_str(), "*");
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_scalar_literal_to_query_ok() -> crate::rules::Result<()> {
    let scalar_literal_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_literal = vec![QueryResult::Literal(&scalar_literal_value)];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), "ec2*".to_string())),
            PathAwareValue::String((Path::root(), "*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(&scalar_query_value),
        QueryResult::Resolved(&scalar_query_list_value),
    ];

    //
    // Literal to query results
    //
    let eval = match CmpOperator::In.compare(&scalar_literal, &query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 2);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(val))) => {
                assert_eq!(std::ptr::eq(val.lhs, &scalar_literal_value), true);
                assert_eq!(std::ptr::eq(val.rhs, &scalar_query_list_value), true);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.lhs, &scalar_literal_value), true);
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_query_value), true);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_list_literal_to_query_ok() -> crate::rules::Result<()> {
    let list_literal_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), "*".to_string())),
            PathAwareValue::String((Path::root(), "ec2:*".to_string())),
        ],
    ));
    let list_literal = vec![QueryResult::Literal(&list_literal_value)];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), "ec2:*".to_string())),
            PathAwareValue::String((Path::root(), "*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(&scalar_query_value),
        QueryResult::Resolved(&scalar_query_list_value),
    ];

    //
    // Literal to query results
    //
    let eval = match CmpOperator::In.compare(&list_literal, &query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 2);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ListIn(l))) => {
                assert_eq!(l.diff.is_empty(), true);
                assert_eq!(std::ptr::eq(l.rhs, &scalar_query_list_value), true);
                assert_eq!(std::ptr::eq(l.lhs, &list_literal_value), true);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(nc)) => {
                assert_eq!(std::ptr::eq(nc.pair.lhs, &list_literal_value), true);
                assert_eq!(std::ptr::eq(nc.pair.rhs, &scalar_query_value), true);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_query_to_scalar_ok() -> crate::rules::Result<()> {
    let scalar_literal_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_literal = vec![QueryResult::Literal(&scalar_literal_value)];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::new("/0".to_string(), 1, 2), "ec2*".to_string())),
            PathAwareValue::String((Path::new("/1".to_string(), 2, 2), "*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(&scalar_query_value),
        QueryResult::Resolved(&scalar_query_list_value),
    ];

    //
    // Query results to Literal. This returns 3 results as we flatten the list to compare with
    // scalar
    //
    let eval = match CmpOperator::In.compare(&query_results, &scalar_literal)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 3);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_literal_value), true);
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    if &p.0 == "" {
                        assert_eq!(std::ptr::eq(pair.lhs, &scalar_query_value), true);
                    } else {
                        assert_eq!(&p.0, "/1");
                        assert_eq!(v == "*", true);
                    }
                }
            }

            //
            // As "ec2*" in "*" FAILs
            //
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_literal_value), true);
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    assert_eq!(&p.0, "/0");
                    assert_eq!(v, "ec2*");
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    //
    // Literal to query check
    //
    let eval = match CmpOperator::In.compare(&scalar_literal, &query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // 2 results, one scalar to scalar okay
    //
    assert_eq!(eval.len(), 2);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.lhs, &scalar_literal_value), true);
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_query_value), true);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(val))) => {
                assert_eq!(std::ptr::eq(val.lhs, &scalar_literal_value), true);
                assert_eq!(std::ptr::eq(val.rhs, &scalar_query_list_value), true);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_query_to_scalar_in_string_ok() -> crate::rules::Result<()> {
    let scalar_literal_value = PathAwareValue::String((Path::root(), "*,ec2*,s3*".to_string()));
    let scalar_literal = vec![QueryResult::Literal(&scalar_literal_value)];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::new("/0".to_string(), 1, 2), "ec2*".to_string())),
            PathAwareValue::String((Path::new("/1".to_string(), 2, 2), "*".to_string())),
            PathAwareValue::String((Path::new("/2".to_string(), 3, 2), "s3*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(&scalar_query_value),
        QueryResult::Resolved(&scalar_query_list_value),
    ];

    //
    // Query results to Literal. This returns 4 results as we flatten the list to compare with
    // scalar
    //
    let eval = match CmpOperator::In.compare(&query_results, &scalar_literal)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 4);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                //
                // RHS value pointer is the same
                //
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_literal_value), true);

                //
                // Expect all String values from the flattened list
                //
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    match p.0.as_str() {
                        "" => {
                            assert_eq!(std::ptr::eq(pair.lhs, &scalar_query_value), true);
                        }

                        "/0" => {
                            assert_eq!(v, "ec2*");
                        }
                        "/1" => {
                            assert_eq!(v, "*");
                        }
                        "/2" => {
                            assert_eq!(v, "s3*");
                        }

                        rest => {
                            println!("{}", rest);
                            unreachable!()
                        }
                    }
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_query_to_scalar_in_string_not_ok() -> crate::rules::Result<()> {
    let scalar_literal_value = PathAwareValue::String((Path::root(), "*,ec2*,s3*".to_string()));
    let scalar_literal = vec![QueryResult::Literal(&scalar_literal_value)];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::new("/0".to_string(), 1, 2), "ec2*".to_string())),
            PathAwareValue::String((Path::new("/1".to_string(), 2, 2), "*".to_string())),
            PathAwareValue::String((Path::new("/2".to_string(), 3, 2), "s3*".to_string())),
            PathAwareValue::String((Path::new("/3".to_string(), 3, 2), "iam*".to_string())), // fails
        ],
    ));
    let unresolved_rhs_traversed_to = PathAwareValue::Map((
        Path::new("/Resources/iam/Properties".to_string(), 2, 10),
        MapValue {
            values: indexmap::IndexMap::new(),
            keys: vec![],
        },
    ));
    let ur = UnResolved {
        reason: None,
        traversed_to: &unresolved_rhs_traversed_to,
        remaining_query: "Policy.Statements[*].Action".to_string(),
    };
    let query_results = vec![
        QueryResult::Resolved(&scalar_query_value),
        QueryResult::Resolved(&scalar_query_list_value),
        QueryResult::UnResolved(ur.clone()),
    ];

    //
    // Query results to Literal. This returns 6 results as we flatten the list to compare with
    // scalar
    //
    let eval = match CmpOperator::In.compare(&query_results, &scalar_literal)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 6);
    for each in eval {
        match each {
            ValueEvalResult::LhsUnresolved(inur) => {
                assert_eq!(ur, inur);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                //
                // RHS value pointer is the same
                //
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_literal_value), true);

                //
                // Expect all String values from the flattened list
                //
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    match p.0.as_str() {
                        "" => {
                            assert_eq!(std::ptr::eq(pair.lhs, &scalar_query_value), true);
                        }

                        "/0" => {
                            assert_eq!(v, "ec2*");
                        }
                        "/1" => {
                            assert_eq!(v, "*");
                        }
                        "/2" => {
                            assert_eq!(v, "s3*");
                        }

                        rest => {
                            println!("{}", rest);
                            unreachable!()
                        }
                    }
                }
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                //
                // RHS value pointer is the same
                //
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_literal_value), true);

                //
                // Expect all String values from the flattened list
                //
                assert_eq!(matches!(pair.lhs, PathAwareValue::String(_)), true);
                if let PathAwareValue::String((p, v)) = pair.lhs {
                    assert_eq!(&p.0, "/3");
                    assert_eq!(v, "iam*");
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_query_to_query_ok() -> crate::rules::Result<()> {
    let lhs_value_path_str = "/LHS".to_string();
    let lhs_scalar_value = PathAwareValue::String((
        Path::new(format!("{}/Scalar", lhs_value_path_str), 0, 0),
        "*".to_string(),
    ));
    let lhs_list_value = PathAwareValue::List((
        Path::new(format!("{}/List", lhs_value_path_str), 1, 1),
        vec![
            PathAwareValue::String((
                Path::new(format!("{}/List/0", lhs_value_path_str), 2, 1),
                "ec2:*".to_string(),
            )),
            PathAwareValue::String((
                Path::new(format!("{}/List/1", lhs_value_path_str), 2, 1),
                "s3:*".to_string(),
            )),
            PathAwareValue::String((
                Path::new(format!("{}/List/2", lhs_value_path_str), 2, 1),
                "iam:*".to_string(),
            )),
        ],
    ));

    let lhs_query_results = vec![
        QueryResult::Resolved(&lhs_scalar_value),
        QueryResult::Resolved(&lhs_list_value),
    ];

    let rhs_scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let rhs_scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::new("/0".to_string(), 1, 2), "ec2:*".to_string())),
            PathAwareValue::String((Path::new("/1".to_string(), 2, 2), "*".to_string())),
            PathAwareValue::String((Path::new("/2".to_string(), 3, 2), "s3:*".to_string())),
            PathAwareValue::String((Path::new("/3".to_string(), 3, 2), "iam:*".to_string())),
        ],
    ));

    let rhs_query_results = vec![
        QueryResult::Resolved(&rhs_scalar_query_value),
        QueryResult::Resolved(&rhs_scalar_query_list_value),
    ];

    let eval = match CmpOperator::In.compare(&lhs_query_results, &rhs_query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // Expect 1 results
    //
    assert_eq!(eval.len(), 1);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(lin))) => {
                assert_eq!(lin.diff.is_empty(), true);
                for each in lin.lhs {
                    if each.is_scalar() {
                        assert_eq!(std::ptr::eq(each, &lhs_scalar_value), true);
                    } else {
                        assert_eq!(std::ptr::eq(each, &lhs_list_value), true);
                    }
                }

                for each in lin.rhs {
                    if each.is_scalar() {
                        assert_eq!(std::ptr::eq(each, &rhs_scalar_query_value), true);
                    } else {
                        assert_eq!(std::ptr::eq(each, &rhs_scalar_query_list_value), true);
                    }
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    //
    // Just list and it contains everything
    //
    let rhs_query_results = vec![QueryResult::Resolved(&rhs_scalar_query_list_value)];

    //
    // Query results to Literal. This returns 6 results as we flatten the list to compare with
    // scalar
    //
    let eval = match CmpOperator::In.compare(&lhs_query_results, &rhs_query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // Expect 1 results
    //
    assert_eq!(eval.len(), 1);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                assert_eq!(qin.diff.is_empty(), true);
                for each in qin.lhs {
                    if each.is_scalar() {
                        assert_eq!(std::ptr::eq(each, &lhs_scalar_value), true);
                    } else {
                        assert_eq!(std::ptr::eq(each, &lhs_list_value), true);
                    }
                }
                for each in qin.rhs {
                    assert_eq!(std::ptr::eq(each, &rhs_scalar_query_list_value), true);
                }
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_query_to_query_not_ok() -> crate::rules::Result<()> {
    let lhs_value_path_str = "/LHS".to_string();
    let lhs_scalar_value = PathAwareValue::String((
        Path::new(format!("{}/Scalar", lhs_value_path_str), 0, 0),
        "*".to_string(),
    ));
    let lhs_list_value = PathAwareValue::List((
        Path::new(format!("{}/List", lhs_value_path_str), 1, 1),
        vec![
            PathAwareValue::String((
                Path::new(format!("{}/List/0", lhs_value_path_str), 2, 1),
                "ec2:*".to_string(),
            )),
            PathAwareValue::String((
                Path::new(format!("{}/List/1", lhs_value_path_str), 2, 1),
                "s3:*".to_string(),
            )),
            PathAwareValue::String((
                Path::new(format!("{}/List/2", lhs_value_path_str), 2, 1),
                "iam:*".to_string(),
            )),
        ],
    ));

    let unresolved_rhs_traversed_to = PathAwareValue::Map((
        Path::new("/Resources/iam/Properties".to_string(), 2, 10),
        MapValue {
            values: indexmap::IndexMap::new(),
            keys: vec![],
        },
    ));
    let ur = UnResolved {
        reason: None,
        traversed_to: &unresolved_rhs_traversed_to,
        remaining_query: "Policy.Statements[*].Action".to_string(),
    };
    let lhs_query_results = vec![
        QueryResult::Resolved(&lhs_scalar_value),
        QueryResult::Resolved(&lhs_list_value),
        QueryResult::UnResolved(ur.clone()),
    ];

    let rhs_scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let rhs_scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::new("/0".to_string(), 1, 2), "ec2:*".to_string())),
            PathAwareValue::String((Path::new("/2".to_string(), 3, 2), "s3:*".to_string())),
            PathAwareValue::String((Path::new("/3".to_string(), 3, 2), "iam:*".to_string())),
        ],
    ));

    let rhs_query_results = vec![
        QueryResult::Resolved(&rhs_scalar_query_value),
        QueryResult::Resolved(&rhs_scalar_query_list_value),
    ];

    let eval = match CmpOperator::In.compare(&lhs_query_results, &rhs_query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // Expect 2 results, one LHS unresolved, one for the rest
    //
    assert_eq!(eval.len(), 2);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                assert_eq!(qin.diff.is_empty(), true);
                assert_eq!(qin.rhs.len(), 2);
                assert_eq!(std::ptr::eq(qin.rhs[0], &rhs_scalar_query_value), true);
                assert_eq!(std::ptr::eq(qin.rhs[1], &rhs_scalar_query_list_value), true);
                assert_eq!(qin.lhs.len(), 2);
                assert_eq!(std::ptr::eq(qin.lhs[0], &lhs_scalar_value), true);
                assert_eq!(std::ptr::eq(qin.lhs[1], &lhs_list_value), true);
            }

            ValueEvalResult::LhsUnresolved(lhsur) => {
                assert_eq!(ur, lhsur);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    //
    // Just list
    //
    let rhs_query_results = vec![QueryResult::Resolved(&rhs_scalar_query_list_value)];

    let eval = match CmpOperator::In.compare(&lhs_query_results, &rhs_query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // Expect 2 results
    //
    assert_eq!(eval.len(), 2);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                assert_eq!(qin.diff.is_empty(), false);
                assert_eq!(qin.diff.len(), 1);
                assert_eq!(std::ptr::eq(qin.diff[0], &lhs_scalar_value), true);
                assert_eq!(qin.rhs.len(), 1);
                assert_eq!(std::ptr::eq(qin.rhs[0], &rhs_scalar_query_list_value), true);
            }

            ValueEvalResult::LhsUnresolved(lhsur) => {
                assert_eq!(ur, lhsur);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    //
    // Checking !IN
    //
    let eval = match (CmpOperator::In, true).compare(&lhs_query_results, &rhs_query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // Expect 2 results
    //
    assert_eq!(eval.len(), 2);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                assert_eq!(qin.diff.is_empty(), false);
                assert_eq!(qin.diff.len(), 1);
                assert_eq!(std::ptr::eq(qin.diff[0], &lhs_list_value), true);
                assert_eq!(qin.rhs.len(), 1);
                assert_eq!(std::ptr::eq(qin.rhs[0], &rhs_scalar_query_list_value), true);
            }

            ValueEvalResult::LhsUnresolved(lhsur) => {
                assert_eq!(ur, lhsur);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_in_literal_list_in_query_ok() -> crate::rules::Result<()> {
    let lhs_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), String::from("Name"))),
            PathAwareValue::String((Path::root(), String::from("Environment"))),
        ],
    ));
    let lhs = QueryResult::Literal(&lhs_value);
    let rhs_value = PathAwareValue::String((Path::root(), String::from("Environment")));
    let rhs = QueryResult::Resolved(&rhs_value);
    match CmpOperator::In.compare(&[lhs], &[rhs]) {
        Ok(EvalResult::Result(result)) => {
            for each in result {
                match each {
                    ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                        Compare::QueryIn(QueryIn { diff, .. }),
                    )) => {
                        assert_eq!(diff.is_empty(), false, "{:?}", diff);
                    }
                    _ => unreachable!(),
                }
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}

#[test]
fn test_operator_in_scalar_literal_to_query_ok_with_unresolved() -> crate::rules::Result<()> {
    let scalar_literal_value =
        PathAwareValue::String((Path::new("Literal".to_string(), 0, 0), "*".to_string()));
    let scalar_literal = vec![QueryResult::Literal(&scalar_literal_value)];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), "ec2*".to_string())),
            PathAwareValue::String((Path::root(), "*".to_string())),
        ],
    ));
    let unresolved_rhs_traversed_to = PathAwareValue::Map((
        Path::new("/Resources/iam/Properties".to_string(), 2, 10),
        MapValue {
            values: indexmap::IndexMap::new(),
            keys: vec![],
        },
    ));
    let ur = UnResolved {
        reason: None,
        traversed_to: &unresolved_rhs_traversed_to,
        remaining_query: "Policy.Statements[*].Action".to_string(),
    };
    let query_results = vec![
        QueryResult::Resolved(&scalar_query_value),
        QueryResult::Resolved(&scalar_query_list_value),
        QueryResult::UnResolved(ur.clone()),
    ];

    let eval = match CmpOperator::In.compare(&scalar_literal, &query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 3);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(std::ptr::eq(pair.lhs, &scalar_literal_value), true);
                assert_eq!(std::ptr::eq(pair.rhs, &scalar_query_value), true);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(val))) => {
                assert_eq!(std::ptr::eq(val.lhs, &scalar_literal_value), true);
                assert_eq!(std::ptr::eq(val.rhs, &scalar_query_list_value), true);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(inur, lhs)) => {
                assert_eq!(std::ptr::eq(lhs, &scalar_literal_value), true);
                assert_eq!(ur, inur);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }

    Ok(())
}

#[test]
fn test_operator_eq_vs_in_from_queries() -> crate::rules::Result<()> {
    let custom =
        AccessQuery::try_from(r#"Resources[ Type == "Custom::Resource" ].Properties.ge"#)?.query;
    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: &value,
        recorder: None,
    };
    let lhs_answers = evaluator.query(&custom)?;
    let custom_data =
        AccessQuery::try_from(r#"Resources[ Type == "Custom::Data" ].Properties.ge"#)?.query;
    let rhs_answers = evaluator.query(&custom_data)?;
    let result = (CmpOperator::Eq, false).compare(&lhs_answers, &rhs_answers)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    let eval_result = &result[0];
    assert_eq!(
        matches!(
            eval_result,
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
        ),
        true
    );

    let result = (CmpOperator::In, false).compare(&lhs_answers, &rhs_answers)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    assert_eq!(
        result
            .iter()
            .find(|r| match r {
                ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_)) => true,
                _ => false,
            })
            .is_some(),
        false
    );

    Ok(())
}
