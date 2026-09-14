use super::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::exprs::AccessQuery;
use crate::rules::EvalContext;
use pretty_assertions::assert_eq;
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
  OutboundRule:
    Type: AWS::EC2::SecurityGroupEgress
    Properties:
      FromPort: 46
      ToPort: 56
"###;

// const RULES_EQ: &str = r###"
// let literal1 = [10, 20, 30]
// let literal2 = [10, 20]

// rule check_eq_literals_fail {
//     %literal1 == %literal2
// }

// rule check_in_literals_pass {
//     %literal2 in %literal1
// }

// let s3s         = Resources[ s3_id | Type == "AWS::S3::Bucket" ]
// let s3Policies  = some Resources[ Type == "AWS::S3::BucketPolicy" ].Bucket.Ref
// rule check_eq_queries_fail when %s3s not empty {
//    %s3Policies == %s3_id
// }

// rule check_query_to_rhs_literal_fail {
//     Resources[ Type == "AWS::IAM::Role" ].Properties.Policy.Statement[*] {
//         Principal != '*'
//     }
// }
// "###;

#[test]
fn test_operator_eq_literal() -> crate::rules::Result<()> {
    let query = AccessQuery::try_from(
        r#"Resources[ Type == "AWS::IAM::Role" ].Properties.Policy.Statement[*].Principal"#,
    )?;
    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let answers = evaluator.query(&query.query)?;
    assert_eq!(answers.len(), 2);
    let literal = PathAwareValue::String((Path::root(), "*".to_string()));
    let literal_string = vec![QueryResult::Literal(Rc::new(literal))];

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
            matches!(
                r,
                ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
            )
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
            matches!(
                r,
                ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
            )
        })
        .count();
    assert_eq!(count, 2);

    Ok(())
}

#[test]
fn test_operator_eq_queries() -> crate::rules::Result<()> {
    let s3_keys = [
        Rc::new(PathAwareValue::String((Path::root(), "s3".to_string()))),
        Rc::new(PathAwareValue::String((Path::root(), "s32".to_string()))),
    ];

    let s3_bucket_refs = [Rc::new(PathAwareValue::String((
        Path::new(
            "/Resources/s3Policy/Properties/Bucket/Ref".to_string(),
            0,
            0,
        ),
        String::from("s3"),
    )))];

    let s3_keys_query_results: Vec<QueryResult> = s3_keys
        .iter()
        .map(Rc::clone)
        .map(QueryResult::Resolved)
        .collect();

    let s3_bucket_policy_results: Vec<QueryResult> = s3_bucket_refs
        .iter()
        .map(Rc::clone)
        .map(QueryResult::Resolved)
        .collect();

    let result =
        (CmpOperator::Eq, false).compare(&s3_keys_query_results, &s3_bucket_policy_results)?;

    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };

    assert_eq!(result.len(), 1);
    let eval_result = &result[0];
    assert!(matches!(
        eval_result,
        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
    ));

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
        QueryResult::Resolved(Rc::new(lhs_scalar)),
        QueryResult::Resolved(Rc::new(lhs_list)),
    ];

    let rhs_scalar = PathAwareValue::String((Path::root(), "*".to_string()));
    let rhs_queries = [QueryResult::Literal(Rc::new(rhs_scalar.clone()))];

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
                assert_eq!(&*pair.rhs, &rhs_scalar);
                assert!(matches!(*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
                    let path = p.0.as_str();
                    assert!(path == "/LHS/List/0" || path == "/LHS/List/2");
                    assert!(v.as_str() == "ec2:*" || v.as_str() == "s3:*");
                }
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                assert_eq!(&*pair.rhs, &rhs_scalar);
                assert!(matches!(*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
                    let path = p.0.as_str();
                    assert!(path == "/LHS/List/1" || path == "/LHS/Scalar");
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
                assert_eq!(&*pair.lhs, &rhs_scalar);
                assert!(matches!(*pair.rhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.rhs {
                    let path = p.0.as_str();
                    assert!(path == "/LHS/List/0" || path == "/LHS/List/2");
                    assert!(v.as_str() == "ec2:*" || v.as_str() == "s3:*");
                }
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                assert_eq!(&*pair.lhs, &rhs_scalar);
                assert!(matches!(&*pair.rhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.rhs {
                    let path = p.0.as_str();
                    assert!(path == "/LHS/List/1" || path == "/LHS/Scalar");
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
    let scalar_literal = vec![QueryResult::Literal(Rc::new(scalar_literal_value.clone()))];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), "ec2*".to_string())),
            PathAwareValue::String((Path::root(), "*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(Rc::new(scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(scalar_query_list_value.clone())),
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
                assert_eq!(&*val.lhs, &scalar_literal_value);
                assert_eq!(&*val.rhs, &scalar_query_list_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::Value(pair))) => {
                assert_eq!(&*pair.lhs, &scalar_literal_value);
                assert_eq!(&*pair.rhs, &scalar_query_value);
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
    let list_literal = vec![QueryResult::Literal(Rc::new(list_literal_value.clone()))];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::root(), "ec2:*".to_string())),
            PathAwareValue::String((Path::root(), "*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(Rc::new(scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(scalar_query_list_value.clone())),
    ];

    //
    // Literal to query results
    //
    let eval = match CmpOperator::In.compare(&list_literal, &query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    assert_eq!(eval.len(), 2);
    // Both arms are counted, because the arm carrying the `is_empty` claim below is optional to a `match`.
    // Two `NotComparable` results satisfy `eval.len() == 2` and never enter the Success arm, so the
    // strongest assertion in this test would be skipped and the test would still report green.
    let mut successes = 0;
    let mut not_comparable = 0;
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ListIn(l))) => {
                successes += 1;
                assert!(
                    l.diff.is_empty(),
                    "a Success must carry an empty diff, got {:?}",
                    l.diff
                );
                // The positive half of the line above. An empty diff means "nothing went unmatched", and
                // on its own that is also what a comparison which asked nothing produces -- the same
                // conflation `contained_in`'s own `diff.is_empty()` Success decision rests on. So the
                // count of elements that DID match is asserted against the operand's length, which
                // separates "every element matched" from "no element was compared".
                assert_eq!(
                    matched_elements(&l).len(),
                    2,
                    "both elements of the literal must read as matched, or the empty diff above is the \
                     emptiness of a comparison that never ran; got {:?}",
                    matched_elements(&l)
                );
                assert_eq!(&*l.rhs, &scalar_query_list_value);
                assert_eq!(&*l.lhs, &list_literal_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(nc)) => {
                not_comparable += 1;
                assert_eq!(*nc.pair.lhs, list_literal_value);
                assert_eq!(&*nc.pair.rhs, &scalar_query_value);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }
    assert_eq!(
        (1, 1),
        (successes, not_comparable),
        "one result per query value and one arm each; a run that reached only one of the two arms \
         leaves the other arm's assertions unexecuted"
    );

    Ok(())
}

#[test]
fn test_operator_in_query_to_scalar_ok() -> crate::rules::Result<()> {
    let scalar_literal_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_literal = vec![QueryResult::Literal(Rc::new(scalar_literal_value.clone()))];
    let scalar_query_value = PathAwareValue::String((Path::root(), "*".to_string()));
    let scalar_query_list_value = PathAwareValue::List((
        Path::root(),
        vec![
            PathAwareValue::String((Path::new("/0".to_string(), 1, 2), "ec2*".to_string())),
            PathAwareValue::String((Path::new("/1".to_string(), 2, 2), "*".to_string())),
        ],
    ));
    let query_results = vec![
        QueryResult::Resolved(Rc::new(scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(scalar_query_list_value.clone())),
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
                assert_eq!(&*pair.rhs, &scalar_literal_value);
                assert!(matches!(&*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
                    if p.0.is_empty() {
                        assert_eq!(&*pair.lhs, &scalar_query_value);
                    } else {
                        assert_eq!(&p.0, "/1");
                        assert_eq!(v, "*");
                    }
                }
            }

            //
            // As "ec2*" in "*" FAILs
            //
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::Value(pair))) => {
                assert_eq!(&*pair.rhs, &scalar_literal_value);
                assert!(matches!(&*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
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
                assert_eq!(&*pair.lhs, &scalar_literal_value);
                assert_eq!(&*pair.rhs, &scalar_query_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(val))) => {
                assert_eq!(&*val.lhs, &scalar_literal_value);
                assert_eq!(&*val.rhs, &scalar_query_list_value);
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
    let scalar_literal = vec![QueryResult::Literal(Rc::new(scalar_literal_value.clone()))];
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
        QueryResult::Resolved(Rc::new(scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(scalar_query_list_value)),
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
                assert_eq!(&*pair.rhs, &scalar_literal_value);
                //
                // Expect all String values from the flattened list
                //
                assert!(matches!(&*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
                    match p.0.as_str() {
                        "" => {
                            assert_eq!(&*pair.lhs, &scalar_query_value);
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
    let scalar_literal = vec![QueryResult::Literal(Rc::new(scalar_literal_value.clone()))];
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
        traversed_to: Rc::new(unresolved_rhs_traversed_to),
        remaining_query: "Policy.Statements[*].Action".to_string(),
    };
    let query_results = vec![
        QueryResult::Resolved(Rc::new(scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(scalar_query_list_value)),
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
                assert_eq!(&*pair.rhs, &scalar_literal_value);
                //
                // Expect all String values from the flattened list
                //
                assert!(matches!(&*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
                    match p.0.as_str() {
                        "" => {
                            assert_eq!(&*pair.lhs, &scalar_query_value);
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
                assert_eq!(&*pair.rhs, &scalar_literal_value);
                //
                // Expect all String values from the flattened list
                //
                assert!(matches!(&&*pair.lhs, PathAwareValue::String(_)));
                if let PathAwareValue::String((p, v)) = &*pair.lhs {
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
        QueryResult::Resolved(Rc::new(lhs_scalar_value.clone())),
        QueryResult::Resolved(Rc::new(lhs_list_value.clone())),
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
        QueryResult::Resolved(Rc::new(rhs_scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(rhs_scalar_query_list_value.clone())),
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
                assert!(
                    lin.diff.is_empty(),
                    "a Success must carry an empty diff, got {:?}",
                    lin.diff
                );
                // The positive half. An empty diff is what "every value matched" and "no value was
                // compared" both look like, and the two `for` loops below iterate the operands, so an
                // empty `lhs` or `rhs` would run no assertion at all and leave that reading unchecked.
                assert_eq!(
                    (2, 2),
                    (lin.lhs.len(), lin.rhs.len()),
                    "both operands must carry their two values, or the empty diff above is the \
                     emptiness of a comparison that never ran and the loops below check nothing; got \
                     lhs {:?} rhs {:?}",
                    lin.lhs,
                    lin.rhs
                );
                for each in lin.lhs {
                    if each.is_scalar() {
                        assert_eq!(&*each, &lhs_scalar_value);
                    } else {
                        assert_eq!(&*each, &lhs_list_value);
                    }
                }

                for each in lin.rhs {
                    if each.is_scalar() {
                        assert_eq!(&*each, &rhs_scalar_query_value);
                    } else {
                        assert_eq!(&*each, &rhs_scalar_query_list_value);
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
    let rhs_query_results = vec![QueryResult::Resolved(Rc::new(
        rhs_scalar_query_list_value.clone(),
    ))];

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
                assert!(
                    qin.diff.is_empty(),
                    "a Success must carry an empty diff, got {:?}",
                    qin.diff
                );
                // The positive half, for the reason given on the first half of this test: with an empty
                // `lhs` the loop below runs no assertion, and an empty diff beside an empty operand is a
                // comparison that asked nothing rather than one every value satisfied.
                assert_eq!(
                    (2, 1),
                    (qin.lhs.len(), qin.rhs.len()),
                    "the two left-hand values against the one list; got lhs {:?} rhs {:?}",
                    qin.lhs,
                    qin.rhs
                );
                for each in qin.lhs {
                    if each.is_scalar() {
                        assert_eq!(&*each, &lhs_scalar_value);
                    } else {
                        assert_eq!(&*each, &lhs_list_value);
                    }
                }
                for each in qin.rhs {
                    assert_eq!(&*each, &rhs_scalar_query_list_value);
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
        traversed_to: Rc::new(unresolved_rhs_traversed_to),
        remaining_query: "Policy.Statements[*].Action".to_string(),
    };
    let lhs_query_results = vec![
        QueryResult::Resolved(Rc::new(lhs_scalar_value.clone())),
        QueryResult::Resolved(Rc::new(lhs_list_value.clone())),
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
        QueryResult::Resolved(Rc::new(rhs_scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(rhs_scalar_query_list_value.clone())),
    ];

    let eval = match CmpOperator::In.compare(&lhs_query_results, &rhs_query_results)? {
        EvalResult::Result(s) => s,
        _ => unreachable!(),
    };
    //
    // Expect 2 results, one LHS unresolved, one for the rest
    //
    assert_eq!(eval.len(), 2);
    // Counted, not just totalled. `eval.len() == 2` is satisfied by two `LhsUnresolved` results, which
    // would skip the Success arm entirely and leave the empty-diff claim in it unexecuted. The comment
    // above says one result of each kind is expected, so that is what is asserted.
    let mut successes = 0;
    let mut unresolved = 0;
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                successes += 1;
                assert!(
                    qin.diff.is_empty(),
                    "a Success must carry an empty diff, got {:?}",
                    qin.diff
                );
                assert_eq!(qin.rhs.len(), 2);
                assert_eq!(&*qin.rhs[0], &rhs_scalar_query_value);
                assert_eq!(&*qin.rhs[1], &rhs_scalar_query_list_value);
                assert_eq!(qin.lhs.len(), 2);
                assert_eq!(&*qin.lhs[0], &lhs_scalar_value);
                assert_eq!(&*qin.lhs[1], &lhs_list_value);
            }

            ValueEvalResult::LhsUnresolved(lhsur) => {
                unresolved += 1;
                assert_eq!(ur, lhsur);
            }

            rest => {
                println!("{:?}", rest);
                unreachable!()
            }
        }
    }
    assert_eq!(
        (1, 1),
        (successes, unresolved),
        "one Success and one unresolved left-hand result, or one of the two arms above checked nothing"
    );

    //
    // Just list
    //
    let rhs_query_results = vec![QueryResult::Resolved(Rc::new(
        rhs_scalar_query_list_value.clone(),
    ))];

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
                assert!(!qin.diff.is_empty());
                assert_eq!(qin.diff.len(), 1);
                assert_eq!(&*qin.diff[0], &lhs_scalar_value);
                assert_eq!(qin.rhs.len(), 1);
                assert_eq!(&*qin.rhs[0], &rhs_scalar_query_list_value);
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
                assert!(!qin.diff.is_empty());
                assert_eq!(qin.diff.len(), 1);
                assert_eq!(&*qin.diff[0], &lhs_list_value);
                assert_eq!(qin.rhs.len(), 1);
                assert_eq!(&*qin.rhs[0], &rhs_scalar_query_list_value);
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
    let lhs = QueryResult::Literal(Rc::new(lhs_value));
    let rhs_value = PathAwareValue::String((Path::root(), String::from("Environment")));
    let rhs = QueryResult::Resolved(Rc::new(rhs_value));
    match CmpOperator::In.compare(&[lhs], &[rhs]) {
        Ok(EvalResult::Result(result)) => {
            for each in result {
                match each {
                    ValueEvalResult::ComparisonResult(ComparisonResult::Fail(
                        Compare::QueryIn(QueryIn { diff, .. }),
                    )) => {
                        assert!(!diff.is_empty());
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
    let scalar_literal = vec![QueryResult::Literal(Rc::new(scalar_literal_value.clone()))];
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
        traversed_to: Rc::new(unresolved_rhs_traversed_to),
        remaining_query: "Policy.Statements[*].Action".to_string(),
    };
    let query_results = vec![
        QueryResult::Resolved(Rc::new(scalar_query_value.clone())),
        QueryResult::Resolved(Rc::new(scalar_query_list_value.clone())),
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
                assert_eq!(&*pair.lhs, &scalar_literal_value);
                assert_eq!(&*pair.rhs, &scalar_query_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(val))) => {
                assert_eq!(&*val.lhs, &scalar_literal_value);
                assert_eq!(&*val.rhs, &scalar_query_list_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::RhsUnresolved(inur, lhs)) => {
                assert_eq!(&*lhs, &scalar_literal_value);
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

/// `==` and `IN` between the same two queries, which do not answer the same way.
///
/// The left query selects `[10, 20, 30]` and `10`; the right selects `[10, 20, 30]`. `IN` is satisfied
/// because every left value has a match on the right -- the list against itself, and `10` inside the
/// list. `==` is not, because the scalar `10` and the list `[10, 20, 30]` are not equal values.
///
/// `==` used to report that as `Fail` and now reports `NotComparable`. The pairing that decides it is
/// `Int(10)` against `List([10, 20, 30])`, and `compare_eq` has no arm for it: this branch compares
/// whole values and does not decompose a list the way the literal-operand branches do. The verdict
/// was reached by `Vec::contains`, which is `PartialEq`, which has to turn an error it cannot report
/// into `false` -- so the clause failed for a reason no report ever named, and `!=` on the same two
/// queries passed at exit 0. The branch now asks the comparator directly and reports what comes back.
/// Both are a failing clause; only one of them says why.
#[test]
fn test_operator_eq_vs_in_from_queries() -> crate::rules::Result<()> {
    let custom =
        AccessQuery::try_from(r#"Resources[ Type == "Custom::Resource" ].Properties.ge"#)?.query;
    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: Rc::new(value),
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
    match eval_result {
        ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(nc)) => {
            // Named, not just typed: the reason has to identify the pair that could not be compared,
            // because the whole point of reporting it is that a reader can see which operand shapes
            // disagreed.
            assert!(
                nc.reason.contains("int") && nc.reason.contains("array"),
                "the refusal did not name the two kinds: {}",
                nc.reason
            );
        }
        rest => panic!("expected NotComparable, got {:?}", rest),
    }

    let result = (CmpOperator::In, false).compare(&lhs_answers, &rhs_answers)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    assert!(!result.iter().any(|r| matches!(
        r,
        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
    )));

    Ok(())
}

#[test]
fn test_operator_not_eq() -> crate::rules::Result<()> {
    let to_port = AccessQuery::try_from(
        r#"Resources[ Type == "AWS::EC2::SecurityGroupEgress" ].Properties.ToPort"#,
    )?;

    let from_port = AccessQuery::try_from(
        r#"Resources[ Type == "AWS::EC2::SecurityGroupEgress" ].Properties.FromPort"#,
    )?;

    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let resolved_to = evaluator.query(&to_port.query)?;
    assert_eq!(resolved_to.len(), 1);

    let resolved_from = evaluator.query(&from_port.query)?;
    assert_eq!(resolved_from.len(), 1);

    let result = match (CmpOperator::Eq, true).compare(&resolved_to, &resolved_from)? {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };

    assert_eq!(result.len(), 1);
    assert!(matches!(
        result[0],
        ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
    ));

    Ok(())
}

/// `!=` between a left operand carrying the root path and a document query, over values that are
/// comparable and unequal. Must pass.
///
/// `test_operator_not_eq` above cannot reach this: both its operands are document queries, so both
/// carry a path, `EqOperation` takes the left-hand diff and the negation wrapper's premise holds. The
/// case that broke is the one where the left operand's unmatched values are all unreportable -- every
/// `parse_int` / `parse_char` / `parse_string` result, and every rule parameter -- because
/// `EqOperation` then takes the *right-hand* diff for the report while the left still has unmatched
/// values, and the wrapper was reversing against that diff. `lhs \ rhs_unmatched` for two disjoint
/// operand sets is all of `lhs`, so `!=` failed.
///
/// Built from a hand-made `QueryResult::Resolved` rather than from a rules file, because that is what a
/// converter function produces: a bare `let x = 7` arrives as `QueryResult::Literal` and short circuits
/// through `is_literal` before any diff is computed, which is why the obvious fixture passes either way.
#[test]
fn not_eq_passes_for_an_unreportable_left_operand() -> crate::rules::Result<()> {
    let to_port = AccessQuery::try_from(
        r#"Resources[ Type == "AWS::EC2::SecurityGroupEgress" ].Properties.ToPort"#,
    )?;

    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    // ToPort is 56, and it carries a document path.
    let resolved_to = evaluator.query(&to_port.query)?;
    assert_eq!(resolved_to.len(), 1);

    // A function result: resolved, so it reaches the query-versus-query branch, but built with
    // `Path::root()`, so the reporter cannot place it.
    let rootless = |i: i64| {
        vec![QueryResult::Resolved(Rc::new(PathAwareValue::Int((
            Path::root(),
            i,
        ))))]
    };

    let unequal = rootless(7);
    let equal = rootless(56);

    // The defect: `7 != 56` must pass.
    let result = match (CmpOperator::Eq, true).compare(&unequal, &resolved_to)? {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    assert!(
        matches!(
            result[0],
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
        ),
        "!= must pass for two comparable, unequal values: {:?}",
        result[0]
    );

    // The polarity control: `56 != 56` must still fail. A fix that made the wrapper always succeed
    // would pass the assertion above and this one catches it.
    let result = match (CmpOperator::Eq, true).compare(&equal, &resolved_to)? {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    assert!(
        matches!(
            result[0],
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
        ),
        "!= must fail for two equal values: {:?}",
        result[0]
    );

    // The `==` control, which is also what pins the reporting choice the diff side exists for. `==` on
    // the unequal pair fails, the diff is taken from the right so that the finding names a value the
    // reader can place, and the diff holds that document value rather than the rootless one.
    let result = match (CmpOperator::Eq, false).compare(&unequal, &resolved_to)? {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 1);
    match &result[0] {
        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
            assert_eq!(qin.diff_from, DiffFrom::Rhs);
            assert_eq!(qin.diff.len(), 1);
            assert_eq!(&*qin.diff[0], &PathAwareValue::Int((Path::root(), 56)));
            assert!(
                !qin.diff[0].self_path().0.is_empty(),
                "the reported value must be one the reporter can place"
            );
            // And the left operand's unmatched value is carried alongside, which is what the negation
            // above reversed against.
            assert_eq!(qin.lhs_unmatched.len(), 1);
            assert_eq!(
                &*qin.lhs_unmatched[0],
                &PathAwareValue::Int((Path::root(), 7))
            );
        }
        other => panic!("== must fail with a query-versus-query diff: {:?}", other),
    }

    Ok(())
}

/// A query-versus-query `==` that both fails on several values and hits a pairing it cannot answer
/// reports every failing value, and the pairing it names is one that actually failed.
///
/// Two separate defects, both from the arm that returned the refusal *instead of* the diff:
///
/// 1. Every other unmatched value went with the discarded diff. Over `[1, 5]` against `["p", "q"]` both
///    left values fail and the report named one, so a template with N offending properties took N runs
///    to fix.
/// 2. The refusal recorded the first error seen anywhere in either sweep, including one hit on the way
///    to a match found afterwards. That pairing decided nothing, and naming it points a reader at the
///    wrong operand.
///
/// The single-value case is asserted too, because it is the common one and it must not gain a second
/// entry saying the same thing about the same property.
#[test]
fn a_refused_pairing_does_not_swallow_the_rest_of_the_diff() -> crate::rules::Result<()> {
    fn at(path: &str, v: PathAwareValue) -> QueryResult {
        // A document path, so `placeable` holds and the diff is taken from the left.
        let placed = match v {
            PathAwareValue::Int((_, i)) => {
                PathAwareValue::Int((Path::new(path.to_string(), 1, 1), i))
            }
            PathAwareValue::String((_, s)) => {
                PathAwareValue::String((Path::new(path.to_string(), 1, 1), s))
            }
            other => other,
        };
        QueryResult::Resolved(Rc::new(placed))
    }
    fn int(i: i64) -> PathAwareValue {
        PathAwareValue::Int((Path::root(), i))
    }
    fn string(s: &str) -> PathAwareValue {
        PathAwareValue::String((Path::root(), s.to_string()))
    }
    fn results(lhs: &[QueryResult], rhs: &[QueryResult]) -> Vec<ValueEvalResult> {
        match (CmpOperator::Eq, false).compare(lhs, rhs).unwrap() {
            EvalResult::Result(v) => v,
            other => panic!("expected a per-value result: {:?}", other),
        }
    }

    // Defect 1: two failing left values, every pairing incomparable.
    let lhs = [at("/A1/V", int(1)), at("/A2/V", int(5))];
    let rhs = [at("/C1/V", string("p")), at("/C2/V", string("q"))];
    let got = results(&lhs, &rhs);

    let refusals = got
        .iter()
        .filter(|r| {
            matches!(
                r,
                ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(_))
            )
        })
        .count();
    assert_eq!(refusals, 1, "the refusal is still reported: {:?}", got);

    let diffs = got
        .iter()
        .filter_map(|r| match r {
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                Some(qin)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(diffs.len(), 1, "and the diff beside it: {:?}", got);
    assert_eq!(
        diffs[0].diff.len(),
        2,
        "both failing values must be named, not just the one the refusal is about"
    );
    let named = diffs[0]
        .diff
        .iter()
        .map(|v| v.self_path().0.clone())
        .collect::<Vec<_>>();
    assert!(
        named.contains(&"/A1/V".to_string()) && named.contains(&"/A2/V".to_string()),
        "expected both properties, got {:?}",
        named
    );

    // Defect 2: the left value hits an incomparable pairing against "x" and then matches against 1, so
    // the refusal decided nothing. The clause still fails, on the right-hand extra. The pairing named
    // must be about "x", the value with no equal -- not about the left value that matched.
    let lhs = [at("/A1/V", int(1))];
    let rhs = [at("/B1/V", string("x")), at("/B2/V", int(1))];
    let got = results(&lhs, &rhs);
    let named = got
        .iter()
        .filter_map(|r| match r {
            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(nc)) => {
                Some(nc.pair.lhs.self_path().0.clone())
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        named,
        vec!["/B1/V".to_string()],
        "the refusal must be about the value that found no equal, not one that matched: {:?}",
        got
    );

    // The single-value case: one failing value, and the refusal already names it. One result, not two.
    let lhs = [at("/A1/V", int(1))];
    let rhs = [at("/C1/V", string("p"))];
    let got = results(&lhs, &rhs);
    assert_eq!(
        got.len(),
        1,
        "a refusal that already names the only failing value must not be doubled: {:?}",
        got
    );
    assert!(matches!(
        got[0],
        ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(_))
    ));

    // Polarity: a refusal fails `!=` as well. Inverting it would let a denylist admit a value it could
    // not compare, which is the exit-0-with-nothing-in-the-report defect.
    let negated = match (CmpOperator::Eq, true).compare(&lhs, &rhs)? {
        EvalResult::Result(v) => v,
        other => panic!("expected a per-value result: {:?}", other),
    };
    assert!(
        negated.iter().any(|r| matches!(
            r,
            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(_))
        )),
        "!= must refuse rather than pass: {:?}",
        negated
    );
    assert!(
        !negated.iter().any(|r| matches!(
            r,
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
        )),
        "!= must not report a success for a pair it could not compare: {:?}",
        negated
    );

    Ok(())
}

/// Every `ListIn` carried by a Success holds an empty diff.
///
/// Why this exists. The negation wrapper has two `ListIn` arms that compute "which elements" two
/// different ways. The Fail arm calls `matched_elements`, which keeps the elements *absent* from the
/// diff. The Success arm has its own loop and keeps *all* elements, because a Success means the whole
/// list matched and every element is what `NOT IN` has to report. Those are different questions, and
/// they return the same answer only while every Success path constructs an empty diff -- with an empty
/// diff, "absent from the diff" is "all of them". Nothing in the type system says the diff is empty
/// there; it is a property of the two construction sites, which is what this test pins.
///
/// The two sites are both in `contained_in`'s list-valued left-hand arm. The nested-right-hand branch
/// passes `vec![]` literally, and the all-flat branch passes a `diff` it has just tested
/// `is_empty()`. A third Success path, or either of these two starting to carry the values that
/// matched, would silently make the Success arm over-report: it would name only the matched elements
/// where it means to name all of them, and `NOT IN`'s finding would understate which values collide.
///
/// What was tried and rejected. Substituting `matched_elements` into the Success arm removes the
/// duplication and is byte-identical today across a 76-case CLI oracle, a 441-clause oracle, 1302
/// monotonicity pairs and the full suite. It was rejected deliberately: a helper answering "matched"
/// standing where "all" is meant is correct only under this invariant, so the substitution converts a
/// visible divergence between two loops into an invisible dependency on an unstated property. Pinning
/// the property and leaving the loops distinct keeps the failure loud.
///
/// Constraints. This is an input-driven test, so it pins the invariant for the shapes below rather
/// than proving it for all inputs. It covers both construction sites and every distinct reason for
/// reaching them: whole-list membership in either operand order, flat subset with and without a
/// nested right-hand element, an element matched at depth, an element matched by a range rather than
/// by equality, and the empty left-hand list in both of its arms. A genuinely new Success path added
/// without a cell here would not be caught, which is why the failure message names the sites.
///
/// The `assert!` on `successes` is load-bearing. Without it a matrix that stopped producing Success
/// results -- a shape change, a parse failure, an operand pair that starts failing -- would satisfy
/// every remaining assertion vacuously and report green while checking nothing.
#[test]
fn a_successful_list_containment_carries_an_empty_diff() -> crate::rules::Result<()> {
    fn value(json: &str) -> crate::rules::Result<Rc<PathAwareValue>> {
        Ok(Rc::new(PathAwareValue::try_from(json)?))
    }

    // A range cannot be spelled in a document, so it is built directly. `[85] IN [r[80,90]]` succeeds
    // through `is_one_of`'s `compare_eq` call rather than through `PartialEq`, which is a separate
    // route to the same construction site.
    let range = Rc::new(PathAwareValue::List((
        Path::root(),
        vec![PathAwareValue::RangeInt((
            Path::root(),
            crate::rules::values::RangeType {
                lower: 80,
                upper: 90,
                inclusive: crate::rules::values::LOWER_INCLUSIVE
                    | crate::rules::values::UPPER_INCLUSIVE,
            },
        ))],
    )));

    let mut cases: Vec<(String, Rc<PathAwareValue>, Rc<PathAwareValue>)> = vec![];
    for (why, lhs, rhs) in [
        (
            "flat subset, no nested right-hand element",
            "[1,2]",
            "[1,2,3]",
        ),
        (
            "flat subset beside a nested right-hand element",
            "[1,2]",
            "[1,2,[9]]",
        ),
        (
            "whole-list membership, nested element last",
            "[1,2]",
            "[\"zzz\",[1,2]]",
        ),
        (
            "whole-list membership, nested element first",
            "[1,2]",
            "[[1,2],\"zzz\"]",
        ),
        (
            "every element matched, one of them nested",
            "[1,[9]]",
            "[1,[9]]",
        ),
        ("element matched at depth", "[[\"a\"]]", "[[\"a\"]]"),
        ("whole-list membership at depth", "[[\"a\"]]", "[[[\"a\"]]]"),
        ("empty left-hand list, all-flat branch", "[]", "[1,2,3]"),
        // Two routes to Success now, and the label names the one no longer taken. `[]` is a
        // whole-list member of `[1,2,3,[]]`, which is why this cell was written; since the
        // `is_empty` guard came off `flat_subset` the vacuous subset reading also holds, and it is
        // the left operand of the `||` so it decides first. Both construct `vec![]`, so the
        // invariant this test pins is unaffected either way -- kept as a cell that reaches the
        // nested-right-hand site by whichever route survives a change to the other.
        (
            "empty left-hand list is a member of the right",
            "[]",
            "[1,2,3,[]]",
        ),
    ] {
        cases.push((why.to_string(), value(lhs)?, value(rhs)?));
    }
    cases.push((
        "element matched by a range rather than by equality".to_string(),
        value("[85]")?,
        Rc::clone(&range),
    ));

    let mut successes = 0;
    for (why, lhs, rhs) in &cases {
        let lhs_len = match &**lhs {
            PathAwareValue::List((_, l)) => l.len(),
            other => panic!("{}: the left operand must be a list, got {:?}", why, other),
        };
        match contained_in(Rc::clone(lhs), Rc::clone(rhs)) {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ListIn(lin))) => {
                successes += 1;
                assert!(
                    lin.diff.is_empty(),
                    "{}: a Success must carry an empty diff, got {:?}. The construction sites are \
                     `contained_in`'s two Success arms -- the nested-right-hand branch passing \
                     `vec![]` and the all-flat branch passing an `is_empty()` diff. The negation \
                     wrapper's Success arm keeps ALL elements while its Fail arm keeps only the \
                     matched ones, and those agree only while this holds.",
                    why,
                    lin.diff
                );
                assert_eq!(
                    matched_elements(&lin).len(),
                    lhs_len,
                    "{}: with an empty diff every element reads as matched, which is what lets the \
                     Success arm's own loop and `matched_elements` agree",
                    why
                );
            }
            other => panic!(
                "{}: expected a successful list containment, got {:?}",
                why, other
            ),
        }
    }

    assert_eq!(
        successes,
        cases.len(),
        "every cell must reach a Success, or the assertions above are vacuous"
    );
    assert!(
        successes >= 10,
        "the matrix must exercise both construction sites, got {} cells",
        successes
    );

    Ok(())
}

/// Which arms of `InOperation::compare` decompose a list-valued left-hand operand into elements.
///
/// The condition `incomparable_membership`'s `(List, right)` element loop is gated on, asserted here
/// rather than only through the predicate because one of the four arms is not separable there: under
/// `(None, None)` the shape refusal further down that same match arm sets `refused` for every
/// non-empty left-hand list, and the loop body never runs for an empty one, so a predicate-level cell
/// asserting `true` for that arm is satisfied whether the gate admits it or not. Asked of the helper,
/// all four arms are visible.
///
/// # The cells, and what each one rules out
///
/// Cells 2 and 3 are the same two operand KINDS -- a queried list-valued left-hand side, a `String`
/// right-hand side -- reached through arms that disagree. `(None, Some)` expands the left-hand list
/// into one `string_in` per element, so the elements are paired; `(Some, Some)` hands the whole pair
/// to `substring_or_contained_in`, so they are not. A condition written in terms of the operand kinds
/// alone cannot answer both, which is why this is asked of `is_literal` and not of the values.
///
/// Cells 4 and 5 split the `(Some, None)` arm on the branch it takes: with no list among the
/// right-hand values it builds an element-wise `Vec::contains` diff, and with one it calls
/// `substring_or_contained_in` on the whole value. Cell 5 carries a `String` right-hand value on
/// purpose -- a gate spelled `both_queried || matches!(right, String(_))` answers `true` here and is
/// wrong, and cell 4 is where that same gate answers `false` and is wrong the other way.
#[test]
fn element_pairings_are_built_only_by_the_arms_that_decompose() {
    fn int(path: &str, value: i64) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::Int((
            Path::new(path.to_string(), 0, 0),
            value,
        )))
    }

    fn string(path: &str, value: &str) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::String((
            Path::new(path.to_string(), 0, 0),
            value.to_string(),
        )))
    }

    fn list(path: &str, elements: Vec<Rc<PathAwareValue>>) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::List((
            Path::new(path.to_string(), 0, 0),
            elements.into_iter().map(|e| (*e).clone()).collect(),
        )))
    }

    let queried_lhs = vec![
        QueryResult::Resolved(list("/L/0", vec![int("/L/0/0", 7)])),
        QueryResult::Resolved(string("/L/1", "zz")),
    ];
    let literal_lhs = vec![QueryResult::Literal(list("/lit", vec![int("/lit/0", 7)]))];

    let both_queried = element_pairings_built(
        &queried_lhs,
        &[QueryResult::Resolved(int("/D/0", 5))],
        &PathAwareValue::Int((Path::new("/D/0".to_string(), 0, 0), 5)),
    );

    let literal_string_right = element_pairings_built(
        &queried_lhs,
        &[QueryResult::Literal(string("/lit", "abc"))],
        &PathAwareValue::String((Path::new("/lit".to_string(), 0, 0), "abc".to_string())),
    );

    let literal_int_right = element_pairings_built(
        &queried_lhs,
        &[QueryResult::Literal(int("/lit", 5))],
        &PathAwareValue::Int((Path::new("/lit".to_string(), 0, 0), 5)),
    );

    let literal_lhs_flat_rhs = element_pairings_built(
        &literal_lhs,
        &[QueryResult::Resolved(int("/D/0", 7))],
        &PathAwareValue::Int((Path::new("/D/0".to_string(), 0, 0), 7)),
    );

    let literal_lhs_nested_rhs = element_pairings_built(
        &literal_lhs,
        &[
            QueryResult::Resolved(list("/D/0", vec![int("/D/0/0", 7)])),
            QueryResult::Resolved(string("/D/1", "a")),
        ],
        &PathAwareValue::String((Path::new("/D/1".to_string(), 0, 0), "a".to_string())),
    );

    let both_literal = element_pairings_built(
        &literal_lhs,
        &[QueryResult::Literal(string("/lit", "abc"))],
        &PathAwareValue::String((Path::new("/lit".to_string(), 0, 0), "abc".to_string())),
    );

    assert_eq!(
        (true, true, false, true, false, false),
        (
            both_queried,
            literal_string_right,
            literal_int_right,
            literal_lhs_flat_rhs,
            literal_lhs_nested_rhs,
            both_literal
        ),
        "1 `(None, None)` asks `is_one_of` per left-hand element. 2 `(None, Some)` against a \
         `String` expands the left-hand list into one `string_in` per element. 3 every other \
         right-hand kind reaches `contained_in` with the value whole, which dispatches on the left \
         value and answers `NotComparable` on the two WHOLE values -- no element pairing exists. \
         4 `(Some, None)` with no list among the right-hand values builds an element-wise \
         `Vec::contains` diff, so a refusal there IS read as \"not a member\". 5 the same arm with a \
         list among them calls `substring_or_contained_in` on the whole value instead; this cell \
         carries a `String` right-hand value, so a gate keyed on the right operand's kind reddens \
         here. 6 `(Some, Some)` never decomposes -- same two operand kinds as cell 2, opposite \
         answer, so the condition cannot be written in terms of the values"
    );
}
