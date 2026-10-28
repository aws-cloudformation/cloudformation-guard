use super::*;
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::exprs::AccessQuery;
use crate::rules::EvalContext;
use pretty_assertions::assert_eq;
use std::convert::TryFrom;

/// `QueryIn::rhs_unmatched` tells "never computed" (`None`) from "computed, every resolved right-hand
/// value matched" (`Some(empty)`): the constructors every `IN` spelling and the negation wrapper build
/// from leave it `None`, the equality operator's two-query arm records `Some` through `from_rhs` or
/// `with_rhs_unmatched`, and the wrapper carries whatever it was handed. The one reader, `eval.rs`'s
/// equality pre-pass beside an undecidable marker, treats `Some(empty)` as "the resolved values may still
/// leave the sets equal" and `None` as a decided `Fail`; one `Vec` for both would read an uncomputed set as
/// a matched one.
#[test]
fn a_query_in_tells_an_uncomputed_right_hand_mismatch_set_from_an_empty_one() {
    let value = |text: &str| Rc::new(PathAwareValue::try_from(text).unwrap());
    let (a, b) = (value("'a'"), value("'b'"));
    let ordinary = QueryIn::new(
        vec![Rc::clone(&a)],
        vec![Rc::clone(&a)],
        vec![Rc::clone(&b)],
    );
    assert_eq!(
        None, ordinary.rhs_unmatched,
        "`new` records no right-hand mismatch set"
    );
    let partly = QueryIn::partly_matched(
        vec![Rc::clone(&a)],
        vec![],
        vec![Rc::clone(&a)],
        vec![Rc::clone(&b)],
    );
    assert_eq!(
        None, partly.rhs_unmatched,
        "`partly_matched` records none either"
    );
    let computed_empty = QueryIn::new(vec![], vec![Rc::clone(&a)], vec![Rc::clone(&a)])
        .with_rhs_unmatched(Some(vec![]));
    assert_eq!(
        Some(vec![]),
        computed_empty.rhs_unmatched,
        "the equality arm's `with_rhs_unmatched(Some(..))` records a computed, empty set"
    );
    let from_rhs = QueryIn::from_rhs(
        vec![Rc::clone(&b)],
        vec![],
        vec![Rc::clone(&a)],
        vec![Rc::clone(&a), Rc::clone(&b)],
    );
    assert_eq!(
        Some(vec![Rc::clone(&b)]),
        from_rhs.rhs_unmatched,
        "`from_rhs` records the right-hand diff as the computed set"
    );
    let carried = QueryIn::new(vec![], vec![Rc::clone(&a)], vec![Rc::clone(&a)])
        .with_rhs_unmatched(from_rhs.rhs_unmatched.clone());
    assert_eq!(
        from_rhs.rhs_unmatched, carried.rhs_unmatched,
        "the negation wrapper's pass-through keeps what it was handed"
    );
}

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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
    // The document value is still the pair's subject with the literal on the left: a rule literal has
    // no path to file a finding against, so the arm names the value from the document as `lhs` and the
    // literal as what it was compared with, exactly as in the forward direction above.
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
                assert!(matches!(&*pair.lhs, PathAwareValue::String(_)));
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
        kind: crate::rules::UnResolvedKind::Absent,
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
    // Expect one result per left-hand value: both matched, each is its own Success.
    //
    assert_eq!(eval.len(), 2);
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
                    (1, 2),
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
    // Expect one Success per left-hand value
    //
    assert_eq!(eval.len(), 2);
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
                    (1, 1),
                    (qin.lhs.len(), qin.rhs.len()),
                    "one left-hand value against the one list; got lhs {:?} rhs {:?}",
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
        kind: crate::rules::UnResolvedKind::Absent,
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
    // Expect 3 results, one LHS unresolved, one Success per resolved left-hand value
    //
    assert_eq!(eval.len(), 3);
    // Counted, not just totalled. `eval.len() == 3` is satisfied by three `LhsUnresolved` results, which
    // would skip the Success arm entirely and leave the empty-diff claim in it unexecuted. The comment
    // above says how many of each kind are expected, so that is what is asserted.
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
                // One left-hand value per result, in the order the values were resolved.
                assert_eq!(qin.lhs.len(), 1);
                if successes == 1 {
                    assert_eq!(&*qin.lhs[0], &lhs_scalar_value);
                } else {
                    assert_eq!(&*qin.lhs[0], &lhs_list_value);
                }
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
        (2, 1),
        (successes, unresolved),
        "one Success per resolved left-hand value and one unresolved left-hand result, or one of the \
         two arms above checked nothing"
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
    // Expect 3 results: the unresolved value, the scalar's own Fail, the list's own Success
    //
    assert_eq!(eval.len(), 3);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                assert!(!qin.diff.is_empty());
                assert_eq!(qin.diff.len(), 1);
                assert_eq!(&*qin.diff[0], &lhs_scalar_value);
                assert_eq!(qin.rhs.len(), 1);
                assert_eq!(&*qin.rhs[0], &rhs_scalar_query_list_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                assert_eq!(qin.lhs.len(), 1);
                assert_eq!(&*qin.lhs[0], &lhs_list_value);
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
    // Expect 3 results: the unresolved value, the scalar's own Success (not in the list), the list's
    // own Fail (it is in the list)
    //
    assert_eq!(eval.len(), 3);
    for each in eval {
        match each {
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                assert!(!qin.diff.is_empty());
                assert_eq!(qin.diff.len(), 1);
                assert_eq!(&*qin.diff[0], &lhs_list_value);
                assert_eq!(qin.rhs.len(), 1);
                assert_eq!(&*qin.rhs[0], &rhs_scalar_query_list_value);
            }

            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                assert_eq!(qin.lhs.len(), 1);
                assert_eq!(&*qin.lhs[0], &lhs_scalar_value);
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
            // One aggregate result for the whole literal list, and it has to be there. A `for`
            // over `result` with no count beside it ran zero times when the operator answered
            // nothing at all, and the test stayed green while `in` reported no verdict.
            assert_eq!(
                result.len(),
                1,
                "a literal list against one scalar is one aggregate verdict, got {:?}",
                result
            );
            match &result[0] {
                ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(
                    QueryIn { diff, .. },
                ))) => {
                    // The element-wise verdict: `Environment` is on the right, `Name` is not,
                    // so the diff names exactly `Name`.
                    let unmatched = diff
                        .iter()
                        .map(|value| match &**value {
                            PathAwareValue::String((_, s)) => s.as_str(),
                            other => panic!("diff holds a non-string {:?}", other),
                        })
                        .collect::<Vec<_>>();
                    assert_eq!(unmatched, vec!["Name"]);
                }
                other => panic!("expected Fail(QueryIn), got {:?}", other),
            }
        }
        other => panic!("expected EvalResult::Result, got {:?}", other),
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
        kind: crate::rules::UnResolvedKind::Absent,
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
/// `==` reports that as `NotComparable`, not `Fail`. The pairing that decides it is
/// `Int(10)` against `List([10, 20, 30])`, and `compare_eq` has no arm for it: this branch compares
/// whole values and does not decompose a list the way the literal-operand branches do. A verdict
/// reached through `Vec::contains`, which is `PartialEq`, would have to turn an error it cannot report
/// into `false` -- the clause would fail for a reason no report ever named, and `!=` on the same two
/// queries would pass at exit 0. The branch asks the comparator directly and reports what comes back.
/// Both are a failing clause; only one of them says why.
#[test]
fn test_operator_eq_vs_in_from_queries() -> crate::rules::Result<()> {
    let custom =
        AccessQuery::try_from(r#"Resources[ Type == "Custom::Resource" ].Properties.ge"#)?.query;
    let value = PathAwareValue::try_from(crate::rules::values::read_from(RESOURCES)?)?;
    let mut evaluator = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
    };
    let lhs_answers = evaluator.query(&custom)?;
    let custom_data =
        AccessQuery::try_from(r#"Resources[ Type == "Custom::Data" ].Properties.ge"#)?.query;
    let rhs_answers = evaluator.query(&custom_data)?;
    // Two left-hand values: the list `[10, 20, 30]`, equal to the right-hand one, and the `10`, which
    // cannot be compared with a list and is the only unmatched value. The refusal is one result and
    // the matched value's PASS is the other.
    let result = (CmpOperator::Eq, false).compare(&lhs_answers, &rhs_answers)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    assert_eq!(result.len(), 2);
    let refusal = result.iter().find_map(|r| match r {
        ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(nc)) => Some(nc),
        _ => None,
    });
    match refusal {
        Some(nc) => {
            // Named, not just typed: the reason has to identify the pair that could not be compared,
            // because the whole point of reporting it is that a reader can see which operand shapes
            // disagreed.
            assert!(
                nc.reason.contains("int") && nc.reason.contains("array"),
                "the refusal did not name the two kinds: {}",
                nc.reason
            );
        }
        None => panic!("expected a NotComparable among {:?}", result),
    }
    assert!(result.iter().any(|r| matches!(
        r,
        ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin)))
            if qin.accepted.len() == 1 && qin.accepted[0].is_list()
    )));

    // Under `IN` both left-hand values are members of the right-hand set -- the list as a whole, and
    // `10` as one of its elements. The two-query arm answers one result per left-hand value, so each
    // is its own `Success` carrying that one value as accepted.
    let result = (CmpOperator::In, false).compare(&lhs_answers, &rhs_answers)?;
    let result = match result {
        EvalResult::Result(v) => v,
        _ => unreachable!(),
    };
    // One result per left-hand value (`Custom::Resource` has two), each a Success.
    assert_eq!(result.len(), 2);
    assert!(!result.iter().any(|r| matches!(
        r,
        ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_))
    )));
    assert!(result.iter().all(|r| matches!(
        r,
        ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin)))
            if qin.accepted.len() == 1 && qin.accepted == qin.lhs
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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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
        refusal_frames: crate::rules::eval_context::RefusalFrames::default(),
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

    // Defect 1: two failing left values, every pairing incomparable. Each is named by its own refusal,
    // since a value the operator could not compare is refused rather than unmatched, and nothing was
    // compared, so there is no diff to report beside them.
    let lhs = [at("/A1/V", int(1)), at("/A2/V", int(5))];
    let rhs = [at("/C1/V", string("p")), at("/C2/V", string("q"))];
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
        named.len(),
        2,
        "one refusal per failing value, each about its own property: {:?}",
        got
    );
    assert!(
        named.contains(&"/A1/V".to_string()) && named.contains(&"/A2/V".to_string()),
        "expected both properties, got {:?}",
        named
    );
    assert_eq!(
        got.len(),
        2,
        "nothing was compared, so the refusals are the whole report: {:?}",
        got
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

/// The query-vs-query arm, told that the right-hand query enumerates a collection, reads its results as
/// one entry set and asks membership of it, which is what the written-out list asks; told that it does
/// not, it keeps containment of each resolved string.
///
/// `Allowed.Types[*]` over `["gp2", "gp3"]` arrives here as two resolved strings, the same two values
/// `Parameters.A.Default` and `Parameters.B.Default` would deliver, so nothing in the values says which
/// was written. `InOperation::rhs_enumerates` is the only thing that does, and the cells below are the
/// two readings of one value set, asked through the entry `binary_operation` uses: with it, `gp` and
/// `""` are unmatched because neither IS an entry; without it, both are contained in `gp2` and matched.
///
/// The entry set is one set and not one entry at a time. A list on the left is a subset question
/// against it -- `[gp2, gp3]` is in `Types[*]` the way it is in `["gp2", "gp3"]`, and one stranger
/// fails -- which a per-entry reading could never answer, since a list against one string is not
/// comparable. The empty list is not a vacuous subset: it is an empty collection, answered as the
/// retrieval error it is before any subset question, so it fails `IN` and `NOT IN` alike, in both
/// spellings, exactly as the written-out list answers it (`ValueEvalResult::EmptyCollection`).
#[test]
fn in_over_an_enumerating_query_is_membership_not_containment() {
    fn string(path: &str, value: &str) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::String((
            Path::new(path.to_string(), 0, 0),
            value.to_string(),
        )))
    }

    fn list(path: &str, elements: &[&str]) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::List((
            Path::new(path.to_string(), 0, 0),
            elements
                .iter()
                .enumerate()
                .map(|(index, element)| {
                    PathAwareValue::String((
                        Path::new(format!("{path}/{index}"), 0, 0),
                        element.to_string(),
                    ))
                })
                .collect(),
        )))
    }

    fn resolved(values: &[Rc<PathAwareValue>]) -> Vec<QueryResult> {
        values
            .iter()
            .map(|value| QueryResult::Resolved(Rc::clone(value)))
            .collect()
    }

    // Whether the clause passes for this one left-hand value: every result the entry hands back is a
    // Success. `not_in` selects the polarity, through the same wrapper `binary_operation` uses. Asked
    // of the verdict rather than of the result's shape, because the two readings answer in different
    // shapes -- the entry set hands back one `contained_in` result per value, as the written-out list
    // does, and the pairing loop one aggregate `QueryIn` -- and the verdict is what a rule sees.
    fn passes(
        not_in: bool,
        lhs: &Rc<PathAwareValue>,
        rhs: &[QueryResult],
        rhs_enumerates: RhsEnumeration,
    ) -> bool {
        let lhs = resolved(&[Rc::clone(lhs)]);
        match (InOperation::shaped(rhs_enumerates, rhs), not_in)
            .compare(&lhs, rhs)
            .unwrap()
        {
            EvalResult::Result(results) => {
                assert!(
                    !results.is_empty(),
                    "one left-hand value against a non-empty right-hand side yields at least one result"
                );
                results.iter().all(|result| {
                    matches!(
                        result,
                        ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
                    )
                })
            }
            _ => panic!("the query-vs-query arm answers with a result vector"),
        }
    }

    let allowed = resolved(&[string("/Allowed/0", "gp2"), string("/Allowed/1", "gp3")]);
    let gp = string("/V/VolumeType", "gp");
    let empty = string("/V/VolumeType", "");
    let gp2 = string("/V/VolumeType", "gp2");
    let io1 = string("/V/VolumeType", "io1");

    let denied = resolved(&[string("/Denied/0", "ssh")]);
    let s = string("/R/Protocol", "s");

    let haystack = resolved(&[string("/Allowed/Default", "production-bucket")]);
    let bucket = string("/B/Name", "bucket");

    let entries = RhsEnumeration::LastPart;
    let names = RhsEnumeration::Names;
    let members = RhsEnumeration::EarlierPart;

    assert_eq!(
        (false, false, true, false, false, false),
        (
            passes(false, &gp, &allowed, entries),
            passes(false, &empty, &allowed, entries),
            passes(false, &gp2, &allowed, entries),
            passes(false, &io1, &allowed, entries),
            passes(false, &s, &denied, entries),
            passes(false, &bucket, &haystack, entries),
        ),
        "an enumerating right-hand query is an entry set: a strict substring of an entry, the empty \
         string and a stranger are all out, and only an equal value is in"
    );

    assert_eq!(
        (true, true, true, false, true, true),
        (
            passes(false, &gp, &allowed, names),
            passes(false, &empty, &allowed, names),
            passes(false, &gp2, &allowed, names),
            passes(false, &io1, &allowed, names),
            passes(false, &s, &denied, names),
            passes(false, &bucket, &haystack, names),
        ),
        "a right-hand query that does not enumerate keeps containment: each resolved string is a \
         haystack, so a substring of one is in and only a stranger is out"
    );

    // `NOT IN` over the same scalars: the negation of each cell above, in both readings.
    assert_eq!(
        (true, true, false, false),
        (
            passes(true, &gp, &allowed, entries),
            passes(true, &s, &denied, entries),
            passes(true, &gp, &allowed, names),
            passes(true, &s, &denied, names),
        ),
        "`NOT IN` admits a substring of an entry when the query enumerates and denies it when the query \
         names a haystack, as `NOT IN [\"ssh\"]` and `NOT IN \"ssh\"` do"
    );

    // A list on the left, against the set as a whole.
    let both_allowed = list("/V/VolumeTypes", &["gp2", "gp3"]);
    let one_stranger = list("/V/VolumeTypes", &["gp2", "io1"]);
    let only_strangers = list("/V/VolumeTypes", &["io1"]);
    let nothing = list("/V/VolumeTypes", &[]);
    assert_eq!(
        (true, false, false, false, false, false, true, false),
        (
            passes(false, &both_allowed, &allowed, entries),
            passes(false, &one_stranger, &allowed, entries),
            passes(false, &only_strangers, &allowed, entries),
            passes(false, &nothing, &allowed, entries),
            passes(true, &both_allowed, &allowed, entries),
            passes(true, &one_stranger, &allowed, entries),
            passes(true, &only_strangers, &allowed, entries),
            passes(true, &nothing, &allowed, entries),
        ),
        "a list on the left is a subset question against the entry set: every element allowed is in; a \
         list holding one stranger is out, and still collides for `NOT IN` through the entry it holds; \
         a list of strangers alone is out and collides with nothing, so `NOT IN` passes it; and the \
         empty list is an empty collection, which fails both polarities as it does against the \
         written-out list"
    );

    // A list each enumerated member holds, `Resources.*[ .. ].Properties.AllowedTypes` resolving to the
    // one list each policy holds. For a scalar on the left the members are the set under BOTH shapes: a
    // scalar is never a member of a list, so the lists the enumeration handed back can only be lists of
    // candidates for it, and `VolumeType IN Mappings.TypesByRegion.*` over `{useast1: [gp2], uswest2:
    // [gp3]}` (a last-part enumeration) admits `gp2` as `IN Resources.*[ .. ].Properties.AllowedTypes`
    // (an earlier-part one) does, and `NOT IN` denies it in both; read as one entry the scalar met a list,
    // was out of `IN`, and `NOT IN` admitted the value the list names. A list on the left is NOT read
    // against the pool: `[gp2, gp3]` is a subset of neither policy's own list and is out.
    let policy_list = resolved(&[list("/Policy/AllowedTypes", &["gp2", "gp3"])]);
    let two_policies = resolved(&[
        list("/P1/AllowedTypes", &["gp2"]),
        list("/P2/AllowedTypes", &["gp3"]),
    ]);
    assert_eq!(
        (true, false, false, true, false, true, true, true, false, false, true),
        (
            passes(false, &gp2, &policy_list, members),
            passes(false, &io1, &policy_list, members),
            passes(true, &gp2, &policy_list, members),
            passes(true, &io1, &policy_list, members),
            passes(false, &both_allowed, &two_policies, members),
            passes(false, &both_allowed, &policy_list, members),
            passes(false, &gp2, &policy_list, entries),
            passes(false, &gp2, &two_policies, entries),
            passes(false, &io1, &two_policies, entries),
            passes(true, &gp2, &two_policies, entries),
            passes(true, &io1, &two_policies, entries),
        ),
        "a list-valued result contributes its members for a scalar on the left under both shapes: `gp2` \
         is in and `io1` out, `NOT IN` denies `gp2` and admits `io1`; a list on the left is a subset of \
         one policy's list or of none, never of their pool"
    );

    // Scalar results under an earlier-part enumeration are pooled into one set for a list on the left,
    // because a projection of scalars is the written-out list of them: two policies whose `AllowedTypes`
    // are the scalars `gp2` and `gp3` spell out `[gp2, gp3]`, and `[gp2, gp3]` is a subset of it. Two
    // policies holding the lists `[gp2]` and `[gp3]` keep the per-result reading (a subset of neither),
    // and a scalar `gp2` beside a list `[gp3]` is the pool `[gp2]` beside the set `[gp3]`, a subset of
    // neither, as `IN [gp2, [gp3]]` refuses it. `[gp2]` is a subset of one set in all three. For a
    // scalar on the left the members are still the set.
    let scalar_policies = resolved(&[
        string("/P1/AllowedTypes", "gp2"),
        string("/P2/AllowedTypes", "gp3"),
    ]);
    let singleton_policies = resolved(&[
        list("/P1/AllowedTypes", &["gp2"]),
        list("/P2/AllowedTypes", &["gp3"]),
    ]);
    let mixed_policies = resolved(&[
        string("/P1/AllowedTypes", "gp2"),
        list("/P2/AllowedTypes", &["gp3"]),
    ]);
    let only_gp2 = list("/V/VolumeTypes", &["gp2"]);
    assert_eq!(
        (true, false, false, true, true, true, true, true),
        (
            passes(false, &both_allowed, &scalar_policies, members),
            passes(false, &both_allowed, &singleton_policies, members),
            passes(false, &both_allowed, &mixed_policies, members),
            passes(false, &only_gp2, &scalar_policies, members),
            passes(false, &only_gp2, &singleton_policies, members),
            passes(false, &only_gp2, &mixed_policies, members),
            passes(false, &gp2, &scalar_policies, members),
            passes(false, &gp2, &mixed_policies, members),
        ),
        "two policies holding `gp2` and `gp3` as scalars pool into `[gp2, gp3]`, which `[gp2, gp3]` is a \
         subset of; as one-element lists, or one of each, it is a subset of no single set; `[gp2]` is a \
         subset of one in all three; a scalar `gp2` is a member of the pool in both spellings"
    );

    // An allowlist of pairs, each a list one enumerated member holds (`Mappings.Combos.*.Pair`). A list
    // on the left is fail-closed in both polarities, asymmetrically: `IN` holds when it is a subset of
    // one pair (a pair assembled from two is out; pooling the members would admit it), and `NOT IN`
    // denies it when any element is a member of any pair, as the pairing loop and the named spelling
    // do, so `[s1, g2]` is out of both. A denylist of one policy's `[ssh]` denies `[ssh, tcp]` for the
    // same reason. The same pairs enumerated as the query's last part (`Pairs.List[*]`) match whole
    // pairs only, as the written-out list of pairs does; so does `DenyGroups.*` over `[[22], [3389]]`,
    // which `[22, 80]` therefore passes, as `NOT IN [[22], [3389]]` passes it (see `EntryCandidates`).
    let s1g1 = list("/X/Pair", &["s1", "g1"]);
    let s1g2 = list("/X/Pair", &["s1", "g2"]);
    let g1s1 = list("/X/Pair", &["g1", "s1"]);
    let combos = resolved(&[
        list("/Combos/a/Pair", &["s1", "g1"]),
        list("/Combos/b/Pair", &["s2", "g2"]),
    ]);
    let ssh_tcp = list("/R/Protocols", &["ssh", "tcp"]);
    let denied_by_policy = resolved(&[list("/Policy/DeniedTypes", &["ssh"])]);
    let deny_groups = resolved(&[
        list("/DenyGroups/ssh", &["22"]),
        list("/DenyGroups/rdp", &["3389"]),
    ]);
    let ports_22_80 = list("/R/Ports", &["22", "80"]);
    let nest_1_9 = Rc::new(PathAwareValue::List((
        Path::new("/X/Nest".to_string(), 0, 0),
        vec![
            PathAwareValue::Int((Path::new("/X/Nest/0".to_string(), 0, 0), 1)),
            PathAwareValue::List((
                Path::new("/X/Nest/1".to_string(), 0, 0),
                vec![PathAwareValue::Int((
                    Path::new("/X/Nest/1/0".to_string(), 0, 0),
                    9,
                ))],
            )),
        ],
    )));
    let deny_nested_nine = vec![QueryResult::Resolved(Rc::new(PathAwareValue::List((
        Path::new("/DenyNestedNine/0".to_string(), 0, 0),
        vec![PathAwareValue::Int((
            Path::new("/DenyNestedNine/0/0".to_string(), 0, 0),
            9,
        ))],
    ))))];
    let only_s1 = list("/X/Pair", &["s1"]);
    assert_eq!(
        (true, false, true, false, false, false, false, true, false, false, true),
        (
            passes(false, &s1g1, &combos, members),
            passes(false, &s1g2, &combos, members),
            passes(false, &g1s1, &combos, members),
            passes(true, &s1g1, &combos, members),
            passes(true, &s1g2, &combos, members),
            passes(true, &g1s1, &combos, members),
            passes(true, &ssh_tcp, &denied_by_policy, members),
            passes(false, &s1g1, &combos, entries),
            passes(false, &s1g2, &combos, entries),
            passes(false, &g1s1, &combos, entries),
            passes(true, &s1g2, &combos, entries),
        ),
        "a pair the allowlist names, or a permutation of one, is in; a pair assembled from two is out; \
         `NOT IN` denies all three for the elements they share with a denied pair, and denies \
         `[ssh, tcp]` for the `ssh` one policy denies; enumerated as entries the pairs match whole and \
         in order, so only `[s1, g1]` is in and `[s1, g2]` collides with nothing"
    );
    assert_eq!(
        (true, false, false),
        (
            passes(true, &ports_22_80, &deny_groups, entries),
            passes(false, &only_s1, &combos, entries),
            passes(true, &nest_1_9, &deny_nested_nine, entries),
        ),
        "enumerated as entries, `[22, 80]` passes the groups `[[22], [3389]]` as the written-out list \
         passes it, `[s1]` is not a subset of a list of pairs, and `[1, [9]]` is denied for the entry \
         `[9]` it holds"
    );

    // The literal-left arm reports as the query-vs-query arm does: a `QueryIn` carrying the resolved
    // entries as its right operand, so the reporter names them with their paths, rather than the raw
    // `contained_in` answer against one list built at the root path.
    let literal_left = match (InOperation::shaped(entries, &allowed), false)
        .compare(&[QueryResult::Literal(Rc::clone(&gp))], &allowed)
        .unwrap()
    {
        EvalResult::Result(results) => results,
        _ => panic!("the literal-left arm answers with a result vector"),
    };
    match literal_left.as_slice() {
        [ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(query_in)))] => {
            assert_eq!(
                2,
                query_in.rhs.len(),
                "the two resolved entries are the right operand of the report"
            );
            assert_eq!(
                vec![Rc::clone(&gp)],
                query_in.diff,
                "the literal is the value the report names"
            );
        }
        _ => panic!("expected one failed `QueryIn` from the literal-left arm"),
    }

    // Mixed left-hand values get one result each, so a quantifier can see each verdict: this is the
    // shape the written-out list produces, and the one `some Vals[*] NOT IN Denied[*]` needs.
    let mixed = resolved(&[Rc::clone(&gp2), Rc::clone(&io1)]);
    let per_value = match (InOperation::shaped(entries, &allowed), true)
        .compare(&mixed, &allowed)
        .unwrap()
    {
        EvalResult::Result(results) => results
            .iter()
            .map(|result| {
                matches!(
                    result,
                    ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
                )
            })
            .collect::<Vec<_>>(),
        _ => panic!("the query-vs-query arm answers with a result vector"),
    };
    assert_eq!(
        vec![false, true],
        per_value,
        "`[gp2, io1] NOT IN Types[*]` is two results, one per value: `gp2` is an entry and is denied, \
         `io1` is not and passes"
    );

    // Plain `compare` on the operator carries no shape, so it is the containment reading; the entry
    // that knows the shape is `InOperation` itself, which is what `binary_operation` builds.
    let bare = match (CmpOperator::In, false)
        .compare(&resolved(&[Rc::clone(&gp)]), &allowed)
        .unwrap()
    {
        EvalResult::Result(results) => results,
        _ => panic!("the query-vs-query arm answers with a result vector"),
    };
    assert!(
        matches!(
            bare.as_slice(),
            [ValueEvalResult::ComparisonResult(
                ComparisonResult::Success(Compare::QueryIn(_))
            )]
        ),
        "`CmpOperator::In.compare` carries no shape and is the non-enumerating reading; got {:?}",
        bare
    );
}

/// A left-hand value no entry can be compared with is refused, not read as "not a member".
///
/// `contained_in`'s scalar arm turns a pair of kinds `compare_eq` has no arm for into a miss, which is
/// right for a written-out list and opened the unsafe direction for the enumerating query: an int or a
/// map against enumerated strings compared with nothing and `NOT IN` passed it, where the pairing loop
/// refused (`found_in_string` answered `NotAString`) and failed closed in both polarities. The entry-set
/// path refuses the same way, naming the first entry it could not compare with at that entry's own
/// path; a value some entry CAN be compared with is decided, so `80` against `[22, "ssh"]` is not a
/// member and `NOT IN` admits it; and a value against members of another non-string kind is a miss, as
/// the pairing loop (`found_in_string` answering `NoneFound` for a non-string haystack, the
/// `NotComparable` dropped) and the written-out list both read it.
#[test]
fn a_left_hand_value_no_entry_can_be_compared_with_is_refused() {
    let port = Rc::new(PathAwareValue::Int((
        Path::new("/R/FromPort".to_string(), 7, 17),
        22,
    )));
    // What `InstanceType: !Ref TypeParam` loads as: a one-key map.
    let ref_map = Rc::new(PathAwareValue::try_from(r#"{"Ref": "TypeParam"}"#).unwrap());
    let strings = [
        QueryResult::Resolved(Rc::new(PathAwareValue::String((
            Path::new("/Denied/Ports/0".to_string(), 3, 13),
            "22".to_string(),
        )))),
        QueryResult::Resolved(Rc::new(PathAwareValue::String((
            Path::new("/Denied/Ports/1".to_string(), 3, 19),
            "3389".to_string(),
        )))),
    ];
    let mixed = [
        QueryResult::Resolved(Rc::new(PathAwareValue::Int((
            Path::new("/Denied/Ports/0".to_string(), 3, 13),
            22,
        )))),
        QueryResult::Resolved(Rc::new(PathAwareValue::String((
            Path::new("/Denied/Ports/1".to_string(), 3, 17),
            "ssh".to_string(),
        )))),
    ];
    let eighty = Rc::new(PathAwareValue::Int((
        Path::new("/R/FromPort".to_string(), 7, 17),
        80,
    )));

    for (left, shape) in [
        (&port, RhsEnumeration::LastPart),
        (&port, RhsEnumeration::EarlierPart),
        (&ref_map, RhsEnumeration::LastPart),
    ] {
        for not_in in [false, true] {
            let results = match (InOperation::shaped(shape, &strings), not_in)
                .compare(&[QueryResult::Resolved(Rc::clone(left))], &strings)
                .unwrap()
            {
                EvalResult::Result(results) => results,
                _ => panic!("the query-vs-query arm answers with a result vector"),
            };
            match results.as_slice() {
                [ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(refused))] => {
                    assert_eq!(
                        (
                            "/Denied/Ports/0".to_string(),
                            Unanswerable::IncomparableKinds
                        ),
                        (refused.pair.rhs.self_path().0.clone(), refused.cause),
                        "{:?} not_in={}: the refusal names the first entry at its own path",
                        shape,
                        not_in
                    );
                }
                other => panic!(
                    "{:?} not_in={}: expected one refusal in both polarities, got {:?}",
                    shape, not_in, other
                ),
            }
        }
    }

    let decided = match (InOperation::shaped(RhsEnumeration::LastPart, &mixed), true)
        .compare(&[QueryResult::Resolved(Rc::clone(&eighty))], &mixed)
        .unwrap()
    {
        EvalResult::Result(results) => results,
        _ => panic!("the query-vs-query arm answers with a result vector"),
    };
    assert!(
        matches!(
            decided.as_slice(),
            [ValueEvalResult::ComparisonResult(
                ComparisonResult::Success(_)
            )]
        ),
        "`80 NOT IN [22, \"ssh\"]` is decided by the `22` it can be compared with, got {:?}",
        decided
    );

    // A string against int entries is a miss, not a refusal, as it is for the written-out `[1, 3]`:
    // the loop this path replaced refused only where a string haystack met a non-string.
    let empty_string = Rc::new(PathAwareValue::String((
        Path::new("/R/Name".to_string(), 2, 9),
        String::new(),
    )));
    let ints = [
        QueryResult::Resolved(Rc::new(PathAwareValue::Int((
            Path::new("/D13/0".to_string(), 1, 8),
            1,
        )))),
        QueryResult::Resolved(Rc::new(PathAwareValue::Int((
            Path::new("/D13/1".to_string(), 1, 11),
            3,
        )))),
    ];
    let missed = match (InOperation::shaped(RhsEnumeration::LastPart, &ints), true)
        .compare(&[QueryResult::Resolved(Rc::clone(&empty_string))], &ints)
        .unwrap()
    {
        EvalResult::Result(results) => results,
        _ => panic!("the query-vs-query arm answers with a result vector"),
    };
    assert!(
        matches!(
            missed.as_slice(),
            [ValueEvalResult::ComparisonResult(
                ComparisonResult::Success(_)
            )]
        ),
        "`\"\" NOT IN D13[*]` over ints is a miss and passes, got {:?}",
        missed
    );

    // And a map against int entries, a worked example: a miss in both readings, so `NOT IN`
    // passes as `{Ref: PortParam} NOT IN [22, 3389]` passes, and nothing moved.
    let map_vs_ints = match (InOperation::shaped(RhsEnumeration::LastPart, &ints), true)
        .compare(&[QueryResult::Resolved(Rc::clone(&ref_map))], &ints)
        .unwrap()
    {
        EvalResult::Result(results) => results,
        _ => panic!("the query-vs-query arm answers with a result vector"),
    };
    assert!(
        matches!(
            map_vs_ints.as_slice(),
            [ValueEvalResult::ComparisonResult(
                ComparisonResult::Success(_)
            )]
        ),
        "a map against int entries is a miss, not a refusal, got {:?}",
        map_vs_ints
    );
}

/// A projection of scalar results is the written-out list of them for a list on the left.
///
/// Under an earlier-part enumeration a list on the left is a subset question asked of one list-valued
/// result at a time, which keeps `[s1, g2]` out of `Combos.*.Pair`; the SCALAR results are pooled into
/// one set, because `Entries[*].Name` over names `gp2`, `gp3` spells out `["gp2", "gp3"]` and
/// `[gp2, gp3] IN ["gp2", "gp3"]` holds. Wrapping each scalar in its own one-element set, the first
/// shape of this, refused every list on the left of a names allowlist for good. Two list-valued results
/// `[gp2]` and `[gp3]` still refuse `[gp2, gp3]` (a subset of neither), and a scalar beside a list
/// (`gp2` and `[gp3]`) refuses it too, as `IN ["gp2", ["gp3"]]` does.
#[test]
fn a_projection_of_scalar_results_is_the_written_out_list_for_a_list_on_the_left() {
    fn string(path: &str, value: &str) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::String((
            Path::new(path.to_string(), 0, 0),
            value.to_string(),
        )))
    }
    fn list(path: &str, elements: &[&str]) -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::List((
            Path::new(path.to_string(), 0, 0),
            elements
                .iter()
                .map(|element| {
                    PathAwareValue::String((
                        Path::new(format!("{}/0", path), 0, 0),
                        element.to_string(),
                    ))
                })
                .collect(),
        )))
    }
    fn resolved(values: &[Rc<PathAwareValue>]) -> Vec<QueryResult> {
        values
            .iter()
            .map(|value| QueryResult::Resolved(Rc::clone(value)))
            .collect()
    }
    fn passes(lhs: &Rc<PathAwareValue>, rhs: &[QueryResult]) -> bool {
        match (InOperation::shaped(RhsEnumeration::EarlierPart, rhs), false)
            .compare(&resolved(&[Rc::clone(lhs)]), rhs)
            .unwrap()
        {
            EvalResult::Result(results) => results.iter().all(|result| {
                matches!(
                    result,
                    ValueEvalResult::ComparisonResult(ComparisonResult::Success(_))
                )
            }),
            _ => panic!("the query-vs-query arm answers with a result vector"),
        }
    }

    let gp2_gp3 = list("/V/VolumeTypes", &["gp2", "gp3"]);
    let gp2 = list("/V/VolumeTypes", &["gp2"]);
    let names = resolved(&[string("/E/0/Name", "gp2"), string("/E/1/Name", "gp3")]);
    let lists = resolved(&[list("/P1/Allowed", &["gp2"]), list("/P2/Allowed", &["gp3"])]);
    let mixed = resolved(&[string("/P1/Allowed", "gp2"), list("/P2/Allowed", &["gp3"])]);
    assert_eq!(
        (true, true, false, true, false, true),
        (
            passes(&gp2_gp3, &names),
            passes(&gp2, &names),
            passes(&gp2_gp3, &lists),
            passes(&gp2, &lists),
            passes(&gp2_gp3, &mixed),
            passes(&gp2, &mixed),
        ),
        "cells in order: `[gp2, gp3]` and `[gp2]` against the names `gp2`, `gp3` (pooled, both hold); \
         against the lists `[gp2]`, `[gp3]` (a subset of neither, of one); against `gp2` beside `[gp3]` \
         (the pool is `[gp2]` alone, so only `[gp2]` holds)"
    );
}

/// A refusal on the list path names the entry that refused, not the first entry.
///
/// `Cats IN %pats[*]` with `let pats = ["abc", /(?!x)((a+)+)b/]` and a list of long `a` strings: the
/// regex is the entry whose backtracking budget runs out, so the refusal names it at `/1`, not `"abc"`
/// at `/0`. `refusing_entry_index` asks `compare_eq` the pairs the list walk asked and stops at the
/// first regex the engine cannot evaluate.
#[test]
fn a_refusal_on_the_list_path_names_the_entry_that_refused() {
    let cats = Rc::new(PathAwareValue::List((
        Path::new("/R/Cats".to_string(), 5, 13),
        vec![PathAwareValue::String((
            Path::new("/R/Cats/0".to_string(), 5, 14),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ))],
    )));
    let patterns = [
        QueryResult::Resolved(Rc::new(PathAwareValue::String((
            Path::new("/0".to_string(), 0, 0),
            "abc".to_string(),
        )))),
        QueryResult::Resolved(Rc::new(PathAwareValue::Regex((
            Path::new("/1".to_string(), 0, 0),
            "(?!x)((a+)+)b".to_string(),
        )))),
    ];
    let results = match (
        InOperation::shaped(RhsEnumeration::LastPart, &patterns),
        false,
    )
        .compare(&[QueryResult::Resolved(Rc::clone(&cats))], &patterns)
        .unwrap()
    {
        EvalResult::Result(results) => results,
        _ => panic!("the query-vs-query arm answers with a result vector"),
    };
    match results.as_slice() {
        [ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(refused))] => {
            assert_eq!(
                ("/1".to_string(), Unanswerable::EngineGaveUp),
                (refused.pair.rhs.self_path().0.clone(), refused.cause),
                "the refusal names the regex at its own path, not the first entry"
            );
        }
        other => panic!("expected one refusal, got {:?}", other),
    }
}

/// A refusal on the entry-set path names an entry the author can find, not the set built here.
///
/// `contained_in` is handed the entries as one list built at the root path, so a refusal it reports
/// carried that list as its right operand, and the report printed the whole set as one value at
/// `[L:0,C:0]`. The one refusal that reaches this path is a regex whose backtracking budget ran out (a
/// pair of kinds the comparator has no arm for is answered "no" by `is_one_of` against a non-string
/// member and refused by `scalar_membership` only against a string one), and a
/// regex entry comes from a `let`-bound literal list enumerated with `[*]`. The refusal is re-pointed at
/// the first entry of the set it was raised against, which carries the entry's own path; the reason and
/// the cause are the refusal's own.
#[test]
fn a_refusal_on_the_entry_set_path_names_an_entry_with_its_path() {
    let subject = Rc::new(PathAwareValue::String((
        Path::new("/R/Cat".to_string(), 5, 12),
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
    )));
    let patterns = [
        QueryResult::Resolved(Rc::new(PathAwareValue::Regex((
            Path::new("/0".to_string(), 0, 0),
            "(?!x)((a+)+)b".to_string(),
        )))),
        QueryResult::Resolved(Rc::new(PathAwareValue::Regex((
            Path::new("/1".to_string(), 0, 0),
            "(?!x)((a+)+)c".to_string(),
        )))),
    ];
    for shape in [RhsEnumeration::LastPart, RhsEnumeration::EarlierPart] {
        let results = match (InOperation::shaped(shape, &patterns), false)
            .compare(&[QueryResult::Resolved(Rc::clone(&subject))], &patterns)
            .unwrap()
        {
            EvalResult::Result(results) => results,
            _ => panic!("the query-vs-query arm answers with a result vector"),
        };
        match results.as_slice() {
            [ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(refused))] => {
                assert_eq!(
                    (
                        "/R/Cat".to_string(),
                        "/0".to_string(),
                        Unanswerable::EngineGaveUp
                    ),
                    (
                        refused.pair.lhs.self_path().0.clone(),
                        refused.pair.rhs.self_path().0.clone(),
                        refused.cause
                    ),
                    "{:?}: the spent budget is a refusal, and the refusal names the first entry at \
                     its own path, not the set at the root path",
                    shape
                );
                assert!(
                    matches!(&*refused.pair.rhs, PathAwareValue::Regex(_)),
                    "{:?}: the right operand of the refusal is the entry itself, got {:?}",
                    shape,
                    refused.pair.rhs
                );
            }
            other => panic!("{:?}: expected one refusal, got {:?}", shape, other),
        }
    }
}

/// A literal list on the left of `NOT IN` against a right-hand query that resolves to scalars is a
/// subset question negated: the clause passes when no element of the list is among the right-hand
/// values and fails when one is.
///
/// `let needles = [5]` and `%needles NOT IN Deny[*]` over a `Deny` of `[7]` failed, at exit 19, with
/// a finding that named `[5]` and read that it "was not present in" `[7]` -- the opposite of what a
/// `NOT IN` failure says. The `(Some, None)` arm built its `QueryIn` with the element-wise diff and
/// `QueryIn::new` set `lhs_unmatched` to that diff, so the negation wrapper's `lhs \ lhs_unmatched`
/// subtracted elements from a one-element set holding the list itself, removed nothing, and the list
/// survived as a collision whatever the right-hand side held.
///
/// The verdict stays at WHOLE-LIST granularity: one `QueryIn` whose single left-hand value is the list,
/// as the document spelling `some Lit IN Deny[*]` over a list-valued `Lit` gives, so that `some` over
/// the literal spelling cannot pass on one matched element of a list that is not a subset. What the
/// repair changes is `lhs_unmatched`: the list itself when no element collides, so the subtraction
/// empties and `NOT IN` passes, and nothing when one does, so the list survives and `NOT IN` fails.
///
/// Cells: NOT IN absent (PASS, the list is the one value), NOT IN present (FAIL, the list is the one
/// collision), the positive `IN` beside each (the element-wise diff `IN` reports), a partly present
/// list (`IN` fails naming the absent element; `NOT IN` fails because the other collides), and the
/// empty list. The empty literal never reaches this constructor: a `[]` written in the rule is a value,
/// read element-wise whatever the right side's kind (`empty_list_literal_in`), and with no element to
/// collide it is a member of a scalar never, so `IN` FAILS and `NOT IN` PASSES, the same answers as
/// against a right-hand list -- not the vacuous subset the older convention passed `IN` on.
#[test]
fn a_literal_list_not_in_a_scalar_query_passes_when_no_element_collides() {
    fn int(path: &str, value: i64) -> PathAwareValue {
        PathAwareValue::Int((Path::new(path.to_string(), 0, 0), value))
    }

    fn list(path: &str, elements: Vec<PathAwareValue>) -> QueryResult {
        QueryResult::Literal(Rc::new(PathAwareValue::List((
            Path::new(path.to_string(), 0, 0),
            elements,
        ))))
    }

    fn render(values: &[Rc<PathAwareValue>]) -> Vec<String> {
        values
            .iter()
            .map(|value| match &**value {
                PathAwareValue::Int((_, i)) => i.to_string(),
                PathAwareValue::List((_, l)) => format!(
                    "list[{}]",
                    l.iter()
                        .map(|e| match e {
                            PathAwareValue::Int((_, i)) => i.to_string(),
                            other => panic!("unexpected element {:?}", other),
                        })
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                other => panic!("unexpected value {:?}", other),
            })
            .collect()
    }

    let needles = list("/needles", vec![int("/needles/0", 5)]);
    let two_needles = list("/needles", vec![int("/needles/0", 5), int("/needles/1", 6)]);
    let no_needles = list("/needles", vec![]);
    let deny_absent = vec![QueryResult::Resolved(Rc::new(int("/Deny/0", 7)))];
    let deny_present = vec![
        QueryResult::Resolved(Rc::new(int("/Deny/0", 5))),
        QueryResult::Resolved(Rc::new(int("/Deny/1", 7))),
    ];

    // Returns (passed, the verdict's left-hand values, the values the verdict names) for one call: the
    // left-hand values on a Success, the diff on a Fail.
    fn verdict(
        negated: bool,
        lhs: &QueryResult,
        rhs: &[QueryResult],
    ) -> (bool, Vec<String>, Vec<String>) {
        let results = match (CmpOperator::In, negated)
            .compare(std::slice::from_ref(lhs), rhs)
            .unwrap()
        {
            EvalResult::Result(results) => results,
            other => panic!("expected a result vector, got {:?}", other),
        };
        assert_eq!(1, results.len(), "one aggregate verdict; got {:?}", results);
        match &results[0] {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                (true, render(&qin.lhs), render(&qin.lhs))
            }
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                (false, render(&qin.lhs), render(&qin.diff))
            }
            // The empty literal's verdict is a plain membership answer for the list itself, from
            // `empty_list_literal_in`, not a `QueryIn`: nothing to diff, the list is the one value.
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::ValueIn(
                pair,
            ))) => {
                let list = render(std::slice::from_ref(&pair.lhs));
                (true, list.clone(), list)
            }
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::ValueIn(pair))) => {
                let list = render(std::slice::from_ref(&pair.lhs));
                (false, list.clone(), list)
            }
            other => panic!("expected a QueryIn or ValueIn verdict, got {:?}", other),
        }
    }

    let s = |v: &str| v.to_string();

    assert_eq!(
        (true, vec![s("list[5]")], vec![s("list[5]")]),
        verdict(true, &needles, &deny_absent),
        "5 is not among [7]: `NOT IN` passes, and the one value it passes on is the list"
    );
    assert_eq!(
        (false, vec![s("list[5]")], vec![s("list[5]")]),
        verdict(true, &needles, &deny_present),
        "5 is among [5, 7]: `NOT IN` fails, and the one collision it names is the list"
    );
    assert_eq!(
        (false, vec![s("list[5]")], vec![s("5")]),
        verdict(false, &needles, &deny_absent),
        "control: `IN` fails over [7], the left-hand value is the list, the diff names the element"
    );
    assert_eq!(
        (true, vec![s("list[5]")], vec![s("list[5]")]),
        verdict(false, &needles, &deny_present),
        "control: `IN` passes over [5, 7] with the list as its one value"
    );
    assert_eq!(
        (false, vec![s("list[5,6]")], vec![s("6")]),
        verdict(false, &two_needles, &deny_present),
        "partly present: `IN` fails naming the element that is absent"
    );
    assert_eq!(
        (false, vec![s("list[5,6]")], vec![s("list[5,6]")]),
        verdict(true, &two_needles, &deny_present),
        "partly present: `NOT IN` fails, because 5 collides, naming the list"
    );
    assert_eq!(
        (false, vec![s("list[]")], vec![s("list[]")]),
        verdict(false, &no_needles, &deny_absent),
        "empty list literal: read element-wise it has no element among [7], so `IN` fails, as `[] IN [7]` does"
    );
    assert_eq!(
        (true, vec![s("list[]")], vec![s("list[]")]),
        verdict(true, &no_needles, &deny_absent),
        "empty list literal: no element collides, so `NOT IN` passes, as `[] NOT IN [7]` does"
    );
}

/// A one-character string against a char range is answered as the character, in both polarities;
/// a longer string stays not comparable.
///
/// No loader produces a `Char`: a YAML `b`, a quoted `"b"` and a rules-side `'b'` are all `String`.
/// `r[a,f]` parses, and `compare_eq` has exactly one membership arm for it, `(Char, RangeChar)`, so
/// `Grade in r[a,f]` over any document fell to the incomparable catch-all and exited 19, and so did
/// `Grade not in r[a,f]`: a clause neither polarity could satisfy, reachable only through
/// `parse_char`. `contained_in` now reads a one-character string as the character it spells before
/// asking the range. The integer range beside it is the control that already worked, and `bc` is
/// the string the arm must still refuse: a string of two characters is not a character, and
/// guessing one would make `"bc" in r[a,f]` answer for `b` alone.
#[test]
fn a_one_character_string_is_tested_against_a_char_range_as_the_character() {
    fn string(value: &str) -> QueryResult {
        QueryResult::Resolved(Rc::new(PathAwareValue::String((
            Path::new("/Grade".to_string(), 0, 0),
            value.to_string(),
        ))))
    }

    let a_to_f = [QueryResult::Literal(Rc::new(PathAwareValue::RangeChar((
        Path::root(),
        crate::rules::values::RangeType {
            lower: 'a',
            upper: 'f',
            inclusive: crate::rules::values::LOWER_INCLUSIVE
                | crate::rules::values::UPPER_INCLUSIVE,
        },
    ))))];

    // One result per left-hand value; this folds it to a verdict name.
    fn verdict(negated: bool, lhs: QueryResult, rhs: &[QueryResult]) -> &'static str {
        let results = match (CmpOperator::In, negated).compare(&[lhs], rhs).unwrap() {
            EvalResult::Result(results) => results,
            other => panic!("expected a result vector, got {:?}", other),
        };
        assert_eq!(1, results.len(), "one verdict per value; got {:?}", results);
        match &results[0] {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => "pass",
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_)) => "fail",
            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(_)) => "refused",
            other => panic!("unexpected result {:?}", other),
        }
    }

    assert_eq!(
        ("pass", "fail", "fail", "pass", "refused", "refused"),
        (
            verdict(false, string("b"), &a_to_f),
            verdict(true, string("b"), &a_to_f),
            verdict(false, string("q"), &a_to_f),
            verdict(true, string("q"), &a_to_f),
            verdict(false, string("bc"), &a_to_f),
            verdict(true, string("bc"), &a_to_f),
        ),
        "`b` is within a..f and `q` is not, in both polarities; `bc` is not a character and is \
         refused in both"
    );

    // The same range written inside a list literal, `in [r[a,f]]`, reaches the scalar-against-list
    // arm instead, and answers the same way. A string the range cannot describe is not refused
    // there: that arm reads a kind refusal as "not a member", as it always has for the bracketed
    // spelling, so `bc` fails `IN` and passes `NOT IN` (the notice in `eval.rs` is what tells the
    // author about that reading).
    let bracketed = [QueryResult::Literal(Rc::new(PathAwareValue::List((
        Path::root(),
        vec![PathAwareValue::RangeChar((
            Path::root(),
            crate::rules::values::RangeType {
                lower: 'a',
                upper: 'f',
                inclusive: crate::rules::values::LOWER_INCLUSIVE
                    | crate::rules::values::UPPER_INCLUSIVE,
            },
        ))],
    ))))];
    assert_eq!(
        ("pass", "fail", "fail", "pass", "fail", "pass"),
        (
            verdict(false, string("b"), &bracketed),
            verdict(true, string("b"), &bracketed),
            verdict(false, string("A"), &bracketed),
            verdict(true, string("A"), &bracketed),
            verdict(false, string("ab"), &bracketed),
            verdict(true, string("ab"), &bracketed),
        ),
        "bracketed: `b` is a member and `A` is not, in both polarities, as for the bare range; `ab` \
         keeps the list arm's not-a-member reading"
    );
}

/// `==` between a queried scalar and a one-element list literal unwraps the list once, and only once.
///
/// `Val == ["a"]` holds for a `Val` of `a`: that single unwrap is documented at
/// `compare_eq_unwrapping_a_one_element_list`. `Val == [["a"]]` held too, because the `(None, Some)`
/// list arm unwrapped `rhsl[0]` inline and then handed the pair to the comparator that unwraps a
/// one-element list itself, so two levels came off and `"a"` met `"a"`. The same two values spelled
/// with the scalar as a rule literal, `%x == [["a"]]`, reach `(Some, Some)`, unwrap once, and refuse
/// `"a"` against `["a"]` as not comparable. One pair of values, two verdicts by spelling.
///
/// The arm now passes the list whole and lets the comparator do its one unwrap, so the nested literal
/// is refused on both routes and the flat one keeps passing. The `["b"]` cell is the control that the
/// unwrap still happens: a refusal there would mean the arm stopped unwrapping altogether.
#[test]
fn a_scalar_against_a_nested_one_element_list_literal_unwraps_once() {
    fn string(path: &str, value: &str) -> PathAwareValue {
        PathAwareValue::String((Path::new(path.to_string(), 0, 0), value.to_string()))
    }

    fn list(elements: Vec<PathAwareValue>) -> PathAwareValue {
        PathAwareValue::List((Path::root(), elements))
    }

    fn verdict(lhs: QueryResult, rhs: QueryResult) -> &'static str {
        let results = match (CmpOperator::Eq, false).compare(&[lhs], &[rhs]).unwrap() {
            EvalResult::Result(results) => results,
            other => panic!("expected a result vector, got {:?}", other),
        };
        assert_eq!(1, results.len(), "one verdict per value; got {:?}", results);
        match &results[0] {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(_)) => "pass",
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(_)) => "fail",
            ValueEvalResult::ComparisonResult(ComparisonResult::NotComparable(_)) => "refused",
            other => panic!("unexpected result {:?}", other),
        }
    }

    let queried_a = || QueryResult::Resolved(Rc::new(string("/Val", "a")));
    let literal_a = || QueryResult::Literal(Rc::new(string("", "a")));
    let flat_a = || QueryResult::Literal(Rc::new(list(vec![string("/0", "a")])));
    let flat_b = || QueryResult::Literal(Rc::new(list(vec![string("/0", "b")])));
    let nested_a = || QueryResult::Literal(Rc::new(list(vec![list(vec![string("/0/0", "a")])])));

    assert_eq!(
        ("pass", "fail", "refused", "refused"),
        (
            verdict(queried_a(), flat_a()),
            verdict(queried_a(), flat_b()),
            verdict(queried_a(), nested_a()),
            verdict(literal_a(), nested_a()),
        ),
        "a one-element list unwraps to its element (pass, fail); a nested one-element list unwraps \
         once to a list, which a scalar cannot equal, on the query route as on the literal route"
    );

    // The mirror: the list on the LEFT, arriving from a query, against a literal scalar, and a literal
    // scalar against a list arriving from a query. Those two arms expand the list element by element,
    // and each element then met the unwrapping comparator -- a second unwrap -- so `LL == "a"` held
    // for an `LL` of `[["a"]]` while `%ll == "a"` with the same list as a rule literal was refused.
    // The expansion IS the one unwrap, so the elements are compared plainly now.
    let queried_l = || QueryResult::Resolved(Rc::new(list(vec![string("/L/0", "a")])));
    let queried_ll =
        || QueryResult::Resolved(Rc::new(list(vec![list(vec![string("/LL/0/0", "a")])])));
    let literal_ll = || QueryResult::Literal(Rc::new(list(vec![list(vec![string("/0/0", "a")])])));

    assert_eq!(
        ("pass", "refused", "refused", "pass", "refused"),
        (
            verdict(queried_l(), literal_a()),
            verdict(queried_ll(), literal_a()),
            verdict(literal_ll(), literal_a()),
            verdict(literal_a(), queried_l()),
            verdict(literal_a(), queried_ll()),
        ),
        "a queried one-element list against a literal scalar is its element (pass); a queried nested \
         list expands to a list, which a scalar cannot equal (refused), as the literal spelling of the \
         same list is; and the same in the other operand order"
    );
}

/// `==` between two queries is set equality: every left value has an equal on the right and every right
/// value has an equal on the left, with no count of occurrences. Pinned, with the question it leaves open.
///
/// A left operand resolving to `1, 1` against a right operand resolving to `1` PASSES, and `1, 2`
/// against `1` FAILS. Whether the first should pass is a design question and not a defect this tree
/// decides: `Resources.*.Properties.Region == %region`, three equal values against one, is the
/// everyday shape of the clause and passes on the set reading as its literal spellings do, and a counted
/// reading was tried here and withdrawn because it fails that clause. Settling it needs the registry
/// corpus measured against both readings, and the maintainers' call; until then this cell is what the
/// arm promises. `!=` is the negation wrapper's reading of the same sweep -- it denies the left values
/// that collide with any right value -- so both `1`s collide with the right-hand `1` and `!=` fails.
#[test]
fn equality_between_two_queries_is_set_equality_without_counting() {
    fn int(path: &str, value: i64) -> QueryResult {
        QueryResult::Resolved(Rc::new(PathAwareValue::Int((
            Path::new(path.to_string(), 0, 0),
            value,
        ))))
    }

    // (passed, the paths the verdict names)
    fn verdict(negated: bool, lhs: &[QueryResult], rhs: &[QueryResult]) -> (bool, Vec<String>) {
        let results = match (CmpOperator::Eq, negated).compare(lhs, rhs).unwrap() {
            EvalResult::Result(results) => results,
            other => panic!("expected a result vector, got {:?}", other),
        };
        assert_eq!(1, results.len(), "one aggregate verdict; got {:?}", results);
        let paths = |values: &[Rc<PathAwareValue>]| {
            values
                .iter()
                .map(|v| v.self_path().0.clone())
                .collect::<Vec<_>>()
        };
        match &results[0] {
            ValueEvalResult::ComparisonResult(ComparisonResult::Success(Compare::QueryIn(qin))) => {
                (true, paths(&qin.diff))
            }
            ValueEvalResult::ComparisonResult(ComparisonResult::Fail(Compare::QueryIn(qin))) => {
                (false, paths(&qin.diff))
            }
            other => panic!("expected a QueryIn verdict, got {:?}", other),
        }
    }

    let one_twice = [int("/A1/V", 1), int("/A2/V", 1)];
    let one_and_two = [int("/A1/V", 1), int("/A2/V", 2)];
    let one_once = [int("/B1/V", 1)];

    assert_eq!(
        (true, vec![]),
        verdict(false, &one_twice, &one_once),
        "two 1s against one 1 is equal as sets; counting occurrences is the open question"
    );
    assert_eq!(
        (false, vec!["/A2/V".to_string()]),
        verdict(false, &one_and_two, &one_once),
        "a distinct value on one side only fails, naming it"
    );
    assert_eq!(
        (false, vec!["/A1/V".to_string(), "/A2/V".to_string()]),
        verdict(true, &one_twice, &one_once),
        "`!=` denies both 1s: each collides with the right-hand 1"
    );
    assert_eq!(
        (false, vec!["/A1/V".to_string()]),
        verdict(true, &one_and_two, &one_once),
        "`!=` denies the colliding 1 and not the 2"
    );

    // The regression cells a counted reading fails: one value against two equal values, in both
    // operand orders (`Resources.A.Name == Resources.*.Name` with two resources named the same).
    fn string(path: &str, value: &str) -> QueryResult {
        QueryResult::Resolved(Rc::new(PathAwareValue::String((
            Path::new(path.to_string(), 0, 0),
            value.to_string(),
        ))))
    }
    let one_foo = [string("/A/Name", "foo")];
    let two_foo = [string("/A/Name", "foo"), string("/B/Name", "foo")];
    assert_eq!(
        (true, vec![]),
        verdict(false, &one_foo, &two_foo),
        "one `foo` against two is equal as sets"
    );
    assert_eq!(
        (true, vec![]),
        verdict(false, &two_foo, &one_foo),
        "two `foo` against one is equal as sets"
    );
}
