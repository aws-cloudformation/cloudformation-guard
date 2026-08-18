use crate::utils::writer::Writer;
use grep_searcher::SearcherBuilder;
use indoc::formatdoc;
use pretty_assertions::{assert_eq, assert_ne};
use std::collections::HashMap;

use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::eval_context::{root_scope, EventRecord, RecordTracker};

use super::*;

//
// All unary function simple tests
//

#[test]
fn test_all_unary_functions() -> Result<()> {
    let path_value = PathAwareValue::try_from("{}")?;
    let non_empty_path_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
            r#"
        Resources:
          ec2:
            Type: AWS::EC2::Instance
            Properties:
              ImageId: ami-123456789012
              Tags: []
        "#,
        )?)?;
    let list_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(r#"[1, 2, 3]"#)?)?;
    let empty_list_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(r#"[]"#)?)?;
    let string_value = PathAwareValue::try_from(r#""String""#)?;
    let empty_string_value = PathAwareValue::try_from(r#""""#)?;
    let int_value = PathAwareValue::try_from(r#"10"#)?;
    let bool_value = PathAwareValue::try_from(r#"true"#)?;
    let float_value = PathAwareValue::try_from(r#"10.2"#)?;
    let char_range_value = PathAwareValue::try_from(r#"r[a, d)"#)?;
    let int_range_value = PathAwareValue::try_from(r#"r(10, 20)"#)?;
    let float_range_value = PathAwareValue::try_from(r#"r(10.0, 20.5]"#)?;
    let null_value = PathAwareValue::Null(path_value::Path::root());

    type UnaryTest<'test> = Vec<(
        Box<dyn Fn(&QueryResult) -> Result<bool>>,
        Vec<QueryResult>,
        Vec<QueryResult>,
    )>;

    let tests: UnaryTest = vec![
        (
            Box::new(exists_operation),
            // Successful tests
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
            ],
            // Failure tests
            vec![QueryResult::UnResolved(UnResolved {
                traversed_to: Rc::new(path_value.clone()),
                reason: None,
                remaining_query: "".to_string(),
            })],
        ),
        (
            Box::new(element_empty_operation),
            // Successful Tests
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(empty_string_value)), // we do check for string empty as well
                QueryResult::Resolved(Rc::new(empty_list_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    remaining_query: "".to_string(),
                    reason: None,
                    traversed_to: Rc::new(path_value.clone()),
                }),
            ],
            // Failure tests
            vec![
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
            ],
        ),
        (
            Box::new(is_string_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(string_value.clone()))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_int_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(int_value.clone()))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_list_operation),
            // Success Case
            vec![
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(empty_list_value.clone())),
            ],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(int_range_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_struct_operation),
            // Success Case
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
            ],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(empty_list_value)),
                QueryResult::Resolved(Rc::new(float_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_bool_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(bool_value))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_float_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(float_value.clone()))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_char_range_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(char_range_value.clone()))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::Resolved(Rc::new(float_range_value.clone())),
                QueryResult::Resolved(Rc::new(int_range_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_int_range_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(int_range_value))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::Resolved(Rc::new(float_range_value.clone())),
                QueryResult::Resolved(Rc::new(char_range_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_float_range_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(float_range_value.clone()))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value.clone())),
                QueryResult::Resolved(Rc::new(string_value.clone())),
                QueryResult::Resolved(Rc::new(int_value.clone())),
                QueryResult::Resolved(Rc::new(non_empty_path_value.clone())),
                QueryResult::Resolved(Rc::new(char_range_value.clone())),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value.clone()),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
        (
            Box::new(is_null_operation),
            // Success Case
            vec![QueryResult::Resolved(Rc::new(null_value.clone()))],
            // Failure Cases
            vec![
                QueryResult::Resolved(Rc::new(path_value.clone())),
                QueryResult::Resolved(Rc::new(list_value)),
                QueryResult::Resolved(Rc::new(string_value)),
                QueryResult::Resolved(Rc::new(int_value)),
                QueryResult::Resolved(Rc::new(non_empty_path_value)),
                QueryResult::Resolved(Rc::new(char_range_value)),
                QueryResult::Resolved(Rc::new(float_value)),
                QueryResult::Resolved(Rc::new(float_range_value)),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: Rc::new(path_value),
                    reason: None,
                    remaining_query: "".to_string(),
                }),
            ],
        ),
    ];

    for (index, (func, successes, failures)) in tests.iter().enumerate() {
        println!("Testing Case #{}", index);
        for (idx, each_success) in successes.iter().enumerate() {
            println!("Testing Success Case {}#{}", index, idx);
            assert!((*func)(each_success)?);
        }
        for (idx, each_failure) in failures.iter().enumerate() {
            println!("Testing Failure Case {}#{}", index, idx);
            assert!(!(*func)(each_failure)?);
        }
    }

    Ok(())
}

#[test]
fn query_empty_and_non_empty() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    let query = AccessQuery::try_from("Resources.*[ Type == /Bucket/ ]")?.query;
    let status = unary_operation(
        &query,
        (CmpOperator::Empty, true),
        false,
        "".to_string(),
        None,
        &mut eval,
        ClauseRole::Assertion,
    )?;
    match status {
        EvaluationResult::QueryValueResult(expected) => {
            assert_eq!(expected.len(), 1);
            let matched = &expected[0].0;
            match matched {
                QueryResult::Resolved(res) => {
                    assert_eq!(res.self_path().0.as_str(), "/Resources/s3");
                }
                _ => unreachable!(),
            }
        }

        EvaluationResult::EmptyQueryResult(..) => unreachable!(),
    }

    let query = AccessQuery::try_from("Resources.*[ Type == /Broker/ ]")?.query;
    let status = unary_operation(
        &query,
        (CmpOperator::Empty, true),
        false,
        "".to_string(),
        None,
        &mut eval,
        ClauseRole::Assertion,
    )?;
    match status {
        EvaluationResult::QueryValueResult(_) => unreachable!(),
        EvaluationResult::EmptyQueryResult(status, _) => {
            assert_eq!(status, Status::FAIL);
        }
    }

    Ok(())
}

//
// Binary comparison testing of each_lhs_value
//

#[test]
fn each_lhs_value_not_comparable() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Parameters:
          allowed_images: [ami-123456789012, ami-01234567890]
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    let query_ec2 = AccessQuery::try_from("Resources.ec2.Properties.ImageId")?.query;
    let lhs = eval.query(&query_ec2)?;
    assert_eq!(lhs.len(), 1);
    let lhs = match &lhs[0] {
        QueryResult::Resolved(val) => val,
        _ => unreachable!(),
    };
    let rhs_query = AccessQuery::try_from("Parameters.allowed_images")?.query;
    let rhs = eval.query(&rhs_query)?;
    let result = each_lhs_compare(compare_eq, Rc::clone(lhs), &rhs)?;

    assert_eq!(result.len(), 1);
    let cmp_result = &result[0];
    match cmp_result {
        ComparisonResult::NotComparable(NotComparableWithRhs {
            pair: LhsRhsPair { rhs: value, .. },
            ..
        }) => {
            let rhs_ptr = match &rhs[0] {
                QueryResult::Resolved(ptr) => &**ptr,
                _ => unreachable!(),
            };

            assert_eq!(rhs_ptr, &**value);
        }

        _ => unreachable!(),
    }

    let result = each_lhs_compare(
        in_cmp(true), // not in operation
        Rc::clone(lhs),
        &rhs,
    )?;

    assert_eq!(result.len(), 1);
    let cmp_result = &result[0];
    match cmp_result {
        ComparisonResult::Comparable(ComparisonWithRhs { outcome, .. }) => {
            assert!(!(*outcome));
        }

        _ => unreachable!(),
    }

    let result = each_lhs_compare(
        in_cmp(false), // in operation
        Rc::clone(lhs),
        &rhs,
    )?;

    assert_eq!(result.len(), 1);
    let cmp_result = &result[0];
    match cmp_result {
        ComparisonResult::Comparable(ComparisonWithRhs { outcome, .. }) => {
            assert!(*outcome);
        }

        _ => unreachable!(),
    }

    Ok(())
}

#[test]
fn each_lhs_value_eq_compare() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Parameters:
          allowed_images: [ami-123456789012, ami-01234567890]
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    let query_ec2 = AccessQuery::try_from("Resources.ec2.Properties.ImageId")?.query;
    let lhs = eval.query(&query_ec2)?;
    assert_eq!(lhs.len(), 1);
    let lhs = match &lhs[0] {
        QueryResult::Resolved(val) => val,
        _ => unreachable!(),
    };
    let rhs_query = AccessQuery::try_from("Parameters.allowed_images[*]")?.query;
    let rhs = eval.query(&rhs_query)?;
    assert_eq!(rhs.len(), 2);
    let result = each_lhs_compare(compare_eq, Rc::clone(lhs), &rhs)?;

    assert_eq!(result.len(), 2);
    for cmp_result in result {
        match cmp_result {
            ComparisonResult::Comparable(ComparisonWithRhs {
                pair: LhsRhsPair { rhs, .. },
                outcome,
            }) => {
                if outcome {
                    match (&**lhs, &*rhs) {
                        (PathAwareValue::String((_, s1)), PathAwareValue::String((_, s2))) => {
                            assert_eq!(s1, s2);
                            assert!(!std::ptr::eq(s1, s2));
                            assert_eq!(s1.as_str(), "ami-123456789012")
                        }
                        (_, _) => unreachable!(),
                    }
                } else {
                    match (&**lhs, &*rhs) {
                        (PathAwareValue::String((_, s1)), PathAwareValue::String((_, s2))) => {
                            assert_ne!(s1, s2);
                            assert!(!std::ptr::eq(s1, s2));
                            assert_eq!(s1.as_str(), "ami-123456789012");
                            assert_eq!(s2.as_str(), "ami-01234567890");
                        }
                        (_, _) => unreachable!(),
                    }
                }
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
fn each_lhs_value_eq_compare_mixed_comparable() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Parameters:
          allowed_images: [ami-123456789012, ami-01234567890]
        Resources:
          iam:
            Type: AWS::IAM::Role
            Properties:
              PolicyDocument:
                Statement:
                  - Principal: '*'
                    Effect: Allow
                    Resource: ['s3*']
                  - Principal: [aws-123, aws-345]
                    Effect: Allow
                    Resource: '*'
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    //
    // Equivalent of Resources.*.Properties.PolicyDocument.Statement[*].Principal
    //
    let lhs_query =
        AccessQuery::try_from("Resources.*.Properties.PolicyDocument.Statement[*].Principal")?
            .query;
    let selected_lhs = eval.query(&lhs_query)?;
    assert_eq!(selected_lhs.len(), 2); // 2 statements present

    let rhs_value = PathAwareValue::try_from(r#""*""#)?;
    let rhs_query_result = vec![QueryResult::Resolved(Rc::new(rhs_value))];
    for each_lhs in selected_lhs {
        match &each_lhs {
            QueryResult::Resolved(lhs) => {
                for cmp_result in each_lhs_compare(
                    not_compare(compare_eq, true),
                    Rc::clone(lhs),
                    &rhs_query_result,
                )? {
                    match cmp_result {
                        ComparisonResult::Comparable(ComparisonWithRhs { outcome, .. }) => {
                            if !outcome {
                                assert_eq!(lhs.self_path().0.as_str(), "/Resources/iam/Properties/PolicyDocument/Statement/0/Principal");
                            } else {
                                assert!(lhs.self_path().0.starts_with("/Resources/iam/Properties/PolicyDocument/Statement/1/Principal"));
                            }
                        }

                        _ => unreachable!(),
                    }
                }
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
fn each_lhs_value_eq_compare_mixed_single_plus_array_form_correct_exec() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Parameters:
          allowed_images: [ami-123456789012, ami-01234567890]
        Resources:
          iam:
            Type: AWS::IAM::Role
            Properties:
              PolicyDocument:
                Statement:
                  - Principal: '*'
                    Effect: Allow
                    Resource: ['s3*']
                  - Principal: [aws-123, aws-345]
                    Effect: Allow
                    Resource: '*'
        "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    //
    // Equivalent of Resources.*.Properties.PolicyDocument.Statement[*].Principal[*] == '*'
    //
    let lhs_query =
        AccessQuery::try_from("Resources.*.Properties.PolicyDocument.Statement[*].Principal[*]")?
            .query;
    let selected_lhs = eval.query(&lhs_query)?;
    assert_eq!(selected_lhs.len(), 3); // 3 selected values

    let rhs_value = PathAwareValue::try_from(r#""*""#)?;
    let rhs_query_result = vec![QueryResult::Resolved(Rc::new(rhs_value))];
    for each_lhs in selected_lhs {
        match each_lhs {
            QueryResult::Resolved(lhs) => {
                for cmp_result in each_lhs_compare(compare_eq, Rc::clone(&lhs), &rhs_query_result)?
                {
                    match cmp_result {
                        ComparisonResult::Comparable(ComparisonWithRhs { outcome, .. }) => {
                            if outcome {
                                assert_eq!(lhs.self_path().0.as_str(), "/Resources/iam/Properties/PolicyDocument/Statement/0/Principal");
                            } else {
                                match lhs.self_path().0.as_str() {
                                    "/Resources/iam/Properties/PolicyDocument/Statement/1/Principal/0" |
                                    "/Resources/iam/Properties/PolicyDocument/Statement/1/Principal/1" => {},
                                    _ => unreachable!()
                                }
                            }
                        }

                        _ => unreachable!(),
                    }
                }
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

macro_rules! test_case {
    ($rhs_value:expr, $lhs:expr, $eval:ident, $func:expr, $assert:expr) => {
        let lhs_gt_query = AccessQuery::try_from($lhs)?.query;
        let rhs_value = $rhs_value;
        let values = $eval.query(&lhs_gt_query)?;
        for each_lhs in values {
            match each_lhs {
                QueryResult::Resolved(res) => {
                    for cmp_result in each_lhs_compare(
                        $func,
                        res,
                        &[QueryResult::Resolved(Rc::new(rhs_value.clone()))],
                    )? {
                        match cmp_result {
                            ComparisonResult::Comparable(ComparisonWithRhs { outcome, .. }) => {
                                assert_eq!(outcome, $assert);
                            }

                            _ => {}
                        }
                    }
                }

                _ => unreachable!(),
            }
        }
    };
}

#[test]
fn binary_comparisons_gt_ge() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        values:
          int: 10
          ints: [20, 10]
          float: 1.0
          array: [1 ,2]
          string: Hi
    "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    //
    // Testing gt
    //
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.int"#,
        eval,
        crate::rules::path_value::compare_gt,
        true
    );
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.ints"#,
        eval,
        crate::rules::path_value::compare_gt,
        true
    );
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.int"#,
        eval,
        crate::rules::path_value::compare_ge,
        true
    );
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.ints"#,
        eval,
        crate::rules::path_value::compare_ge,
        true
    );
    test_case!(
        PathAwareValue::try_from("10")?,
        r#"values.ints"#,
        eval,
        crate::rules::path_value::compare_ge,
        true
    );

    test_case!(
        PathAwareValue::try_from("15")?,
        r#"values.int"#,
        eval,
        crate::rules::path_value::compare_gt,
        false
    );

    test_case!(
        PathAwareValue::try_from("0.5")?,
        r#"values.float"#,
        eval,
        crate::rules::path_value::compare_gt,
        true
    );
    test_case!(
        PathAwareValue::try_from("1.5")?,
        r#"values.float"#,
        eval,
        crate::rules::path_value::compare_gt,
        false
    );
    test_case!(
        PathAwareValue::try_from("1.0")?,
        r#"values.float"#,
        eval,
        crate::rules::path_value::compare_ge,
        true
    );

    test_case!(
        PathAwareValue::try_from(r#""Hi""#)?,
        r#"values.string"#,
        eval,
        crate::rules::path_value::compare_ge,
        true
    );
    test_case!(
        PathAwareValue::try_from(r#""Di""#)?,
        r#"values.string"#,
        eval,
        crate::rules::path_value::compare_gt,
        true
    );
    test_case!(
        PathAwareValue::try_from(r#""Ji""#)?,
        r#"values.string"#,
        eval,
        crate::rules::path_value::compare_gt,
        false
    );
    Ok(())
}

#[test]
fn binary_comparisons_lt_le() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        values:
          int: 10
          ints: [20, 10]
          float: 1.0
          array: [1 ,2]
          string: Hi
    "#,
    )?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    //
    // Testing gt
    //
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.int"#,
        eval,
        crate::rules::path_value::compare_lt,
        false
    );
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.ints"#,
        eval,
        crate::rules::path_value::compare_lt,
        false
    );
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.int"#,
        eval,
        crate::rules::path_value::compare_le,
        false
    );
    test_case!(
        PathAwareValue::try_from("8")?,
        r#"values.ints"#,
        eval,
        crate::rules::path_value::compare_le,
        false
    );

    test_case!(
        PathAwareValue::try_from("20")?,
        r#"values.ints"#,
        eval,
        crate::rules::path_value::compare_le,
        true
    );
    test_case!(
        PathAwareValue::try_from("15")?,
        r#"values.int"#,
        eval,
        crate::rules::path_value::compare_lt,
        true
    );

    test_case!(
        PathAwareValue::try_from("0.5")?,
        r#"values.float"#,
        eval,
        crate::rules::path_value::compare_lt,
        false
    );
    test_case!(
        PathAwareValue::try_from("1.0")?,
        r#"values.float"#,
        eval,
        crate::rules::path_value::compare_le,
        true
    );
    test_case!(
        PathAwareValue::try_from("1.5")?,
        r#"values.float"#,
        eval,
        crate::rules::path_value::compare_lt,
        true
    );

    test_case!(
        PathAwareValue::try_from(r#""Hi""#)?,
        r#"values.string"#,
        eval,
        crate::rules::path_value::compare_le,
        true
    );
    test_case!(
        PathAwareValue::try_from(r#""Di""#)?,
        r#"values.string"#,
        eval,
        crate::rules::path_value::compare_lt,
        false
    );
    test_case!(
        PathAwareValue::try_from(r#""Ji""#)?,
        r#"values.string"#,
        eval,
        crate::rules::path_value::compare_lt,
        true
    );
    Ok(())
}

#[test]
fn test_compare_rulegen() -> Result<()> {
    let rulegen_created = r#"
let aws_ec2_securitygroup_resources = Resources.*[ Type == 'AWS::EC2::SecurityGroup' ]
rule aws_ec2_securitygroup when %aws_ec2_securitygroup_resources !empty {
  %aws_ec2_securitygroup_resources.Properties.SecurityGroupEgress == [{"CidrIp":"0.0.0.0/0","IpProtocol":-1},{"CidrIpv6":"::/0","IpProtocol":-1}]
}"#;
    let template = r#"
Resources:

  # SecurityGroups
  ## Alb Security Groups

  rFrontendAppSpecificSg:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Frontend Security Group
      GroupName: secgrp-frontend
      SecurityGroupEgress:
        - CidrIp: "0.0.0.0/0"
          IpProtocol: -1
        - CidrIpv6: "::/0"
          IpProtocol: -1
      VpcId: vpc-123abc
    "#;
    let rules = RulesFile::try_from(rulegen_created)?;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(template)?)?;
    let mut root = root_scope(&rules, Rc::new(value));
    //let mut tracker = RecordTracker::new(&mut root);
    let status = eval_rules_file(&rules, &mut root, None)?;
    assert_eq!(status, Status::PASS);
    Ok(())
}

#[test]
fn block_guard_pass() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          iam:
            Type: AWS::IAM::Role
            Properties:
              PolicyDocument:
                Statement:
                  - Principal: '*'
                    Effect: Allow
                    Resource: ['s3*']
                  - Principal: [aws-123, aws-345]
                    Effect: Allow
                    Resource: '*'
          ecs:
            Type: AWS::ECS::Task
            Properties:
              Role:
                Ref: iam
        "#,
    )?)?;

    let block_clauses = GuardClause::try_from(
        r#"Resources[ Type == /Role/ ].Properties.PolicyDocument {
      Statement[*] {
         Principal != '*' <<No wildcard allowed for Principals>>
      }
    }
    "#,
    )?;

    let mut tracker = RecordTracker::new();
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: Some(&mut tracker),
    };
    let status = eval_guard_clause(&block_clauses, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);
    let top = tracker.extract();
    match top.container.as_ref() {
        Some(record) => {
            assert!(matches!(
                record,
                RecordType::BlockGuardCheck(BlockCheck {
                    status: Status::FAIL,
                    ..
                })
            ),);
            //
            // 2 Map Filters, 1 Block Clause
            //
            assert_eq!(top.children.len(), 3);
            let top_child = &top.children[2];
            assert!(matches!(
                top_child.container.as_ref().unwrap(),
                RecordType::BlockGuardCheck(BlockCheck {
                    status: Status::FAIL,
                    ..
                })
            ),);
            assert_eq!(top_child.children.len(), 2); // There are 2 Statements inside PolicyDocument
            for (idx, each) in top_child.children.iter().enumerate() {
                match each.container.as_ref() {
                    Some(inner) => {
                        if idx == 0 {
                            assert!(matches!(
                                inner,
                                RecordType::GuardClauseBlockCheck(BlockCheck {
                                    status: Status::FAIL,
                                    ..
                                })
                            ),);
                            assert_eq!(each.children.len(), 1); // only on principal value
                            let guard_rec = &each.children[0];
                            match guard_rec.container.as_ref().unwrap() {
                                RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                                    ComparisonClauseCheck {
                                        status: Status::FAIL,
                                        custom_message: Some(msg),
                                        message: None,
                                        comparison: (CmpOperator::Eq, true),
                                        from: QueryResult::Resolved(from_q),
                                        to: Some(QueryResult::Resolved(_)),
                                    },
                                )) => {
                                    assert_eq!(msg, "No wildcard allowed for Principals");
                                    assert_eq!(from_q.self_path().0.as_str(), "/Resources/iam/Properties/PolicyDocument/Statement/0/Principal");
                                }
                                _ => unreachable!(),
                            }
                        } else {
                            assert!(matches!(
                                inner,
                                RecordType::GuardClauseBlockCheck(BlockCheck {
                                    status: Status::PASS,
                                    ..
                                })
                            ),);
                            assert_eq!(each.children.len(), 2); // there are 2 principal values
                            for each_clause_check in &each.children {
                                match &each_clause_check.container {
                                    Some(RecordType::ClauseValueCheck(ClauseCheck::Success)) => {}
                                    _ => unreachable!(),
                                }
                            }
                        }
                    }
                    None => unreachable!(),
                }
            }
        }
        None => unreachable!(),
    }

    Ok(())
}

#[test]
fn test_guard_10_compatibility_and_diff() -> Result<()> {
    let value_str = r###"
    Statement:
      - Principal: ['*', 's3:*']
    "###;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    //
    // Evaluation differences with 1.0 for Statement.*.Principal == '*'
    //
    // Guard 1.0 this would PASS with at-least one semantics for the payload above. This is where docs
    // need to be consulted to understand that == is at-least-one and != is ALL. Due to this decision certain
    // expressions like ensure that ALL AWS::EC2::Volume Encrypted == true, could not be specified
    //
    // In Guard 2.0 this would FAIL. The reason being that Guard 2.0 goes for explicitness in specifying
    // clauses. By default it asserts for ALL semantics. If you expecting to match at-least one or more
    // you must use SOME keyword that would evaluate correctly. With this support in 2.0 we can
    // support ALL expressions like
    //
    //        AWS::EC2::Volume Properties.Encrypted == true
    //
    // At the same time, one can explicitly express at-least-one or more semantics using SOME
    //
    //         AWS::EC2::Volume SOME Properties.Encrypted == true
    //
    // And finally
    //
    //       AWS::EC2::Volume Properties {
    //             Encrypted !EXISTS or
    //             Encrypted == true
    //       }
    //
    // can be correctly specified. This also makes the intent clear to both the rule author and
    // auditor what was acceptable. Here, it is okay that accept Encrypted was not specified
    // as an attribute or when specified it must be true. This makes it clear to the reader/auditor
    // rather than guess at how Guard engine evaluates.
    //
    // The evaluation engine is purposefully dumb and stupid, defaults to working
    // one way consistently enforcing ALL semantics. Needs to told explicitly to do otherwise
    //

    let clause_str = r#"Statement.*.Principal == '*'"#;
    let clause = GuardClause::try_from(clause_str)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause_str = r#"SOME Statement.*.Principal == '*'"#;
    let clause = GuardClause::try_from(clause_str)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let value_str = r###"
    Statement:
      - Principal: aws
      - Principal: ['*', 's3:*']
    "###;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    //
    // Evaluate the SOME clause again, it must pass with the value as well
    //
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn block_evaluation() -> Result<()> {
    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true
                    'aws:sourceVpc': ['vpc-1234']
              - Action: Allow
                Resource: ['*', "aws:"]

    "#;
    let value = serde_yaml::from_str::<serde_yaml::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let clause_str = r#"Resources.*[ Type == 'AWS::ApiGateway::RestApi' ].Properties {
        EndpointConfiguration == ["PRIVATE"]
        some Policy.Statement[*] {
            Action == 'Allow'
            Condition[ keys == 'aws:IsSecure' ] !empty
        }
    }
    "#;
    let clause = GuardClause::try_from(clause_str)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);
    Ok(())
}

#[test]
fn block_evaluation_fail() -> Result<()> {
    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true
                    'aws:sourceVpc': ['vpc-1234']
              - Action: Allow
                Resource: ['*', "aws:"]
      apiGw2:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]

    "#;
    let value = serde_yaml::from_str::<serde_yaml::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let clause_str = r#"Resources.*[ Type == 'AWS::ApiGateway::RestApi' ].Properties {
        EndpointConfiguration == ["PRIVATE"]
        some Policy.Statement[*] {
            Action == 'Allow'
            Condition[ keys == 'aws:IsSecure' ] !empty
        }
    }
    "#;
    let clause = GuardClause::try_from(clause_str)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

#[test]
fn variable_projections() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          s3_bucket:
            Type: AWS::S3::Bucket
          s3_bucket_policy:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket:
                Ref: s3_bucket
          s3_bucket_policy_2:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket: aws:arn
        "#,
    )?)?;

    let rules_file = RulesFile::try_from(
        r#"
    let policies = Resources[ Type == /BucketPolicy$/ ]
    rule policies_check when %policies not empty { # testing no view projection check
      %policies.Properties.Bucket exists
      %policies.Properties.Bucket not empty # checks both Map not empty/ string not empty
      #
      # checks Ref's value is not empty. This has 2 results, one FAILure for s3_bucket_policy_2
      # one PASS for s3_bucket_policy. Due to some keyword it does PASS
      #
      some %policies.Properties.Bucket.Ref not empty
    }
    "#,
    )?;
    let mut root_scope = root_scope(&rules_file, Rc::new(path_value));
    let status = eval_rules_file(&rules_file, &mut root_scope, None)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn variable_projections_failures() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          s3_bucket:
            Type: AWS::S3::Bucket
          s3_bucket_policy:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket:
                Ref: s3_bucket
          s3_bucket_policy_2:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket: ""
        "#,
    )?)?;

    let rules_file = RulesFile::try_from(
        r#"
    let policies = Resources[ Type == /BucketPolicy$/ ]
    rule policies_check when %policies not empty { # testing no view projection check
      %policies.Properties.Bucket exists
      %policies.Properties.Bucket not empty # checks both Map not empty/ string not empty
      #
      # checks Ref's value is not empty. This has 2 results, one FAILure for s3_bucket_policy_2
      # one PASS for s3_bucket_policy. Due to some keyword it does PASS
      #
      some %policies.Properties.Bucket.Ref not empty
    }
    "#,
    )?;
    let mut root_scope = root_scope(&rules_file, Rc::new(path_value));
    let status = eval_rules_file(&rules_file, &mut root_scope, None)?;
    assert_eq!(status, Status::FAIL); // for s3_bucket_policy_2.Properties.Bucket == ""

    let top = root_scope.reset_recorder().extract();
    assert_eq!(top.children.len(), 1); // one rule
    let rule = &top.children[0];
    assert_eq!(rule.children.len(), 4); // 1 one for rule condition, 3 for rule clauses
                                        //assert_eq!(matches!(rule_block.container, Some(RecordType::RuleBlock(Status::FAIL))), true);
    for (idx, each_rule_clause) in rule.children.iter().enumerate() {
        if idx == 0 {
            // Condition block
            assert!(matches!(
                each_rule_clause.container,
                Some(RecordType::RuleCondition(Status::PASS))
            ),);
            assert_eq!(each_rule_clause.children.len(), 1); //
            let gbc = &each_rule_clause.children[0];
            assert!(matches!(
                gbc.container,
                Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                    status: Status::PASS,
                    ..
                }))
            ),);
        } else if idx == 2 {
            assert!(matches!(
                each_rule_clause.container,
                Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                    status: Status::FAIL,
                    ..
                }))
            ),);
            assert_eq!(each_rule_clause.children.len(), 2); //
            let failed_clause = &each_rule_clause.children[1];
            assert!(matches!(
                failed_clause.container,
                Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(
                    UnaryValueCheck {
                        comparison: (CmpOperator::Empty, true),
                        value: ValueCheck {
                            status: Status::FAIL,
                            ..
                        }
                    }
                )))
            ),);
        } else {
            assert!(matches!(
                each_rule_clause.container,
                Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                    status: Status::PASS,
                    ..
                }))
            ),);
        }
    }

    Ok(())
}

#[test]
fn query_cross_joins() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          s3_bucket:
            Type: AWS::S3::Bucket
          s3_bucket_policy:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket:
                Ref: s3_bucket
        "#,
    )?)?;
    let rules_files = RulesFile::try_from(
        r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#,
    )?;
    let mut root_scope = root_scope(&rules_files, Rc::new(path_value.clone()));
    let status = eval_rules_file(&rules_files, &mut root_scope, None)?;
    assert_eq!(status, Status::PASS);

    let rules_files = RulesFile::try_from(
        r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /NotBucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#,
    )?;
    let mut root_scope = eval_context::root_scope(&rules_files, Rc::new(path_value));
    let status = eval_rules_file(&rules_files, &mut root_scope, None)?;
    assert_eq!(status, Status::SKIP);

    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          s3_bucket:
            Type: AWS::S3::Bucket
          s3_bucket_policy:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket:
                Ref: s3_bucket
          s3_bucket_policy_2:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket: aws:arn...
        "#,
    )?)?;

    //
    // NO some present for assignment, hence failure
    //
    let rules_files = RulesFile::try_from(
        r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#,
    )?;
    let mut root_scope = eval_context::root_scope(&rules_files, Rc::new(path_value.clone()));
    let status = eval_rules_file(&rules_files, &mut root_scope, None)?;
    assert_eq!(status, Status::FAIL);

    //
    // Using SOME to indicate not all BucketPolicy object will have Bucket References. In
    // our payload s3_bucket_policy_2 is skipped as it does not resolve
    //
    let rules_files = RulesFile::try_from(
        r#"
    rule s3_cross_query_join {
       let policies = some Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#,
    )?;
    let mut root_scope = eval_context::root_scope(&rules_files, Rc::new(path_value.clone()));
    let status = eval_rules_file(&rules_files, &mut root_scope, None)?;
    assert_eq!(status, Status::PASS);

    //
    // Using SOME at the block level will yield the same result
    // s3_bucket_policy_2 is skipped
    //
    let rules_files = RulesFile::try_from(
        r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       some Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#,
    )?;
    let mut root_scope = eval_context::root_scope(&rules_files, Rc::new(path_value));
    let status = eval_rules_file(&rules_files, &mut root_scope, None)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn cross_rule_clause_when_checks() -> Result<()> {
    let rules_skipped = r#"
    rule skipped when skip !exists {
        Resources.*.Properties.Tags !empty
    }

    rule dependent_on_skipped when skipped {
        Resources.*.Properties exists
    }

    rule dependent_on_dependent when dependent_on_skipped {
        Resources.*.Properties exists
    }

    rule dependent_on_not_skipped when !skipped {
        Resources.*.Properties exists
    }
    "#;

    let input = r#"
    {
        skip: true,
        Resources: {
            first: {
                Type: 'WhackWhat',
                Properties: {
                    Tags: [{ hi: "there" }, { right: "way" }]
                }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules = RulesFile::try_from(rules_skipped)?;
    let mut root = root_scope(&rules, Rc::new(resources));
    let status = eval_rules_file(&rules, &mut root, None)?;
    assert_eq!(status, Status::PASS);
    let mut expectations = HashMap::with_capacity(4);
    expectations.insert("skipped".to_string(), Status::SKIP);
    expectations.insert("dependent_on_skipped".to_string(), Status::SKIP);
    expectations.insert("dependent_on_dependent".to_string(), Status::SKIP);
    expectations.insert("dependent_on_not_skipped".to_string(), Status::PASS);
    let rules_results = root.reset_recorder().extract().children;
    assert_eq!(rules_results.len(), 4);
    for each in rules_results {
        match each.container {
            Some(RecordType::RuleCheck(status)) => {
                assert_eq!(expectations.get(status.name), Some(&status.status));
            }

            _ => unreachable!(),
        }
    }

    let input = r#"
    {
        Resources: {
            first: {
                Type: 'WhackWhat',
                Properties: {
                    Tags: [{ hi: "there" }, { right: "way" }]
                }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let mut root = root_scope(&rules, Rc::new(resources));
    let status = eval_rules_file(&rules, &mut root, None)?;
    assert_eq!(status, Status::PASS);
    expectations.clear();
    expectations.insert("skipped".to_string(), Status::PASS);
    expectations.insert("dependent_on_skipped".to_string(), Status::PASS);
    expectations.insert("dependent_on_dependent".to_string(), Status::PASS);
    expectations.insert("dependent_on_not_skipped".to_string(), Status::SKIP);

    let rules_results = root.reset_recorder().extract().children;
    assert_eq!(rules_results.len(), 4);
    for each in rules_results {
        match each.container {
            Some(RecordType::RuleCheck(status)) => {
                assert_eq!(expectations.get(status.name), Some(&status.status));
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
fn test_field_type_array_or_single() -> Result<()> {
    let statements = r#"{
        Statement: [{
            Action: '*',
            Effect: 'Allow',
            Resources: '*'
        }, {
            Action: ['api:Get', 'api2:Set'],
            Effect: 'Allow',
            Resources: '*'
        }]
    }
    "#;
    let path_value = PathAwareValue::try_from(statements)?;
    let clause = GuardClause::try_from(r#"Statement[*].Action != '*'"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let statements = r#"{
        Statement: {
            Action: '*',
            Effect: 'Allow',
            Resources: '*'
        }
    }
    "#;
    let path_value = PathAwareValue::try_from(statements)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"Statement[*].Action[*] != '*'"#)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    // Test old format
    let clause = GuardClause::try_from(r#"Statement.*.Action.* != '*'"#)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"some Statement[*].Action == '*'"#)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let clause = GuardClause::try_from(r#"some Statement[*].Action != '*'"#)?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_for_in_and_not_in() -> Result<()> {
    let statements = r#"
    {
      "mainSteps": [
          {
            "action": "aws:updateAgent"
          },
          {
            "action": "aws:configurePackage"
          }
        ]
    }"#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(statements)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };

    let clause = GuardClause::try_from(
        r#"mainSteps[*].action !IN ["aws:updateSsmAgent", "aws:updateAgent"]"#,
    )?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(
        r#"mainSteps[*].action IN ["aws:updateSsmAgent", "aws:updateAgent"]"#,
    )?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(
        r#"some mainSteps[*].action IN ["aws:updateSsmAgent", "aws:updateAgent"]"#,
    )?;
    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_rule_with_range_test_and_this() -> Result<()> {
    let rule_str = r#"rule check_parameter_validity {
     InputParameter.TcpBlockedPorts[*] {
         this in r[0, 65535] <<[NON_COMPLIANT] Parameter TcpBlockedPorts has invalid value.>>
     }
 }"#;

    let rule = Rule::try_from(rule_str)?;

    let value_str = r#"
    InputParameter:
        TcpBlockedPorts:
            - 21
            - 22
            - 101
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let value_str = r#"
    InputParameter:
        TcpBlockedPorts:
            - 21
            - 22
            - 101
            - 100000
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_inner_when_skipped() -> Result<()> {
    let rule_str = r#"
    rule no_wild_card_in_managed_policy {
        Resources[ Type == /ManagedPolicy/ ] {
            when Properties.ManagedPolicyName != /Admin/ {
                Properties.PolicyDocument.Statement[*].Action[*] != '*'
            }
        }
    }
    "#;

    let rule = Rule::try_from(rule_str)?;
    let value_str = r#"
    Resources:
      ReadOnlyAdminPolicy:
        Type: 'AWS::IAM::ManagedPolicy'
        Properties:
          PolicyDocument:
            Statement:
              - Action: '*'
                Effect: Allow
                Resource: '*'
            Version: 2012-10-17
          Description: ''
          ManagedPolicyName: AdminPolicy
      ReadOnlyPolicy:
        Type: 'AWS::IAM::ManagedPolicy'
        Properties:
          PolicyDocument:
            Statement:
              - Action:
                  - 'cloudwatch:*'
                  - '*'
                Effect: Allow
                Resource: '*'
            Version: 2013-10-17
          Description: ''
          ManagedPolicyName: OperatorPolicy
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r#"
    Resources:
      ReadOnlyAdminPolicy:
        Type: 'AWS::IAM::ManagedPolicy'
        Properties:
          PolicyDocument:
            Statement:
              - Action: '*'
                Effect: Allow
                Resource: '*'
            Version: 2012-10-17
          Description: ''
          ManagedPolicyName: AdminPolicy
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::SKIP);

    let value_str = r#"
    Resources: {}
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::SKIP);

    let value_str = r#"{}"#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value_str)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_multiple_valued_clause_reporting() -> Result<()> {
    struct ReportAssertions {}

    impl<'value> RecordTracer<'value> for ReportAssertions {
        fn start_record(&mut self, _context: &str) -> Result<()> {
            Ok(())
        }

        fn end_record(&mut self, _context: &str, record: RecordType<'value>) -> Result<()> {
            match record {
                RecordType::GuardClauseBlockCheck(BlockCheck {
                    message,
                    status,
                    at_least_one_matches,
                }) => {
                    assert_eq!(message, None);
                    assert_eq!(status, Status::FAIL);
                    assert!(!at_least_one_matches);
                }

                RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                    status,
                    from,
                    to,
                    ..
                })) => {
                    assert!(to.is_some());
                    assert_eq!(status, Status::FAIL);
                    match from {
                        QueryResult::Resolved(res) => {
                            assert!(
                                res.self_path().0.as_str() == "/Resources/second/Properties/Name"
                                    || res.self_path().0.as_str()
                                        == "/Resources/failed/Properties/Name",
                            );
                        }

                        _ => unreachable!(),
                    }
                }

                RecordType::ClauseValueCheck(ClauseCheck::Success) => {}

                RecordType::RuleCheck(NamedStatus { name, status, .. }) => {
                    assert_eq!(name, "name_check");
                    assert_eq!(status, Status::FAIL);
                }

                RecordType::FileCheck(NamedStatus { status, .. }) => {
                    assert_eq!(status, Status::FAIL);
                }

                _ => unreachable!(),
            }
            Ok(())
        }
    }

    let rule = r###"
    rule name_check { Resources.*.Properties.Name == /NAME/ }
    "###;

    let value = r###"
    Resources:
      second:
        Properties:
          Name: FAILEDMatch
      first:
        Properties:
          Name: MatchNAME
      matches:
        Properties:
          Name: MatchNAME
      failed:
        Properties:
          Name: FAILEDMatch
    "###;

    let rules = Rule::try_from(rule)?;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value)?)?;
    let mut asserter = ReportAssertions {};
    let mut root = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: Some(&mut asserter),
    };
    let status = eval_rule(&rules, &mut root, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let rule = r###"
    let resources = Resources.*
    rule name_check { %resources.Properties.Name == /NAME/ }
    "###;

    let rules = RulesFile::try_from(rule)?;
    let mut root = root_scope(&rules, Rc::new(values));
    let status = eval_rules_file(&rules, &mut root, None)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[rstest::rstest]
#[case("SubdomainMaster", "Master.PrivateIp", Status::PASS)]
#[case("SubdomainInternal", "Master.PrivateIp", Status::PASS)]
#[case("SubdomainDefault", "Infra1.PrivateIp", Status::PASS)]
#[case("SubdomainDefault", "Infra1.PrivateIp", Status::PASS)]
#[case("Subdomain", "Infra1.PrivateIp", Status::FAIL)]
#[case("SubdomainDefault", "Infra1.PublicIp", Status::FAIL)]
#[case("Subdomain", "Master.PrivateIp", Status::FAIL)]
#[case("SubdomainDefault", "Master.PublicIp", Status::FAIL)]
fn test_in_comparison_operator_for_list_of_lists(
    #[case] name_arg: &str,
    #[case] resource_records_arg: &str,
    #[case] status_arg: Status,
) -> Result<()> {
    let template = formatdoc! {
        r###"
        Resources:
            MasterRecord:
                Type: AWS::Route53::RecordSet
                Properties:
                    HostedZoneName: !Ref 'HostedZoneName'
                    Comment: DNS name for my instance.
                    Name: !Join ['', [!Ref '{}', ., !Ref 'HostedZoneName']]
                    Type: A
                    TTL: "900"
                    ResourceRecords:
                    - !GetAtt '{}'"###,
        name_arg,
        resource_records_arg,
    };

    let rules = r#"
    let aws_route53_recordset_resources = Resources.*[ Type == 'AWS::Route53::RecordSet' ]
    rule aws_route53_recordset when %aws_route53_recordset_resources !empty {
      let targets = [{"Fn::Join": ["",[{"Ref": "SubdomainMaster"},".", {"Ref": "HostedZoneName"}]]}, {"Fn::Join": ["",[{"Ref": "SubdomainWild"},".", {"Ref": "HostedZoneName"}]]}, {"Fn::Join": ["",[{"Ref": 'SubdomainInternal'},".", {"Ref": "HostedZoneName"}]]}, {"Fn::Join": ["",[{"Ref": "SubdomainDefault"},".", {"Ref": "HostedZoneName"}]]}]
      %aws_route53_recordset_resources.Properties.Comment == "DNS name for my instance."
      %aws_route53_recordset_resources.Properties.ResourceRecords IN [[{"Fn::GetAtt": "Master.PrivateIp"}], [{"Fn::GetAtt": "Infra1.PrivateIp"}]]
      %aws_route53_recordset_resources.Properties.Name IN %targets
      %aws_route53_recordset_resources.Properties.Type == "A"
      %aws_route53_recordset_resources.Properties.TTL == "900"
      %aws_route53_recordset_resources.Properties.HostedZoneName == {"Ref": "HostedZoneName"}
    }
    "#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(&template)?)?;
    let rule_eval = RulesFile::try_from(rules)?;
    let mut context = root_scope(&rule_eval, Rc::new(value));
    let status = eval_rules_file(&rule_eval, &mut context, None)?;
    assert_eq!(status, status_arg);

    Ok(())
}

#[rstest::rstest]
#[case(r#"'900'"#, Status::PASS)]
#[case(r#"!!str 900"#, Status::PASS)]
#[case(r#"900"#, Status::FAIL)]
#[case(r#"!!int "900""#, Status::FAIL)]
#[case(r#"!!float "900""#, Status::FAIL)]
fn test_type_conversions(#[case] ttl_arg: &str, #[case] status_arg: Status) -> Result<()> {
    let template = formatdoc! {
        r###"
        Resources:
            MasterRecord:
                Type: AWS::Route53::RecordSet
                Properties:
                    TTL: {}
                    "###,
        ttl_arg,
    };

    let rules = r#"
    let aws_route53_recordset_resources = Resources.*[ Type == 'AWS::Route53::RecordSet' ]
    rule aws_route53_recordset when %aws_route53_recordset_resources !empty {
      %aws_route53_recordset_resources.Properties.TTL == "900"
    }
    "#;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(&template)?)?;
    let rule_eval = RulesFile::try_from(rules)?;
    let mut context = root_scope(&rule_eval, Rc::new(value));
    let status = eval_rules_file(&rule_eval, &mut context, None)?;
    assert_eq!(status, status_arg);

    Ok(())
}

#[test]
fn is_bool() -> Result<()> {
    let rule_str = r###"
    rule check_is_bool{
        foo is_bool
    }
    "###;

    let resources_str = r###"
    {
        foo: false
    }
    "###;

    let value = PathAwareValue::try_from(resources_str)?;
    let rules_file = RulesFile::try_from(rule_str)?;
    println!("{:?}", rules_file);
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::PASS);

    let resources_str = r#"
    {
        foo: "false"
    }
    "#;
    let value = PathAwareValue::try_from(resources_str)?;
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn is_int() -> Result<()> {
    let rule_str = r###"
    rule check_is_int{
        foo is_int
    }
    "###;

    let resources_str = r###"
    {
        foo: 1
    }
    "###;

    let value = PathAwareValue::try_from(resources_str)?;
    let rules_file = RulesFile::try_from(rule_str)?;
    println!("{:?}", rules_file);
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::PASS);

    let resources_str = r#"
    {
        foo: "1"
    }
    "#;
    let value = PathAwareValue::try_from(resources_str)?;
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn double_projection_tests() -> Result<()> {
    let rule_str = r###"
    rule check_ecs_against_local_or_metadata {
        let ecs_tasks = Resources.*[
            Type == 'AWS::ECS::TaskDefinition'
            Properties.TaskRoleArn exists
        ]

        let iam_references = some %ecs_tasks.Properties.TaskRoleArn.'Fn::GetAtt'[0]
        when %iam_references !empty {
            let iam_local = Resources.%iam_references
            %iam_local.Type == 'AWS::IAM::Role'
            %iam_local.Properties.PermissionsBoundary exists
        }

        let ecs_task_role_is_string = %ecs_tasks[
            Properties.TaskRoleArn is_string
        ]
        when %ecs_task_role_is_string !empty {
            %ecs_task_role_is_string.Metadata.NotRestricted exists
        }
    }
    "###;

    let resources_str = r#"
    {
        Resources: {
            ecs: {
                Type: 'AWS::ECS::TaskDefinition',
                Metadata: {
                    NotRestricted: true
                },
                Properties: {
                    TaskRoleArn: "aws:arn..."
                }
            },
            ecs2: {
              Type: 'AWS::ECS::TaskDefinition',
              Properties: {
                TaskRoleArn: { 'Fn::GetAtt': ["iam", "arn"] }
              }
            },
            iam: {
              Type: 'AWS::IAM::Role',
              Properties: {
                PermissionsBoundary: "aws:arn"
              }
            }
        }
    }
    "#;

    let value = PathAwareValue::try_from(resources_str)?;
    let rules_file = RulesFile::try_from(rule_str)?;
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::PASS);

    let resources_str = r#"
    {
        Resources: {
            ecs2: {
              Type: 'AWS::ECS::TaskDefinition',
              Properties: {
                TaskRoleArn: { 'Fn::GetAtt': ["iam", "arn"] }
              }
            }
        }
    }
    "#;
    let value = PathAwareValue::try_from(resources_str)?;
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_rules_with_some_clauses() -> Result<()> {
    let query = r#"let x = some Resources.*[ Type == 'AWS::IAM::Role' ].Properties.Tags[ Key == /[A-Za-z0-9]+Role/ ]"#;
    let resources = r#"    {
      "Resources": {
          "CounterTaskDefExecutionRole5959CB2D": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "AssumeRolePolicyDocument": {
                      "Statement": [
                      {
                          "Action": "sts:AssumeRole",
                          "Effect": "Allow",
                          "Principal": {
                          "Service": "ecs-tasks.amazonaws.com"
                          }
                      }],
                      "Version": "2012-10-17"
                  },
                  "PermissionsBoundary": {"Fn::Sub" : "arn::aws::iam::${AWS::AccountId}:policy/my-permission-boundary"},
                  "Tags": [{ "Key": "TestRole", "Value": ""}]
              },
              "Metadata": {
                  "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
              }
          },
          "BlankRole001": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "AssumeRolePolicyDocument": {
                      "Statement": [
                      {
                          "Action": "sts:AssumeRole",
                          "Effect": "Allow",
                          "Principal": {
                          "Service": "ecs-tasks.amazonaws.com"
                          }
                      }],
                      "Version": "2012-10-17"
                  },
                  "Tags": [{ "Key": "FooBar", "Value": ""}]
              },
              "Metadata": {
                  "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
              }
          },
          "BlankRole002": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "AssumeRolePolicyDocument": {
                      "Statement": [
                      {
                          "Action": "sts:AssumeRole",
                          "Effect": "Allow",
                          "Principal": {
                          "Service": "ecs-tasks.amazonaws.com"
                          }
                      }],
                      "Version": "2012-10-17"
                  }
              },
              "Metadata": {
                  "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
              }
          }
      }
    }
    "#;
    let value = PathAwareValue::try_from(resources)?;
    let parsed = RulesFile::try_from(query)?;
    let mut eval = root_scope(&parsed, Rc::new(value));
    let selected = eval.resolve_variable("x")?;
    println!("{:?}", selected);
    assert_eq!(selected.len(), 1);

    Ok(())
}

#[test]
fn test_support_for_atleast_one_match_clause() -> Result<()> {
    let clause_some_str = r#"some Tags[*].Key == /PROD/"#;
    let clause_some = GuardClause::try_from(clause_some_str)?;

    let clause_str = r#"Tags[*].Key == /PROD/"#;
    let clause = GuardClause::try_from(clause_str)?;

    let values_str = r#"{
        Tags: [
            {
                Key: "InPROD",
                Value: "ProdApp"
            },
            {
                Key: "NoP",
                Value: "NoQ"
            }
        ]
    }
    "#;
    let values = PathAwareValue::try_from(values_str)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };

    let status = eval_guard_clause(&clause_some, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"{ Tags: [] }"#;
    let values = PathAwareValue::try_from(values_str)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let status = eval_guard_clause(&clause_some, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"{ }"#;
    let values = PathAwareValue::try_from(values_str)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&clause_some, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let status = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    //
    // Trying out the selection filters
    //
    let selection_str = r#"Resources[
        Type == 'AWS::DynamoDB::Table'
        some Properties.Tags[*].Key == /PROD/
    ]"#;
    let resources_str = r#"{
        Resources: {
            ddbSelected: {
                Type: 'AWS::DynamoDB::Table',
                Properties: {
                    Tags: [
                        {
                            Key: "PROD",
                            Value: "ProdApp"
                        }
                    ]
                }
            },
            ddbNotSelected: {
                Type: 'AWS::DynamoDB::Table'
            }
        }
    }"#;
    let _resources = PathAwareValue::try_from(resources_str)?;
    let selection_query = AccessQuery::try_from(selection_str)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let selected = eval.query(&selection_query.query)?;
    println!("Selected = {:?}", selected);
    assert_eq!(selected.len(), 1);

    Ok(())
}

#[test]
fn test_map_keys_function() -> Result<()> {
    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true

    "#;
    let value = serde_yaml::from_str::<serde_yaml::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;

    let rule_str = r#"
let api_gw = Resources[ Type == 'AWS::ApiGateway::RestApi' ]
rule check_rest_api_is_private_and_has_access {
    %api_gw {
      Properties.EndpointConfiguration == ["PRIVATE"]
      some Properties.Policy.Statement[*].Condition[ keys == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !empty
    }
}"#;
    let rule = RulesFile::try_from(rule_str)?;
    let mut root = root_scope(&rule, Rc::new(value));
    let status = eval_rules_file(&rule, &mut root, None)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r#"
    Resources:
      apiGw:
        Type: 'AWS::ApiGateway::RestApi'
        Properties:
          EndpointConfiguration: ["PRIVATE"]
          Policy:
            Statement:
              - Action: Allow
                Resource: ['*', "aws:"]
                Condition:
                    'aws:IsSecure': true
                    'aws:sourceVpc': ['vpc-1234']

    "#;
    let value = serde_yaml::from_str::<serde_yaml::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let mut root = root_scope(&rule, Rc::new(value));
    let status = eval_rules_file(&rule, &mut root, None)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn ensure_all_list_value_access_on_empty_fails() -> Result<()> {
    let resources = r#"Tags: []"#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let claused_failure_spec = GuardClause::try_from(r#"Tags[*].Key == /Name/"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(r#"some Tags[*].Key == /Name/"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(r#"Tags[*] { Key == /Name/ }"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(r#"some Tags[*] { Key == /Name/ }"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(r#"Tags !empty"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(r#"Tags empty"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let claused_failure_spec = GuardClause::try_from(r#"Tags[*] !empty"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(r#"Tags[*] empty"#)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let status = eval_guard_clause(&claused_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn ensure_all_map_values_access_on_empty_fails() -> Result<()> {
    let resources = r#"Resources: {}"#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values.clone()),
        recorder: None,
    };

    let clause_failure_spec = GuardClause::try_from(r#"Resources.*.Properties exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause_failure_spec = GuardClause::try_from(r#"Resources.* { Properties exists }"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let clause_failure_spec = GuardClause::try_from(r#"Resources exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    //
    // Resources is empty, hence FAIL
    //
    let clause_failure_spec =
        GuardClause::try_from(r#"Resources[ Type == /Bucket/ ].Properties exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::SKIP);

    //
    // Resource present filter did not select, SKIP
    //
    let resources = r#"
    Resources:
      ec2:
        Type: AWS::EC2::Instance
        Properties:
          ImageId: ami-1234554657
    "#;
    let _value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let status = eval_guard_clause(&clause_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::SKIP);

    //
    // No resources present
    //
    let resources = r#"{}"#;
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let clause_failure_spec = GuardClause::try_from(r#"Resources exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

fn find_failed_clauses<'event, 'value>(
    root: &'event EventRecord<'value>,
) -> Vec<&'event EventRecord<'value>> {
    match &root.container {
        Some(RecordType::Filter(_)) | Some(RecordType::ClauseValueCheck(ClauseCheck::Success)) => {
            vec![]
        }

        Some(RecordType::ClauseValueCheck(_)) => vec![root],

        _ => {
            let mut acc = Vec::new();
            for child in &root.children {
                acc.extend(find_failed_clauses(child));
            }
            acc
        }
    }
}

#[test]
fn filter_based_join_clauses_failures_and_skips() -> Result<()> {
    let resources = r#"
    Resources:
      function:
        Type: AWS::Lambda::Function
        Properties:
          Code: ''
          Role:
            Ref: iam
      function2:
        Type: AWS::Lambda::Function
        Properties:
          Code: ''
          Role: aws:arn
      iam:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: ['*']
      iam2:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: '*'
    "#;

    let rules = r###"
    rule ensure_lambda_role_local_stack {
      let with_refs = some Resources[ Type == 'AWS::Lambda::Function' ].Properties.Role.Ref
      Resources.%with_refs {
         Type == 'AWS::IAM::Role'
         Properties.PolicyDocument.Statement[*] {
           Action != '*'
           Principal != '*'
         }
      }
    }
    "###;

    let rules_file = RulesFile::try_from(rules)?;
    let path_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let mut eval = root_scope(&rules_file, Rc::new(path_value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::FAIL);

    let top = eval.reset_recorder().extract();
    let failed_clauses = find_failed_clauses(&top);
    assert_eq!(failed_clauses.len(), 2);
    for each in failed_clauses {
        if let Some(RecordType::ClauseValueCheck(check)) = &each.container {
            match check {
                ClauseCheck::Comparison(ComparisonClauseCheck { status, from, .. }) => {
                    assert_eq!(*status, Status::FAIL);
                    assert!(each.context.contains("Action") || each.context.contains("Principal"),);
                    assert!(from.resolved().map_or(false, |res| {
                        let path = res.self_path().0.as_str();
                        path == "/Resources/iam/Properties/PolicyDocument/Statement/Action"
                            || path
                                == "/Resources/iam/Properties/PolicyDocument/Statement/Principal/0"
                    }))
                }

                _ => unreachable!(),
            }
        }
    }

    //
    // No Lambda resources present, expect SKIP, same rules file
    //

    let resources = r#"
    Resources:
      iam:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: ['*']
      iam2:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: '*'
    "#;
    let path_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let mut eval = root_scope(&rules_file, Rc::new(path_value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::SKIP);

    //
    // Lambda resources not connected IAM, expect skip
    //
    let resources = r#"
    Resources:
      function2:
        Type: AWS::Lambda::Function
        Properties:
          Code: ''
          Role: aws:arn
      iam:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: ['*']
    "#;
    let path_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let mut eval = eval.reset_root(Rc::new(path_value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::SKIP);

    //
    // Lambda resource present, but have dangling reference
    //

    let resources = r###"
    Resources:
      function:
        Type: AWS::Lambda::Function
        Properties:
          Code: ''
          Role:
            Ref: iamNotThere # dangling reference
      iam:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: ['*']
    "###;
    let path_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;

    let mut eval = eval.reset_root(Rc::new(path_value));

    //
    // Let us track failures and assert on what must be observed
    //
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::FAIL);

    let top = eval.reset_recorder().extract();
    let failed_clauses = find_failed_clauses(&top);
    assert_eq!(failed_clauses.len(), 1);
    match &failed_clauses[0].container {
        Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(check))) => {
            assert_eq!(check.status, Status::FAIL);
            assert_eq!(check.from.resolved(), None);
        }
        _ => unreachable!(),
    }

    Ok(())
}

#[test]
fn filter_based_with_join_pass_use_cases() -> Result<()> {
    let resources = r#"
    Resources:
      function:
        Type: AWS::Lambda::Function
        Properties:
          Code: ''
          Role:
            Ref: iam
      function2:
        Type: AWS::Lambda::Function
        Properties:
          Code: ''
          Role: aws:arn
      iam:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: ['*']
      iam2:
        Type: AWS::IAM::Role
        Properties:
          PolicyDocument:
            Statement:
              Action: '*'
              Resource: '*'
              Effect: Allow
              Principal: '*'
    "#;

    let rules = r###"
    rule ensure_lambda_role_local_stack {
      let with_refs = some Resources[ Type == 'AWS::Lambda::Function' ].Properties.Role.Ref
      Resources.%with_refs {
         Type == 'AWS::IAM::Role'
         Properties.PolicyDocument.Statement[*] {
           Action == '*'
           Principal == '*'
         }
      }
    }
    "###;

    let path_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut eval = root_scope(&rules_file, Rc::new(path_value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn rule_clause_tests() -> Result<()> {
    let r = r###"
    rule check_all_resources_have_tags_present {
    let all_resources = Resources.*.Properties

    %all_resources.Tags EXISTS
    %all_resources.Tags !EMPTY
}
    "###;
    let rule = RulesFile::try_from(r)?;

    let v = r#"
    {
        "Resources": {
            "vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/25",
                    "Tags": [
                        {
                            "Key": "my-vpc",
                            "Value": "my-vpc"
                        }
                    ]
                }
            }
        }
    }
    "#;

    let value = PathAwareValue::try_from(v)?;
    let mut eval = root_scope(&rule, Rc::new(value));
    let status = eval_rules_file(&rule, &mut eval, None)?;
    assert_eq!(Status::PASS, status);

    //
    // Tags Empty, FAIL
    //
    let v = r#"
    {
        "Resources": {
            "vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.0.0.0/25",
                    "Tags": []
                }
            }
        }
    }
    "#;

    let value = PathAwareValue::try_from(v)?;
    let mut eval = eval.reset_root(Rc::new(value));
    let status = eval_rules_file(&rule, &mut eval, None)?;
    assert_eq!(Status::FAIL, status);

    Ok(())
}

#[test]
fn rule_test_type_blocks() -> Result<()> {
    let r = r"
    rule iam_basic_checks {
  AWS::IAM::Role {
    Properties.AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
    Properties.PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
    Properties.Tags[*].Value == /[a-zA-Z0-9]+/
    Properties.Tags[*].Key   == /[a-zA-Z0-9]+/
  }
}";

    let value = r#"
    {
        "Resources": {
            "iamrole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "PermissionsBoundary": "arn:aws:iam::123456789012:policy/permboundary",
                    "AssumeRolePolicyDocument": {
                        "Version": "2021-01-10",
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*"
                        }
                    }
                }
            },
            "iamRole2": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "PermissionsBoundary": "arn:aws:iam::123456789112:policy/permboundary",
                  "AssumeRolePolicyDocument": {
                      "Version": "2021-01-10",
                      "Statement": {
                          "Effect": "Allow",
                          "Principal": "*",
                          "Action": "*",
                          "Resource": "*"
                      }
                  },
                  "Tags": [
                    { "Key": "Key", "Value": "Value" }
                  ]
              }
            }
        }
    }
    "#;

    let root = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value)?)?;
    let rules_file = RulesFile::try_from(r)?;
    let mut root_context = root_scope(&rules_file, Rc::new(root));
    let status = eval_rules_file(&rules_file, &mut root_context, None)?;
    assert_eq!(Status::FAIL, status);

    let top = root_context.reset_recorder().extract();
    let failed_clause = find_failed_clauses(&top);
    assert_eq!(failed_clause.len(), 2); // For Tag's key and value check for first resource
    for each in failed_clause {
        match &each.container {
            Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                ComparisonClauseCheck {
                    from, status, to, ..
                },
            ))) => {
                assert_eq!(*status, Status::FAIL);
                assert_eq!(from.resolved(), None);
                assert_eq!(*to, None);
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

#[test]
fn rules_file_tests_the_unituitive_all_clause_that_skips() -> Result<()> {
    let file = r#"
let iam_resources = Resources.*[ Type == "AWS::IAM::Role" ]
rule iam_resources_exists {
    %iam_resources !EMPTY
}

rule iam_basic_checks when iam_resources_exists {
    %iam_resources.Properties.AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
    %iam_resources.Properties.PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
    #
    # This check FAILs as it tests using a conjoined call. It is testing that ALL
    # IAM resources have non empty Tags. This FAILs as "iamrole" does not have Tags
    # property specified. Therefore this check overall leads to PASS, which is the
    # correct outcome as specified. See next test on the right way to use this
    #
    when %iam_resources.Properties.Tags EXISTS
         %iam_resources.Properties.Tags !EMPTY {

        %iam_resources.Properties.Tags[*].Value == /[a-zA-Z0-9]+/
        %iam_resources.Properties.Tags[*].Key   == /[a-zA-Z0-9]+/
    }
}"#;

    let value = r#"
    {
        "Resources": {
            "iamrole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "PermissionsBoundary": "arn:aws:iam::123456789012:policy/permboundary",
                    "AssumeRolePolicyDocument": {
                        "Version": "2021-01-10",
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*"
                        }
                    }
                }
            },
            "iamRole2": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "PermissionsBoundary": "arn:aws:iam::123456789112:policy/permboundary",
                  "AssumeRolePolicyDocument": {
                      "Version": "2021-01-10",
                      "Statement": {
                          "Effect": "Allow",
                          "Principal": "*",
                          "Action": "*",
                          "Resource": "*"
                      }
                  },
                  "Tags": [
                    { "Key": "Key", "Value": "Value" }
                  ]
              }
            }
        }
    }
    "#;

    let root = PathAwareValue::try_from(value)?;
    let rules_file = RulesFile::try_from(file)?;
    let mut root_context = root_scope(&rules_file, Rc::new(root));
    let status = eval_rules_file(&rules_file, &mut root_context, None)?;
    assert_eq!(Status::PASS, status);

    Ok(())
}

#[test]
fn rules_file_tests_simpler_correct_form_using_newer_constructs() -> Result<()> {
    let file = r"
rule iam_basic_checks {
    Resources[ Type == 'AWS::IAM::Role' ] {
        Properties {
            AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
            PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
            Tags[*] {
                Key   == /[a-zA-Z0-9]+/
                Value == /[a-zA-Z0-9]+/
            }
        }
    }
}";

    //
    // Missing Tag properties
    //
    let value = r#"
    {
        "Resources": {
            "iamrole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "PermissionsBoundary": "arn:aws:iam::123456789012:policy/permboundary",
                    "AssumeRolePolicyDocument": {
                        "Version": "2021-01-10",
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*"
                        }
                    }
                }
            },
            "iamRole2": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "PermissionsBoundary": "arn:aws:iam::123456789112:policy/permboundary",
                  "AssumeRolePolicyDocument": {
                      "Version": "2021-01-10",
                      "Statement": {
                          "Effect": "Allow",
                          "Principal": "*",
                          "Action": "*",
                          "Resource": "*"
                      }
                  },
                  "Tags": [
                    { "Key": "Key", "Value": "Value" }
                  ]
              }
            }
        }
    }
    "#;

    let root = PathAwareValue::try_from(value)?;
    let rules_file = RulesFile::try_from(file)?;
    let mut root_context = root_scope(&rules_file, Rc::new(root));

    let status = eval_rules_file(&rules_file, &mut root_context, None)?;
    assert_eq!(Status::FAIL, status);

    let top = root_context.reset_recorder().extract();
    let failed_clause = find_failed_clauses(&top);
    assert_eq!(failed_clause.len(), 1); // There is only one for Tag[*] block
    for each in failed_clause {
        match &each.container {
            Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(ValueCheck {
                status,
                from,
                ..
            }))) => {
                assert_eq!(*status, Status::FAIL);
                assert_eq!(from.resolved(), None);
            }

            _ => unreachable!(),
        }
    }

    //
    // Empty Tag properties
    //
    let value = r#"
    {
        "Resources": {
            "iamrole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "PermissionsBoundary": "arn:aws:iam::123456789012:policy/permboundary",
                    "AssumeRolePolicyDocument": {
                        "Version": "2021-01-10",
                        "Statement": {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "*",
                            "Resource": "*"
                        }
                    },
                    Tags: []
                }
            },
            "iamRole2": {
              "Type": "AWS::IAM::Role",
              "Properties": {
                  "PermissionsBoundary": "arn:aws:iam::123456789112:policy/permboundary",
                  "AssumeRolePolicyDocument": {
                      "Version": "2021-01-10",
                      "Statement": {
                          "Effect": "Allow",
                          "Principal": "*",
                          "Action": "*",
                          "Resource": "*"
                      }
                  },
                  "Tags": [
                    { "Key": "Key", "Value": "Value" }
                  ]
              }
            }
        }
    }
    "#;

    let root = PathAwareValue::try_from(value)?;
    let mut root_context = root_context.reset_root(Rc::new(root));
    let status = eval_rules_file(&rules_file, &mut root_context, None)?;
    assert_eq!(Status::FAIL, status);

    let top = root_context.reset_recorder().extract();
    let failed_clause = find_failed_clauses(&top);
    assert_eq!(failed_clause.len(), 1); // There is only one for Tag[*] block
    for each in failed_clause {
        match &each.container {
            Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(ValueCheck {
                status,
                from,
                ..
            }))) => {
                assert_eq!(*status, Status::FAIL);
                assert_eq!(from.resolved(), None);
                match from.unresolved_traversed_to() {
                    Some(val) => {
                        assert_eq!(
                            val.self_path().0.as_str(),
                            "/Resources/iamrole/Properties/Tags"
                        );
                    }
                    None => unreachable!(),
                }
            }

            _ => unreachable!(),
        }
    }

    Ok(())
}

const SAMPLE: &str = r#"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "false"}
                }
            },
            {
                "Sid": "ServicePutObject",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "true"}
                }
            }
        ]
    }
    "#;

#[test]
fn test_iam_statement_clauses() -> Result<()> {
    let sample = r#"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "false"},
                    "StringEquals": {"aws:SourceVpc": "vpc-12243sc"}
                }
            },
            {
                "Sid": "ServicePutObject",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::my-service-bucket/*",
                "Condition": {
                    "Bool": {"aws:ViaAWSService": "true"}
                }
            }
        ]
    }
    "#;
    let values = PathAwareValue::try_from(sample)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };

    let clause = r#"Statement[
        Condition EXISTS ].Condition.*[
            this is_struct ][ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY"#;
    // let clause = "Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ]";
    let parsed = GuardClause::try_from(clause)?;
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(Status::PASS, status);

    let clause = r#"Statement[ Condition EXISTS
                                     Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] NOT EMPTY
    "#;
    let parsed = GuardClause::try_from(clause)?;
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(Status::PASS, status);

    let parsed = GuardClause::try_from(
        r#"SOME Statement[*].Condition.*[ THIS IS_STRUCT ][ KEYS ==  /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY"#,
    )?;
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(Status::PASS, status);

    let sample = r#"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject"
            }
        ]
    }"#;
    let value = PathAwareValue::try_from(sample)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let sample = r#"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Condition": {
                    "array": [1, 3, 4]
                }
            }
        ]
    }"#;
    let value = PathAwareValue::try_from(sample)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    let sample = r#"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject",
                "Condition": {
                    "array": [1, 3, 4],
                    "StringEquals": {"aws:SourceVpc": "vpc-12243sc"}
                }
            }
        ]
    }"#;
    let value = PathAwareValue::try_from(sample)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let value = PathAwareValue::try_from(SAMPLE)?;
    let parsed = GuardClause::try_from(clause)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(value),
        recorder: None,
    };
    let status = eval_guard_clause(&parsed, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(Status::FAIL, status);

    Ok(())
}

#[test]
fn test_api_gateway() -> Result<()> {
    let rule = r#"
rule check_rest_api_private {
  AWS::ApiGateway::RestApi {
    # Endpoint configuration must only be private
    Properties.EndpointConfiguration == ["PRIVATE"]

    # At least one statement in the resource policy must contain a condition with the key of "aws:sourceVpc" or "aws:sourceVpce"
    Properties.Policy.Statement[ Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] !EMPTY
  }
}
    "#;

    let rule = Rule::try_from(rule)?;

    let resources = r#"
    {
        "Resources": {
            "apigatewayapi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "PrincipalPutObjectIfIpAddress",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "false"},
                                    "StringEquals": {"aws:SourceVpc": "vpc-12243sc"}
                                }
                            },
                            {
                                "Sid": "ServicePutObject",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "true"}
                                }
                            }
                        ]
                    },
                    "EndpointConfiguration": ["PRIVATE"]
                }
            }
        }
    }"#;

    let values = PathAwareValue::try_from(resources)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_api_gateway_cleaner_model() -> Result<()> {
    let rule = r#"
rule check_rest_api_private {
  AWS::ApiGateway::RestApi {
    Properties {
        # Endpoint configuration must only be private
        EndpointConfiguration == ["PRIVATE"]
        some Policy.Statement[*] {
            Condition.*[ keys == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] not empty
        }
    }
  }
}
    "#;

    let rule = Rule::try_from(rule)?;

    let resources = r#"
    {
        "Resources": {
            "apigatewayapi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "PrincipalPutObjectIfIpAddress",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "false"},
                                    "StringEquals": {"aws:SourceVpc": "vpc-12243sc"}
                                }
                            },
                            {
                                "Sid": "ServicePutObject",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "true"}
                                }
                            }
                        ]
                    },
                    "EndpointConfiguration": ["PRIVATE"]
                }
            }
        }
    }"#;

    let values = PathAwareValue::try_from(resources)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let resources = r#"
    {
        "Resources": {
            "apigatewayapi": {
                "Type": "AWS::ApiGateway::RestApi",
                "Properties": {
                    "Policy": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Sid": "PrincipalPutObjectIfIpAddress",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "false"},
                                    "Bool": {"aws:SecureTransport": "true"}
                                }
                            },
                            {
                                "Sid": "ServicePutObject",
                                "Effect": "Allow",
                                "Action": "s3:PutObject",
                                "Resource": "arn:aws:s3:::my-service-bucket/*",
                                "Condition": {
                                    "Bool": {"aws:ViaAWSService": "true"}
                                }
                            }
                        ]
                    },
                    "EndpointConfiguration": ["PRIVATE"]
                }
            }
        }
    }"#;

    let values = PathAwareValue::try_from(resources)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(values),
        recorder: None,
    };
    let status = eval_rule(&rule, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn testing_iam_role_prov_serve() -> Result<()> {
    let resources = r#"
    {
        "Resources": {
            "CounterTaskDefExecutionRole5959CB2D": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Statement": [
                        {
                            "Action": "sts:AssumeRole",
                            "Effect": "Allow",
                            "Principal": {
                            "Service": "ecs-tasks.amazonaws.com"
                            }
                        }],
                        "Version": "2012-10-17"
                    },
                    "PermissionBoundary": {"Fn::Sub" : "arn::aws::iam::${AWS::AccountId}:policy/my-permission-boundary"},
                    "Tags": [{ "Key": "TestRole", "Value": ""}]
                },
                "Metadata": {
                    "aws:cdk:path": "foo/Counter/TaskDef/ExecutionRole/Resource"
                }
            }
        }
    }
    "#;

    let rules = r#"
let iam_roles = Resources.*[ Type == "AWS::IAM::Role"  ]
let ecs_tasks = Resources.*[ Type == "AWS::ECS::TaskDefinition" ]

rule deny_permissions_boundary_iam_role when %iam_roles !EMPTY {
    # atleast one Tags contains a Key "TestRole"
    %iam_roles.Properties.Tags[ Key == "TestRole" ] NOT EMPTY
    %iam_roles.Properties.PermissionBoundary !EXISTS
}

rule deny_task_role_no_permission_boundary when %ecs_tasks !EMPTY {
    let task_role = %ecs_tasks.Properties.TaskRoleArn

    when %task_role.'Fn::GetAtt' EXISTS {
        let role_name = %task_role.'Fn::GetAtt'[0]
        let iam_roles_by_name = Resources.*[ KEYS == %role_name ]
        %iam_roles_by_name !EMPTY
        iam_roles_by_name.Properties.Tags !EMPTY
    } or
    %task_role == /aws:arn/ # either a direct string or
}
    "#;

    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(resources)?;
    let mut eval = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut eval, None)?;

    println!("{}", status);
    Ok(())
}

#[test]
fn testing_sg_rules_pro_serve() -> Result<()> {
    let sgs = r#"
    [{
    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "SecurityGroupEgress": [
          {
            "CidrIp": "0.0.0.0/0",
            "Description": "Allow all outbound traffic by default",
            "IpProtocol": "-1"
          }
        ],
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
},
    {
    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "SecurityGroupEgress": [
          {
            "CidrIpv6": "::/0",
            "Description": "Allow all outbound traffic by default",
            "IpProtocol": "-1"
          }
        ],
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
}, {
    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "SecurityGroupEgress": [
          {
            "CidrIp": "10.0.0.0/16",
            "Description": "",
            "IpProtocol": "-1"
          }
        ],
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
},
{    "Resources": {
    "CounterServiceSecurityGroupF41A3908": {
      "Type": "AWS::EC2::SecurityGroup",
      "Properties": {
        "GroupDescription": "foo/Counter/Service/SecurityGroup",
        "VpcId": {
          "Ref": "Vpc8378EB38"
        }
      },
      "Metadata": {
        "aws:cdk:path": "foo/Counter/Service/SecurityGroup/Resource"
      }
    }
    }
}]

    "#;

    let rules = r#"
let sgs = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule deny_egress when %sgs NOT EMPTY {
    # Ensure that none of the security group contain a rule
    # that has Cidr Ip set to any
    %sgs.Properties.SecurityGroupEgress[ CidrIp   == "0.0.0.0/0" or
                                         CidrIpv6 == "::/0" ] EMPTY
}

    "#;

    let rules_file = RulesFile::try_from(rules)?;

    let values = PathAwareValue::try_from(sgs)?;
    let samples = match values {
        PathAwareValue::List((_p, v)) => v,
        _ => unreachable!(),
    };

    for (index, each) in samples.iter().enumerate() {
        let mut root_context = root_scope(&rules_file, Rc::new(each.clone()));
        let status = eval_rules_file(&rules_file, &mut root_context, None)?;
        println!("{}", format!("Status {} = {}", index, status).underline());
    }

    Ok(())
}

#[test]
fn test_s3_bucket_pro_serv() -> Result<()> {
    let values = r#"
    [
{
    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : false,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : false,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : false,
                "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : true,
                "BlockPublicPolicy" : true,
                "IgnorePublicAcls" : true,
                "RestrictPublicBuckets" : false
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BlockPublicAcls" : false,
                "BlockPublicPolicy" : false,
                "IgnorePublicAcls" : false,
                "RestrictPublicBuckets" : false
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
            "BlockPublicAcls" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
            "BlockPublicAcls" : true,
            "BlockPublicPolicy" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
},

{    "Resources": {
        "S3Bucket": {
            "Type": "AWS::S3::Bucket",
            "Properties": {
            "BlockPublicAcls" : true,
            "BlockPublicPolicy" : true,
            "RestrictPublicBuckets" : true
            },
            "Metadata": {
             "aws:cdk:path": "foo/Counter/S3/Resource"
            }
        }
    }
}]

    "#;

    let parsed_values = match PathAwareValue::try_from(values)? {
        PathAwareValue::List((_, v)) => v,
        _ => unreachable!(),
    };

    let rule = r#"
    rule deny_s3_public_bucket {
    AWS::S3::Bucket {  # this is just a short form notation for Resources.*[ Type == "AWS::S3::Bucket" ]
        Properties.BlockPublicAcls NOT EXISTS or
        Properties.BlockPublicPolicy NOT EXISTS or
        Properties.IgnorePublicAcls NOT EXISTS or
        Properties.RestrictPublicBuckets NOT EXISTS or

        Properties.BlockPublicAcls == false or
        Properties.BlockPublicPolicy == false or
        Properties.IgnorePublicAcls == false or
        Properties.RestrictPublicBuckets == false
    }
}

    "#;

    let s3_rule = RulesFile::try_from(rule)?;
    let expectations = [
        Status::FAIL,
        Status::PASS,
        Status::PASS,
        Status::PASS,
        Status::PASS,
        Status::PASS,
        Status::PASS,
        Status::PASS,
        Status::PASS,
        Status::PASS,
    ];

    for (idx, each) in parsed_values.iter().enumerate() {
        let mut root_scope = root_scope(&s3_rule, Rc::new(each.clone()));
        let status = eval_rules_file(&s3_rule, &mut root_scope, None)?;
        assert_eq!(status, expectations[idx]);
    }
    Ok(())
}

#[test]
fn match_lhs_with_rhs_single_element_pass() -> Result<()> {
    let clause = r#"algorithms == ["KMS"]"#;
    let value = r#"algorithms: KMS"#;
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value)?)?;
    let guard_clause = GuardClause::try_from(clause)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let status = eval_guard_clause(&guard_clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::PASS);

    let clause = r#"algorithms == ["KMS", "SSE"]"#;
    let value = r#"algorithms: KMS"#;
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(value)?)?;
    let guard_clause = GuardClause::try_from(clause)?;
    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };
    let status = eval_guard_clause(&guard_clause, &mut eval, ClauseRole::Assertion)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn parameterized_evaluations() -> Result<()> {
    let parameterized = r###"
    rule check_iam_statements(statements) {
        %statements {
            when Effect == 'Allow' {
                Action != '*'
            }
        }
    }

    rule iam_checks {
        when Resources exists {
            Resources[ Type == /IAM::Role/ ] {
                check_iam_statements(Properties.AssumeRolePolicyDocument.Statement[*])
            }
        }

        when resourceType == /IAM::Role/ {
            check_iam_statements(configuration.assumeRolePolicyDocument.Statement[*])
        }
    }
    "###;

    let rules_files = RulesFile::try_from(parameterized)?;
    let template_value = r###"
    Resources:
      iamRole:
        Type: AWS::IAM::Role
        Properties:
          AssumeRolePolicyDocument:
            Statement:
              - Action: '*'
                Principal: '*'
                Resource: '*'
                Effect: Allow
    "###;
    let template =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(template_value)?)?;

    let mut eval = root_scope(&rules_files, Rc::new(template));
    let status = eval_rules_file(&rules_files, &mut eval, None)?;
    let top = eval.reset_recorder().extract();
    let mut writer = Writer::default();
    crate::commands::validate::print_verbose_tree(&top, &mut writer);
    assert_eq!(status, Status::FAIL);

    let aws_config_value = r###"
    version: 1.2
    resourceType: AWS::IAM::Role
    configuration:
      assumeRolePolicyDocument:
        Statement:
          - Action: 'sts:AssumeRole'
            Principal: '*'
            Resource: '*'
            Effect: Allow
    "###;
    let config_value =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(aws_config_value)?)?;

    let mut eval = root_scope(&rules_files, Rc::new(config_value));
    let status = eval_rules_file(&rules_files, &mut eval, None)?;
    let top = eval.reset_recorder().extract();
    crate::commands::validate::print_verbose_tree(&top, &mut writer);
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn using_resource_names_for_assessment() -> Result<()> {
    let resources = r###"
    Resources:
        s3:
            Type: AWS::S3::Bucket
        s3Policy:
            Type: AWS::S3::BucketPolicy
            Properties:
                BucketName:
                    Ref: s3
        s3Fail:
            Type: AWS::S3::Bucket
    "###;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;

    let rules_file = r###"
    rule check_s3_has_bucket_policy {
        let s3_buckets = Resources[ s3_name | Type == 'AWS::S3::Bucket' ]
        let s3_bucket_policy_associations =
            some Resources[ Type == 'AWS::S3::BucketPolicy' ].Properties.BucketName.Ref
        when %s3_buckets not empty {
            # %s3_name == %s3_bucket_policy_associations
            %s3_bucket_policy_associations == %s3_name
                <<ALL S3 buckets do not have a bucket policy associated>>
        }
    }
    "###;

    let rules = RulesFile::try_from(rules_file)?;
    let mut eval = root_scope(&rules, Rc::new(value));
    let status = eval_rules_file(&rules, &mut eval, None)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
#[ignore]
fn test_string_in_comparison() -> Result<()> {
    let resources = r#"
    Resources:
      s3:
        Type: AWS::S3::Bucket
      s3Policy:
        Type: AWS::S3::BucketPolicy
        Properties:
          PolicyDocument:
            Statement:
              Resource:
                Fn::Sub: "aws:arn:s3::${s3}"
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;

    let rules = r###"
    let s3_buckets = Resources[ bucket_names | Type == 'AWS::S3::Bucket' ]
    rule s3_policies {
        when %s3_buckets not empty {
            Resources[ Type == 'AWS::S3::BucketPolicy' ] {
                some %bucket_names[*] in Properties.PolicyDocument.Statement.Resource.'Fn::Sub'
            }
        }
    }
    "###;

    let rules_files = RulesFile::try_from(rules)?;
    let mut eval = root_scope(&rules_files, Rc::new(value));
    let status = eval_rules_file(&rules_files, &mut eval, None)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_searcher() -> Result<()> {
    let resources = r#"
    Resources:
      s3:
        Type: AWS::S3::Bucket
      s3Policy:
        Type: AWS::S3::BucketPolicy
        Properties:
          PolicyDocument:
            Statement:
              Resource:
                Fn::Sub: "aws:arn:s3::${s3}"
    "#;

    use grep_matcher::Matcher;
    use grep_regex::RegexMatcher;

    let matcher = RegexMatcher::new("\\s+(s3):$|\\s+(s3Policy):$").unwrap();
    SearcherBuilder::new()
        .line_number(true)
        .build()
        .search_slice(
            &matcher,
            resources.as_bytes(),
            grep_searcher::sinks::UTF8(|_, line| {
                let mut captures = matcher.new_captures()?;
                let _matched = matcher.captures(line.trim_end().as_bytes(), &mut captures)?;
                Ok(true)
            }),
        )?;

    Ok(())
}

#[test]
fn status_combinator() {
    let skip: Status = Status::SKIP;
    let pass: Status = Status::PASS;
    let fail: Status = Status::FAIL;

    assert_eq!(skip.and(skip), Status::SKIP);

    assert_eq!(skip.and(pass), Status::PASS);
    assert_eq!(pass.and(skip), Status::PASS);
    assert_eq!(pass.and(pass), Status::PASS);

    assert_eq!(fail.and(fail), Status::FAIL);
    assert_eq!(fail.and(skip), Status::FAIL);
    assert_eq!(skip.and(fail), Status::FAIL);
    assert_eq!(pass.and(fail), Status::FAIL);
    assert_eq!(fail.and(pass), Status::FAIL);
}

//
// Comparisons whose right-hand side (the reference/allow/deny list) resolves to no
// values. These used to SKIP, which exits 0, so an allowlist that resolved empty
// reported compliance for a violating template.
//
// The answer depends on polarity, and on whether the clause is a body assertion or a
// `when` condition. All four combinations are pinned here because getting any one of
// them wrong reintroduces a wrong PASS or starts failing compliant templates.
//
fn status_of(rules: &str, input: &str) -> Result<Status> {
    let value = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    eval_rules_file(&rules_file, &mut root, None)
}

const ONE_BUCKET: &str = r#"
{
    Resources: {
        bucket: {
            Type: 'AWS::S3::Bucket',
            Properties: { BucketName: "PUBLIC-INSECURE" }
        }
    }
}
"#;

#[test]
fn positive_comparison_against_empty_reference_fails() -> Result<()> {
    // "the name must be one of the approved names", where the approved list is
    // derived from a resource type absent from this template. Nothing qualifies, so
    // the clause cannot be satisfied. Before the fix this SKIPped and exited 0.
    let rules = r###"
    let approved = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId
    rule name_must_be_approved {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName IN %approved
    }
    "###;
    assert_eq!(status_of(rules, ONE_BUCKET)?, Status::FAIL);
    Ok(())
}

/// A negated comparison whose reference resolved to no values fails as an assertion.
///
/// This asserted SKIP until the semantics were settled in review, on the reading that the
/// clause is vacuously satisfied: there is nothing to collide with, and a denylist is
/// legitimately empty whenever the template contains none of the denied values.
///
/// The reading was rejected because the two error modes are not symmetric. A wrong FAIL is
/// visible and gets investigated; a wrong SKIP exits 0 and is indistinguishable from PASS in
/// CI, so a rule whose only check is `Property != %empty_reference` silently enforced nothing.
/// That is a denylist bypass, and it is the hole this branch exists to close.
///
/// The alternative considered was to keep the SKIP and require authors to declare the
/// expectation with an accompanying `!empty` clause. Rejected: it leaves every existing
/// ruleset without such a guard silently defeatable, which is the state being fixed.
///
/// FAIL specifically, not merely "not SKIP" -- a PASS here would short-circuit a disjunction
/// and abandon its sibling disjuncts, which
/// `vacuous_negated_comparison_does_not_satisfy_a_disjunction` covers.
#[test]
fn negated_comparison_against_empty_reference_fails() -> Result<()> {
    let rules = r###"
    let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId
    rule name_must_not_be_denied {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName != %denied
    }
    "###;
    assert_eq!(status_of(rules, ONE_BUCKET)?, Status::FAIL);
    Ok(())
}

/// The escape hatch for a reference that is legitimately allowed to be empty.
///
/// Failing closed on an empty reference is only defensible if an author who genuinely expects
/// one has a way to say so. `when <reference> !empty { ... }` is that way, and it needs no new
/// machinery: the gate's own `!empty` check fails when the reference resolved to nothing, so
/// `eval_rule` treats the rule as inapplicable and the guarded comparison never runs.
///
/// Asserted rather than assumed. The claim was made in review as the reason failing closed is
/// safe, and if it were wrong the change would leave no way to express a permissibly-empty
/// denylist at all.
#[test]
fn an_empty_reference_can_be_guarded_with_a_when_not_empty_gate() -> Result<()> {
    let guarded = r###"
    let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId
    rule name_must_not_be_denied when %denied !empty {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName != %denied
    }
    "###;

    // The gate closes on the empty reference, so the rule does not apply and the clause that
    // would otherwise fail never runs.
    assert_eq!(
        status_of(guarded, ONE_BUCKET)?,
        Status::SKIP,
        "the `when %denied !empty` guard must make the rule inapplicable rather than failing \
         it -- without this there is no way to express a permissibly-empty reference"
    );

    // Liveness: with a non-empty reference the gate opens and the comparison decides. Without
    // this row the assertion above is satisfied by a rule that never ran for any reason.
    let with_keys = r#"
    {
        Resources: {
            bucket: { Type: 'AWS::S3::Bucket', Properties: { BucketName: "PUBLIC-INSECURE" } },
            key: { Type: 'AWS::KMS::Key', Properties: { KeyId: "PUBLIC-INSECURE" } }
        }
    }
    "#;
    assert_eq!(
        status_of(guarded, with_keys)?,
        Status::FAIL,
        "liveness: with a populated reference the gate must open and the collision be caught"
    );

    Ok(())
}

/// Why the empty-reference arms stay a SKIP for a `when` condition instead of failing closed
/// like an assertion.
///
/// The condition fold in `eval_conjunction_clauses` absorbs a SKIP but counts a FAIL, and it
/// answers FAIL before PASS. A gate that cannot compare therefore has to SKIP: failing it
/// would outrank the sibling conditions that did pass, make the rule inapplicable, and drop a
/// body those siblings would have enforced -- all at exit 0, which is the same wrong-PASS
/// shape this branch exists to close.
///
/// Two conditions joined by AND here. The first compares against an empty reference and cannot be
/// evaluated; the second passes. With the SKIP the second decides, the body runs, and its
/// violation is reported as a FAIL. Under an unconditional FAIL the rule reports SKIP and
/// nothing is enforced.
///
/// This shape is required to observe the difference at all. With a single condition both
/// statuses are indistinguishable, because `eval_rule` maps every non-PASS condition to a
/// rule-level SKIP; a disjunction hides it too, since a passing arm short-circuits either
/// way. An earlier version of this test used one condition and passed no matter which status
/// the arm returned.
///
/// `empty_reference_in_a_when_condition_does_not_disarm_the_block` is the same test for the
/// positive polarity, which reaches the other empty-reference arm.
#[test]
fn negated_empty_reference_in_a_when_condition_does_not_disarm_the_block() -> Result<()> {
    let rules = r###"
    let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId
    rule name_is_approved when Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName != %denied
                               Resources.*[ Type == 'AWS::S3::Bucket' ] !empty {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'approved-name'
    }
    "###;

    assert_eq!(
        status_of(rules, ONE_BUCKET)?,
        Status::FAIL,
        "the unevaluatable condition must be absorbed so the passing condition still applies \
         the rule; a FAIL there reports SKIP and drops the body"
    );
    Ok(())
}

#[test]
fn negation_on_a_parameterized_rule_call_is_honored() -> Result<()> {
    // `not r(...)` used to behave identically to `r(...)`: the parser stores the
    // leading `not` on the call, but eval_parameterized_rule_call returned the
    // invoked rule's status unchanged, discarding it. Same defect class as the
    // dropped clause-level negation on binary comparisons.
    //
    // `inner` PASSes here, so `not inner("x")` must FAIL and `inner("x")` must PASS.
    // Before the fix both PASSed.
    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { BucketName: "b" }
            }
        }
    }
    "#;

    let negated = r###"
    rule inner(t) {
        %t == 'AWS::S3::Bucket'
    }
    rule outer {
        not inner(Resources.bucket.Type)
    }
    "###;

    let plain = r###"
    rule inner(t) {
        %t == 'AWS::S3::Bucket'
    }
    rule outer {
        inner(Resources.bucket.Type)
    }
    "###;

    // The two forms must disagree; that they agreed is what proved the bug.
    assert_eq!(status_of(negated, input)?, Status::FAIL);
    assert_eq!(status_of(plain, input)?, Status::PASS);

    Ok(())
}

#[test]
fn parameterized_rule_used_as_a_gate_does_not_disarm_the_block() -> Result<()> {
    // Regression test for a wrong PASS found by review.
    //
    // A parameterized rule invoked from a `when` condition is a gate, so its body
    // must evaluate with gate semantics. eval_when_clause threaded the role into its
    // Clause and NamedRule arms but not ParameterizedNamedRule, and everything
    // downstream defaulted to assertion strictness. The gate therefore FAILed instead
    // of SKIPping, eval_rule read a non-PASS condition as "rule does not apply", and
    // the guarded body -- the real check -- was never evaluated. Exit 0 on a
    // violating template, where base correctly exited 19.
    //
    // `inner` SKIPs (its query selects a resource type not present). `gate` is
    // parameterized and negates it. `must_be_encrypted` is gated on `gate`.
    let rules = r###"
    rule inner {
        Resources.*[ Type == 'AWS::Nonexistent::Thing' ] {
            Properties.Foo == 'bar'
        }
    }

    rule gate(unused) {
        not inner
    }

    rule must_be_encrypted when gate("x") {
        Resources.Bucket.Properties.Encrypted == true
    }
    "###;

    let input = r#"
    {
        Resources: {
            Bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { BucketName: "mybucket", Encrypted: false }
            }
        }
    }
    "#;

    // The gate must open, so the body runs and its violated check fails the rule.
    // With the role not threaded to the parameterized gate, the gate FAILed, the rule
    // was treated as inapplicable, and this returned SKIP.
    assert_eq!(status_of(rules, input)?, Status::FAIL);

    Ok(())
}

#[test]
fn vacuous_negated_comparison_does_not_satisfy_a_disjunction() -> Result<()> {
    // Regression test for a wrong PASS found by review.
    //
    // eval_conjunction_clauses treats PASS as short-circuiting (`continue
    // 'conjunction`) but SKIP as absorbing (`=> {}`). Reporting the vacuous
    // empty-denylist case as PASS therefore satisfied the whole `or` block and
    // abandoned the sibling disjunct unevaluated, so an unencrypted resource passed
    // the gate. Base 57bbdbf failed this ruleset correctly; an intermediate version
    // of this change passed it.
    //
    // Disjunct 1 is vacuously satisfied (empty denylist). Disjunct 2 is the real
    // check and genuinely fails. The rule must fail.
    let rules = r###"
    let denied = Resources[ Type == 'AWS::S3::Bucket' ].Properties.BucketName
    rule gate {
        Resources.V.Properties.Encrypted != %denied
        or
        Resources.V.Properties.Encrypted == true
    }
    "###;

    let input = r#"
    {
        Resources: {
            V: {
                Type: 'AWS::EC2::Volume',
                Properties: { Encrypted: false }
            }
        }
    }
    "#;

    assert_eq!(status_of(rules, input)?, Status::FAIL);
    Ok(())
}

#[test]
fn empty_reference_in_a_when_condition_does_not_disarm_the_block() -> Result<()> {
    // The critical case. If the empty-RHS condition FAILs, the gate is not-PASS and
    // eval_rule treats that as "rule does not apply", skipping the entire body --
    // so the real check silently stops running and the file exits 0. The condition
    // must stay a SKIP so the remaining conditions decide the gate.
    let rules = r###"
    let empt = Resources.*[ Type == 'AWS::EC2::Instance' ].Properties.Foo
    rule gated when Resources.*.Type IN %empt
                    Resources.*.Type == /S3/ {
        Resources.*.Properties.BucketName == /^secure-/
    }
    "###;
    // FAIL specifically. "Not PASS" would also admit SKIP, which is the exact
    // failure mode this test exists to catch: a SKIP here means the gate closed and
    // the body never ran, which is indistinguishable from a pass at the gate because
    // both exit 0. Asserting FAIL proves the body actually executed and rejected the
    // bucket name.
    assert_eq!(status_of(rules, ONE_BUCKET)?, Status::FAIL);
    Ok(())
}

#[test]
fn literal_lhs_against_empty_reference_fails_without_panicking() -> Result<()> {
    // A `let` literal on the left resolves to QueryResult::Literal, which three
    // reporters treat as unreachable inside a comparison record. Emitting a status
    // rather than a per-value comparison keeps this off that path.
    let rules = r###"
    let lit = "foo"
    let empt = Resources.*[ Type == 'AWS::EC2::Instance' ].Properties.Missing
    rule literal_lhs {
        %lit IN %empt
    }
    "###;
    // Must produce a verdict rather than panicking.
    let status = status_of(rules, ONE_BUCKET)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

//
// Clause-level negation on a BINARY comparison.
//
// `not <query> == <value>` parses (parser.rs:969 accepts a leading not before the
// query) and is stored as GuardAccessClause::negation, but the binary evaluation
// path used to drop it, so the clause evaluated as its un-negated self -- the exact
// inverse of the author's intent -- while the report still displayed the `not`.
//
// The unary path was never affected; these tests cover the binary path and assert
// that an un-negated clause is unchanged.
//
fn eval_single_rule(rules: &str, resources: &str) -> Result<Status> {
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(resources)?)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut eval = root_scope(&rules_file, Rc::new(value));
    eval_rules_file(&rules_file, &mut eval, None)
}

#[test]
fn negated_binary_clause_is_honored() -> Result<()> {
    let encrypted_false = r#"
    Resources:
      bucket:
        Type: AWS::S3::Bucket
        Properties:
          Encrypted: false
    "#;
    let encrypted_true = r#"
    Resources:
      bucket:
        Type: AWS::S3::Bucket
        Properties:
          Encrypted: true
    "#;

    // "It must NOT be the case that Encrypted == false."
    let negated = r###"
    rule encrypted_must_not_be_false {
        not Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Encrypted == false
    }
    "###;

    // Encrypted: false violates the intent -> FAIL.
    // Before the fix this returned PASS.
    assert_eq!(eval_single_rule(negated, encrypted_false)?, Status::FAIL);

    // Encrypted: true satisfies the intent -> PASS.
    // Before the fix this returned FAIL.
    assert_eq!(eval_single_rule(negated, encrypted_true)?, Status::PASS);

    Ok(())
}

#[test]
fn unnegated_binary_clause_is_unchanged() -> Result<()> {
    let encrypted_false = r#"
    Resources:
      bucket:
        Type: AWS::S3::Bucket
        Properties:
          Encrypted: false
    "#;
    let encrypted_true = r#"
    Resources:
      bucket:
        Type: AWS::S3::Bucket
        Properties:
          Encrypted: true
    "#;

    let plain = r###"
    rule encrypted_equals_false {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Encrypted == false
    }
    "###;

    // The negated and un-negated forms must now disagree on every input; before the
    // fix they agreed, which is what proved the `not` was being dropped.
    assert_eq!(eval_single_rule(plain, encrypted_false)?, Status::PASS);
    assert_eq!(eval_single_rule(plain, encrypted_true)?, Status::FAIL);

    Ok(())
}

#[test]
fn negation_composes_with_operator_not_flag() -> Result<()> {
    let encrypted_false = r#"
    Resources:
      bucket:
        Type: AWS::S3::Bucket
        Properties:
          Encrypted: false
    "#;

    // Double negation: clause-level `not` plus the operator's own `!=`.
    // `not X != false` is equivalent to `X == false`, which holds here -> PASS.
    let double = r###"
    rule double_negation {
        not Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Encrypted != false
    }
    "###;
    assert_eq!(eval_single_rule(double, encrypted_false)?, Status::PASS);

    // Single negation via the operator alone is unaffected: `X != false` is false
    // here -> FAIL.
    let op_only = r###"
    rule op_not_only {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Encrypted != false
    }
    "###;
    assert_eq!(eval_single_rule(op_only, encrypted_false)?, Status::FAIL);

    Ok(())
}

//
// `not <rule>` where the dependent rule SKIPped.
//
// In a rule BODY this is an assertion, and a SKIPped rule is not evidence, so it
// must not report compliance. It previously returned PASS -- and because the
// enclosing rule then reported PASS rather than SKIP, the output gave no hint that
// the check had never run.
//
// In a `when` CONDITION the same shape is intentional ("apply this rule when that
// other rule did not apply") and is covered by cross_rule_clause_when_checks, so
// that behavior is deliberately preserved here.
//
#[test]
fn negated_reference_to_skipped_rule_does_not_pass_in_rule_body() -> Result<()> {
    // `inner` SKIPs: its query filters on a resource type absent from the input.
    let rules = r###"
    rule inner {
        Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId exists
    }

    rule deny when Resources.*.Type exists {
        not inner
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { BucketName: "b" }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL specifically. Before the fix this was PASS, manufactured from a dependent
    // rule that never ran. "Not PASS" would also admit SKIP, and a SKIP would mean
    // the negated reference had been made merely inert rather than fail-closed --
    // still exit 0, so still a gate bypass. FAIL is the property that matters.
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn negated_reference_to_skipped_rule_still_gates_a_when_condition() -> Result<()> {
    // Same shape, but the negated reference is a `when` condition rather than a body
    // assertion. Gating here is intentional: the guarded block should still run.
    let rules = r###"
    rule inner {
        Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId exists
    }

    rule gated when not inner {
        Resources.*.Type exists
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { BucketName: "b" }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // The gate opens and the body (`Type exists`) holds, so this passes.
    assert_eq!(status, Status::PASS);

    Ok(())
}

/// A non-negated parameterized gate that SKIPs must not poison the rest of the `when`.
///
/// `eval_parameterized_rule_call` returned the invoked rule's status through a `_` arm that
/// converted any non-PASS, non-strict-SKIP result into FAIL for a non-negated call. With a
/// single condition that is invisible: FAIL and SKIP both make `eval_rule` treat the rule as
/// inapplicable and drop the guarded body.
///
/// It becomes visible with two conditions, which is why this test has two.
/// `eval_conjunction_clauses` absorbs SKIP (`Status::SKIP => {}`) but counts a FAIL, so the
/// inapplicable gate returning FAIL dropped a body that the passing sibling condition should
/// have kept enforced. `ClauseRole::Gate` is documented as "the block it guards is still
/// decided by the remaining conditions", so FAIL here defeated the role propagation.
///
/// The fixture: `no_such_type` invokes a parameterized rule whose query selects nothing, so it
/// SKIPs; `bucket_exists` PASSes; and the guarded body requires a Name the template violates.
/// The body must therefore run and the file must FAIL. Before the fix it exited 0 with the
/// body dropped, which is the wrong-PASS shape this whole branch is about.
#[test]
fn a_skipping_parameterized_gate_does_not_drop_a_body_its_sibling_enforces() -> Result<()> {
    // `relevant` must SKIP, not FAIL, or this fixture tests the wrong arm. A binary
    // comparison whose left-hand query selects nothing yields `EvalResult::Skip`
    // (`CmpOperator::compare`'s `lhs.is_empty()` guard), so the rule SKIPs. `!empty` would
    // FAIL instead -- an unresolved query is EMPTY, so `!empty` is false -- which reaches the
    // `_` arm by a different route and would not exercise the SKIP path at all.
    let rules = r###"
    rule relevant(ty) {
        Resources.*[ Type == %ty ].Properties.Name == 'anything'
    }
    rule guarded when relevant('AWS::Nonexistent::Type') Resources.*[ Type == 'AWS::S3::Bucket' ] !empty {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'safebucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            b: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket" }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL: the parameterized gate does not apply, the sibling condition passes, so the body
    // runs and catches `publicbucket`. SKIP here would mean the inapplicable gate closed the
    // whole `when` and the violation went unreported while the process exited 0.
    assert_eq!(
        status,
        Status::FAIL,
        "a parameterized gate that did not apply suppressed a body its sibling condition \
         should have kept enforced"
    );

    Ok(())
}

/// A `when` block inside a gate must not evaluate its body as an assertion.
///
/// `eval_when_condition_block` took no role and hardcoded `ClauseRole::Assertion` for the guarded
/// body, on the reasoning that a guarded block holds the rule's own assertions however its
/// conditions were evaluated. True of a rule evaluated as an assertion; false of one evaluated as a
/// gate.
///
/// The cost was a wrong PASS of exactly the shape this module exists to prevent. Wrapping an
/// empty-reference clause in `when { ... }` inside a parameterized gate failed it as an assertion;
/// `eval_conjunction_clauses` counts a FAIL and absorbs a SKIP and answers FAIL before PASS, so the
/// failure outranked the passing sibling condition, the enclosing rule became inapplicable, and its
/// guarded check was dropped at exit 0. The same rule without the inner `when` exited 19.
///
/// Both spellings are asserted together, because the defect was invisible in either alone: each on
/// its own merely looks like whatever the current behaviour is, and only the pair shows that
/// wrapping a clause in `when` changed its meaning.
#[test]
fn nested_when_inherits_the_enclosing_role() -> Result<()> {
    // A gate whose body holds the empty-reference clause directly. The clause SKIPs as a gate, the
    // SKIP is absorbed, the passing sibling applies the rule, and the body decides.
    let direct = r###"
    let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId
    rule relevant(ty) {
        Resources.*[ Type == %ty ].Properties.BucketName != %denied
    }
    rule guarded when relevant('AWS::S3::Bucket')
                      Resources.*[ Type == 'AWS::S3::Bucket' ] !empty {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'approved-name'
    }
    "###;

    // The same gate, with the clause wrapped in a `when` block whose condition passes. Wrapping
    // must not change what the clause means.
    let nested = r###"
    let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId
    rule relevant(ty) {
        when Resources.*[ Type == %ty ] !empty {
            Resources.*[ Type == %ty ].Properties.BucketName != %denied
        }
    }
    rule guarded when relevant('AWS::S3::Bucket')
                      Resources.*[ Type == 'AWS::S3::Bucket' ] !empty {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName == 'approved-name'
    }
    "###;

    assert_eq!(
        status_of(direct, ONE_BUCKET)?,
        Status::FAIL,
        "baseline: the gate does not apply, the sibling passes, and the body catches the name"
    );
    assert_eq!(
        status_of(nested, ONE_BUCKET)?,
        Status::FAIL,
        "wrapping the gate's clause in `when` dropped the guarded body: the clause failed as an \
         assertion, which outranked the passing sibling condition and exited 0"
    );

    Ok(())
}

/// Exhaustive check that the role reaching a leaf clause survives arbitrary `when` nesting.
///
/// `nested_when_inherits_the_enclosing_role` pins the one shape that was broken. This pins the
/// surface around it, because the defect was not that one arm was wrong on purpose -- it was that
/// role threading is invisible when omitted. Three of the four arms of `eval_guard_clause` forwarded
/// `role` and one silently did not, and nothing failed.
///
/// The axes are the enclosing role, the nesting depth, and the leaf clause's polarity. Rows are
/// generated rather than written out, and `ROWS_EXPECTED` is asserted against the product of the
/// axis lengths, so dropping an axis value fails instead of quietly shrinking coverage.
///
/// What makes each cell observable: an empty-reference clause is the leaf precisely because it
/// answers differently by role -- FAIL as an assertion, SKIP as a gate. The fixtures are built so
/// the two answers produce *different file statuses*, which a single fixture would not do:
///
/// - As an assertion, a correct leaf FAILs the rule, so the file FAILs. Leaking the gate role
///   instead would SKIP it.
/// - As a gate, a correct leaf SKIPs, is absorbed by the condition fold, and lets the passing
///   sibling apply the rule, whose body is written to pass -- so the file PASSes. Leaking the
///   assertion role instead would FAIL the gate, outrank the sibling, and SKIP the rule.
///
/// So expected FAIL for assertions and PASS for gates, with SKIP being the signature of a leaked
/// role in either direction.
#[test]
fn the_role_reaching_a_leaf_clause_survives_every_nesting() -> Result<()> {
    // (label, clause tail against an empty reference)
    const LEAVES: [(&str, &str); 2] = [("negated", "!= %denied"), ("positive", "IN %denied")];
    const DEPTHS: [usize; 3] = [0, 1, 2];
    const ROLES: [&str; 2] = ["assertion", "gate"];
    const ROWS_EXPECTED: usize = 2 * 3 * 2;

    let mut rows = 0;

    for (leaf_label, leaf_tail) in LEAVES {
        for depth in DEPTHS {
            for role in ROLES {
                // The gate fixture has to use a *parameterized* rule. A plain named rule is also
                // evaluated as a top-level rule in its own right, as an assertion, so its own
                // failure would decide the file status and mask what the gate reference did with
                // it. A parameterized rule needs arguments, so it is only ever evaluated where it
                // is called. An earlier version of this matrix used a plain rule and failed on
                // that, not on the behaviour under test.
                //
                // The type is therefore spelled through the parameter in the gate case and
                // literally in the assertion case, so both fixtures select the same resources.
                let ty = if role == "gate" {
                    "%ty"
                } else {
                    "'AWS::S3::Bucket'"
                };
                let condition = format!("Resources.*[ Type == {ty} ] !empty");

                // Wrap the leaf in `depth` passing `when` blocks.
                let mut body =
                    format!("Resources.*[ Type == {ty} ].Properties.BucketName {leaf_tail}");
                for _ in 0..depth {
                    body = format!("when {condition} {{\n            {body}\n        }}");
                }

                let rules = if role == "assertion" {
                    // Top level, so the clauses are assertions.
                    format!(
                        "let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId\n\
                         rule r {{\n        {body}\n    }}"
                    )
                } else {
                    // Invoked as a parameterized gate, with a passing sibling condition so a gate
                    // FAIL is distinguishable from a gate SKIP, and a body written to pass.
                    format!(
                        "let denied = Resources.*[ Type == 'AWS::KMS::Key' ].Properties.KeyId\n\
                         rule relevant(ty) {{\n        {body}\n    }}\n\
                         rule guarded when relevant('AWS::S3::Bucket')\n\
                                           Resources.*[ Type == 'AWS::S3::Bucket' ] !empty {{\n\
                             Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName \
                             == 'PUBLIC-INSECURE'\n\
                         }}"
                    )
                };

                let expected = if role == "assertion" {
                    Status::FAIL
                } else {
                    Status::PASS
                };

                let got = status_of(rules.as_str(), ONE_BUCKET)?;
                assert_eq!(
                    got, expected,
                    "{role} leaf {leaf_label} at nesting depth {depth}: expected {expected:?}, \
                     got {got:?}. SKIP here means the role was lost on the way to the leaf and the \
                     clause answered as the other kind.\nrules:\n{rules}"
                );
                rows += 1;
            }
        }
    }

    assert_eq!(
        rows, ROWS_EXPECTED,
        "the matrix must cover every combination of the axes; an axis lost a value"
    );

    Ok(())
}

/// Every explanation this module records must have a path to the reader.
///
/// A message written into a record and never rendered is worse than no message: the code reads as
/// though the failure explains itself, the documentation says it does, and the operator sees
/// nothing. That is exactly what happened to the empty-reference explanation. It was constructed,
/// stored, and dropped, and the claim that it "names the cause and the remedy" went into
/// docs/CLAUSES.md and into a review comment before anyone checked the output.
///
/// So this counts the sites rather than trusting the next author to check. The count is taken by
/// exclusion -- every `message:` field that is not `None`, not a type annotation, and not a
/// forward of the rule author's own `custom_message` -- because the first version counted the
/// literal string `message: Some` and undercounted the moment a message was built in a `match`
/// arm instead. Counting what is left over cannot be fooled by a new spelling.
#[test]
fn every_recorded_explanation_has_a_rendering_path() {
    let source = include_str!("eval.rs");
    let total = source.matches("message: ").count();
    // `message: None` is an explicit no-explanation, and `message: Option<...>` is a struct field
    // or function parameter rather than a construction site.
    let empty = source.matches("message: None").count();
    let declarations = source.matches("message: Option").count();
    // The rule author's own message, which has always rendered. A different feature from the
    // evaluator explaining its own verdict, and not what this test guards.
    let custom = source.matches("message: custom_message").count()
        + source.matches("message: gnc.custom_message").count()
        + source
            .matches("message: self.call_rule.named_rule.custom_message")
            .count();
    let sites = total - empty - declarations - custom;

    // Evaluator-generated explanations, by the record variant each lands on:
    //
    //   ClauseValueCheck        3   leaf value checks; rendered by the clause arms already
    //   GuardClauseBlockCheck   5   rendered: falls back to the message when no children report
    //   BlockGuardCheck         1   rendered: uses the record's message, not a hardcoded sentence
    //   WhenCheck               2   rendered: same fallback as GuardClauseBlockCheck
    //   TypeCheck               5   four failures, plus the one skip site below
    //   Disjunction             1   rendered: reported as a block when no disjunct recorded anything
    //
    // The fifth GuardClauseBlockCheck is the newest: a `when` condition that references a rule
    // which did not apply. That gate now answers SKIP instead of FAIL, so the conjunction absorbs
    // it rather than dropping the guarded body, and the resulting rule-level SKIP needs to say
    // which condition declined. It reaches the reader through `find_skip_reason`, and is asserted
    // end to end by `a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block`.
    //
    // The TypeCheck skip site is the one that was hardest to render. A skipped rule used to reach
    // the reporters as a bare name, so a message on a skip record was recorded and discarded --
    // this test refused an earlier attempt to add one, which is what it is for. Skips now carry
    // their reason through `find_skip_reason`. It is one `message:` site holding four sentences:
    // an empty selection, an unselectable one, a `when` condition that exempted everything, and
    // clauses that were inapplicable to everything. `a_skipped_type_block_explains_itself_in_the_output`
    // and `a_type_block_skip_names_the_cause_it_can_support` assert them end to end.
    //
    // The per-slot variant of that message is deliberately gone. Recording it against the
    // resource slot put a second `TypeCheck` where display.rs documents a `TypeBlock`, and
    // `find_skip_reason` reads it off the block's own record anyway, so the reason now travels in
    // a local instead of a record.
    //
    // If this total changes, find the new site, note which variant it records against, and confirm
    // it reaches rendered output before updating the number.
    const SITES_EXPECTED: usize = 17;

    assert_eq!(
        sites, SITES_EXPECTED,
        "the number of recorded explanations in eval.rs changed from {SITES_EXPECTED} to {sites}. \
         A new message needs a rendering path, or it will be recorded and silently discarded; \
         update the table above once you have checked that it reaches the output."
    );
}

/// `EMPTY` and `!EMPTY` on a boolean are an incompatible-type error, not a silent pass.
///
/// `EMPTY` on a boolean fails, in both polarities, and says why.
///
/// The Bool arm of `element_empty_operation` computed `(*boolean).to_string().is_empty()`. Neither
/// "true" nor "false" is ever the empty string, so EMPTY on a boolean was unconditionally false and
/// `!EMPTY` unconditionally true: a clause that reads like a check and cannot fail for any input. A
/// rule author writing `Properties.Enabled !EMPTY` got a green check that verified nothing.
///
/// Removing the arm lets a boolean reach the same incompatible-type treatment every other unsupported
/// type gets. That treatment used to be an error that aborted the file, and is now a fail-closed
/// verdict on the clause -- see `an_incompatible_type_does_not_discard_other_rules`. Both polarities
/// FAIL, deliberately: the question is unanswerable, so neither spelling gets to claim an answer.
///
/// All four combinations are covered because the two axes fail differently. The old code made
/// `!EMPTY` a silent *pass* and `EMPTY` a silent *fail*, so a test on one polarity alone would have
/// left the other spelling unguarded, and `true` versus `false` is exactly the axis the old
/// implementation was insensitive to -- asserting only one value would not have distinguished
/// "handled" from "ignored".
#[test]
fn empty_on_a_boolean_fails_closed_in_both_polarities() -> Result<()> {
    fn recorded_messages(record: &EventRecord<'_>, out: &mut Vec<String>) {
        if let Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(check))) = &record.container {
            if let Some(message) = &check.value.message {
                out.push(message.clone());
            }
        }
        for child in &record.children {
            recorded_messages(child, out);
        }
    }

    for value in ["true", "false"] {
        for comparator in ["EMPTY", "!EMPTY"] {
            let rules = format!(
                r###"
                rule flag_check {{
                    Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Enabled {comparator}
                }}
                "###
            );
            let input = format!(
                r#"
                {{
                    Resources: {{
                        b: {{
                            Type: 'AWS::S3::Bucket',
                            Properties: {{ Enabled: {value} }}
                        }}
                    }}
                }}
                "#
            );

            let resources = PathAwareValue::try_from(input.as_str())?;
            let rules_file = RulesFile::try_from(rules.as_str())?;
            let mut root = root_scope(&rules_file, Rc::new(resources));
            let status = eval_rules_file(&rules_file, &mut root, None)?;

            assert_eq!(
                status,
                Status::FAIL,
                "`Enabled {}` on the boolean {} must fail closed. Before this fix `!EMPTY` passed \
                 for every boolean and `EMPTY` failed for every boolean, in both cases without \
                 comparing anything.",
                comparator,
                value
            );

            let mut messages = Vec::new();
            recorded_messages(&root.reset_recorder().extract(), &mut messages);
            assert!(
                messages.iter().any(|m| m.contains("EMPTY")),
                "the recorded explanation should name the EMPTY operation so the author can find \
                 the clause; `{} {}` recorded {:?}",
                value,
                comparator,
                messages
            );
            assert!(
                messages.iter().any(|m| m.contains("Enabled")),
                "the recorded explanation should name the offending path; `{} {}` recorded {:?}",
                value,
                comparator,
                messages
            );
        }
    }

    Ok(())
}

/// A gate that compares against a decimal must still guard its body.
///
/// This is the composed form of the mixed-numeric defect fixed in `compare_values`, and it is the
/// reason that defect mattered more than a wrong FAIL. `Size > 10` against `Size: 50.5` was
/// NotComparable, `eval_rule` maps any non-PASS condition to `Status::SKIP`, and SKIP exits 0. So
/// the rule below stopped enforcing encryption entirely -- and it did so silently, with no clause
/// named in the output -- the moment a template wrote a volume size as `50.5` instead of `50`.
///
/// Both fixtures are asserted, because the integer one is what makes the decimal one meaningful:
/// without it a reader cannot tell whether the rule ever had teeth.
#[test]
fn a_float_valued_gate_condition_still_guards_its_body() -> Result<()> {
    let rules = r###"
    rule large_volumes_are_encrypted when Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size > 10 {
        Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Encrypted == true
    }
    "###;

    let integer_size = r#"{
        "Resources": {
            "V": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50, "Encrypted": false } }
        }
    }"#;
    let decimal_size = r#"{
        "Resources": {
            "V": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50.5, "Encrypted": false } }
        }
    }"#;

    let rules_file = RulesFile::try_from(rules)?;
    for (label, input) in [("integer", integer_size), ("decimal", decimal_size)] {
        let resources = PathAwareValue::try_from(input)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        let status = eval_rules_file(&rules_file, &mut root, None)?;

        assert_eq!(
            status,
            Status::FAIL,
            "the {} template has an unencrypted volume over 10 GiB and must FAIL. SKIP here means \
             the gate could not evaluate its comparison, dropped the body, and exited 0",
            label
        );
    }

    Ok(())
}

/// The comparison operators, pinned across every operand type pairing.
///
/// The mixed-numeric defect fixed in `compare_values` was reachable because no test drove the
/// ordering operators against a type they did not already agree with: `Ge`, `Gt`, `Lt` and `Le` in
/// `real_binary_operation` had no coverage at all. A grid is the cheap way to keep that from
/// recurring, and it doubles as the specification -- each cell is one clause evaluated end to end
/// through `eval_rules_file`.
///
/// Read a grid as rows = the value the template puts in `Properties.Size`, columns = `OPS`. What
/// the grid is really asserting is the absence of a wrong PASS: a cell that says FAIL is saying
/// this pairing cannot be decided or is genuinely false, and either way the run must not exit 0.
/// PASS appears only where the comparison is both decidable and true.
///
/// Two behaviours are worth naming because they look like typos and are not. A list on the left is
/// distributed element-wise, so `[1,2,3] < 50` is PASS -- every element is smaller. And an absent
/// property fails rather than skips, which is the fail-closed behaviour this branch settled on.
#[test]
fn the_comparison_matrix_over_operand_types_is_pinned() -> Result<()> {
    const OPS: [&str; 6] = ["==", "!=", ">", ">=", "<", "<="];

    // (label, what to write for Properties, in template order)
    const LHS: [(&str, &str); 8] = [
        ("int", r#""Size": 50"#),
        ("float", r#""Size": 50.5"#),
        ("string", r#""Size": "fifty""#),
        ("list", r#""Size": [1,2,3]"#),
        ("map", r#""Size": {"a":1}"#),
        ("bool", r#""Size": true"#),
        ("null", r#""Size": null"#),
        ("missing", ""),
    ];

    // (right-hand side as written in the rule, one row per LHS above, cells in OPS order)
    const GRIDS: [(&str, [&str; 8]); 6] = [
        (
            "50",
            [
                "PASS FAIL FAIL PASS FAIL PASS", // int 50 vs 50
                "FAIL PASS PASS PASS FAIL FAIL", // float 50.5 vs 50
                "FAIL FAIL FAIL FAIL FAIL FAIL", // string
                "FAIL PASS FAIL FAIL PASS PASS", // list, element-wise
                "FAIL FAIL FAIL FAIL FAIL FAIL", // map
                "FAIL FAIL FAIL FAIL FAIL FAIL", // bool
                "FAIL FAIL FAIL FAIL FAIL FAIL", // null
                "FAIL FAIL FAIL FAIL FAIL FAIL", // missing property
            ],
        ),
        (
            "10",
            [
                "FAIL PASS PASS PASS FAIL FAIL", // int 50 vs 10
                "FAIL PASS PASS PASS FAIL FAIL", // float 50.5 vs 10
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL PASS FAIL FAIL PASS PASS",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
            ],
        ),
        (
            "10.5",
            [
                "FAIL PASS PASS PASS FAIL FAIL", // int 50 vs float 10.5
                "FAIL PASS PASS PASS FAIL FAIL", // float 50.5 vs float 10.5
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL PASS FAIL FAIL PASS PASS",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
            ],
        ),
        (
            "'fifty'",
            [
                "FAIL FAIL FAIL FAIL FAIL FAIL", // int vs string: not comparable, fails closed
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "PASS FAIL FAIL PASS FAIL PASS", // string vs equal string
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
            ],
        ),
        (
            "[1,2,3]",
            [
                "FAIL FAIL PASS PASS FAIL FAIL", // 50 exceeds every element
                "FAIL FAIL PASS PASS FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "PASS FAIL FAIL FAIL FAIL FAIL", // identical lists
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
            ],
        ),
        (
            "true",
            [
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "PASS FAIL FAIL FAIL FAIL FAIL", // bools compare for equality, not order
                "FAIL FAIL FAIL FAIL FAIL FAIL",
                "FAIL FAIL FAIL FAIL FAIL FAIL",
            ],
        ),
    ];

    let mut cells = 0;
    for (rhs, rows) in GRIDS {
        for ((lhs_label, properties), row) in LHS.iter().zip(rows) {
            let expectations = row.split_whitespace().collect::<Vec<_>>();
            assert_eq!(
                expectations.len(),
                OPS.len(),
                "grid row for {} vs {} has {} cells, expected {}",
                lhs_label,
                rhs,
                expectations.len(),
                OPS.len()
            );

            for (op, expected) in OPS.iter().zip(expectations) {
                let rules = format!(
                    "rule r {{\n  Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {} {}\n}}\n",
                    op, rhs
                );
                let input = format!(
                    r#"{{ "Resources": {{ "V": {{ "Type": "AWS::EC2::Volume", "Properties": {{ {} }} }} }} }}"#,
                    properties
                );

                let rules_file = RulesFile::try_from(rules.as_str())?;
                let resources = PathAwareValue::try_from(input.as_str())?;
                let mut root = root_scope(&rules_file, Rc::new(resources));
                let status = eval_rules_file(&rules_file, &mut root, None)?;

                let expected = match expected {
                    "PASS" => Status::PASS,
                    "FAIL" => Status::FAIL,
                    "SKIP" => Status::SKIP,
                    other => panic!("unknown expectation {} in the grid", other),
                };
                assert_eq!(
                    status, expected,
                    "Size {} {} with a {} operand: expected {:?}, got {:?}",
                    op, rhs, lhs_label, expected, status
                );
                cells += 1;
            }
        }
    }

    assert_eq!(
        cells,
        GRIDS.len() * LHS.len() * OPS.len(),
        "the grid did not evaluate every cell"
    );

    Ok(())
}

/// The type block's status fold, across the resource populations that produce each answer.
///
/// `eval_type_block_clause` counts passes and fails over the matched resources and answers
/// `FAIL` if any failed, else `PASS` if any passed, else `SKIP` -- the same shape as
/// `eval_conjunction_clauses`, and it absorbs a per-resource SKIP the same way. None of those
/// arms had a test reaching them, including the one that decides whether a violating resource is
/// reported at all.
#[test]
fn the_type_block_status_fold_is_pinned() -> Result<()> {
    const RULES: &str = r###"
    rule r {
        AWS::EC2::Volume {
            Properties.Encrypted == true
        }
    }
    "###;

    // (label, resources, expected status)
    let cases: [(&str, &str, Status); 5] = [
        (
            "no resource of that type matches",
            r#""Q": { "Type": "AWS::SQS::Queue", "Properties": {} }"#,
            // Nothing to check, so nothing is asserted. SKIP exits 0, which is only safe
            // because it means the type is genuinely absent from the template.
            Status::SKIP,
        ),
        (
            "one matching resource, compliant",
            r#""A": { "Type": "AWS::EC2::Volume", "Properties": { "Encrypted": true } }"#,
            Status::PASS,
        ),
        (
            "one matching resource, violating",
            r#""A": { "Type": "AWS::EC2::Volume", "Properties": { "Encrypted": false } }"#,
            Status::FAIL,
        ),
        (
            "two resources, one violating",
            r#""A": { "Type": "AWS::EC2::Volume", "Properties": { "Encrypted": true } },
               "B": { "Type": "AWS::EC2::Volume", "Properties": { "Encrypted": false } }"#,
            // The fail must outrank the pass. PASS here would report a compliant template
            // while B goes unencrypted.
            Status::FAIL,
        ),
        (
            "matching resource, property absent",
            r#""A": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50 } }"#,
            // An absent property is not a pass. This is the fail-closed reading the branch
            // settled on for queries that resolve to nothing.
            Status::FAIL,
        ),
    ];

    let rules_file = RulesFile::try_from(RULES)?;
    for (label, resources, expected) in cases {
        let input = format!(r#"{{ "Resources": {{ {} }} }}"#, resources);
        let resources = PathAwareValue::try_from(input.as_str())?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        let status = eval_rules_file(&rules_file, &mut root, None)?;
        assert_eq!(status, expected, "type block with {}", label);
    }

    Ok(())
}

/// A type block's `when` conditions are evaluated against each resource, not the file root.
///
/// The conditions used to be evaluated once, before the loop over matched resources, against the
/// enclosing resolver -- while the block's clauses were evaluated against each resource. That
/// split made the natural spelling a trap. `AWS::EC2::Volume when Properties.Size > 10 { ... }`
/// reads as "every volume over 10 GiB must ..." and instead looked for `Properties` at the file
/// root, found nothing, and skipped: `not_applicable`, exit 0, for every template it was ever run
/// against, including the ones it was written to catch.
///
/// All three spellings are asserted because the change has a cost as well as a benefit, and the
/// cost should be visible in a test rather than inferred from a commit message. A literal
/// root-anchored path resolved before and does not now. The variable idiom is unaffected, which is
/// what makes the trade acceptable: `ValueScope::resolve_variable` delegates to the parent, and
/// real rulesets reach the file root that way rather than by spelling out `Resources.<name>`.
#[test]
fn a_type_block_condition_is_evaluated_against_each_resource() -> Result<()> {
    // Both volumes are over 10 GiB. B is unencrypted, so any spelling that actually applies the
    // block must FAIL, and SKIP means the condition never matched anything.
    const BOTH_LARGE: &str = r#"{
        "Resources": {
            "A": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50, "Encrypted": true } },
            "B": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50, "Encrypted": false } }
        }
    }"#;

    let resource_relative = r###"
    rule r {
        AWS::EC2::Volume when Properties.Size > 10 {
            Properties.Encrypted == true
        }
    }
    "###;

    let through_a_variable = r###"
    let volumes = Resources.*[ Type == 'AWS::EC2::Volume' ]
    rule r {
        AWS::EC2::Volume when %volumes !empty {
            Properties.Encrypted == true
        }
    }
    "###;

    let root_anchored = r###"
    rule r {
        AWS::EC2::Volume when Resources.A.Properties.Size > 10 {
            Properties.Encrypted == true
        }
    }
    "###;

    for (label, rules, expected) in [
        // The spelling that used to skip everything.
        (
            "a resource-relative condition",
            resource_relative,
            Status::FAIL,
        ),
        // Unaffected: variables resolve through the parent scope.
        (
            "a condition on a variable",
            through_a_variable,
            Status::FAIL,
        ),
        // The cost of the change. A path anchored at the file root no longer resolves, because
        // the condition is now evaluated where the clauses are: at the resource.
        ("a root-anchored literal path", root_anchored, Status::SKIP),
    ] {
        let rules_file = RulesFile::try_from(rules)?;
        let resources = PathAwareValue::try_from(BOTH_LARGE)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            expected,
            "type block with {} over a template holding an unencrypted 50 GiB volume",
            label
        );
    }

    // Per-resource applicability is the point of the change, so assert it rather than assuming it
    // follows. A resource the condition exempts must not shield one it does not.
    let rules_file = RulesFile::try_from(resource_relative)?;
    for (label, resources, expected) in [
        (
            "one exempt resource and one violating",
            r#""A": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 5, "Encrypted": false } },
               "B": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 50, "Encrypted": false } }"#,
            Status::FAIL,
        ),
        (
            "every resource exempt",
            r#""A": { "Type": "AWS::EC2::Volume", "Properties": { "Size": 5, "Encrypted": false } }"#,
            // Nothing was asserted, and SKIP says so. A PASS here would claim the unencrypted
            // volume had been checked.
            Status::SKIP,
        ),
    ] {
        let input = format!(r#"{{ "Resources": {{ {} }} }}"#, resources);
        let values = PathAwareValue::try_from(input.as_str())?;
        let mut root = root_scope(&rules_file, Rc::new(values));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            expected,
            "type block over {}",
            label
        );
    }

    Ok(())
}

/// The unary operators, pinned across every value shape they can meet.
///
/// `unary_operation` and the `is_*` family had no test that walked them against the full set of
/// value shapes, which is how the negation arm survived with no coverage at all. The interesting
/// column is EMPTY: on a container it answers, and on a scalar the question is unanswerable, because
/// both statuses are wrong -- an int is not empty, but calling it non-empty implies the question made
/// sense.
///
/// Cells are the status for the operator, then the status for its negation. `CLOSED` marks the
/// unanswerable cells, which FAIL in both polarities rather than inverting. Those cells used to be an
/// error that aborted the whole rules file, discarding every other rule's verdict; the matrix pinned
/// that as `ERR` until `an_incompatible_type_does_not_discard_other_rules` replaced it.
#[test]
fn the_unary_operator_matrix_over_value_shapes_is_pinned() -> Result<()> {
    // (label, what to write for Properties)
    const SHAPES: [(&str, &str); 11] = [
        ("int", r#""Size": 50"#),
        ("float", r#""Size": 50.5"#),
        ("string", r#""Size": "fifty""#),
        ("empty string", r#""Size": """#),
        ("list", r#""Size": [1,2,3]"#),
        ("empty list", r#""Size": []"#),
        ("map", r#""Size": {"a":1}"#),
        ("empty map", r#""Size": {}"#),
        ("bool", r#""Size": true"#),
        ("null", r#""Size": null"#),
        ("absent", ""),
    ];

    // (operator, one cell per SHAPES row, in order)
    const MATRIX: [(&str, [&str; 11]); 8] = [
        // int   float  str    ""     list   []     map    {}     bool   null   absent
        (
            "EXISTS",
            [
                "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS", "PASS",
                "FAIL",
            ],
        ),
        (
            "EMPTY",
            [
                "CLOSED", "CLOSED", "FAIL", "PASS", "FAIL", "PASS", "FAIL", "PASS", "CLOSED",
                "CLOSED", "PASS",
            ],
        ),
        (
            "IS_STRING",
            [
                "FAIL", "FAIL", "PASS", "PASS", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL",
                "FAIL",
            ],
        ),
        (
            "IS_LIST",
            [
                "FAIL", "FAIL", "FAIL", "FAIL", "PASS", "PASS", "FAIL", "FAIL", "FAIL", "FAIL",
                "FAIL",
            ],
        ),
        (
            "IS_STRUCT",
            [
                "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "PASS", "PASS", "FAIL", "FAIL",
                "FAIL",
            ],
        ),
        (
            "IS_BOOL",
            [
                "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "PASS", "FAIL",
                "FAIL",
            ],
        ),
        (
            "IS_INT",
            [
                "PASS", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL",
                "FAIL",
            ],
        ),
        (
            "IS_FLOAT",
            [
                "FAIL", "PASS", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL", "FAIL",
                "FAIL",
            ],
        ),
    ];

    fn evaluate(clause: &str, properties: &str) -> Result<Option<Status>> {
        let rules = format!(
            "rule r {{\n  Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {}\n}}\n",
            clause
        );
        let input = format!(
            r#"{{ "Resources": {{ "V": {{ "Type": "AWS::EC2::Volume", "Properties": {{ {} }} }} }} }}"#,
            properties
        );
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let resources = PathAwareValue::try_from(input.as_str())?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        // `None` is an error escaping the evaluation. No cell in this matrix should produce one --
        // an unanswerable clause is a verdict about that clause now, not an abort -- so the option is
        // kept in order to fail on it explicitly rather than to tolerate it.
        Ok(eval_rules_file(&rules_file, &mut root, None).ok())
    }

    for (operator, cells) in MATRIX {
        for ((shape, properties), expected) in SHAPES.iter().zip(cells) {
            let plain = evaluate(operator, properties)?;
            let negated = evaluate(&format!("not {}", operator), properties)?;

            match expected {
                "CLOSED" => {
                    // Both polarities, and both FAIL. A negation that inverted here would be the
                    // worse outcome: `not EMPTY` on an int would PASS, certifying a clause the
                    // evaluator could not evaluate.
                    assert_eq!(
                        plain,
                        Some(Status::FAIL),
                        "{} on a {} operand cannot be answered, so it must fail closed",
                        operator,
                        shape
                    );
                    assert_eq!(
                        negated,
                        Some(Status::FAIL),
                        "not {} on a {} operand must also fail closed rather than inverting",
                        operator,
                        shape
                    );
                }
                "PASS" | "FAIL" => {
                    let (want, want_negated) = if expected == "PASS" {
                        (Status::PASS, Status::FAIL)
                    } else {
                        (Status::FAIL, Status::PASS)
                    };
                    assert_eq!(plain, Some(want), "{} on a {} operand", operator, shape);
                    // The negation must invert. A negated operator that answers the same status
                    // as its positive form is the shape of the role-propagation defect: the
                    // clause stops discriminating and a violating template can exit 0.
                    assert_eq!(
                        negated,
                        Some(want_negated),
                        "not {} on a {} operand must invert {} 's answer",
                        operator,
                        shape,
                        operator
                    );
                }
                other => panic!("unknown expectation {} in the matrix", other),
            }
        }
    }

    Ok(())
}

/// The status decisions that a coverage sweep found nothing reaching.
///
/// Grouped into one test because they share a purpose rather than a mechanism: each is a line that
/// decides PASS, FAIL or SKIP and that no test in the suite executed. That is the shape the two
/// defects in this branch's parent PR had, and the shape the mixed-numeric defect had -- not an
/// exotic input, just a decision nobody had ever asserted.
///
/// None of these turned out to be wrong, which is worth recording as plainly as a bug would be: an
/// audit that only reports its finds is indistinguishable from one that stopped early.
#[test]
fn the_status_decisions_with_no_prior_coverage_are_correct() -> Result<()> {
    const RESOURCES: &str = r#"{
        "Resources": { "B": { "Type": "AWS::S3::Bucket", "Properties": { "Name": "b" } } }
    }"#;

    // A clause-level `not` in front of `EMPTY`, where two negations compose: the operator's own
    // flag and the clause's. The arm that applies the second had never run in either direction.
    //
    // The query has to end in a filter, or be a lone variable, to reach that arm at all.
    // `unary_operation` handles `EMPTY` on such a query in a separate early-return block, and the
    // clause-level flip lives inside that block. A first version of this test used
    // `not Resources.B.Properties.Missing EMPTY`, a plain key path: it produced the right answer
    // by an entirely different route and left the arm at zero. Worth knowing before editing these.
    let clause_level_negation = [
        // %buckets is not empty, so `EMPTY` is false and the clause's `not` makes it true.
        (
            "not %buckets EMPTY",
            "let buckets = Resources.*[ Type == \"AWS::S3::Bucket\" ]\n\
             rule r { not %buckets EMPTY }",
            Status::PASS,
        ),
        // Both negations applied. If the two flips ever collapsed into one, this row and the one
        // above would agree -- and a clause that answers the same either way has stopped
        // discriminating, which is the defect this branch opened with.
        (
            "not %buckets not EMPTY",
            "let buckets = Resources.*[ Type == \"AWS::S3::Bucket\" ]\n\
             rule r { not %buckets not EMPTY }",
            Status::FAIL,
        ),
        // The same clause without the leading `not`, so the flip is visibly what moves the answer.
        (
            "%buckets EMPTY, no clause negation",
            "let buckets = Resources.*[ Type == \"AWS::S3::Bucket\" ]\n\
             rule r { %buckets EMPTY }",
            Status::FAIL,
        ),
        // A filter as the final query part reaches the same block by the other condition, and a
        // filter selecting nothing takes the empty branch inside it.
        (
            "not <filter> EMPTY, filter matches",
            r#"rule r { not Resources.*[ Type == "AWS::S3::Bucket" ] EMPTY }"#,
            Status::PASS,
        ),
        (
            "not <filter> EMPTY, filter matches nothing",
            r#"rule r { not Resources.*[ Type == "AWS::None::Type" ] EMPTY }"#,
            Status::FAIL,
        ),
    ];

    // A negated parameterized call. The SKIP case is already covered; these are the two where the
    // invoked rule reached a verdict and the negation has to invert it.
    let negated_parameterized = [
        (
            "not r(x) where r fails",
            "rule inner(n) { Resources.B.Properties.Name == %n }\nrule r { not inner(\"wrong\") }",
            Status::PASS,
        ),
        (
            "not r(x) where r passes",
            "rule inner(n) { Resources.B.Properties.Name == %n }\nrule r { not inner(\"b\") }",
            Status::FAIL,
        ),
    ];

    // A disjunction in which every disjunct skipped. SKIP rather than PASS matters: PASS would
    // report that one of the alternatives held when none of them was evaluated.
    let all_disjuncts_skip = [(
        "gate disjunction where both sides skip",
        "rule gate(ty) { Resources.*[ Type == %ty ].Properties.Name == \"zzz\" }\n\
         rule r when gate(\"AWS::None::One\") or gate(\"AWS::None::Two\") { \
         Resources.B.Properties.Name == \"nope\" }",
        Status::SKIP,
    )];

    for (label, rules, expected) in clause_level_negation
        .iter()
        .chain(negated_parameterized.iter())
        .chain(all_disjuncts_skip.iter())
    {
        let rules_file = RulesFile::try_from(*rules)?;
        let resources = PathAwareValue::try_from(RESOURCES)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            *expected,
            "{}",
            label
        );
    }

    Ok(())
}

/// The disjunction context must not carry compiler-version-dependent text.
///
/// `std::any::type_name` is documented as being for diagnostics with no stability guarantee, and
/// this use is not confined to diagnostics: the result goes into a record context that reaches
/// verbose output, which four golden-file tests compare byte for byte. rustc 1.77.2 renders
/// `GuardClause<'_>` and later versions render `GuardClause`, so before this was normalised the
/// suite passed on the pinned toolchain and failed on any newer one -- those four tests had to be
/// skipped to measure coverage on nightly at all.
///
/// Asserting the absence of generic arguments rather than a literal expected string, because the
/// module path could legitimately change if these types move, and pinning it would turn a rename
/// into a test failure for no reason. What must not come back is the part that varies by compiler.
#[test]
fn the_disjunction_context_is_stable_across_compilers() {
    for name in [
        disjunction_type_name::<GuardClause<'_>>(),
        disjunction_type_name::<RuleClause<'_>>(),
        disjunction_type_name::<WhenGuardClause<'_>>(),
    ] {
        assert!(
            !name.contains('<') && !name.contains('>'),
            "the disjunction context still carries generic arguments ({}), which rustc renders \
             differently between versions",
            name
        );
        assert!(
            name.ends_with("Clause"),
            "expected the clause type's name, got {}",
            name
        );
    }
}

/// An index after an interpolated key selects the key; it must not then be applied to the value.
///
/// `query_retrieval_with_converter` resolves a variable used where a map key is expected, and peeks
/// at the following query part: an index there says *which* of the resolved keys to use. Having
/// consumed it, the recursion advanced by one anyway, so the index was applied a second time -- to
/// the value the key had just selected. `Resources.%names[0].Type` picked `BucketA` and then tried
/// to index into it, the query resolved to nothing, and every part after `[0]` was discarded.
///
/// It survived because the form without an index always worked, so a reader comparing
/// `Resources.%names.Type` against `Resources.%names[0].Type` would see one work and assume the
/// other was a rule-authoring mistake. The failure is also quiet in the wrong way: an unresolved
/// query is reported as a retrieval failure on the input, not as a query the evaluator could not
/// walk, so it reads as a problem with the template.
///
/// The gate case is asserted last because that is where it costs enforcement rather than just a
/// wrong verdict: an unresolved condition does not pass, a rule whose condition does not pass is
/// reported not applicable, and its body never runs. Same shape as the mixed-numeric defect,
/// reached through the query resolver instead of the comparison.
#[test]
fn an_index_after_an_interpolated_key_is_not_applied_twice() -> Result<()> {
    // `Pointer` names two other resources, so `%names` resolves to the keys "BucketA" and "BucketB".
    const RESOURCES: &str = r#"{
        "Resources": {
            "Pointer": {
                "Type": "AWS::CloudFormation::Stack",
                "Properties": { "Targets": ["BucketA", "BucketB"] }
            },
            "BucketA": { "Type": "AWS::S3::Bucket", "Properties": { "Name": "a" } },
            "BucketB": { "Type": "AWS::S3::Bucket", "Properties": { "Name": "b" } }
        }
    }"#;

    const PREAMBLE: &str = "let names = Resources.Pointer.Properties.Targets[*]\n";

    let cases: [(&str, &str, Status); 7] = [
        // Selecting a key by index, then continuing the traversal. All of these resolved to
        // nothing before the fix, so all of them failed.
        (
            "index then a key",
            r#"rule r { Resources.%names[0].Type == "AWS::S3::Bucket" }"#,
            Status::PASS,
        ),
        (
            "index then two more keys",
            r#"rule r { Resources.%names[0].Properties.Name == "a" }"#,
            Status::PASS,
        ),
        (
            "the second key",
            r#"rule r { Resources.%names[1].Properties.Name == "b" }"#,
            Status::PASS,
        ),
        // Still able to fail: the fix must not make the query resolve to something that passes
        // regardless of the value.
        (
            "index then a key, wrong value",
            r#"rule r { Resources.%names[0].Properties.Name == "b" }"#,
            Status::FAIL,
        ),
        // Without an index every resolved key is used, so BucketB's "b" fails the check.
        (
            "no index, all keys",
            r#"rule r { Resources.%names.Properties.Name == "a" }"#,
            Status::FAIL,
        ),
        // An index past the resolved keys is still out of bounds, and still fails closed.
        (
            "index out of bounds",
            r#"rule r { Resources.%names[5].Type == "AWS::S3::Bucket" }"#,
            Status::FAIL,
        ),
        // The same query as a condition. Before the fix this was SKIP: the gate could not be
        // resolved, so the rule was reported not applicable and the violation below went
        // unreported at exit 0.
        (
            "the same query as a gate",
            r#"rule r when Resources.%names[0].Type == "AWS::S3::Bucket" {
                   Resources.BucketA.Properties.Name == "nonsense"
               }"#,
            Status::FAIL,
        ),
    ];

    for (label, rule, expected) in cases {
        let rules = format!("{}{}", PREAMBLE, rule);
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let resources = PathAwareValue::try_from(RESOURCES)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            expected,
            "{}",
            label
        );
    }

    Ok(())
}

/// An unresolvable type block query must skip, not abort the rules file.
///
/// This one is a regression this branch introduced and a defect it inherited, in the same place.
///
/// Moving a type block's conditions per-resource removed an early return that had been masking an
/// error path: the condition never passed when written resource-relative, so the block's query never
/// ran. With the conditions inside the loop the query always runs, and against a document with no
/// `Resources` at its root it produced an `UnResolved` slot, whose arm returned `Err`. An `Err` from
/// a rule aborts the whole rules file, so a violation an *unrelated* rule had already found stopped
/// being reported and the exit code went from 19 to 255.
///
/// The inherited half is that a type block with no `when` at all reached the same `Err` on the
/// merge-base, so the abort predates this work; the change only made it reachable for the guarded
/// form. Both are fixed by treating an unselectable slot the way the `values.is_empty()` branch
/// already treats an empty selection -- as not applicable. `ur.reason` moves onto the record instead
/// of into an error, so the explanation still reaches the reader.
///
/// The last assertion is the one that matters. A differential against the merge-base is what found
/// this, and it only found it once the corpus contained a rules file holding a type block *and*
/// something else; with one rule per file the abort and a clean skip are indistinguishable by exit
/// code alone.
#[test]
fn an_unresolved_type_block_query_skips_without_aborting_the_file() -> Result<()> {
    // No `Resources` key at all, so the type block's query cannot be resolved.
    const NO_RESOURCES: &str = r#"{ "Region": "us-east-1", "Account": "123456789012" }"#;

    let plain = r###"
    rule r {
        AWS::EC2::Volume {
            Properties.Encrypted == true
        }
    }
    "###;

    let guarded = r###"
    rule r {
        AWS::EC2::Volume when Properties.Size > 10 {
            Properties.Encrypted == true
        }
    }
    "###;

    for (label, rules) in [("without a when", plain), ("with a when", guarded)] {
        let rules_file = RulesFile::try_from(rules)?;
        let resources = PathAwareValue::try_from(NO_RESOURCES)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        let status = eval_rules_file(&rules_file, &mut root, None);
        assert!(
            status.is_ok(),
            "a type block {} whose query cannot be resolved returned an error, which aborts the \
             whole rules file: {:?}",
            label,
            status.err()
        );
        assert_eq!(
            status.unwrap(),
            Status::SKIP,
            "a type block {} over a document that does not contain the type is not applicable",
            label
        );
    }

    // The reason the Err mattered: it took unrelated rules down with it. This file holds a failing
    // rule that has nothing to do with the type block, and its verdict has to survive.
    let two_rules = r###"
    rule unrelated_violation {
        Region == "eu-west-1"
    }
    rule type_block_rule {
        AWS::EC2::Volume when Properties.Size > 10 {
            Properties.Encrypted == true
        }
    }
    "###;
    let rules_file = RulesFile::try_from(two_rules)?;
    let resources = PathAwareValue::try_from(NO_RESOURCES)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    assert_eq!(
        eval_rules_file(&rules_file, &mut root, None)?,
        Status::FAIL,
        "the unrelated rule fails on this input, and an unresolvable type block elsewhere in the \
         file must not suppress that"
    );

    Ok(())
}

/// An index literal too large for the array must not panic the process.
///
/// The parser reads index literals as `i64` and narrows them with `as i32`, so a positive literal
/// above `i32::MAX` arrives at the evaluator as a negative number, and `2147483648` arrives as
/// exactly `i32::MIN`. The three places that turned an index into a slot took its absolute value
/// with `-index`, which is not representable for `i32::MIN`: debug builds panicked with "attempt to
/// negate with overflow" and release builds wrapped, then failed the bounds check with a value
/// nobody could read.
///
/// A panic is the wrong answer for any rule text. cfn-guard is a library as well as a CLI, and this
/// input is reachable from a ruleset with a typo in it -- the repo fuzzes rule parsing precisely
/// because that is not a hypothetical.
///
/// Both the interpolated-key path and the plain list path are exercised, because they call different
/// functions with the same defect. What each answers is unchanged for in-range indices; the
/// out-of-range ones now resolve to nothing instead of aborting.
#[test]
fn an_out_of_range_index_does_not_panic() -> Result<()> {
    const DATA: &str = r#"{ "Items": [ "zero", "one" ], "Resources": { "A": { "Type": "t" } } }"#;

    // `i32::MIN` after the parser's `as i32` narrowing, spelled both ways, plus the plain negative.
    let queries = [
        "Items[2147483648]",
        "Items[-2147483648]",
        "Items[-1]",
        "Items[0]",
    ];

    for query in queries {
        let rules = format!("rule r {{\n    {} == \"zero\"\n}}\n", query);
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let value = PathAwareValue::try_from(DATA)?;
        let mut root = root_scope(&rules_file, Rc::new(value));
        // The verdict is not the point -- not panicking is. Asserting `is_ok` also covers the
        // release-build half, where the wrapped index produced a retrieval error rather than a
        // crash and so would have passed a panic-only test.
        let status = eval_rules_file(&rules_file, &mut root, None);
        assert!(
            status.is_ok(),
            "{} returned an error instead of resolving or failing to resolve: {:?}",
            query,
            status.err()
        );
    }

    // In-range indices still answer what they always did, in case `unsigned_abs` changed more than
    // the overflow case. Guard treats a negative index as its absolute value rather than as an
    // offset from the end, which is surprising but long-standing, so `[-1]` and `[1]` agree.
    for (query, expected) in [
        ("Items[0]", Status::PASS),
        ("Items[1]", Status::FAIL),
        ("Items[-1]", Status::FAIL),
    ] {
        let rules = format!("rule r {{\n    {} == \"zero\"\n}}\n", query);
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let value = PathAwareValue::try_from(DATA)?;
        let mut root = root_scope(&rules_file, Rc::new(value));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            expected,
            "{} against {}",
            query,
            DATA
        );
    }

    Ok(())
}

/// A type block that reports SKIP names a cause it can actually support.
///
/// There are four ways to get here and the block used to distinguish two of them, so the other two
/// were told the wrong story: the fallback sentence claimed "every X in the input was exempted by
/// the type block's `when` condition", which is a false statement whenever the block has no `when`
/// condition at all. That is reachable two ways -- a filter in a body clause selecting nothing, and
/// an inner `when` that does not fire -- and both are ordinary rule shapes rather than contrivances.
///
/// Naming the wrong cause is worse than naming none, because it sends the reader to inspect a
/// condition that does not exist. This whole branch is about making an exit-0 non-check visible, and
/// a wrong explanation is a regression against that, not a cosmetic one.
///
/// Asserted through the record tree rather than the console, so the test does not depend on which
/// reporter is in play; `a_skipped_type_block_explains_itself_in_the_output` covers the rendering.
#[test]
fn a_type_block_skip_names_the_cause_it_can_support() -> Result<()> {
    // One volume, 5 GiB, unencrypted. It carries a tag so that a filter over `Tags` selects
    // nothing rather than failing to resolve `Tags` at all -- those are different outcomes, and
    // only the first one reaches the SKIP arms under test.
    const ONE_SMALL_VOLUME: &str = r#"{
        "Resources": {
            "Vol": {
                "Type": "AWS::EC2::Volume",
                "Properties": {
                    "Size": 5,
                    "Encrypted": false,
                    "Tags": [ { "Key": "Name", "Value": "v" } ]
                }
            }
        }
    }"#;

    // (label, rules, the fragment the reason must contain, a fragment it must not)
    let cases = [
        (
            "a `when` condition that exempted the only volume",
            r###"
            rule r {
                AWS::EC2::Volume when Properties.Size > 10 {
                    Properties.Encrypted == true
                }
            }
            "###,
            "exempted by the type block's `when` condition",
            "no clause in the type block applied",
        ),
        (
            "no `when` condition, body filter selects nothing",
            r###"
            rule r {
                AWS::EC2::Volume {
                    Properties.Tags[ Key == 'nope' ].Value == 'x'
                }
            }
            "###,
            "no clause in the type block applied",
            // Tighter than "was exempted": a block with no `when` of its own must not mention one
            // at all, which is the mistake this case exists to catch.
            "`when` condition",
        ),
        (
            "no `when` condition, inner `when` does not fire",
            r###"
            rule r {
                AWS::EC2::Volume {
                    when Properties.Size > 100 {
                        Properties.Encrypted == true
                    }
                }
            }
            "###,
            "no clause in the type block applied",
            // Tighter than "was exempted": a block with no `when` of its own must not mention one
            // at all, which is the mistake this case exists to catch.
            "`when` condition",
        ),
        (
            "the type is absent from the input entirely",
            r###"
            rule r {
                AWS::SQS::Queue {
                    Properties.QueueName exists
                }
            }
            "###,
            "no AWS::SQS::Queue in the input",
            "exempted",
        ),
    ];

    for (label, rules, expected, forbidden) in cases {
        let rules_file = RulesFile::try_from(rules)?;
        let value = PathAwareValue::try_from(ONE_SMALL_VOLUME)?;
        let mut root = root_scope(&rules_file, Rc::new(value));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            Status::SKIP,
            "{label}: the rule does not apply on this input"
        );
        let top = root.reset_recorder().extract();
        // Arguments spelled out rather than captured inline: this crate is on edition 2018, where a
        // lone string literal passed to `assert!`/`panic!` becomes the payload verbatim instead of
        // going through `format_args!`, so `{label}` would print as those seven characters.
        let reason = crate::rules::eval_context::find_skip_reason(&top)
            .unwrap_or_else(|| panic!("{}: no skip reason was recorded at all", label));
        assert!(
            reason.contains(expected),
            "{}: wanted {:?} in the reason, got {:?}",
            label,
            expected,
            reason
        );
        assert!(
            !reason.contains(forbidden),
            "{}: the reason claimed {:?}, which this rule cannot support: {:?}",
            label,
            forbidden,
            reason
        );
    }

    Ok(())
}

/// The two spellings of a `when` gate on an inapplicable rule have to agree, and neither may
/// silently disarm the block.
///
/// `eval_conjunction_clauses` absorbs a SKIP and counts a FAIL, and answers FAIL before PASS. So a
/// gate condition that returns FAIL because the rule it references did not apply outranks the
/// sibling conditions that passed: the `when` does not pass, `eval_rule` drops the body, and the
/// file exits 0 having enforced nothing. That is the failure mode `ClauseRole::Gate` exists to
/// prevent -- "the block it guards is still decided by the remaining conditions".
///
/// `eval_parameterized_rule_call` was given a `Status::SKIP if !negation => Status::SKIP` arm for
/// exactly this, with a comment claiming it mirrors `eval_guard_named_clause`. It did not:
/// `eval_guard_named_clause` had no such arm, so the plain reference still answered FAIL. Two
/// rulesets that differ only in whether the gate takes a parameter disagreed -- one exited 0 with
/// the body unenforced, the other exited 19 having enforced it.
///
/// Both spellings are asserted here rather than only the fixed one, because the property under test
/// is the agreement. A future change that "fixes" the parameterized arm back to FAIL would keep a
/// single-spelling test passing.
///
/// The single-condition case is asserted alongside: with one condition, SKIP and FAIL are
/// indistinguishable at the rule level (`eval_rule` maps every non-PASS condition to SKIP), so a
/// test that used one condition would have passed against the defect.
#[test]
fn a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block() -> Result<()> {
    // `skipper`'s filter selects nothing, so its only clause -- and therefore the rule -- is SKIP.
    // `Present` is 3, so the guarded body fails if it is ever reached.
    const DATA: &str = r#"{ "Present": 3, "Items": [ { "Kind": "yes", "Value": 1 } ] }"#;

    let named = r###"
    rule skipper {
        Items[ Kind == 'nope' ].Value == 1
    }

    rule gated when skipper
                    Present exists {
        Present == 2
    }
    "###;

    let parameterized = r###"
    rule skipper(v) {
        Items[ Kind == 'nope' ].Value == %v
    }

    rule gated when skipper(1)
                    Present exists {
        Present == 2
    }
    "###;

    for (label, rules) in [
        ("a plain named-rule gate", named),
        ("a parameterized gate", parameterized),
    ] {
        let rules_file = RulesFile::try_from(rules)?;
        let value = PathAwareValue::try_from(DATA)?;
        let mut root = root_scope(&rules_file, Rc::new(value));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            Status::FAIL,
            "{label} on a rule that did not apply was absorbed by neither the conjunction nor the \
             fold: the sibling condition passed, so the body had to be enforced and it fails on \
             this input. SKIP here means the body was dropped at exit 0."
        );
    }

    // With the gate as the only condition the rule is genuinely inapplicable, and stays so.
    let sole_condition = r###"
    rule skipper {
        Items[ Kind == 'nope' ].Value == 1
    }

    rule gated when skipper {
        Present == 2
    }
    "###;
    let rules_file = RulesFile::try_from(sole_condition)?;
    let value = PathAwareValue::try_from(DATA)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    assert_eq!(
        eval_rules_file(&rules_file, &mut root, None)?,
        Status::SKIP,
        "with nothing else to decide the `when`, a gate on an inapplicable rule leaves the rule \
         inapplicable"
    );

    Ok(())
}

/// Generated rule shapes, checked against invariants that need no oracle.
///
/// Every hand-written test in this file asserts a verdict someone worked out by hand, which means it
/// covers the combinations that occurred to whoever wrote it. The regression this branch introduced
/// was invisible to all of them and to a differential over the repository's 45 rule files, because it
/// only appeared when a rules file held a type block *and* an unrelated rule -- with one rule per
/// file, an abort and a clean skip both leave nothing reported and are indistinguishable. Combining
/// constructs is what a generator does that a fixture author does not.
///
/// The invariants below hold regardless of what the right answer for a given rule is, which is what
/// makes generation useful here: there is no oracle, so anything requiring one is not asserted.
///
/// 1. **Canary isolation.** Prepending an always-failing rule must still report that rule's failure.
///    This is the invariant that catches an abort, and the one the regression violated.
/// 2. **Determinism.** The same input evaluated twice gives the same status.
/// 3. **Negation discriminates.** For a clause both polarities can decide, `not X` and `X` must not
///    agree. A clause that answers the same either way has stopped checking anything, which is the
///    defect `a54e4ca` and `0e140b3` fixed.
///
/// Invariant 1 held an exception until recently: an incompatible-type error propagated out and
/// aborted the rules file, so a canary in the same file lost its finding, and the test asserted the
/// exception rather than skipping the cell. That is what told us the exception could be deleted once
/// the error became a per-clause failure, and it is why the assertion is now unconditional -- no
/// generated cell may error at all. Asserting an exception you intend to remove is worth more than
/// excluding the cell, because the exclusion would still be here.
#[test]
fn generated_rule_shapes_hold_the_evaluator_invariants() -> Result<()> {
    const FILTER: &str = "Resources.*[ Type == 'AWS::EC2::Volume' ]";
    const CANARY: &str = "rule zz_canary_must_fail {\n    Region == 'no-such-region-zzz'\n}\n\n";

    // (label, clause). Every one is valid in an assertion and in a condition.
    let clauses: [(&str, String); 7] = [
        ("eq_int", format!("{FILTER}.Properties.Size == 50")),
        ("gt_int", format!("{FILTER}.Properties.Size > 10")),
        ("le_float", format!("{FILTER}.Properties.Size <= 100.5")),
        (
            "in_list",
            format!("{FILTER}.Properties.Size IN [10, 50, 100]"),
        ),
        ("exists", format!("{FILTER}.Properties.Size EXISTS")),
        ("is_int", format!("{FILTER}.Properties.Size IS_INT")),
        // EMPTY on an integer cannot be answered: an int is not empty, but calling it non-empty
        // implies the question made sense. It fails closed in both polarities and, until this
        // branch, aborted the whole file instead. The clause earns its place by being the one that
        // used to abort -- it is what the canary invariant was strengthened against.
        ("empty_on_scalar", format!("{FILTER}.Properties.Size EMPTY")),
    ];

    // (label, document). The families matter more than the count: a query that resolves, one that
    // resolves to the wrong type, one that resolves to nothing, and one with no root at all -- which
    // is the input that turned an unresolvable type block query into an abort.
    let templates: [(&str, &str); 6] = [
        (
            "resolvable",
            r#"{"Region":"us-east-1","Resources":{"V":{"Type":"AWS::EC2::Volume","Properties":{"Size":50,"Encrypted":true}}}}"#,
        ),
        (
            "violating",
            r#"{"Region":"us-east-1","Resources":{"V":{"Type":"AWS::EC2::Volume","Properties":{"Size":50,"Encrypted":false}}}}"#,
        ),
        (
            "float_size",
            r#"{"Region":"us-east-1","Resources":{"V":{"Type":"AWS::EC2::Volume","Properties":{"Size":50.5,"Encrypted":false}}}}"#,
        ),
        (
            "string_size",
            r#"{"Region":"us-east-1","Resources":{"V":{"Type":"AWS::EC2::Volume","Properties":{"Size":"50","Encrypted":false}}}}"#,
        ),
        (
            "absent_property",
            r#"{"Region":"us-east-1","Resources":{"V":{"Type":"AWS::EC2::Volume","Properties":{}}}}"#,
        ),
        (
            "absent_root",
            r#"{"Region":"us-east-1","Account":"123456789012"}"#,
        ),
    ];

    // Each takes a clause and yields a rule body. `body` is a second assertion, so guarded shapes
    // have something to guard.
    fn shapes(clause: &str, body: &str) -> Vec<(&'static str, String)> {
        vec![
            ("bare", format!("rule r {{\n    {clause}\n}}\n")),
            ("gate", format!("rule r when {clause} {{\n    {body}\n}}\n")),
            (
                "nested_when",
                format!("rule r {{\n    when {clause} {{\n        when {clause} {{\n            {body}\n        }}\n    }}\n}}\n"),
            ),
            ("conjunction", format!("rule r {{\n    {clause}\n    {body}\n}}\n")),
            ("disjunction", format!("rule r {{\n    {clause} or\n    {body}\n}}\n")),
            (
                "type_block_gate",
                "rule r {\n    AWS::EC2::Volume when Properties.Size > 10 {\n        Properties.Encrypted == true\n    }\n}\n".to_string(),
            ),
        ]
    }

    fn evaluate(rules: &str, data: &str) -> Result<Status> {
        let rules_file = RulesFile::try_from(rules)?;
        let resources = PathAwareValue::try_from(data)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        eval_rules_file(&rules_file, &mut root, None)
    }

    let body = format!("{FILTER}.Properties.Encrypted == true");
    let mut cells = 0;

    for (clause_label, clause) in &clauses {
        for (shape_label, rule) in shapes(clause, &body) {
            for (tmpl_label, data) in templates {
                let case = format!("{clause_label}/{shape_label} over {tmpl_label}");
                let alone = evaluate(&rule, data);

                // 2. Determinism. Cheap, and it catches state or ordering leaking between runs.
                let again = evaluate(&rule, data);
                match (&alone, &again) {
                    (Ok(first), Ok(second)) => assert_eq!(
                        first, second,
                        "{case}: evaluating the same input twice gave different statuses"
                    ),
                    (Err(_), Err(_)) => {}
                    _ => panic!(
                        "{}: one of two identical evaluations errored and the other did not",
                        case
                    ),
                }

                // 1. Canary isolation. No cell may error: an error escaping one rule aborts the
                // file and discards every other rule's verdict, which the canary is there to detect.
                assert!(
                    alone.is_ok(),
                    "{}: the rule returned an error rather than a verdict, which aborts the whole \
                     rules file: {:?}",
                    case,
                    alone.as_ref().err()
                );
                let with_canary = evaluate(&format!("{CANARY}{rule}"), data);
                assert_eq!(
                    with_canary.as_ref().ok(),
                    Some(&Status::FAIL),
                    "{case}: adding an unrelated always-failing rule stopped that rule's \
                     failure being reported, which is what an abort looks like from outside"
                );
                cells += 1;
            }
        }
    }

    // 4. The generator cannot silently shrink. 7 clauses x 6 shapes x 6 templates.
    assert_eq!(cells, 7 * 6 * 6, "the generated space changed size");

    // 3. Negation. Two assertions, because the obvious one is wrong.
    //
    // `not X` does not have to differ from `X` in general: a comparison that cannot be decided fails
    // closed in *both* polarities, which is deliberate and documented in CLAUSES.md -- `Size == 50`
    // and `not Size == 50` both FAIL when Size is the string "50", and both fail when the right-hand
    // reference resolves to nothing. An earlier version of this test asserted they always differ and
    // failed on exactly that case, which is the right outcome for the wrong reason.
    //
    // What always holds is that they must not both PASS. A clause and its negation both holding is
    // incoherent regardless of what the operands are.
    //
    // The stronger form is asserted where decidability is known: over the two templates whose
    // properties are present and of the expected type, every clause here can be decided, so a `not`
    // that changed nothing is the defect `a54e4ca` and `0e140b3` fixed -- and that defect made the
    // pair identical, which the both-PASS rule alone would miss whenever the answer was FAIL.
    const DECIDABLE: [&str; 2] = ["resolvable", "violating"];
    // Decidability is a property of the clause as well as the template. `EMPTY` on an integer cannot
    // be answered whatever the document says, so it fails closed in both polarities by design and the
    // stronger assertion does not apply to it. The both-PASS rule below still does, which is the half
    // that would catch a fail-closed clause turning into a pass-open one.
    const UNANSWERABLE: [&str; 1] = ["empty_on_scalar"];
    for (clause_label, clause) in &clauses {
        for (tmpl_label, data) in templates {
            let plain = evaluate(&format!("rule r {{\n    {clause}\n}}\n"), data);
            let negated = evaluate(&format!("rule r {{\n    not {clause}\n}}\n"), data);
            let (Ok(p), Ok(n)) = (plain, negated) else {
                // Explicit arguments: on edition 2018 a single-literal panic message is not a format
                // string, so inline captures would print as braces.
                panic!(
                    "{} over {}: evaluation returned an error rather than a verdict",
                    clause_label, tmpl_label
                );
            };
            assert!(
                !(p == Status::PASS && n == Status::PASS),
                // Explicit arguments: on edition 2018 a single-literal assert message is not a
                // format string, so inline captures would print as braces.
                "{} over {}: the clause and its negation both passed",
                clause_label,
                tmpl_label
            );
            if DECIDABLE.contains(&tmpl_label)
                && !UNANSWERABLE.contains(clause_label)
                && p != Status::SKIP
                && n != Status::SKIP
            {
                assert_ne!(
                    p, n,
                    "{clause_label} over {tmpl_label}: the clause and its negation both answered \
                     {p:?} over input that decides it, so the `not` changed nothing"
                );
            }
        }
    }

    Ok(())
}
