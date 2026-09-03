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

/// Build the rule the capture-scoping tests use, over a given spelling of the capturing selection.
///
/// The `or` is what makes an iteration able to capture nothing while still reaching the clause that
/// reads the capture: a bucket with no *enabled* config takes the second disjunct, so the filter never
/// selects an entry and no key is captured, and `some %cfg` is evaluated anyway.
///
/// Parameterised over the spelling because the two spellings reach the capture by different paths --
/// `Properties.Config[ cfg | ... ]` filters the map directly, `Properties.Config[*][ cfg | ... ]`
/// expands it first -- and a fix that covered only the first left the second answering with a previous
/// resource's key at exit 0.
fn config_capture_rule(selection: &str) -> String {
    format!(
        r#"
rule configs_named_alpha {{
    Resources.*[ Type == 'AWS::S3::Bucket' ] {{
        {selection} !empty or
        {selection} empty
        some %cfg == "alpha"
    }}
}}
"#,
        selection = selection
    )
}

const CONFIG_CAPTURE_SELECTIONS: [&str; 2] = [
    "Properties.Config[ cfg | Enabled == true ]",
    "Properties.Config[*][ cfg | Enabled == true ]",
];

/// `BucketA` has an enabled config named `alpha`; `BucketB` has one, but disabled.
const COMPLIANT_BUCKET_FIRST: &str = r#"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        alpha:
          Enabled: true
  BucketB:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        beta:
          Enabled: false
"#;

/// The same two resources as [`COMPLIANT_BUCKET_FIRST`], in the other order.
const COMPLIANT_BUCKET_SECOND: &str = r#"
Resources:
  BucketB:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        beta:
          Enabled: false
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        alpha:
          Enabled: true
"#;

/// `[*]` and `.*` followed by a filter agree on a map that is a single object.
///
/// Both wildcards expand a map into its entries, so for a `Statement` written as one object the value
/// reaching the filter is a *field value* -- the string `Allow` -- and `Effect == 'Allow'` resolves
/// nothing against it. `[*]` evaluated the predicate there anyway, selected nothing, and an assertion
/// over the empty selection reported SKIP at exit 0 with the violation unflagged; `.*` reported the
/// same input unresolved and failed. The `!empty` spelling caught it in both, which is why only the
/// assertion form hid.
#[rstest::rstest]
#[case::all_indices("Statement[*][ Effect == 'Allow' ].Action == \"never\"", Status::FAIL)]
#[case::all_values("Statement.*[ Effect == 'Allow' ].Action == \"never\"", Status::FAIL)]
#[case::all_indices_not_empty("Statement[*][ Effect == 'Allow' ] !empty", Status::FAIL)]
#[case::all_values_not_empty("Statement.*[ Effect == 'Allow' ] !empty", Status::FAIL)]
fn a_filter_after_a_wildcard_reads_a_single_object_the_same_either_way(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    let rules = format!("rule statements_are_denied {{ {} }}", clause);
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let single_object = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Statement:
          Effect: Allow
          Action: "s3:*"
        "#,
    )?)?;

    let mut scope = root_scope(&rules_file, Rc::new(single_object));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        expected,
        "{} must not answer differently from the other spelling of the same query",
        clause
    );

    Ok(())
}

/// A value filter's capture binds the selected key whether or not a wildcard precedes it.
///
/// `Resources[ nm | ... ]` always worked, because `accumulate_map` hands the filter the entry's key.
/// After a wildcard the map had already been expanded by the time the filter ran, so the key was gone
/// and the filter was invoked with its capture name forced to `None`: `nm` was declared in a position
/// the parser accepts and was then unresolvable, ending the run at exit 255 and losing the report for
/// every other rule in the file.
///
/// All three spellings are cases of one test because the defect was that they disagreed.
#[rstest::rstest]
#[case::no_wildcard("Resources[ nm | Type == 'AWS::S3::Bucket' ] !empty")]
#[case::all_indices("Resources[*][ nm | Type == 'AWS::S3::Bucket' ] !empty")]
#[case::all_values("Resources.*[ nm | Type == 'AWS::S3::Bucket' ] !empty")]
fn a_value_filter_capture_binds_its_key_after_a_wildcard(#[case] selection: &str) -> Result<()> {
    let rules = format!(
        "rule buckets_named_a {{\n    {}\n    some %nm == \"BucketA\"\n}}",
        selection
    );
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          BucketA:
            Type: AWS::S3::Bucket
          SomeVolume:
            Type: AWS::EC2::Volume
        "#,
    )?)?;

    let mut scope = root_scope(&rules_file, Rc::new(template));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        Status::PASS,
        "{} selects BucketA, so the capture reading it has a key to bind",
        selection
    );

    Ok(())
}

/// A filter directly on a scalar still evaluates its predicate against that scalar.
///
/// This is the scalar leg of the array-or-single leniency, and the reason
/// `filter_cannot_apply_to_expanded_entry` is limited to entries a wildcard expanded: `Tags` here is a
/// bare string, so nothing was expanded and the value under the filter is the value the rule is about.
/// A first version of the fix above reported every scalar under a wildcard unresolved and turned this
/// rule from a pass into a failure.
#[test]
fn a_filter_on_an_unexpanded_scalar_still_tests_that_scalar() -> Result<()> {
    let rules_file = RulesFile::try_from("rule tagged_x { Tags[*][ this == 'x' ] !empty }")?;
    let scalar = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Tags: "x"
        "#,
    )?)?;

    let mut scope = root_scope(&rules_file, Rc::new(scalar));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        Status::PASS
    );

    Ok(())
}

#[test]
fn a_capture_does_not_leak_from_one_iteration_of_a_block_into_the_next() -> Result<()> {
    for selection in CONFIG_CAPTURE_SELECTIONS {
        let rules = config_capture_rule(selection);
        let rules_file = RulesFile::try_from(rules.as_str())?;

        // `BucketB` has a config but none that is enabled, so it captures no key and cannot satisfy
        // `some %cfg == "alpha"`. It used to read the key `BucketA` captured and pass on it -- at
        // exit 0, with the non-compliant bucket unnamed in the report.
        let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
            COMPLIANT_BUCKET_FIRST,
        )?)?;
        let mut scope = root_scope(&rules_file, Rc::new(template));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            Status::FAIL,
            "{} let a compliant resource's key satisfy a non-compliant one",
            selection
        );

        // The same two resources the other way round. Whether a name is a capture is read from the
        // rule text, so the verdict cannot depend on which resource the block iterated first: an
        // earlier version of this fix learned the name at runtime and gave FAIL in one order and a
        // file-fatal error in the other.
        let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
            COMPLIANT_BUCKET_SECOND,
        )?)?;
        let mut scope = root_scope(&rules_file, Rc::new(template));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            Status::FAIL,
            "{} answered differently with the resources in the other order",
            selection
        );
    }

    Ok(())
}

#[test]
fn a_declared_capture_that_selected_nothing_fails_its_clause_rather_than_the_file() -> Result<()> {
    let rules = config_capture_rule(CONFIG_CAPTURE_SELECTIONS[0]);
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let no_enabled_config = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          BucketB:
            Type: AWS::S3::Bucket
            Properties:
              Config:
                beta:
                  Enabled: false
        "#,
    )?)?;

    // A name the rule text declares as a capture resolves to an empty selection when nothing matched,
    // which fails the clause reading it. It used to be an unresolved-variable error, which takes the
    // whole file down and loses the findings of every other rule in it.
    //
    // The split is deliberate: a name that appears *nowhere* as a capture -- a typo, or one belonging
    // to another rule -- is still an error, because that is a broken ruleset rather than a
    // non-compliant template.
    let mut scope = root_scope(&rules_file, Rc::new(no_enabled_config));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        Status::FAIL
    );

    Ok(())
}

#[test]
fn a_block_still_resolves_a_variable_it_does_not_declare_as_a_capture() -> Result<()> {
    // The interception is limited to names the block's own clauses declare as filter captures, so a
    // clause inside the block has to keep reaching past it to find a file-level assignment. Both
    // channels are read by one clause here: `%cfg` from the filter, `%allowed` from outside.
    let rules_file = RulesFile::try_from(
        r#"
    let allowed = "alpha"
    rule configs_are_allowed {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Config[ cfg | Enabled == true ] !empty
            some %cfg == %allowed
        }
    }
    "#,
    )?;
    let bucket = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          BucketA:
            Type: AWS::S3::Bucket
            Properties:
              Config:
                alpha:
                  Enabled: true
        "#,
    )?)?;

    let mut scope = root_scope(&rules_file, Rc::new(bucket));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        Status::PASS
    );

    Ok(())
}

/// A capture written as a bare name in brackets is declared, so an iteration that did not make it
/// answers empty instead of reading a neighbour's key.
///
/// `Properties.Tags[ tk ]` does not parse to `QueryPart::Filter`. `all_indices` is the first branch of
/// `predicate_or_index` and it accepts a bare `var_name`, so the pipe-less spelling lands on
/// `AllIndices(Some("tk"))` -- an arm that captures the entry's key at retrieval just as a filter does.
/// `collect_query_capture_names` read names out of `Filter` and `MapKeyFilter` only, so no block
/// declared `tk`, `BlockScope::resolve_variable` deferred to its parent, and the parent held the keys
/// earlier iterations had merged up.
///
/// The nested `when` is what lets an iteration capture nothing without failing: `BucketB` has no
/// `Tags`, so the capturing clause never runs, and `BucketB` is the only resource that reaches the
/// clause reading `%tk`.
///
/// Three documents in one test because order independence is the property, and the leaky order was the
/// one that passed. `BucketB` alone ended the run at 255, `BucketA` then `BucketB` exited 0 with
/// `BucketB` credited with `BucketA`'s key, and the reverse order was 255 again. Adding a compliant
/// resource is what made the non-compliant one pass, which is why a rule of this shape looks correct
/// when it is tested one resource at a time.
#[test]
fn a_bare_name_capture_does_not_leak_across_iterations_of_a_block() -> Result<()> {
    let rules_file = RulesFile::try_from(
        r#"
    rule tag_named {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            when Properties.Tags exists {
                Properties.Tags[ tk ] !empty
            }
            when Properties.Other exists {
                some %tk == "Name"
            }
        }
    }
    "#,
    )?;

    // The names order the iteration, so the third document spells the same two resources as
    // `ABucketB` and `ZBucketA` to put the non-compliant one first.
    let arrangements = [
        (
            "the non-compliant bucket alone",
            r#"
        Resources:
          BucketB:
            Type: AWS::S3::Bucket
            Properties:
              Other: true
        "#,
        ),
        (
            "the compliant bucket first",
            r#"
        Resources:
          BucketA:
            Type: AWS::S3::Bucket
            Properties:
              Tags:
                Name: alpha
          BucketB:
            Type: AWS::S3::Bucket
            Properties:
              Other: true
        "#,
        ),
        (
            "the compliant bucket second",
            r#"
        Resources:
          ABucketB:
            Type: AWS::S3::Bucket
            Properties:
              Other: true
          ZBucketA:
            Type: AWS::S3::Bucket
            Properties:
              Tags:
                Name: alpha
        "#,
        ),
    ];

    for (arrangement, document) in arrangements {
        let template =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;
        let mut scope = root_scope(&rules_file, Rc::new(template));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            Status::FAIL,
            "with {}, a bucket that captured no key under `tk` must not pass on another bucket's",
            arrangement
        );
    }

    Ok(())
}

/// A name that appears nowhere as a capture stays an unresolved-variable error.
///
/// The control on the test above, and it asserts behaviour that must not change rather than behaviour
/// that does: `tk` is declared by `Properties.Tags[ tk ]`, so resolving it to nothing fails the clause
/// reading it, while `absent` is a typo or a name belonging to another rule. Collapsing the second into
/// the first would turn an unwritable rule into a quiet FAIL that reads like a finding about the
/// template.
#[test]
fn a_capture_name_that_appears_nowhere_is_still_an_unresolved_variable() -> Result<()> {
    let rules_file = RulesFile::try_from(
        r#"
    rule tag_named {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            when Properties.Tags exists {
                Properties.Tags[ tk ] !empty
            }
            when Properties.Other exists {
                some %absent == "Name"
            }
        }
    }
    "#,
    )?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Resources:
          BucketB:
            Type: AWS::S3::Bucket
            Properties:
              Other: true
        "#,
    )?)?;

    let mut scope = root_scope(&rules_file, Rc::new(template));
    let error = eval_rules_file(&rules_file, &mut scope, None)
        .expect_err("a name no filter declares must not resolve to an empty selection");
    assert!(
        error.to_string().contains("absent"),
        "the error has to name the variable it could not resolve, got: {}",
        error
    );

    Ok(())
}

/// Two buckets whose enabled configs are named `alpha` and `beta`.
const ALPHA_THEN_BETA: &str = r#"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        alpha:
          Enabled: true
  BucketB:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        beta:
          Enabled: true
"#;

/// The same two resources as [`ALPHA_THEN_BETA`], in the other order.
const BETA_THEN_ALPHA: &str = r#"
Resources:
  BucketB:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        beta:
          Enabled: true
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        alpha:
          Enabled: true
"#;

/// Two buckets that both satisfy `some %cfg == "alpha"` on their own keys.
const BOTH_ALPHA: &str = r#"
Resources:
  BucketA:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        alpha:
          Enabled: true
  BucketC:
    Type: AWS::S3::Bucket
    Properties:
      Config:
        alpha:
          Enabled: true
"#;

/// A block that only reads `%cfg` does not get the keys an earlier block captured.
///
/// The third instance of one family. The per-iteration `captured` map stopped iteration two of a block
/// reading iteration one's key; `capture_names` stopped an iteration that captured nothing under a name
/// its own block declares from reaching past itself. This is the shape neither covers: a *sibling* block
/// that declares no capture at all, so its lookup defers, and what it reached was the union
/// `merge_captures_into_parent` had already handed to the enclosing scope. `BucketB`, whose only enabled
/// config is `beta`, satisfied `some %cfg == "alpha"` on `BucketA`'s key at exit 0 in either document
/// order.
///
/// The two readings hold different values, which is what makes the verdict say which one was used: the
/// union is `["alpha", "beta"]` and the second block's own iteration has nothing. Both document orders
/// are asserted because order independence is the property -- a first-iteration-wins artifact would
/// answer differently in the two.
///
/// The last arrangement is the discriminator, and it is why `BOTH_ALPHA` exists: on a document where
/// every bucket has its own `alpha`, the same assertion inside a block that *declares* the capture
/// passes. So the FAILs above are the read resolving to nothing, not the rule being unsatisfiable or
/// the document being wrong.
#[test]
fn a_sibling_block_does_not_read_a_capture_merged_out_of_an_earlier_block() -> Result<()> {
    let reads_only = RulesFile::try_from(
        r#"
    rule configs_named_alpha {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Config[ cfg | Enabled == true ] !empty
        }
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            some %cfg == "alpha"
        }
    }
    "#,
    )?;

    for (arrangement, document) in [
        ("the bucket with alpha first", ALPHA_THEN_BETA),
        ("the bucket with alpha second", BETA_THEN_ALPHA),
        ("both buckets carrying alpha", BOTH_ALPHA),
    ] {
        let template =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(document)?)?;
        let mut scope = root_scope(&reads_only, Rc::new(template));
        assert_eq!(
            eval_rules_file(&reads_only, &mut scope, None)?,
            Status::FAIL,
            "with {}, a block that captures nothing under `cfg` must not read the keys the earlier \
             block captured",
            arrangement
        );
    }

    let declares_it_too = RulesFile::try_from(
        r#"
    rule configs_named_alpha {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Config[ cfg | Enabled == true ] !empty
        }
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Config[ cfg | Enabled == true ] !empty
            some %cfg == "alpha"
        }
    }
    "#,
    )?;
    let template =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(BOTH_ALPHA)?)?;
    let mut scope = root_scope(&declares_it_too, Rc::new(template));
    assert_eq!(
        eval_rules_file(&declares_it_too, &mut scope, None)?,
        Status::PASS,
        "the same assertion over the same document passes when the reading block captures its own \
         key, so the failures above are the empty selection rather than an unsatisfiable rule"
    );

    Ok(())
}

/// A clause after the block still reads every iteration's keys, and a clause inside a nested block
/// still reads only its own iteration's.
///
/// The two readings that `merge_captures_into_parent` is there to give, asserted over one document so
/// that they cannot both be the same thing. `alpha` and `beta` are keys of *different* buckets: the
/// rule-level clause after the block passes on either of them because it means the union, and the
/// clause inside the nested block fails on `alpha` because `BucketB`'s iteration only has `beta`.
///
/// Splitting merged keys out of `captured` had to keep both. Withholding the union from every lookup
/// would break the first; offering it to a nested block is the defect the split is for.
#[test]
fn a_capture_reads_as_the_union_after_its_block_and_per_iteration_inside_a_nested_one() -> Result<()>
{
    let after_the_block = |expected_key: &str| {
        format!(
            r#"
    rule configs_named {{
        Resources.*[ Type == 'AWS::S3::Bucket' ] {{
            Properties.Config[ cfg | Enabled == true ] !empty
        }}
        some %cfg == "{}"
    }}
    "#,
            expected_key
        )
    };

    for (key, expected) in [
        ("alpha", Status::PASS),
        ("beta", Status::PASS),
        ("gamma", Status::FAIL),
    ] {
        let rules = after_the_block(key);
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let template =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ALPHA_THEN_BETA)?)?;
        let mut scope = root_scope(&rules_file, Rc::new(template));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            expected,
            "a clause after the block reads the union of both iterations, so `{}` must be {:?}",
            key,
            expected
        );
    }

    let nested = RulesFile::try_from(
        r#"
    rule configs_named_alpha {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Config[ cfg | Enabled == true ] !empty
            Properties {
                some %cfg == "alpha"
            }
        }
    }
    "#,
    )?;
    let template =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ALPHA_THEN_BETA)?)?;
    let mut scope = root_scope(&nested, Rc::new(template));
    assert_eq!(
        eval_rules_file(&nested, &mut scope, None)?,
        Status::FAIL,
        "the same document and the same key: a nested block reads the iteration it is inside, so \
         `BucketB` must not pass on `BucketA`'s alpha"
    );

    let template =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(BOTH_ALPHA)?)?;
    let mut scope = root_scope(&nested, Rc::new(template));
    assert_eq!(
        eval_rules_file(&nested, &mut scope, None)?,
        Status::PASS,
        "a nested block still reads the key its own iteration captured"
    );

    Ok(())
}

/// A key captured at rule-body level is readable inside a block, and stays so.
///
/// The other half of the precision the split buys. `nm` here is not per-iteration data at all: one
/// query at rule-body level bound it, the way a `let` would, and the block reading it is asking about
/// the whole selection rather than about the resource it is iterating. Withholding it would have turned
/// this rule from a pass into a failure, so the line the split draws is between a key that left the
/// block that made it and a key no block made.
#[test]
fn a_capture_made_at_rule_level_is_still_readable_inside_a_block() -> Result<()> {
    for (expected_name, expected) in [("BucketA", Status::PASS), ("BucketZ", Status::FAIL)] {
        let rules = format!(
            r#"
    rule buckets_named {{
        Resources[ nm | Type == 'AWS::S3::Bucket' ] !empty
        Resources.*[ Type == 'AWS::S3::Bucket' ] {{
            some %nm == "{}"
        }}
    }}
    "#,
            expected_name
        );
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let template =
            PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ALPHA_THEN_BETA)?)?;
        let mut scope = root_scope(&rules_file, Rc::new(template));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            expected,
            "`{}` read inside the block must be {:?}",
            expected_name,
            expected
        );
    }

    Ok(())
}

/// A key captured in a nested block is readable after the block that contains it.
///
/// The chain the split has to preserve: the nested block hands its keys to the block around it, and
/// that block hands them on when it ends. A first version of the split took only `captured` on the way
/// out, so a key that arrived as a merged one stopped one level short. The clause after the outer block
/// then read an empty selection -- `capture_names` on the rule body includes names the nested block
/// declares, so it failed the clause instead of erroring, which is a wrong FAIL and quiet with it.
#[test]
fn a_capture_from_a_nested_block_travels_past_the_block_around_it() -> Result<()> {
    let rules_file = RulesFile::try_from(
        r#"
    rule configs_named_alpha {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties {
                Config[ cfg | Enabled == true ] !empty
            }
        }
        some %cfg == "beta"
    }
    "#,
    )?;
    let template =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(ALPHA_THEN_BETA)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(template));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        Status::PASS,
        "`beta` is BucketB's key, captured two blocks in, and the clause after the outer block reads \
         the union"
    );

    Ok(())
}

/// A capture name a block declares does not hide an enclosing binding of the same name.
///
/// `capture_names` used to answer the lookup itself, before asking the parent, so an outer `let` or an
/// enclosing parameterized rule's parameter became unreachable for the whole block -- in every
/// iteration, and even where the capturing clause provably never ran. Each case here is paired with a
/// control that differs only in the capture's name, and the control passed while the collision failed at
/// exit 19, on a variable whose `let` sits at the top of the file.
///
/// Three shapes because they reach the same short-circuit by different routes: a `when` block whose
/// condition failed, so the capturing clause did not run; a wildcard over a list, where `accumulate` has
/// an index rather than a key and the name can *never* be populated on any input; and a rule parameter,
/// which lives in `ResolvedParameterContext` and is reachable only through the parent chain, so the
/// argument the call site passed was never read.
///
/// Every case is asserted with its mirror, which is what shows the outer binding was read rather than
/// the clause being skipped: `"fromlet"` passes and `"other"` fails, and the failing one reports
/// `Value="fromlet"` as what it found.
#[rstest::rstest]
#[case::when_condition_failed(
    r#"
    let allowed = "fromlet"
    rule r {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            when Properties.Missing exists {
                Properties.Config[ allowed | Enabled == true ] !empty
            }
            %allowed == "EXPECTED"
        }
    }
    "#,
    "bucket"
)]
#[case::wildcard_over_a_list(
    r#"
    let allowed = "fromlet"
    rule r {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Ports[ allowed ] > 0
            %allowed == "EXPECTED"
        }
    }
    "#,
    "ports"
)]
#[case::rule_parameter(
    r#"
    rule inner(allowed) {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            when Properties.Missing exists {
                Properties.Config[ allowed | Enabled == true ] !empty
            }
            %allowed == "EXPECTED"
        }
    }
    rule caller {
        inner("fromlet")
    }
    "#,
    "bucket"
)]
fn a_declared_capture_does_not_hide_an_enclosing_binding_of_the_same_name(
    #[case] rules: &str,
    #[case] document: &str,
) -> Result<()> {
    let template = match document {
        "ports" => {
            r#"
        Resources:
          BucketA:
            Type: AWS::S3::Bucket
            Properties:
              Ports:
                - 80
                - 443
        "#
        }
        _ => {
            r#"
        Resources:
          BucketA:
            Type: AWS::S3::Bucket
            Properties:
              Config:
                alpha:
                  Enabled: true
        "#
        }
    };

    for (expected_value, expected) in [("fromlet", Status::PASS), ("other", Status::FAIL)] {
        let rules = rules.replace("EXPECTED", expected_value);
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(template)?)?;
        let mut scope = root_scope(&rules_file, Rc::new(value));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            expected,
            "the block declares `allowed` as a capture and captured nothing, so `%allowed` is the \
             enclosing binding: comparing it with {:?} must be {:?}",
            expected_value,
            expected
        );
    }

    Ok(())
}

/// A capture shadows a same-named assignment in an *enclosing* scope, and the parser accepts that.
///
/// The half of the assigned-and-captured collision that is left alone, and it needs asserting because
/// the parser now refuses the other half: a name assigned and captured in one scope is rejected, since
/// there the winner is decided by the kind of the assigned value. Across scopes the more local
/// declaration wins, which is the one rule an author can carry between every other pair of nested
/// bindings, so this file is accepted and `%cfg` reads the captured key.
///
/// Asserted with its mirror, because the two candidate values differ: the capture holds `alpha` and the
/// file-level assignment holds `"fromlet"`, and only one of the two clauses can pass.
#[rstest::rstest]
#[case::the_capture_wins("alpha", Status::PASS)]
#[case::the_enclosing_assignment_does_not("fromlet", Status::FAIL)]
fn a_capture_shadows_an_enclosing_assignment_of_the_same_name(
    #[case] expected_key: &str,
    #[case] expected: Status,
) -> Result<()> {
    let rules = format!(
        r#"
    let cfg = "fromlet"

    rule configs_named {{
        Resources.*[ Type == 'AWS::S3::Bucket' ] {{
            Properties.Config[ cfg | Enabled == true ] !empty
            some %cfg == "{}"
        }}
    }}
    "#,
        expected_key
    );
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let template =
        PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(BOTH_ALPHA)?)?;
    let mut scope = root_scope(&rules_file, Rc::new(template));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        expected,
        "`%cfg` inside the block is the captured key, so `{}` must be {:?}",
        expected_key,
        expected
    );

    Ok(())
}

/// One bucket and one instance, so that two filters over `Resources` select different keys.
const BUCKET_AND_INSTANCE: &str = r#"
Resources:
  Alpha:
    Type: AWS::S3::Bucket
  Inst:
    Type: AWS::EC2::Instance
"#;

/// A capture in a file-level assignment's query reads the same in every rule and at any clause
/// position.
///
/// Two rules with the same two clauses used to give PASS and then an unresolved-variable error at exit
/// 255, and swapping the two clauses in one rule did the same. The assignment's result is memoised for
/// the file and never invalidated, so the second read of `%names` did not re-run the query and made no
/// capture, while `reset_captures` had already discarded the keys the first read produced. A verdict
/// that depends on which rule you are in, or on the order of two clauses that do not mention each
/// other, is not one an author can reason about.
///
/// Reading the capture name now resolves the assignment that declares it, and the keys are kept for the
/// file rather than for the rule. Each case below is asserted with its mirror, so the PASSes are the
/// key `Alpha` being read rather than a clause that could not fail.
#[rstest::rstest]
#[case::assignment_then_capture("%names !empty\n        %nm == \"Alpha\"", Status::PASS)]
#[case::capture_then_assignment("%nm == \"Alpha\"\n        %names !empty", Status::PASS)]
#[case::assignment_then_capture_mirror("%names !empty\n        %nm == \"Inst\"", Status::FAIL)]
#[case::capture_then_assignment_mirror("%nm == \"Inst\"\n        %names !empty", Status::FAIL)]
#[case::capture_alone("%nm == \"Alpha\"", Status::PASS)]
#[case::capture_alone_mirror("%nm == \"Inst\"", Status::FAIL)]
fn a_file_level_capture_reads_the_same_in_every_rule_and_at_any_clause_position(
    #[case] clauses: &str,
    #[case] expected: Status,
) -> Result<()> {
    // Two rules with the same body, so that a capture bound only in the rule that first forced the
    // assignment shows up as the two rules disagreeing.
    let rules = format!(
        r#"
    let names = Resources[ nm | Type == 'AWS::S3::Bucket' ]

    rule first {{
        {clauses}
    }}

    rule second {{
        {clauses}
    }}
    "#,
        clauses = clauses
    );
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        BUCKET_AND_INSTANCE,
    )?)?;
    let mut scope = root_scope(&rules_file, Rc::new(template));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        expected,
        "both rules run the clauses `{}` and must agree",
        clauses
    );

    Ok(())
}

/// A clause that mentions neither the capture nor anything it touches does not change what it holds.
///
/// Two assignments spelling their capture `nm` appended into one root-level list, so `%nm` held the keys
/// of whichever assignments some clause had forced. Adding `%b_names !empty` -- which names nothing the
/// assertion reads -- turned a PASS into a FAIL at exit 19, and nothing in the file says the two `nm`s
/// are one binding.
///
/// Reading `%nm` now resolves every assignment that declares it, so the answer is the union either way.
/// `some %nm == "Inst"` is the discriminator: it is false if only the bucket assignment contributed and
/// true if both did, and it has to give the same answer with the extra clause and without it. The
/// `all` spelling is asserted alongside because that is the shape that changed verdict.
///
/// The file declares one name twice in one scope, which `docs/QUERY_AND_FILTERING.md` forbids and the
/// parser ought to refuse. The union is what makes the verdict independent of the clause list until it
/// does; a parse rejection would supersede this test rather than contradict it.
#[rstest::rstest]
#[case::one_assignment_forced("%a_names !empty", "some %nm == \"Inst\"", Status::PASS)]
#[case::both_assignments_forced(
    "%a_names !empty\n        %b_names !empty",
    "some %nm == \"Inst\"",
    Status::PASS
)]
#[case::one_assignment_forced_all("%a_names !empty", "%nm == \"Alpha\"", Status::FAIL)]
#[case::both_assignments_forced_all(
    "%a_names !empty\n        %b_names !empty",
    "%nm == \"Alpha\"",
    Status::FAIL
)]
fn a_capture_two_file_level_assignments_declare_reads_as_the_union_of_both(
    #[case] preamble: &str,
    #[case] assertion: &str,
    #[case] expected: Status,
) -> Result<()> {
    let rules = format!(
        r#"
    let a_names = Resources[ nm | Type == 'AWS::S3::Bucket' ]
    let b_names = Resources[ nm | Type == 'AWS::EC2::Instance' ]

    rule r {{
        {preamble}
        {assertion}
    }}
    "#,
        preamble = preamble,
        assertion = assertion
    );
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        BUCKET_AND_INSTANCE,
    )?)?;
    let mut scope = root_scope(&rules_file, Rc::new(template));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        expected,
        "`{}` must not answer differently for the clauses that ran before it",
        assertion
    );

    Ok(())
}

/// A file-level capture whose query matched nothing fails its clause; a name declared nowhere is still
/// an error.
///
/// The same split `BlockScope::lookup` makes for a name a block declares, applied at file level, and it
/// is the reason the split has to be made twice: `%nm` resolved when the query matched and ended the
/// run at exit 255 when it did not, so whether the file produced a report depended on the template it
/// was run against.
#[test]
fn a_file_level_capture_that_matched_nothing_fails_its_clause_rather_than_the_file() -> Result<()> {
    let matched_nothing = RulesFile::try_from(
        r#"
    let functions = Resources[ nm | Type == 'AWS::Lambda::Function' ]

    rule r {
        %nm == "Alpha"
    }
    "#,
    )?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        BUCKET_AND_INSTANCE,
    )?)?;
    let mut scope = root_scope(&matched_nothing, Rc::new(template));
    assert_eq!(
        eval_rules_file(&matched_nothing, &mut scope, None)?,
        Status::FAIL,
        "no resource is a Lambda function, so `nm` has no keys and the clause reading it fails"
    );

    let declared_nowhere = RulesFile::try_from(
        r#"
    let names = Resources[ nm | Type == 'AWS::S3::Bucket' ]

    rule r {
        %absent == "Alpha"
    }
    "#,
    )?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        BUCKET_AND_INSTANCE,
    )?)?;
    let mut scope = root_scope(&declared_nowhere, Rc::new(template));
    let error = eval_rules_file(&declared_nowhere, &mut scope, None)
        .expect_err("a name no assignment declares must not resolve to an empty selection");
    assert!(
        error.to_string().contains("absent"),
        "the error has to name the variable it could not resolve, got: {}",
        error
    );

    Ok(())
}

/// A filter predicate reading the capture its own filter declares terminates.
///
/// Resolving a capture name now resolves the assignment declaring it, which is a new way for one
/// resolution to ask for another, so the loop it closes has to be checked rather than assumed absent.
/// `Type == %nm` asks for `nm` while the assignment binding `nm` is the one being resolved. The
/// in-progress set answers that inner ask by declining to resolve the assignment a second time, the
/// predicate selects nothing, and the clause fails. Returning a verdict at all is the property; a
/// stack overflow is not a verdict, and this rule text reaches the recursion in one line.
#[test]
fn a_filter_predicate_reading_its_own_capture_does_not_recurse() -> Result<()> {
    let rules_file = RulesFile::try_from(
        r#"
    let names = Resources[ nm | Type == %nm ]

    rule r {
        %nm !empty
    }
    "#,
    )?;
    let template = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        BUCKET_AND_INSTANCE,
    )?)?;
    let mut scope = root_scope(&rules_file, Rc::new(template));
    assert_eq!(
        eval_rules_file(&rules_file, &mut scope, None)?,
        Status::FAIL,
        "the filter selected nothing, so `nm` has no keys and `!empty` over it fails"
    );

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

/// The `Fn::GetAtt` literals in the rule below are two-element lists because that is the shape the
/// template's `!GetAtt 'Master.PrivateIp'` loads as. They used to be the dotted string, which is what
/// the loaders used to produce and what CloudFormation does not: the Template Reference gives
/// `!GetAtt logicalName.attributeName` as the short form of `{"Fn::GetAtt": [logicalName, attributeName]}`,
/// and JSON has no other shape for it. Quoting the payload does not change that, which is why the
/// single-quoted spelling here still splits.
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
      %aws_route53_recordset_resources.Properties.ResourceRecords IN [[{"Fn::GetAtt": ["Master", "PrivateIp"]}], [{"Fn::GetAtt": ["Infra1", "PrivateIp"]}]]
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

fn eval_one_rule(rules: &str, data: &str) -> Result<Status> {
    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(data)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    eval_rules_file(&rules_file, &mut root, None)
}

/// Both flavours of empty selection answer the same way.
///
/// A selection can come up empty two ways, and they used to disagree. A filter that runs and keeps
/// nothing returns no values and the clause reports SKIP. A collection that is absent or empty never
/// reached the filter at all: it produced an unresolved marker, the clause's operator ran on *that*,
/// and `not exists` read it as vacuously true -- so the first two rows below reported PASS. A document
/// containing nothing was called compliant while a document containing one unrelated resource
/// correctly reported the rule inapplicable, which is less information yielding the stronger claim.
///
/// The last two rows are why this is a consistency fix and not a licence to skip: the rule still
/// passes what it should pass and, above all, still fails what it should fail.
#[test]
fn both_flavours_of_empty_selection_agree() -> Result<()> {
    const RULE: &str = r#"rule H {
    Resources.*[ Type == 'AWS::DynamoDB::Table' ].Properties.TableName not exists
}"#;

    let cases: [(&str, &str, Status); 5] = [
        ("no Resources key at all", r#"{}"#, Status::SKIP),
        (
            "Resources present but empty",
            r#"{"Resources":{}}"#,
            Status::SKIP,
        ),
        (
            "one resource of an unrelated type, filtered away",
            r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"b"}}}}"#,
            Status::SKIP,
        ),
        (
            "one compliant table",
            r#"{"Resources":{"T":{"Type":"AWS::DynamoDB::Table","Properties":{"KeySchema":[]}}}}"#,
            Status::PASS,
        ),
        (
            "one violating table",
            r#"{"Resources":{"T":{"Type":"AWS::DynamoDB::Table","Properties":{"TableName":"t"}}}}"#,
            Status::FAIL,
        ),
    ];

    for (label, data, expected) in cases {
        assert_eq!(
            expected,
            eval_one_rule(RULE, data)?,
            "{label}: the two flavours of empty selection must agree"
        );
    }

    Ok(())
}

/// The empty-selection SKIP reaches only a selection, never a subject.
///
/// This is the narrowing half of `both_flavours_of_empty_selection_agree`, and every row is a shape
/// that must keep failing. A missing *property* is represented by the same unresolved marker an empty
/// selection used to produce, so answering SKIP for both would retire `Properties.X exists` -- the
/// single most common clause in any real ruleset. The discriminator is whether a filter is still
/// pending: with one, the query is choosing subjects and an empty result means the rule does not
/// apply; without one, the query is projecting a property of a subject already chosen and an empty
/// result is an answer about that subject.
///
/// The `filter_then_empty_tags` row is the one that pins the direction of that test rather than its
/// mere presence: the filter has already run and matched, so the empty `Tags` belongs to a selected
/// bucket and the clause fails. Searching the whole query for a filter instead of the part of it that
/// is still ahead would turn that row into SKIP.
#[test]
fn an_empty_selection_never_excuses_a_missing_subject() -> Result<()> {
    const BUCKET: &str =
        r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"BucketName":"b"}}}}"#;
    const TAGS_EMPTY: &str =
        r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"Tags":[]}}}}"#;
    const TAGS_OK: &str = r#"{"Resources":{"B":{"Type":"AWS::S3::Bucket","Properties":{"Tags":[{"Key":"PROD","Value":"v"}]}}}}"#;

    let cases: [(&str, &str, &str, Status); 8] = [
        // A missing leaf property, with and without a filter that matched.
        (
            "missing property under a wildcard",
            "Resources.*.Properties.BucketEncryption exists",
            BUCKET,
            Status::FAIL,
        ),
        (
            "missing property under a filter that matched",
            "Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketEncryption exists",
            BUCKET,
            Status::FAIL,
        ),
        // An empty collection that is itself the subject of the clause.
        (
            "empty tag list is not an excuse for !empty",
            "Resources.*.Properties.Tags[*] !empty",
            TAGS_EMPTY,
            Status::FAIL,
        ),
        (
            "empty tag list is not an excuse for a tag-content check",
            "Resources.*.Properties.Tags[*].Key == /PROD/",
            TAGS_EMPTY,
            Status::FAIL,
        ),
        (
            "a filter that already ran does not make a later empty collection a selection",
            "Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags[*].Key == /PROD/",
            TAGS_EMPTY,
            Status::FAIL,
        ),
        (
            "the same clause still passes when the tag is there",
            "Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags[*].Key == /PROD/",
            TAGS_OK,
            Status::PASS,
        ),
        // A bare wildcard with no filter anywhere: not a selection, so unchanged.
        (
            "empty Resources under a wildcard with no filter",
            "Resources.*.Properties exists",
            r#"{"Resources":{}}"#,
            Status::FAIL,
        ),
        (
            "absent Resources under a wildcard with no filter",
            "Resources.*.Properties exists",
            r#"{}"#,
            Status::FAIL,
        ),
    ];

    for (label, clause, data, expected) in cases {
        let rule = format!("rule G {{\n    {clause}\n}}\n");
        assert_eq!(expected, eval_one_rule(&rule, data)?, "{label}");
    }

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

    // The same template with no `aws:Source*` condition on the second statement, which must FAIL.
    //
    // This fixture used to spell that with `"Bool"` twice in one `Condition` -- once for
    // `aws:ViaAWSService` and once for `aws:SecureTransport`. `PathAwareValue::try_from(&str)` reads a
    // document through the rules-value grammar, whose map parser kept the last entry silently, so the
    // condition this test actually evaluated was decided by entry order and the first `Bool` was dead
    // text. `parse_map` refuses a repeated key now. The verdict below is unchanged and always came from
    // the missing `aws:SourceVpc` condition rather than from either `Bool`.
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

/// Substring `IN` where the right-hand side is a query rather than a literal: `%bucket_names[*]`
/// resolves to `"s3"` and `Resource.'Fn::Sub'` to the longer `"aws:arn:s3::${s3}"`.
///
/// Broken rather than unimplemented, which is why it is a test again rather than a feature request. It
/// passed when it was written -- measured on c2447bee, where every `IN` clause went through `in_cmp` in
/// `eval.rs`, whose `(String, String)` arm is `rhs.contains(lhs)` however the two operands were
/// obtained. `InOperation::compare` in `eval/operators.rs` replaced that path in 901d40a6 and reached
/// `string_in`, the containment check, only from the arms whose right-hand side satisfies `is_literal`;
/// a query landed in the `(None, None)` arm, which asked `contained_in` alone, and two scalars there
/// fall through to `compare_eq`. So a scalar query against a string literal held while the same scalar
/// query against a query resolving to that identical string failed.
///
/// The `#[ignore]` arrived in 1aca9003, in the same hunk that first gave the function `#[test]` --
/// 901d40a6 had carried it in with no attribute at all, so nothing observed what that commit dropped,
/// and no reason was recorded when it was finally parked.
///
/// `substring_in_answers_the_same_against_a_query_as_against_a_literal` is where the reading is pinned
/// cell by cell, in both polarities and for all four operand spellings. This one is kept because it is
/// the shape a user wrote: `some`, a filter capture and a `when` block wrapped around the mechanism,
/// none of which was ever implicated, so between the two of them a regression that only shows up under
/// composition still has somewhere to land.
#[test]
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

/// `EMPTY` on a lone variable asks about the value, not about whether the query resolved.
///
/// The shortcut that answers `EMPTY` without projecting the query tested `res.is_null()`. Null is
/// empty, but so are other things, and nothing else was consulted, so on a variable bound to a value:
///
///   - an empty list reported itself NOT empty, and `EMPTY` on it reported false
///   - an empty string did the same
///   - a number or a boolean could not fail either polarity for any input, which is the silent
///     always-pass that `element_empty_operation` removed for the direct path and this arm kept
///
/// A `let` binding and a rule parameter both take this path, which is why the boolean fix looked
/// complete while `%flag !EMPTY` still could not fail.
///
/// The shortcut itself has to stay, and the second half of this table is why: for `%vols !empty` an
/// empty selection resolves to zero values and is answered before the per-value loop. Removing the
/// arm sends that case to a SKIP further down, turning the most common gate in the registry from a
/// failure into a silent skip. Only the question inside it was wrong.
///
/// A query ending in a filter keeps resolution semantics, and `block_evaluation` is the case that
/// says so: `Condition[ keys == 'aws:IsSecure' ] !empty` means "that key is present", and the value
/// it selects is a boolean, which has no emptiness of its own.
#[test]
fn empty_on_a_lone_variable_asks_about_the_value() -> Result<()> {
    let input = r#"
    {
        Resources: {
            Vol: {
                Type: 'AWS::EC2::Volume',
                Properties: { Tags: [], Name: "", Enabled: true, Size: 50 }
            }
        }
    }
    "#;

    // (clause, expected, why)
    let cases = [
        (
            "let x = Resources.Vol.Properties.Tags\nrule r { %x !EMPTY }",
            Status::FAIL,
            "the list is empty",
        ),
        (
            "let x = Resources.Vol.Properties.Tags\nrule r { %x EMPTY }",
            Status::PASS,
            "the list is empty",
        ),
        (
            "let x = Resources.Vol.Properties.Name\nrule r { %x !EMPTY }",
            Status::FAIL,
            "the string is empty",
        ),
        (
            "let x = Resources.Vol.Properties.Name\nrule r { %x EMPTY }",
            Status::PASS,
            "the string is empty",
        ),
        (
            "let x = Resources.Vol.Properties.Enabled\nrule r { %x !EMPTY }",
            Status::FAIL,
            "a boolean has no emptiness, so the clause fails closed",
        ),
        (
            "let x = Resources.Vol.Properties.Size\nrule r { %x !EMPTY }",
            Status::FAIL,
            "a number has no emptiness, so the clause fails closed",
        ),
        (
            "rule inner(p) { %p !EMPTY }\nrule r { inner(Resources.Vol.Properties.Enabled) }",
            Status::FAIL,
            "a parameter takes the same path as a let binding",
        ),
        // The selection idiom, which must not change.
        (
            "let x = Resources.*[ Type == 'AWS::EC2::Volume' ]\nrule r { %x !EMPTY }",
            Status::PASS,
            "the selection has a resource in it",
        ),
        (
            "let x = Resources.*[ Type == 'AWS::Nonexistent::Type' ]\nrule r { %x !EMPTY }",
            Status::FAIL,
            "the selection is empty",
        ),
        (
            "let x = Resources.*[ Type == 'AWS::Nonexistent::Type' ]\nrule r { %x EMPTY }",
            Status::PASS,
            "the selection is empty",
        ),
    ];

    for (rules, expected, why) in cases {
        assert_eq!(
            status_of(rules, input)?,
            expected,
            "{}: expected {:?} because {}",
            rules.replace('\n', "  "),
            expected,
            why
        );
    }

    Ok(())
}

/// The status a named rule reached, read off the record tree.
///
/// The file-level status is not enough for this class. A rule referenced as a gate is often also a
/// top-level rule, so its own failure exits the file 19 whether or not the rule it gates ever ran --
/// which is how a silenced verdict hides behind a passing exit-code assertion.
fn rule_status_in(rules: &str, input: &str, rule_name: &str) -> Result<Status> {
    let value = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    eval_rules_file(&rules_file, &mut root, None)?;
    let top = root.reset_recorder().extract();

    for child in &top.children {
        if let Some(RecordType::RuleCheck(NamedStatus { name, status, .. })) = &child.container {
            if *name == rule_name {
                return Ok(*status);
            }
        }
    }
    panic!("no rule named {} in the record tree", rule_name);
}

/// An unanswerable clause does not silence the rule it guards, at any composition depth.
///
/// This is the invariant the 252-cell corpus already asserts, swept over a second axis. That corpus
/// varies the operator and the operand and wraps exactly one clause in exactly one gate. Every defect
/// in this family that escaped it did so by composing: the undecidable answer crossed more than one
/// site on its way out, and each site that converted it early lost what the next one needed.
///
/// Two axes here, and both were blind spots:
///
///   - SHAPE: where the clause sits relative to the guard. A gate's own condition, a nested `when`
///     inside the gate rule, a named-rule reference, a parameterized call.
///   - BINDING: how the value reaches the clause. A direct query, or a `let` variable -- which takes
///     a different path through `unary_operation` and answered `is_null` there until recently.
///
/// The assertion is per rule, not per file, and the reason is in `rule_status_in`.
///
/// Only clauses that genuinely cannot be answered are swept. An empty reference used as a gate is a
/// different thing: `when %vols !empty` means "no such resources, so this rule does not apply", which
/// is the documented idiom and correctly SKIPs. Mixing the two would make this invariant assert that
/// a legitimate non-match is a defect.
#[test]
fn an_unanswerable_clause_never_silences_the_rule_it_guards() -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            Vol: {
                Type: 'AWS::EC2::Volume',
                Properties: { Enabled: true, Size: 50, Encrypted: false }
            }
        }
    }
    "#;

    // Violated by the template, so every shape below has a real finding to lose.
    const BODY: &str = "Resources.Vol.Properties.Encrypted == true";
    // Holds, for the control form and for inner bodies that must not fail on their own.
    const HOLDS: &str = "Resources.Vol.Properties.Encrypted == false";

    // Clauses with no answer in either polarity: the operand does not support the operator.
    let unanswerable = [
        ("direct bool", "Resources.Vol.Properties.Enabled !EMPTY"),
        ("direct int", "Resources.Vol.Properties.Size EMPTY"),
        ("let-bound bool", "%flag !EMPTY"),
    ];

    // Plain templates rather than `format!`, because every one of these is mostly braces and the
    // escaping is harder to read than the rules they describe. GUARD is the clause under test.
    let shapes = [
        ("gate_direct", "rule guarded when GUARD { BODY }"),
        (
            "when_inside_gate",
            "rule guarded when HOLDS { when GUARD { BODY } }",
        ),
        (
            "named_gate_direct",
            "rule inner { GUARD }\nrule guarded when inner { BODY }",
        ),
        (
            "named_gate_nested_when",
            "rule inner { when GUARD { HOLDS } }\nrule guarded when inner { BODY }",
        ),
        (
            "param_gate_direct",
            "rule inner(u) { GUARD }\nrule guarded when inner(\"x\") { BODY }",
        ),
        (
            "param_gate_nested_when",
            "rule inner(u) { when GUARD { HOLDS } }\nrule guarded when inner(\"x\") { BODY }",
        ),
        // The gate rule's own rule-level `when`, which is a different site from a `when` block in its
        // body and was converting the undecidable answer to a status regardless of role. Three
        // spellings of one condition disagreed: inline and block-level failed closed, this one
        // reported the rule not applicable. No parameterized counterpart -- the parser rejects
        // `rule r(p) when ... {}`.
        (
            "named_gate_rule_level_when",
            "rule inner when GUARD { HOLDS }\nrule guarded when inner { BODY }",
        ),
    ];

    // A type block's clauses and its `when` condition both resolve against each resource, so this
    // shape needs resource-relative operands rather than the root-anchored ones above. `%flag` carries
    // over unchanged, because `ValueScope::resolve_variable` delegates to the parent.
    let type_block_shape =
        "rule inner(u) { AWS::EC2::Volume when GUARD { THOLDS } }\nrule guarded when inner(\"x\") { BODY }";
    let type_block_unanswerable = [
        ("direct bool", "Properties.Enabled !EMPTY"),
        ("direct int", "Properties.Size EMPTY"),
        ("let-bound bool", "%flag !EMPTY"),
    ];

    let build = |shape: &str, guard: &str| {
        format!(
            "let flag = Resources.Vol.Properties.Enabled\n{}",
            shape
                .replace("GUARD", guard)
                .replace("BODY", BODY)
                .replace("HOLDS", HOLDS)
        )
    };

    for (clause_name, clause) in unanswerable {
        for (shape_name, shape) in shapes {
            // The control proves the shape can reach and fail the body at all. Without it, a fixture
            // that silences the body for an unrelated reason reads as a passing invariant.
            let control = build(shape, HOLDS);
            assert_eq!(
                rule_status_in(&control, INPUT, "guarded")?,
                Status::FAIL,
                "control for {}: a decidable guard must let the body run and fail, otherwise this \
                 shape cannot detect anything:\n{}",
                shape_name,
                control
            );

            let rules = build(shape, clause);
            assert_ne!(
                rule_status_in(&rules, INPUT, "guarded")?,
                Status::SKIP,
                "{} in {}: the guard cannot be answered, which is not the same as a guard that was \
                 decided and did not match. Reporting the rule as not applicable exits 0 with the \
                 violation inside it unreported:\n{}",
                clause_name,
                shape_name,
                rules
            );
        }
    }

    // The type block, with its own operands. Same invariant, same control discipline.
    let build_tb = |guard: &str| {
        format!(
            "let flag = Resources.Vol.Properties.Enabled\n{}",
            type_block_shape
                .replace("GUARD", guard)
                .replace("THOLDS", "Properties.Size > 0")
                .replace("BODY", BODY)
        )
    };

    for (clause_name, clause) in type_block_unanswerable {
        let control = build_tb("Properties.Size > 0");
        assert_eq!(
            rule_status_in(&control, INPUT, "guarded")?,
            Status::FAIL,
            "control for the type-block shape must let the body run and fail:\n{}",
            control
        );

        let rules = build_tb(clause);
        assert_ne!(
            rule_status_in(&rules, INPUT, "guarded")?,
            Status::SKIP,
            "{} in a type block's `when`: an undecidable condition there used to make the type block \
             FAIL, which one level out is a condition that did not match, so the rule it gates was \
             dropped at exit 0:\n{}",
            clause_name,
            rules
        );
    }

    Ok(())
}

/// A number is one clause, not a number and a rule reference.
///
/// `Size == 1e5` did not fail to parse. It split: `1` became the integer, and the leftover `e5` became
/// a bare identifier, which is a valid clause -- a reference to a rule by that name. So the rule was
/// `Size == 1` *and* a reference to `e5`.
///
/// With no rule of that name the run dies with "Rule e5 by that name does not exist", which at least
/// says something is wrong. With one, it evaluates cleanly and checks the wrong number. Measured on
/// v3.2.0 and on this branch before the fix: `Size: 1` reported PASS at exit 0 against a rule
/// demanding 100000, because `Size == 1` held and `e5` passed.
///
/// The exponent form is the realistic trigger, and the same split swallowed any digit running into a
/// letter -- the fuzzed `m<0m<03333333` in `test_with_payload_failing_type_block` is the other shape,
/// and it used to parse as two clauses.
#[test]
fn a_number_is_not_a_number_and_a_rule_reference() -> Result<()> {
    // `Size: 1`, and a rule named after the exponent suffix so the split is silent rather than fatal.
    let input = r#"
    {
        Resources: { R: { Type: 'T', Properties: { Size: 1 } } }
    }
    "#;
    let rules = r###"
    rule e5 {
        Resources.R.Properties.Size EXISTS
    }

    rule threshold {
        Resources.R.Properties.Size == 1e5
    }
    "###;

    assert_eq!(
        status_of(rules, input)?,
        Status::FAIL,
        "the rule demands 100000 and the template has 1, so this must fail. PASS here means `1e5` \
         was read as `1` and a reference to the rule named `e5`"
    );

    // The literal forms, so the shape test in `parse_float` cannot narrow again. A float needs a
    // fraction or an exponent, and either may carry a sign; a bare integer stays an integer.
    for accepted in [
        "1.5", "-1.5", "0.0", "-0.0", "40", "-40", "1e5", "1E5", "1e+5", "1e-5", "-1e5", "-1e+5",
        "1.5e+3",
    ] {
        let rule = format!("rule r {{ Resources.R.Properties.Size == {} }}", accepted);
        assert!(
            RulesFile::try_from(rule.as_str()).is_ok(),
            "{} is a number and must parse",
            accepted
        );
    }

    // Rejected, and loudly: a digit running into a letter is never two clauses, and a bare `.` on
    // either side of the digits is not a number in this grammar.
    for rejected in ["1x", "2abc", "1e5x", ".5", "1."] {
        let rule = format!("rule r {{ Resources.R.Properties.Size == {} }}", rejected);
        assert!(
            RulesFile::try_from(rule.as_str()).is_err(),
            "{} must be a parse error rather than a number followed by something else",
            rejected
        );
    }

    Ok(())
}

/// A conversion that cannot be made fails its clause, not the file.
///
/// `parse_int` on a value it cannot convert used to abort the run: exit 255, and every other rule's
/// verdict discarded with it, including a real violation an unrelated rule had already found. Two
/// causes -- the conversions reported `ParseError` for something that never parsed, and the error was
/// raised while resolving a `let`, which propagates past the machinery that turns an incompatible type
/// into a clause-level verdict.
///
/// The canary is the whole point: it fails on its own, so if the file still reports its failure then the
/// conversion took only its own clause down.
#[test]
fn a_failed_conversion_does_not_discard_other_rules() -> Result<()> {
    let input = r#"
    {
        Resources: { R: { Type: 'T', Properties: { Junk: "abc" } } }
    }
    "#;
    let rules = r###"
    rule CANARY {
        Resources.R.Properties.Junk == "this-will-not-match"
    }

    rule USES_PARSE_INT {
        let n = parse_int(Resources.R.Properties.Junk)
        %n > 0
    }
    "###;

    // FAIL, not an Err: an Err here is the abort, and it takes CANARY's verdict with it.
    assert_eq!(
        status_of(rules, input)?,
        Status::FAIL,
        "a value that cannot be converted must fail its own clause and leave the file reporting"
    );

    // And the same conversion inside a gate stays undecided rather than reading as a condition that
    // did not match, so the rule it guards is not silently dropped.
    // A function call belongs in a `let`, not directly in a `when`, so the gate reads the variable.
    let gated = r###"
    let n = parse_int(Resources.R.Properties.Junk)

    rule guarded when %n > 0 {
        Resources.R.Properties.Junk == "this-will-not-match"
    }
    "###;
    assert_ne!(
        rule_status_in(gated, input, "guarded")?,
        Status::SKIP,
        "an undecidable gate must not report the rule as not applicable"
    );

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
// `not <query> == <value>` parses (`parser::clause_with_map` accepts a leading not
// before the query) and is stored as GuardAccessClause::negation, but the binary evaluation
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
// In a rule BODY this is an assertion, and a SKIPped rule is not evidence, so it must not
// report compliance. It once returned PASS -- and because the enclosing rule then reported
// PASS rather than SKIP, the output gave no hint that the check had never run.
//
// This asserted FAIL for a while, on the reasoning that only failing closed prevents the
// bypass. That over-corrected: FAIL does not merely withhold compliance, it reports a
// violation, and there is none -- the input below holds one S3 bucket and no KMS key, so
// `inner` is about nothing. Reporting a violation for an absent resource type is the same
// false positive that `an_inapplicable_dependent_rule_does_not_fail_the_reference` covers
// for the non-negated spelling, and it is the reason the assertion here is now SKIP.
//
// SKIP is not compliance, which is the property the FAIL was reaching for: the enclosing
// rule reports SKIP rather than PASS, so the omission is still visible in the output, and
// `find_skip_reason` names the rule that did not apply. What SKIP gives up is the exit code
// -- 0 rather than 19 -- and that is the deliberate trade. A dependent rule that did not
// apply is not applicable in either polarity, which is what makes it the identity of a
// conjunction rather than something a rule can fail on.
//
// In a `when` CONDITION the same shape is intentional ("apply this rule when that other
// rule did not apply"), is covered by cross_rule_clause_when_checks, and is deliberately
// preserved -- see the test immediately below.
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

    // SKIP specifically, asserted rather than "not PASS". PASS is the original defect --
    // compliance manufactured from a dependent rule that never ran. FAIL is the
    // over-correction -- a violation reported against a template that has no KMS key to
    // violate anything. SKIP is the only answer that is neither.
    assert_eq!(status, Status::SKIP);

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

/// A reference to a rule that did not apply must not fail the referencing rule.
///
/// Decomposing a ruleset over disjoint resource types is the natural way to write one: a helper
/// per type, each guarded by a `when` on its own type, and an aggregate that references them all.
/// On any real template most helpers do not apply, and the aggregate used to fail once for every
/// one of them -- exit 19, reason "dependent rule [H_B] did not PASS", against a template that
/// violates nothing. That made the decomposition unusable, and neither workaround is
/// behaviour-preserving: `H_A H_B` fails whenever any type is absent, and `H_A OR H_B` passes as
/// soon as any single helper passes, which is a false negative in a compliance rule.
///
/// The clause path already answered this correctly -- a clause whose query selects nothing SKIPs,
/// and `eval_conjunction_clauses` absorbs a SKIP. The reference path asked instead whether the
/// dependent rule's status was PASS, and SKIP is not PASS.
///
/// All four combinations are asserted, not just the one that changed. The three unchanged ones are
/// the point: a fix that made an inapplicable reference inert must not also make a *violated* one
/// inert, or a reference would guarantee nothing at all.
///
/// Both spellings are asserted for the same reason as
/// `a_named_rule_gate_on_a_skipped_rule_does_not_disarm_the_block`:
/// `eval_parameterized_rule_call` carries its own copy of this arm, the two have drifted apart
/// before, and a single-spelling test would pass against half a fix. The parameterized helpers
/// reach inapplicability through their body rather than a `when`, because the parser does not
/// accept a condition on a parameterized rule.
#[test]
fn an_inapplicable_dependent_rule_does_not_fail_the_reference() -> Result<()> {
    let plain = r###"
    rule H_A when Resources.*[ Type == 'AWS::IAM::Role' ] !empty {
        Resources.*[ Type == 'AWS::IAM::Role' ].Properties.RoleName not exists
    }
    rule H_B when Resources.*[ Type == 'AWS::DynamoDB::Table' ] !empty {
        Resources.*[ Type == 'AWS::DynamoDB::Table' ].Properties.TableName not exists
    }
    rule MAIN {
        H_A
        H_B
    }
    "###;

    let parameterized = r###"
    rule H_A(kind) {
        Resources.*[ Type == %kind ].Properties.RoleName not exists
    }
    rule H_B(kind) {
        Resources.*[ Type == %kind ].Properties.TableName not exists
    }
    rule MAIN {
        H_A('AWS::IAM::Role')
        H_B('AWS::DynamoDB::Table')
    }
    "###;

    const CLEAN_ROLE: &str = r#"{ "Resources": {
        "r": { "Type": "AWS::IAM::Role", "Properties": { "Path": "/" } } } }"#;
    const NAMED_ROLE: &str = r#"{ "Resources": {
        "r": { "Type": "AWS::IAM::Role", "Properties": { "RoleName": "static" } } } }"#;
    const NAMED_ROLE_CLEAN_TABLE: &str = r#"{ "Resources": {
        "r": { "Type": "AWS::IAM::Role", "Properties": { "RoleName": "static" } },
        "t": { "Type": "AWS::DynamoDB::Table", "Properties": { "BillingMode": "PAY_PER_REQUEST" } } } }"#;
    const CLEAN_BOTH: &str = r#"{ "Resources": {
        "r": { "Type": "AWS::IAM::Role", "Properties": { "Path": "/" } },
        "t": { "Type": "AWS::DynamoDB::Table", "Properties": { "BillingMode": "PAY_PER_REQUEST" } } } }"#;

    let scenarios = [
        (
            "H_A holds and H_B does not apply",
            CLEAN_ROLE,
            Status::PASS,
            "the reference to an inapplicable H_B contributes nothing, so MAIN is decided by \
             H_A alone -- this is the case that used to FAIL with nothing violated",
        ),
        (
            "H_A is violated and H_B does not apply",
            NAMED_ROLE,
            Status::FAIL,
            "an inapplicable H_B must not rescue a violated H_A",
        ),
        (
            "H_A is violated and H_B holds",
            NAMED_ROLE_CLEAN_TABLE,
            Status::FAIL,
            "a reference to a rule that FAILs must still fail, which is the whole point of a \
             reference",
        ),
        (
            "both hold",
            CLEAN_BOTH,
            Status::PASS,
            "unchanged, and the control for the other three",
        ),
    ];

    for (spelling, rules) in [
        ("plain reference", plain),
        ("parameterized call", parameterized),
    ] {
        for (scenario, input, expected, why) in &scenarios {
            let rules_file = RulesFile::try_from(rules)?;
            let value = PathAwareValue::try_from(*input)?;
            let mut root = root_scope(&rules_file, Rc::new(value));
            assert_eq!(
                eval_rules_file(&rules_file, &mut root, None)?,
                *expected,
                "{}, {}: {}",
                spelling,
                scenario,
                why
            );
        }
    }

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
    //   ClauseValueCheck        4   leaf value checks; rendered by the clause arms already
    //   GuardClauseBlockCheck   5   rendered: falls back to the message when no children report
    //   BlockGuardCheck         1   rendered: uses the record's message, not a hardcoded sentence
    //   WhenCheck               2   rendered: same fallback as GuardClauseBlockCheck
    //   TypeCheck               5   four failures, plus the one skip site below
    //   Disjunction             1   rendered: reported as a block when no disjunct recorded anything
    //   RuleCheck               1   rendered: printed as the rule's Reason -- see below
    //
    // The `RuleCheck` site is the newest. A rule whose `when` condition cannot be evaluated now fails
    // closed instead of being treated as not applicable, and the reader needs to be told that the rule
    // failed for that reason rather than on one of its own clauses. Verified by running it: the console
    // prints `Rule <name> failed for <file>. Reason The rule's condition could not be
    // evaluated ...`, and `an_unevaluatable_gate_fails_the_rule_closed` asserts it end to end.
    //
    // The `WhenCheck` count is unchanged, and one of its two messages is worth a note: its text was
    // corrected in the same commit, because it said "bailing" for a case that no longer bails. It is
    // still not the rendering path for that case -- the clause's own `ClauseValueCheck` record is, and
    // that is what names the offending path and operation in the output.
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
    // The newest `ClauseValueCheck` is the lone-variable `EMPTY` arm, which now answers the
    // operator's question instead of `is_null` and therefore has an incompatible-type case to
    // explain. Confirmed rendered before this number was raised: `%f !EMPTY` on a boolean prints
    // `Attempting EMPTY operation on type bool that does not support it at
    // /Resources/Vol/Properties/Enabled` in the console reporter.
    //
    // The fourth `ClauseValueCheck` is the newest overall: `report_by_lhs` recording why a map-key
    // membership comparison had no answer. It was `message: None`, so `Cfg[ keys not in [/re/] ]` over
    // a key whose pattern exhausted its backtracking budget printed "provided value [...] did match
    // expected value in [...]. Error Message []" -- a claim of success about a comparison that was
    // abandoned. This test is why the number moved rather than the message being added quietly, and
    // both rendering paths were checked before raising it, because they are separate:
    //
    //   console     `NameInfo` reads `InComparisonCheck::message` (reporters/validate/common.rs) and
    //               `binary_error_message` prints it in the `Error Message [...]` slot. No reporter
    //               change was needed.
    //   structured  `eval_context.rs`'s `ClauseCheck::InComparison` arm dropped `message` through a
    //               `..` and built its own sentence, so `-o json`, `--structured`, FFI and Lambda saw
    //               nothing. That arm now appends `. Error = [...]` the way its `Comparison` sibling
    //               does. Measured: the reason appears in both renderings for `IN` and `NOT IN`, and
    //               `==`/`!=` output is byte-identical to the base.
    //
    // `an_undecided_map_key_membership_filter_says_why` in `guard/tests/validate.rs` asserts it end to
    // end, and pins that a key whose comparison WAS answered keeps an empty slot.
    //
    // If this total changes, find the new site, note which variant it records against, and confirm
    // it reaches rendered output before updating the number.
    const SITES_EXPECTED: usize = 20;

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

/// An index after an interpolated key counts the keys the variable names, not the results it resolved
/// to.
///
/// The two differ when one result holds a list. `let k = Cfg.KeyList` over `KeyList: [Name, Owner]`
/// resolves to a single result holding the whole list, and the expansion of that list into one key per
/// element happens after the index has already been applied. So the length was one: `[0]` selected the
/// list and then used *every* key in it, and `[1]` was out of bounds. Over
/// `Tags: {Name: alpha, Owner: bob}`, `some Cfg.Tags.%k[0] == "bob"` passed at exit 0 although the 0th
/// key is `Name` and names `alpha`.
///
/// The index was inert rather than off by one, which is what `list_bound_without_an_index` shows: the
/// same rule with no index at all answers the same way, so `[0]` was selecting nothing. Under either
/// reading of `[N]` -- the Nth key, or the Nth resolved value -- exactly one key must come back, and two
/// came back.
///
/// Every clause is run against both spellings of the binding because the defect was that they
/// disagreed. `Cfg.KeyList[*]` was always right: the projection makes one result per key, so there was
/// nothing left to flatten. The pair is also why this survived, since the two spellings look
/// interchangeable and only one of them was.
///
/// The `alpha` and negative cases matter even though their verdict did not move. Both passed before for
/// the wrong reason -- every key was in play, so `alpha` was among the values and `[-1]` offset into a
/// length of one and landed back on the whole list. They pin which key the index now selects, which a
/// verdict that was already right cannot.
#[rstest::rstest]
#[case::zeroth_key_is_not_the_last_value("%k[0]", "\"bob\"", Status::FAIL)]
#[case::zeroth_key_names_alpha("%k[0]", "\"alpha\"", Status::PASS)]
#[case::first_key_names_bob("%k[1]", "\"bob\"", Status::PASS)]
#[case::last_key_names_bob("%k[-1]", "\"bob\"", Status::PASS)]
#[case::past_the_last_key("%k[2]", "\"bob\"", Status::FAIL)]
#[case::without_an_index("%k", "\"bob\"", Status::PASS)]
fn an_index_after_an_interpolated_key_counts_keys_not_results(
    #[case] selection: &str,
    #[case] expected_value: &str,
    #[case] expected: Status,
) -> Result<()> {
    const CONFIG: &str = r#"
Cfg:
  KeyList: [Name, Owner]
  Tags:
    Name: alpha
    Owner: bob
"#;

    // The same two keys reached two ways: bound as the list itself, and bound as its elements.
    for preamble in ["let k = Cfg.KeyList", "let k = Cfg.KeyList[*]"] {
        let rules = format!(
            "{}\nrule tag_is_bob {{ some Cfg.Tags.{} == {} }}",
            preamble, selection, expected_value
        );
        let rules_file = RulesFile::try_from(rules.as_str())?;
        let config = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(CONFIG)?)?;

        let mut scope = root_scope(&rules_file, Rc::new(config));
        assert_eq!(
            eval_rules_file(&rules_file, &mut scope, None)?,
            expected,
            "`{}` under `{}` must not answer differently from the other spelling of the same keys",
            selection,
            preamble
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
    // the overflow case.
    //
    // This comment used to say the opposite of the code: that a negative index is its absolute value
    // rather than an offset from the end, "so `[-1]` and `[1]` agree". `index_offset` counts back
    // from the end, and `docs/CLAUSES.md` documents that. The claim survived because the two
    // readings cannot be told apart on a two-element list -- index 1 is also the last element -- so
    // the assertion below held either way. `a_negative_index_counts_back_from_the_end` uses three
    // elements, where they disagree.
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

/// A skip explanation taken off a failing comparison says where the comparison came from, and does
/// not invent a condition.
///
/// The sibling above is the same defect one arm over. This one is the `ClauseValueCheck` arm of
/// `own_skip_reason`, which prefixed every explanation it found with "the rule did not apply because
/// one of its conditions was not met". That is a claim about the rule's *shape*, and a query filter
/// refuses comparisons without any `when` existing anywhere: `rule g { Resources.*[ Properties.Size >
/// 10 ] { Properties.X == 1 } }` over `Size: "50"` exits 0 SKIP and said a condition was not met, in a
/// rule with zero `when` tokens. A reader goes looking for a condition they never wrote.
///
/// Which populations reach that arm was asserted rather than measured, and that is the reason this
/// survived -- the comment above it enumerated two shapes, argued a third impossible, and declared a
/// fourth unreachable, so the arm read as fully accounted for. Measured by walking the record tree,
/// the paths that arrive are `RuleCondition`, `WhenCheck > WhenCondition`, `TypeCheck > TypeBlock >
/// TypeCondition`, `RuleCondition > Disjunction`, `BlockGuardCheck > Filter`, `GuardClauseBlockCheck >
/// Filter`, and `RuleCondition > .. > Filter`. Three of those seven pass through a filter, and two of
/// the three have no condition record anywhere on the path.
///
/// So the wording is chosen from the path rather than assumed, and the three cells below are the three
/// answers. A condition record anywhere above the comparison earns the condition sentence -- including
/// the last cell, where a filter sits *inside* a `when`, because there the rule does have a condition
/// and it genuinely was not met. A filter with no condition above it gets a sentence about a filter. A
/// path carrying neither gets neither claim, which is the part that matters for the next reader: a
/// record shape nobody has enumerated yet lands on the claim-free wording instead of a false one.
///
/// The four condition cells are not padding. A fix that stopped saying "condition" everywhere would
/// silence a true sentence on four ordinary rule shapes, and only these cells can fail for that.
///
/// Asserted through the record tree rather than the console, for the reason given on the sibling.
#[test]
fn a_comparison_skip_reason_names_the_gate_it_was_reached_through() -> Result<()> {
    // `Size` is a string and every gate below compares it to an integer, so the refusal is the same
    // `PathAwareValues are not comparable String, int` in each cell and only the path differs. `X` is
    // present so a body clause has something to read once a gate does open.
    const ONE_STRING_SIZED_VOLUME: &str = r#"{
        "Resources": {
            "V1": {
                "Type": "AWS::EC2::Volume",
                "Properties": { "Size": "50", "X": 1 }
            }
        }
    }"#;

    // (label, rules, the fragment the reason must contain, a fragment it must not)
    let cases = [
        (
            "a query filter, with no `when` anywhere in the rule",
            r#"rule g { Resources.*[ Properties.Size > 10 ] { Properties.X == 1 } }"#,
            "query filter",
            "condition",
        ),
        (
            "a query filter in a `let`, still with no `when`",
            r#"let sel = Resources.*[ Properties.Size > 10 ]
               rule g { %sel.Properties.X == 1 }"#,
            "query filter",
            "condition",
        ),
        (
            "a `when` condition on the rule",
            r#"rule g when Resources.V1.Properties.Size > 10 { Resources.V1.Properties.X == 1 }"#,
            "one of its conditions was not met",
            "query filter",
        ),
        (
            "a `when` condition on a block inside the rule",
            r#"rule g { when Resources.V1.Properties.Size > 10 { Resources.V1.Properties.X == 1 } }"#,
            "one of its conditions was not met",
            "query filter",
        ),
        (
            "a `when` condition on a type block",
            r#"rule g { AWS::EC2::Volume when Properties.Size > 10 { Properties.X == 1 } }"#,
            "one of its conditions was not met",
            "query filter",
        ),
        (
            "a filter inside a `when` condition -- the condition is real and was not met",
            r#"rule g when Resources.*[ Properties.Size > 10 ] not empty { Resources.V1.Properties.X == 1 }"#,
            "one of its conditions was not met",
            "query filter",
        ),
    ];

    for (label, rules, expected, forbidden) in cases {
        let rules_file = RulesFile::try_from(rules)?;
        let value = PathAwareValue::try_from(ONE_STRING_SIZED_VOLUME)?;
        let mut root = root_scope(&rules_file, Rc::new(value));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            Status::SKIP,
            "{label}: the rule does not apply on this input"
        );
        let top = root.reset_recorder().extract();
        // Arguments spelled out rather than captured inline, for the edition-2018 reason given on the
        // sibling test.
        let reason = crate::rules::eval_context::find_skip_reason(&top)
            .unwrap_or_else(|| panic!("{}: no skip reason was recorded at all", label));

        // Every cell keeps the explanation itself. A fix that dropped the refusal to avoid misnaming
        // its source would pass a contains/forbids pair about the prefix alone.
        assert!(
            reason.contains("not comparable"),
            "{}: the reason lost the comparison's own explanation: {:?}",
            label,
            reason
        );
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
///    defect the two clause-level negation commits fixed, for binary comparisons and for
///    parameterized rule calls.
/// 4. **An unanswerable gate does not disarm its body.** Where the body fails on its own, wrapping it
///    in a gate the evaluator cannot answer must not turn the verdict into success. Added after a
///    reviewer found that exact loss by hand; the 252 cells here all guarded a body and none of them
///    caught it, because canary isolation only detects a lost verdict belonging to another rule.
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
    // that changed nothing is the dropped-negation defect -- and that defect made the
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

    // 5. A gate that cannot be answered must not report success while a violation sits inside it.
    //
    // This is the invariant the corpus was missing, and a reviewer found the gap by hand: the shapes
    // below all guard a body, and the body violates on the templates named here, but nothing asserted
    // that the guarded form still fails. The first version of the unevaluatable-clause fix answered
    // SKIP for a gate, so every one of these cells returned success with the violation unreported --
    // 252 cells and not one of them noticed, because canary isolation only catches a lost verdict when
    // the lost verdict belongs to a *different* rule.
    //
    // Oracle-free: rather than asserting a known-correct status, it asserts a relationship. Take the
    // body on its own; if that FAILs, then wrapping it in a gate the evaluator cannot answer must not
    // turn it into PASS or SKIP, whatever the right answer for the gate is.
    const GATE_SHAPES: [&str; 2] = ["gate", "nested_when"];
    // The cells that still disarm their body, listed rather than counted so a new one names itself.
    //
    // All of them are an undecidable *comparison* used as a gate -- a query that does not resolve, or
    // a type mismatch -- which is the case `f3c919f` records as needing a status meaning "could not
    // tell". That is #720's `Outcome` lattice, where `Unevaluatable` is a value a gate can return
    // instead of collapsing into "did not match". None of the entries below is a regression from this
    // branch.
    //
    // No `empty_on_scalar` cell appears here, which is the point of the list: that clause used to
    // disarm its body in every one of these shapes, and it is what a reviewer found by hand.
    //
    // The eight `absent_root` cells that used to be listed here are gone, and not because a gate
    // stopped losing a verdict -- because there is no longer a verdict to lose. `absent_root` carries
    // no `Resources` key and `FILTER` selects from it, so on that template the *body alone* used to
    // report FAIL: "a volume is unencrypted", about a document containing no volumes. An empty
    // selection now reports SKIP, which is what a filter that keeps nothing has always reported, so
    // the body is inapplicable rather than violated and this loop's `body_alone != FAIL` guard drops
    // the cell before it can be counted. Measured both ways rather than reasoned: on the merge-base
    // the body alone is FAIL and the gated form SKIP, and with the empty-selection fix both are SKIP.
    //
    // `in_list` has no `string_size` entry, and the reason is worth knowing: `IN` against a type it
    // cannot compare answers FAIL while `NOT IN` answers PASS, so the pair is not recognised as
    // undecidable and the invariant skips those cells. That disagreement between the two operators is
    // itself a defect -- `every_operator_and_operand_shape_agrees_with_a_stated_oracle` records it --
    // and closing it would add two entries here rather than remove any.
    const DISARMED_BY_AN_UNDECIDABLE_COMPARISON: [&str; 14] = [
        "eq_int/gate/absent_property",
        "eq_int/gate/string_size",
        "eq_int/nested_when/absent_property",
        "eq_int/nested_when/string_size",
        "gt_int/gate/absent_property",
        "gt_int/gate/string_size",
        "gt_int/nested_when/absent_property",
        "gt_int/nested_when/string_size",
        "in_list/gate/absent_property",
        "in_list/nested_when/absent_property",
        "le_float/gate/absent_property",
        "le_float/gate/string_size",
        "le_float/nested_when/absent_property",
        "le_float/nested_when/string_size",
    ];
    let mut disarmed: Vec<String> = Vec::new();
    for (clause_label, clause) in &clauses {
        for (tmpl_label, data) in templates {
            let body_alone = evaluate(&format!("rule r {{\n    {body}\n}}\n"), data)?;
            if body_alone != Status::FAIL {
                continue;
            }
            // Whether a clause can be answered depends on the value it meets, not on the clause alone:
            // `Size EMPTY` is unanswerable against an integer and perfectly answerable against a
            // string, where "not empty" is the right answer and skipping the rule is the correct gating
            // idiom. An earlier version of this loop keyed off a clause-level list and failed on
            // exactly that case.
            //
            // Both polarities failing is the fail-closed signature of a clause that could not be
            // decided, and invariant 3 above independently asserts that a *decidable* clause and its
            // negation differ -- so the two together make this a sound marker rather than a guess.
            let plain = evaluate(&format!("rule r {{\n    {clause}\n}}\n"), data)?;
            let negated = evaluate(&format!("rule r {{\n    not {clause}\n}}\n"), data)?;
            if !(plain == Status::FAIL && negated == Status::FAIL) {
                continue;
            }
            for shape_label in GATE_SHAPES {
                let rule = shapes(clause, &body)
                    .into_iter()
                    .find(|(label, _)| *label == shape_label)
                    .map(|(_, text)| text)
                    .expect("the shape table no longer has this shape");
                let cell = format!("{}/{}/{}", clause_label, shape_label, tmpl_label);
                if evaluate(&rule, data)? != Status::FAIL {
                    disarmed.push(cell);
                }
            }
        }
    }

    // Exactly the documented set, no more and no less. A new entry is a new way to lose a verdict; a
    // missing entry means something fixed it, and then this list and the paragraph above it should go.
    disarmed.sort();
    assert_eq!(
        disarmed, DISARMED_BY_AN_UNDECIDABLE_COMPARISON,
        "the set of gate shapes that disarm their guarded body changed"
    );

    Ok(())
}

/// Every operator against every operand shape, in both polarities and in both positions, checked
/// against a stated expectation rather than against itself.
///
/// This exists because `generated_rule_shapes_hold_the_evaluator_invariants` cannot catch a wrong
/// answer. Its invariants -- canary isolation, determinism, and that a clause and its negation never
/// both pass -- are all satisfiable by a verdict that is wrong but self-consistent, and that is exactly
/// what a boolean `!EMPTY` used as a gate was: 252 cells passed and a reviewer found it by reading the
/// code. Coverage without an oracle measures how much code ran, not whether it was right.
///
/// So `ORACLE` states, for each operator and operand shape, whether the clause can be answered at all
/// and what the answer is when it can. Those 110 judgments come from the language semantics, and all
/// 440 cells derive from them by the four rules on `expected`. A cell that disagrees is either a defect
/// or a wrong judgment, and both are worth knowing.
///
/// Two judgments are worth stating because they are easy to get backwards, and one of them was:
///
/// - A comparison against a list is applied to the list's *elements*, because a query expands a list.
///   `Size == 50` against `[1, 2, 3]` records three separate checks at `/Size/0`, `/Size/1` and
///   `/Size/2`, so the answer is a definite false rather than "no answer". The first version of this
///   table called it undecidable and reported three defects that were not defects.
/// - A unary operator does *not* expand. `Tags !empty` is documented as a check on the list itself, so
///   `EMPTY` against a list answers about the list.
///
/// The remaining disagreements are listed by name in `KNOWN`. All of them are #720's scope: an
/// undecidable comparison used as a gate still disarms the body it guards, and a comparison against an
/// empty collection still passes vacuously. Both need a status meaning "could not tell", which is the
/// `Outcome` lattice. Listing them by name rather than counting them means a new one identifies itself,
/// and fixing one fails this test and asks for its own removal from the list.
#[test]
fn every_operator_and_operand_shape_agrees_with_a_stated_oracle() -> Result<()> {
    // Order is load-bearing: `ORACLE`'s rows are indexed by it.
    const SHAPES: [(&str, &str); 11] = [
        ("int_50", r#""Size": 50"#),
        ("float_50_5", r#""Size": 50.5"#),
        ("string_50", r#""Size": "50""#),
        ("empty_string", r#""Size": """#),
        ("list", r#""Size": [1, 2, 3]"#),
        ("empty_list", r#""Size": []"#),
        ("map", r#""Size": {"a": 1}"#),
        ("empty_map", r#""Size": {}"#),
        ("bool_true", r#""Size": true"#),
        ("null", r#""Size": null"#),
        ("absent", ""),
    ];

    const OPERATORS: [(&str, &str); 10] = [
        ("EXISTS", "EXISTS"),
        ("EMPTY", "EMPTY"),
        ("IS_STRING", "IS_STRING"),
        ("IS_INT", "IS_INT"),
        ("IS_LIST", "IS_LIST"),
        ("IS_STRUCT", "IS_STRUCT"),
        ("IS_BOOL", "IS_BOOL"),
        ("eq_50", "== 50"),
        ("gt_10", "> 10"),
        ("in_list", "IN [10, 50, 100]"),
    ];

    // What the clause is able to say about an operand shape. Columns follow SHAPES.
    //
    // Three answers, not two, and the third arrived from a reviewer's argument rather than from first
    // principles. An empty collection is not undecidable -- emptiness is a fact -- and `no element ==
    // 50` over zero elements is vacuously true, which is why failing it "rejected a compliant
    // template". But vacuous truth is not an affirmative pass either, because the clause examined
    // nothing, so the honest reading is that the negated form asserts nothing and reports neither.
    //
    // `Unanswerable` and `Vacuous` have to stay apart: a type mismatch has no answer in either
    // polarity, while an empty collection has a different answer in each. This is the one row where
    // the fail-closed rule does not apply uniformly.
    #[derive(Copy, Clone, Debug, PartialEq)]
    enum Answer {
        /// The clause has this answer for this operand.
        Says(bool),
        /// The clause cannot be answered at all, so it fails closed in both polarities.
        Unanswerable,
        /// An empty collection: the positive form claims something over nothing, which
        /// `docs/QUERY_AND_FILTERING.md` calls a retrieval error and therefore a failure, and the
        /// negated form is vacuously true and claims nothing.
        Vacuous,
    }
    use Answer::{Says, Unanswerable, Vacuous};

    #[allow(clippy::type_complexity)]
    const ORACLE: [(&str, [Answer; 11]); 10] = [
        (
            "EXISTS",
            [
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(true),
                Says(false),
            ],
        ),
        (
            "EMPTY",
            [
                Unanswerable,
                Unanswerable,
                Says(false),
                Says(true),
                Says(false),
                Says(true),
                Says(false),
                Says(true),
                Unanswerable,
                Unanswerable,
                Says(true),
            ],
        ),
        (
            "IS_STRING",
            [
                Says(false),
                Says(false),
                Says(true),
                Says(true),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
            ],
        ),
        (
            "IS_INT",
            [
                Says(true),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
            ],
        ),
        (
            "IS_LIST",
            [
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(true),
                Says(true),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
            ],
        ),
        (
            "IS_STRUCT",
            [
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(true),
                Says(true),
                Says(false),
                Says(false),
                Says(false),
            ],
        ),
        (
            "IS_BOOL",
            [
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(false),
                Says(true),
                Says(false),
                Says(false),
            ],
        ),
        (
            "eq_50",
            [
                Says(true),
                Says(false),
                Unanswerable,
                Unanswerable,
                Says(false),
                Vacuous,
                Unanswerable,
                Unanswerable,
                Unanswerable,
                Unanswerable,
                Unanswerable,
            ],
        ),
        (
            "gt_10",
            [
                Says(true),
                Says(true),
                Unanswerable,
                Unanswerable,
                Says(false),
                Vacuous,
                Unanswerable,
                Unanswerable,
                Unanswerable,
                Unanswerable,
                Unanswerable,
            ],
        ),
        (
            "in_list",
            [
                Says(true),
                Says(false),
                Unanswerable,
                Unanswerable,
                Says(false),
                Vacuous,
                Unanswerable,
                Unanswerable,
                Unanswerable,
                Unanswerable,
                Unanswerable,
            ],
        ),
    ];

    /// The verdict a cell must produce, from the oracle, by four rules.
    ///
    /// 1. An assertion that cannot be answered fails closed. PASS would certify a check that never
    ///    ran; SKIP exits 0, which is the same thing one level out.
    /// 2. An assertion that can be answered passes when the answer holds, and `not` inverts the
    ///    answer and nothing else.
    /// 3. A gate that cannot be answered fails the rule. Not SKIP: `eval_rule` maps every non-PASS
    ///    condition to a rule-level SKIP, so SKIP drops the guarded body and exits 0 with the
    ///    violation inside it unreported.
    /// 4. A gate that can be answered either opens, and the body decides -- always FAIL here, since
    ///    the body is always violated -- or does not match, and the rule does not apply.
    fn expected(answer: Answer, negated: bool, gate: bool) -> Status {
        match answer {
            Unanswerable => Status::FAIL,
            Vacuous => match (gate, negated) {
                // A claim over nothing, which the specification calls a retrieval error.
                (false, false) => Status::FAIL,
                // Vacuously true, and it asserts nothing, so neither pass nor fail.
                (false, true) => Status::SKIP,
                // In a gate the two readings converge, so this cell is weak evidence either way.
                // Vacuous truth opens the gate and the body decides, which is FAIL here because the
                // body is always violated; the retrieval-error reading fails the gate closed, also
                // FAIL. SKIP is the one answer that is wrong, because that is the outcome which
                // drops the guarded body and exits 0. Measured on both branches: the reported
                // failure is the body clause, not the condition, so the gate does open.
                (true, _) => Status::FAIL,
            },
            Says(answer) => {
                let holds = if negated { !answer } else { answer };
                match (gate, holds) {
                    (false, true) => Status::PASS,
                    (false, false) => Status::FAIL,
                    (true, true) => Status::FAIL,
                    (true, false) => Status::SKIP,
                }
            }
        }
    }

    // The cells that do not agree, split by whether the current answer contradicts the specification
    // or merely contradicts this oracle. Conflating the two was misleading: 37 of the 48 are behaviour
    // the documentation describes on purpose, and reading a single count of 48 as "48 defects"
    // overstates the position by a factor of four.

    // Contradicts the specification. Each of these passes while comparing nothing.
    //
    // `docs/QUERY_AND_FILTERING.md` lists `Tags: []` beside a missing key and an empty map as retrieval
    // errors and states that all retrieval errors are failures. Measured, the other two do fail, so the
    // empty-collection rows are the outlier rather than a design choice. #720 fixes them.
    //
    // `docs/CLAUSES.md` says a comparison across kinds that are not both numeric "cannot be decided,
    // and the clause fails rather than guessing", and `docs/KNOWN_ISSUES.md` records the silent
    // conversion to `false` as a tracked defect. `!=` honours that; `NOT IN` does not. Fixing it needs
    // five registry rules to change first -- see the revert in `9a9600d` -- so both classes now emit a
    // deprecation notice a release ahead of the change.
    const VIOLATES_THE_SPEC: [&str; 12] = [
        "eq_50/empty_list/not/assert",
        "eq_50/empty_list/plain/assert",
        "gt_10/empty_list/not/assert",
        "gt_10/empty_list/plain/assert",
        "in_list/bool_true/not/assert",
        "in_list/empty_list/not/assert",
        "in_list/empty_list/plain/assert",
        "in_list/empty_map/not/assert",
        "in_list/empty_string/not/assert",
        "in_list/map/not/assert",
        "in_list/null/not/assert",
        "in_list/string_50/not/assert",
    ];

    // Conforms to the specification, which documents the hazard rather than the fix.
    //
    // `docs/CLAUSES.md:203-225` states that a condition which cannot be decided does not pass, that the
    // rule is therefore reported as not applicable, that the run exits 0, and that "the fix is in the
    // rule or the input rather than in Guard". It says so with a worked example. So these are not
    // defects against the current specification, and the oracle is stricter than the document.
    //
    // They are still the wrong answer, and #720 changes it: `Outcome::Unevaluatable` lets a gate say
    // "could not tell" instead of collapsing into "did not match". That PR owns the rewrite of those
    // lines, so that no merged state has the document disagreeing with the code.
    const CONFORMS_TO_THE_SPEC: [&str; 37] = [
        "eq_50/absent/not/gate",
        "eq_50/absent/plain/gate",
        "eq_50/bool_true/not/gate",
        "eq_50/bool_true/plain/gate",
        "eq_50/empty_map/not/gate",
        "eq_50/empty_map/plain/gate",
        "eq_50/empty_string/not/gate",
        "eq_50/empty_string/plain/gate",
        "eq_50/map/not/gate",
        "eq_50/map/plain/gate",
        "eq_50/null/not/gate",
        "eq_50/null/plain/gate",
        "eq_50/string_50/not/gate",
        "eq_50/string_50/plain/gate",
        "gt_10/absent/not/gate",
        "gt_10/absent/plain/gate",
        "gt_10/bool_true/not/gate",
        "gt_10/bool_true/plain/gate",
        "gt_10/empty_map/not/gate",
        "gt_10/empty_map/plain/gate",
        "gt_10/empty_string/not/gate",
        "gt_10/empty_string/plain/gate",
        "gt_10/map/not/gate",
        "gt_10/map/plain/gate",
        "gt_10/null/not/gate",
        "gt_10/null/plain/gate",
        "gt_10/string_50/not/gate",
        "gt_10/string_50/plain/gate",
        "in_list/absent/not/gate",
        "in_list/absent/plain/gate",
        "in_list/bool_true/plain/gate",
        "in_list/empty_list/not/gate",
        "in_list/empty_map/plain/gate",
        "in_list/empty_string/plain/gate",
        "in_list/map/plain/gate",
        "in_list/null/plain/gate",
        "in_list/string_50/plain/gate",
    ];

    const FILTER: &str = "Resources.*[ Type == 'AWS::EC2::Volume' ]";
    let body = format!("{FILTER}.Properties.MustFail == true");

    let mut disagreements: Vec<String> = Vec::new();
    let mut cells = 0;
    for (op_label, op) in OPERATORS {
        let answers = ORACLE
            .iter()
            .find(|(label, _)| *label == op_label)
            .map(|(_, answers)| answers)
            .expect("every operator needs an oracle row");
        for (shape_index, (shape_label, props)) in SHAPES.iter().enumerate() {
            // `MustFail` is false in every shape, so a guarded body always has a violation to report.
            // That is what makes a wrong SKIP visible as a lost verdict rather than as a bare exit 0.
            let properties = match props.is_empty() {
                true => r#""MustFail": false"#.to_string(),
                false => format!(r#"{}, "MustFail": false"#, props),
            };
            let data = format!(
                r#"{{ "Resources": {{ "V": {{ "Type": "AWS::EC2::Volume", "Properties": {{ {} }} }} }} }}"#,
                properties
            );
            for negated in [false, true] {
                let clause = format!(
                    "{}{FILTER}.Properties.Size {}",
                    if negated { "not " } else { "" },
                    op
                );
                for gate in [false, true] {
                    let rule = match gate {
                        false => format!("rule r {{\n    {clause}\n}}\n"),
                        true => format!("rule r when {clause} {{\n    {body}\n}}\n"),
                    };
                    let rules_file = RulesFile::try_from(rule.as_str())?;
                    let values = PathAwareValue::try_from(data.as_str())?;
                    let mut root = root_scope(&rules_file, Rc::new(values));
                    let actual = eval_rules_file(&rules_file, &mut root, None)?;
                    let want = expected(answers[shape_index], negated, gate);
                    cells += 1;
                    if actual != want {
                        disagreements.push(format!(
                            "{}/{}/{}/{}",
                            op_label,
                            shape_label,
                            if negated { "not" } else { "plain" },
                            if gate { "gate" } else { "assert" }
                        ));
                    }
                }
            }
        }
    }

    // The space cannot shrink without saying so: 10 operators x 11 shapes x 2 polarities x 2 positions.
    assert_eq!(cells, 10 * 11 * 2 * 2, "the generated space changed size");

    disagreements.sort();
    let mut expected: Vec<String> = VIOLATES_THE_SPEC
        .iter()
        .chain(CONFORMS_TO_THE_SPEC.iter())
        .map(|s| (*s).to_string())
        .collect();
    expected.sort();
    assert_eq!(
        disagreements, expected,
        "the set of cells disagreeing with the oracle changed. A new entry is a wrong verdict or a \
         wrong judgment; a missing entry means something was fixed, and then it should come off \
         whichever of the two lists holds it."
    );

    Ok(())
}

/// A range inside a list literal is a range.
///
/// `contained_in` decided list membership with `Vec::contains`, which compares by `PartialEq`, and
/// `PartialEq` is asked `element == value` -- the direction that has no range arm, and must not get
/// one, because `eq` has to stay symmetric while membership does not. So a range nested in a list
/// literal matched nothing, in either polarity. For a `Port` of 85, `Port in [r[80,90]]` failed and
/// `Port not in [r[80,90]]` passed: a denylist of port ranges that admits every port.
///
/// Unwrapped, the same question was always answered correctly, because `Port in r[80,90]` reaches
/// `compare_eq`, which is where the range table lives. Both spellings are asserted here, since the
/// two agreeing is the actual property.
///
/// Every cell has its opposite, so a fix that made membership always true, or always false, fails
/// rather than passing half the table.
#[rstest::rstest]
#[case::covering_range_wrapped("in [r[80,90]]", Status::PASS)]
#[case::covering_range_unwrapped("in r[80,90]", Status::PASS)]
#[case::covering_range_wrapped_negated("not in [r[80,90]]", Status::FAIL)]
#[case::covering_range_unwrapped_negated("not in r[80,90]", Status::FAIL)]
#[case::excluding_range_wrapped("in [r[10,20]]", Status::FAIL)]
#[case::excluding_range_wrapped_negated("not in [r[10,20]]", Status::PASS)]
#[case::range_beside_a_matching_value("in [r[10,20], 85]", Status::PASS)]
#[case::range_beside_a_non_matching_value("in [r[10,20], 99]", Status::FAIL)]
#[case::two_ranges_one_covering("in [r[10,20], r[80,90]]", Status::PASS)]
#[case::two_ranges_neither_covering("in [r[10,20], r[30,40]]", Status::FAIL)]
fn a_range_inside_a_list_literal_is_a_range(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            Vol: {
                Type: 'AWS::EC2::Volume',
                Properties: { Port: 85 }
            }
        }
    }
    "#;

    // A plain template rather than `format!`, following the convention above: the rule is mostly
    // braces and the escaping reads worse than the rule it describes.
    let rules = "rule ranged { Resources.Vol.Properties.Port CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "ranged")?,
        "clause: Port {}",
        clause
    );

    Ok(())
}

/// A nested list on the right of `IN` is found wherever it sits in the list.
///
/// The same shape as `a_range_inside_a_list_literal_is_a_range` above, in the branch that fix did not
/// reach. That one made `contained_in` ask each right-hand element in turn instead of asking
/// `Vec`-style membership once, because a range nested in a list literal was not being read as a
/// range. This is the list-valued-left-hand arm, where the element inspected was `rhsl[0]` and it
/// decided the reading for elements 1..n: a list there meant "is the whole left-hand list one of
/// these elements", anything else meant "is every left-hand element one of these".
///
/// So the answer turned on the order the right-hand list was typed in. For a `Pair` of `[1, 2]`,
/// `Pair NOT IN ["zzz", [1,2]]` exited 0 while `Pair NOT IN [[1,2], "zzz"]` exited 19 -- one
/// denylist, one value, and a permutation deciding whether it admitted a value it verbatim contains.
/// `IN` inverted identically and printed `was not present in [["zzz",[1,2]]]`, a finding refuted by
/// the set beside it.
///
/// The `_first`/`_last` pairing IS the assertion: each pair differs only in element order, so a cell
/// that disagrees with its partner is the defect regardless of which verdict is the right one. Two of
/// these nine failed before the fix, both `_last` cells.
///
/// The other seven are controls, and each stops a different over-fix. The two `Port` cells keep the
/// scalar-left-hand arm -- the one d7f01ec actually changed -- in view, since both arms read the same
/// right-hand list. `subset_over_a_flat_list` is the reading that has to survive: deleting the subset
/// branch outright fails it, checked by replacing that branch with an unconditional failure. The two
/// `absent_nested_list` cells are a nested list that genuinely is not there, which must keep failing
/// in both positions; making the membership test unconditionally true fails both.
///
/// The two `subset_survives_a_nested_neighbour` cells are the pair that pins WHICH order-independent
/// rule this is. Gating the subset reading on the right-hand side holding no list is also
/// order-independent and also closes the defect, but it makes `IN [1, 2, [9]]` fail -- so adding an
/// unrelated nested entry to an allowlist stops the flat entries beside it from matching. The `_first`
/// spelling of this pair failed before the fix and the `_last` one passed, so between them they hold
/// the rule in place from both sides.
#[rstest::rstest]
#[case::nested_list_first("Pair", r#"IN [[1,2], "zzz"]"#, Status::PASS)]
#[case::nested_list_last("Pair", r#"IN ["zzz", [1,2]]"#, Status::PASS)]
#[case::denylist_holds_it_first("Pair", r#"NOT IN [[1,2], "zzz"]"#, Status::FAIL)]
#[case::denylist_holds_it_last("Pair", r#"NOT IN ["zzz", [1,2]]"#, Status::FAIL)]
#[case::scalar_branch_first("Port", r#"IN [85, "zzz"]"#, Status::PASS)]
#[case::scalar_branch_last("Port", r#"IN ["zzz", 85]"#, Status::PASS)]
#[case::subset_over_a_flat_list("Pair", r#"IN ["zzz", 1, 2]"#, Status::PASS)]
#[case::absent_nested_list_first("Pair", r#"IN [[3,4], "zzz"]"#, Status::FAIL)]
#[case::absent_nested_list_last("Pair", r#"IN ["zzz", [3,4]]"#, Status::FAIL)]
#[case::subset_survives_a_nested_neighbour_last("Pair", r#"IN [1, 2, [9]]"#, Status::PASS)]
#[case::subset_survives_a_nested_neighbour_first("Pair", r#"IN [[9], 1, 2]"#, Status::PASS)]
fn a_nested_list_on_the_right_of_in_is_found_in_any_position(
    #[case] property: &str,
    #[case] comparison: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Pair: [1, 2],
        Port: 85
    }
    "#;

    let rules = format!("rule membership {{ {property} {comparison} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {} {}",
        property,
        comparison
    );

    Ok(())
}

/// What a denylist written as a list holding a nested list admits, cell by cell.
///
/// `a_nested_list_on_the_right_of_in_is_found_in_any_position` above covers the same arm and has four
/// `NOT IN` cells, and in every one of them the whole left-hand list IS a member of the denylist. So no
/// cell anywhere in the suite asked what `NOT IN` answers when membership *fails*, and the arm answered
/// that case by reporting the entire left-hand list as the unmatched diff. The negation wrapper reads
/// that field as a set of left-hand *elements* and keeps the ones absent from it; a whole list matches
/// no element, so every element survived, and `NOT IN` failed for every left-hand value whenever the
/// denylist held any nested list at all. `Pair NOT IN [[99,98]]` -- two disjoint pairs -- exited 19.
///
/// Stated rather than derived, because nothing in the suite constrains this. Head, the correct fix, and
/// two candidate fixes that are wrong in different ways all give 903 passed and 0 failed, so a green
/// suite after a change here is evidence of nothing. The oracle below is the measurement.
///
/// The rule these cells state, for a NON-EMPTY left-hand list: `NOT IN` fails if and only if the whole
/// left-hand list is a member of the right-hand list, OR any left-hand element is. The qualifier is
/// load-bearing and used to be missing -- six cells below contradict the unqualified reading outright,
/// and the paragraph on the `empty` cells says why all six are right and the rule still holds everywhere
/// else. They are `denied_empty_over_a_flat_list`, `denied_empty_over_a_nested_list` and
/// `denied_empty_over_a_mixed_denylist`, each with its `_via_query` twin. It was two before the empty
/// case stopped depending on the denylist's shape, and the count moves with that exception rather than
/// with this rule.
///
/// It is not `not(IN)`. `IN` over a list-valued left-hand side means whole-list membership or a complete
/// subset, so a left-hand list only *partly* present is outside `IN` and inside `NOT IN`, and both
/// polarities fail -- `Nest`, which is `[1, [9]]`, against a denylist of `[[9]]` is exactly that.
/// Fail-closed on a partial collision is the same reading `found_in_string`'s `Partial` applies to
/// substring `IN`, and it is the safe direction: a denylist that cannot decide must not report
/// compliance.
///
/// A verdict-negating fix was built and rejected. It marked the membership branch's failures with a
/// field mirroring `QueryIn::diff_from` and had the wrapper flip the verdict for them instead of
/// recomputing a diff. It is smaller and it fixes the six cells above, and it admits four values the
/// denylist names: `denied_by_a_nested_element_collision` and `denied_by_a_nested_element_that_is_named`
/// both reach exit 0 under it, because flipping "the whole list is not a member" to PASS says nothing
/// about the elements. 29 of these cells, against 36 for populating the diff element-wise.
///
/// `denied_by_one_flat_element` is the control that separates them and the one to read first if a later
/// change moves anything here. `Pair NOT IN [1, 3]` must FAIL: `1` is named. Verdict negation turns it
/// PASS.
///
/// Every cell has a `_via_query` twin naming the same denylist as a document property, because the rule
/// above is about two values and says nothing about how the right-hand one was written. It used to be
/// pinned for the written-out spelling only, and the two spellings disagreed on exactly the cells that
/// matter: `Pair NOT IN DenyOneThree` exited 0 where `Pair NOT IN [1, 3]` exited 19, and
/// `Nest NOT IN DenyNestedNine` exited 0 where `Nest NOT IN [[9]]` exited 19. Two denylists admitting a
/// value whose element they name, in the spelling a real rules file uses.
///
/// A written-out right-hand side reaches `InOperation`'s `(None, Some)` arm, which hands the pair
/// straight to `contained_in` and lets the negation wrapper read the element-wise `ListIn` diff it
/// returns. A queried one reaches the `(None, None)` arm, which keeps one verdict for the whole
/// left-hand operand set and counted only `contained_in`'s *Success* as a match -- so a `Fail` carrying
/// a real element collision was indistinguishable from a total miss, joined the unmatched set, and
/// negated to a pass. The 34 twins that were already green are why the repair had to leave the `IN`
/// polarity and every total miss alone rather than fail closed on the whole arm.
///
/// The `_via_query` cells for `Empty` agree with their written-out siblings, and both arms now answer
/// FAIL for every denylist shape rather than only for a flat one. `contained_in` used to fail an empty
/// left-hand list against a denylist holding a nested list, and it did so with an *empty* diff; an empty
/// diff is correctly no collision, so the wrapper found nothing colliding and `NOT IN` passed. Reading
/// that "failed" as "collided" was the tempting repair and is still the wrong one -- it makes a Fail
/// with no members mean a collision, which is the one thing the diff exists to deny. The fix sits
/// upstream of the wrapper instead: an empty left-hand list satisfies the subset reading vacuously, as
/// it always did over a flat denylist, so `contained_in` answers Success and the wrapper is never handed
/// a Fail with nothing in it.
///
/// The `_whatever_its_depth` cells are why the subset test no longer requires the matching right-hand
/// element to be a non-list. With that requirement, an element that is itself a list could not
/// contribute to the subset reading even when the denylist holds it verbatim, so `Nest IN [1, [9]]`
/// failed while `Nest NOT IN [1, [9]]` also failed -- neither polarity would admit a pair of operands
/// where every element of the left is written out on the right. It also let the failure branch produce
/// an empty diff, which contradicts the Fail it is attached to. Without the requirement, "every element
/// matched" and "the element-wise diff is empty" are the same statement, so a failure always carries the
/// values that caused it. `in_elements_wrapped_one_deep_is_not_a_subset` is the control on the other
/// side: dropping the requirement must not make `[1, 2]` a subset of `[[1], [2]]`.
///
/// The `empty` cells used to pin an inconsistency deliberately. It is closed now, because it was not
/// stable under adding a denylist entry. An empty left-hand list is vacuously a subset, so it passed `IN`
/// over a flat denylist; over one holding a nested list, the `is_empty` guard in `contained_in`
/// (`eval/operators.rs`) kept it out of the subset reading. `NOT IN` inherited both answers by negation,
/// which put a Fail-to-Success flip inside one denylist family: `Empty NOT IN [1, 2]` failed and
/// `Empty NOT IN [1, 2, [9]]` passed, so adding an entry stopped a denylist denying a value it had
/// already denied. Monotonicity is the property that cannot be traded away here, and it forces the empty
/// case to answer the same way whatever the denylist holds. The guard is gone, and the branch selector's
/// comment where it stood carries the argument, as the guard's own comment used to.
///
/// FAIL is that answer, and not because the unqualified rule gives it. The rule gives PASS: `[]` is not a
/// member of `[1,2,3]` and has no element that `[1,2,3]` names, so neither disjunct holds. FAIL is the
/// answer because `denied_empty_over_a_flat_list` and `denied_empty_over_a_flat_list_via_query` have been
/// FAIL since before the nested-list work began, and because it is the conservative direction for a
/// denylist. The vacuous reading is what sits between the rule and the cells, which is why the rule above
/// is still stated for a non-empty left-hand list and this is still an exception to it rather than an
/// instance of it.
///
/// Six cells contradict the unqualified reading now rather than two, and that is this commit's doing:
/// `denied_empty_over_a_nested_list` and `denied_empty_over_a_mixed_denylist` join the two flat cells,
/// each with its `_via_query` twin. All six are the same single exception, applied uniformly instead of
/// only where the denylist happened to be flat. The `_denylist_holding_an_empty_list` pair is not among
/// them, and that is why it is here: `[]` is a whole-list member of `[1, 2, []]`, so the unqualified rule
/// gives FAIL on its own and those cells agree with it without needing the exception at all. They fail
/// for a reason that survives the vacuous reading being revisited.
///
/// The cost is the one the previous comment here named: `in_empty_over_a_nested_list` moves from FAIL to
/// PASS, a second vacuous pass rather than one fewer. Two things make that the right side of the trade.
/// The other direction -- failing the empty case everywhere, so that no vacuous pass is left -- is
/// monotone too, but it moves `in_empty_over_a_flat_list`, which predates this work and is what an
/// allowlist spelled `x IN <list>` rests on. And neither pass is what `vacuous_comparison_notice` in
/// `eval.rs` deprecates: that notice fires on `compared_nothing`, an operand query that expanded to no
/// values at all, while an empty list is one value that does get compared. Measured rather than
/// reasoned: `Empty NOT IN [1,2,3]` and `Empty NOT IN [1,2,3,[9]]` each print nothing on stderr. Both
/// passes were silent before and both are silent after, so this adds no unnoticed behavior; it makes one
/// answer out of two.
///
/// The `_mixed_denylist` cells are the coverage whose absence let the flip land. Every empty-left-hand
/// cell here held a denylist that was purely flat or purely nested, so the one shape where the branch
/// selector actually changed -- flat entries beside a nested list -- was never asked, in either arm.
#[rstest::rstest]
#[case::undenied_nested_pair("Pair", r#"NOT IN [[99,98]]"#, Status::PASS)]
#[case::undenied_nested_singleton("Pair", r#"NOT IN [[7]]"#, Status::PASS)]
#[case::undenied_nested_strings("Pair", r#"NOT IN [["a"],["b"]]"#, Status::PASS)]
#[case::undenied_mixed_denylist("Pair", r#"NOT IN ["x", ["y"]]"#, Status::PASS)]
#[case::undenied_strings_against_a_nested_pair("Strs", r#"NOT IN [[1,2]]"#, Status::PASS)]
#[case::undenied_strings_against_a_mixed_denylist("Strs", r#"NOT IN ["x","y",[9]]"#, Status::PASS)]
#[case::denied_by_whole_list_membership("Strs", r#"NOT IN [["a","b"]]"#, Status::FAIL)]
#[case::denied_by_element_collision("Strs", r#"NOT IN ["a","b",[9]]"#, Status::FAIL)]
#[case::in_nested_pair("Pair", r#"IN [[99,98]]"#, Status::FAIL)]
#[case::in_nested_singleton("Pair", r#"IN [[7]]"#, Status::FAIL)]
#[case::in_nested_strings("Pair", r#"IN [["a"],["b"]]"#, Status::FAIL)]
#[case::in_mixed_denylist("Pair", r#"IN ["x", ["y"]]"#, Status::FAIL)]
#[case::in_strings_against_a_nested_pair("Strs", r#"IN [[1,2]]"#, Status::FAIL)]
#[case::in_strings_against_a_mixed_denylist("Strs", r#"IN ["x","y",[9]]"#, Status::FAIL)]
#[case::in_by_whole_list_membership("Strs", r#"IN [["a","b"]]"#, Status::PASS)]
#[case::in_by_flat_subset_beside_a_nested_element("Strs", r#"IN ["a","b",[9]]"#, Status::PASS)]
#[case::denied_by_one_flat_element("Pair", r#"NOT IN [1, 3]"#, Status::FAIL)]
#[case::undenied_by_a_disjoint_flat_list("Pair", r#"NOT IN [3, 4]"#, Status::PASS)]
#[case::denied_by_every_flat_element("Pair", r#"NOT IN [1, 2]"#, Status::FAIL)]
#[case::in_one_flat_element("Pair", r#"IN [1, 3]"#, Status::FAIL)]
#[case::in_a_disjoint_flat_list("Pair", r#"IN [3, 4]"#, Status::FAIL)]
#[case::in_every_flat_element("Pair", r#"IN [1, 2]"#, Status::PASS)]
#[case::in_flat_subset_survives_a_nested_neighbour("Pair", r#"IN [1, 2, [9]]"#, Status::PASS)]
#[case::denied_by_flat_subset_beside_a_nested_neighbour(
    "Pair",
    r#"NOT IN [1, 2, [9]]"#,
    Status::FAIL
)]
#[case::in_elements_wrapped_one_deep_is_not_a_subset("Pair", r#"IN [[1],[2]]"#, Status::FAIL)]
#[case::undenied_by_elements_wrapped_one_deep("Pair", r#"NOT IN [[1],[2]]"#, Status::PASS)]
#[case::in_partly_nested_left_is_not_a_subset("Nest", r#"IN [[9]]"#, Status::FAIL)]
#[case::denied_by_a_nested_element_collision("Nest", r#"NOT IN [[9]]"#, Status::FAIL)]
#[case::in_a_nested_element_is_a_member("Deep", r#"IN [["a"]]"#, Status::PASS)]
#[case::denied_by_a_nested_element_that_is_named("Deep", r#"NOT IN [["a"]]"#, Status::FAIL)]
#[case::in_every_element_found_whatever_its_depth("Nest", r#"IN [1, [9]]"#, Status::PASS)]
#[case::denied_by_every_element_whatever_its_depth("Nest", r#"NOT IN [1, [9]]"#, Status::FAIL)]
#[case::in_empty_over_a_flat_list("Empty", r#"IN [1,2,3]"#, Status::PASS)]
#[case::in_empty_over_a_nested_list("Empty", r#"IN [[9]]"#, Status::PASS)]
#[case::in_empty_over_a_mixed_denylist("Empty", r#"IN [1, 2, [9]]"#, Status::PASS)]
#[case::in_empty_over_a_denylist_holding_an_empty_list("Empty", r#"IN [1, 2, []]"#, Status::PASS)]
#[case::denied_empty_over_a_flat_list("Empty", r#"NOT IN [1,2,3]"#, Status::FAIL)]
#[case::denied_empty_over_a_nested_list("Empty", r#"NOT IN [[9]]"#, Status::FAIL)]
#[case::denied_empty_over_a_mixed_denylist("Empty", r#"NOT IN [1, 2, [9]]"#, Status::FAIL)]
#[case::denied_empty_over_a_denylist_holding_an_empty_list(
    "Empty",
    r#"NOT IN [1, 2, []]"#,
    Status::FAIL
)]
#[case::undenied_nested_pair_via_query("Pair", "NOT IN DenyNestedPair", Status::PASS)]
#[case::undenied_nested_singleton_via_query("Pair", "NOT IN DenyNestedSeven", Status::PASS)]
#[case::undenied_nested_strings_via_query("Pair", "NOT IN DenyWrappedStrs", Status::PASS)]
#[case::undenied_mixed_denylist_via_query("Pair", "NOT IN DenyMixedStrs", Status::PASS)]
#[case::undenied_strings_against_a_nested_pair_via_query(
    "Strs",
    "NOT IN DenyNestedOneTwo",
    Status::PASS
)]
#[case::undenied_strings_against_a_mixed_denylist_via_query(
    "Strs",
    "NOT IN DenyStrsAndNine",
    Status::PASS
)]
#[case::denied_by_whole_list_membership_via_query("Strs", "NOT IN DenyNestedAB", Status::FAIL)]
#[case::denied_by_element_collision_via_query("Strs", "NOT IN DenyABAndNine", Status::FAIL)]
#[case::in_nested_pair_via_query("Pair", "IN DenyNestedPair", Status::FAIL)]
#[case::in_nested_singleton_via_query("Pair", "IN DenyNestedSeven", Status::FAIL)]
#[case::in_nested_strings_via_query("Pair", "IN DenyWrappedStrs", Status::FAIL)]
#[case::in_mixed_denylist_via_query("Pair", "IN DenyMixedStrs", Status::FAIL)]
#[case::in_strings_against_a_nested_pair_via_query("Strs", "IN DenyNestedOneTwo", Status::FAIL)]
#[case::in_strings_against_a_mixed_denylist_via_query("Strs", "IN DenyStrsAndNine", Status::FAIL)]
#[case::in_by_whole_list_membership_via_query("Strs", "IN DenyNestedAB", Status::PASS)]
#[case::in_by_flat_subset_beside_a_nested_element_via_query(
    "Strs",
    "IN DenyABAndNine",
    Status::PASS
)]
#[case::denied_by_one_flat_element_via_query("Pair", "NOT IN DenyOneThree", Status::FAIL)]
#[case::undenied_by_a_disjoint_flat_list_via_query("Pair", "NOT IN DenyThreeFour", Status::PASS)]
#[case::denied_by_every_flat_element_via_query("Pair", "NOT IN DenyOneTwo", Status::FAIL)]
#[case::in_one_flat_element_via_query("Pair", "IN DenyOneThree", Status::FAIL)]
#[case::in_a_disjoint_flat_list_via_query("Pair", "IN DenyThreeFour", Status::FAIL)]
#[case::in_every_flat_element_via_query("Pair", "IN DenyOneTwo", Status::PASS)]
#[case::in_flat_subset_survives_a_nested_neighbour_via_query(
    "Pair",
    "IN DenyOneTwoAndNine",
    Status::PASS
)]
#[case::denied_by_flat_subset_beside_a_nested_neighbour_via_query(
    "Pair",
    "NOT IN DenyOneTwoAndNine",
    Status::FAIL
)]
#[case::in_elements_wrapped_one_deep_is_not_a_subset_via_query(
    "Pair",
    "IN DenyWrappedOneTwo",
    Status::FAIL
)]
#[case::undenied_by_elements_wrapped_one_deep_via_query(
    "Pair",
    "NOT IN DenyWrappedOneTwo",
    Status::PASS
)]
#[case::in_partly_nested_left_is_not_a_subset_via_query("Nest", "IN DenyNestedNine", Status::FAIL)]
#[case::denied_by_a_nested_element_collision_via_query(
    "Nest",
    "NOT IN DenyNestedNine",
    Status::FAIL
)]
#[case::in_a_nested_element_is_a_member_via_query("Deep", "IN DenyNestedWrappedA", Status::PASS)]
#[case::denied_by_a_nested_element_that_is_named_via_query(
    "Deep",
    "NOT IN DenyNestedWrappedA",
    Status::FAIL
)]
#[case::in_every_element_found_whatever_its_depth_via_query(
    "Nest",
    "IN DenyOneAndNine",
    Status::PASS
)]
#[case::denied_by_every_element_whatever_its_depth_via_query(
    "Nest",
    "NOT IN DenyOneAndNine",
    Status::FAIL
)]
#[case::in_empty_over_a_flat_list_via_query("Empty", "IN DenyOneTwoThree", Status::PASS)]
#[case::in_empty_over_a_nested_list_via_query("Empty", "IN DenyNestedNine", Status::PASS)]
#[case::in_empty_over_a_mixed_denylist_via_query("Empty", "IN DenyOneTwoAndNine", Status::PASS)]
#[case::in_empty_over_a_denylist_holding_an_empty_list_via_query(
    "Empty",
    "IN DenyOneTwoAndEmpty",
    Status::PASS
)]
#[case::denied_empty_over_a_flat_list_via_query("Empty", "NOT IN DenyOneTwoThree", Status::FAIL)]
#[case::denied_empty_over_a_nested_list_via_query("Empty", "NOT IN DenyNestedNine", Status::FAIL)]
#[case::denied_empty_over_a_mixed_denylist_via_query(
    "Empty",
    "NOT IN DenyOneTwoAndNine",
    Status::FAIL
)]
#[case::denied_empty_over_a_denylist_holding_an_empty_list_via_query(
    "Empty",
    "NOT IN DenyOneTwoAndEmpty",
    Status::FAIL
)]
fn a_list_denylist_holding_a_nested_list_denies_only_what_it_names(
    #[case] property: &str,
    #[case] comparison: &str,
    #[case] expected: Status,
) -> Result<()> {
    // The `Deny*` properties are the written-out denylists above, one per distinct list, so that a
    // `_via_query` cell asks the same question of the same two values through the other arm. Flat, not
    // nested under `Resources`: an unqualified right-hand name resolves against the document root, and
    // wrapping the data changes what it resolves to rather than how it is compared.
    const INPUT: &str = r#"
    {
        Pair: [1, 2],
        Strs: ["a", "b"],
        Nest: [1, [9]],
        Deep: [["a"]],
        Empty: [],
        DenyNestedPair: [[99,98]],
        DenyNestedSeven: [[7]],
        DenyWrappedStrs: [["a"],["b"]],
        DenyMixedStrs: ["x", ["y"]],
        DenyNestedOneTwo: [[1,2]],
        DenyStrsAndNine: ["x","y",[9]],
        DenyNestedAB: [["a","b"]],
        DenyABAndNine: ["a","b",[9]],
        DenyOneThree: [1, 3],
        DenyThreeFour: [3, 4],
        DenyOneTwo: [1, 2],
        DenyOneTwoAndNine: [1, 2, [9]],
        DenyWrappedOneTwo: [[1],[2]],
        DenyNestedNine: [[9]],
        DenyNestedWrappedA: [["a"]],
        DenyOneAndNine: [1, [9]],
        DenyOneTwoThree: [1,2,3],
        DenyOneTwoAndEmpty: [1, 2, []]
    }
    "#;

    let rules = format!("rule membership {{ {property} {comparison} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {} {}",
        property,
        comparison
    );

    Ok(())
}

/// One variable, two bindings, one answer.
///
/// `let d = <name>` and `let d = <list>` read identically at the use site, and a rules file names its
/// denylist with the first form far more often than it writes the list out at the clause. But the two
/// bindings reach different arms of `InOperation::compare`: a variable bound to a query is not a
/// literal, so `%d` on the right lands in the two-query arm, while a variable bound to a list stays
/// literal and lands beside a written-out list. So the arm that had the element-collision defect is the
/// one a real rules file reaches, and the arm that was correct is the one the suite exercised.
///
/// Measured before the repair: `let d = DenyOneThree` with `Pair NOT IN %d` exited 0 and
/// `let d = [1, 3]` with the same clause exited 19, on one document where `Pair` is `[1, 2]` and both
/// bindings name `1`. Every cell here is paired so that a change reaching only one binding form fails
/// rather than passing half the table.
///
/// The document is shared with
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`, whose `_via_query` cells cover
/// the unwrapped `Pair NOT IN DenyOneThree` spelling. This adds the variable indirection on top of it,
/// which is a third spelling of the same question rather than a third code path.
#[rstest::rstest]
#[case::query_bound_one_flat_element("DenyOneThree", "Pair NOT IN %d", Status::FAIL)]
#[case::literal_bound_one_flat_element("[1, 3]", "Pair NOT IN %d", Status::FAIL)]
#[case::query_bound_disjoint_flat_list("DenyThreeFour", "Pair NOT IN %d", Status::PASS)]
#[case::literal_bound_disjoint_flat_list("[3, 4]", "Pair NOT IN %d", Status::PASS)]
#[case::query_bound_nested_element_collision("DenyNestedNine", "Nest NOT IN %d", Status::FAIL)]
#[case::literal_bound_nested_element_collision("[[9]]", "Nest NOT IN %d", Status::FAIL)]
#[case::query_bound_in_every_flat_element("DenyOneTwo", "Pair IN %d", Status::PASS)]
#[case::literal_bound_in_every_flat_element("[1, 2]", "Pair IN %d", Status::PASS)]
#[case::query_bound_in_one_flat_element("DenyOneThree", "Pair IN %d", Status::FAIL)]
#[case::literal_bound_in_one_flat_element("[1, 3]", "Pair IN %d", Status::FAIL)]
fn a_denylist_named_by_a_variable_denies_what_the_same_list_written_out_denies(
    #[case] binding: &str,
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Pair: [1, 2],
        Nest: [1, [9]],
        DenyOneThree: [1, 3],
        DenyThreeFour: [3, 4],
        DenyOneTwo: [1, 2],
        DenyNestedNine: [[9]]
    }
    "#;

    let rules = format!("let d = {binding}\nrule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "let d = {} / {}",
        binding,
        clause
    );

    Ok(())
}

/// Which spelling of a queried denylist reaches the element-wise reading, and which does not.
///
/// The element-collision defect lives in one arm of `InOperation::compare`, the `(None, None)` one, and
/// it needs a particular shape to be visible: a left operand that resolves to a single list-valued
/// result against a right operand that resolves the same way. That is narrow enough that three nearby
/// spellings of the same question were never wrong, and a fix has to not be credited with them. The
/// `_expanded` cells are those spellings, measured at `0d2694f` before the repair and unchanged by it.
///
/// `Pair[*]` splits the left operand into one scalar result per element, so each element asks scalar
/// membership on its own and the whole-list granularity that lost the collision never arises. Expanding
/// both sides does the same.
///
/// Expanding only the RIGHT side is a second instance of the same defect rather than a nearby spelling,
/// and the diagnosis this comment used to carry was wrong. It said that a list against a scalar is what
/// `contained_in` calls not comparable, that `NOT IN` over an incomparable pairing passes, and that
/// `right_expanded_denies_nothing_yet` was therefore the tracked `docs/KNOWN_ISSUES.md` defect the
/// `incomparable_membership` notice is about -- so the cell pinned exit 0 and the fix was deferred to
/// whenever that notice became an error. The first clause is true; the conclusion does not follow, and
/// it is refutable by reading the arm boundary rather than only by measurement. `contained_in`
/// dispatches on the left value first: a list-valued left-hand side enters its `List` arm, and the
/// `Err(_) => {}` that implements "not comparable means not a member" sits in the `rest` arm below,
/// guarded by the left value NOT being a list. `Pair` is `[1, 2]`. So that suppression is unreachable
/// for this clause, no experiment on it could have moved the verdict, and the measurement that promoting
/// it leaves exit 0 unchanged is a corollary of the boundary rather than independent evidence.
///
/// Where it is, is the two-query arm's element-collision tracking. That arm reads a collision out of a
/// `Fail(Compare::ListIn(..))`, `contained_in` returns that shape only when BOTH operands are lists, and
/// a right operand expanded to scalars pairs a list with a scalar at every step -- which is the arm that
/// answers not comparable. So no collision was ever recorded, `collides` stayed empty, and the negation
/// wrapper read a left-hand list the denylist verbatim names as having matched nothing.
///
/// Which makes the repair an addition rather than a correction. `NotComparable` is the right answer for
/// what that arm is asked; "not comparable is not a match" is stated explicitly for a scalar left-hand
/// side and was implemented for a list one by the absence of an arm -- the whole-list reading standing in
/// for a question about elements. The element question is what was missing, and supplying it is the fix.
///
/// One sibling is open, it is in this table rather than only in a comment, and it is open because no
/// repair confined to this arm closes it. `Nest NOT IN DenyNestedNine[*]` -- a `Nest` of `[1, [9]]`
/// against a denylist of `[[9]]` -- is exit 0 while the written-out, unexpanded, and both-expanded
/// spellings of the same question are all exit 19. `Deny[*]` resolves the right operand to the inner
/// list `[9]`, and the collision question reads a list-shaped right-hand value as a set of candidate
/// entries, so that spelling compares against `{9}` where the others compare against `{[9]}`.
/// `right_expanded_nested_string_entry_undenied_no_local_fix` is the same bypass in strings.
///
/// What was tried and rejected, measured rather than argued. Dropping the `!eachr.is_list()` guard on
/// the arm added here asks the entry question for a list-shaped right-hand result, closes both open
/// cells, and moves no `IN` cell. It also turns
/// `an_lhs_element_equal_to_the_whole_unexpanded_denylist_is_undenied` from PASS to FAIL while its
/// written-out twin stays PASS: a `Wrap13` of `[[1, 3]]` against a `Deny13` of `[1, 3]` is denied by the
/// query spelling and admitted by the literal one, which is this table's own defect class mirrored into
/// over-denial. The full suite does not catch it -- 2553 passed with the only two failures being the
/// pinned cell above, one per target -- which is why the `Wrap13` cells are here.
///
/// No local predicate separates the two, because they are one shape. A list-valued right-hand result is
/// either the whole denylist, which an unexpanded `Deny13` resolves to, or a single entry, which
/// `Deny13[*]` resolves to, and the first wants decomposing while the second wants taking whole. "An
/// element of the left operand equals the whole right operand" is true of `Nest` against `[9]` and of
/// `Wrap13` against `[1, 3]` alike, and the first owes FAIL and the second PASS.
///
/// And no repair confined to this arm can be right, which is a proof rather than a preference about which
/// reading to prefer. For a `Denies` of `[[1, 3]]` -- one entry -- `Denies[0]` and `Denies[*]` resolve to
/// the same single value, the inner list `[1, 3]`, at the same path, so `compare` receives one identical
/// `QueryResult` either way. The oracle owes them opposite verdicts: `Denies[0]` is a single right-hand
/// operand whose value IS the right-hand list, members `1` and `3`, and `Pair` holds `1`, so FAIL;
/// `Denies[*]` names the entry set, whose one member is `[1, 3]`, which `Pair` neither is nor holds, so
/// PASS. `DenyNestedNine[0]` against `DenyNestedNine[*]` is the same pair with the polarity reversed.
/// Each pair holds one cell that is right today and one that is wrong, and anything written in that arm
/// moves both together, so at most one member of each pair can be correct. The
/// `a_single_indexed_entry_denies_by_its_members` group pins this.
///
/// That also rules out joining `unanswerable`, the arm's third answer, which fails closed in both
/// polarities for a pairing that has no right verdict either way. These pairings DO have right verdicts,
/// and one member of each pair is a PASS, so failing closed would deny a value no denylist names and
/// would assert that a decided question is undecided. The information is missing from the call, not from
/// the question, and that is the test for which of the two shapes a new ambiguity has.
///
/// `QueryResult` is `Literal | Resolved | UnResolved`, carrying the value and its path and no record of
/// the traversal, and `binary_operation` receives the right-hand side already resolved, consuming the
/// access expression that separates the two spellings. Carrying the provenance would change
/// `Comparator::compare` for every operator and would still miss `NOT IN %deny`, which
/// `a_denylist_named_by_a_variable_denies_what_the_same_list_written_out_denies` covers, since a
/// variable's binding is resolved before the comparator sees it. So closing this is a change to how a
/// queried right-hand operand reaches the comparators, not a change to this arm.
///
/// The deprecation notice stops firing for this clause, which is that deprecation completing rather than
/// a warning going missing. `incomparable_membership` asks about the whole left-hand value, and `[1, 2]`
/// is incomparable with `1` and with `3` alike, so it still answers `Some`; `binary_operation` gates the
/// notice on the verdict and the clause now fails. The notice's own words are "passed because the value
/// could not be compared", and it promised a future release would fail closed here. For this shape that
/// release is this one. `the_incomparable_membership_notice_is_only_emitted_for_a_clause_that_passed` is
/// what keeps the two in step.
///
/// The nested cells exist because reading them wrong nearly buried the defect. Moving the same two
/// values under `Resources.R.Properties` and keeping the clause as `Pair NOT IN Deny13` makes every
/// polarity exit 19, which reads as "the defect does not reproduce when nested". It is not: the
/// unqualified name resolves to nothing there, and the finding says so --
/// "property [Pair] to compare from is missing" -- so both polarities fail for a reason that has nothing
/// to do with membership. `nested_unqualified_undenied` is that cell, and it is FAIL for a disjoint
/// denylist, which is the tell. Written so the query actually selects the values, the nested document
/// reproduces the bypass exactly as the flat one does: `nested_qualified_denied` was exit 0 at `0d2694f`.
///
/// So the document's shape does not change which arm reads the clause. Only the query's shape does.
#[rstest::rstest]
#[case::flat_denied("flat", "Pair NOT IN Deny13", Status::FAIL)]
#[case::flat_undenied("flat", "Pair NOT IN Deny34", Status::PASS)]
#[case::left_expanded_denied("flat", "Pair[*] NOT IN Deny13", Status::FAIL)]
#[case::left_expanded_undenied("flat", "Pair[*] NOT IN Deny34", Status::PASS)]
#[case::both_expanded_denied("flat", "Pair[*] NOT IN Deny13[*]", Status::FAIL)]
#[case::both_expanded_undenied("flat", "Pair[*] NOT IN Deny34[*]", Status::PASS)]
#[case::right_expanded_denied("flat", "Pair NOT IN Deny13[*]", Status::FAIL)]
#[case::right_expanded_undenied("flat", "Pair NOT IN Deny34[*]", Status::PASS)]
// The mirror of the cell above it, and the one that says the repair denies only what the denylist
// names. `Deny349` is `Deny34` with a `9` added, so a fix that read any right-hand scalar as a
// collision -- or that failed closed on the incomparable pairing wholesale -- turns this PASS into a
// FAIL for a `Pair` holding neither 3 nor 4 nor 9. Adding an element to a denylist must never turn a
// FAIL into a PASS, and removing one must never turn a PASS into a FAIL; this is that property in the
// direction the repair could plausibly break.
#[case::right_expanded_undenied_by_a_longer_disjoint_list(
    "flat",
    "Pair NOT IN Deny349[*]",
    Status::PASS
)]
// Whole-list membership through the same expansion. `DenyNestedPair[*]` expands the outer list, so the
// right operand resolves to the single list `[1, 2]` and the pairing is list-against-list -- the shape
// that always worked. Here so that a repair aimed at the list-against-scalar shape cannot be credited
// with this one, and so that it stays FAIL if the new arm ever starts firing where a `ListIn` exists.
#[case::right_expanded_denied_by_whole_list_membership(
    "flat",
    "Pair NOT IN DenyNestedPair[*]",
    Status::FAIL
)]
#[case::flat_in_one_element("flat", "Pair IN Deny13", Status::FAIL)]
#[case::flat_in_disjoint("flat", "Pair IN Deny34", Status::FAIL)]
// `IN` for the spelling this commit repairs, both polarities of denylist. The repair moves `collides`,
// which only the negation wrapper reads, so neither of these may move: `[1, 2]` is not a subset of
// `{1, 3}` and not a subset of `{3, 4}`, and `IN` fails for both either way. If one of them moves, the
// fix reached `diff` and changed what `IN` means.
#[case::right_expanded_in_one_element("flat", "Pair IN Deny13[*]", Status::FAIL)]
#[case::right_expanded_in_disjoint("flat", "Pair IN Deny34[*]", Status::FAIL)]
// An open bypass, pinned with the three spellings that answer it correctly so the disagreement is in
// one table rather than in a comment. `DenyNestedNine` is `[[9]]` and `Nest` is `[1, [9]]`, so the
// denylist names `[9]` and the property holds `[9]`: every spelling owes exit 19. Three deliver it.
// `Nest NOT IN DenyNestedNine[*]` still passes, because `Deny[*]` resolves the right operand to the
// inner list `[9]` and the collision question then reads THAT as a set of candidate entries, `{9}`,
// rather than as the single entry `[9]` the other spellings compare against.
//
// The name says `no_local_fix` because that is measured rather than assumed, and the measurement is a
// cell in this table rather than a claim in this comment. Asking the entry question for a list-shaped
// right-hand result -- dropping the `!eachr.is_list()` guard on the arm `e331c6b` added, which is the
// whole of the obvious fix -- does close this cell and the `DeepA` one below. It also turns
// `an_lhs_element_equal_to_the_whole_unexpanded_denylist_is_undenied` from PASS to FAIL while its
// written-out twin stays PASS, which is a denylist over-denying in the spelling that was already
// right, and the same query-versus-literal divergence this table exists to close, mirrored. Measured
// on two fixtures and two value kinds.
//
// The reason no local predicate separates the two is that they are the same shape. A list-valued
// `eachr` is either the whole denylist, which `Deny13` unexpanded resolves to, or one entry, which
// `Deny13[*]` resolves to, and the two want opposite readings: decompose it for the first, take it
// whole for the second. `Nest` against an `eachr` of `[9]` and `Wrap13` against an `eachr` of
// `[1, 3]` are both "an element of the left operand equals the whole right operand", and the first
// owes FAIL while the second owes PASS. `QueryResult` is `Literal | Resolved | UnResolved` and
// carries no record of which traversal produced a value, and `binary_operation` is handed the
// right-hand side already resolved, so the arm cannot ask.
//
// Stronger than that, and this is a proof rather than a difficulty: the two spellings can be made
// indistinguishable. `Denies[0]` and `Denies[*]` over a `Denies` of `[[1, 3]]` deliver the same
// single value, the inner list `[1, 3]`, at the same path, so `compare` receives one identical
// `QueryResult` either way -- while the oracle owes them opposite verdicts. The
// `a_single_indexed_entry_denies_by_its_members` group below carries it. Threading the provenance
// would change `Comparator::compare` for every operator, and would still not reach `NOT IN %deny`,
// which `a_denylist_named_by_a_variable_denies_what_the_same_list_written_out_denies` covers. That
// is a design change rather than a repair to this arm, so this cell records the bypass and the guard
// cells below record what refuses the shortcut.
#[case::right_expanded_nested_entry_undenied_no_local_fix(
    "flat",
    "Nest NOT IN DenyNestedNine[*]",
    Status::PASS
)]
#[case::nested_entry_denied_written_out("flat", "Nest NOT IN [[9]]", Status::FAIL)]
#[case::nested_entry_denied_unexpanded("flat", "Nest NOT IN DenyNestedNine", Status::FAIL)]
#[case::nested_entry_denied_both_expanded("flat", "Nest[*] NOT IN DenyNestedNine[*]", Status::FAIL)]
// The same bypass in strings, so that the open cell above cannot be read as an integer-comparison
// quirk. `DeepA` is `[["a"]]` and `DenyWrappedA` is `[["a"]]`: the denylist names `["a"]` and the
// property holds `["a"]`. Written out and unexpanded both deny it; the right-expanded spelling does
// not. A fix that closes one of these two and not the other has found something narrower than the
// mechanism.
#[case::right_expanded_nested_string_entry_undenied_no_local_fix(
    "flat",
    "DeepA NOT IN DenyWrappedA[*]",
    Status::PASS
)]
#[case::nested_string_entry_denied_written_out("flat", r#"DeepA NOT IN [["a"]]"#, Status::FAIL)]
#[case::nested_string_entry_denied_unexpanded("flat", "DeepA NOT IN DenyWrappedA", Status::FAIL)]
// THE GUARD. `Wrap13` is `[[1, 3]]` and `Deny13` is `[1, 3]`, so the left operand's single element is
// the denylist itself. The denylist names `1` and `3`; `Wrap13` is not `1` or `3` and holds neither, so
// every spelling owes PASS and every spelling delivers it today. This is the cell that a fix for the
// two open cells above must not move, and the obvious fix moves the middle one. Keep all three: the
// divergence is only visible as the pair, because a fix that over-denies here leaves the written-out
// spelling alone and the unexpanded query is where it shows.
#[case::an_lhs_element_equal_to_the_whole_denylist_is_undenied_written_out(
    "flat",
    "Wrap13 NOT IN [1, 3]",
    Status::PASS
)]
#[case::an_lhs_element_equal_to_the_whole_unexpanded_denylist_is_undenied(
    "flat",
    "Wrap13 NOT IN Deny13",
    Status::PASS
)]
#[case::an_lhs_element_equal_to_the_whole_denylist_is_undenied_right_expanded(
    "flat",
    "Wrap13 NOT IN Deny13[*]",
    Status::PASS
)]
// THE PROOF that the open cells above cannot be closed inside `InOperation::compare`, as opposed to
// merely not being closed by the obvious repair. `Denies` is `[[1, 3]]`, one entry. `Denies[0]` and
// `Denies[*]` therefore resolve to the same single value, the inner list `[1, 3]`, at the same path,
// and `compare` receives one identical `QueryResult` either way -- the access expression that
// separates them is consumed by `binary_operation` before any comparator is called.
//
// The oracle owes them opposite verdicts. `Denies[0]` names a single right-hand operand whose VALUE is
// the right-hand list, so its members are `1` and `3` and `Pair` holds `1`: FAIL. `Denies[*]` names the
// entry set, whose one member is `[1, 3]`, which `Pair` neither is nor holds: PASS. The nested-entry
// shape is the same pair with the polarity reversed: `DenyNestedNine[0]` has members `9`, which `Nest`
// does not hold, so PASS, while `DenyNestedNine[*]` has the single member `[9]`, which `Nest` holds, so
// FAIL.
//
// So each pair contains one cell that is right today and one that is wrong, and any change confined to
// that arm moves both together. That is not an argument about which reading is better; it is a proof
// that at most one member of each pair can be correct until the provenance survives the call. Measured:
// deleting the `!eachr.is_list()` guard closes `right_expanded_nested_entry_undenied_no_local_fix` and
// reddens `a_single_indexed_nested_entry_denies_by_its_members` in the same run.
//
// It also disposes of answering "undecidable" and joining `unanswerable`, which is how this arm handles
// a genuinely incomparable pairing by failing closed in both polarities. `Pair NOT IN Denies[0]` and
// `Nest NOT IN DenyNestedNine[0]` have definite correct answers that the oracle fixes from the operand
// values, and one of them is a PASS. Reporting undecidable there would assert that a decided question
// has no answer, which is the same kind of false claim as reporting a collision nothing established.
// The information is missing from the call, not from the question -- which is the test for whether
// `unanswerable` is the honest answer to a new ambiguity or a dodge.
//
// An earlier revision of this table described `Denies[0]` as an entry whose path ends in a digit,
// offered as the reason a path-shape test would be unsound. That was wrong about which reading it
// wants: as a single-valued right operand it wants its whole value decomposed, exactly as an unexpanded
// `Deny13` does. The correction strengthens the conclusion rather than weakening it, because the two
// spellings turn out to be indistinguishable by path as well as by value, which is what makes the pair
// a proof instead of an argument. Recorded so nobody re-derives the wrong reading.
#[case::a_single_indexed_entry_denies_by_its_members("flat", "Pair NOT IN Denies[0]", Status::FAIL)]
#[case::the_same_value_right_expanded_over_denies("flat", "Pair NOT IN Denies[*]", Status::FAIL)]
#[case::a_single_indexed_nested_entry_denies_by_its_members(
    "flat",
    "Nest NOT IN DenyNestedNine[0]",
    Status::PASS
)]
// The disjoint mirror of the open cells, in all four spellings. `DenyNestedEight` is `[[8]]`, so it
// names `[8]` and `Nest` holds `[9]`: nothing named, PASS everywhere. A fix that closed the bypass by
// failing closed on the pairing wholesale, rather than by asking whether the entry is named, turns
// these four FAIL. Over-denial is the worse defect of the two, so the mirror is pinned in as many
// spellings as the bypass is.
#[case::nested_entry_undenied_by_a_disjoint_denylist_written_out(
    "flat",
    "Nest NOT IN [[8]]",
    Status::PASS
)]
#[case::nested_entry_undenied_by_a_disjoint_denylist_unexpanded(
    "flat",
    "Nest NOT IN DenyNestedEight",
    Status::PASS
)]
#[case::right_expanded_nested_entry_undenied_by_a_disjoint_denylist(
    "flat",
    "Nest NOT IN DenyNestedEight[*]",
    Status::PASS
)]
#[case::both_expanded_nested_entry_undenied_by_a_disjoint_denylist(
    "flat",
    "Nest[*] NOT IN DenyNestedEight[*]",
    Status::PASS
)]
// THE MIRROR DEFECT, and the pair above settles it too, so it has no repair inside
// `InOperation::compare` either. `DenyWrappedOneTwo` is `[[1], [2]]`, so it names `[1]` and `[2]`;
// `Pair` is `[1, 2]`, which is neither and holds neither, so every spelling owes PASS. The written-out
// and unexpanded ones deliver it. The right-expanded one FAILS, because the entry `[1]` is decomposed to
// the candidate set `{1}` and `Pair` holds `1` -- the same reading at the same wrong depth as the bypass
// above, in the direction that denies a value the denylist does not name, which is the worse direction
// for a policy tool. It arrives by the `element_collision` read of `contained_in`'s `ListIn` diff rather
// than by the `!eachr.is_list()` guard, so it is a second site and the same confusion.
//
// THE PAIR, in this defect's own entry shape rather than by analogy. `DenyWrapOne` is `[[1]]`, one entry,
// so `DenyWrapOne[0]` and `DenyWrapOne[*]` resolve to the same single value -- the inner list `[1]` -- at
// the same path, and `rhs_selected` holds exactly one result either way. `compare` receives one identical
// `QueryResult`, down to the count, so not even the number of right-hand results separates the two
// spellings; that is why the one-entry denylist is the construction and the two-entry `DenyWrappedOneTwo`
// is not, since for that one `[0]` and `[*]` do differ in count. The oracle owes them opposite verdicts.
// `DenyWrapOne[0]` is a single right-hand operand whose value IS the right-hand list, so its members are
// `1` and `Pair` holds `1`: FAIL. `DenyWrapOne[*]` names the entry set, whose one member is `[1]`, which
// `Pair` neither is nor holds: PASS. One cell of the pair is right today and one is wrong, and anything
// written in that arm moves both together, so at most one of them can be correct.
//
// So the over-denial and the under-denial are one impossibility with two faces, not two defects with a
// repair between them. `the_same_value_right_expanded_over_denies` above is already an instance of this
// defect: it is the `[*]` half of the pair `27383c98` recorded, and that commit framed the pair as being
// about `right_expanded_nested_entry_undenied_no_local_fix` alone, so the conclusion for the over-denial
// was there and unread. `DenyWrapOne` is added so the argument does not rest on `[[1, 3]]` standing in
// for `[[1]]`, and `DenyWrappedOneTwo[0]` because the two-entry spelling is the one a sweep counts and it
// needs its own coupled cell beside it.
//
// WHAT WAS CORRECTED. This block used to end "a fix that reads a list-shaped right-hand result as one
// entry turns this cell PASS, and that is the fix landing rather than a regression". The first clause is
// true and the second is false, which is measured rather than argued. Taking the entry reading -- the
// `matched_elements` read neutralized and the `!eachr.is_list()` guard dropped together, which is the
// only way to take it, since the two sites answer for the same operand shapes -- five open cells reach
// their owed verdict and twelve correct ones leave theirs in the same run, over fourteen distinct clauses
// in three tables. Reaching it: `DenyWrapOne[*]`, `DenyWrappedOneTwo[*]` and `Denies[*]` go 19 to 0, and
// `DenyNestedNine[*]` and `DenyWrappedA[*]` go 0 to 19. Leaving it, in this table: `DenyWrapOne[0]`,
// `DenyWrappedOneTwo[0]` and `Denies[0]` go 19 to 0, `DenyNestedNine[0]` goes 0 to 19,
// `Pair NOT IN Deny13` and its nested-document spelling return to the exit 0 that `e331c6b` closed,
// `Nest NOT IN DenyNestedNine` unexpanded loses its denial, and `Wrap13 NOT IN Deny13` starts
// over-denying at 19. Two cells each in
// `a_denylist_named_by_a_variable_denies_what_the_same_list_written_out_denies` and
// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names` leave theirs as well, which is the
// unexpanded whole denylist being read as one entry -- the half of the shape that must be decomposed.
// Every fix is paired with more than one break.
//
// Which is why these stay pinned at the current wrong answer, on the same terms as the open cells above:
// the suite stays green, the disagreement stays visible, and closing it is the change that lets the
// provenance separating the two spellings survive the call, not a repair to that arm.
#[case::wrapped_elements_undenied_written_out("flat", "Pair NOT IN [[1], [2]]", Status::PASS)]
#[case::wrapped_elements_undenied_unexpanded("flat", "Pair NOT IN DenyWrappedOneTwo", Status::PASS)]
#[case::right_expanded_wrapped_elements_over_denied(
    "flat",
    "Pair NOT IN DenyWrappedOneTwo[*]",
    Status::FAIL
)]
// The coupled cell for the spelling above, correct today and reddened by any repair that turns it PASS.
// `DenyWrappedOneTwo[0]` is the same entry `[1]` at the same path as that clause's first right-hand
// result, and as a single right-hand operand its members are `1`, which `Pair` holds.
#[case::a_single_indexed_wrapped_entry_denies_by_its_members(
    "flat",
    "Pair NOT IN DenyWrappedOneTwo[0]",
    Status::FAIL
)]
// The one-entry construction, which is what closes the count as a discriminator. Both spellings deliver
// the inner list `[1]` from one right-hand result, and the first owes FAIL by its members while the
// second owes PASS by its entry. The `[*]` cell is the over-denial and is pinned wrong; the `[0]` cell is
// right today. They cannot both be right until the provenance survives the call.
#[case::wrapped_one_entry_undenied_written_out("flat", "Pair NOT IN [[1]]", Status::PASS)]
#[case::wrapped_one_entry_undenied_unexpanded("flat", "Pair NOT IN DenyWrapOne", Status::PASS)]
#[case::a_single_indexed_wrapped_one_entry_denies_by_its_members(
    "flat",
    "Pair NOT IN DenyWrapOne[0]",
    Status::FAIL
)]
#[case::the_same_wrapped_value_right_expanded_over_denies(
    "flat",
    "Pair NOT IN DenyWrapOne[*]",
    Status::FAIL
)]
// `IN` for the nested-entry shapes, both polarities of denylist. `collides` is read only by the
// negation wrapper, so a repair confined to it may not move either of these: `[1, [9]]` is not a subset
// of `{9}` and not a subset of `{8}`, and it is not a member of either, so `IN` fails both ways. If one
// moves, the fix reached `diff`.
#[case::right_expanded_in_nested_entry("flat", "Nest IN DenyNestedNine[*]", Status::FAIL)]
#[case::right_expanded_in_disjoint_nested_entry("flat", "Nest IN DenyNestedEight[*]", Status::FAIL)]
#[case::nested_qualified_denied(
    "nested",
    "Resources.R.Properties.Pair NOT IN Resources.R.Properties.Deny13",
    Status::FAIL
)]
#[case::nested_qualified_undenied(
    "nested",
    "Resources.R.Properties.Pair NOT IN Resources.R.Properties.Deny34",
    Status::PASS
)]
#[case::nested_qualified_right_expanded_denied(
    "nested",
    "Resources.R.Properties.Pair NOT IN Resources.R.Properties.Deny13[*]",
    Status::FAIL
)]
#[case::nested_qualified_right_expanded_undenied(
    "nested",
    "Resources.R.Properties.Pair NOT IN Resources.R.Properties.Deny34[*]",
    Status::PASS
)]
#[case::nested_unqualified_denied("nested", "Pair NOT IN Deny13", Status::FAIL)]
#[case::nested_unqualified_undenied("nested", "Pair NOT IN Deny34", Status::FAIL)]
fn which_spelling_of_a_queried_denylist_reaches_which_arm(
    #[case] document: &str,
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // Verbatim the fixture the defect was reproduced against, plus one disjoint denylist for the
    // undenied polarity. `Pair` holds `1`, which `Deny13` names and `Deny34` does not. `Deny349` is
    // `Deny34` with an unrelated element added and `DenyNestedPair` wraps the pair one level deep; both
    // are for the right-expanded cells and neither changes what the original cells ask. `Nest` and
    // `DenyNestedNine` are the sibling the repair does not reach: a denylist entry that is itself a
    // list, which the property holds as an element.
    //
    // The rest exist for the open right-expanded sibling and for the guard that refuses the obvious fix
    // for it. `DenyNestedEight` is `DenyNestedNine` with the named value changed, so it names nothing
    // `Nest` holds -- the over-denial mirror. `DeepA` and `DenyWrappedA` are the same open bypass in
    // strings rather than integers, so a reader cannot take it for an integer-comparison quirk.
    // `DenyWrappedOneTwo` is the mirror defect in the other direction, over-denial. The class predates
    // this effort but the right-expanded cell does not, and an earlier revision here said it was "already
    // present and not introduced by anything on this branch", which is false for the cell it annotated.
    // Measured across three binaries, owed verdicts being written-out PASS, unexpanded PASS,
    // right-expanded PASS and single-indexed FAIL: at the pre-effort `5a3bfd5` the four are 19, 0, 0, 0,
    // so the WRITTEN-OUT spelling over-denied and the right-expanded one was right; at `9bcf2053` they
    // are 0, 0, 19, 19, so the written-out spelling was repaired and the right-expanded one broke.
    // `element_collision`, the mechanism that produces the current 19, has no occurrence in
    // `operators.rs` at `5a3bfd5` and arrives at `05232a25`. So this effort has already paid the price
    // the pair predicts once, without recognizing it as a trade: the over-denial moved from one spelling
    // to another rather than going away. That is what "at most one member of each pair can be correct"
    // looks like when it happens to someone.
    // `DenyWrapOne` is `DenyWrappedOneTwo` with the second entry removed, so that `[0]` and
    // `[*]` over it deliver one identical right-hand result and the same count of them; it is what makes
    // the over-denial's impossibility a pair rather than an analogy. `Wrap13` is the guard: its single
    // element IS `Deny13`, which is the one shape that makes the entry reading and the candidate-set
    // reading contradict each other, and the cells for it are what a fix has to keep PASS.
    const FLAT: &str = r#"
    {
        Pair: [1, 2],
        Nest: [1, [9]],
        Wrap13: [[1, 3]],
        DeepA: [["a"]],
        Deny13: [1, 3],
        Deny34: [3, 4],
        Deny349: [3, 4, 9],
        DenyNestedPair: [[1, 2]],
        DenyNestedNine: [[9]],
        DenyNestedEight: [[8]],
        DenyWrappedOneTwo: [[1], [2]],
        DenyWrapOne: [[1]],
        DenyWrappedA: [["a"]],
        Denies: [[1, 3]]
    }
    "#;

    const NESTED: &str = r#"
    {
        Resources: {
            R: {
                Properties: {
                    Pair: [1, 2],
                    Deny13: [1, 3],
                    Deny34: [3, 4]
                }
            }
        }
    }
    "#;

    let input = match document {
        "flat" => FLAT,
        "nested" => NESTED,
        other => panic!("unknown document `{}`", other),
    };

    let rules = format!("rule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, input, "membership")?,
        "{} document, clause: {}",
        document,
        clause
    );

    Ok(())
}

/// An empty left-hand list answers the same way whatever spelling names the denylist.
///
/// Why this exists: `4609b60e` made a denylist that grew keep denying an empty list, and it could not
/// reach the spellings where the right-hand query is expanded. `Empty NOT IN [1, 3]` and
/// `Empty NOT IN D13` both exit 19, and `Empty NOT IN D13[*]` exits 0 -- the same two values, and the
/// `[*]` deciding whether the denial happens. That is the same class of defect
/// `which_spelling_of_a_queried_denylist_reaches_which_arm` above is about, in the vacuous case.
///
/// The convention these cells encode is the one that table and
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names` already state: an empty left-hand
/// list is vacuously a subset of anything, so it passes `IN` and fails `NOT IN`, and `denied_empty_over_a_flat_list`
/// is where that is pinned for the written-out spelling. `vacuous_comparison_notice` in `eval.rs` is
/// separately deprecating the behavior. This test is not an argument for the convention; it is the claim
/// that the convention should not depend on how the right-hand operand was spelled.
///
/// Why this one is fixable where the right-expanded nested entry is not. That defect is impossible to
/// repair inside `InOperation::compare` because `Denies[0]` and `Denies[*]`, over a `Denies` of
/// `[[1, 3]]`, hand `compare` one identical `QueryResult` while the oracle owes them opposite verdicts,
/// so anything written there moves both together. Apply the same test here and the pair agrees: the
/// three `Denies` cells below are all FAIL, and they are FAIL because an empty left-hand list is
/// vacuously a subset of the entry set `{[1, 3]}` and of the member set `{1, 3}` alike. The verdict does
/// not depend on which reading of a list-shaped right-hand result is taken, so the ambiguity that blocks
/// the other defect does not arise, and the repair is available. `a_single_indexed_entry_denies_by_its_members`
/// is the contrasting pair to read beside these.
///
/// Where the answer was lost: `contained_in` supplies the vacuous match from its list-against-list arm,
/// where an empty left-hand list produces an empty diff and so a Success. A right-hand operand expanded
/// to scalars never reaches that arm -- a list against a scalar is `contained_in`'s incomparable
/// catch-all -- so the match was never found. The `Dn9[*]` cells are the control that separates the two:
/// `Dn9` is `[[9]]`, so `Dn9[*]` resolves to the inner list `[9]` and the pairing is list-against-list,
/// which always worked. A fix credited with those cells has not touched the defect.
///
/// The mirror, and it is the failure this fix could plausibly cause. A vacuous match must be available
/// to an empty LIST and to nothing else. `EmptyStr` and `EmptyMap` are the two values that look empty and
/// are not lists, and both must stay PASS in both spellings: `""` is not a member of `{1, 3}` and neither
/// is `{}`, and no subset reading applies to either, so the correct answer is the one they already give.
/// The `Pair` cells are the other half of the mirror: a non-empty list must keep answering by what the
/// denylist names, PASS for a disjoint one and FAIL for one that names an element, so a fix that made
/// every list-valued left-hand side match vacuously would redden them.
#[rstest::rstest]
// The defect, in the three spellings that lose the denial. `D13` and `D34` hold scalars, so `[*]` and
// `[0]` both resolve the right operand to a scalar, which is the shape where the vacuous match was lost.
// `D34` is disjoint from anything and still owes FAIL, which is the whole point of the convention: the
// empty case does not consult the denylist.
#[case::empty_denied_right_expanded("Empty NOT IN D13[*]", Status::FAIL)]
#[case::empty_denied_single_indexed("Empty NOT IN D13[0]", Status::FAIL)]
#[case::empty_denied_by_a_disjoint_denylist_right_expanded("Empty NOT IN D34[*]", Status::FAIL)]
// The two spellings that were already right, so the fix is visibly closing a gap rather than inventing a
// rule.
#[case::empty_denied_written_out("Empty NOT IN [1, 3]", Status::FAIL)]
#[case::empty_denied_unexpanded("Empty NOT IN D13", Status::FAIL)]
// The list-against-list control. `Dn9[*]` resolves to the inner list `[9]`, so this pairing reaches
// `contained_in`'s list arm and has always produced the vacuous match. Here so that a repair aimed at the
// scalar shape cannot be credited with it.
#[case::empty_denied_by_a_nested_entry_unexpanded("Empty NOT IN Dn9", Status::FAIL)]
#[case::empty_denied_by_a_nested_entry_right_expanded("Empty NOT IN Dn9[*]", Status::FAIL)]
// The contrasting pair: the exact operand shapes that make the right-expanded nested entry unrepairable
// in that arm. `Denies` is `[[1, 3]]`, so `Denies[0]` and `Denies[*]` deliver one identical value to
// `compare`. For a non-empty left-hand side those two owe opposite verdicts, which is the proof recorded
// in `which_spelling_of_a_queried_denylist_reaches_which_arm`. For an empty one they owe the same verdict,
// and that is why this defect has a repair and that one does not.
#[case::empty_denied_by_a_one_entry_denylist_unexpanded("Empty NOT IN Denies", Status::FAIL)]
#[case::empty_denied_by_a_one_entry_denylist_right_expanded("Empty NOT IN Denies[*]", Status::FAIL)]
#[case::empty_denied_by_a_one_entry_denylist_single_indexed("Empty NOT IN Denies[0]", Status::FAIL)]
// `IN` for the same spellings. The convention passes an empty left-hand side, three spellings already do,
// and the expanded one is the outlier that moves with the fix. If these disagree after a change, the
// vacuous match is being applied in one polarity only.
#[case::empty_in_written_out("Empty IN [1, 3]", Status::PASS)]
#[case::empty_in_unexpanded("Empty IN D13", Status::PASS)]
#[case::empty_in_right_expanded("Empty IN D13[*]", Status::PASS)]
#[case::empty_in_a_nested_entry_right_expanded("Empty IN Dn9[*]", Status::PASS)]
// THE MIRROR. Empty and not a list, so no vacuous subset reading applies and PASS is correct. A fix that
// keyed on "looks empty" rather than on "is an empty list" reddens these.
#[case::an_empty_string_is_not_vacuously_denied("EmptyStr NOT IN D13[*]", Status::PASS)]
#[case::an_empty_string_is_not_vacuously_denied_unexpanded("EmptyStr NOT IN D13", Status::PASS)]
#[case::an_empty_map_is_not_vacuously_denied("EmptyMap NOT IN D13[*]", Status::PASS)]
#[case::an_empty_map_is_not_vacuously_denied_unexpanded("EmptyMap NOT IN D13", Status::PASS)]
// The other half of the mirror: a non-empty list still answers by what the denylist names.
#[case::a_non_empty_list_is_undenied_by_a_disjoint_denylist("Pair NOT IN D34[*]", Status::PASS)]
#[case::a_non_empty_list_is_denied_by_a_named_element("Pair NOT IN D13[*]", Status::FAIL)]
fn an_empty_left_hand_list_is_vacuously_in_every_spelling_of_a_denylist(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // `EmptyStr` and `EmptyMap` are the mirror values, not decoration: they are what separates "is an
    // empty list" from "looks empty". `Denies` holds exactly one entry so that `Denies[0]` and
    // `Denies[*]` deliver the same value, which is what makes the contrast with the unrepairable defect
    // measurable rather than asserted.
    const INPUT: &str = r#"
    {
        Empty: [],
        EmptyStr: "",
        EmptyMap: {},
        Pair: [1, 2],
        D13: [1, 3],
        D34: [3, 4],
        Dn9: [[9]],
        Denies: [[1, 3]]
    }
    "#;

    let rules = format!("rule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// The vacuous subset reading belongs to a right operand that denotes a SET, and a string does not.
///
/// Why this exists. `9bcf2053` gave the empty left-hand list a vacuous match at the top of the
/// right-hand loop with no test on the right operand, and licensed the omission with "there is no
/// reading of the right operand for this case to get wrong". That is true of a list-valued right
/// operand, which is the only shape its supporting argument examines, and false of a string. `IN`
/// against a string is substring containment, not set membership -- `found_in_string` and the
/// `(None, Some)` string arm exist for that relation alone -- and no subset reading applies to a
/// haystack. So the property-name and literal spellings of one question came apart: `Empty NOT IN Str`
/// exited 19 while `Empty NOT IN "abc"`, the same string written out, exited 0. The failing report read
/// `provided value [[]] did match expected value in [["abc"]]`, a match against a string nothing
/// compared.
///
/// Which of the two answers is right, and it is not a convention chosen here. `found_in_string` returns
/// `NoneFound` for an empty left-hand list on purpose, and the reason recorded above it is that this
/// keeps its existing answer -- `NOT IN` over nothing passes -- rather than adding a second vacuous
/// pass to the one `vacuous_comparison_notice` is already deprecating. That decision predates this
/// branch, the literal spelling has always delivered it, and these cells make the query spelling
/// deliver it too.
///
/// Where the boundary actually falls, measured against the literal spelling of each right-operand kind
/// rather than argued. A list literal denies an empty list, so every query spelling that resolves to a
/// list must too, and the `D13` cells of
/// `an_empty_left_hand_list_is_vacuously_in_every_spelling_of_a_denylist` are that. For the three
/// non-list kinds the literal spellings are here beside their query spellings:
///
/// ```text
///                       IN   NOT IN   mechanism
/// [1, 3]                 0     19     vacuous subset match
/// ["abc"]                0     19     vacuous subset match
/// [{"k": 1}]             0     19     vacuous subset match
/// "abc"                  0      0     string arm decomposes an empty list into no comparison at all
/// 5                     19     19     NotComparable, fails closed in both polarities
/// true                  19     19     NotComparable, fails closed in both polarities
/// 1.5                   19     19     NotComparable, fails closed in both polarities
/// null                  19     19     NotComparable, fails closed in both polarities
/// {"k": 1}              19     19     NotComparable, fails closed in both polarities
/// ```
///
/// So `NOT IN` against a map or a non-string scalar literal is 19, and the vacuous match makes the
/// query spelling AGREE with it. Those cells were never the regression, which is why `Map`, `Maps[*]`,
/// `Maps[0]`, `N` and `B` are FAIL here with their literals beside them: reverting them to the parent's
/// 0 would have re-opened a divergence rather than closed one.
///
/// The `NOT IN` column is the width of the fix; the `IN` column is not, and this doc used to claim
/// otherwise -- "only the string column disagrees, and only in the `NOT IN` polarity". Read the table
/// above down the `IN` column instead: a non-string scalar or a map literal is 19 there too, while the
/// vacuous match answers 0 for every query spelling of one, so `Empty IN Map` is 0 against a written-out
/// `{"k": 1}` at 19 and the same holds for `N`, `B`, `Flt` and `Nullv`. That divergence is the mirror of
/// the one this fix closed -- the same check, the other polarity -- and the reason nothing contradicted
/// the claim is that every cell here was a `NOT IN` cell. The `IN` cells below are that gap filled, and
/// `the_in_polarity_of_a_queried_scalar_right_operand_has_no_repair_in_this_arm` carries the proof that
/// it cannot be closed here rather than the assertion that it is fine.
///
/// Two `IN` columns, and only one of them is unfixable. The non-string kinds are the unfixable one, for the
/// reason that proof gives. The STRING kind's `IN` column was fixable all along and is fixed below: the two
/// candidate oracles for a query that resolves to a string disagree only in the `NOT IN` polarity -- `"abc"`
/// is 0 and `["abc"]` is 19 -- and agree at 0 on `IN`, so there is one answer to give and giving it costs
/// the entry-set reading nothing. Reading the `27383c98` impossibility as covering both polarities is what
/// left the `IN` polarity over-denied; the note on `an_empty_list_is_in_a_string` below has the mechanism.
///
/// That sentence said "eight cells over-denied" and the figure is retired rather than corrected, for the
/// reason `operators.rs` gives beside the skip: it counted a hand-authored population nobody named, its own
/// enumeration there lists seven spellings, and ten clauses were measured moving. What survives is the
/// predicate -- the skip moves no `NOT IN` cell at all -- because enlarging the population cannot falsify
/// it.
///
/// AND NO REPAIR CONFINED TO THIS ARM CAN SERVE BOTH STRING SPELLINGS, which is the construction
/// `27383c98` established and the reason `Strs[*]` sits in this table at PASS rather than being fixed
/// too. `Strs` is `["abc"]`, one entry, so `Strs[0]` and `Strs[*]` both resolve to the inner string
/// `String("abc")` at the same path `/Strs/0`, `Location` included, and `compare` receives one identical
/// `QueryResult` either way. The oracle owes them opposite verdicts. `Strs[0]` IS a single operand whose
/// value is the haystack, so its answer is the literal `"abc"`'s answer, PASS. `Strs[*]` names the entry
/// set `{"abc"}`, so its answer is the literal `["abc"]`'s answer, FAIL. Anything written at that site
/// moves both together, so at most one can be right, and the pair is in the table with
/// `Empty NOT IN Strs` -- FAIL, from the vacuous match, untouched -- so the disagreement is visible
/// without reading a comment.
///
/// `Strs[0]` versus `Strs[*]`, and this doc used to pair `Strs[*]` with `Str`. That pair does not carry
/// the argument: `Strs[*]` resolves at `/Strs/0` and `Str` at `/Str`, so a predicate over the path
/// separates them and nothing at the site has to move them together.
/// `the_string_pair_that_cannot_be_separated_is_the_index_and_wildcard_spellings` asserts the identity on
/// the `QueryResult` for the `[0]`/`[*]` pair and the difference for `Str`, which is where the claim
/// lives. `Str` is still the spelling whose answer is SERVED, for the reason below; it is just not the
/// spelling that makes the choice forced.
///
/// Which one we serve, and why that is not a coin flip. `Str` at 19 is an OVER-denial: it denies a
/// value nothing named and reports a match against a string no comparison examined. `Strs[*]` at 0 is
/// an under-denial of a convention `vacuous_comparison_notice` is deprecating anyway. The comment above
/// the collision arm in `operators.rs` already states that over-denial is the worse direction for a
/// policy tool, and `Str` at 0 is additionally the answer `found_in_string` documents and the parent
/// shipped. Both reasons point the same way.
///
/// Rejected: gating on `rhs_selected.len() > 1` as well, which would fix `Strs2[*]` -- a two-entry
/// string denylist -- while leaving `Strs[*]` at PASS. It buys one cell and makes the verdict depend on
/// how many entries the denylist happens to hold, so a rule would pass against a one-entry denylist and
/// fail against a two-entry one with nothing in the clause to explain it. `Strs2[*]` is here at PASS
/// rather than FAIL to record that this is a residual and not an oversight.
///
/// The `IN` polarity is here because the fix moves it too, and it is now fixed rather than recorded.
/// `Empty IN Str` was FAIL where `Empty IN "abc"` is PASS -- a divergence older than this branch,
/// measured at `27383c98` at exit 19 -- along with `Strs[0]`, `Strs[*]`, `Strs2[*]`, both
/// `Resources.*.Properties.Name` spellings and the mixed `Lists[*]`. Eight cells, every one an
/// over-denial: a policy tool reporting a violation of a denylist that examined nothing.
///
/// THIS ARM CAN REACH PASS/PASS, and the claim that it could not is what left them. That claim priced two
/// moves -- skipping the value gives PASS/FAIL, recording it gives FAIL/PASS -- and both are true. The
/// third move is to emit no result for the value at all, which is exactly what the `(None, Some)` string
/// arm does: it decomposes a list left-hand side into one `string_in` per element, so an EMPTY list
/// produces none and `EvalResult::Result(vec![])` passes both polarities. That is the mechanism this doc
/// already named as the fix while placing it in another arm; the two-query arm needed a fourth outcome for
/// a left-hand value, not a different verdict for one.
///
/// What it does NOT reach is the `NOT IN` half of the `Strs[0]`-versus-`Strs[*]` impossibility above,
/// because that one is real: those two spellings deliver one identical value and the two candidate oracles
/// owe it opposite verdicts in that polarity. They agree on `IN`, both at PASS, which is why the pair
/// blocks one polarity and not the other. `Empty NOT IN Strs[*]` is still the residual, still at PASS, and
/// still sitting beside `Empty NOT IN Strs` at FAIL.
#[rstest::rstest]
// THE REGRESSION. A string right operand, in every spelling that reaches the two-query arm. All PASS,
// which is what the written-out spelling below has always answered.
#[case::an_empty_list_is_not_vacuously_in_a_string("Empty NOT IN Str", Status::PASS)]
#[case::an_empty_list_is_not_vacuously_in_a_right_expanded_string_entry(
    "Empty NOT IN Strs[*]",
    Status::PASS
)]
#[case::an_empty_list_is_not_vacuously_in_a_single_indexed_string_entry(
    "Empty NOT IN Strs[0]",
    Status::PASS
)]
#[case::an_empty_list_is_not_vacuously_in_a_two_entry_right_expanded_string_denylist(
    "Empty NOT IN Strs2[*]",
    Status::PASS
)]
// The spelling that was always right, and the one the four above are made to agree with.
#[case::an_empty_list_is_not_vacuously_in_a_string_literal("Empty NOT IN \"abc\"", Status::PASS)]
// THE PAIR, and the residual. `Strs` is a list, so the vacuous match at the top of the right-hand loop
// answers it and denies; `Strs[*]` resolves to the entry `"abc"` and keeps the string answer. One of the
// two is wrong and nothing at that site can fix which.
//
// Two corrections to what this comment used to say, both measured. It said `Strs` "reaches
// `contained_in`'s list arm" -- it does not. Instrumenting that call site: `Empty NOT IN Strs` and
// `Empty IN Strs` make ZERO calls to `contained_in`, while `D13 NOT IN Strs` and `Strs2 NOT IN Strs`
// make one each, so the probe is shown to fire and the zero is a real absence rather than a dead
// counter. The check fires for any non-string right-hand result, a list included, so the denial comes
// from the vacuous match and never from `contained_in`. `operators.rs` said this all along and this
// comment contradicted it.
//
// And it named the wrong pair. `Strs[*]` and `Str` are NOT indistinguishable -- `Strs[*]` resolves at
// `/Strs/0` and `Str` at `/Str`, so a predicate over the path separates them. The pair that genuinely
// cannot be separated is `Strs[0]` versus `Strs[*]`, both `String("abc")` at `/Strs/0`, which is the
// same `[0]`-versus-`[*]` construction the `D1` and `OneKeyMap` proofs use.
// `the_string_pair_that_cannot_be_separated_is_the_index_and_wildcard_spellings` asserts both halves.
// The conclusion is unchanged; only the pair supporting it was wrong.
#[case::an_empty_list_is_vacuously_in_an_unexpanded_string_denylist(
    "Empty NOT IN Strs",
    Status::FAIL
)]
#[case::an_empty_list_is_vacuously_in_a_string_list_literal("Empty NOT IN [\"abc\"]", Status::FAIL)]
// A MAP RIGHT OPERAND WAS NOT THE REGRESSION, and its literal is the evidence. `Empty NOT IN {"k": 1}`
// is 19 because a list against a map is `contained_in`'s incomparable catch-all and `NotComparable`
// fails closed, so the vacuous match agrees with the written-out spelling here rather than diverging
// from it. Reverting these to the parent's PASS would have opened a divergence.
#[case::an_empty_list_is_vacuously_in_a_map("Empty NOT IN Map", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_map_literal("Empty NOT IN {\"k\": 1}", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_right_expanded_map_entry(
    "Empty NOT IN Maps[*]",
    Status::FAIL
)]
#[case::an_empty_list_is_vacuously_in_a_single_indexed_map_entry(
    "Empty NOT IN Maps[0]",
    Status::FAIL
)]
#[case::an_empty_list_is_vacuously_in_a_map_list_literal("Empty NOT IN [{\"k\": 1}]", Status::FAIL)]
// A NON-STRING SCALAR RIGHT OPERAND, same story and the same evidence: `5` and `true` written out are
// both 19, so the query spellings agree with them.
#[case::an_empty_list_is_vacuously_in_an_int("Empty NOT IN N", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_an_int_literal("Empty NOT IN 5", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_bool("Empty NOT IN B", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_bool_literal("Empty NOT IN true", Status::FAIL)]
// THE `IN` POLARITY. All four PASS, and the first two were FAIL: the string exclusion kept the empty list
// out of the vacuous match, which is right, and then recorded it as UNMATCHED, which is what diverged from
// the literal. A skipped pairing is now a skipped pairing -- no comparison, nothing reported, both
// polarities pass -- so these agree with `Empty IN "abc"` beside them.
//
// `Strs[0]` is here as well, because it is the other half of the pair the `NOT IN` impossibility is built
// on: both readings of it owe PASS on `IN`, so the impossibility does not reach this polarity and the cell
// is fixable where its `NOT IN` sibling is not.
#[case::an_empty_list_is_in_a_string("Empty IN Str", Status::PASS)]
#[case::an_empty_list_is_in_a_right_expanded_string_entry("Empty IN Strs[*]", Status::PASS)]
#[case::an_empty_list_is_in_a_single_indexed_string_entry("Empty IN Strs[0]", Status::PASS)]
#[case::an_empty_list_is_in_a_string_literal("Empty IN \"abc\"", Status::PASS)]
#[case::an_empty_list_is_in_an_unexpanded_string_denylist("Empty IN Strs", Status::PASS)]
// The list control, so a change credited with the string cells has not moved the shape the vacuous
// match is actually for.
#[case::an_empty_list_is_vacuously_in_a_right_expanded_int_denylist(
    "Empty NOT IN D13[*]",
    Status::FAIL
)]
#[case::an_empty_list_is_in_a_right_expanded_int_denylist("Empty IN D13[*]", Status::PASS)]
// THE `IN` POLARITY OF THE NON-STRING KINDS, which had no cell at all before and is where the
// divergence this table's doc used to deny actually lives. Every query spelling is PASS and every
// written-out spelling beside it is FAIL, because the vacuous match answers `IN` with a match while the
// literal reaches `NotComparable` and fails closed. Each pair is a divergence, none is closable in this
// arm, and `the_in_polarity_of_a_queried_scalar_right_operand_has_no_repair_in_this_arm` is the proof.
//
// Pinned at the answer the code gives rather than the answer the literal owes, so that a repair which
// moves them has to move them here and say so, and so that the two candidate repairs measured in that
// test cannot land silently: both turn every PASS in this block FAIL.
//
// That guarantee was overstated until the `MixedRev[*]` cell below was added. It held of the cells present
// and not in general: at `b8d3901e` this file held no `IN` cell for `MixedRev` in any spelling, so
// `Empty IN MixedRev[*]` moved 0 to 19 under BOTH candidate repairs with nothing to observe it.
//
// The evidence used to be stated as "`MixedRev` appeared four times in this file and every occurrence was a
// `NOT IN` cell", and that conflated grep hits with cells. Four occurrences is right; one of them is a cell.
// At `b8d3901e` they are line 9999, a row in a prose table; 10012, the cell `"Empty NOT IN MixedRev[*]"`;
// 10040, a prose sentence; and 10058, the data-document field `MixedRev: [5, "abc"],`. The conclusion is
// unaffected and is in fact stronger than the evidence it was resting on -- one `NOT IN` cell and no `IN`
// cell is a wider gap than four `NOT IN` cells would have been.
// A block that pins every PASS it happens to contain still lets a repair land silently through the
// spelling it does not contain, which is the same authored-population blind spot the count in that test
// fell into. With the cell added the claim is true as written.
#[case::an_empty_list_is_in_a_map("Empty IN Map", Status::PASS)]
#[case::an_empty_list_is_not_in_a_map_literal("Empty IN {\"k\": 1}", Status::FAIL)]
#[case::an_empty_list_is_in_a_right_expanded_map_entry("Empty IN Maps[*]", Status::PASS)]
#[case::an_empty_list_is_in_a_single_indexed_map_entry("Empty IN Maps[0]", Status::PASS)]
// The map kind's own list literal, which is 0 and so agrees with the two spellings above it. Only the
// bare `{"k": 1}` disagrees, which is what makes this a `[0]`-versus-`[*]` split rather than a kind that
// is simply wrong.
#[case::an_empty_list_is_in_a_map_list_literal("Empty IN [{\"k\": 1}]", Status::PASS)]
#[case::an_empty_list_is_in_an_int("Empty IN N", Status::PASS)]
#[case::an_empty_list_is_not_in_an_int_literal("Empty IN 5", Status::FAIL)]
#[case::an_empty_list_is_in_a_bool("Empty IN B", Status::PASS)]
#[case::an_empty_list_is_not_in_a_bool_literal("Empty IN true", Status::FAIL)]
#[case::an_empty_list_is_in_a_float("Empty IN Flt", Status::PASS)]
#[case::an_empty_list_is_not_in_a_float_literal("Empty IN 1.5", Status::FAIL)]
#[case::an_empty_list_is_in_a_null("Empty IN Nullv", Status::PASS)]
#[case::an_empty_list_is_not_in_a_null_literal("Empty IN null", Status::FAIL)]
// The float and null `NOT IN` cells, which the int and bool rows above already have. These two kinds
// agree with their literals in this polarity exactly as `N` and `B` do, so a repair cannot claim the
// vacuous match is wrong for a float or a null without moving a cell that is right.
#[case::an_empty_list_is_vacuously_in_a_float("Empty NOT IN Flt", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_float_literal("Empty NOT IN 1.5", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_null("Empty NOT IN Nullv", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_null_literal("Empty NOT IN null", Status::FAIL)]
// THE ELEMENT-COMPOSITION DEPENDENCE, which is the residual stated as a measurement instead of as a
// footnote. `Strs2[*]` and `Mixed[*]` are both `[*]` expansions of a two-entry list, so neither is a
// query-versus-literal divergence of the kind the rest of this table is about; the spelling class is the
// same and only the element kinds differ. Their written-out spellings are both FAIL. They answer
// differently anyway, because the check fires for a right-hand result that is not a string and
// `Mixed` holds one:
//
//     Strs2[*]   ["abc", "zzz"]   PASS   literal FAIL   <- the residual
//     Mixed[*]   ["abc", 5]       FAIL   literal FAIL
//     MixedRev[*] [5, "abc"]      FAIL   literal FAIL
//
// So the denylist's element kinds decide the verdict with nothing in the clause to explain it, and
// `Strs2[*]` is the cell that is wrong. It is not repairable here: the only thing separating `Strs2[*]`
// from `Strs[*]` is that it holds two entries rather than one, `Strs[*]` is indistinguishable from
// `Strs[0]`, and `a_multi_candidate_string_query_is_not_an_entry_set` measures what keying on the entry
// count costs.
#[case::an_empty_list_is_vacuously_in_a_mixed_kind_entry_set("Empty NOT IN Mixed[*]", Status::FAIL)]
#[case::an_empty_list_is_vacuously_in_a_mixed_kind_list_literal(
    "Empty NOT IN [\"abc\", 5]",
    Status::FAIL
)]
#[case::an_empty_list_is_vacuously_in_a_non_string_first_mixed_entry_set(
    "Empty NOT IN MixedRev[*]",
    Status::FAIL
)]
#[case::an_empty_list_is_vacuously_in_a_non_string_first_mixed_list_literal(
    "Empty NOT IN [5, \"abc\"]",
    Status::FAIL
)]
#[case::an_empty_list_is_in_a_mixed_kind_entry_set("Empty IN Mixed[*]", Status::PASS)]
// The `IN` polarity of the reversed mixed order, which had no cell in this file at all. At `b8d3901e` the
// only `MixedRev` cell anywhere was
// `an_empty_list_is_vacuously_in_a_non_string_first_mixed_entry_set` -- the claim here used to be "appeared
// four times and every one was `NOT IN`", which counted grep hits rather than cells; three of the four are
// prose and data. So `Empty IN MixedRev[*]` was free to move: it goes 0 to
// 19 under both candidate repairs measured in
// `the_in_polarity_of_a_queried_scalar_right_operand_has_no_repair_in_this_arm` while its literal
// `[5, "abc"]` stays 0, and it is one of the twelve losses that repair's price used to omit. Here so that
// the block's "no repair lands silently" guarantee covers the spelling it was missing.
#[case::an_empty_list_is_in_a_non_string_first_mixed_entry_set(
    "Empty IN MixedRev[*]",
    Status::PASS
)]
#[case::an_empty_list_is_in_a_non_string_first_mixed_list_literal(
    "Empty IN [5, \"abc\"]",
    Status::PASS
)]
// The all-string two-entry expansion in the `IN` polarity, PASS and agreeing with its literal. It was FAIL
// -- the string column's own `IN` divergence -- and the note on `an_empty_list_is_in_a_string` above has
// how giving this arm the `(None, Some)` arm's no-comparison outcome closed it.
#[case::an_empty_list_is_in_a_two_entry_right_expanded_string_denylist(
    "Empty IN Strs2[*]",
    Status::PASS
)]
fn the_vacuous_subset_reading_belongs_to_a_right_operand_that_denotes_a_set(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // `Strs` holds exactly one entry so that `Strs[0]` and `Strs[*]` deliver one identical `QueryResult`,
    // which is what makes the impossibility measurable rather than asserted. Not `Str` against either of
    // them: `Str` resolves at `/Str` and both bracketed spellings at `/Strs/0`, so that pairing is
    // separable and would prove nothing. `Strs2` holds two so that the rejected arity-keyed repair has a
    // cell it would move. `Maps` mirrors `Strs` for the map kind, where the literal spelling turns out to
    // agree and no impossibility arises.
    //
    // `Flt` and `Nullv` are here because the `IN` cells below need every non-string scalar kind the
    // literal table lists, and a float and a null reach `NotComparable` by the same route an int and a
    // bool do -- so a repair that special-cased two of the four kinds would pass a shorter table.
    //
    // `Mixed` and `MixedRev` are the mixed-kind entry sets, in both orders. They are what makes the
    // element-composition dependence measurable: `Mixed[*]` and `Strs2[*]` are both `[*]` expansions of
    // a two-entry list and both written-out spellings are 19, yet they answer differently because one
    // holds a non-string. Both orders, because the check reads one right-hand result at a time and an
    // order-dependent version of it would answer by whichever kind the loop reached first.
    const INPUT: &str = r#"
    {
        Empty: [],
        Str: "abc",
        Strs: ["abc"],
        Strs2: ["abc", "zzz"],
        Map: {"k": 1},
        Maps: [{"k": 1}],
        N: 5,
        B: true,
        Flt: 1.5,
        Nullv: null,
        Mixed: ["abc", 5],
        MixedRev: [5, "abc"],
        D13: [1, 3]
    }
    "#;

    let rules = format!("rule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// The `IN` polarity of a queried non-list right operand cannot be repaired in `InOperation::compare`.
///
/// The vacuous match makes `Empty IN Map` exit 0 where the written-out `Empty IN {"k": 1}` exits 19, and
/// the same holds for `N`, `B`, `Flt` and `Nullv`. That is the mirror of the divergence the check closed:
/// one check, two polarities, and only the `NOT IN` one was ever measured, because
/// `the_vacuous_subset_reading_belongs_to_a_right_operand_that_denotes_a_set` held nine `NOT IN` cells
/// for the map, int and bool kinds and no `IN` cell for any of them. Its doc stated the narrower claim
/// outright -- "only the string column disagrees, and only in the `NOT IN` polarity" -- so the gap was
/// asserted closed rather than left unexamined.
///
/// THE PROOF, by the construction `27383c98` established and `9bcf2053` reused. `D1` is `[5]`, one entry,
/// so cardinality cannot discriminate. `D1[0]` and `D1[*]` resolve to the same single `Int(5)` at the
/// same path `/D1/0`, and `compare` receives one identical `QueryResult` either way -- the access
/// expression that separates them is consumed by `binary_operation` before any comparator is called. No
/// predicate over the value, the kind or the path can tell them apart.
///
/// The oracle owes them opposite verdicts on `IN`. `D1[0]` is a single right-hand operand whose value IS
/// the entry, so it answers as the literal `5` does: FAIL. `D1[*]` names the entry set, whose written
/// form is `[5]`, so it answers as `Empty IN [5]` does: PASS. At most one can be right, and anything
/// written at that site moves both together.
///
/// WHY `NOT IN` WAS REPAIRABLE AND THIS IS NOT, which is the whole asymmetry and is visible in the cells
/// below rather than argued. `Empty NOT IN 5` and `Empty NOT IN [5]` are BOTH 19 -- the first because
/// `NotComparable` fails closed, the second because the vacuous match negates -- so the two spellings
/// agree in that polarity and one answer serves both. On `IN` they disagree, 19 against 0, because
/// `NotComparable` still fails closed while a vacuous match passes. The scalar and the singleton-list
/// readings of one value coincide on `NOT IN` and diverge on `IN`, so the repair was available in exactly
/// the polarity it was made in.
///
/// WHICH SIDE IS SERVED, and it is not a coin flip. The code serves the `[*]` reading: every query
/// spelling of a non-list right operand answers `IN` with a match. Two repairs that serve the other side
/// were built and measured, and both cost more than they buy.
///
/// Firing only for a list-valued right-hand result reddens 27 rstest cells at `b8d3901e` -- measured, and
/// this doc said 21 -- and is a revert rather than a repair.
/// A `[*]` over a scalar denylist resolves to scalars, so the check becomes a no-op for exactly the shape
/// it exists for: `Empty NOT IN D13[*]` returns to 0, re-opening the defect `9bcf2053` closed, and
/// `Empty NOT IN Map`, `N` and `B` fall to 0 where their literals are 19. It does bring `Empty IN Map`,
/// `N`, `B`, `Flt`, `Nullv` and `D1[0]` to 19, and it takes `Empty IN D13[*]`, `D1[*]`, `Maps[*]` and
/// `Mixed[*]` to 19 where their list literals are 0.
///
/// Recording the pairing as unanswerable and letting `NotComparable` fail closed in both polarities is
/// the better of the two and is still wrong. It is surgical -- every cell it moves is an `IN` cell and no
/// `NOT IN` cell moves at all, so the whole `NOT IN` column the previous repair delivered survives. It
/// brings `Empty IN Map`, `Maps[0]`, `N`, `B`, `Flt`, `Nullv` and `D1[0]` to the 19 their literals owe,
/// and takes THIRTEEN the other way. Five are in the two tables this doc had in view -- `Empty IN Strs`,
/// `D13[*]`, `D1[*]`, `Maps[*]` and `Mixed[*]`, from 0 to 19 where their list literals are 0. Seven more
/// are `Empty IN` cells pinned at PASS elsewhere: cases 12, 13 and 14 of
/// `an_empty_left_hand_list_is_vacuously_in_every_spelling_of_a_denylist` and cases 73 through 76 of
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names`. The thirteenth had no cell anywhere
/// -- `Empty IN MixedRev[*]`, which is why the suite showed only 19 red cells at `b8d3901e` for a repair
/// that moves 20 things. Seven right for thirteen wrong, so it
/// loses on count AND on direction rather than winning narrowly on one, and the comment above the
/// collision arm in
/// `operators.rs` records over-denial as the worse direction for a policy tool. `SomeList IN Allowed[*]`
/// is the ordinary allowlist spelling, so under that repair every allowlist rule starts reporting a
/// violation whenever the list it checks is empty, while the cells it fixes are comparisons of a list
/// against a map, an int or a null that no rule author writes on purpose. `Empty IN D13[*]` is also the
/// list control in the table above, whose stated job is to catch a change credited with one kind that
/// moved the shape the vacuous match is actually for.
///
/// `Empty IN Strs` is in that loss list because this check fires for ANY non-string right-hand result,
/// a list included, so an unexpanded list denylist is answered here and never reaches `contained_in`'s
/// list arm at all -- instrumented at that call site, `Empty IN Strs` and `Empty NOT IN Strs` make zero
/// calls to `contained_in`, while `D13 NOT IN Strs` and `Strs2 NOT IN Strs` make one each, so the zero is
/// a measured absence rather than a counter that never fired.
///
/// THE METHOD THIS PARAGRAPH USED TO RECOMMEND IS WHAT PRODUCED THE WRONG NUMBER, and that is the part
/// worth keeping. It said counting the losses "needs the test cells rather than a sweep of clause exit
/// codes", after a 47-clause CLI sweep had put the loss at four. Cells were then counted -- over the two
/// tables in view, which gave five. The true figure is twelve. Cells exist only where somebody wrote one,
/// so a count over them is short by however many nobody wrote, and `Empty IN MixedRev[*]` is the proof:
/// it goes 0 to 19 under this repair while its literal `[5, "abc"]` stays 0, and at `b8d3901e` this file
/// held exactly one `MixedRev` cell and it was `NOT IN`, so nothing could observe it. A clause sweep has the
/// opposite blind spot -- it misses nothing unauthored -- and neither method alone is sound.
///
/// That last count was itself an instance of the trap, which is worth naming inside the paragraph that
/// names the trap. It read "all four of `MixedRev`'s occurrences in this file were `NOT IN` cells". Four is
/// the number of grep hits, not of cells: at `b8d3901e` one hit is the cell, and the other three are a row
/// in a prose table, a prose sentence, and the data-document field the cells query. Counting matches for an
/// identifier and reporting the total as a population of cells is the same substitution of a convenient
/// population for the real one that this paragraph is about.
///
/// WHICH SHAPE OF FIGURE IS SAFE. A count over a hand-authored cell population is not a property of the
/// code; it moves when someone writes another cell. A PREDICATE over the moved set is: "every cell it
/// moves is an `IN` cell" cannot be falsified by enlarging the population, which is why that claim above
/// survived this correction and both counts beside it did not. At this commit the same repair reddens 22
/// cells rather than 19 -- eight gains and fourteen losses -- because the `OneKeyMap` pair added one of
/// each and the `MixedRev[*]` cell made the previously invisible thirteenth loss observable. The code did
/// not change between those two figures; only the population did. A count over a CLOSED population is safe, the
/// way `3fe2c62d` counts two of 28: seven non-empty subsets of {undecided, decided-no, decided-yes} times
/// two quantifiers times two roles, computed inside the test rather than authored one cell at a time. So
/// the trap is not counting cells; it is counting over a hand-authored population while claiming a
/// property of the code. Prefer a predicate, else a closed population, else a named clause sweep.
///
/// It is additionally the answer `Pair NOT IN Denies[0]` already rules out for this arm: `unanswerable`
/// is honest when the information is missing from the question and a dodge when it is missing from the
/// call. Here the oracle fixes a definite verdict for both members of the pair from the operand values,
/// and one of them is a PASS, so reporting undecidable asserts that a decided question has no answer.
///
/// So the residual is `Empty IN D1[0]` and every bare-field and `[0]` spelling like it, pinned in the
/// table above at the answer the code gives. What would close it is the same thing the `Denies[0]` proof
/// asks for and no local change supplies: the access expression surviving into the comparator, so that a
/// value reached by `[0]` can be told from the same value reached by `[*]`.
///
/// THE `D1` PAIR ALONE DOES NOT ESTABLISH THAT RESIDUAL, and the sentence above claimed it did. Both
/// `D1[0]` and `D1[*]` resolve at `/D1/0`, so both paths end in a numeric index, and a predicate keyed on
/// that -- "the last path segment is a digit" -- treats the pair alike and escapes it. Under that
/// predicate the five cells this proof prices as the `unanswerable` repair's cost move on their own:
/// `Empty IN Map`, `N`, `B`, `Flt` and `Nullv` resolve at `/Map`, `/N`, `/B`, `/Flt` and `/Nullv` and
/// would reach the 19 their literals owe, while `D1[*]`, `D13[*]`, `Maps[*]` and `Strs` keep their PASS.
/// So "every bare-field and `[0]` spelling like it" asserted coverage the pair does not provide.
///
/// `OneKeyMap` of `{"Inner": 5}` provides it, and the four cells below carry it. `OneKeyMap.Inner` and
/// `OneKeyMap.*` resolve to one identical `Int(5)` at one identical `/OneKeyMap/Inner` -- no digit in
/// either path -- and owe opposite verdicts by this proof's own construction: the named spelling IS the
/// operand and answers as `5` does, 19; the expanded one names the entry set `{5}` and answers as `[5]`
/// does, 0. `a_digit_free_query_pair_resolves_identically_and_forecloses_a_path_shaped_repair` asserts
/// the identity on the `QueryResult` rather than on the verdicts, which is where the claim lives.
#[rstest::rstest]
// THE PAIR. Identical value, identical path, one `QueryResult`, opposite owed verdicts. `D1[0]` owes
// FAIL and gets PASS; `D1[*]` owes PASS and gets it.
#[case::a_single_indexed_int_entry_is_vacuously_matched_by_an_empty_list(
    "Empty IN D1[0]",
    Status::PASS
)]
#[case::a_right_expanded_int_entry_is_vacuously_matched_by_an_empty_list(
    "Empty IN D1[*]",
    Status::PASS
)]
// The two oracles the pair is owed to, which disagree. This is the cell that makes the impossibility a
// measurement: with these two equal there would be one answer to give and no trade.
#[case::an_empty_list_is_not_in_a_bare_int_literal("Empty IN 5", Status::FAIL)]
#[case::an_empty_list_is_in_a_one_entry_int_list_literal("Empty IN [5]", Status::PASS)]
// THE SAME FOUR SPELLINGS IN THE POLARITY THAT AGREES, which is why the repair was possible there. All
// four are FAIL, so the pair has one answer and both members get it.
#[case::a_single_indexed_int_entry_vacuously_denies_an_empty_list(
    "Empty NOT IN D1[0]",
    Status::FAIL
)]
#[case::a_right_expanded_int_entry_vacuously_denies_an_empty_list(
    "Empty NOT IN D1[*]",
    Status::FAIL
)]
#[case::a_bare_int_literal_denies_an_empty_list_closed("Empty NOT IN 5", Status::FAIL)]
#[case::a_one_entry_int_list_literal_vacuously_denies_an_empty_list(
    "Empty NOT IN [5]",
    Status::FAIL
)]
// THE DIGIT-FREE PAIR, which forecloses the path-shaped repair the `D1` pair leaves open. Same
// construction, same owed verdicts, and neither path ends in an index: `OneKeyMap.Inner` owes FAIL and
// gets PASS, `OneKeyMap.*` owes PASS and gets it. A repair that moved `Empty IN Map` by path shape moves
// the second of these with it.
#[case::a_named_map_entry_is_vacuously_matched_by_an_empty_list(
    "Empty IN OneKeyMap.Inner",
    Status::PASS
)]
#[case::a_wildcard_map_entry_is_vacuously_matched_by_an_empty_list(
    "Empty IN OneKeyMap.*",
    Status::PASS
)]
// The same two spellings in the polarity that agrees, so this pair carries the asymmetry the `D1` pair
// does rather than only half of it.
#[case::a_named_map_entry_vacuously_denies_an_empty_list(
    "Empty NOT IN OneKeyMap.Inner",
    Status::FAIL
)]
#[case::a_wildcard_map_entry_vacuously_denies_an_empty_list(
    "Empty NOT IN OneKeyMap.*",
    Status::FAIL
)]
fn the_in_polarity_of_a_queried_scalar_right_operand_has_no_repair_in_this_arm(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // One entry, so `D1[0]` and `D1[*]` deliver the same value at the same path and neither the value
    // nor the count nor the path can separate them. A two-entry denylist would let a repair discriminate
    // on cardinality and would prove nothing.
    //
    // `OneKeyMap` is the same construction with the numeric index removed from both paths, which is what
    // the `D1` pair cannot supply: a map key reached by name and the same key reached by `*` resolve at
    // `/OneKeyMap/Inner` either way. One key for the same reason `D1` holds one entry.
    const INPUT: &str = r#"
    {
        Empty: [],
        D1: [5],
        OneKeyMap: {"Inner": 5}
    }
    "#;

    let rules = format!("rule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// An uncompared empty list does not silence the siblings that WERE compared.
///
/// Why this exists: the repair that makes `Empty IN Str` agree with `Empty IN "abc"` works by emitting no
/// result for a left-hand value that no right-hand result was compared against. The aggregate `QueryIn`
/// this arm folds every left-hand value into decides Success from `diff.is_empty()`, which cannot tell
/// "everything matched" from "nothing was asked", so the aggregate has to be suppressed as well -- and the
/// condition for suppressing it is the one thing in that repair with a price.
///
/// `no_comparison == lhs_selected.len()` is the condition, and `> 0` is the wrong version of it. `Lists` of
/// `[[], ["abc"]]` separates them: the empty entry is uncompared and the `["abc"]` entry is contained in
/// the haystack verbatim, so the clause has a real match to report and `NOT IN` must deny. Under `> 0` the
/// whole aggregate disappears and the clause passes -- measured, `Lists[*] NOT IN Str` goes from 19 to 0
/// while `Lists[*] NOT IN "abc"` stays at 19 beside it. That is a denylist admitting a value it names, the
/// defect class this whole region exists to close, reintroduced by the repair for it.
///
/// Both orders, because `lhs_selected` is walked in query order and a condition that happened to be right
/// only when the empty entry came first would pass a one-order table. `ListsRev` is `[["abc"], []]`.
///
/// The `IN` cells are here because they are what the repair is for and they must move together with
/// nothing else: both spellings PASS, agreeing with their literals, where before the repair both were FAIL.
///
/// # The sibling that MATCHES could not catch the defect this test is named for
///
/// `Lists` holds `["abc"]` against a `Str` of `"abc"` -- a sibling that is CONTAINED. So `diff` comes out
/// empty, `lhs_unmatched` comes out empty, and the negation wrapper's `lhs \ lhs_unmatched` returns all of
/// `lhs` whether or not the uncompared value was removed from it. Every cell here passed against a build
/// that withheld the value from `diff` and left it in `lhs`, which is the actual defect: `QueryIn` carries
/// both sets, the wrapper derives "collided" from their difference, and a value missing from one and
/// present in the other reads as MATCHED. Seventeen `NOT IN` cells over-denied silently on that build and
/// this table was green for all of them. It gave the right answer for the wrong reason.
///
/// `Mismatch` is the shape that discriminates: `[[], ["zzz"]]` against `"abc"`, one uncompared entry and one
/// entry that IS compared and does NOT match. Now `diff` holds `["zzz"]`, so `lhs_unmatched` is non-empty,
/// and `lhs \ lhs_unmatched` is exactly the leftover uncompared value -- non-empty, read as a collision,
/// `NOT IN` denies. `Mismatch[*] NOT IN Str` was 19 on that build with `Mismatch[*] NOT IN "abc"` at 0
/// beside it, and the report named `[[]]` as having matched `[["abc"]]`.
///
/// One right-hand string the sibling does not contain is the whole difference between a table that can see
/// this class and one that cannot. `Zstr` is `"zzz"`, which `Lists`'s own `["abc"]` sibling does not contain,
/// so it discriminates for the `Lists` fixture too and both fixtures carry the shape.
#[rstest::rstest]
// THE GUARD THAT DISCRIMINATES: one uncompared value, one sibling compared that does NOT match. The
// uncompared value must not be reported as a match, so `NOT IN` must PASS -- these are FAIL on a build that
// removes it from `diff` alone.
#[case::an_unmatched_sibling_does_not_make_the_uncompared_value_a_match(
    "Mismatch[*] NOT IN Str",
    Status::PASS
)]
#[case::an_unmatched_sibling_does_not_make_the_uncompared_value_a_match_reversed(
    "MismatchRev[*] NOT IN Str",
    Status::PASS
)]
// Their literals, which is what those two are made to agree with.
#[case::an_unmatched_sibling_written_out("Mismatch[*] NOT IN \"abc\"", Status::PASS)]
#[case::an_unmatched_sibling_written_out_reversed("MismatchRev[*] NOT IN \"abc\"", Status::PASS)]
// The same shape reached from the OTHER fixture, by naming a string its sibling does not contain. This is
// the one-line change that would have caught the defect in the original table.
#[case::a_matched_fixture_against_a_string_it_does_not_contain(
    "Lists[*] NOT IN Zstr",
    Status::PASS
)]
#[case::a_matched_fixture_against_a_string_it_does_not_contain_written_out(
    "Lists[*] NOT IN \"zzz\"",
    Status::PASS
)]
// And the `IN` polarity of the discriminating shape, so a repair cannot move one polarity only.
#[case::an_unmatched_sibling_fails_in("Mismatch[*] IN Str", Status::FAIL)]
#[case::an_unmatched_sibling_fails_in_written_out("Mismatch[*] IN \"abc\"", Status::FAIL)]
// THE GUARD. One uncompared value, one matched sibling: the match is reported and `NOT IN` denies. Kept
// because it pins the opposite verdict for the opposite sibling, but it cannot see the wrapper defect --
// see the note above.
#[case::a_matched_sibling_still_denies("Lists[*] NOT IN Str", Status::FAIL)]
#[case::a_matched_sibling_still_denies_reversed("ListsRev[*] NOT IN Str", Status::FAIL)]
// The literals the two above are made to agree with.
#[case::a_matched_sibling_still_denies_written_out("Lists[*] NOT IN \"abc\"", Status::FAIL)]
#[case::a_matched_sibling_still_denies_written_out_reversed(
    "ListsRev[*] NOT IN \"abc\"",
    Status::FAIL
)]
// THE REPAIR. The uncompared value no longer counts as unmatched, so `IN` passes as its literal does.
#[case::an_uncompared_value_does_not_fail_in("Lists[*] IN Str", Status::PASS)]
#[case::an_uncompared_value_does_not_fail_in_reversed("ListsRev[*] IN Str", Status::PASS)]
#[case::an_uncompared_value_does_not_fail_in_written_out("Lists[*] IN \"abc\"", Status::PASS)]
#[case::an_uncompared_value_does_not_fail_in_written_out_reversed(
    "ListsRev[*] IN \"abc\"",
    Status::PASS
)]
// The all-uncompared case, which is the one the suppression is FOR: every left-hand value is an empty list
// against a string, so nothing was asked and both polarities pass exactly as the literal does.
#[case::every_value_uncompared_passes_in("Empties[*] IN Str", Status::PASS)]
#[case::every_value_uncompared_passes_not_in("Empties[*] NOT IN Str", Status::PASS)]
#[case::every_value_uncompared_passes_in_written_out("Empties[*] IN \"abc\"", Status::PASS)]
#[case::every_value_uncompared_passes_not_in_written_out("Empties[*] NOT IN \"abc\"", Status::PASS)]
// The non-string control, so a change credited with these cells has not touched the vacuous match itself.
// A non-string right operand still takes an empty list through the match, in both spellings.
#[case::a_matched_sibling_against_an_int_denylist("Lists[*] NOT IN D13[*]", Status::FAIL)]
#[case::every_value_uncompared_against_an_int_denylist("Empties[*] NOT IN D13[*]", Status::FAIL)]
fn an_uncompared_empty_list_does_not_silence_its_siblings(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // `Lists` and `ListsRev` are the same two entries in both orders. `Empties` is the all-uncompared
    // shape, two empty lists, which is what distinguishes suppressing the aggregate from dropping it
    // whenever anything was skipped.
    //
    // `Mismatch` and `MismatchRev` are the shape that discriminates the wrapper defect: the sibling is
    // `["zzz"]`, which `Str` does NOT contain, so the sibling reaches `diff` and leaves `lhs_unmatched`
    // non-empty. Only then does `lhs \ lhs_unmatched` expose an uncompared value still sitting in `lhs`.
    // With a contained sibling both sets come out empty and the difference is invisible, which is why the
    // original table passed against the buggy build.
    //
    // `Zstr` gives the `Lists` fixture the same discriminating power without a second fixture: a string
    // its `["abc"]` sibling does not contain.
    const INPUT: &str = r#"
    {
        Lists: [[], ["abc"]],
        ListsRev: [["abc"], []],
        Mismatch: [[], ["zzz"]],
        MismatchRev: [["zzz"], []],
        Empties: [[], []],
        Str: "abc",
        Zstr: "zzz",
        D13: [1, 3]
    }
    "#;

    let rules = format!("rule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// Every string spelling warns through the channel whose wording is true of it.
///
/// Why this exists: making the two-query arm skip a string pairing moved this family's deprecation notice
/// from `incomparable_membership_notice` to `vacuous_comparison_notice`, and
/// `an_empty_list_against_a_queried_string` in
/// `the_notice_asks_about_every_granularity_the_operator_decides_at` was pinned on the first of those. A
/// bare flip of that cell to `false` would assert only that one notice stopped, which is satisfied by the
/// clause going silent -- the outcome that would actually be a regression. This asserts the notice that is
/// emitted instead, across the whole family and in both polarities, so silence fails here.
///
/// Why the vacuous channel is the true one, and it is a statement about the mechanism rather than a
/// preference between two strings. `vacuous_comparison_notice` fires on `compared_nothing && all` -- a
/// comparison that produced no per-value result and answers PASS on the strength of it. That is precisely
/// what the skip creates, and precisely why the literal `Empty NOT IN "abc"` has always emitted it: the
/// `(None, Some)` string arm decomposes an empty list into no `string_in` calls. The membership wording,
/// "could not be compared with any element of the list", names an element comparison that does not happen
/// and a list that is never read -- there is no list on the right, only a haystack. It was accurate about
/// the OLD path, where `contained_in` refused on the shape pair `([], "abc")` and the arm dropped the
/// refusal. That path is gone, so the sentence describing it went with it.
///
/// Both polarities on every cell, because the notice gate gives `IN` and `NOT IN` different treatment
/// elsewhere -- it is suppressed under `some`, per the gate's own comment -- and the `IN` half is newly
/// PASSing here, so it is the half with no prior behavior to inherit. It gains a notice it never had: at
/// the parent these clauses exited 19 with no notice at all, which is a false report with no warning
/// attached rather than a true pass with one.
///
/// Every literal is here beside its query spellings, which is the same shape the verdict tables in this
/// file use: the claim is agreement with the literal, so the literal has to be measured in the same run
/// rather than trusted from a comment.
#[rstest::rstest]
// The bare field, and the spelling `the_notice_asks_about_every_granularity_the_operator_decides_at`
// carries as its moved cell.
#[case::a_queried_string_not_in("Empty NOT IN Ustr")]
#[case::a_queried_string_in("Empty IN Ustr")]
#[case::a_bare_string_field_not_in("Empty NOT IN Str")]
#[case::a_bare_string_field_in("Empty IN Str")]
// The two bracketed spellings, which resolve identically to each other.
#[case::a_single_indexed_string_entry_not_in("Empty NOT IN Strs[0]")]
#[case::a_single_indexed_string_entry_in("Empty IN Strs[0]")]
#[case::a_right_expanded_string_entry_not_in("Empty NOT IN Strs[*]")]
#[case::a_right_expanded_string_entry_in("Empty IN Strs[*]")]
// The two-entry expansion, so the family is not covered only at arity one.
#[case::a_two_entry_string_entry_set_not_in("Empty NOT IN Strs2[*]")]
#[case::a_two_entry_string_entry_set_in("Empty IN Strs2[*]")]
// The multi-candidate string query, which has no list anywhere in the operand.
#[case::a_multi_resource_string_query_not_in("Empty NOT IN Resources.*.Properties.Name")]
#[case::a_multi_resource_string_query_in("Empty IN Resources.*.Properties.Name")]
#[case::a_single_resource_string_query_not_in("Empty NOT IN OneRes.*.Properties.Name")]
#[case::a_single_resource_string_query_in("Empty IN OneRes.*.Properties.Name")]
// THE LITERALS the fourteen above are made to agree with. These emitted the vacuous notice before this
// branch and still do; they are the reference, not the thing under test.
#[case::a_string_literal_not_in("Empty NOT IN \"abc\"")]
#[case::a_string_literal_in("Empty IN \"abc\"")]
fn every_string_spelling_warns_through_the_channel_that_is_true_of_it(
    #[case] clause: &str,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Empty: [],
        Str: "abc",
        Ustr: "abc",
        Strs: ["abc"],
        Strs2: ["abc", "zzz"],
        Resources: {
            R1: { Properties: { Name: "abc" } },
            R2: { Properties: { Name: "zzz" } }
        },
        OneRes: {
            R1: { Properties: { Name: "abc" } }
        }
    }
    "#;

    let (status, notices) = status_and_deprecations(clause, INPUT)?;

    assert_eq!(
        Status::PASS,
        status,
        "`{}` must pass, as its literal does -- the notice claims are about a clause that PASSED without \
         comparing anything, so a FAIL here would make the rest of this cell meaningless",
        clause
    );

    assert!(
        notices
            .iter()
            .any(|notice| notice.contains("passed without comparing anything")),
        "`{}` must warn through the vacuous channel; silence is the regression this cell exists to \
         catch. Recorded {:?}",
        clause,
        notices
    );

    assert!(
        !membership_notice_present(&notices),
        "`{}` must not claim an element comparison it never made: there is no list on the right and no \
         element was read. Recorded {:?}",
        clause,
        notices
    );

    Ok(())
}

/// A pairing the operator skipped does not earn a sibling value a membership notice.
///
/// Why this exists: the test above asserts the suppression correctly and only over left operands whose
/// SOLE value is the empty list, so it holds on exactly the population where the stale condition in
/// `incomparable_membership` was harmless. `incomparable_membership` ORs `refused` over the whole
/// (value, element) cross product, so as soon as the empty list has a sibling the refusal it contributed
/// rides out on whichever pairing decided the clause. With `Mix` of `[[], "q"]` and `Ustr` of `"abc"`,
/// `Mix[*] NOT IN Ustr` exited 0 and printed "could not be compared with any element of the list" -- and
/// the value that decided it is `"q"` against `"abc"`, String against String, comparable, decided false.
/// The `[]` that produced the refusal was compared with nothing: at `69628df7` the operator's two-query
/// arm skips an empty left-hand list against every right-hand kind, incrementing `uncompared_pairings`
/// and continuing for a string and taking `continue 'each_lhs` otherwise, both before `contained_in` is
/// called. The condition still named the string as the operator's exclusion, so the predicate answered
/// `refused` for a pairing the operator never built.
///
/// Why the sibling has to be a plain string not present in the haystack, which is the whole reason this
/// shape is narrow. The notice gate also requires the clause to have passed, so the sibling has to be
/// compared, contribute no refusal of its own, and still let the clause pass. An int or a map sibling
/// refuses on its own pairing and the clause fails closed -- `Mix[*] NOT IN Uint` is exit 19 -- and a
/// sibling the haystack contains fails the clause on the match, so `MixHit[*] NOT IN Ustr` over
/// `[[], "abc"]` is exit 19 too. Both are suppressed by the verdict gate whatever this predicate answers,
/// which is why the family reached only through a sibling like `"q"`.
///
/// The `NoEmpty` cell is the discriminator and not decoration: it is the same clause with the empty list
/// dropped from the left operand, and it was silent before the fix while `Mix[*]` was not. That is what
/// attributes the notice to the skipped pairing rather than to anything about `"q"`.
///
/// The `expected = true` cells are the reason this cannot pass by the channel going quiet, and they cover
/// two different ways of going quiet because one cell does not cover both. A cell asserting only absence
/// is satisfied by a predicate that answers `false` for everything, so each of the three paths that can
/// set `refused` needs a cell that depends on it:
///
/// - `NoEmpty[*] NOT IN Uint` reaches the `(left, right)` catch-all. Its value is `"q"`, not a list, so it
///   never enters the arm this fix touches -- it is the cell that says the notice still exists at all.
/// - `Mix NOT IN Uint` is the same denylist UNEXPANDED, so its single value is the non-empty list
///   `[[], "q"]` and it enters this arm, but its refusal comes from the inner element loop via
///   `pair_refused("q", 7)` rather than from the shape refusal. It is the cell for that loop.
///
/// Widening the condition to "the left list MENTIONS an empty list" rather than "the value being paired IS
/// one" is NOT pinned here, and the reason is that it is not a distinguishable repair: measured across a
/// 210-clause grid of the mixed-left shapes it moves nothing this fix does not, because a value that is an
/// empty list is incomparable to any non-list right operand, so the inner loop refuses on it wherever the
/// shape refusal would have. Recorded so nobody adds a cell for a difference that cannot be observed.
/// - `Ints NOT IN Uint` over `[1, 2]` and `7` depends on the shape refusal itself and on nothing else.
///   Every element pair is Int against Int, which `pair_refused` answers, so the inner loop contributes
///   nothing and `refused` is true only because a non-empty list against a non-list is a shape
///   `contained_in` declines. Measured: disabling just the `if both_queried && !vacuous_match` assignment
///   leaves the other two cells green and reddens this one, so without it a blanket suppression of this
///   arm would pass the whole cell.
///
/// It passes rather than failing closed because the right operand is queried: the `(None, None)` arm drops
/// the `NotComparable` -- which is the reason this notice exists -- so the value joins the unmatched set
/// and `NOT IN` succeeds on a comparison that was never decided. `Ints NOT IN 7` written out is exit 19 on
/// the same two values.
#[rstest::rstest]
// THE DEFECT. An empty list beside a string sibling that decides the clause, in both element orders and
// at two sibling counts.
#[case::an_empty_list_beside_a_string_sibling("Mix[*] NOT IN Ustr", false)]
#[case::a_string_sibling_written_first("MixRev[*] NOT IN Ustr", false)]
#[case::an_empty_list_beside_two_string_siblings("MixTwoStr[*] NOT IN Ustr", false)]
// THE DISCRIMINATOR. The same clause with the empty list dropped, silent before the fix and after it.
#[case::the_same_clause_without_the_empty_list("NoEmpty[*] NOT IN Ustr", false)]
// THE CHANNEL STILL WORKS. A genuine incomparability with no empty list in the operand at all.
#[case::a_genuine_refusal_still_warns("NoEmpty[*] NOT IN Uint", true)]
// And the same denylist unexpanded, whose one value is a NON-empty list, so the shape refusal is owed and
// a fix keyed on "mentions an empty list" rather than "is one" reddens here.
#[case::a_non_empty_list_holding_an_empty_one_still_warns("Mix NOT IN Uint", true)]
// The cell that depends on the shape refusal and nothing else, so suppressing this arm wholesale cannot
// pass the table. Every element pair here is comparable; only the shape is not.
#[case::a_shape_refusal_with_no_refusing_element_still_warns("Ints NOT IN Uint", true)]
fn a_skipped_pairing_does_not_earn_a_sibling_a_membership_notice(
    #[case] clause: &str,
    #[case] expected: bool,
) -> Result<()> {
    // `Mix` and `MixRev` differ only in element order, because the predicate walks the cross product and
    // an order-sensitive version of it would answer by whichever pairing it reached first. `NoEmpty` is
    // `Mix` minus the empty list, so the two differ in exactly the thing under test.
    const INPUT: &str = r#"
    {
        Ustr: "abc",
        Uint: 7,
        Mix: [[], "q"],
        MixRev: ["q", []],
        MixTwoStr: [[], "q", "z"],
        NoEmpty: ["q"],
        Ints: [1, 2]
    }
    "#;

    let (status, notices) = status_and_deprecations(clause, INPUT)?;

    // Asserted, because the notice gate requires the clause to have passed: a FAIL here suppresses the
    // notice whatever the predicate answered, and the absence cells would then hold for the wrong reason.
    assert_eq!(
        Status::PASS,
        status,
        "`{}` must pass for the notice gate to be reached at all; a FAIL makes this cell vacuous",
        clause
    );

    let membership = notices
        .iter()
        .any(|notice| notice.contains("could not be compared with any element"));

    assert_eq!(
        expected,
        membership,
        "`{}` must {} the membership notice. Recorded {:?}",
        clause,
        if expected { "emit" } else { "not emit" },
        notices
    );

    Ok(())
}

/// Which two string spellings are actually inseparable, asserted on the resolution.
///
/// Why this exists: the string impossibility was written as "`Strs[*]` resolves to the same `"abc"` that
/// `Str` does and cannot be told apart from it" for several commits, and that pair does not carry the
/// argument. Same value, different path -- `/Strs/0` against `/Str` -- so a predicate over the path
/// separates them and nothing at the comparison site is forced to move them together. The conclusion was
/// right and its support was not, which is the same defect shape as the `D1` pair leaving a digit-keyed
/// repair open.
///
/// The pair that is inseparable is `Strs[0]` versus `Strs[*]`: one entry, so both resolve to
/// `String("abc")` at `/Strs/0` with the same `Location`, and the oracle owes them opposite verdicts on
/// `NOT IN` -- `Strs[0]` is an operand whose value is the haystack, answering as `"abc"` does at PASS,
/// while `Strs[*]` names the entry set, answering as `["abc"]` does at FAIL. That is the same
/// `[0]`-versus-`[*]` construction the `D1` and `OneKeyMap` proofs use.
///
/// Both halves are asserted, the identity and the difference. Asserting only the identity would leave the
/// wrong pair standing beside it, since a reader who checks the surviving `Str` sentence finds nothing
/// contradicting it.
#[test]
fn the_string_pair_that_cannot_be_separated_is_the_index_and_wildcard_spellings() -> Result<()> {
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        Str: "abc"
        Strs: ["abc"]
        "#,
    )?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    // Each query bound before it is walked: `AccessQuery::try_from(..)?.query` is a temporary, and the
    // results borrow from it.
    let indexed_query = AccessQuery::try_from("Strs[0]")?;
    let expanded_query = AccessQuery::try_from("Strs[*]")?;
    let bare_query = AccessQuery::try_from("Str")?;

    let mut resolved = Vec::new();
    for (spelling, query) in [
        ("Strs[0]", &indexed_query),
        ("Strs[*]", &expanded_query),
        ("Str", &bare_query),
    ] {
        let results = eval.query(&query.query)?;
        assert_eq!(1, results.len(), "`{}` must deliver one result", spelling);
        match &results[0] {
            QueryResult::Resolved(value) => resolved.push(Rc::clone(value)),
            other => panic!("`{}` must resolve; got {:?}", spelling, other),
        }
    }
    let (indexed, expanded, bare) = (&resolved[0], &resolved[1], &resolved[2]);

    assert_eq!(
        indexed.self_path(),
        expanded.self_path(),
        "`Strs[0]` and `Strs[*]` must reach `compare` at one path, `Location` included -- that is what \
         forces anything written at the site to move both together"
    );
    assert_eq!(
        indexed, expanded,
        "`Strs[0]` and `Strs[*]` must deliver one identical value"
    );

    assert_eq!(
        indexed, bare,
        "all three spellings do deliver the same string, which is why the wrong pair looked convincing"
    );
    assert_ne!(
        bare.self_path(),
        expanded.self_path(),
        "`Str` must NOT share a path with `Strs[*]`, or the discarded pairing would have been a valid \
         impossibility after all and this test would be asserting the opposite of its own doc"
    );

    Ok(())
}

/// The digit-free half of that pair, asserted on the resolution rather than on the verdict.
///
/// Why this exists: the impossibility above is carried by `D1[0]` and `D1[*]`, and BOTH of those paths
/// end in a numeric index. That leaves a predicate available -- "the last path segment is a digit" --
/// which treats the two members alike and so is not foreclosed by them, while separating them from the
/// five cells the proof cites to reject the `unanswerable` repair: `Empty IN Map`, `N`, `B`, `Flt` and
/// `Nullv` resolve at `/Map`, `/N`, `/B`, `/Flt` and `/Nullv`, no digit anywhere. So a repair keyed on
/// that predicate would bring exactly those five to the 19 their literals owe and leave `D1[*]`,
/// `D13[*]`, `Maps[*]` and `Strs` untouched, which is the whole cost the proof prices. The residual
/// sentence claimed coverage of "every bare-field and `[0]` spelling like it"; the pair does not
/// provide it.
///
/// `OneKeyMap` of `{"Inner": 5}` provides it. `OneKeyMap.Inner` and `OneKeyMap.*` resolve to one
/// identical `Int(5)` at one identical `/OneKeyMap/Inner`, `Location` included, with no trailing digit
/// for a path-shaped predicate to key on -- and the oracle owes them opposite verdicts by the same
/// construction as `D1`: `OneKeyMap.Inner` IS the operand, so it answers as `5` does, 19, and
/// `OneKeyMap.*` names the entry set `{5}`, so it answers as `[5]` does, 0. Any predicate over the
/// value, the kind or the path moves both together, so a repair that fixes `Empty IN Map` by path shape
/// breaks `Empty IN OneKeyMap.*`.
///
/// On the resolution and not only on the two verdicts, because the verdicts alone are satisfied by both
/// spellings being wrong for unrelated reasons. What makes this a proof is that `compare` cannot tell
/// the two calls apart, and that is a statement about the `QueryResult`, so it is asserted there.
#[test]
fn a_digit_free_query_pair_resolves_identically_and_forecloses_a_path_shaped_repair() -> Result<()>
{
    let path_value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(
        r#"
        OneKeyMap:
          Inner: 5
        "#,
    )?)?;

    let mut eval = BasicQueryTesting {
        root: Rc::new(path_value),
        recorder: None,
    };

    let named_query = AccessQuery::try_from("OneKeyMap.Inner")?;
    let expanded_query = AccessQuery::try_from("OneKeyMap.*")?;
    let named = eval.query(&named_query.query)?;
    let expanded = eval.query(&expanded_query.query)?;

    assert_eq!(1, named.len(), "the named spelling must deliver one result");
    assert_eq!(
        1,
        expanded.len(),
        "the expanded spelling must deliver one result, or cardinality would separate the pair"
    );

    let (named, expanded) = match (&named[0], &expanded[0]) {
        (QueryResult::Resolved(named), QueryResult::Resolved(expanded)) => (named, expanded),
        pair => panic!("both spellings must resolve; got {:?}", pair),
    };

    assert_eq!(
        named.self_path(),
        expanded.self_path(),
        "the two spellings must reach `compare` at one path, `Location` included, or a predicate over \
         the path could separate them and the impossibility would not hold"
    );
    assert_eq!(
        named, expanded,
        "the two spellings must deliver one identical value"
    );

    let last_segment = named
        .self_path()
        .0
        .rsplit('/')
        .next()
        .expect("a path always has a final segment");
    assert!(
        !last_segment.is_empty() && !last_segment.chars().all(|each| each.is_ascii_digit()),
        "the point of this pair is that neither member's path ends in an index, so that the \
         digit-keyed repair the `D1` pair leaves open is foreclosed too; the final segment is {:?}",
        last_segment
    );

    Ok(())
}

/// A query that resolves to several strings is several haystacks, not an entry set.
///
/// This is the guard on the repair that closes `Empty NOT IN Strs2[*]`, which is the one cell in the
/// string family that diverges from its literal without being covered by the `Strs[0]`-versus-`Strs[*]`
/// impossibility. `Strs2` is `["abc", "zzz"]`, so `Strs2[*]` delivers two strings and the written-out
/// `Empty NOT IN ["abc", "zzz"]` is 19, while the query spelling is 0.
///
/// The repair that closes it is excluding a string from the vacuous match only when there is exactly one
/// right-hand result -- `rhs_selected.len() > 1` added to the string test. `f6639d51` rejected that on
/// the ground that arity carries no semantic content, and the rejection is worth more than that
/// argument, because the argument is answerable: two or more results prove the operand cannot have come
/// from a `[0]` index, which yields exactly one, so the count looks like the provenance signal the
/// `[0]`-versus-`[*]` collapse destroys. Measured, it does what it claims and nothing else in the
/// two-query arm moves: `Empty NOT IN Strs2[*]` goes to 19 and `Empty IN Strs2[*]` to 0, both correct,
/// with no other cell in a 94-clause sweep of the empty-left-hand shapes touched. That sweep is not
/// reproducible from the tree -- its clause list was never committed, so the figure cannot be re-derived
/// or falsified here. Treat it as a note on what was run rather than as a measurement, and if the question
/// comes up again, commit the clause list. The 140-clause grid quoted on the string skip in `operators.rs`
/// has the same limitation and is flagged there too.
///
/// What refutes it is the shape below. `Resources.*.Properties.Name` over two resources delivers two
/// strings, and each one is a haystack that `IN` asks substring containment of -- there is no list
/// anywhere in the operand and no entry set for anything to be a subset of. So arity does NOT prove an
/// entry set, and under the arity gate this clause exits 19: the empty list is denied against two strings
/// nothing compared, which is the exact false report `9bcf2053` was written to remove, recovered by
/// adding a second resource. The single-resource spelling stays 0 under the same repair, so the boundary
/// it draws falls between one resource and two.
///
/// Two entries in a list and two matching resources are indistinguishable at that site for the same
/// reason the pair in `the_in_polarity_of_a_queried_scalar_right_operand_has_no_repair_in_this_arm` is:
/// `rhs_selected` is a flat list of values and the query that produced it is gone. So `Strs2[*]` is a
/// residual rather than an oversight, and it is pinned at PASS in the table above with its literal at
/// FAIL beside it.
///
/// The `IN` column here is the string kind's own divergence, unrelated to the arity question and older
/// than this branch: both written-out spellings are PASS -- `Empty IN "abc"` and
/// `Empty IN ["abc", "zzz"]` -- and every query spelling was FAIL. It is closed now, by giving the
/// two-query arm the outcome the `(None, Some)` string arm already had -- no comparison at all for an
/// empty left-hand list, and so no result to report in either polarity -- and the `IN` cells below are at
/// PASS accordingly. It is recorded on `an_empty_list_is_not_vacuously_in_a_string` and is not what these
/// cells are for; they are here so that a change to the arity question has to say it did not move them.
#[rstest::rstest]
// THE REFUTATION. Two resources, two string results, no list. PASS, and the arity-keyed repair turns it
// FAIL.
#[case::an_empty_list_is_not_vacuously_in_a_multi_resource_string_query(
    "Empty NOT IN Resources.*.Properties.Name",
    Status::PASS
)]
// The one-result spelling of the same shape, which that repair leaves alone. The two together are what
// show the boundary it draws is the resource count.
#[case::an_empty_list_is_not_vacuously_in_a_single_resource_string_query(
    "Empty NOT IN Resources.Alpha.Properties.Name",
    Status::PASS
)]
// The cell the repair exists for, and its literal. The residual, pinned.
#[case::an_empty_list_is_not_vacuously_in_a_two_entry_string_entry_set(
    "Empty NOT IN Strs2[*]",
    Status::PASS
)]
#[case::an_empty_list_is_vacuously_in_a_two_entry_string_list_literal(
    "Empty NOT IN [\"abc\", \"zzz\"]",
    Status::FAIL
)]
// The `IN` polarity of all three, so a change credited with either question has to say which cells it
// moved. All three agree with the list literal below now. They were FAIL, which was the string kind's own
// `IN` divergence and not the arity question these cells are for: an empty left-hand list against a string
// is no comparison at all, so the clause has nothing to report and passes. The skip in the two-query arm
// of `operators.rs` is what closes them, and it moves no `NOT IN` cell, so the arity refutation above is
// untouched.
#[case::an_empty_list_is_in_a_multi_resource_string_query(
    "Empty IN Resources.*.Properties.Name",
    Status::PASS
)]
#[case::an_empty_list_is_in_a_single_resource_string_query(
    "Empty IN Resources.Alpha.Properties.Name",
    Status::PASS
)]
#[case::an_empty_list_is_in_a_two_entry_string_entry_set("Empty IN Strs2[*]", Status::PASS)]
#[case::an_empty_list_is_in_a_two_entry_string_list_literal(
    "Empty IN [\"abc\", \"zzz\"]",
    Status::PASS
)]
fn a_multi_candidate_string_query_is_not_an_entry_set(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // Two resources holding one string property each, so the wildcard delivers two string results with
    // no list in the operand. `Strs2` holds the same two strings as list entries, so the two spellings
    // differ only in where the values came from -- which is the information the site does not have.
    const INPUT: &str = r#"
    {
        Empty: [],
        Strs2: ["abc", "zzz"],
        Resources: {
            Alpha: { Properties: { Name: "abc" } },
            Beta:  { Properties: { Name: "zzz" } }
        }
    }
    "#;

    let rules = format!("rule membership {{ {clause} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A range inside a list literal is a range for a list-valued left-hand side too.
///
/// `d7f01ec` made a range nested in a list literal behave like a range, and it did so in
/// `contained_in`'s scalar-left-hand arm only. The list-valued arm decides its subset reading with
/// `Vec::contains`, which is `PartialEq`, and `PartialEq` has no range-membership arm -- those live in
/// `compare_eq`. So the same defect that commit describes survived one branch over: for `Ports` of
/// `[85]`, `Ports IN [r[80,90]]` failed and `Ports NOT IN [r[80,90]]` passed, which is a denylist of
/// forbidden port ranges admitting every port. Measured at `689b417` and at earlier commits on this
/// branch; it never moved, so it is that commit's incompleteness rather than a regression from it.
///
/// Seventeen of these cells were wrong before the fix. Every one has its opposite polarity here, so a
/// fix that made membership always true, or always false, fails rather than passing half the table.
///
/// The reference spelling is a plain element, not the unwrapped range. For a scalar left-hand side
/// `Port IN r[80,90]` has always been right and is the natural control, but a *list* against an
/// unwrapped range refuses in both polarities -- `contained_in`'s list arm sends a non-list right-hand
/// side to the incomparable catch-all -- so it cannot say what the wrapped spelling ought to answer.
/// The `_reference_plain_element` cells do that instead: `Ports IN [85]` passes and
/// `Ports NOT IN [85]` fails, and `[r[80,90]]` has to give the same two answers for a value the range
/// covers. The two `list_against_an_unwrapped_range` cells are here so that a later change which makes
/// that spelling answer has to say so out loud; they are not the property under test.
///
/// The rule these cells state, unchanged from
/// `a_list_denylist_holding_a_nested_list_denies_only_what_it_names` including its qualifier: for a
/// non-empty left-hand list, `NOT IN` fails if and only if the whole left-hand list is a member of the
/// right-hand list, or any left-hand element is. No property here is an empty list, so nothing below
/// exercises the vacuous case that qualifier is about -- the six cells that do are
/// `denied_empty_over_a_flat_list`, `denied_empty_over_a_nested_list` and
/// `denied_empty_over_a_mixed_denylist`, each with its `_via_query` twin, in the oracle named above. A range
/// covering an element makes that element a member. It is not `not(IN)`, and `Partly` -- `[85, 99]`,
/// one element inside `r[80,90]` and one outside -- is the cell where that matters: it is not a subset,
/// so `IN` fails, and `85` is named, so `NOT IN` fails as well. Both polarities failing on a partial
/// collision is what the plain-element spelling beside it already does, which is why
/// `partly_covered_reference_plain_denied` sits next to it.
///
/// The three numeric-widening cells are separate because `compare_eq`'s range table is typed: `Int`
/// against `RangeInt`, `Float` against `RangeInt`, and `Int` against `RangeFloat` are three arms, and a
/// fix that reached only the first would pass `list_covered` while leaving a float-valued property
/// undeniable.
///
/// `range_beside_a_nested_list` is the second branch of the same arm. A right-hand list holding any
/// nested list takes the membership-or-subset path rather than the flat-subset path, and both compute
/// the element-wise diff the same way, so both needed the same repair. Without that cell a fix to the
/// flat branch alone reads as complete.
#[rstest::rstest]
#[case::scalar_covered_wrapped("Port", "IN [r[80,90]]", Status::PASS)]
#[case::scalar_covered_unwrapped("Port", "IN r[80,90]", Status::PASS)]
#[case::scalar_denied_wrapped("Port", "NOT IN [r[80,90]]", Status::FAIL)]
#[case::scalar_denied_unwrapped("Port", "NOT IN r[80,90]", Status::FAIL)]
#[case::scalar_uncovered_wrapped("Port", "IN [r[10,20]]", Status::FAIL)]
#[case::scalar_undenied_wrapped("Port", "NOT IN [r[10,20]]", Status::PASS)]
#[case::list_covered("Ports", "IN [r[80,90]]", Status::PASS)]
#[case::list_denied("Ports", "NOT IN [r[80,90]]", Status::FAIL)]
#[case::list_reference_plain_element("Ports", "IN [85]", Status::PASS)]
#[case::list_reference_plain_element_denied("Ports", "NOT IN [85]", Status::FAIL)]
#[case::list_uncovered("Outside", "IN [r[80,90]]", Status::FAIL)]
#[case::list_undenied("Outside", "NOT IN [r[80,90]]", Status::PASS)]
#[case::every_element_covered("AllIn", "IN [r[80,90]]", Status::PASS)]
#[case::every_element_denied("AllIn", "NOT IN [r[80,90]]", Status::FAIL)]
#[case::no_element_covered("AllOut", "IN [r[80,90]]", Status::FAIL)]
#[case::no_element_denied("AllOut", "NOT IN [r[80,90]]", Status::PASS)]
#[case::partly_covered_is_not_a_subset("Partly", "IN [r[80,90]]", Status::FAIL)]
#[case::partly_covered_is_still_denied("Partly", "NOT IN [r[80,90]]", Status::FAIL)]
#[case::partly_covered_reference_plain("Partly", "IN [85]", Status::FAIL)]
#[case::partly_covered_reference_plain_denied("Partly", "NOT IN [85]", Status::FAIL)]
#[case::int_and_float_covered("Mixed", "IN [r[80,90]]", Status::PASS)]
#[case::int_and_float_denied("Mixed", "NOT IN [r[80,90]]", Status::FAIL)]
#[case::float_in_an_int_range("Floats", "IN [r[80,90]]", Status::PASS)]
#[case::float_in_an_int_range_denied("Floats", "NOT IN [r[80,90]]", Status::FAIL)]
#[case::int_in_a_float_range("Ports", "IN [r[80.0,90.0]]", Status::PASS)]
#[case::int_in_a_float_range_denied("Ports", "NOT IN [r[80.0,90.0]]", Status::FAIL)]
#[case::range_beside_a_string("Ports", r#"IN [r[80,90], "zzz"]"#, Status::PASS)]
#[case::range_beside_a_string_denied("Ports", r#"NOT IN [r[80,90], "zzz"]"#, Status::FAIL)]
#[case::range_beside_a_nested_list("Ports", "IN [r[80,90], [9]]", Status::PASS)]
#[case::range_beside_a_nested_list_denied("Ports", "NOT IN [r[80,90], [9]]", Status::FAIL)]
#[case::two_ranges_one_covering("Ports", "IN [r[10,20], r[80,90]]", Status::PASS)]
#[case::two_ranges_one_covering_denied("Ports", "NOT IN [r[10,20], r[80,90]]", Status::FAIL)]
#[case::two_ranges_neither_covering("Outside", "IN [r[10,20], r[30,40]]", Status::FAIL)]
#[case::two_ranges_neither_covering_undenied(
    "Outside",
    "NOT IN [r[10,20], r[30,40]]",
    Status::PASS
)]
#[case::plain_element_matches_beside_a_range("Outside", "IN [r[10,20], 99]", Status::PASS)]
#[case::plain_element_denies_beside_a_range("Outside", "NOT IN [r[10,20], 99]", Status::FAIL)]
#[case::list_against_an_unwrapped_range("Ports", "IN r[80,90]", Status::FAIL)]
#[case::list_against_an_unwrapped_range_negated("Ports", "NOT IN r[80,90]", Status::FAIL)]
fn a_range_in_a_list_denylist_denies_a_list_valued_property(
    #[case] property: &str,
    #[case] comparison: &str,
    #[case] expected: Status,
) -> Result<()> {
    // Nothing sits on a bound. `r[80,90]` is inclusive and `r(80,90)` is not, and a cell whose answer
    // turns on which one it is would be testing the bound reading rather than the membership one.
    const INPUT: &str = r#"
    {
        Port: 85,
        Ports: [85],
        Outside: [99],
        AllIn: [81, 85, 89],
        AllOut: [1, 2, 3],
        Partly: [85, 99],
        Mixed: [85, 85.5],
        Floats: [85.5]
    }
    "#;

    let rules = format!("rule membership {{ {property} {comparison} }}");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "membership")?,
        "clause: {} {}",
        property,
        comparison
    );

    Ok(())
}

/// The `NOT IN` deprecation notice goes out only for a clause the incomparability let pass.
///
/// `incomparable_membership` is gated on one thing: that some pair of the flattened operands refused to
/// compare. It never consulted the verdict, and it could not have -- it was called before `cmp.compare`
/// ran, so at that point there was no verdict to read. The notice's own wording is "<clause> passed
/// because the value could not be compared with any element of the list", so on a clause that failed it
/// printed the opposite of what happened. Measured across 231 `NOT IN` shapes: 177 reach the notice, 146
/// of them pass and 31 fail, and before this change all 177 printed it. Those counts were taken while
/// the predicate compared whole values and returned on the first answered pair, so they are the record of
/// why the verdict gate was added rather than a census of what fires today.
///
/// Which matters because of what the notice is for. It warns that a future release fails closed where
/// the tool passes today, and it is the line an author greps for to find the clauses that need
/// migrating before an upgrade. Beside a failure it costs a wasted investigation, and it misdirects
/// as well: a clause that already fails is not one the fail-closed change will move.
///
/// The negative cells are three separate reasons a firing clause fails rather than one case repeated,
/// which is why there are three groups of them rather than one:
///
/// - `a_scalar_denylist_that_already_fails_closed` reaches `NotComparable` instead of the
///   suppressed-error path, so it fails closed in this release already. The notice's premise that the
///   pair "is currently read as not a member" is false there.
/// - The four `_the_denylist_names` cells fail because they collide with an element the denylist names,
///   which is an ordinary decided verdict. They are now silent for a second reason as well, and the
///   second one is the repair: the predicate compares the left-hand list's elements against the
///   right-hand elements, as `contained_in` does, so `IntList NOT IN IntList` answers every pair and has
///   no refusal to report. It used to compare the whole list value -- comparable with nothing -- and fire
///   on all four, leaving only the verdict gate between the notice and a clause decided perfectly
///   normally.
/// - `an_empty_left_hand_list` fails on the vacuous subset reading. `Haystack` holds no list, so
///   `contained_in` takes its all-flat branch, where an empty left-hand list has an empty element-wise
///   diff and `IN` succeeds on a value with nothing in it; the negation turns that into a failure. An
///   earlier revision of this line blamed `contained_in`'s deliberate `is_empty` guard, which lived in
///   the other branch and was never reached from here. That guard is gone now and this cell did not
///   move when it went, which is the evidence. It too is silent twice over now: flattening an empty list
///   yields no element to compare, and a predicate with nothing to compare has nothing to warn about.
///
/// Asserted through `status_and_deprecations` rather than `status_and_messages`. A deprecation notice
/// is not a record message -- it goes to `RootScope::deprecations`, which the commands drain to
/// stderr after evaluation -- so `recorded_comparison_messages` walking the record tree cannot see
/// one however it is worded, and neither can a `Status`-only assertion. That is why the defect
/// survived: nothing in the suite read the collection the notice lands in.
///
/// Every cell carries its status as well as its notice expectation. Suppressing the notice by moving
/// a verdict would fix the contradiction and break the clause, so a change that does that has to fail
/// here rather than read as a repair.
#[rstest::rstest]
// Clauses the incomparability lets pass. The notice is true of these and must survive.
#[case::a_map_against_a_scalar_denylist("Map NOT IN Haystack", Status::PASS, true)]
#[case::a_nested_list_against_a_scalar_denylist("Deep NOT IN Haystack", Status::PASS, true)]
#[case::a_list_against_a_disjoint_scalar_denylist("IntList NOT IN Haystack", Status::PASS, true)]
#[case::a_bool_against_an_int_denylist("Bool NOT IN IntList", Status::PASS, true)]
#[case::a_map_list_against_an_int_denylist("MapList NOT IN IntList", Status::PASS, true)]
// Clauses that fail. Each printed the notice before this change.
#[case::a_scalar_denylist_that_already_fails_closed("Map NOT IN Str", Status::FAIL, false)]
#[case::an_int_list_the_denylist_names("IntList NOT IN IntList", Status::FAIL, false)]
#[case::a_string_list_the_denylist_names("StrList NOT IN StrList", Status::FAIL, false)]
#[case::a_nested_list_the_denylist_names("Deep NOT IN Deep", Status::FAIL, false)]
#[case::a_map_list_the_denylist_names("MapList NOT IN MapList", Status::FAIL, false)]
#[case::an_empty_left_hand_list("EmptyList NOT IN Haystack", Status::FAIL, false)]
// Controls: silent before this change and silent after it.
#[case::a_denial_that_was_decided("Int NOT IN IntList", Status::FAIL, false)]
#[case::a_map_denied_by_a_map_denylist("Map NOT IN MapList", Status::FAIL, false)]
// Was a control expecting silence, and the silence was the early return's rather than a fact about the
// clause. `Haystack` is `[7, "zzz", false]`: `1` is answered against `7` and cannot be compared with
// either of the other two, so this clause passes on two suppressed refusals and a fail-closed release
// moves it. The predicate returned on the answered pair and never reached them. It is a scalar, so
// nothing here turns on the granularity fix -- `the_notice_asks_about_the_pairs_the_operator_compared`
// separates the two faults.
#[case::an_undenied_value_beside_elements_it_cannot_be_compared_with(
    "Int NOT IN Haystack",
    Status::PASS,
    true
)]
#[case::the_positive_polarity_never_notices("Map IN Haystack", Status::FAIL, false)]
fn the_incomparable_membership_notice_is_only_emitted_for_a_clause_that_passed(
    #[case] clause: &str,
    #[case] expected: Status,
    #[case] expect_notice: bool,
) -> Result<()> {
    // Flat, and every left-hand shape sits beside the denylist that names it, so a `_the_denylist_names`
    // cell and its passing counterpart differ only in the right-hand side.
    const INPUT: &str = r#"
    {
        Int: 1,
        Str: "a",
        Bool: true,
        IntList: [1, 2],
        StrList: ["a", "b"],
        Deep: [["a"]],
        Map: { a: 1 },
        MapList: [{ a: 1 }],
        EmptyList: [],
        Haystack: [7, "zzz", false]
    }
    "#;

    let (status, notices) = status_and_deprecations(clause, INPUT)?;

    assert_eq!(
        expected, status,
        "`{}` changed verdict; this is a diagnostics fix and must move no status",
        clause
    );

    assert_membership_notice(clause, status, expect_notice, &notices);

    Ok(())
}

/// The notice asks about the pairs the operator compared, not about the whole left-hand value.
///
/// `incomparable_membership` used to decide on `compare_eq(whole_left_hand_value, element)`, while
/// `contained_in` decides a list-valued left-hand side by comparing its ELEMENTS. The two questions have
/// different answers for the commonest denylist shape there is, and the predicate's was the wrong one: a
/// list of strings against a flat list of strings is `(List, String)` at whole-value granularity, a pair
/// `compare_eq` has no arm for, so an ordinary compliant rule was told a passing clause would fail closed
/// in a future release when nothing about it moves.
///
/// The first four cells are that class, and they are the observable harm: `Strs NOT IN ["x", "y"]` is what
/// a rule author writes, every pair it compares is string against string, and it collides with nothing.
/// Two spellings of each because a written-out denylist and a queried one reach different arms of
/// `InOperation::compare`, and the predicate is upstream of both.
///
/// `a_denylist_entry_no_element_can_be_compared_with` is the other half of the discriminator the predicate's
/// own note records, and the pair inverts under this fix. Before it, `Strs NOT IN ["x","y"]` emitted and
/// `Strs NOT IN ["x","y",["p"]]` did not, though both pass and their element-wise facts are identical --
/// adding a nested list flipped `compare_eq(whole_list, element)` from `Err` to `Ok` because `(List, List)`
/// is an arm and `(List, String)` is not, so the trigger was decided by the kind of an unrelated denylist
/// entry. After it, the silence and the notice are the other way round, and each is about a pair the
/// operator built: `["p"]` is an element every element of `Strs` is compared against and cannot be compared
/// with, and `"x"` and `"y"` are elements it compares fine.
///
/// The two early-return cells are the second fault, which is not the same one and does not go with it. The
/// loop used to return false on the first pair `compare_eq` answered, deciding
/// the whole cross product on one pair's evidence, so a denylist holding one element of the right kind
/// silenced the notice however many of its other elements refused. Aligning the granularity without this
/// makes it worse rather than better: the element-wise pairs it exposes are walked in the order the
/// denylist is written, so an answered pair anywhere before a refusing one discarded a refusal that had
/// already been seen. Measured over 132 shapes, alignment alone took true positives from 72 to 69 and false
/// negatives from 17 to 20 -- the four false alarms went and eleven true positives went with them. The two
/// changes are one fix.
///
/// The last three cells are controls for what must NOT change:
///
/// - `a_left_hand_value_that_is_not_a_list_is_not_flattened` keeps the five aws-guard-rules-registry
///   notices alive in miniature. Four of those are a `!Ref`-shaped MAP against a regex denylist and the
///   fifth a MAP against a plain string; a map is not a list, so nothing about it flattens, and if this
///   cell ever goes silent the registry corpus has lost its notices too.
/// - `a_nested_element_is_flattened_one_level_only` is red for a recursive flatten. `Deep` is `[["a"]]`, so
///   one level gives the element `["a"]`, which is what `is_one_of` compares and which no string can be
///   compared with. Flattening twice would hand the loop `"a"`, answer `Ok(false)` against every element,
///   and lose a notice that is owed.
/// - `nothing_refused_so_nothing_is_owed` is the silence that was always right, and it holds the predicate
///   to "some pair refused" rather than "some pair did not match".
#[rstest::rstest]
// The false-alarm class: a list-valued left-hand side against a denylist of its own element kind. Silent
// after this fix, and each of these four emitted before it.
#[case::a_flat_denylist_every_element_can_be_compared_with(
    "Strs NOT IN [\"x\", \"y\"]",
    Status::PASS,
    false
)]
#[case::the_same_denylist_reached_through_a_query("Strs NOT IN DenyStrs", Status::PASS, false)]
#[case::an_int_list_against_a_disjoint_int_denylist("Ints NOT IN [7, 8]", Status::PASS, false)]
#[case::the_same_int_denylist_through_a_query("Ints NOT IN DenyInts", Status::PASS, false)]
// The other half of the discriminator. Silent before this fix and noticed after it, on the element pair
// `("a", ["p"])` that the operator does build and cannot decide.
#[case::a_denylist_entry_no_element_can_be_compared_with(
    "Strs NOT IN [\"x\", \"y\", [\"p\"]]",
    Status::PASS,
    true
)]
// The early return, isolated. The whole-value pair `([1,2], [1,9])` is one `compare_eq` answers -- equal
// lengths, so it zips and reports false -- and it is the first pair the old loop built, which returned on
// it. Every element pair refuses: `(Int, List)` has no arm and neither has `(Int, String)`. So the old
// predicate was silent here for a reason that had nothing to do with the pairs the clause was decided on.
// A denylist nobody writes by hand, and that is the point: it is the shape that separates the two faults.
#[case::an_answered_pair_no_longer_decides_the_whole_cross_product(
    "Ints NOT IN [[1, 9], \"x\"]",
    Status::PASS,
    true
)]
// The same fault where the left-hand side is a scalar and nothing flattens, so this cell moves under the
// early return alone. `Haystack` is `[7, "zzz", false]`: `"a"` is answered against `"zzz"` and refuses
// against `7` and `false`.
#[case::a_scalar_beside_the_elements_it_cannot_be_compared_with(
    "Str NOT IN Haystack",
    Status::PASS,
    true
)]
// Controls.
#[case::a_left_hand_value_that_is_not_a_list_is_not_flattened(
    "Map NOT IN Haystack",
    Status::PASS,
    true
)]
#[case::a_nested_element_is_flattened_one_level_only("Deep NOT IN DenyStrs", Status::PASS, true)]
#[case::nothing_refused_so_nothing_is_owed("Int NOT IN DenyInts", Status::PASS, false)]
fn the_notice_asks_about_the_pairs_the_operator_compared(
    #[case] clause: &str,
    #[case] expected: Status,
    #[case] expect_notice: bool,
) -> Result<()> {
    // Every denylist here is disjoint from every left-hand value, so no cell's verdict rests on a
    // collision and the notice expectation is the only thing that separates them.
    const INPUT: &str = r#"
    {
        Int: 1,
        Str: "a",
        Strs: ["a", "b"],
        Ints: [1, 2],
        Deep: [["a"]],
        Map: { a: 1 },
        DenyStrs: ["x", "y"],
        DenyInts: [7, 8],
        Haystack: [7, "zzz", false]
    }
    "#;

    let (status, notices) = status_and_deprecations(clause, INPUT)?;

    assert_eq!(
        expected, status,
        "`{}` changed verdict; this is a diagnostics fix and must move no status",
        clause
    );

    assert_membership_notice(clause, status, expect_notice, &notices);

    Ok(())
}

/// The notice asks about every granularity the operator decides at, and about the refusals it never
/// asks `compare_eq` for.
///
/// Aligning the predicate to `contained_in`'s ELEMENT pairs removed a class of false alarm and took
/// thirteen owed notices with it, because element pairs are not all the operator decides on. Two
/// mechanisms, and each cell below names which one it is about.
///
/// # The second granularity
///
/// `contained_in`'s list-against-list arm decides at TWO granularities when the denylist holds a list.
/// It asks `is_one_of` per left-hand ELEMENT, and then, if no element matched, walks the denylist again
/// comparing the WHOLE left-hand list against each entry -- the loop that decides `whole_list_member`.
/// A refusal in that second loop is a refusal the clause's answer rests on, and a predicate built from
/// element pairs alone cannot see it.
///
/// Both `EmptyOuter` cells are that shape and neither is exotic. `EmptyOuter` is `[[]]`, one entry, and
/// against `[[1]]` every element pair is answered -- `compare_eq([], [1])` is `(List, List)` at unequal
/// lengths, which reports false without looking at an element -- while the whole-value pair
/// `compare_eq([[]], [1])` has EQUAL lengths, so it zips and `compare_eq([], 1)` refuses. `Nest` against
/// `[[2], [7, 8]]` is the same mechanism at length two.
///
/// The flat-denylist controls are the win this must not give back. A denylist holding no list never
/// reaches the second loop, so `Strs NOT IN ["x", "y"]` and `Ints NOT IN [7, 8]` stay silent -- those
/// two are cells of `the_notice_asks_about_the_pairs_the_operator_compared` as well, kept here because
/// the repair for the granularity above is one condition away from reinstating them.
///
/// # The shape refusal
///
/// `contained_in` dispatches on the left value first, so a list-valued left-hand side against a right
/// value that is not a list reaches its `List` arm's catch-all and answers `NotComparable` on the SHAPES,
/// without calling `compare_eq` at all. There is no comparison result to read there, so a predicate that
/// only reads `compare_eq` cannot see that refusal by construction; the shape is what carries it.
///
/// Whether the clause passes on it is decided one level up, by which arm of `InOperation::compare` the
/// operands reached. The `(None, None)` arm -- both sides queries -- drops the `NotComparable` and the
/// value joins the unmatched set, so `NOT IN` passes; every other arm reports it and the clause already
/// fails closed. That is the whole reason `both_queried` gates the refusal in `incomparable_membership`
/// rather than the values doing, and the three controls are what pin the boundary:
/// `Ports NOT IN 5` fails today because a literal right-hand side reaches the `(None, Some)` arm, which
/// pushes the refusal; `Empty NOT IN "abc"` never reaches `contained_in` at all, because a literal string
/// takes the `string_in` path; and `Empty NOT IN D13[*]` matches vacuously before `contained_in` is
/// called, so there is no refusal to see and no pass to notice.
///
/// `Empty NOT IN Ustr` is the cell `incomparable_membership`'s own comment called the one notice the
/// alignment took away rather than corrected, on the reading that flattening an empty list leaves no
/// element to compare. True of the element pairs and not of the clause: the refusal WAS the shape pair
/// `([], "abc")`, which is what made the cell repairable here.
///
/// Past tense as of `69628df7`, and the sentence here used to be present tense -- "the refusal is the
/// shape pair `([], "abc")`, which is there whether or not anything flattens". That pairing is now skipped
/// before `contained_in` is called, so the refusal does not exist and the cell has moved out of this
/// block; the note above `an_empty_list_against_a_queried_string` records the move and the notice
/// that replaced it.
///
/// The verdict question that cell also sits in -- `Empty NOT IN Str` against `Empty NOT IN Strs[*]`, where
/// at most one spelling can be right -- is untouched, because nothing here moves a verdict.
///
/// # Why the fail-closed measurement is not in this test
///
/// `the_notice_fires_exactly_where_fail_closed_moves_the_answer` measures "does the coming change move
/// this clause" from the language itself, using `!=` as the fail-closed spelling of `NOT IN`. That works
/// only for a scalar left-hand side against a one-element denylist, and every cell here has a
/// list-valued left-hand side or a multi-entry denylist. So these were classified against a build with
/// the four `NotComparable` suppressions promoted -- `is_one_of`, `contained_in`'s whole-list and scalar
/// loops, and the `(None, None)` arm's dropped result -- over 1080 clause shapes, on 2026-09-03: each
/// cell marked `true` below PASSes today and FAILs under that build.
///
/// THAT ORACLE HAS TO BE REBUILT ON THE COMMIT BEING CLASSIFIED, and the clause that used to close this
/// paragraph is why it is worth saying. It read "and each `false` cell answers the same either way",
/// stated as a property of the method. It is a property of the tree the method was run against. A promoted
/// build made from `b8d3901e` still routes an empty left-hand list against a string through
/// `contained_in`, so it answers 19 for `an_empty_list_against_a_queried_string` where this tree
/// answers 0 -- read off that artifact the cell would be marked `true`. The `false` marking is right, for
/// the reason recorded above the cell itself; what was wrong is the claim that the named oracle reaches
/// it.
///
/// At this commit the oracle cannot reach that family at all, and that is checkable without building one.
/// Instrumented at `contained_in`'s entry with the release binary: `Empty NOT IN Ustr`,
/// `Empty NOT IN Str` and `Empty NOT IN Strs[*]` make ZERO calls to it, against one call each for
/// `D13 NOT IN Strs` and `Strs2 NOT IN Strs` as positive controls. Promoting what a function returns
/// cannot move a clause that never calls it. So classify a new cell in this family by that call count
/// rather than by the artifact, and rebuild the artifact before trusting it on any other.
///
/// What this test can hold on its own is the verdict, which no cell may move.
///
/// # The fourth column
///
/// Every cell carries the vacuous-comparison notice it expects as well as the membership one, because a
/// column that only records which notice stopped is satisfied by the clause going silent altogether. That
/// is not hypothetical here: `an_empty_list_against_a_queried_string` was flipped to `false` when its
/// warning moved channels, and the flip on its own would have pinned an absence rather than the notice
/// that replaced it. Two cells carry `true` there and the other eleven record nothing of any kind, so the
/// column is the honest shape of what this table can say.
#[rstest::rstest]
// The second granularity. Every element pair is answered and the whole-value pair refuses.
#[case::a_whole_value_pair_only_a_nested_denylist_builds(
    "EmptyOuter NOT IN [[1]]",
    Status::PASS,
    true,
    false
)]
#[case::the_same_whole_value_pair_at_length_two(
    "Nest NOT IN [[2], [7, 8]]",
    Status::PASS,
    true,
    false
)]
#[case::a_whole_value_pair_that_zips_onto_a_regex(
    "Deep NOT IN [[/zzz/]]",
    Status::PASS,
    true,
    false
)]
// Controls for it: a flat denylist never reaches the second loop, so these two stay silent.
#[case::a_flat_denylist_builds_no_whole_value_pair(
    "Strs NOT IN [\"x\", \"y\"]",
    Status::PASS,
    false,
    false
)]
#[case::a_flat_int_denylist_builds_no_whole_value_pair(
    "Ints NOT IN [7, 8]",
    Status::PASS,
    false,
    false
)]
#[case::a_flat_queried_denylist_builds_no_whole_value_pair(
    "Ports NOT IN DenyInts",
    Status::PASS,
    false,
    false
)]
// The shape refusal, which `compare_eq` is never asked about.
#[case::a_list_against_queried_scalars("Ports NOT IN D13[*]", Status::PASS, true, false)]
#[case::a_list_against_a_queried_map("Maps NOT IN Umap", Status::PASS, true, false)]
#[case::a_list_against_a_queried_scalar("Ports NOT IN Uint", Status::PASS, true, false)]
// Controls for it: four ways the refusal is not what the clause passed on.
#[case::a_literal_scalar_already_fails_closed("Ports NOT IN 5", Status::FAIL, false, false)]
#[case::a_literal_string_never_reaches_the_refusal(
    "Empty NOT IN \"abc\"",
    Status::PASS,
    false,
    true
)]
#[case::a_vacuous_match_happens_before_the_refusal(
    "Empty NOT IN D13[*]",
    Status::FAIL,
    false,
    false
)]
// `Empty NOT IN Ustr` MOVED from the refusal block to this one, and the cell that follows it in this
// file is why. It was `true` here: the shape pair `([], "abc")` reached `contained_in`, refused on the
// shapes, and the `(None, None)` arm dropped the refusal, so the clause passed on it and this notice was
// owed. That is no longer the path. A string right operand paired with an empty left-hand list is now
// skipped before `contained_in` is called at all, so there is no refusal for the clause to pass on --
// which is exactly the condition the control two lines above describes for the literal spelling, and the
// query spelling now reaches the comparison the same way the literal does.
//
// The clause still warns, through the channel whose wording is true of it. Measured, both polarities:
// `Empty NOT IN Ustr` and `Empty IN Ustr` emit `vacuous_comparison_notice` -- "passed without comparing
// anything, because the query selected an empty collection" -- which is what happened, where "could not
// be compared with any element of the list" names an element comparison that no longer occurs and a list
// that was never read. `Empty NOT IN "abc"` and `Empty IN "abc"` emit that same notice and always have,
// so this is the query spelling joining its literal rather than losing its diagnostic.
// `every_string_spelling_warns_through_the_channel_that_is_true_of_it` asserts the notice that IS emitted
// across the whole family, so the coverage this cell gave up is replaced by a stronger claim than the
// absence of one notice.
#[case::an_empty_list_against_a_queried_string("Empty NOT IN Ustr", Status::PASS, false, true)]
fn the_notice_asks_about_every_granularity_the_operator_decides_at(
    #[case] clause: &str,
    #[case] expected: Status,
    #[case] expect_notice: bool,
    #[case] expect_vacuous_notice: bool,
) -> Result<()> {
    // Every denylist is disjoint from every left-hand value, so no cell's verdict rests on a collision.
    const INPUT: &str = r#"
    {
        Strs: ["a", "b"],
        Ints: [1, 2],
        Deep: [["a"]],
        Empty: [],
        EmptyOuter: [[]],
        Maps: [{ a: 1 }],
        Nest: [[1], [9]],
        Ports: [85],
        D13: [1, 3],
        DenyInts: [7, 8],
        Umap: { k: 1 },
        Uint: 5,
        Ustr: "abc"
    }
    "#;

    let (status, notices) = status_and_deprecations(clause, INPUT)?;

    assert_eq!(
        expected, status,
        "`{}` changed verdict; this is a diagnostics fix and must move no status",
        clause
    );

    assert_membership_notice(clause, status, expect_notice, &notices);

    // The fourth column, and it is here rather than only in the membership one because two cells in this
    // table are silent on the membership channel while warning through the other. Asserting only what
    // stopped is what the defect this table records looks like from the inside: the cell that flipped to
    // `false` when the notice changed channels would have passed just as well had the clause gone silent
    // altogether, which is the outcome that would be a regression rather than the fix.
    //
    // The column is `true` for exactly the two `Empty`-against-a-string spellings, measured on 2026-09-03
    // -- every other cell here records no notice of any kind, so there is nothing else to name.
    // `every_string_spelling_warns_through_the_channel_that_is_true_of_it` makes the same claim across the
    // whole string family in both polarities; this keeps the two cells self-contained, so a change that
    // deleted that test would not leave these two resting on an absence again.
    let vacuous_emitted = notices
        .iter()
        .any(|n| n.contains("passed without comparing anything"));
    assert_eq!(
        expect_vacuous_notice,
        vacuous_emitted,
        "`{}` reached {:?}, so the vacuous-comparison notice should {}; recorded {:?}",
        clause,
        status,
        match expect_vacuous_notice {
            true =>
                "have been emitted, because the clause passed without comparing anything and that \
                     is the channel whose wording is true of it",
            false => "have stayed silent",
        },
        notices
    );

    Ok(())
}

/// The branch that decides membership with `PartialEq` reaches no state this notice is about.
///
/// `InOperation::compare`'s `(Some, None)` arm decides a list-valued LITERAL against a right-hand side
/// holding no list with `!rhs.contains(elem)`. That is `Vec::contains`, so `PartialEq`, so nothing in the
/// branch can refuse: there is no `compare_eq` result for `incomparable_membership` to read and no
/// `contained_in` refusal for its shape arm to record either, because `contained_in` is never called.
///
/// **Read what this cell can and cannot fail on, because the two assertions are not equally strong.** The
/// verdict is the strong half: all three clauses FAIL, at the merge-base and here alike, measured. The
/// silence is the weak half, and it is over-determined -- a failing clause has its notice suppressed by
/// `clause_passed` in `binary_operation` whatever the predicate answered, so the absence of a notice here is
/// not evidence that the predicate stayed quiet. An earlier revision of this test asserted `Status::PASS`
/// on the guess that these clauses passed, which is how the over-determination surfaced: they do not, and
/// the whole branch has no passing cell to write a discriminating cell against. Across 80 `NOT IN` cells of
/// this shape, every one FAILs.
///
/// So what it guards is the conjunction: a change that makes one of these PASS *and* emits a notice on it
/// trips both assertions, and that is the only route by which this branch could start claiming the coming
/// fail-closed change moves a clause the change does not reach. A change that moves only the verdict trips
/// the first. Nothing here can catch the shape arm firing on a clause that keeps failing, and no cell can,
/// which is why `incomparable_membership`'s own comment records the limit rather than implying coverage.
///
/// Through `deprecations_for_rules` rather than `status_and_deprecations`, because the `let` has to be
/// written out and the wrapping helper cannot express one.
///
/// `%lit NOT IN D13[*]` against a LITERAL and not a query: `Ports NOT IN D13[*]`, the same denylist against
/// the same shape of value from a query, is a cell of
/// `the_notice_asks_about_every_granularity_the_operator_decides_at` and does expect the notice, because
/// there the operand reaches `contained_in` and is refused on the shapes. The pair is the point.
#[test]
fn a_membership_decided_by_partial_eq_owes_no_notice() -> Result<()> {
    const INPUT: &str = r#"
    {
        D13: [1, 3],
        Strs: ["a", "b"]
    }
    "#;

    for rules in [
        "let lit = [85]\nrule r { %lit NOT IN D13[*] }",
        "let lit = [\"x\", \"y\"]\nrule r { %lit NOT IN Strs[*] }",
        "let lit = []\nrule r { %lit NOT IN D13[*] }",
    ] {
        let (status, notices) = deprecations_for_rules(rules, INPUT)?;

        assert_eq!(
            Status::FAIL,
            status,
            "`{}` changed verdict; this is a diagnostics fix and must move no status",
            rules
        );

        assert!(
            !membership_notice_present(&notices),
            "`{}` is decided by `Vec::contains`, which cannot refuse, so there is no refusal for the \
             notice to be about; recorded {:?}",
            rules,
            notices
        );

        // The silence above is the weak half twice over. The doc comment names the first reason -- a
        // failing clause has its notice suppressed by the verdict gate whatever the predicate answered --
        // and this is the second: a build where nothing emits this notice satisfies it too. The control
        // separates that world from this one; nothing separates the verdict suppression, which is why the
        // comment records the limit.
        assert_the_membership_channel_is_live();
    }

    Ok(())
}

/// The notice goes out exactly where the coming fail-closed release changes the clause's answer.
///
/// A previous revision gated this on whether the file *reports* the clause, and reached that gate
/// through `ClauseRole`: a failing `Gate` was noticed because `eval_conjunction_clauses` absorbs a
/// failing condition and `eval_rule` maps every non-PASS condition to SKIP, so the rule it guards is
/// dropped at exit 0. Both halves of that are wrong, and the second is wrong in a way the first hides.
///
/// `ClauseRole` does not carry reportedness. Its own documentation says what it answers -- whether an
/// *unevaluatable* clause FAILs or SKIPs -- and that is a different question. Two `Assertion`-role
/// routes absorb a failure at exit 0: a disjunct beside a passing disjunct, and `some`. Neither
/// carries `Gate`, so a reportedness gate reached through the role misses both. Nor could the role be
/// swapped for something better, because reportedness is not known where this notice is built. It is
/// a function of statuses computed strictly later: a sibling disjunct that decides an `or` may not have
/// run yet -- `eval_conjunction_clauses` short-circuits on the first PASS, so `Other == 5 or Ports NOT
/// IN [1, 3]` never evaluates the second disjunct at all -- and a gate clause is reported or not
/// according to whether some *later* clause in the same rule fails. Measured: with the failing sibling
/// in the same rule the report names the gate clause, and with it moved to another rule the report does
/// not. Nothing reachable from `binary_operation` can see either.
///
/// The gate does not need reportedness, because that was never the question the notice asks. The notice
/// warns that a future release fails closed where this one passes, so it belongs on the clauses whose
/// answer that change *moves*, and on no others. A clause that does not pass today does not move: `!=`
/// already fails closed, so the destination is measurable now, and a clause that already reaches
/// `NotComparable` answers the same as one that fails on a named element. Asserted, both FAIL; gated,
/// both SKIP the rule at exit 0. `the_notice_fires_exactly_where_fail_closed_moves_the_answer` measures
/// that against the fail-closed spelling of each shape rather than deriving it, so it fails if the
/// language ever stops agreeing.
///
/// So the gate is the verdict alone, which is what it was before the role joined it -- read under the
/// query's own `match_all`, since "did this clause pass" needs one value for `some` and every value
/// otherwise. That reading is load-bearing rather than tidy: an `all(PASS)` one is silent on a `some`
/// clause that passes on a genuine incomparability while a sibling value fails to a spent regex budget.
/// `a_some_clause_that_passes_on_a_refusal` is that shape here and `a_refusing_pair_beside_a_spent_budget`
/// is it with the budget; `clause_passed` weighs the two readings. It used to cost a false alarm as well --
/// `a_some_clause_one_value_of_which_fails` was that cost, on a clause every pair of which is int against
/// int -- and it does not any more, because that noise came from the predicate's whole-value premise rather
/// than from this reading of the verdict.
///
/// The cells that changed answer when the role left this gate are the two former `absorb` ones, the
/// filter, and `an_already_fail_closed_gate`. The rest are controls, and each pins a different edge:
///
/// - `an_assertion_that_fails` keeps f3eb258's guarantee: the file names that clause at exit 19, so a
///   notice claiming it passed would contradict the line the author greps.
/// - `a_passing_gate_beside_a_failing_body` exits 19 for a *different* clause. Suppression is per
///   clause and not per file, so this notice must survive an exit 19 it is not about.
/// - `a_gate_that_fails_on_comparable_values` fails as a gate with nothing incomparable in it, so the
///   predicate must not become a licence to notice every failing gate.
/// - `an_already_fail_closed_gate` is the cell the role gate got wrong on its own terms. `Cfg NOT IN
///   Scalar` reaches `NotComparable` and so fails closed in this release already, which makes the
///   notice's premise that the pair "is currently read as not a member" false there. The 15-cell test
///   above carries the same shape as `a_scalar_denylist_that_already_fails_closed` and could not catch
///   this one, because `status_and_deprecations` wraps every cell in `rule r { .. }` and so only ever
///   measures the `Assertion` role.
///
/// The mixed clause is `Resources.*.Properties.Ports NOT IN [1, 3]` over `A: [1, 2]` and `B: [7, 8]`:
/// one value fails on the collision, the other does not. It appears three times -- asserted, gated, and
/// with `some` -- because `match_all` and not the role is what decides its verdict. All three are silent,
/// and the two that fail are silent for a different reason from the one that passes: the clause the change
/// moves has to have a pair nothing can decide, and this denylist has none. An earlier revision described
/// the passing one as passing "with the incomparability", which was the whole-value premise talking.
///
/// The passing cells therefore carry a denylist entry of another kind -- `[1, "x"]` or `[7, "x"]` rather
/// than `[1, 3]` or `[7, 8]` -- since that is what a clause whose answer the fail-closed release moves
/// looks like once the predicate asks about the pairs the operator built. Their statuses are the ones the
/// int-only spellings had, so the roles and the fold this table is about are unchanged.
///
/// Through `status_and_deprecations`' sibling rather than `recorded_comparison_messages`, for the
/// reason given on that helper: a notice never enters the record tree.
#[rstest::rstest]
// Clauses that reach PASS on a pair nothing can decide. These are the ones the change moves.
#[case::an_assertion_that_passes(
    "rule r { Resources.B.Properties.Ports NOT IN [1, \"x\"] }",
    Status::PASS,
    ExpectedNotice::Passed
)]
#[case::a_gate_that_passes(
    "rule r when Resources.A.Properties.Ports NOT IN [7, \"x\"] { Resources.A.Properties.Ports EXISTS }",
    Status::PASS,
    ExpectedNotice::Passed
)]
// `some` reaches PASS on one value while another fails, and the verdict is read under the query's own
// `match_all`, so the clause counts as passing and is eligible to be noticed. Whether it IS noticed is the
// predicate's question, and the answer here is no: every pair `contained_in` compares is int against int --
// `[1, 2]` collides with `1` element-wise and `[7, 8]` does not -- so nothing about this clause is
// undecidable and the fail-closed release leaves it where it is.
//
// This cell expected the notice while the predicate compared whole values, and that expectation was one of
// the false alarms the whole-value premise produced. It is the third of the mixed-clause trio below, so the
// three still differ only in role and quantifier. `a_some_clause_that_passes_on_a_refusal` is the paired
// cell that keeps `some` covered in the other direction.
#[case::a_some_clause_one_value_of_which_fails(
    "rule r { some Resources.*.Properties.Ports NOT IN [1, 3] }",
    Status::PASS,
    ExpectedNotice::Silent
)]
// The same shape with one denylist entry of another kind, which is what makes the clause's answer rest on
// a pair nothing can decide: `7` and `8` are answered against `1` and refuse against `"x"`. `some` is what
// carries the clause to PASS while `A` fails on its collision, so this is where the `match_all`-aware
// verdict reading in `clause_passed` is observable through a notice.
#[case::a_some_clause_that_passes_on_a_refusal(
    "rule r { some Resources.*.Properties.Ports NOT IN [1, \"x\"] }",
    Status::PASS,
    ExpectedNotice::Passed
)]
// Clauses the change leaves where they are: the two below do not pass at all, and the `some` cell above
// passes with every pair answered.
#[case::an_assertion_that_fails(
    "rule r { Resources.A.Properties.Ports NOT IN [1, 3] }",
    Status::FAIL,
    ExpectedNotice::Silent
)]
#[case::a_gate_that_fails(
    "rule r when Resources.A.Properties.Ports NOT IN [1, 3] { Resources.A.Properties.Ports EXISTS }",
    Status::SKIP,
    ExpectedNotice::Silent
)]
#[case::a_mixed_clause_asserted(
    "rule r { Resources.*.Properties.Ports NOT IN [1, 3] }",
    Status::FAIL,
    ExpectedNotice::Silent
)]
#[case::a_mixed_clause_gated(
    "rule r when Resources.*.Properties.Ports NOT IN [1, 3] { Resources.A.Properties.Ports EXISTS }",
    Status::SKIP,
    ExpectedNotice::Silent
)]
// A filter predicate is a gate as well, and this one narrowed the selection to nothing.
#[case::a_filter_predicate_that_selected_nothing(
    "rule r { Resources.*[ Properties.Ports NOT IN [1, 3, 7, 9] ].Properties.Ports EXISTS }",
    Status::SKIP,
    ExpectedNotice::Silent
)]
// Controls.
#[case::a_passing_gate_beside_a_failing_body(
    "rule r when Resources.A.Properties.Ports NOT IN [7, \"x\"] { Resources.A.Properties.Missing EXISTS }",
    Status::FAIL,
    ExpectedNotice::Passed
)]
#[case::a_gate_that_fails_on_comparable_values(
    "rule r when Resources.A.Properties.Ports NOT IN [[1, 2]] { Resources.A.Properties.Ports EXISTS }",
    Status::SKIP,
    ExpectedNotice::Silent
)]
#[case::an_already_fail_closed_gate(
    "rule r when Cfg NOT IN Scalar { Resources.A.Properties.Ports EXISTS }",
    Status::SKIP,
    ExpectedNotice::Silent
)]
fn the_incomparable_membership_notice_is_emitted_where_fail_closed_moves_the_clause(
    #[case] rules: &str,
    #[case] expected: Status,
    #[case] expected_notice: ExpectedNotice,
) -> Result<()> {
    // `A` collides with `[1, 3]` element-wise and `B` does not, so one document serves the assertion
    // cells, the gate cells and the mixed clause that needs both answers at once. `Cfg` and `Scalar`
    // are a pair `compare_eq` has no arm for, which is how `an_already_fail_closed_gate` reaches the
    // `NotComparable` this release already refuses on.
    const INPUT: &str = r#"
    {
        Cfg: { a: 1 },
        Scalar: "a",
        Resources: {
            A: { Properties: { Ports: [1, 2] } },
            B: { Properties: { Ports: [7, 8] } }
        }
    }
    "#;

    let (status, notices) = deprecations_for_rules(rules, INPUT)?;

    assert_eq!(
        expected, status,
        "`{}` changed verdict; this is a diagnostics fix and must move no status",
        rules
    );

    assert_notice(rules, status, expected_notice, &notices);

    Ok(())
}

/// A regex that ran out of backtracking budget is not an incomparable pair, and gets no notice.
///
/// `incomparable_membership` decides comparability with `compare_eq(..).is_ok()`, and `fancy_regex`
/// answers `Err` when its backtracking engine gives up rather than when the operands cannot be
/// compared. A `String` against a `Regex` is a pair `compare_eq` has an arm for -- it builds the
/// pattern and runs it -- so an exhausted budget arrives as `Error::RegexError` from a comparison that
/// was perfectly well typed. Read as incomparability, it produces a notice whose stated reason is
/// wrong: the values were comparable and the engine quit.
///
/// This was latent while the notice was gated on the verdict alone, because these clauses fail --
/// `match_value` promotes `RegexError` -- and a failing clause was suppressed. It stops being latent as
/// soon as a failure that nothing reports is noticed again, which is what the gate above now does. So
/// the two changes have to arrive together: measured on the tree before this, `rule r when Cat[*] NOT
/// IN [/(?!x)((a+)+)b/] { ... }` over thirty `a` characters exits 0 with a notice saying the value
/// could not be compared with any element of the list.
///
/// The third cell is what makes the fix narrow rather than a blanket silence, and it is a fact about
/// `compare_eq`'s arms rather than a judgment call. `(String, Regex)` is an arm, so a spent budget
/// there is a `RegexError`. `(List, Regex)` is not an arm at all: it falls through to `compare_values`,
/// whose catch-all refuses with `NotComparable`, which is a real incomparability and keeps its notice.
/// The last cell does NOT follow from the same fact, and reading it that way is the mistake worth
/// naming here. "`(List, Regex)` is not an arm, so the whole-list spelling never reaches the engine"
/// joins a premise to a conclusion, and the conclusion fails under both readings of what it is about.
///
/// Of `incomparable_membership` it was true only for a FLAT denylist, and only while that predicate
/// compared the WHOLE left-hand value against each element of the right-hand side flattened one level.
/// Then `Cat NOT IN [/re/]` asked `compare_eq(List, Regex)` and refused without running anything, while
/// `Cat NOT IN [[/re/]]` was handed `(List, List)`, which zips into `(String, Regex)` and runs the
/// pattern -- so the predicate reached the engine on a whole-list left-hand side too, and the sentence was
/// never true of it in general, only of the input this cell happens to use. Both operands are flattened
/// now, so the two spellings have swapped: the flat one builds `(String, Regex)` and reaches the engine,
/// and the nested one builds `(String, List)` and refuses. Neither is observable here, because both
/// clauses fail and the verdict gate suppresses the notice either way.
///
/// Of the CLAUSE it is false for the flat spelling as well, because the clause also runs
/// `contained_in`'s element-wise pass, where each String element of `Cat` meets the `Regex` through the
/// `(String, Regex)` arm that builds the pattern and runs it. One sentence about which arms exist got
/// read as a sentence about a clause, and the cell then pinned a verdict the predicate has no say over.
///
/// So the last cell is a `RegexError` case after all, and it now refuses. Measured on this input:
/// `One not in [/re/]` for a scalar `One` exits 19 with the reason, `Cat[*] not in [/re/]` exits 19 with
/// the reason, and `Cat not in [/re/]` exited 0 with a notice. Two spellings of one question already
/// answered 19, and this cell pinned the third as correct. `operators.rs` states the requirement it
/// broke: a regex `compare_eq` could not evaluate "is read rather than discarded, which is what makes
/// `Port in [/re/]` answer the same way as `Port == /re/`".
///
/// # Why `Silent` is right on the gate cells, and why they no longer say nothing at all
///
/// An earlier revision justified `Silent` here with "the clause now fails AND the report names the regex".
/// The first half held everywhere; the second was true only of the assertion cells. Measured before
/// `undecided_gate`: `rule r when Cat[*] NOT IN [/re/] { Cat EXISTS }` exited 0 with **zero bytes on stdout
/// and zero on stderr**, and so did the `[[/re/]]` spelling, whose `(List, List)` pair reaches the engine
/// through the zip. Asserted, the same clause exited 19 with about 500 bytes naming the regex. So two of
/// these cells pinned a run that reported nothing whatsoever about a clause the tool could not evaluate,
/// and a justification resting on the report was resting on the wrong role.
///
/// `Silent` stands anyway, and not by inertia. This notice makes one claim -- a future release fails closed
/// where this one passes -- and both halves of it are false here. The pair was comparable in kind and the
/// engine gave up, so there is no incomparable pair to warn about; and the clause does not pass, so the
/// fail-closed change does not move it. A notice would be two false sentences bought to fill a silence.
///
/// **That silence was a real defect, it was not this one, and `undecided_gate` is what closed it.** The
/// note this replaces said the gap "predates every commit on this branch" and that closing it "means making
/// an unevaluatable gate visible in the report rather than borrowing a deprecation notice to stand in for
/// it". That is exactly what happened, through the verdict rather than through report text: a spent budget
/// in a gate is now an `IncompatibleError`, so `eval_rule` fails the rule closed instead of mapping a
/// per-value FAIL to a rule-level SKIP. The two gate cells above therefore expect FAIL, and the run that
/// produced zero bytes now exits 19 naming the rule and the reason. The assertion cells are unchanged and
/// are the control: they already failed closed with the clause and operands named, and converting there
/// would have replaced that with a rule-level failure and lost the comparison record.
///
/// **The silence is still there for one cell**, and that is the boundary this test now marks.
/// `an_ordinary_regex_against_a_whole_list_in_a_condition` stays SKIP at exit 0 with nothing reported. Its
/// FAIL is a *decided* one -- the element matches the pattern -- so no comparison result carries an
/// undecided answer and `undecided_gate` has nothing to read. Its own cell comment traces the two operand
/// shapes that make the predicate and the verdict disagree there.
///
/// The wider boundary is a refusal to compare *kinds*, which a gate must keep absorbing even when a
/// comparison result does carry it. Rule authors write a value against both spellings it might carry --
/// `ScanOnPush == 'False' OR ScanOnPush == false` is the registry's canonical shape -- and rely on the
/// pairing that does not apply answering "no" rather than "unknown". Measured: reading every undecided
/// comparison as unknown moves 143 rules of the pinned aws-guard-rules-registry corpus off their
/// expectations, most of them suppression tests expecting SKIP, against 0 failed rules at the base.
/// `ECR_REPO_SCAN_ON_PUSH` fails on a compliant template that way.
///
/// So `Unanswerable` splits the two causes and only `EngineGaveUp` fails a gate closed. That leaves the
/// kind-mismatch half open, tracked in `docs/KNOWN_ISSUES.md`, whose repair still needs those registry
/// rules changed first -- exactly the precondition `incomparable_membership_notice` already records.
#[rstest::rstest]
// The pattern is `CATASTROPHIC`, spelled out because a `#[case]` attribute cannot interpolate a const.
#[case::a_catastrophic_regex_in_a_condition_fails_closed(
    "rule r when Cat[*] NOT IN [/(?!x)((a+)+)b/] { Cat EXISTS }",
    Status::FAIL,
    ExpectedNotice::Silent
)]
#[case::a_catastrophic_regex_asserted(
    "rule r { Cat[*] NOT IN [/(?!x)((a+)+)b/] }",
    Status::FAIL,
    ExpectedNotice::Silent
)]
// Silent because the clause does not pass, not because the pair is comparable: `(List, Regex)` is not
// a `compare_eq` arm, so the whole-list comparison is a real incomparability and the predicate fires.
// It was the did-not-pass wording while a failing gate was noticed, and that wording is gone with the
// gate that reached it -- a gate that fails answers the same before and after the fail-closed change.
//
// SKIP rather than FAIL, and this is the cell that separates `undecided_gate` from the predicate above
// it. The clause is decided element by element, where `"aaa..."` against `/^a+$/` matches -- so
// `contained_in` answers Success, `NOT IN` negates it, and the FAIL is a decided verdict with no undecided
// comparison result anywhere in it. `undecided_gate` reads the results, finds nothing undecided, and
// declines.
//
// The predicate declines too, and it used to fire: probing the whole left-hand value gave it
// `compare_eq(Cat, /^a+$/)`, which is not an arm and refused, and only the verdict gate stood between that
// refusal and a notice on a clause the regex plainly answered. It compares elements now, gets the match,
// and has nothing to report. So this cell is `Silent` twice over, and the surviving half of what it marks
// is the report: the run says nothing at all about a clause it could not evaluate, because its FAIL is
// decided and no result carries an undecided answer.
#[case::an_ordinary_regex_against_a_whole_list_in_a_condition(
    "rule r when Cat NOT IN [/^a+$/] { Cat EXISTS }",
    Status::SKIP,
    ExpectedNotice::Silent
)]
#[case::a_comparable_element_beside_the_catastrophic_one_fails_closed(
    "rule r when Mixed[*] NOT IN [/(?!x)((a+)+)b/] { Mixed EXISTS }",
    Status::FAIL,
    ExpectedNotice::Silent
)]
#[case::the_whole_list_spelling_now_refuses(
    "rule r { Cat NOT IN [/(?!x)((a+)+)b/] }",
    Status::FAIL,
    ExpectedNotice::Silent
)]
fn a_spent_backtracking_budget_is_not_an_incomparable_pair(
    #[case] rules: &str,
    #[case] expected: Status,
    #[case] expected_notice: ExpectedNotice,
) -> Result<()> {
    // Thirty `a` characters is the length at which `(?!x)((a+)+)b` exhausts the budget, the same
    // subject `a_regex_that_exceeds_the_backtrack_limit_fails_the_clause_instead_of_aborting` uses.
    // `Mixed` carries one element the pattern answers on, so the clause has a pair that decides beside the
    // one that gave up and a cell can tell the two causes apart. That was written when one comparable pair
    // silenced the notice by itself; it no longer does, and the cell is silent because nothing here
    // refuses -- neither `(String, Regex)` pair is a kind mismatch.
    const INPUT: &str = r#"
    {
        Cat: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
        Mixed: ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "ok"]
    }
    "#;

    let (status, notices) = deprecations_for_rules(rules, INPUT)?;

    assert_eq!(
        expected, status,
        "`{}` changed verdict; this is a diagnostics fix and must move no status",
        rules
    );

    assert_notice(rules, status, expected_notice, &notices);

    Ok(())
}

/// One value's spent regex budget does not silence the notice another value earned.
///
/// `incomparable_membership` walks every left-hand value against every right-hand element and returns on
/// the first `RegexError`, which is a decision about the whole clause taken on the evidence of one pair.
/// The pair it is right about is its own: a spent backtracking budget means the operands were of
/// comparable kinds and the engine quit, so that pair is not an incomparability and must not produce a
/// notice. What does not follow is that no *other* pair is one.
///
/// The cells are the isolation. `A` is a string thirty `a` characters long, which exhausts the budget
/// against this pattern; `B` is a list of ints, and `(Int, Regex)` is not a `compare_eq` arm at all, so
/// its pairs refuse with `NotComparable` -- a real incomparability, and the shape the notice exists for.
/// Measured before this: `B` alone earns the notice, `A` alone earns nothing and fails, and the two
/// together earn nothing. Adding `A` to the query destroyed the warning `B` was owed, on a clause that
/// passes.
///
/// `B`'s refusal used to be the whole-value pair `(List, Regex)` rather than its elements. The predicate
/// flattens both operands now, so the refusing pairs are `(1, /re/)` and `(2, /re/)`; the cell is
/// unchanged because neither reading can compare an int with a pattern.
///
/// `some` is required and is not incidental. A value whose pair exhausts the budget fails its own
/// `contained_in` pass, because `match_value` promotes `RegexError`, so under `match_all` the clause
/// cannot pass and the verdict gate suppresses the notice for a reason that has nothing to do with this
/// defect. `some` lets `B` carry the clause to PASS while `A` fails, which is the only shape where the
/// early return is observable through the gate at all.
///
/// So the silencing is per pair: a `RegexError` pair is passed over and the notice goes out if some other
/// pair refused. It used to say "and none was answered", because an answered pair returned for the whole
/// clause; that early return is gone, for the reason `incomparable_membership` now records -- a value
/// passes `NOT IN` by matching nothing, so an answered pair says only that this element was not the
/// collision. `a_comparable_element_beside_the_catastrophic_one_fails_closed` in the test above still
/// expects silence and still gets it, because nothing in that clause refuses: one pair spends the budget
/// and the other answers.
#[rstest::rstest]
// The list value alone. Its pair refuses, the clause passes, and the notice is owed.
#[case::a_refusing_pair_alone("some Multi.B.V NOT IN [/(?!x)((a+)+)b/]", Status::PASS, true)]
// Both values. The same refusing pair is still there, and so is the notice.
#[case::a_refusing_pair_beside_a_spent_budget(
    "some Multi.*.V NOT IN [/(?!x)((a+)+)b/]",
    Status::PASS,
    true
)]
// The spent budget alone. Nothing refused, so nothing is owed -- and the clause fails, because
// `match_value` promotes the error.
#[case::a_spent_budget_alone("some Multi.A.V NOT IN [/(?!x)((a+)+)b/]", Status::FAIL, false)]
fn a_spent_budget_on_one_value_does_not_silence_another_values_notice(
    #[case] clause: &str,
    #[case] expected: Status,
    #[case] expect_notice: bool,
) -> Result<()> {
    // Thirty `a` characters is the length at which `(?!x)((a+)+)b` exhausts the budget, matching the
    // test above. `B` holds ints so that its pairs against the pattern reach `compare_values`' catch-all
    // rather than the regex engine, whichever granularity the predicate compares at.
    const INPUT: &str = r#"
    {
        Multi: {
            A: { V: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
            B: { V: [1, 2] }
        }
    }
    "#;

    let (status, notices) = deprecations_for_rules(&format!("rule r {{ {clause} }}"), INPUT)?;

    assert_eq!(
        expected, status,
        "`{}` changed verdict; this is a diagnostics fix and must move no status",
        clause
    );

    assert_membership_notice(clause, status, expect_notice, &notices);

    Ok(())
}

/// What a clause answers when its values carry a mix of decided and undecided comparisons.
///
/// Three answers rather than a `Status`, because that is the shape of the question and `Status` cannot
/// hold it. A gate needs to tell "decided, and the answer is no" from "no answer", and both arrive as
/// `Status::FAIL` on the values. The evaluator carries the difference in the `Result`, not the `Status`:
/// a decided no is `Ok(FAIL)` and no answer is an `Err` the caller splits by role.
#[derive(Debug, PartialEq, Eq)]
enum ClauseAnswer {
    /// Decided, and the clause does not hold.
    DecidedNo,
    /// Decided, and the clause holds.
    DecidedYes,
    /// No answer either way.
    NoAnswer,
}

/// The three-valued table a clause's answer has to follow, over every combination of value kinds.
///
/// # Why this is a table and not two cells
///
/// `undecided_gate` reads a vector of per-value statuses and decides whether the clause has an answer.
/// That is three-valued logic over a quantifier, and it has two arms that are mirror images:
///
///     match_all  ->  no if ANY value is decided-no;  unknown if none is and some value is unknown
///     some       ->  yes if ANY value is decided-yes; unknown if none is and some value is unknown
///
/// The first version of this fix implemented the `some` arm and left the `match_all` arm returning
/// unknown on `reason.is_some()` alone. That is wrong for the reason the table makes obvious:
/// `AND(no, unknown)` is `no`, not unknown, because a clause needing every value is already decided the
/// moment one value definitively fails. Measured on `Cat = [<thirty a characters>, "zzz"]` against
/// `Cat[*] NOT IN [/(?!x)((a+)+)b/, "zzz"]`, before this commit: a rule whose gate was that clause went
/// from not-applicable to a reported violation, because an undecided sibling was read as making an
/// already-decided conjunction unknown.
///
/// A two-cell test would have pinned exactly that pair and nothing around it, which is how the defect
/// got in: the change that introduced it was checked against three shapes, and both wrong cells were
/// outside those three. So this enumerates all seven non-empty subsets of {undecided, decided-no,
/// decided-yes} against both quantifiers, and asserts the whole table rather than the diff.
///
/// # Reading a cell
///
/// The clause is evaluated directly rather than through a rule, so the answer is observed where it is
/// made. One level up a gate turns `DecidedNo` into a rule-level SKIP and an `Err` into a rule-level
/// failure -- indistinguishable as exit codes, which is why asserting on the rule would need the
/// rendered message to tell the two apart. `.github/scripts` has no oracle for this; the end-to-end
/// spelling is `an_undecided_membership_gate_fails_the_rule_closed` in `guard/tests/validate.rs`.
///
/// The `Assertion` half is the control, and it is the same table flattened: an assertion has no use for
/// the third value, so `NoAnswer` becomes `Ok(FAIL)` and every row that is not decided-yes fails. It
/// must not move, because an assertion's report names the clause and its operands.
#[test]
fn a_clauses_answer_follows_three_valued_logic_over_every_value_combination() -> Result<()> {
    // Thirty `a` characters is the length at which this pattern exhausts `fancy_regex`'s backtracking
    // budget, so the pair is comparable in kind and has no answer. `"zzz"` is named by the denylist, so
    // `NOT IN` decides no. `"q"` is named by neither, so `NOT IN` decides yes.
    const UNDECIDED: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DECIDED_NO: &str = "zzz";
    const DECIDED_YES: &str = "q";
    const DENYLIST: &str = r#"[/(?!x)((a+)+)b/, "zzz"]"#;

    use ClauseAnswer::{DecidedNo, DecidedYes, NoAnswer};

    // (label, values, match_all answer, some answer)
    let table = [
        ("U", vec![UNDECIDED], NoAnswer, NoAnswer),
        ("F", vec![DECIDED_NO], DecidedNo, DecidedNo),
        ("P", vec![DECIDED_YES], DecidedYes, DecidedYes),
        ("UF", vec![UNDECIDED, DECIDED_NO], DecidedNo, NoAnswer),
        ("UP", vec![UNDECIDED, DECIDED_YES], NoAnswer, DecidedYes),
        ("FP", vec![DECIDED_NO, DECIDED_YES], DecidedNo, DecidedYes),
        (
            "UFP",
            vec![UNDECIDED, DECIDED_NO, DECIDED_YES],
            DecidedNo,
            DecidedYes,
        ),
    ];

    for (label, values, expected_all, expected_some) in table {
        let mut input = String::from("Cat:\n");
        for v in &values {
            input.push_str("  - ");
            input.push_str(v);
            input.push('\n');
        }
        let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_yaml::Value>(&input)?)?;

        for (quantifier, expected) in [("", &expected_all), ("some ", &expected_some)] {
            let clause_str = format!("{}Cat[*] NOT IN {}", quantifier, DENYLIST);
            let clause = GuardClause::try_from(clause_str.as_str())?;

            let mut eval = BasicQueryTesting {
                root: Rc::new(value.clone()),
                recorder: None,
            };
            let answer = match eval_guard_clause(&clause, &mut eval, ClauseRole::Gate) {
                Ok(Status::PASS) => DecidedYes,
                Ok(Status::FAIL) => DecidedNo,
                Ok(other) => panic!("`{}` on {} answered {:?}", clause_str, label, other),
                Err(e) => {
                    assert!(
                        is_unevaluatable(&e),
                        "`{}` on {} raised an error the evaluator does not classify as \
                         unevaluatable, so every role-split site would propagate it and abort the \
                         run instead of failing the clause: {}",
                        clause_str,
                        label,
                        e
                    );
                    NoAnswer
                }
            };
            assert_eq!(
                *expected, answer,
                "`{}` over {} answered {:?} as a gate, expected {:?}. A gate that answers \
                 `NoAnswer` fails its rule closed; one that answers `DecidedNo` reports the rule as \
                 not applicable. Getting those two the wrong way round either invents a violation \
                 or drops a check at exit 0.",
                clause_str, label, answer, expected
            );

            // The assertion control: no third value, so anything not decided-yes fails, and nothing
            // reaches the caller as an error.
            let mut eval = BasicQueryTesting {
                root: Rc::new(value.clone()),
                recorder: None,
            };
            let asserted = eval_guard_clause(&clause, &mut eval, ClauseRole::Assertion)?;
            let expected_asserted = match expected {
                DecidedYes => Status::PASS,
                _ => Status::FAIL,
            };
            assert_eq!(
                expected_asserted, asserted,
                "`{}` over {} answered {:?} as an assertion, expected {:?}; the assertion half of \
                 this table must not move",
                clause_str, label, asserted, expected_asserted
            );
        }
    }

    Ok(())
}

/// Which stderr line a cell of the two tests above expects, so each one names the wording rather than
/// only whether something arrived.
///
/// Two states rather than a `bool`, and the second carries the wording rather than only presence,
/// because the defect f3eb258 fixed was a notice that said "passed because" beside a clause that had
/// failed. A cell asserting presence alone is satisfied by that notice, so `Passed` checks the sentence
/// as well.
///
/// There were three states while a non-passing clause could be noticed too, for a body that said the
/// clause did not pass and that nothing reported it. Both halves of that body were false in reachable
/// cases -- the report names a failing gate whenever a later clause in the same rule fails, and a pair
/// that already reaches `NotComparable` is not one "currently read as not a member" -- and the class it
/// went out on does not move under the coming change at all. The body and the state went together with
/// the gate that reached them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExpectedNotice {
    /// No incomparable-membership notice at all.
    Silent,
    /// The notice for a clause the incomparability let pass.
    Passed,
}

/// A clause that must emit the incomparable-membership notice, run beside every cell that asserts the
/// notice stayed away.
///
/// # Why this exists
///
/// A cell of the form "this clause emits no membership notice" passes in two different worlds: the clause
/// is correctly quiet, or `incomparable_membership` answers false for everything and the channel is dead.
/// A predicate over an absence cannot separate them, and this file had thirty-seven such cells --
/// thirteen `ExpectedNotice::Silent` and twenty-four `false` notice columns. Silencing the predicate at
/// its source reddened only the cells expecting a notice; every silent cell stayed green while checking
/// nothing.
///
/// # What was tried and rejected
///
/// Asserting the diagnostic the cell's own clause emits instead. That is the stronger claim wherever it
/// is available -- it is what `every_string_spelling_warns_through_the_channel_that_is_true_of_it` does --
/// and it is available for two cells out of the thirty-seven. Measured on 2026-09-03 over every silent
/// cell in this file: `Empty NOT IN "abc"` and `Empty NOT IN Ustr` record the vacuous notice, and the
/// other thirty-five record nothing whatsoever. A clause with no diagnostic of its own has nothing to
/// name, so the liveness has to come from elsewhere in the same run.
///
/// A sibling `true` cell of the same table was rejected as that elsewhere. rstest generates one test per
/// cell, so a sibling is a separate run: it proves the channel was live in ITS process and says nothing
/// about this one. It also goes when the cell goes, so a table that loses its positive group loses its
/// liveness without any cell reddening.
///
/// # What this proves and what it does not
///
/// It proves the channel was live in this process. It does not prove the caller's own clause reached the
/// predicate, and nothing over an absence can, which is why the failure message says that rather than
/// implying coverage the cell does not have.
///
/// `Map NOT IN Haystack` is the control because it is measured live rather than assumed -- it is a
/// notice-expecting cell of two tables in this file, `a_map_against_a_scalar_denylist` and
/// `a_left_hand_value_that_is_not_a_list_is_not_flattened` -- and because it is the miniature of the five
/// aws-guard-rules-registry notices the corpus check pins. A map is not a list, so nothing about it
/// flattens and neither the granularity fix nor the shape refusal reaches it.
fn assert_the_membership_channel_is_live() {
    let (status, notices) =
        status_and_deprecations(MEMBERSHIP_CONTROL_CLAUSE, MEMBERSHIP_CONTROL_INPUT)
            .expect("the membership control must evaluate");
    assert_the_membership_channel_is_live_given(status, &notices);
}

/// The clause whose notice stands in for the channel, and the document it is asked of.
///
/// Named rather than inlined so that the negative control below can state what it is a control FOR.
const MEMBERSHIP_CONTROL_CLAUSE: &str = "Map NOT IN Haystack";
const MEMBERSHIP_CONTROL_INPUT: &str = r#"
{
    Map: { a: 1 },
    Haystack: [7, "zzz", false]
}
"#;

/// Whether a run's notices carry the incomparable-membership one.
///
/// The one place this substring is written. It was written in four, and a predicate duplicated per caller
/// is a predicate that can be loosened in one of them: widening any single copy to `"DEPRECATION"` or
/// `"could not be"` makes the vacuous notice satisfy it, which is the precise failure the stay-quiet
/// control in `validate.rs` shipped with for one commit. One definition, one negative control over it.
fn membership_notice_present(notices: &[String]) -> bool {
    !membership_notices(notices).is_empty()
}

/// The matching notices themselves, for the one caller that checks their wording as well as their arrival.
///
/// `membership_notice_present` is defined over this rather than beside it, so the substring has exactly one
/// home and the negative control covers both readings of it.
fn membership_notices(notices: &[String]) -> Vec<&String> {
    notices
        .iter()
        .filter(|n| n.contains("could not be compared with any element"))
        .collect()
}

/// The assertions of the liveness control, split from the run that feeds them.
///
/// Split so that `the_liveness_control_reddens_when_the_channel_is_dead` can hand these the notices a dead
/// channel produces and require them to fire. Without that, the control itself is unguarded: it is a
/// shared dependency of every silent cell in this file, and deleting its `assert!` would return all of
/// them to passing vacuously with nothing anywhere going red. A control that cannot be shown to fail is
/// the defect this whole class is about, one level up.
fn assert_the_membership_channel_is_live_given(status: Status, notices: &[String]) {
    assert_eq!(
        Status::PASS,
        status,
        "`{}` must pass on the incomparability for the notice below to be owed; a FAIL here means the \
         control is broken rather than the cell that called it",
        MEMBERSHIP_CONTROL_CLAUSE
    );
    assert!(
        membership_notice_present(notices),
        "`{}` must emit the incomparable-membership notice, so that a cell asserting the absence of \
         that notice is asserting something. Nothing emitted it here, which means the channel is dead \
         and the caller's silence is not evidence about the caller's clause. Recorded {:?}",
        MEMBERSHIP_CONTROL_CLAUSE,
        notices
    );
}

/// The liveness control's own negative control: it must reject a dead channel.
///
/// # Why this exists
///
/// `assert_the_membership_channel_is_live` is what makes thirty-eight silent cells in this file
/// non-vacuous, which makes it a single point of failure for the class. Silencing
/// `incomparable_membership` at its source reddens all thirty-eight, so the control demonstrably detects
/// a dead channel today. That is not the same as the control being guarded: weaken it -- delete the
/// `assert!`, loosen the substring, swap the clause for one that always warns -- and every one of those
/// cells goes back to passing on an absence, with nothing red anywhere. The suite would report 3103 green
/// while checking the same nothing it checked before this branch.
///
/// So the control is required to fail. Each row is a way the channel dies, and the third is not
/// hypothetical: a control asserting only that *some* deprecation line arrived is what the stay-quiet test
/// in `validate.rs` shipped with, and it stayed green with the membership predicate silenced because the
/// fixture's other clause kept warning.
///
/// # What was tried and rejected
///
/// Asserting the predicate alone, without `catch_unwind`. That guards the substring but not the
/// `assert!` that consumes it, and the deletion case is the likelier edit -- a helper whose body is
/// trimmed during a refactor. The panic is the thing the callers depend on, so the panic is what is
/// measured.
///
/// Swapping the panic hook to suppress the expected backtraces was rejected. `panic::set_hook` is
/// process-global, so under a parallel run it would swallow a genuinely failing test's message for the
/// duration and make that failure harder to read. The printed panics below are expected output.
///
/// # Known limitation
///
/// This cannot catch the control being deleted from its CALLERS. Nothing over an absence can: a cell that
/// no longer calls the control is a cell with no liveness half, and it looks exactly like the cells this
/// branch started from. `git grep -c assert_the_membership_channel_is_live` is the check for that, and
/// the count belongs in the review rather than in a test.
#[test]
fn the_liveness_control_reddens_when_the_channel_is_dead() {
    const VACUOUS: &str = "DEPRECATION: Empty not IN  Ustr passed without comparing anything, \
                           because the query selected an empty collection.";

    for (why, notices) in [
        (
            "total silence, which is what a dead predicate produces",
            vec![],
        ),
        (
            "the other channel alone, which is what silencing only this predicate produces",
            vec![VACUOUS.to_string()],
        ),
        (
            "a deprecation line that is not this notice, which a prefix-only control accepts",
            vec!["DEPRECATION: something else entirely".to_string()],
        ),
    ] {
        assert!(
            !membership_notice_present(&notices),
            "{}: the predicate must reject this, or every silent cell in this file is satisfied by it",
            why
        );

        // The panic, not just the predicate: the callers depend on this function refusing, and a body
        // trimmed to nothing would still satisfy the assertion above.
        let outcome = std::panic::catch_unwind(|| {
            assert_the_membership_channel_is_live_given(Status::PASS, &notices)
        });
        assert!(
            outcome.is_err(),
            "{}: the liveness control must panic on a dead channel. It did not, so it is no longer a \
             control, and the cells that call it are asserting absences nothing checks.",
            why
        );
    }

    // And it accepts the live channel, measured from a real run rather than from a literal, so the three
    // refusals above are not the refusals of a predicate that rejects everything.
    let (status, notices) =
        status_and_deprecations(MEMBERSHIP_CONTROL_CLAUSE, MEMBERSHIP_CONTROL_INPUT)
            .expect("the membership control must evaluate");
    assert!(
        membership_notice_present(&notices),
        "the control clause must still emit the notice, or the rejections above are vacuous too; \
         recorded {:?}",
        notices
    );
    assert_the_membership_channel_is_live_given(status, &notices);
}

/// Checks a cell's membership-notice expectation, and on the silent side proves the channel was live.
///
/// The four boolean tables above each carried their own copy of this block, and each copy's `false` side
/// was an absence nothing separated from total silence. One helper, so the liveness arrives with the
/// expectation rather than having to be remembered per table.
fn assert_membership_notice(
    subject: &str,
    status: Status,
    expect_notice: bool,
    notices: &[String],
) {
    assert_eq!(
        expect_notice,
        membership_notice_present(notices),
        "`{}` reached {:?}, so the incomparable-membership notice should {}; recorded {:?}",
        subject,
        status,
        match expect_notice {
            true => "have been emitted",
            false => "have stayed silent",
        },
        notices
    );

    if !expect_notice {
        assert_the_membership_channel_is_live();
    }
}

/// Checks the membership notices a run recorded against what the cell expects.
///
/// Every matching notice is checked rather than one of them, because a cell that only looks for the
/// wording it wants is satisfied by that notice arriving beside one carrying the other wording, which
/// is a state where an author reading the wrong one is told the wrong thing.
///
/// The `Silent` arm calls `assert_the_membership_channel_is_live`, for the reason given there: on its own
/// it is satisfied by a build that emits this notice for nothing at all.
fn assert_notice(rules: &str, status: Status, expected: ExpectedNotice, notices: &[String]) {
    let membership = membership_notices(notices);

    match expected {
        ExpectedNotice::Silent => {
            assert!(
                membership.is_empty(),
                "`{}` reached {:?} with nothing for this notice to say, so it should have stayed \
                 silent; recorded {:?}",
                rules,
                status,
                notices
            );
            assert_the_membership_channel_is_live();
        }
        // Which wording, not just whether one arrived. The notice that says "passed because" on a
        // clause that did not pass is the contradiction f3eb258 removed, and emitting on a wider set of
        // clauses is a route back to it.
        ExpectedNotice::Passed => {
            assert!(
                !membership.is_empty(),
                "`{}` passed on the incomparability, so the notice should have been emitted; \
                 recorded {:?}",
                rules,
                notices
            );
            assert!(
                membership.iter().all(|n| n.contains("passed because")),
                "`{}` passed, so every membership notice must say so; recorded {:?}",
                rules,
                membership
            );
        }
    }
}

/// The notice fires on exactly the clauses the coming fail-closed change moves, measured rather than
/// asserted.
///
/// The table above says which cells expect a notice, and a table can be wrong in the same direction as
/// the code it checks -- which is how the previous gate shipped: it was widened to a class of clauses,
/// the cells for that class were written to expect the notice, and both agreed on a claim that was
/// false. Nothing in that suite measured the property the notice actually asserts.
///
/// This does, and `!=` is what makes it possible. The notice's own text names it -- "a future release
/// fails closed here, as `!=` already does" -- and for a scalar left-hand side against a one-element
/// denylist, `X NOT IN [v]` and `X != v` ask exactly the same question of exactly the same pair. One
/// answers it by reading an incomparable pair as "not a member" and the other by refusing it, so the pair
/// of spellings is this release's before and after. Each cell evaluates both and compares the statuses,
/// so "does this clause move" is read off the language rather than taken from a table, and the notice
/// expectation is checked against that measurement. The two assertions are independent: a change to the
/// gate cannot satisfy the first, and a change to `!=` cannot satisfy the second.
///
/// **One element in the denylist and a scalar on the left, both required.** A second element gives the
/// clause a pair `!=` never sees, so the two spellings stop being the same question. And `!=` on a
/// list-valued left-hand side is not the fail-closed spelling of `NOT IN` on one: `NOT IN` reads a list
/// element-wise through `contained_in` while `!=` compares the whole value, so the pair of clauses would
/// differ in what they compare as well as in how they treat a refusal, and the measurement would not be
/// about the notice at all.
///
/// Substituting the right-hand side for one nothing can be compared with was tried first and is wrong,
/// which is worth recording because it looks equivalent. `NOT IN` over such an operand does not fail
/// closed; it passes, for the same reason the notice exists. Measured: `Str NOT IN Umap` over `{"k": 1}`
/// exits 0 with the notice, so a cell asserting it as the fail-closed destination compares PASS against
/// PASS and concludes that nothing moves.
#[rstest::rstest]
// A scalar that passes because the one element cannot be compared with it. `!=` refuses that pair, so
// this is a clause the change moves.
#[case::a_clause_that_passes_on_the_incomparability("Str", "1", true)]
// A scalar the denylist names. Both spellings fail, so it does not move.
#[case::a_clause_the_denylist_names("Int", "1", false)]
// A scalar the denylist does not name, compared with an element it can be compared with. Both pass, and
// the predicate never fires; the control for "moves" and "notice" agreeing on false for two reasons.
#[case::a_clause_decided_on_comparable_values("Int", "2", false)]
fn the_notice_fires_exactly_where_fail_closed_moves_the_answer(
    #[case] lhs: &str,
    #[case] denied: &str,
    #[case] moves: bool,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Str: "a",
        Int: 1
    }
    "#;

    let clause = format!("{lhs} NOT IN [{denied}]");
    let (live_status, notices) = deprecations_for_rules(&format!("rule r {{ {clause} }}"), INPUT)?;

    // The same question asked with the operator that already refuses what this one reads as a non-match.
    let fail_closed = format!("rule r {{ {lhs} != {denied} }}");
    let (fail_closed_status, _) = deprecations_for_rules(&fail_closed, INPUT)?;

    assert_eq!(
        moves,
        live_status != fail_closed_status,
        "`{}` reached {:?} and its fail-closed spelling `{}` reached {:?}, so the coming change {} \
         this clause; the cell says it {}",
        clause,
        live_status,
        fail_closed,
        fail_closed_status,
        match live_status != fail_closed_status {
            true => "moves",
            false => "leaves",
        },
        match moves {
            true => "moves",
            false => "does not move",
        }
    );

    assert_eq!(
        moves,
        membership_notice_present(&notices),
        "`{}` is a clause the change {}, so the notice should {}; recorded {:?}",
        clause,
        match moves {
            true => "moves",
            false => "leaves where it is",
        },
        match moves {
            true => "have been emitted",
            false => "have stayed silent",
        },
        notices
    );

    // The measurement above is about `!=`, not about the notice: silencing the predicate leaves both
    // statuses where they are, so the `moves == false` cells would keep passing with the channel dead.
    // The two assertions this test calls independent stay independent -- the control is a third
    // evaluation and reads neither of them.
    if !moves {
        assert_the_membership_channel_is_live();
    }

    Ok(())
}

/// Two different clauses that render the same text get two notices, not one.
///
/// Both deprecation notices are built from a context that is the clause's own `Display`, and both land in
/// `RootScope::deprecations`, which is a `BTreeSet`. A `Display` carries no rule name, no file and no
/// position, so two clauses that differ in something the rendering drops produce the same string and the
/// set keeps one of them. A variable is the cheapest way to reach that -- `%v NOT IN [1]` renders
/// identically however `v` is bound -- but it is not a special case: the collapse is available to any two
/// clauses whose text matches, in one rules file or across several.
///
/// Which is a correctness problem rather than untidy output. The notice exists to be worked through
/// before an upgrade, and an author who fixes the clause the surviving line appears to name has fixed one
/// of two clauses and has been told nothing about the other. The count is what misleads: two defective
/// clauses report as one.
///
/// So each notice names the source position of the clause it is about. That also has to leave dedup doing
/// its job, which is why `a_deprecation_notice_reaches_the_test_command` is the other half of this: it
/// asserts two notices from three test cases rather than six, and it holds because a position is fixed at
/// parse time and so is the same on every evaluation of the same clause. A qualifier that varied per
/// emission -- a counter, or the value that triggered it -- would satisfy this test and break that one.
///
/// Asserted as a set and not a count. Two notices whose texts are equal would pass a length check after a
/// change that made the set two entries wide for some other reason, and equal texts are the defect.
#[rstest::rstest]
#[case::the_incomparable_membership_notice(
    "rule a {\n  let v = L1\n  %v NOT IN [1]\n}\nrule b {\n  let v = L2\n  %v NOT IN [1]\n}",
    "could not be compared with any element"
)]
#[case::the_vacuous_comparison_notice(
    "rule a {\n  let v = E1\n  %v == 50\n}\nrule b {\n  let v = E2\n  %v == 50\n}",
    "without comparing anything"
)]
fn each_deprecation_notice_identifies_the_clause_it_is_about(
    #[case] rules: &str,
    #[case] marker: &str,
) -> Result<()> {
    // `L1`/`L2` are string lists against an integer denylist, so both membership clauses pass on the
    // incomparability. `E1`/`E2` are empty, so both vacuous clauses compare nothing and pass.
    const INPUT: &str = r#"
    {
        L1: ["a", "b"],
        L2: ["c", "d"],
        E1: [],
        E2: []
    }
    "#;

    let (status, notices) = deprecations_for_rules(rules, INPUT)?;

    assert_eq!(
        Status::PASS,
        status,
        "both clauses pass in this release; a notice must not have moved that"
    );

    let matched: Vec<&String> = notices.iter().filter(|n| n.contains(marker)).collect();
    assert_eq!(
        2,
        matched.len(),
        "two clauses reached this notice, so two lines are owed; got {:?}",
        matched
    );
    assert_ne!(
        matched[0], matched[1],
        "the two lines are byte-identical, so they would have collapsed in the set the notices are \
         collected in and the second clause would go unreported; got {:?}",
        matched
    );

    Ok(())
}

/// `or` is decided by whichever disjunct can decide it, in either order.
///
/// `eval_conjunction_clauses` returned on the first disjunct that raised, so the rest of the
/// disjunction never ran. With one disjunct undecidable and another decided true, the two spellings
/// of the same condition disagreed: `true or undecidable` opened its gate and evaluated the body,
/// and `undecidable or true` reported that the condition could not be evaluated and dropped the body.
///
/// The exit code cannot see this. Both spellings exit 19 on a document the body fails, because the
/// rule fails either way -- only the reason differs, and only one of them is the real finding. So the
/// body here is a clause that *holds*, which makes the two outcomes different statuses: PASS if the
/// gate opened and the body ran, FAIL if the condition was treated as undecidable.
///
/// The last four cells are the controls. Two of them pin the case where nothing can decide the
/// disjunction, which must still fail closed rather than skip, and in both orders.
#[rstest::rstest]
#[case::undecidable_or_true("UNDECIDABLE or TRUE", Status::PASS)]
#[case::true_or_undecidable("TRUE or UNDECIDABLE", Status::PASS)]
#[case::undecidable_or_false("UNDECIDABLE or FALSE", Status::FAIL)]
#[case::false_or_undecidable("FALSE or UNDECIDABLE", Status::FAIL)]
#[case::control_true_gate("TRUE", Status::PASS)]
#[case::control_false_gate("FALSE", Status::SKIP)]
#[case::control_undecidable_gate("UNDECIDABLE", Status::FAIL)]
#[case::control_true_or_false("TRUE or FALSE", Status::PASS)]
fn a_disjunction_is_decided_by_the_disjunct_that_can_decide_it(
    #[case] gate: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            Vol: {
                Type: 'AWS::EC2::Volume',
                Properties: { Enabled: true, Size: 50 }
            }
        }
    }
    "#;

    // `Enabled` is a boolean, so `!EMPTY` on it is a question with no answer. The other two are
    // ordinary decided clauses, and the body is one that holds, so the rule's status says whether
    // the gate opened.
    let rules = "rule guarded when GATE { Resources.Vol.Properties.Size == 50 }"
        .replace("GATE", gate)
        .replace("UNDECIDABLE", "Resources.Vol.Properties.Enabled !EMPTY")
        .replace("TRUE", "Resources.Vol.Properties.Size == 50")
        .replace("FALSE", "Resources.Vol.Properties.Size == 99");

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "guarded")?,
        "gate: {}\nrules:\n{}",
        gate,
        rules
    );

    Ok(())
}

/// A map key that reads as an integer is still a key.
///
/// Retrieval decided between "index" and "key name" by asking whether the key text parses as an
/// `i64`, without looking at what it was being applied to. `Items.0` is index access written without
/// brackets, which is why a key is read as a number at all -- but a map takes the same text as a name,
/// and so any map key that reads as an integer was unaddressable. Quoting it changed nothing: the
/// quotes are gone by the time retrieval sees a `Key`, which is why `"1.5"` resolved and `"80"` did
/// not.
///
/// The shape that made this worth fixing is `Mappings`, where account ids are keys:
/// `Mappings.AccountToEnv."123456789012".Env` matched nothing on a template holding exactly that key.
/// Ports and status codes are the same shape.
///
/// The list cells are the controls that matter -- bracketless index access is the reason the number
/// parse exists, so a fix that simply stopped parsing would break it, and `L.0 == "second"` fails so
/// the index is doing real work rather than resolving to the first thing it finds.
#[rstest::rstest]
#[case::zero_key("M.\"0\" == \"zero\"", Status::PASS)]
#[case::negative_key("M.\"-1\" == \"neg\"", Status::PASS)]
#[case::integer_key("M.\"80\" == \"eighty\"", Status::PASS)]
#[case::integer_key_wrong_value("M.\"80\" == \"wrong\"", Status::FAIL)]
#[case::float_shaped_key("M.\"1.5\" == \"float\"", Status::PASS)]
#[case::absent_integer_key("M.\"99\" exists", Status::FAIL)]
#[case::list_index_without_brackets("L.0 == \"first\"", Status::PASS)]
#[case::second_list_index("L.1 == \"second\"", Status::PASS)]
#[case::list_index_discriminates("L.0 == \"second\"", Status::FAIL)]
#[case::list_index_out_of_range("L.5 exists", Status::FAIL)]
fn a_map_key_that_reads_as_an_integer_is_still_a_key(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            Vol: {
                Type: 'AWS::X::Y',
                Properties: {
                    M: { "0": "zero", "-1": "neg", "80": "eighty", "1.5": "float" },
                    L: ["first", "second"]
                }
            }
        }
    }
    "#;

    let rules = "rule keyed { Resources.Vol.Properties.CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "keyed")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A negative index counts back from the end, on a list long enough to prove it.
///
/// `eval_context.rs` names this test as what pins the behaviour, and it did not exist. The behaviour
/// is real and documented -- `docs/CLAUSES.md` says `Items[-1]` is the last element and `Items[-2]` the
/// one before it -- but the only test touching a negative index used a two-element list, where "the
/// last element" and "the absolute value" are the same index. It held under either reading, and its
/// comment asserted the reading the code does not use.
///
/// Three elements is the shortest list where `[-1]` and `[1]` disagree. `[-3]` is the first element
/// under this reading and out of range under the other, and `[-4]` is out of range under both, so both
/// ends of the range are pinned rather than just the near one.
#[rstest::rstest]
#[case::last_element("Items[-1]", "c", Status::PASS)]
#[case::last_is_not_the_middle("Items[-1]", "b", Status::FAIL)]
#[case::second_from_the_end("Items[-2]", "b", Status::PASS)]
#[case::furthest_back_in_range("Items[-3]", "a", Status::PASS)]
#[case::furthest_back_is_not_the_last("Items[-3]", "c", Status::FAIL)]
#[case::one_past_the_start("Items[-4]", "a", Status::FAIL)]
#[case::positive_index_control("Items[1]", "b", Status::PASS)]
#[case::first_element_control("Items[0]", "a", Status::PASS)]
fn a_negative_index_counts_back_from_the_end(
    #[case] query: &str,
    #[case] value_compared: &str,
    #[case] expected: Status,
) -> Result<()> {
    const DATA: &str = r#"{ "Items": [ "a", "b", "c" ] }"#;

    let rules = "rule r { QUERY == \"VALUE\" }"
        .replace("QUERY", query)
        .replace("VALUE", value_compared);
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let value = PathAwareValue::try_from(DATA)?;
    let mut root = root_scope(&rules_file, Rc::new(value));

    assert_eq!(
        eval_rules_file(&rules_file, &mut root, None)?,
        expected,
        "{} == {:?} against {}",
        query,
        value_compared,
        DATA
    );

    Ok(())
}

/// `EMPTY` on a boolean is an incompatible type, in both polarities and for both values.
///
/// `element_empty_operation` names this test as what covers all four combinations, and it did not
/// exist. The behaviour it describes is the one that mattered: the old arm computed
/// `(*boolean).to_string().is_empty()`, and neither "true" nor "false" is the empty string, so `EMPTY`
/// on a boolean was unconditionally false and `!EMPTY` unconditionally true -- a clause that reads like
/// a check and cannot fail for any input.
///
/// All four cells assert FAIL, which is what distinguishes the fix from the defect: under the old arm
/// the two `!EMPTY` cells passed. The wording of the diagnostic is covered by
/// `every_recorded_explanation_has_a_rendering_path`, which is what makes sure it reaches a reporter at
/// all; this test is about the verdict.
#[rstest::rstest]
#[case::empty_on_true("EMPTY", "true")]
#[case::not_empty_on_true("!EMPTY", "true")]
#[case::empty_on_false("EMPTY", "false")]
#[case::not_empty_on_false("!EMPTY", "false")]
fn boolean_empty_is_an_incompatible_type(#[case] operator: &str, #[case] flag: &str) -> Result<()> {
    let input = "{ Resources: { Vol: { Type: 'AWS::X::Y', Properties: { Flag: FLAG } } } }"
        .replace("FLAG", flag);
    let rules = "rule flagged { Resources.Vol.Properties.Flag OP }".replace("OP", operator);

    assert_eq!(
        Status::FAIL,
        rule_status_in(&rules, &input, "flagged")?,
        "`Flag {}` on the boolean {} must fail rather than answer a question the operator cannot ask",
        operator,
        flag
    );

    Ok(())
}

/// A filter applied directly to an already-indexed value is reported, not a panic.
///
/// `predicate_or_index` lets an array index and a filter sit adjacent, so `Rules[0][ Action ==
/// 'allow' ]` parses. Retrieval then reached a `_ => unreachable!()` whose match only handled a
/// preceding wildcard or key, and the process died at exit 101 -- taking the finding with it. `this`
/// and a map-key filter in the same position did the same.
///
/// Asserted as FAIL rather than as a specific message: what `[ ... ]` ought to mean when applied to one
/// already-selected value is a language question -- on a map the operator filters the map's *entries*,
/// which is not what an author writing `Rules[0][ ... ]` means -- so retrieval reports the query as
/// unresolved and lets the clause fail closed rather than inventing an answer.
#[rstest::rstest]
#[case::filter_after_an_index("Resources.One.Properties.Rules[0][ Action == 'allow' ] !empty")]
#[case::filter_after_a_filter(
    "Resources.*[ Type == 'AWS::S3::Bucket' ][ Type == 'AWS::S3::Bucket' ] !empty"
)]
fn a_filter_applied_to_an_indexed_value_does_not_panic(#[case] clause: &str) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            One: {
                Type: 'AWS::S3::Bucket',
                Properties: { Rules: [ { Action: 'allow' } ] }
            }
        }
    }
    "#;

    let rules = "rule filtered { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        Status::FAIL,
        rule_status_in(&rules, INPUT, "filtered")?,
        "{} must fail closed rather than abort the process",
        clause
    );

    Ok(())
}

/// A scalar function argument whose query selects nothing fails the rule, and neither panics nor aborts.
///
/// `resolve_function` pushes the query's result verbatim, and an empty result is legitimate -- a filter
/// that matches no resource produces one. Every scalar-positional argument then indexed `[0]` on it,
/// which panicked at exit 101 *before* reaching the arm that already carried the right message. Five
/// sites: two in `substring`, two in `regex_replace`, one in `join`.
///
/// The first argument was never affected, because it is passed as a slice rather than indexed, which is
/// why this went unnoticed.
///
/// This asserted the message on the error out of `eval_rules_file`, because the arm reached instead of
/// the panic reported `ParseError` and that class aborts the run. It is `IncompatibleError` now, which
/// `is_unevaluatable` recognises, so the clause fails closed and the file keeps reporting -- there is no
/// error to read the message off. The rule's verdict is the stronger assertion anyway: FAIL covers both
/// the panic this was written for and the abort that replaced it.
#[rstest::rstest]
#[case::substring_from("let r = substring(%s, %empty_sel, 3)")]
#[case::substring_to("let r = substring(%s, 1, %empty_sel)")]
#[case::join_separator("let r = join(%s, %empty_sel)")]
fn a_function_argument_that_selects_nothing_does_not_panic(#[case] call: &str) -> Result<()> {
    const INPUT: &str = r#"
    { Resources: { One: { Type: 'AWS::S3::Bucket' } } }
    "#;

    let rules = "let s = \"hello\"\nlet empty_sel = Resources[ Type == 'AWS::Nonexistent::Type' ]\nrule r {\n    CALL\n    %r == \"unused\"\n}\n"
        .replace("CALL", call);

    assert_eq!(
        Status::FAIL,
        rule_status_in(&rules, INPUT, "r")?,
        "{} must fail closed rather than panic or abort",
        call
    );

    Ok(())
}

/// A filter after a wildcard resolves its predicate against the element, not the document.
///
/// `accumulate` -- the helper that expands a list -- passed the resolver through unchanged, while every
/// other expansion path rebuilds it as a `ValueScope` rooted at the element. Anything downstream that
/// consults the scope's root rather than the value being traversed therefore saw the whole document, and
/// a filter predicate is exactly that.
///
/// So `Items[*][ Sub == 2 ]` tested `Sub == 2` against the file root, matched nothing, and selected
/// nothing, while `Items[ Sub == 2 ]` -- which reaches the filter's own List arm and rebases there -- was
/// right. Two spellings of one query disagreed.
///
/// The empty selection is not the damage. An assertion whose query selects nothing is *not applicable*,
/// so the guarded comparison reported SKIP and a violating value went unflagged at exit 0. That is the
/// `assertion_over_the_selection` cell, and its control is the same assertion written the working way.
///
/// `predicate_naming_the_document_root` is the cell that distinguishes a wrong root from a genuine
/// non-match: `Resources.One.Type` is unreachable from a list element, so it must NOT hold. It passed
/// before the fix, which is what proved the root was the document rather than the element.
#[rstest::rstest]
#[case::wildcard_filter_matches(
    "Resources.One.Properties.Items[*][ Sub == 2 ] !empty",
    Status::PASS
)]
#[case::wildcard_filter_matches_other(
    "Resources.One.Properties.Items[*][ Sub == 9 ] !empty",
    Status::PASS
)]
#[case::wildcard_filter_no_match(
    "Resources.One.Properties.Items[*][ Sub == 99 ] !empty",
    Status::FAIL
)]
#[case::plain_filter_control("Resources.One.Properties.Items[ Sub == 2 ] !empty", Status::PASS)]
#[case::predicate_naming_the_document_root(
    "Resources.One.Properties.Items[*][ Resources.One.Type == 'AWS::S3::Bucket' ] !empty",
    Status::FAIL
)]
#[case::assertion_over_the_selection(
    "Resources.One.Properties.Items[*][ Sub == 2 ].Public == false",
    Status::FAIL
)]
#[case::assertion_control(
    "Resources.One.Properties.Items[ Sub == 2 ].Public == false",
    Status::FAIL
)]
fn a_filter_after_a_wildcard_resolves_against_the_element(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            One: {
                Type: 'AWS::S3::Bucket',
                Properties: {
                    Items: [ { Sub: 2, Public: true }, { Sub: 9, Public: false } ]
                }
            }
        }
    }
    "#;

    let rules = "rule filtered { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "filtered")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A filter capture belongs to the iteration that made it.
///
/// `RootScope::add_variable_capture_key` appends and never resets, and both `BlockScope` and
/// `ValueScope` used to hand captures up to it. So every key a filter captured outlived its iteration
/// and piled up in one list for the whole file, and because `resolve_variable` reads
/// `resolved_variables` before `variable_queries`, the grown list is what a later `%name` saw.
///
/// The result is a false PASS on the resource that should fail:
///
/// | template                       | before | correct |
/// |--------------------------------|--------|---------|
/// | BucketB alone (only `beta`)    | FAIL   | FAIL    |
/// | BucketA + BucketB              | PASS   | FAIL    |
/// | BucketA alone (has `alpha`)    | PASS   | PASS    |
///
/// The second row is the defect: adding a *compliant* resource made a non-compliant one pass, because
/// BucketB saw `["alpha", "beta"]` and satisfied `some %cfg == "alpha"` on the strength of BucketA's
/// key. What makes it dangerous is the first row -- tested on the offending resource alone, the rule
/// looks like it works.
///
/// The third row is the liveness control, and it is the one that matters here: a fix that simply broke
/// the capture would make every row FAIL and look correct without it.
#[rstest::rstest]
#[case::non_compliant_alone(false, true, Status::FAIL)]
#[case::compliant_beside_non_compliant(true, true, Status::FAIL)]
#[case::compliant_alone(true, false, Status::PASS)]
fn a_filter_capture_does_not_outlive_its_iteration(
    #[case] with_alpha: bool,
    #[case] with_beta: bool,
    #[case] expected: Status,
) -> Result<()> {
    // `alpha` is the config name the rule demands; `beta` is a bucket that has an enabled config under
    // a different name, so it must fail.
    let mut resources = vec![];
    if with_alpha {
        resources.push(
            "BucketA: { Type: 'AWS::S3::Bucket', Properties: { Config: { alpha: { Enabled: true } } } }",
        );
    }
    if with_beta {
        resources.push(
            "BucketB: { Type: 'AWS::S3::Bucket', Properties: { Config: { beta: { Enabled: true } } } }",
        );
    }
    let input = format!("{{ Resources: {{ {} }} }}", resources.join(", "));

    let rules = r###"
    rule every_bucket_has_an_enabled_alpha_config {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            Properties.Config[ cfg | Enabled == true ] !empty
            some %cfg == "alpha"
        }
    }
    "###;

    assert_eq!(
        expected,
        rule_status_in(rules, &input, "every_bucket_has_an_enabled_alpha_config")?,
        "alpha={} beta={} over {}",
        with_alpha,
        with_beta,
        input
    );

    Ok(())
}

/// A key filter's capture name binds the keys it selected.
///
/// The arm bound the name as `_name` and no call site ever saw it, so
/// `Resources[ mk | keys == /^Bucket/ ]` declared `mk` and left it unresolvable. The run then died at
/// 255 with "Could not resolve variable by name mk", which blames the wrong thing -- the variable *was*
/// declared, in a position the parser accepts.
///
/// A key filter is the one filter shape where the key is what the predicate tested, so it is the shape
/// where capturing it is unambiguous.
///
/// `filtered_out_key` is the cell that makes this a test of the selection rather than of the plumbing:
/// `TableC` exists in the template and must NOT be captured, because the predicate excluded it. And the
/// all-must-match form fails over two captured keys, which shows the capture is a list rather than
/// whichever key happened to be last.
#[rstest::rstest]
#[case::selected_key("some %mk == \"BucketA\"", Status::PASS)]
#[case::other_selected_key("some %mk == \"BucketB\"", Status::PASS)]
#[case::filtered_out_key("some %mk == \"TableC\"", Status::FAIL)]
#[case::all_must_match_over_two_keys("%mk == \"BucketA\"", Status::FAIL)]
fn a_key_filter_capture_binds_the_selected_keys(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            BucketA: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'a' } },
            BucketB: { Type: 'AWS::S3::Bucket', Properties: { BucketName: 'b' } },
            TableC:  { Type: 'AWS::DynamoDB::Table', Properties: { TableName: 'c' } }
        }
    }
    "#;

    let rules = "rule keyed {\n    Resources[ mk | keys == /^Bucket/ ] !empty\n    CLAUSE\n}"
        .replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "keyed")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// `[*]` on a map passes the map through, except when a filter comes next.
///
/// The pass-through is deliberate and load-bearing: a schema field that accepts "an array or a single
/// value" is written once as `Statement[*].Action`, and handing the map onward is what makes that resolve
/// when `Statement` is one object rather than a list. IAM policies are exactly that shape, and
/// `test_field_type_array_or_single` pins it. Expanding the map unconditionally breaks that test and two
/// join tests, which is how the first attempt at this was rejected.
///
/// A filter next is the one position where pass-through cannot be what was meant. The predicate was
/// tested once against the whole map, matched nothing, and the filter selected nothing -- so
/// `Resources[*][ Type == 'AWS::S3::Bucket' ]` selected no resources at all, and an assertion over that
/// empty selection reported SKIP with the violation unflagged, while the `.*` spelling of the same query
/// was right. Two spellings disagreed, and the wrong one failed open.
///
/// The leniency cells are the controls, and they are the reason this is keyed on what comes next rather
/// than fixed by expanding: they must keep passing whether `Statement` is a list or a map.
#[rstest::rstest]
#[case::assertion_via_bracket_wildcard(
    "Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.Public == false",
    Status::FAIL
)]
#[case::assertion_via_dot_wildcard(
    "Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Public == false",
    Status::FAIL
)]
#[case::filter_via_bracket_wildcard(
    "Resources[*][ Type == 'AWS::S3::Bucket' ] !empty",
    Status::PASS
)]
#[case::filter_via_dot_wildcard("Resources.*[ Type == 'AWS::S3::Bucket' ] !empty", Status::PASS)]
#[case::filter_matching_nothing("Resources[*][ Type == 'AWS::None::Here' ] !empty", Status::FAIL)]
fn a_bracket_wildcard_on_a_map_expands_only_for_a_filter(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    // BucketA is public, so an assertion that reaches it must fail. TableC is a different type, so the
    // filter has something to exclude.
    const INPUT: &str = r#"
    {
        Resources: {
            BucketA: { Type: 'AWS::S3::Bucket', Properties: { Public: true } },
            TableC:  { Type: 'AWS::DynamoDB::Table', Properties: { Public: false } }
        }
    }
    "#;

    let rules = "rule mapped { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "mapped")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// The control for the case above: the array-or-single leniency must survive it.
///
/// `Statement[*].Action` has to resolve whether `Statement` is a list of statements or one statement
/// object. A filter never follows the wildcard in this idiom -- a key does -- which is what lets the two
/// cases be told apart.
#[rstest::rstest]
#[case::statement_is_a_list(r#"{ Statement: [ { Action: '*' } ] }"#)]
#[case::statement_is_a_single_map(r#"{ Statement: { Action: '*' } }"#)]
fn a_bracket_wildcard_still_accepts_an_array_or_a_single_value(#[case] input: &str) -> Result<()> {
    let rules = "rule lenient { Statement[*].Action != '*' }";

    assert_eq!(
        Status::FAIL,
        rule_status_in(rules, input, "lenient")?,
        "`Statement[*].Action` must resolve for {}",
        input
    );

    Ok(())
}

/// A filter capture is per-iteration inside its block and accumulated after it.
///
/// Two readings, both wanted, and getting one of them broke the other. Storing captures only in the
/// block fixed the false PASS -- one resource's key satisfying another resource's clause -- but killed the
/// name at the end of the block while the rule still referenced it. An unresolvable variable is an
/// internal error, so a single rule took the whole file's report down at exit 255 rather than failing a
/// clause.
///
/// So the block owns the captures while it runs, and hands them to the enclosing scope on the way out:
///
/// - `in_block_sees_only_its_own_iteration` is the false PASS. `BucketB` has no `alpha` config and must
///   fail even though `BucketA` does.
/// - `after_block_sees_every_iteration` reads the name after the block, where every iteration's keys are
///   what such a clause means -- and what it saw before any of this.
#[rstest::rstest]
#[case::in_block_sees_only_its_own_iteration(true, Status::FAIL)]
#[case::after_block_sees_every_iteration(false, Status::PASS)]
fn a_filter_capture_is_scoped_to_its_block_and_survives_it(
    #[case] read_inside_the_block: bool,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            BucketA: { Type: 'AWS::S3::Bucket', Properties: { Config: { alpha: { Enabled: true } } } },
            BucketB: { Type: 'AWS::S3::Bucket', Properties: { Config: { beta:  { Enabled: true } } } }
        }
    }
    "#;

    let rules = if read_inside_the_block {
        "rule scoped {\n    Resources.*[ Type == 'AWS::S3::Bucket' ] {\n        Properties.Config[ cfg | Enabled == true ] !empty\n        some %cfg == \"alpha\"\n    }\n}"
    } else {
        "rule scoped {\n    Resources.*[ Type == 'AWS::S3::Bucket' ] {\n        Properties.Config[ cfg | Enabled == true ] !empty\n    }\n    some %cfg == \"alpha\"\n}"
    };

    assert_eq!(
        expected,
        rule_status_in(rules, INPUT, "scoped")?,
        "read {} the block",
        if read_inside_the_block {
            "inside"
        } else {
            "after"
        }
    );

    Ok(())
}

/// A capture in a rule's `when` condition does not outlive the rule.
///
/// A rule condition is evaluated against the enclosing scope, so a capture made there landed in the
/// file-wide map and survived its rule. Two rules using the same capture name in their conditions then
/// interfered: the second saw the first's keys, and a clause reading the name failed on evidence from a
/// rule it has nothing to do with.
///
/// `renamed_capture` is the cell that proves it: the two rulesets differ *only* in what the first rule
/// calls its capture, and that changed the second rule's verdict. No rule should have to know what
/// another rule named a local.
#[rstest::rstest]
#[case::same_capture_name("nm")]
#[case::renamed_capture("other")]
fn a_capture_in_a_rule_condition_does_not_outlive_the_rule(#[case] first_name: &str) -> Result<()> {
    const INPUT: &str = r#"
    { Resources: { A: { Type: 'AWS::S3::Bucket' }, B: { Type: 'AWS::EC2::Instance' } } }
    "#;

    let rules = "rule first when Resources[ FIRST | Type == 'AWS::S3::Bucket' ] !empty {\n    Resources.A.Type == 'AWS::S3::Bucket'\n}\nrule second when Resources[ nm | Type == 'AWS::EC2::Instance' ] !empty {\n    %nm == \"B\"\n}"
        .replace("FIRST", first_name);

    // `second` captures the instance key, which is "B", so it holds -- whatever the first rule called its
    // own capture.
    assert_eq!(
        Status::PASS,
        rule_status_in(&rules, INPUT, "second")?,
        "second must not depend on what first named its capture (first used {:?})",
        first_name
    );

    Ok(())
}

/// A filter applied to an already-indexed value fails closed in both polarities.
///
/// The first version of this reported the query as *unresolved*, which means "the value is not there" --
/// and `!exists` and `empty` answer that with PASS. So an assertion failed closed only when it was written
/// positively: `Tags[0][ Key == 'Name' ] exists` failed, and `... !exists` passed at exit 0 on a query
/// the engine had explicitly refused to evaluate.
///
/// `IncompatibleError` is the branch's channel for "no answer either way". The clause arm fails an
/// assertion closed in both polarities, so negating the clause cannot turn it into a pass.
#[rstest::rstest]
#[case::exists("Resources.One.Tags[0][ Key == 'Name' ] exists")]
#[case::not_exists("Resources.One.Tags[0][ Key == 'Name' ] !exists")]
#[case::empty("Resources.One.Tags[0][ Key == 'Name' ] empty")]
#[case::not_empty("Resources.One.Tags[0][ Key == 'Name' ] !empty")]
fn a_filter_on_an_indexed_value_fails_closed_in_both_polarities(
    #[case] clause: &str,
) -> Result<()> {
    const INPUT: &str = r#"
    { Resources: { One: { Tags: [ { Key: 'Name', Value: 'v1' } ] } } }
    "#;

    let rules = "rule indexed { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        Status::FAIL,
        rule_status_in(&rules, INPUT, "indexed")?,
        "{} must fail rather than pass on a query the engine refused to evaluate",
        clause
    );

    Ok(())
}

/// The control for the case above: the supported spelling still decides normally.
#[rstest::rstest]
#[case::exists_holds("Resources.One.Tags[ Key == 'Name' ] exists", Status::PASS)]
#[case::not_exists_does_not("Resources.One.Tags[ Key == 'Name' ] !exists", Status::FAIL)]
fn a_filter_without_an_index_still_decides(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    { Resources: { One: { Tags: [ { Key: 'Name', Value: 'v1' } ] } } }
    "#;

    let rules = "rule supported { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "supported")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A key filter after `[*]` keeps the map as its subject.
///
/// The wildcard-expands-for-a-filter arm briefly included key filters, and that was wrong for a reason
/// worth keeping: a key filter's subject *is* the map whose keys are matched, so handing that map through
/// is exactly right. Routing it into `accumulate_map` moves the subject down a level, onto each entry's
/// own keys instead of the logical ids -- so `Resources[*][ keys == /^Bucket/ ]` stopped matching the
/// bucket names and started matching `Type` and `Properties`.
///
/// It produced both failure directions at once: a false failure on `!empty`, and FAIL turning into SKIP on
/// the assertion form -- the same silent miss the arm exists to remove.
///
/// `own_key_discriminator` is the cell that proves the mechanism rather than the symptom. `/^Type$/`
/// matches no logical id and every resource's own key, so it must NOT hold; while the subject was one
/// level down it did.
#[rstest::rstest]
#[case::key_filter_not_empty("Resources[*][ keys == /^Bucket/ ] !empty", Status::PASS)]
#[case::key_filter_assertion(
    "Resources[*][ keys == /^Bucket/ ].Type == \"never-matches\"",
    Status::FAIL
)]
#[case::own_key_discriminator("Resources[*][ keys == /^Type$/ ] !empty", Status::FAIL)]
#[case::control_without_a_wildcard("Resources[ keys == /^Bucket/ ] !empty", Status::PASS)]
#[case::value_filter_still_expands(
    "Resources[*][ Type == 'AWS::S3::Bucket' ].Properties.Public == false",
    Status::FAIL
)]
fn a_key_filter_after_a_wildcard_keeps_the_map_as_its_subject(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            BucketA: { Type: 'AWS::S3::Bucket', Properties: { Public: true } },
            BucketB: { Type: 'AWS::S3::Bucket', Properties: { Public: false } }
        }
    }
    "#;

    let rules = "rule keyed { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "keyed")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A rules file whose lines end with a bare CR still enforces its rules.
///
/// `comment2` searched for `\n` alone while `multispace1` treats a lone `\r` as whitespace everywhere else, so
/// in a CR-only file a comment ran to the end of the file. With the comment on the first line, every rule
/// after it became comment text, the file parsed to no rules at all, and an empty rules file is not an error --
/// so a violating template came back compliant at exit 0 with nothing printed on any channel. That is the
/// shape of the unterminated-message defect fixed earlier on this branch, reached through line endings.
///
/// Asserted on the verdict, and on the rule count first so the failure says which of the two went wrong.
#[test]
fn a_cr_only_rules_file_still_enforces_its_rules() -> Result<()> {
    const INPUT: &str = r#"
    {
        Resources: {
            bucket: { Type: 'AWS::S3::Bucket', Properties: { Encrypted: false } }
        }
    }
    "#;

    let cr = "# encryption is mandatory\rrule encrypted {\r  Resources.*.Properties.Encrypted == true\r}\r";
    let lf = cr.replace('\r', "\n");

    for (spelling, rules) in [("CR", cr), ("LF", lf.as_str())] {
        let parsed = crate::rules::parser::rules_file(crate::rules::parser::from_str2(rules))?
            .unwrap_or_else(|| panic!("{} spelling parsed to no rules at all", spelling));
        assert_eq!(
            parsed.guard_rules.len(),
            1,
            "{} spelling lost the rule after the comment",
            spelling
        );
        assert_eq!(
            Status::FAIL,
            rule_status_in(rules, INPUT, "encrypted")?,
            "{} spelling must still fail the violating template",
            spelling
        );
    }
    Ok(())
}

/// A function call on the right of `keys` compares against the map's keys, like the other two right-hand sides.
///
/// `map_keys_match` took a value and an access there and not a function call, so `access` matched the
/// function's name as a query, `close_array` failed recoverably on the `(`, and `predicate_filter_clauses` read
/// the same text as an ordinary filter over a child property named `keys`. Both readings parse, so this is
/// asserted on the verdict rather than on the tree: the document is built so the two disagree in both
/// directions. Its one entry is keyed `alpha` and that entry has a child named `keys` whose value is `zulu`, so
/// a key filter for `alpha` selects the entry and the property reading does not -- and for `zulu` it is the
/// other way round. Each function case is paired with the literal spelling of the same question, which is the
/// verdict it has to agree with.
///
/// Before the fix, `to_lower("ALPHA")` failed and `to_lower("ZULU")` passed. Both were the property reading
/// answering a question nobody asked, at exit 19 and exit 0 respectively, with no diagnostic naming the key.
/// Six of these cases held the opposite verdict before it: the four `==`/`!=` function cases and the `in` and
/// `not in` ones. The literal spellings and the two quoted-property cases held already and are here as the
/// references the function spellings have to agree with; `case_is_not_folded` also held already, by arriving at
/// the same verdict through the wrong reading, and is here to pin that the function is evaluated at all.
#[rstest::rstest]
#[case::function_result_matches_the_key(
    r#"Tags[ keys == to_lower("ALPHA") ] !empty"#,
    Status::PASS
)]
#[case::literal_spelling_of_the_same_question(r#"Tags[ keys == "alpha" ] !empty"#, Status::PASS)]
#[case::function_result_matches_no_key(r#"Tags[ keys == to_lower("ZULU") ] !empty"#, Status::FAIL)]
#[case::literal_spelling_agrees_there_too(r#"Tags[ keys == "zulu" ] !empty"#, Status::FAIL)]
#[case::case_is_not_folded(r#"Tags[ keys == to_upper("alpha") ] !empty"#, Status::FAIL)]
#[case::not_equal_selects_the_other_key(r#"Tags[ keys != to_lower("ZULU") ] !empty"#, Status::PASS)]
#[case::not_equal_excludes_the_only_key(
    r#"Tags[ keys != to_lower("ALPHA") ] !empty"#,
    Status::FAIL
)]
#[case::in_takes_a_function_too(r#"Tags[ keys in to_lower("ALPHA") ] !empty"#, Status::PASS)]
#[case::not_in_takes_one(r#"Tags[ keys not in to_lower("ZULU") ] !empty"#, Status::PASS)]
#[case::a_quoted_first_token_is_still_the_property(
    r#"Tags[ "keys" == to_lower("ZULU") ] !empty"#,
    Status::PASS
)]
#[case::and_the_property_reading_answers_about_the_child(
    r#"Tags[ "keys" == to_lower("ALPHA") ] !empty"#,
    Status::FAIL
)]
fn a_function_call_on_the_right_of_keys_compares_against_the_keys(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Tags: {
            alpha: { keys: 'zulu' }
        }
    }
    "#;

    let rules = "rule keyed { CLAUSE }".replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "keyed")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// One key set, two spellings, one verdict.
///
/// `real_binary_operation` widened `keys ==` to membership by counting `QueryResult`s, and a single
/// `Resolved` holding an n-element list counts as one. `let nested = KeyList` over
/// `KeyList: [Name, Owner]` is exactly that, so `keys == %nested` stayed strict equality;
/// `compare_eq` refused every key-against-list pairing, the filter selected nothing, and the clause
/// SKIPped -- exit 0 with nothing in the report. The same key names spelled `%flat` (`KeyList[*]`)
/// arrive as two results, widen as intended, and answer. Two spellings of one clause disagreed, and
/// the silent one was wrong.
///
/// Both clause shapes are here because the two failures are not the same failure. The `!empty`
/// selection form asks whether the filter picked the entries up at all, and it reported FAIL --
/// visible, if puzzling. The assertion form reported SKIP, which exits 0, and that is the pair that
/// catches the fail-open: a rule whose only check is that clause passed a document it rejects.
///
/// `in_spelling_already_agrees` is the reference the `==` cells have to meet rather than a
/// regression guard. `IN` was never broken here, because `in_cmp` walks a list-valued right-hand
/// element itself, so it is what `==` should have been answering all along.
#[rstest::rstest]
#[case::one_result_holding_two_keys("Tags[ keys == %nested ] !empty", Status::PASS)]
#[case::two_results_same_two_keys("Tags[ keys == %flat ] !empty", Status::PASS)]
#[case::in_spelling_already_agrees("Tags[ keys IN %nested ] !empty", Status::PASS)]
#[case::assertion_over_one_result(r#"Tags[ keys == %nested ].Value == "RIGHT""#, Status::FAIL)]
#[case::assertion_over_two_results(r#"Tags[ keys == %flat ].Value == "RIGHT""#, Status::FAIL)]
fn a_key_set_from_one_result_widens_like_a_key_set_from_several(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        KeyList: ["Name", "Owner"],
        Tags: {
            Name: { Value: 'WRONG' },
            Owner: { Value: 'WRONG' }
        }
    }
    "#;

    let rules = "let nested = KeyList\nlet flat = KeyList[*]\nrule keyed { CLAUSE }"
        .replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "keyed")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A key is outside a denylist only if it differs from every entry, not from one of them.
///
/// `MapKeyComparator::NotIn` folded through the one-match report along with `In`, so a key counted as
/// "not in" the list as soon as any single element differed from it. `Name` against
/// `[Name, Zebra]` answers false and then true, and the second answer won: the filter selected the
/// one key the denylist names. Any denylist of two or more distinct elements selects the keys it
/// denies, and it does so at exit 0, so the rule reports compliance on the document it was written
/// to reject.
///
/// `NotEq` next door already folds with ALL and is correct, which is the basis for ALL being the
/// right fold here rather than a rule invented for one comparator.
///
/// `single_element_denylist_unchanged` does NOT pin that, and the distinction is worth stating because
/// the obvious reading of this cell is wrong. Routing `NotEq` through the ANY fold instead leaves the
/// whole grid green, measured. `NotEq` only ever reaches the fold with exactly one value --
/// `widened_for` promotes it to `NotIn` above that -- and ANY over one comparison is ALL over one, so
/// which fold the `Eq`/`NotEq` arm uses is not observable from any rules file. What this cell does
/// pin is the arm itself: dropping the inversion that makes `!=` negate turns it red.
///
/// `an_undenied_key_is_still_selected` is the control that matters most, because the cheap wrong fix
/// -- folding `NotIn` so that any single match rejects the whole *map* rather than the one key --
/// passes the first cell by selecting nothing at all, for every input. `Mixed` has one denied key and
/// one undenied one, so a filter that selects nothing fails it.
///
/// `one_result_holding_the_denylist` answered correctly before any of this and is the cell that binds
/// the fold to the flattening two functions up. The fault needs several `QueryResult`s to be visible
/// at all: with one result holding the whole list, `in_cmp` walks the elements itself and returns a
/// single `ComparisonResult`, so ANY over one result and ALL over one result are the same fold and
/// neither can be wrong. `%denylist` is that spelling, and `%denytwo` is the `[*]` spelling that
/// splits into two results and exposes the fold.
///
/// Which means the flattening in `real_binary_operation` moves this cell INTO the fault: it turns the
/// one result into two, so with the flattening in place and the fold left at ANY, a spelling that was
/// correct starts passing a document it should reject. Measured at 19 on 559bdd2, 0 with the
/// flattening alone, and 19 with both. The two changes are not independent and must not be landed
/// apart, which is what this cell is here to catch.
#[rstest::rstest]
#[case::every_key_denied_selects_nothing("OnlyDenied[ keys NOT IN %denytwo ] !empty", Status::FAIL)]
#[case::an_undenied_key_is_still_selected("Mixed[ keys NOT IN %denytwo ] !empty", Status::PASS)]
#[case::single_element_denylist_unchanged(r#"OnlyDenied[ keys != "Name" ] !empty"#, Status::FAIL)]
#[case::one_result_holding_the_denylist("OnlyDenied[ keys NOT IN %denylist ] !empty", Status::FAIL)]
fn negated_key_membership_requires_every_element_to_differ(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        DenyTwo: ["Name", "Zebra"],
        OnlyDenied: { Name: 'x' },
        Mixed: { Name: 'x', Other: 'y' }
    }
    "#;

    let rules = "let denytwo = DenyTwo[*]\nlet denylist = DenyTwo\nrule keyed { CLAUSE }"
        .replace("CLAUSE", clause);

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "keyed")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// The same regex inside a list literal, which panicked at a second and independent site.
///
/// `IN [/re/]` does not reach `compare_eq` first. `contained_in` asks `Vec`-style membership, which
/// is `PathAwareValue::eq`, and that arm held `regex.is_match(s).unwrap()` under the comment "given
/// that we have already validated the regular expression". The premise is false: validation at
/// parse time proves the pattern compiles and says nothing about whether a match completes. So this
/// spelling aborted at `path_value.rs` while the unwrapped one aborted at `operators.rs`.
///
/// `PartialEq` returns `bool` and cannot report an error, and the arm cannot be removed -- this
/// membership loop is itself the caller that needs it, for every element of the list literal. So
/// `eq` answers `false` and `contained_in` asks `compare_eq` as well, reading the error `eq` had to
/// swallow. That is what makes these three spellings agree with the four above rather than
/// reporting a plain mismatch.
#[rstest::rstest]
#[case::in_a_list("IN [/(?!x)((a+)+)b/]")]
#[case::not_in_a_list("NOT IN [/(?!x)((a+)+)b/]")]
#[case::in_a_mixed_list("IN [/(?!x)((a+)+)b/, 5]")]
fn a_regex_in_a_list_literal_fails_the_clause_instead_of_aborting(#[case] rhs: &str) {
    let clause = format!("Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {rhs}");

    let outcome =
        std::panic::catch_unwind(|| status_and_messages(clause.as_str(), THIRTY_AS).unwrap());

    let (status, messages) = match outcome {
        Ok(pair) => pair,
        Err(..) => panic!("`{}` panicked instead of returning a verdict", clause),
    };

    assert_eq!(
        Status::FAIL,
        status,
        "`{}` must fail the clause, and must agree with the unwrapped spelling: one input \
         answering differently depending on whether the regex is bracketed is its own defect",
        clause
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("regular expression could not be evaluated")),
        "`{}` should give the same reason the unwrapped spelling gives; recorded {:?}",
        clause,
        messages
    );
}

/// A regex that cannot be evaluated fails its clause instead of aborting the process.
///
/// `fancy_regex` returns a `Result` from `is_match` rather than a `bool`, because a backtracking
/// engine can run out of budget instead of answering. A pattern needs a lookaround or a
/// backreference to be put on that engine at all, and then a nested quantifier makes the work grow
/// with the length of the subject. `compare_eq` passed that error up as `Error::RegexError`, and
/// `match_value` had arms for `Ok` and for `Error::NotComparable` and met everything else with
/// `_ => unreachable!()`. So `Size == /(?!x)((a+)+)b/` against thirty characters aborted at exit
/// 101, and every other rule in the file lost its verdict with it.
///
/// The four spellings here are the ones that reach `match_value`. The unwrapped `IN` and `NOT IN`
/// arrive through `contained_in`'s final arm rather than through `EqOperation`, which is a second
/// route to the same panic and would not be covered by `==` alone.
///
/// `catch_unwind` is what makes the absence of the panic explicit. Asserting on the status alone
/// would not: an aborting build never returns a status to assert on, so the assertion would be
/// unreachable rather than false.
#[rstest::rstest]
#[case::equals("==")]
#[case::not_equals("!=")]
#[case::in_bare("IN")]
#[case::not_in_bare("NOT IN")]
fn a_regex_that_exceeds_the_backtrack_limit_fails_the_clause_instead_of_aborting(
    #[case] operator: &str,
) {
    let clause = format!(
        "Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {operator} {CATASTROPHIC}"
    );

    let outcome =
        std::panic::catch_unwind(|| status_and_messages(clause.as_str(), THIRTY_AS).unwrap());

    let (status, messages) = match outcome {
        Ok(pair) => pair,
        Err(..) => panic!("`{}` panicked instead of returning a verdict", clause),
    };

    assert_eq!(
        Status::FAIL,
        status,
        "`{}` must fail the clause; the comparison has no answer, so neither polarity gets to \
         claim one",
        clause
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("regular expression could not be evaluated")),
        "`{}` should say the regex could not be evaluated, so the author can find the pattern; \
         recorded {:?}",
        clause,
        messages
    );
    assert!(
        messages.iter().any(|m| m.contains("backtracking")),
        "`{}` should carry fancy_regex's own reason rather than the `RegexError` wrapper's text, \
         which claims a parse error for a pattern that parsed; recorded {:?}",
        clause,
        messages
    );
}

/// The control: an ordinary regex is unaffected, in both spellings and both polarities.
///
/// The fix reaches every regex comparison, so the ordinary cases need pinning too -- an
/// unevaluatable pattern reporting correctly is worth nothing if a pattern that matches stopped
/// matching. `IN [/re/]` is included because it is the spelling whose membership loop was
/// restructured.
#[rstest::rstest]
#[case::equals_matching("== /prod/", Status::PASS)]
#[case::equals_not_matching("== /nomatch/", Status::FAIL)]
#[case::not_equals_matching("!= /prod/", Status::FAIL)]
#[case::not_equals_not_matching("!= /nomatch/", Status::PASS)]
#[case::in_list_matching("IN [/prod/]", Status::PASS)]
#[case::in_list_not_matching("IN [/nomatch/]", Status::FAIL)]
#[case::not_in_list_matching("NOT IN [/prod/]", Status::FAIL)]
#[case::not_in_list_not_matching("NOT IN [/nomatch/]", Status::PASS)]
fn an_ordinary_regex_comparison_is_unchanged(#[case] comparison: &str, #[case] expected: Status) {
    const INPUT: &str = r#"
    {
        Resources: {
            V: { Type: 'AWS::EC2::Volume', Properties: { Size: 'prod-volume' } }
        }
    }
    "#;

    let clause = format!("Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {comparison}");
    let (status, _) = status_and_messages(clause.as_str(), INPUT).unwrap();

    assert_eq!(expected, status, "clause: {}", clause);
}

/// A list-valued property must not be admitted by a denylist that could not evaluate it.
///
/// `contained_in` decides a scalar left-hand side and a list-valued one in different arms, and only
/// one of them read the error. The scalar arm walks the right-hand list itself, keeps the first
/// `RegexError` it meets and reports it when nothing matched, which is what
/// `a_regex_in_a_list_literal_fails_the_clause_instead_of_aborting` pinned. The list arm asked
/// `is_one_of`, which returns `bool` and reached `compare_eq(..).unwrap_or(false)`, so a pattern that
/// could not be evaluated read as "this element is not a member".
///
/// For `NOT IN` that is the whole defect: no element matched, so every element landed in the diff,
/// the negation wrapper turned the failure into a success, and the run exited 0. Measured on the
/// thirty `a`s below, `Size NOT IN [/(?!x)((a+)+)b/]` exits 19 in the scalar spelling and 0 in the
/// list spelling. A denylist admitting a value it could not evaluate is the shape
/// `docs/KNOWN_ISSUES.md` records, and it is also why the direction of the fix is not a coin flip:
/// the scalar arm's answer is the documented one, so the list arm moves onto it rather than the
/// reverse.
///
/// `IN` is here because its status was already FAIL and its reason was not. It reported "was not
/// present in", a claim about the value that nothing established, since the comparison that would
/// have established it never completed. So the message assertion is what makes these cells
/// discriminate at all: on status alone, two of the four were already green and the defect would
/// have looked half its size.
///
/// The nested spellings are a second site rather than a second case of the first. `[[/re/]]` puts a
/// list in the denylist, which sends the clause through the `rhsl.iter().any(is_list)` branch, and
/// there the element-wise diff never sees the regex at all -- `compare_eq(String, List)` refuses
/// before any pattern runs. The whole-list reading beside it is what raises, through
/// `compare_eq(List, List)` recursing onto the inner pair, and it swallowed the error at its own
/// call site. Repairing `is_one_of` alone leaves `Size NOT IN [[/re/]]` at exit 0.
///
/// `backtracking` is asserted as well as the reason, for the purpose it serves in
/// `a_regex_that_exceeds_the_backtrack_limit_fails_the_clause_instead_of_aborting`: `RegexError`'s
/// own text claims a parse error, which is false of a pattern that compiled and then ran out of
/// budget, so the assertion pins fancy_regex's message rather than the wrapper's.
#[rstest::rstest]
#[case::scalar_in(THIRTY_AS, "IN [/(?!x)((a+)+)b/]")]
#[case::scalar_not_in(THIRTY_AS, "NOT IN [/(?!x)((a+)+)b/]")]
#[case::list_in(THIRTY_AS_IN_A_LIST, "IN [/(?!x)((a+)+)b/]")]
#[case::list_not_in(THIRTY_AS_IN_A_LIST, "NOT IN [/(?!x)((a+)+)b/]")]
#[case::list_in_a_nested_list(THIRTY_AS_IN_A_LIST, "IN [[/(?!x)((a+)+)b/]]")]
#[case::list_not_in_a_nested_list(THIRTY_AS_IN_A_LIST, "NOT IN [[/(?!x)((a+)+)b/]]")]
fn a_denylist_refuses_a_value_it_could_not_evaluate_in_either_spelling(
    #[case] template: &str,
    #[case] rhs: &str,
) {
    let clause = format!("Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {rhs}");
    let (status, messages) = status_and_messages(clause.as_str(), template).unwrap();

    assert_eq!(
        Status::FAIL,
        status,
        "`{}` must fail the clause: the comparison has no answer, so neither polarity gets to claim \
         one, and a denylist that admits the value it could not evaluate is the outcome this cell \
         exists to prevent",
        clause
    );
    assert!(
        messages
            .iter()
            .any(|m| m.contains("regular expression could not be evaluated")),
        "`{}` should say the regex could not be evaluated rather than claim the value was absent; \
         recorded {:?}",
        clause,
        messages
    );
    assert!(
        messages.iter().any(|m| m.contains("backtracking")),
        "`{}` should carry fancy_regex's own reason rather than the `RegexError` wrapper's text, \
         which claims a parse error for a pattern that parsed; recorded {:?}",
        clause,
        messages
    );
}

/// An element that matches still decides, beside one that could not be evaluated.
///
/// The precedence the repair above has to keep, and the reason it is not "any `RegexError` refuses
/// the clause". When some element of the right-hand list matches the value, the answer never
/// depended on the element that failed, so the clause is decided rather than unanswerable. That is
/// how the scalar arm has always read it, and `in_a_mixed_list` covers the same precedence one arm
/// over.
///
/// Both polarities, because a repair that refused too eagerly moves them in opposite directions.
/// `NOT IN` would go from FAIL to FAIL for a different reason and hide behind its own exit code,
/// which is what the negative message assertion is here to catch. `IN` would go from PASS to FAIL
/// and turn a compliant template into a reported violation.
///
/// # Why the same clause without the matching element is run beside each cell
///
/// The negative message assertion could not fail. Measured on 2026-09-03: both spellings record ZERO
/// comparison messages, so `messages` is empty and a predicate over its contents is satisfied by the
/// emptiness rather than by anything about the regex. It would have gone on passing had the reporting
/// stopped recording comparison messages at all, which is the state it looks like it rules out.
///
/// The discriminator is the same clause with the matching element removed. `IN [/re/]` over the same
/// value DOES record "The regular expression could not be evaluated against the value", measured in the
/// same run below. So the pair says what the cell means: the message exists, this mechanism produces it
/// for this pattern and this value, and adding an element that matches is what makes it go away. Without
/// the second half the cell asserts an absence against a channel that was never shown to speak.
#[rstest::rstest]
#[case::denied_by_the_element_that_matched(
    "NOT IN [/(?!x)((a+)+)b/, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
    Status::FAIL
)]
#[case::admitted_by_the_element_that_matched(
    "IN [/(?!x)((a+)+)b/, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']",
    Status::PASS
)]
fn an_element_that_matches_decides_membership_beside_an_unevaluatable_regex(
    #[case] rhs: &str,
    #[case] expected: Status,
) {
    let clause = format!("Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {rhs}");
    let (status, messages) = status_and_messages(clause.as_str(), THIRTY_AS_IN_A_LIST).unwrap();

    assert_eq!(expected, status, "clause: {}", clause);
    assert!(
        !messages
            .iter()
            .any(|m| m.contains("regular expression could not be evaluated")),
        "`{}` was decided by the element that matched, so it must not report the element that could \
         not be evaluated; recorded {:?}",
        clause,
        messages
    );

    // The positive half: the same denylist with the matching element taken out. The polarity is kept, so
    // the pair differs in one element and nothing else.
    let alone = format!(
        "Resources.*[ Type == 'AWS::EC2::Volume' ].Properties.Size {}",
        match expected {
            Status::PASS => "IN [/(?!x)((a+)+)b/]",
            _ => "NOT IN [/(?!x)((a+)+)b/]",
        }
    );
    let (alone_status, alone_messages) =
        status_and_messages(alone.as_str(), THIRTY_AS_IN_A_LIST).unwrap();

    assert_eq!(
        Status::FAIL,
        alone_status,
        "`{}` has nothing left to decide it, so it fails closed on the pattern that gave up; a \
         different verdict means the control is broken rather than the cell",
        alone
    );
    assert!(
        alone_messages
            .iter()
            .any(|m| m.contains("regular expression could not be evaluated")),
        "`{}` must record the message the cell above asserts the absence of. Nothing recorded it here, \
         so the absence above is the emptiness of the message channel rather than a fact about the \
         element that matched; recorded {:?}",
        alone,
        alone_messages
    );
}

/// Every comparison message recorded anywhere in the evaluation tree.
fn recorded_comparison_messages(record: &EventRecord<'_>, out: &mut Vec<String>) {
    if let Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(check))) = &record.container {
        if let Some(message) = &check.message {
            out.push(message.clone());
        }
    }
    for child in &record.children {
        recorded_comparison_messages(child, out);
    }
}

/// The same, over both clause-check variants that carry an explanation.
///
/// Separate from `recorded_comparison_messages` rather than replacing it, because the two answer
/// different questions and the existing callers want the narrower one. `Comparison` is what `==` and
/// `!=` record; `InComparison` is what `IN` and `NOT IN` record, through `report_by_lhs`. A test that
/// reads only the first cannot see a membership explanation at all, which is how the missing one went
/// unnoticed: every message assertion in this module was blind to that variant.
fn recorded_clause_messages(record: &EventRecord<'_>, out: &mut Vec<String>) {
    match &record.container {
        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(check))) => {
            if let Some(message) = &check.message {
                out.push(message.clone());
            }
        }
        Some(RecordType::ClauseValueCheck(ClauseCheck::InComparison(check))) => {
            if let Some(message) = &check.message {
                out.push(message.clone());
            }
        }
        _ => {}
    }
    for child in &record.children {
        recorded_clause_messages(child, out);
    }
}

/// Which clause checks the evaluation recorded, by variant and status, in tree order.
///
/// The variant matters and the message does not, which is why this is separate from
/// `recorded_comparison_messages`. A clause that records two verdicts about one value records them as
/// two different variants -- the reason as a `Comparison` and the membership claim as an
/// `InComparison` -- and the second one carries no message at all, so a message-based assertion cannot
/// see it. Measured: with the second record present and absent, the message list is identical.
fn recorded_clause_check_kinds(record: &EventRecord<'_>, out: &mut Vec<String>) {
    if let Some(RecordType::ClauseValueCheck(check)) = &record.container {
        out.push(match check {
            ClauseCheck::Success => "Success".to_string(),
            ClauseCheck::Comparison(c) => format!("Comparison({:?})", c.status),
            ClauseCheck::InComparison(c) => format!("InComparison({:?})", c.status),
            ClauseCheck::Unary(c) => format!("Unary({:?})", c.value.status),
            ClauseCheck::NoValueForEmptyCheck(_) => "NoValueForEmptyCheck".to_string(),
            ClauseCheck::DependentRule(c) => format!("DependentRule({:?})", c.status),
            ClauseCheck::MissingBlockValue(c) => format!("MissingBlockValue({:?})", c.status),
        });
    }
    for child in &record.children {
        recorded_clause_check_kinds(child, out);
    }
}

/// Which of the three unanswerable-containment reasons a value gets, asserted on the message text.
///
/// `substring_in_answers_the_same_against_a_query_as_against_a_literal` covers the same five kinds and
/// asserts `Status` only, for all twenty of its cells. That is why nothing caught a prose claim about
/// these reasons being false for one of them: the verdict is FAIL for every kind and stays FAIL whichever
/// reason is attached, so a status-only grid cannot tell the reasons apart. These cells read the recorded
/// message.
///
/// The distinction they pin is which operand a reason is about. `found_in_string` destructures only
/// `PathAwareValue::List`, so `HoldsANonString` is the complaint about elements it tested one at a time,
/// and `NotAString` is the complaint about a value it never decomposed. A `Map` gets the second one, and
/// that is right: nothing looked inside it, so a message naming its elements would describe contents no
/// comparison examined.
///
/// `map_is_not_a_string` is the cell the wording was wrong about. The variant's doc justified the split
/// by asserting "a scalar holds nothing", and `{"a": 1}` holds something -- and the crate agrees, because
/// `PathAwareValue::is_scalar` is `!self.is_list() && !self.is_map()`, so a `Map` is not a scalar by the
/// definition three files over. The message itself was accurate the whole time; only the reason given
/// for it was not, and the negative assertion here is the half that matters: a `Map` must NOT be told it
/// holds a value that is not a string, because the reason for that message is about elements.
///
/// `int_is_not_a_string` is beside it so the cell pair shows the two kinds sharing one reason rather than
/// a `Map` having its own. Giving `Map` a separate variant was considered and rejected: behaviour and
/// message are already right for every input that reaches the arm, so it would add a variant without
/// changing anything a rule author sees.
///
/// The forbidden fragment is doing the work on the first two cells, and it has to, because the two
/// messages are not independent strings: the element-level one reads "X holds a value that is not a
/// string, so it cannot be tested for containment", which CONTAINS the value-level one as a substring.
/// So a positive-only assertion on "is not a string, so it cannot be tested for containment" is
/// satisfied by either reason and discriminates nothing. The first draft of this test made the mirror
/// mistake and failed on `a_list_holding_a_non_string_is_about_its_elements`, where the forbidden
/// fragment matched inside that cell's own expected text.
///
/// The two list cells forbid each other's reason instead, and that is load-bearing rather than
/// symmetry-for-its-own-sake. `MixedList` used to reach `Partial` and report "Some but not all of",
/// which is what `found_in_string` testing for a non-string BEFORE counting hits exists to prevent, so
/// forbidding that string on `MixedList` pins the ordering. `BadList` is all strings, so the
/// element-kind reason must not appear for it.
#[rstest::rstest]
#[case::map_is_not_a_string(
    "Map not in Haystack",
    "is not a string, so it cannot be tested for containment",
    "holds a value that is not a string"
)]
#[case::int_is_not_a_string(
    "Int not in Haystack",
    "is not a string, so it cannot be tested for containment",
    "holds a value that is not a string"
)]
#[case::a_list_holding_a_non_string_is_about_its_elements(
    "MixedList not in Haystack",
    "holds a value that is not a string, so it cannot be tested for containment",
    "Some but not all of"
)]
#[case::a_partly_contained_list_is_about_how_much(
    "BadList not in Haystack",
    "Some but not all of",
    "holds a value that is not a string"
)]
fn the_reason_a_containment_cannot_be_asked_names_the_right_operand(
    #[case] clause: &str,
    #[case] expected_fragment: &str,
    #[case] forbidden_fragment: &str,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Haystack: "aws:arn:s3::${s3}",
        Map: { "a": 1 },
        Int: 5,
        MixedList: ["s3", 5],
        BadList: ["s3", "zzz"]
    }
    "#;

    let (status, messages) = status_and_messages(clause, INPUT)?;

    assert_eq!(
        Status::FAIL,
        status,
        "`{}` must fail closed; the message is only meaningful with the verdict",
        clause
    );

    let joined = messages.join("\n");

    assert!(
        joined.contains(expected_fragment),
        "`{}` must record a reason containing `{}`; recorded: {:?}",
        clause,
        expected_fragment,
        messages
    );

    assert!(
        !joined.contains(forbidden_fragment),
        "`{}` must NOT be given the reason for the other kind, containing `{}`; recorded: {:?}",
        clause,
        forbidden_fragment,
        messages
    );

    Ok(())
}

/// A decided element collision outranks an undecidable containment, in the arm as well as inside
/// `is_one_of`.
///
/// Why this exists. The two-query arm has two "third answers" for one value and they had opposite
/// precedence. `unanswerable_membership` is gated on `!element_collision`, with the reason written out
/// beside it -- a matched element decides the value, so the comparison that could not be evaluated
/// changed nothing -- and that is the precedence `is_one_of` applies internally, applied again at the
/// arm. `unanswerable_against` was checked unconditionally, one screen above it, so for a clause where
/// both fired the containment complaint won and the collision was never reported.
///
/// The clause that shows it. With `Vals` of `["abc", "zzz"]` and `Deny` of `["abcdef", "zzz"]`,
/// `Vals NOT IN Deny[*]` recorded `Some but not all of Value=["abc","zzz"] is contained in
/// Value="abcdef"` -- a statement that the question has no answer -- while `element_collision` was true,
/// because `"zzz"` is verbatim a denylist entry. Two right-hand results produce the two records: the
/// undecidable one comes from `"abcdef"`, which holds `"abc"` and not `"zzz"`, and the collision comes
/// from `"zzz"`, which one left-hand element equals exactly. So this is not a value the tool cannot
/// decide; it is a value the denylist names, described as undecidable.
///
/// A report defect and not a wrong verdict, which is why the status assertion is not the discriminating
/// one. `NotComparable` fails closed in both polarities -- measured, `Vals IN Deny[*]` and
/// `Vals NOT IN Deny[*]` are both exit 19 -- and a non-empty `diff` carrying a collision also fails
/// both, so the exit code is 19 before and after. What moves is which record a rule author reads: the
/// undecidable reason disappears and an `InComparison` naming the collision takes its place. A
/// status-only assertion cannot see that, which is the same blind spot
/// `the_reason_a_containment_cannot_be_asked_names_the_right_operand` above was written to cover.
///
/// Which answer should win, and why it is the collision. A collision is a claim the arm can support:
/// the denylist holds this element, so `NOT IN` denies it on that basis and the report can say so. An
/// undecidable containment supports no claim about the value at all. Reporting the second while holding
/// the first states the weaker of two findings and discards the one a rule author can act on. The arm
/// already agreed with that twice -- `found_in_string`'s `All` continues the outer loop immediately, and
/// `unanswerable_membership` yields to `element_collision` -- so this is one site joining a rule the
/// other two already follow rather than a new rule.
///
/// Why nothing caught it. `found_in_string` outranks the collision arm for essentially every string
/// pairing, so `e331c6b`'s arm has observable effect only when no right-hand value is a string -- which
/// is what its own reproducer used, `rhs_kind=int`. Traced: for a list-valued left-hand side against a
/// string right operand, if any element is contained the answer is `Partial` or `All`, and if any element
/// is not a string it is `HoldsANonString`; both record or continue before the collision can decide.
/// Only "every element is a string and none is contained" reaches the collision arm, and an element that
/// EQUALS the string would also be contained in it, so that case can never produce a collision either.
/// The mixed case in this test is the gap: the undecidable record and the collision come from different
/// right-hand results, so neither of those traces applies to both at once.
///
/// `an_int_denylist_reports_the_collision` is the control for the shape that always worked, where no
/// right-hand value is a string and so nothing competes with the collision. A fix credited with it has
/// not touched the defect.
#[rstest::rstest]
// THE DEFECT. Both third answers fire, from different right-hand results, and the collision must be the
// one reported.
#[case::a_string_denylist_reports_the_collision_not_the_undecidable_containment(
    "Vals NOT IN Deny[*]",
    "Some but not all of"
)]
// The same clause in the other polarity. `IN` fails for a different reason -- the value is unmatched --
// and must not carry the undecidable reason either.
#[case::the_in_polarity_reports_no_undecidable_reason_either(
    "Vals IN Deny[*]",
    "Some but not all of"
)]
// The control: an int denylist, so no right-hand value is a string, `found_in_string` records nothing,
// and the collision was always the answer.
#[case::an_int_denylist_reports_the_collision("Ints NOT IN DenyInts[*]", "Some but not all of")]
fn a_decided_element_collision_outranks_an_undecidable_containment(
    #[case] clause: &str,
    #[case] forbidden_fragment: &str,
) -> Result<()> {
    // `Deny` holds one entry that CONTAINS a left-hand element without equalling it and one that equals
    // another element exactly. That split is the fixture: one entry drives `found_in_string` to
    // `Partial` and the other drives `is_one_of` to `Matched`, so the two third answers come from
    // different right-hand results and compete.
    const INPUT: &str = r#"
    {
        Vals: ["abc", "zzz"],
        Deny: ["abcdef", "zzz"],
        Ints: [1, 2],
        DenyInts: [2, 7]
    }
    "#;

    let (status, messages) = status_and_messages(clause, INPUT)?;

    assert_eq!(
        Status::FAIL,
        status,
        "`{}` must fail closed; this change moves the report, not the verdict",
        clause
    );

    assert!(
        !messages.join("\n").contains(forbidden_fragment),
        "`{}` names a value the denylist holds verbatim, so it must NOT be reported as undecidable \
         with a reason containing `{}`; recorded: {:?}",
        clause,
        forbidden_fragment,
        messages
    );

    Ok(())
}

/// The collision the clause above must report, asserted positively on the record variant.
///
/// The negative assertion next door cannot tell "the collision is reported" from "nothing is reported":
/// `recorded_comparison_messages` only reads `Comparison` records, and the membership claim is an
/// `InComparison` carrying no message at all. So a fix that dropped both third answers would satisfy it.
/// This reads the variants instead, which is what `recorded_clause_check_kinds` exists for and the same
/// pairing `an_unanswerable_containment_records_one_verdict_not_two` uses.
#[rstest::rstest]
#[case::a_string_denylist("Vals NOT IN Deny[*]")]
#[case::an_int_denylist("Ints NOT IN DenyInts[*]")]
fn a_reported_collision_is_recorded_as_a_membership_check(#[case] clause: &str) -> Result<()> {
    const INPUT: &str = r#"
    {
        Vals: ["abc", "zzz"],
        Deny: ["abcdef", "zzz"],
        Ints: [1, 2],
        DenyInts: [2, 7]
    }
    "#;

    let rules = format!("rule r {{\n  {clause}\n}}");
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let value = PathAwareValue::try_from(INPUT)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut root, None)?;
    let mut kinds = Vec::new();
    recorded_clause_check_kinds(&root.reset_recorder().extract(), &mut kinds);

    assert_eq!(Status::FAIL, status, "clause: {}", clause);

    assert!(
        kinds.iter().any(|kind| kind.starts_with("InComparison")),
        "`{}` must record the collision as a membership check; recorded: {:?}",
        clause,
        kinds
    );

    Ok(())
}

/// Runs one clause and returns the rule's status together with the deprecation notices recorded.
///
/// Separate from `status_and_messages` next door, and the distinction is the reason a notice that
/// contradicted its own clause went unnoticed for two commits. A deprecation notice is not a record
/// message: it is inserted into `RootScope::deprecations`, a set the commands drain to stderr once
/// evaluation is over, and it never appears in the record tree at all. So `recorded_comparison_messages`
/// cannot see one however it is worded, and a test that wants to assert on a notice has to read the
/// scope rather than the tree.
///
/// The notices come back in `BTreeSet` order rather than emission order. Nothing here depends on the
/// order, and a caller that starts to should assert on membership instead: two notices about the same
/// clause are deduplicated by the set, so emission order is not recoverable from it anyway.
fn status_and_deprecations(clause: &str, input: &str) -> Result<(Status, Vec<String>)> {
    deprecations_for_rules(&format!("rule r {{\n  {clause}\n}}"), input)
}

/// The same, for a caller that needs to write the rule itself.
///
/// A clause wrapped in `rule r { ... }` is always an assertion, so the helper above cannot express a
/// clause whose role is `Gate` -- a `when` condition or a filter predicate. Those are where a failing
/// clause is absorbed rather than reported, which is the case the notice gate turns on, so a test for
/// it has to supply the whole rule.
fn deprecations_for_rules(rules: &str, input: &str) -> Result<(Status, Vec<String>)> {
    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(input)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut root, None)?;
    let notices = root.deprecations().cloned().collect();
    Ok((status, notices))
}

/// Runs one clause and returns the rule's status together with the comparison messages recorded.
fn status_and_messages(clause: &str, input: &str) -> Result<(Status, Vec<String>)> {
    let rules = format!("rule r {{\n  {clause}\n}}");
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let value = PathAwareValue::try_from(input)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut root, None)?;
    let mut messages = Vec::new();
    recorded_comparison_messages(&root.reset_recorder().extract(), &mut messages);
    Ok((status, messages))
}

/// One byte below the backtracking threshold for `(?!x)((a+)+)b` on the map-key filter path, and one
/// byte above it. The pattern compiles either way -- `fancy-regex` is a backtracking engine and
/// supports the lookahead -- so what differs is whether `is_match` finishes.
const SEVENTEEN_AS: &str = "aaaaaaaaaaaaaaaaa";
const EIGHTEEN_AS: &str = "aaaaaaaaaaaaaaaaaa";

/// A map-key filter says when a comparison had no answer, and stays quiet when it had one.
///
/// All four comparators reach the same regex through `[ keys <op> ... ]`, and two of them dropped the
/// reason. `real_binary_operation` routes `==`/`!=` to `report_all_values` and so to `report_value`,
/// which 07774380 taught to carry the reason; `IN`/`NOT IN` route to `report_by_lhs`, which that
/// commit's scoping sentence named and did not change.
///
/// **Status cannot be the assertion here.** Every cell's status is identical with the defect present
/// and with it fixed, so a status or exit-code assertion is satisfied either way -- the shape of a test
/// that cannot fail. What moves is the recorded message, so that is what is read. The status is still
/// asserted, per case, to pin that it does not move.
///
/// The seventeen-character control is the other half, and without it this test would only show that a
/// diagnostic is present rather than that it is present *for the right reason*. The threshold is a
/// property of the template, not of the rule: seventeen `a` characters decide cleanly -- the pattern
/// finds no `b` -- and eighteen exhaust the budget. A build that attached the reason unconditionally
/// would pass the eighteen-character cells and fail the seventeen-character ones.
///
/// The status grid is worth reading, because it is not uniform and an earlier draft of this test
/// assumed it was:
///
/// ```text
///            ==     !=     in     not in
///   17 `a`   FAIL   PASS   FAIL   PASS
///   18 `a`   FAIL   FAIL   FAIL   FAIL
/// ```
///
/// The negated comparators move from PASS to FAIL on one extra byte of map key. A key that decidedly
/// does not match satisfies `!=` and `NOT IN`, so it is selected and `!empty` holds; a key nobody could
/// decide about fails closed, so nothing is selected and `!empty` does not. That is the
/// template-dependence made concrete, and it is the direction that does not lose a violation -- the
/// verdict gets stricter, not laxer. Before this change it happened with no diagnostic at all, which is
/// the whole cost: a rule silently stopped deciding above a length nobody chose, and the only signal
/// was a verdict that also has an innocent explanation.
///
/// The two decided FAIL cells carry the discriminating weight for the negative half, since a PASS
/// records no comparison message at all and would satisfy the negative assertion trivially.
///
/// The pattern is not uncompilable and the failure is not a parse error. `guard/Cargo.toml` pins
/// `fancy-regex`, whose engine backtracks and accepts `(?!x)`; `((a+)+)` is what makes the number of
/// paths grow with the length of the subject, and the error text is "Max limit for backtracking count
/// exceeded" from `is_match`, not from compilation.
#[rstest::rstest]
#[case::equals_undecidable("==", CATASTROPHIC, EIGHTEEN_AS, Status::FAIL, true)]
#[case::equals_decided("==", CATASTROPHIC, SEVENTEEN_AS, Status::FAIL, false)]
#[case::not_equals_undecidable("!=", CATASTROPHIC, EIGHTEEN_AS, Status::FAIL, true)]
#[case::not_equals_decided("!=", CATASTROPHIC, SEVENTEEN_AS, Status::PASS, false)]
#[case::in_undecidable("in", "[/(?!x)((a+)+)b/]", EIGHTEEN_AS, Status::FAIL, true)]
#[case::in_decided("in", "[/(?!x)((a+)+)b/]", SEVENTEEN_AS, Status::FAIL, false)]
#[case::not_in_undecidable("not in", "[/(?!x)((a+)+)b/]", EIGHTEEN_AS, Status::FAIL, true)]
#[case::not_in_decided("not in", "[/(?!x)((a+)+)b/]", SEVENTEEN_AS, Status::PASS, false)]
fn a_map_key_filter_says_when_a_comparison_had_no_answer(
    #[case] operator: &str,
    #[case] rhs: &str,
    #[case] key: &str,
    #[case] expected: Status,
    #[case] expect_reason: bool,
) -> Result<()> {
    const REASON: &str = "could not be evaluated";

    let input = format!(r#"{{ "Cfg": {{ "{key}": 1, "other": 2 }} }}"#);
    let clause = format!("Cfg[ keys {operator} {rhs} ] !empty");
    let rules = format!("rule r {{\n  {clause}\n}}");

    let rules_file = RulesFile::try_from(rules.as_str())?;
    let value = PathAwareValue::try_from(input.as_str())?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut root, None)?;
    let mut messages = Vec::new();
    recorded_clause_messages(&root.reset_recorder().extract(), &mut messages);

    // Asserted to document that it does NOT discriminate: unchanged by this fix in every cell, which
    // is why the message is what the rest of the test reads.
    assert_eq!(
        expected,
        status,
        "`{}` over a {}-character key changed verdict; this fix is about what the report says, not \
         what it decides",
        clause,
        key.len()
    );

    let said = messages.iter().any(|m| m.contains(REASON));
    match expect_reason {
        true => assert!(
            said,
            "`{}` over {} characters exhausts the backtracking budget, so the report must say the \
             comparison had no answer rather than that the key did not match; recorded {:?}",
            clause,
            key.len(),
            messages
        ),
        false => assert!(
            !said,
            "`{}` over {} characters is decided -- the pattern finds no `b` -- so no explanation is \
             owed, and one appearing here would mean the reason is attached unconditionally rather \
             than to the comparisons that had none; recorded {:?}",
            clause,
            key.len(),
            messages
        ),
    }

    Ok(())
}

const CATASTROPHIC: &str = "/(?!x)((a+)+)b/";

const THIRTY_AS: &str = r#"
{
    Resources: {
        V: { Type: 'AWS::EC2::Volume', Properties: { Size: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' } }
    }
}
"#;

/// The same thirty characters, held in a one-element list rather than as a scalar.
///
/// Two brackets of difference in the template, and they decide which arm of `contained_in` answers:
/// a scalar reaches the `rest =>` arm and a list reaches the `List` arm. Nothing about the regex or
/// the clause changes, which is what makes the pair a measurement of the arms rather than of the
/// pattern.
const THIRTY_AS_IN_A_LIST: &str = r#"
{
    Resources: {
        V: { Type: 'AWS::EC2::Volume', Properties: { Size: ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] } }
    }
}
"#;

/// A scalar against a one-element list answers the same whether the list was typed or resolved.
///
/// `EqOperation::compare` unwraps a one-element list on the right and compares the scalar with that
/// element, but only in the `(None, Some)` arm -- the one a *literal* right-hand side reaches.
/// `is_literal` returns `Some` for a single `QueryResult::Literal` alone, so a variable bound to a
/// query arrives as `Resolved`, lands in the `(None, None)` arm, and that arm compares the scalar
/// with the list as a whole. `compare_eq_symmetric` has no scalar-against-list arm, so it refuses,
/// and the refusal is reported as `PathAwareValues are not comparable String, array`.
///
/// So with `Val: Name` and `OneKey: [Name]`, `Val == ["Name"]` passed and `Val == %onekey` exited 19
/// on the same two values. The negated spelling is the one that costs more: `Val != ["Other"]` passed
/// and `Val != %otherkey` failed, so a rule asserting that a value differs from a reference rejected
/// a document where it plainly does -- a false finding rather than a missed one.
///
/// The unwrap here is symmetric, and `variable_lhs_matches` is why. This arm reads `==` as equality of
/// two operand *sets* and folds in both directions, deliberately, so that an extra value on either
/// side is seen. Unwrapping on one side only would leave `%onekey == Val` failing on the reverse pass
/// with the forward pass already matched -- the same defect, mirrored, and no better for having half
/// a fix.
///
/// The four two-element cells are the control that keeps the unwrap narrow. A scalar and a list of two
/// are not comparable in either spelling and in either polarity, and they must stay that way: this
/// unwraps a one-element list, it does not widen `==` to membership. The two `IN` cells are the
/// reference rather than a guard -- membership already agreed across both spellings, which is what
/// `==` had to be brought up to.
///
/// The `lit_` cells are the same defect in the arms the first fix did not reach, and the count came out
/// of running them rather than out of reading the code. A one-element list can arrive as a document
/// property, as a variable bound to a query, or as a rule literal, and against a scalar arriving the
/// same three ways that is six orderings. Five of them were wrong and are named here:
///
///     %lit_name    == Val            (Some, None)   list on the left, refused
///     %lit_other   != Val            (Some, None)   list on the left, refused
///     %lit_name    == %scalar_name   (Some, Some)   list on the left, refused
///     %scalar_name == %lit_name      (Some, Some)   list on the right, refused
///     %lit_other   != %scalar_name   (Some, Some)   list on the left, refused
///
/// `%lit_other != Val` is the expensive one, the same shape as `variable_rhs_differs` above: two values
/// that visibly differ, and the clause asserting they differ exited 19 with "PathAwareValues are not
/// comparable array, String".
///
/// `query_list_lhs_matches` and `literal_scalar_lhs_matches` are the two orderings that were already
/// right, and they are here because they are right for a different reason. Those arms walk the list and
/// compare element by element rather than unwrapping, which agrees with the unwrap for a list of one
/// and would keep agreeing if the unwrap were removed. Without them, the fix looks like it is what makes
/// those two cells pass.
///
/// The four `lit_two` cells extend the narrowness control to the literal spellings. A list of two
/// against a scalar must stay incomparable however the two operands were written.
///
/// The `one_element_range_` and `one_element_regex_` cells cover the kinds the unwrap moved but the
/// grid did not. Every cell above is a string against a string, in six orderings, so the whole table
/// held even though `compare_eq_unwrapping_a_one_element_list` sits in front of `compare_eq`'s range
/// arms and its regex arm too -- and those are the two kinds where the unwrap is doing something a
/// plain element-wise walk would not. `[r[80,90]]` against a `Port` of `85` and `[/Nam/]` against a
/// `Val` of `Name` are that question, both orderings each, because being asked from every arm is this
/// function's whole point. The `_unwrapped_reference` cells are the answers the bracketed spellings
/// have to agree with: a clause that answers differently depending on whether the range or the regex
/// was bracketed is its own defect, which is what the string cells above were written to say.
///
/// `two_element_range_list_stays_incomparable` is the narrowness control for those kinds, matching what
/// the `lit_two` cells do for strings. Both polarities, because a list of two against a scalar has no
/// right answer either way and must not acquire one by widening the unwrap.
///
/// All eleven were already green when added. They are coverage for a landed change rather than a repair,
/// which is why nothing here moves and no code changed with them. Two of them earn their place under
/// measurement rather than by argument: restricting `single_element` inside
/// `compare_eq_unwrapping_a_one_element_list` to unwrap only a `String` reddens
/// `one_element_range_lhs` and `one_element_regex_lhs` and NOTHING else in the suite -- 1094 passed,
/// 2 failed -- so those two are the only cells anywhere that catch a kind-blind regression in the
/// unwrap. The other nine did not fall to that perturbation, or to removing the inline `rhsl[0]` unwrap
/// in the `(None, Some)` arm, which leaves the whole suite green because the comparator called on both
/// sides of that branch unwraps anyway. They are kept as the agreement and narrowness statements the
/// grid is built out of, not as canaries.
#[rstest::rstest]
#[case::literal_rhs_matches(r#"Val == ["Name"]"#, Status::PASS)]
#[case::variable_rhs_matches("Val == %onekey", Status::PASS)]
#[case::variable_lhs_matches("%onekey == Val", Status::PASS)]
#[case::literal_rhs_differs(r#"Val == ["Other"]"#, Status::FAIL)]
#[case::variable_rhs_differs("Val == %otherkey", Status::FAIL)]
#[case::negated_literal_rhs_matches(r#"Val != ["Name"]"#, Status::FAIL)]
#[case::negated_variable_rhs_matches("Val != %onekey", Status::FAIL)]
#[case::negated_literal_rhs_differs(r#"Val != ["Other"]"#, Status::PASS)]
#[case::negated_variable_rhs_differs("Val != %otherkey", Status::PASS)]
#[case::two_element_literal_is_not_unwrapped(r#"Val == ["Name", "Other"]"#, Status::FAIL)]
#[case::two_element_variable_is_not_unwrapped("Val == %twokeys", Status::FAIL)]
#[case::negated_two_element_literal(r#"Val != ["Name", "Other"]"#, Status::FAIL)]
#[case::negated_two_element_variable("Val != %twokeys", Status::FAIL)]
#[case::in_spelling_already_agrees_literal(r#"Val IN ["Name"]"#, Status::PASS)]
#[case::in_spelling_already_agrees_variable("Val IN %onekey", Status::PASS)]
#[case::literal_list_lhs_matches("%lit_name == Val", Status::PASS)]
#[case::literal_list_lhs_differs("%lit_other == Val", Status::FAIL)]
#[case::negated_literal_list_lhs_matches("%lit_name != Val", Status::FAIL)]
#[case::negated_literal_list_lhs_differs("%lit_other != Val", Status::PASS)]
#[case::both_literal_list_lhs_matches("%lit_name == %scalar_name", Status::PASS)]
#[case::both_literal_list_rhs_matches("%scalar_name == %lit_name", Status::PASS)]
#[case::both_literal_list_lhs_differs("%lit_other == %scalar_name", Status::FAIL)]
#[case::negated_both_literal_list_lhs_matches("%lit_name != %scalar_name", Status::FAIL)]
#[case::negated_both_literal_list_lhs_differs("%lit_other != %scalar_name", Status::PASS)]
#[case::query_list_lhs_matches("OneKey == %scalar_name", Status::PASS)]
#[case::negated_query_list_lhs_differs("OtherKey != %scalar_name", Status::PASS)]
#[case::literal_scalar_lhs_matches("%scalar_name == OneKey", Status::PASS)]
#[case::negated_literal_scalar_lhs_differs("%scalar_name != OtherKey", Status::PASS)]
#[case::two_element_literal_list_lhs("%lit_two == Val", Status::FAIL)]
#[case::negated_two_element_literal_list_lhs("%lit_two != Val", Status::FAIL)]
#[case::two_element_both_literal("%lit_two == %scalar_name", Status::FAIL)]
#[case::negated_two_element_both_literal("%lit_two != %scalar_name", Status::FAIL)]
#[case::one_element_range_rhs("Port == %lit_range", Status::PASS)]
#[case::one_element_range_lhs("%lit_range == Port", Status::PASS)]
#[case::negated_one_element_range("Port != %lit_range", Status::FAIL)]
#[case::one_element_range_uncovered("Val == %lit_range", Status::FAIL)]
#[case::one_element_range_unwrapped_reference("Port == r[80,90]", Status::PASS)]
#[case::one_element_regex_rhs("Val == %lit_re", Status::PASS)]
#[case::one_element_regex_lhs("%lit_re == Val", Status::PASS)]
#[case::negated_one_element_regex("Val != %lit_re", Status::FAIL)]
#[case::one_element_regex_unwrapped_reference("Val == /Nam/", Status::PASS)]
#[case::two_element_range_list_stays_incomparable("Port == %lit_two_ranges", Status::FAIL)]
#[case::negated_two_element_range_list("Port != %lit_two_ranges", Status::FAIL)]
fn a_one_element_list_compares_the_same_typed_as_resolved(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Val: "Name",
        Port: 85,
        OneKey: ["Name"],
        OtherKey: ["Other"],
        TwoKeys: ["Name", "Other"]
    }
    "#;

    let rules = format!(
        "let onekey = OneKey\nlet otherkey = OtherKey\nlet twokeys = TwoKeys\n\
         let lit_name = [\"Name\"]\nlet lit_other = [\"Other\"]\n\
         let lit_two = [\"Name\", \"Other\"]\nlet scalar_name = \"Name\"\n\
         let lit_range = [r[80,90]]\nlet lit_re = [/Nam/]\n\
         let lit_two_ranges = [r[10,20], r[80,90]]\n\
         rule r {{ {clause} }}"
    );

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "r")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// `IN` against a string is containment, and a query on the right answers it like a literal does.
///
/// Substring `IN` is reached through `string_in`, and `InOperation::compare` calls it only from the two
/// arms whose right-hand side satisfies `is_literal`. A query right-hand side resolves to `Resolved`,
/// so `%needle in Haystack` and `Needle in Haystack` both fall through to `contained_in`, where two
/// scalars end at `compare_eq` -- equality. The identical question spelled with the string written out
/// passed. This is not a new operator: `Needle in "aws:arn:s3::${s3}"` is containment today and has
/// been since the clause form existed. It is one reading of `IN` that two spellings disagreed about.
///
/// The `denied_` cells are the ones that mattered enough to fix. `Needle not in Haystack` PASSED with
/// `Needle` a verbatim substring of what `Haystack` holds -- a denylist admitting the value it names,
/// at exit 0. All three spellings of it (scalar query needle, literal needle, list needle) did the
/// same, and all three now fail. Every one of them already failed when the haystack was typed as a
/// literal, so this closes a gap rather than tightening a rule: no clause that reports compliance
/// today under the literal spelling reports differently now.
///
/// `list_needle_query_haystack` follows the arm it has to agree with rather than the other list rule
/// in this operator. With a string literal on the right, a list-valued left-hand side is expanded and
/// every element checked, so `["s3","arn"] in "aws:arn:s3::${s3}"` holds and `["s3","zzz"]` does not.
/// The `(None, None)` arm compares a left-hand result whole, so the expansion happens inside the
/// containment test instead. An empty list does not match, which follows `contained_in`'s `is_empty`
/// guard rather than inventing a second answer for a vacuous comparison.
///
/// A left-hand side that arrived as a literal is NOT expanded, and the two `list_literal_needle` cells
/// pin that. `%list_lit in "aws:arn:s3::${s3}"` fails today -- the literal-to-literal arm asks
/// `string_in` on the list as a whole, gets "not comparable", and falls through -- so the query-
/// right-hand spelling of it has to fail too. Expanding it would make the query spelling the more
/// permissive of the two, which is the shape of the defect being fixed here, pointing the other way.
///
/// The `int_needle` and `list_membership` cells are controls. A non-string operand stays incomparable
/// in both spellings, and `IN` against an actual list is still membership: nothing above touches the
/// reading that `docs/CLAUSES.md` documents.
///
/// The five scalar type cells -- `Int`, `Float`, `Bool`, `Map`, `Null` -- are the same defect one type
/// at a time, and they are separate from `int_needle` because the two spellings reach different arms.
/// `%int` is a literal and goes to `(Some, None)`, which asks `contained_in` per result and reports the
/// incomparable answer, so both polarities failed there and the earlier `int_needle` cells pinned it.
/// A property reference goes to `(None, None)`, which keeps one verdict for the whole operand set and
/// treated an incomparable pairing as a plain miss -- so `Int not in Haystack` reported compliance at
/// exit 0 for every non-string value a document can hold, while `Int not in "aws:arn:s3::${s3}"` failed.
/// Naming the type in each case matters because a fix aimed at one of them would leave the rest: the
/// only thing the five have in common is that containment cannot be asked of them.
///
/// `undenied_wholly_absent_list_query_haystack` is the control that decides where the fix goes. Making
/// the loop report `contained_in`'s "not comparable" answer also closes the five cells above, and it
/// breaks this one: a list against a string is an incomparable pair too, and containment has already
/// decided that pairing correctly as a genuine miss. `NoneList not in Haystack` must stay PASS.
#[rstest::rstest]
#[case::query_needle_literal_haystack(r#"Needle in "aws:arn:s3::${s3}""#, Status::PASS)]
#[case::query_needle_query_haystack("Needle in Haystack", Status::PASS)]
#[case::literal_needle_literal_haystack(r#"%needle in "aws:arn:s3::${s3}""#, Status::PASS)]
#[case::literal_needle_query_haystack("%needle in Haystack", Status::PASS)]
#[case::list_needle_literal_haystack(r#"NeedleList in "aws:arn:s3::${s3}""#, Status::PASS)]
#[case::list_needle_query_haystack("NeedleList in Haystack", Status::PASS)]
#[case::absent_query_needle_literal_haystack(r#"Absent in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::absent_query_needle_query_haystack("Absent in Haystack", Status::FAIL)]
#[case::absent_literal_needle_query_haystack("%absent in Haystack", Status::FAIL)]
#[case::partly_absent_list_literal_haystack(r#"BadList in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::partly_absent_list_query_haystack("BadList in Haystack", Status::FAIL)]
#[case::denied_query_needle_literal_haystack(r#"Needle not in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::denied_query_needle_query_haystack("Needle not in Haystack", Status::FAIL)]
#[case::denied_literal_needle_literal_haystack(
    r#"%needle not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_literal_needle_query_haystack("%needle not in Haystack", Status::FAIL)]
#[case::denied_list_needle_literal_haystack(
    r#"NeedleList not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_list_needle_query_haystack("NeedleList not in Haystack", Status::FAIL)]
#[case::undenied_query_needle_literal_haystack(
    r#"Absent not in "aws:arn:s3::${s3}""#,
    Status::PASS
)]
#[case::undenied_query_needle_query_haystack("Absent not in Haystack", Status::PASS)]
#[case::undenied_literal_needle_query_haystack("%absent not in Haystack", Status::PASS)]
#[case::list_literal_needle_literal_haystack(r#"%list_lit in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::list_literal_needle_query_haystack("%list_lit in Haystack", Status::FAIL)]
#[case::int_needle_literal_haystack(r#"%int in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::int_needle_query_haystack("%int in Haystack", Status::FAIL)]
#[case::list_membership_literal(r#"Needle in ["s3", "other"]"#, Status::PASS)]
#[case::list_membership_query("Needle in NeedleList", Status::PASS)]
#[case::denied_partly_absent_list_literal_haystack(
    r#"BadList not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_partly_absent_list_query_haystack("BadList not in Haystack", Status::FAIL)]
#[case::wholly_absent_list_literal_haystack(r#"NoneList in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::wholly_absent_list_query_haystack("NoneList in Haystack", Status::FAIL)]
#[case::undenied_wholly_absent_list_literal_haystack(
    r#"NoneList not in "aws:arn:s3::${s3}""#,
    Status::PASS
)]
#[case::undenied_wholly_absent_list_query_haystack("NoneList not in Haystack", Status::PASS)]
#[case::partly_typed_list_literal_haystack(r#"MixedList in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::partly_typed_list_query_haystack("MixedList in Haystack", Status::FAIL)]
#[case::denied_partly_typed_list_literal_haystack(
    r#"MixedList not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_partly_typed_list_query_haystack("MixedList not in Haystack", Status::FAIL)]
#[case::wholly_typed_list_literal_haystack(r#"IntList in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::wholly_typed_list_query_haystack("IntList in Haystack", Status::FAIL)]
#[case::denied_wholly_typed_list_literal_haystack(
    r#"IntList not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_wholly_typed_list_query_haystack("IntList not in Haystack", Status::FAIL)]
#[case::int_query_needle_literal_haystack(r#"Int in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::int_query_needle_query_haystack("Int in Haystack", Status::FAIL)]
#[case::denied_int_query_needle_literal_haystack(r#"Int not in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::denied_int_query_needle_query_haystack("Int not in Haystack", Status::FAIL)]
#[case::float_query_needle_literal_haystack(r#"Float in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::float_query_needle_query_haystack("Float in Haystack", Status::FAIL)]
#[case::denied_float_query_needle_literal_haystack(
    r#"Float not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_float_query_needle_query_haystack("Float not in Haystack", Status::FAIL)]
#[case::bool_query_needle_literal_haystack(r#"Bool in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::bool_query_needle_query_haystack("Bool in Haystack", Status::FAIL)]
#[case::denied_bool_query_needle_literal_haystack(
    r#"Bool not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_bool_query_needle_query_haystack("Bool not in Haystack", Status::FAIL)]
#[case::map_query_needle_literal_haystack(r#"Map in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::map_query_needle_query_haystack("Map in Haystack", Status::FAIL)]
#[case::denied_map_query_needle_literal_haystack(r#"Map not in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::denied_map_query_needle_query_haystack("Map not in Haystack", Status::FAIL)]
#[case::null_query_needle_literal_haystack(r#"Null in "aws:arn:s3::${s3}""#, Status::FAIL)]
#[case::null_query_needle_query_haystack("Null in Haystack", Status::FAIL)]
#[case::denied_null_query_needle_literal_haystack(
    r#"Null not in "aws:arn:s3::${s3}""#,
    Status::FAIL
)]
#[case::denied_null_query_needle_query_haystack("Null not in Haystack", Status::FAIL)]
fn substring_in_answers_the_same_against_a_query_as_against_a_literal(
    #[case] clause: &str,
    #[case] expected: Status,
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Needle: "s3",
        Absent: "zzz",
        Haystack: "aws:arn:s3::${s3}",
        NeedleList: ["s3", "arn"],
        BadList: ["s3", "zzz"],
        NoneList: ["zz", "qq"],
        MixedList: ["s3", 5],
        IntList: [5, 6],
        Int: 5,
        Float: 5.5,
        Bool: true,
        Map: { "a": 1 },
        Null: null
    }
    "#;

    let rules = format!(
        "let needle = \"s3\"\nlet absent = \"zzz\"\nlet list_lit = [\"s3\", \"arn\"]\n\
         let int = 5\nrule r {{ {clause} }}"
    );

    assert_eq!(
        expected,
        rule_status_in(&rules, INPUT, "r")?,
        "clause: {}",
        clause
    );

    Ok(())
}

/// A value containment cannot be asked of records one verdict, not two that disagree.
///
/// `unanswerable_and_nothing_unmatched` in the `(None, None)` arm of `InOperation::compare` had no test
/// at all: removing it left 976 passed and 0 failed. It also had a comment that described something it
/// does not do. The comment said an empty `diff` "would otherwise report Success", implying the flag
/// keeps a clause from passing; measured, the clause exits 19 either way, because the `NotComparable`
/// record fails closed on its own and decides the verdict whatever else is recorded beside it.
///
/// What it actually does is decide how many verdicts the report carries, and the `NOT IN` spelling is
/// where that shows. Without the flag, `Int not in Haystack` for an `Int` of `5` records two FAILs about
/// one value: a `Comparison` saying `/Int` is not a string so containment cannot be tested, and an
/// `InComparison` filing `/Int` as a value that was present in the haystack. The second contradicts the
/// first and is the one a denylist report would show as the violation. On the `IN` spelling the second
/// record is a bare `Success` with no message and no operands, so the message list is unchanged there --
/// which is why this test compares record *variants* and `recorded_comparison_messages` could not have
/// caught it.
///
/// `Values[*]` is why the flag is no longer called `every_value_was_unanswerable`. Its condition is that
/// something was unanswerable and nothing was left unmatched, and with `Values: ["s3", 5]` both hold
/// while one of the two values was perfectly answerable and matched in full. The old name described a
/// narrower case than the code, so a reader checking whether the flag applied would have concluded it
/// did not.
///
/// The last three cells are the control. When nothing was unanswerable the flag is false and the single
/// `QueryIn` record must still be recorded, including the `InComparison` that reports a genuine
/// collision -- `Needle not in Haystack` is a real violation and has to keep filing one.
#[rstest::rstest]
#[case::unanswerable_in("Int in Haystack", Status::FAIL, &["Comparison(FAIL)"])]
#[case::unanswerable_not_in("Int not in Haystack", Status::FAIL, &["Comparison(FAIL)"])]
#[case::partly_unanswerable_in("Values[*] in Haystack", Status::FAIL, &["Comparison(FAIL)"])]
#[case::partly_unanswerable_not_in("Values[*] not in Haystack", Status::FAIL, &["Comparison(FAIL)"])]
#[case::answerable_in("Needle in Haystack", Status::PASS, &["Success"])]
#[case::answerable_not_in("Needle not in Haystack", Status::FAIL, &["InComparison(FAIL)"])]
#[case::answerable_miss_not_in("NoneList not in Haystack", Status::PASS, &["Success"])]
fn an_unanswerable_containment_records_one_verdict_not_two(
    #[case] clause: &str,
    #[case] expected: Status,
    #[case] expected_kinds: &[&str],
) -> Result<()> {
    const INPUT: &str = r#"
    {
        Needle: "s3",
        Haystack: "aws:arn:s3::${s3}",
        Int: 5,
        Values: ["s3", 5],
        NoneList: ["zz", "qq"]
    }
    "#;

    let rules = format!("rule r {{ {clause} }}");
    let rules_file = RulesFile::try_from(rules.as_str())?;
    let value = PathAwareValue::try_from(INPUT)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    let mut kinds = Vec::new();
    recorded_clause_check_kinds(&root.reset_recorder().extract(), &mut kinds);

    assert_eq!(expected, status, "clause: {}", clause);
    assert_eq!(expected_kinds, kinds.as_slice(), "clause: {}", clause);

    Ok(())
}
