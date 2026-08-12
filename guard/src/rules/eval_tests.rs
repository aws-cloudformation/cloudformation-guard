use crate::utils::writer::Writer;
use grep_searcher::SearcherBuilder;
use indoc::formatdoc;
use pretty_assertions::{assert_eq, assert_ne};
use std::collections::HashMap;

use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use crate::rules::eval_context::{
    root_scope, simplified_json_from_root, ClauseReport, EventRecord, RecordTracker,
};

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

/// A LIVE DEFECT INTRODUCED BY THIS BRANCH: a wrong FAIL across a named-rule gate.
///
/// This is the cost of the empty-collection FAIL, and it was not visible until a reviewer
/// measured the *satisfiable-body* case. Earlier gate fixtures all used a failing body, so
/// both "gate opened, body failed" and "gate closed, body dropped" exited 19 and the exit
/// code could not tell them apart.
///
/// `vac_eq` compares an empty collection, so it FAILs (correctly, as an assertion). `body`
/// gates on it. `eval_rule` treats any non-PASS condition as "rule does not apply", so
/// `body` is dropped even though its own check would pass:
///
/// - v3.2.0: exit 0, both rules compliant — but see below, that PASS is itself the defect.
/// - this branch: exit 19, `not_compliant: [vac_eq]`, `not_applicable: [body]`.
///
/// The regression is the `not_applicable: [body]`, not the exit code, and the distinction is
/// the point: exit 19 cannot tell "gate opened, body failed" from "gate closed, body dropped".
/// v3.2.0's exit 0 is not the target to restore, because it comes from `Tags == 'Owner'`
/// reporting *compliant* against `Tags: []` — the empty-collection wrong PASS this branch
/// removes. Asserting that status would make this test green exactly when the defect is
/// reintroduced.
///
/// Cause is the named-rule boundary: `eval_context.rs:1116` evaluates a named rule's body
/// with `ClauseRole::Assertion` whatever the reference site is, so the `role.is_strict()`
/// guard on the empty-collection arm cannot see that the rule is being used as a gate. At a
/// *syntactic* `when` the guard works and the gate opens — verified separately — so this is
/// specific to the named-rule spelling.
///
/// Not reverted, deliberately: reverting restores the original wrong PASS, where
/// `Tags == 'Owner'` certifies `Tags: []` as compliant, and a wrong PASS on a policy gate is
/// worse than a wrong FAIL. But it is a real regression, and it is why keying the rule-status
/// cache on `(rule, role)` is a prerequisite for finishing this work rather than a
/// refinement. Scope is bounded: the same shape with populated data is unaffected on every
/// pin.
#[test]
#[ignore = "known regression from this branch: empty-collection FAIL drops a named-rule gate's body"]
fn a_named_rule_gate_does_not_drop_a_satisfiable_body() -> Result<()> {
    // `Name` matches what `body` requires, so `body` is satisfiable. Only `Tags: []` is
    // unusual, and it is what makes the gate condition fail.
    let input = r#"
    {
        Resources: {
            b: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    // The named-rule spelling is the subject, so it has to stay. Every named rule in Guard is
    // also a top-level rule, so `vac_eq` cannot be hidden from the file-level fold.
    let named_gate = r###"
    rule vac_eq {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags == 'Owner'
    }
    rule body when vac_eq {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'publicbucket'
    }
    "###;

    // Asserted on `body`'s own applicability, NOT on the file's status. Both halves of that
    // choice are load-bearing.
    //
    // The file status cannot express this regression. `eval_rules_file` evaluates every
    // top-level rule with `ClauseRole::Assertion` unconditionally (eval.rs:2354) and folds
    // `fails > 0 -> FAIL` (eval.rs:2379), so a `vac_eq` that fails strictly forces the file to
    // FAIL however the gate behaves. Keying the rule-status cache on `(rule, role)` fixes the
    // gate and cannot touch that fold.
    //
    // And the file status that *would* make this file PASS is itself the defect: on v3.2.0
    // `Tags == 'Owner'` reports `compliant` against `Tags: []`, which is the empty-collection
    // wrong PASS this branch removes. An earlier version of this test asserted exactly that
    // PASS as its target — so it would have gone green precisely when the defect was
    // reintroduced, with a green suite certifying the opposite.
    //
    // What is both reachable and wrong-PASS-free is narrower: `body` is satisfiable, so it
    // must not be reported not-applicable. `vac_eq` failing is correct and stays correct.
    let report_for = |data: &str| -> Result<Vec<String>> {
        let resources = PathAwareValue::try_from(data)?;
        let rules_file = RulesFile::try_from(named_gate)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        let _ = eval_rules_file(&rules_file, &mut root, None)?;
        let top = root.reset_recorder().extract();
        Ok(simplified_json_from_root(&top)?.not_applicable.into_iter().collect())
    };

    // Liveness first, for the reason recorded on the ordering reproduction: an absence claim
    // is satisfied when nothing runs at all, so a query that stopped selecting would let the
    // claim below pass while blind. With populated tags the gate opens on real evidence.
    let populated = r#"
    {
        Resources: {
            b: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: ['Owner'] }
            }
        }
    }
    "#;
    let live = report_for(populated)?;
    assert!(
        live.is_empty(),
        "liveness: with `Tags: ['Owner']` both rules apply and nothing should be \
         not-applicable, got {:?}. Anything else means the query stopped selecting and the \
         claim below is meaningless.",
        live
    );

    // The claim.
    let dropped = report_for(input)?;
    assert!(
        !dropped.iter().any(|name| name == "body"),
        "`body` was reported not-applicable even though its own check passes: the failing \
         gate condition swallowed it. not_applicable = {:?}",
        dropped
    );

    Ok(())
}

/// A LIVE DEFECT, pre-existing in v3.2.0: `IN` certifies an empty collection as compliant.
///
/// `Tags IN ['Owner']` against `Tags: []` exits 0 and reports `"compliant"` with
/// `not_applicable: []` — an affirmative certification that the policy held. The mechanism
/// is in `contained_in`: `diff` is "elements of the left side absent from the right", so an
/// empty left side produces an empty `diff` and an affirmative `Success`. This is *not* the
/// empty-`statues` fold that `2224cb1` addressed for `==`; a result is pushed, and it is a
/// positive one. A fix must suppress a wrong Success rather than supply a missing entry.
///
/// Two measurements say the current behaviour is not merely a defensible reading of
/// universal quantification:
///
/// - The same template under `==` fails (exit 19). One spelling of "the tag must be Owner"
///   blocks the deployment and the other certifies it.
/// - `Tags not in ['Owner']` on the same empty list *also* fails (19). A proposition and its
///   negation cannot both be unsatisfied, so the pair is internally inconsistent whatever
///   the intended reading.
///
/// Ignored rather than fixed because the guard belongs at the `eval.rs`
/// `EmptyLhsCollection` arm, where the clause role is visible — failing this inside a `when`
/// condition would close the gate and drop the guarded body, which is how two earlier
/// attempts on this branch regressed. `EmptyLhsCollection` is currently emitted only by
/// `EqOperation`, so routing `InOperation` and `CommonOperator` through it changes the
/// comparator contract. Runs under `cargo test -- --ignored`; will pass when addressed.
#[test]
#[ignore = "known defect, pre-existing in v3.2.0: IN certifies an empty collection as compliant"]
fn in_does_not_certify_an_empty_collection() -> Result<()> {
    let rules = r###"
    rule tags_must_name_owner {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags IN ['Owner']
    }
    "###;

    let input = r#"
    {
        Resources: {
            b: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));

    // FAIL, matching what the same rule spelled with `==` already does. SKIP would also be
    // arguable — "no tags, so nothing to check" — but PASS is not: it affirmatively
    // certifies a bucket that carries none of the required tags.
    assert_eq!(eval_rules_file(&rules_file, &mut root, None)?, Status::FAIL);

    Ok(())
}

/// A LIVE DEFECT, pre-existing in v3.2.0: the ordering operators certify an empty collection.
///
/// This is the same class as `in_does_not_certify_an_empty_collection` but a *different
/// impl* — `CommonOperator`, not `contained_in` — so a fix for `IN` will not touch it. Worth
/// its own test for that reason.
///
/// The argument that this is a defect rather than defensible vacuous truth is stronger here
/// than for `IN`. `Ports <= 100` and `Ports > 100` are exact logical negations, and **both**
/// return PASS on the same `Ports: []`. Universal quantification over an empty set defends
/// "every element satisfies P" for both P and not-P; it cannot defend certifying `x <= 100`
/// and `x > 100` for the same x. `<` and `>=` behave identically — all four route through
/// the same impl.
///
/// Ignored rather than fixed for the same reason as the `IN` case, and here the hazard is
/// measured rather than inferred: `rule r when ...Ports <= 100 { ...Name == 'safe' }` exits
/// 19 on `Ports: []` *because* the vacuous PASS opens the gate and the body then catches a
/// violating name. Making the comparison non-PASS in the comparator turns that into exit 0
/// with the body dropped — one unenforced clause traded for a disarmed block.
#[test]
#[ignore = "known defect, pre-existing in v3.2.0: <= and > both certify an empty collection"]
fn ordering_operators_do_not_certify_an_empty_collection() -> Result<()> {
    let input = r#"
    {
        Resources: {
            sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { Ports: [] } }
        }
    }
    "#;

    // Exact logical negations. At most one may pass for any given input.
    let le = r###"
    rule ports_must_be_low {
        Resources.*[ Type == 'AWS::EC2::SecurityGroup' ].Properties.Ports <= 100
    }
    "###;
    let gt = r###"
    rule ports_must_be_high {
        Resources.*[ Type == 'AWS::EC2::SecurityGroup' ].Properties.Ports > 100
    }
    "###;

    // Liveness FIRST, and it is not decoration. An earlier version of this test asserted
    // only `passes <= 1` over the two negations, which had two false greens:
    //
    // - Rename one character in the Type filter and both rules SKIP. SKIP is not PASS, so
    //   `passes == 0` satisfied `<= 1` and the test went green while blind.
    // - Add one resource that genuinely violates `<= 100`. The rule aggregates across
    //   resources, so `> 100` becomes FAIL overall and `passes` drops to 1 — green, with the
    //   rule text unchanged and the empty resource still certified under both negations.
    //   Verified from the blame paths that the empty resource is never named.
    //
    // Going absolute per operator kills the second but not the first: rot yields SKIP and
    // `SKIP != PASS`, so an `assert_ne!(PASS)` claim alone still passes blind. The liveness
    // rows are what close that — under rot they fail before the claim is reached.
    //
    // `[9]` rather than `[80]` for the liveness row on purpose: `"9" <= "100"` is false
    // lexicographically and true numerically, so this row also pins numeric comparison. That
    // matters because an earlier measurement of this operator class was confounded by string
    // ordering, and `[8080]` discriminates nothing — it is false under both readings.
    let live_low = r#"
    { Resources: { sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { Ports: [9] } } } }
    "#;
    let live_high = r#"
    { Resources: { sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { Ports: [8080] } } } }
    "#;

    let status_of_pair = |rules: &str, data: &str| -> Result<Status> {
        let resources = PathAwareValue::try_from(data)?;
        let rules_file = RulesFile::try_from(rules)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        eval_rules_file(&rules_file, &mut root, None)
    };

    assert_eq!(
        status_of_pair(le, live_low)?,
        Status::PASS,
        "liveness: `Ports <= 100` must pass on [9] — numerically true, lexicographically \
         false, so this also pins numeric semantics. A SKIP here means the query stopped \
         selecting and every other row in this test is meaningless."
    );
    assert_eq!(
        status_of_pair(le, live_high)?,
        Status::FAIL,
        "liveness: `Ports <= 100` must fail on [8080]"
    );
    assert_eq!(
        status_of_pair(gt, live_high)?,
        Status::PASS,
        "liveness: `Ports > 100` must pass on [8080]"
    );
    assert_eq!(
        status_of_pair(gt, live_low)?,
        Status::FAIL,
        "liveness: `Ports > 100` must fail on [9]"
    );

    // The claim, stated absolutely per operator rather than as a count. Each negation is
    // asserted on its own, so no aggregation across resources and no SKIP can launder it.
    assert_ne!(
        status_of_pair(le, input)?,
        Status::PASS,
        "`Ports <= 100` certified an empty collection"
    );
    assert_ne!(
        status_of_pair(gt, input)?,
        Status::PASS,
        "`Ports > 100` certified an empty collection"
    );

    Ok(())
}

/// The control for the ordering operators, which must keep passing.
///
/// Both polarities on populated collections, so a future fix for the empty case cannot
/// quietly break ordinary numeric comparison. These are the rows that make the empty row
/// above interpretable — without them, a wrong answer on `[]` could just mean the rule or
/// the query was malformed.
///
/// It also pins **numeric** rather than lexicographic comparison, which is a stronger
/// guarantee than it looks and is load-bearing here: an earlier measurement of this operator
/// class was discarded as confounded by string ordering. Note which fixtures carry that
/// weight. `[8080]` discriminates nothing — `8080 <= 100` and `"8080" <= "100"` are both
/// false. `[80]` and `[9]` are the discriminating ones: `"80" <= "100"` and `"9" <= "100"` are
/// both false lexicographically (`'8'`/`'9'` > `'1'` at index 0) and true numerically, so a
/// PASS on either can only be numeric.
#[test]
fn ordering_operators_still_decide_populated_collections_correctly() -> Result<()> {
    let rules = r###"
    rule ports_must_be_low {
        Resources.*[ Type == 'AWS::EC2::SecurityGroup' ].Properties.Ports <= 100
    }
    "###;

    // Both discriminate numeric from lexicographic; `[9]` most sharply, since it is a single
    // digit and cannot be read as "shorter string sorts first".
    let low = r#"
    { Resources: { sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { Ports: [80] } } } }
    "#;
    let single_digit = r#"
    { Resources: { sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { Ports: [9] } } } }
    "#;
    let high = r#"
    { Resources: { sg: { Type: 'AWS::EC2::SecurityGroup', Properties: { Ports: [8080] } } } }
    "#;

    let rules_file = RulesFile::try_from(rules)?;

    for (data, want, why) in [
        (low, Status::PASS, "80 <= 100 numerically; false lexicographically"),
        (single_digit, Status::PASS, "9 <= 100 numerically; false lexicographically"),
        (high, Status::FAIL, "8080 <= 100 is false under either reading"),
    ] {
        let resources = PathAwareValue::try_from(data)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        assert_eq!(
            eval_rules_file(&rules_file, &mut root, None)?,
            want,
            "{}",
            why
        );
    }

    Ok(())
}

/// The control for the above, which must keep passing: `IN` on a populated collection.
///
/// Pinned separately so that a future fix for the empty case cannot quietly break the
/// ordinary one. Both polarities are exercised — a satisfying list passes, a violating list
/// fails — which is what establishes that the rule and query are well formed and that only
/// the empty case is wrong.
#[test]
fn in_still_decides_populated_collections_correctly() -> Result<()> {
    let rules = r###"
    rule tags_must_name_owner {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags IN ['Owner']
    }
    "###;

    let satisfying = r#"
    { Resources: { b: { Type: 'AWS::S3::Bucket', Properties: { Tags: ['Owner'] } } } }
    "#;
    let violating = r#"
    { Resources: { b: { Type: 'AWS::S3::Bucket', Properties: { Tags: ['Backup'] } } } }
    "#;

    let rules_file = RulesFile::try_from(rules)?;

    let resources = PathAwareValue::try_from(satisfying)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    assert_eq!(eval_rules_file(&rules_file, &mut root, None)?, Status::PASS);

    let resources = PathAwareValue::try_from(violating)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    assert_eq!(eval_rules_file(&rules_file, &mut root, None)?, Status::FAIL);

    Ok(())
}

/// Every FAIL must state a reason. This asserts report *contents*, not just status.
///
/// The gap this closes: no test in the repository asserted anything about a report's
/// `checks`, so a FAIL that produced an empty report was green in all 355 of them. The
/// empty-collection FAIL added by `2224cb1` did exactly that — `eval_context.rs`'s
/// `QueryResult::Resolved` arm wrapped its whole body in `if let Some(to) = to` with no
/// `else`, and that FAIL is the one construction site pairing a resolved `from` with
/// `to: None`, so it pushed no `ClauseReport` at all.
///
/// The visible result was exit 19 with `checks: []` in JSON and YAML, `results: []` in
/// SARIF, an empty `<failure/>` in JUnit, and "Number of non-compliant resources 0" on the
/// console — a blocked deployment with nothing to act on, and the message built at the
/// construction site never reaching any output.
///
/// Written against the general property rather than the one operator that exposed it: any
/// rule reporting FAIL must carry at least one clause explaining why.
#[test]
fn a_failing_rule_always_reports_at_least_one_reason() -> Result<()> {
    // Three shapes that all FAIL, including both operand orders of the empty-collection
    // case. The third is a plain scalar mismatch, which reported correctly all along and
    // is here so the test would catch a regression in the normal path too.
    let rulesets = [
        r###"
        rule tags_must_name_owner {
            Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags == 'Owner'
        }
        "###,
        r###"
        let expected = 'Owner'
        rule tags_must_name_owner_mirrored {
            %expected == Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags
        }
        "###,
        r###"
        rule name_must_be_private {
            Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'privatebucket'
        }
        "###,
    ];

    let input = r#"
    {
        Resources: {
            bucketEmptyTags: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    // Asserted through the serialized structured output rather than the internal report
    // type, for two reasons: the builder is private to eval_context, and this is the
    // artifact a user or a CI job actually consumes. `checks: []` under a FAIL is exactly
    // what the defect looked like from outside.
    for rules in rulesets {
        let resources = PathAwareValue::try_from(input)?;
        let rules_file = RulesFile::try_from(rules)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        let status = eval_rules_file(&rules_file, &mut root, None)?;

        assert_eq!(
            status,
            Status::FAIL,
            "ruleset was expected to fail, ruleset was: {}",
            rules
        );

        // Assert on the CONSTRUCTED report, not on the recorded evaluation tree.
        //
        // This distinction is the whole point. `eval.rs` always wrote a ClauseValueCheck
        // record, so a test that walked the recorder passed even with the defect present --
        // I wrote that test first and the mutation check caught it. The report builder in
        // eval_context is where the record was dropped, so that is the layer to assert at.
        let top = root.reset_recorder().extract();
        let report = simplified_json_from_root(&top)?;

        assert!(
            !report.not_compliant.is_empty(),
            "a failing file reported nothing non-compliant, ruleset was: {}",
            rules
        );
        for clause in &report.not_compliant {
            assert!(
                !clause_report_is_empty(clause),
                "rule reported FAIL with an empty report, so every format renders it as a \
                 blocked deployment with no stated reason. Ruleset was: {}",
                rules
            );
        }
    }

    Ok(())
}

/// True when a report names a failure but carries nothing explaining it.
///
/// Structural rather than message-keyed on purpose: the property is "the report has
/// something in it", and asserting on wording would accept a report that says the wrong
/// thing while rejecting a correct rewording.
fn clause_report_is_empty(report: &ClauseReport<'_>) -> bool {
    match report {
        ClauseReport::Rule(rule) => {
            rule.checks.is_empty() || rule.checks.iter().all(clause_report_is_empty)
        }
        // A block report is a leaf: it carries its own message rather than children.
        ClauseReport::Block(_) => false,
        ClauseReport::Disjunctions(disj) => {
            disj.checks.is_empty() || disj.checks.iter().all(clause_report_is_empty)
        }
        // A leaf clause report is the thing that explains a failure, so reaching one means
        // the report is not empty.
        ClauseReport::Clause(_) => false,
    }
}

/// A denylist written with a parameter did not block the value it named.
///
/// `LetValue::Value` -- a literal argument at the call site -- was bound as
/// `QueryResult::Resolved`, while `resolve_variable` returns `let` literals as
/// `QueryResult::Literal`. `is_literal` recognises only the latter, so the two spellings
/// of the same literal took different comparator arms: `let` reached the element-wise
/// `(None, Some(_))` arm, and a parameter reached `(None, None)`, which compares whole
/// query results through `diff`. A list-valued left side was therefore compared against
/// the scalar *as a list*, never matched, and the negation inverted that into a pass.
///
/// The blast radius is not empty collections. `Tags: ["PublicRead"]` -- a populated list
/// holding exactly the banned value -- passed, while the byte-identical policy with the
/// value inlined or bound with `let` correctly failed.
#[test]
fn a_denylist_passed_through_a_parameter_still_blocks_the_banned_value() -> Result<()> {
    let rules = r###"
    rule no_banned_tag(banned) {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != %banned
    }

    rule main { no_banned_tag("PublicRead") }
    "###;

    let input = r#"
    {
        Resources: {
            exposedBucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "customerdata", Tags: ['PublicRead'] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));

    assert_eq!(eval_rules_file(&rules_file, &mut root, None)?, Status::FAIL);

    Ok(())
}

/// The positive half of the same defect: `==` through a parameter was inverted.
///
/// It failed the template that *did* match and passed the one that did not, for the same
/// reason -- a whole-list-versus-scalar comparison whose result happened to be wrong in
/// both directions. Asserted together with the negated form because a fix that corrects
/// only one of them would leave the arm half-wrong in a way a single-polarity test cannot
/// see.
#[test]
fn a_positive_comparison_through_a_parameter_matches_the_right_template() -> Result<()> {
    let rules = r###"
    rule tag_must_match(wanted) {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags == %wanted
    }

    rule main { tag_must_match("Keeper") }
    "###;

    let matching = r#"
    {
        Resources: {
            b: { Type: 'AWS::S3::Bucket', Properties: { Tags: ['Keeper'] } }
        }
    }
    "#;

    let non_matching = r#"
    {
        Resources: {
            b: { Type: 'AWS::S3::Bucket', Properties: { Tags: ['Other'] } }
        }
    }
    "#;

    let rules_file = RulesFile::try_from(rules)?;

    let resources = PathAwareValue::try_from(matching)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    assert_eq!(
        eval_rules_file(&rules_file, &mut root, None)?,
        Status::PASS,
        "the template carrying the wanted tag must pass"
    );

    let resources = PathAwareValue::try_from(non_matching)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    assert_eq!(
        eval_rules_file(&rules_file, &mut root, None)?,
        Status::FAIL,
        "the template without the wanted tag must fail"
    );

    Ok(())
}

/// A literal argument must behave identically however it is spelled.
///
/// This is the property the fix restores, and the one whose absence made the defect
/// invisible: every spelling other than the parameter form was already correct, so any
/// fixture that inlined the value or used `let` passed.
#[test]
fn a_literal_argument_agrees_across_parameter_let_and_inline_spellings() -> Result<()> {
    let input = r#"
    {
        Resources: {
            b: { Type: 'AWS::S3::Bucket', Properties: { Tags: ['PublicRead'] } }
        }
    }
    "#;

    let parameterized = r###"
    rule deny(banned) { Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != %banned }
    rule main { deny("PublicRead") }
    "###;

    let let_bound = r###"
    let banned = 'PublicRead'
    rule main { Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != %banned }
    "###;

    let inlined = r###"
    rule main { Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != 'PublicRead' }
    "###;

    let mut statuses = Vec::new();
    for rules in [parameterized, let_bound, inlined] {
        let resources = PathAwareValue::try_from(input)?;
        let rules_file = RulesFile::try_from(rules)?;
        let mut root = root_scope(&rules_file, Rc::new(resources));
        statuses.push(eval_rules_file(&rules_file, &mut root, None)?);
    }

    assert_eq!(
        statuses,
        vec![Status::FAIL, Status::FAIL, Status::FAIL],
        "parameter, let and inline spellings of the same literal disagreed"
    );

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

//
// Empty collection on the left-hand side of a comparison.
//
// `flattened`/`selected` expand a list into its elements, so an empty list contributes
// none. The comparison loop then pushed zero results and the enclosing fold read an empty
// result vector as "nothing to check" and reported PASS -- so `Tags == 'Owner'` against
// `Tags: []` was reported as *compliant*, not as not-applicable. It claimed to have
// verified a property it never compared, while the same rule against a missing `Tags`
// correctly failed. The weaker input was treated more leniently.
//

#[test]
fn an_empty_collection_fails_a_positive_comparison_as_an_assertion() -> Result<()> {
    let rules = r###"
    rule tags_must_be_owner {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags == 'Owner'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL, not SKIP. SKIP would also exit 0, which is operationally identical to the
    // PASS being fixed: the clause would still go unenforced at the gate.
    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// The cardinality that a previous attempt at this fix silently failed to handle.
///
/// That attempt tested `lhs_flattened.is_empty()` -- the flattening of *all* query
/// results together -- so a single sibling with a non-empty list made it non-empty and the
/// guard never ran. It fired on single-resource templates and did nothing on the mixed
/// templates that are the common real-world shape, while passing every test written for
/// it, all of which had one resource.
///
/// This asserts the per-result behaviour directly: `BucketFull` genuinely satisfies the
/// rule, so the file-level FAIL can only come from `BucketEmpty` being caught.
#[test]
fn an_empty_collection_is_caught_even_when_a_sibling_resource_satisfies_the_rule() -> Result<()> {
    let rules = r###"
    rule tags_must_be_owner {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags == 'Owner'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucketEmpty: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            },
            bucketFull: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "privatebucket", Tags: ['Owner'] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// The counterpart, and the reason the fix is resolved by role rather than in the
/// comparator.
///
/// `eval_rule` treats any non-PASS condition as "this rule does not apply" and drops the
/// guarded body (eval.rs:2082). A fix that failed the empty comparison unconditionally
/// would therefore turn this blocked template into a passing one -- trading one unenforced
/// clause for an entire disarmed block. That is exactly how an earlier attempt regressed,
/// and it exits 0, so nothing downstream notices.
#[test]
fn an_empty_collection_in_a_when_condition_does_not_disarm_the_guarded_block() -> Result<()> {
    let rules = r###"
    rule name_must_be_safe when Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags == 'Owner' {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name != 'publicbucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL because the body ran and `publicbucket` violated it. A SKIP here would mean
    // the gate closed and the violation went unreported.
    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// The same defect written backwards, which the first version of this fix left open.
///
/// `'Owner' == Properties.Tags` is legal Guard and means what `Properties.Tags == 'Owner'`
/// means, but it takes a different comparator arm: the literal is the left side, so the
/// empty list arrives as the *right* operand and a separate loop pushes nothing. Fixing
/// only the first spelling left the wrong PASS reachable by anyone who happened to write
/// the operands in the other order -- measured 0 with the first fix in place, 19 now.
///
/// Found by asking which arms of `EqOperation` the fix did not touch, rather than by a
/// failing test. The asymmetry is invisible from the rule author's side.
#[test]
fn an_empty_collection_fails_when_it_is_the_right_hand_operand() -> Result<()> {
    let rules = r###"
    let expected = 'Owner'
    rule tags_must_be_owner {
        %expected == Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// The gate counterpart of the mirrored form. Same requirement as the un-mirrored gate
/// test: the guarded body must still run, so the violation is still reported.
#[test]
fn a_mirrored_empty_collection_in_a_when_condition_does_not_disarm_the_block() -> Result<()> {
    let rules = r###"
    let expected = 'Owner'
    rule name_must_be_safe when %expected == Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name != 'publicbucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// A negated comparison over an empty collection is vacuously true, so it must not fail.
///
/// The empty-LHS record is emitted before the per-value inversion, so a FAIL raised there
/// is one the `not` can never reach. Without the `!cmp.1` guard this reports FAIL, which
/// is a wrong FAIL: `not (Tags == 'Owner')` is satisfied when there are no tags at all.
#[test]
fn a_negated_comparison_over_an_empty_collection_does_not_fail() -> Result<()> {
    let rules = r###"
    rule r {
        Resources.*[ Type == 'AWS::S3::Bucket' ] {
            not Properties.Tags == 'Owner'
        }
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "n", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // PASS, and the fact that it is not SKIP is a known defect -- see
    // `a_vacuous_negated_clause_does_not_absorb_a_disjunction` below, which is #[ignore]d
    // with the reproduction and the reason.
    //
    // Not FAIL is the property this test guards, and it is real: `not (Tags == 'Owner')`
    // over an empty collection is vacuously true, so the clause must not be blamed for
    // having nothing to compare.
    //
    // PASS rather than SKIP matters because PASS short-circuits
    // `eval_conjunction_clauses`, so this clause can satisfy an `or` block and abandon its
    // siblings. Reporting SKIP here was implemented twice and reverted twice; the second
    // attempt regressed a named-rule gate from exit 19 to 0. The assertion is exact rather
    // than `assert_ne!(FAIL)` so that any future change to this status is visible instead
    // of silently admitted.
    assert_eq!(status, Status::PASS);

    Ok(())
}

/// A LIVE DEFECT, kept as an executable reproduction rather than a passing assertion.
///
/// `eval_conjunction_clauses` short-circuits on PASS (`continue 'conjunction'`) but absorbs
/// SKIP (`=> {}`), so a vacuously-satisfied first disjunct reported as PASS satisfies the
/// whole `or` and its siblings never run. Here the sibling is a real failing check, so the
/// file exits 0 while `Name` is `publicbucket`, and reports `"compliant"` -- not
/// `"not_applicable"`. Pre-existing: v3.2.0 exits 0 for this ruleset too.
///
/// Ignored because both fixes for it were worse than the defect. Returning SKIP from the
/// empty-collection arm was implemented twice:
///
/// - Unconditionally: closed the direct `when Tags != 'Owner'` gate, 19 -> 0.
/// - Narrowed to `role.is_strict()`: still closed a gate reached through a *named rule*,
///   19 -> 0, because `eval_context.rs:1116` evaluates every named rule's body with
///   `ClauseRole::Assertion` regardless of the reference site, and caches the status per
///   rule name so the poisoned SKIP is reused by later references.
///
/// `ClauseRole` carries the assertion/gate asymmetry at every syntactic site and cannot
/// carry it across a named-rule boundary, which erases the reference context by
/// construction. A real fix needs the reference-site role threaded into rule evaluation and
/// the status cache keyed on (rule, role) -- a change to the rule-evaluation contract.
///
/// Left ignored rather than deleted so the reproduction survives: `cargo test -- --ignored`
/// runs it, and it will start passing the moment the underlying issue is addressed.
///
/// Known weakness, recorded rather than fixed. `assert_eq!(FAIL)` is satisfied by *any* part
/// of the rule failing, so a one-line template edit reaches green without a fix: change
/// `Tags: []` to `Tags: ['Owner']` and the second disjunct performs a real comparison, really
/// fails, and the test passes while the vacuous-absorption defect is untouched. The rule is
/// named `vacuous_ne_absorbs_or`, so the signal to a reader editing the template is at least
/// present. Left as-is because tightening it would need the same liveness-plus-absolute shape
/// as `ordering_operators_do_not_certify_an_empty_collection`, and the fixture here has only
/// one meaningful data shape to vary — the empty list is the whole point of it.
///
/// Note for anyone running `--ignored`: five tests are ignored in this crate and they are
/// not the same kind of thing.
///
/// Introduced by this branch, so ours to answer for:
/// - This one, the vacuous-negation disjunction absorption.
/// - `a_named_rule_gate_does_not_drop_a_satisfiable_body` — a wrong FAIL: the
///   empty-collection FAIL drops the body of a rule that gates on it via a named reference.
///   Both of these need the rule-status cache keyed on `(rule, role)`, which is the single
///   prerequisite for finishing this work.
///
/// Pre-existing in v3.2.0, recorded not caused:
/// - `in_does_not_certify_an_empty_collection` and
///   `ordering_operators_do_not_certify_an_empty_collection` — the same class in two
///   different comparator impls, so fixing one will not resolve the other. Each has a
///   companion, non-ignored control pinning that populated collections still decide
///   correctly.
///
/// Not ours at all:
/// - `test_string_in_comparison`, an upstream failure parked in 2023 (commit `1aca9003`,
///   verified by `git blame`), failing identically on the pre-branch tree.
///
/// So four of the five should start passing when their defect is addressed; the fifth is not
/// ours and is not expected to.
#[test]
#[ignore = "known defect: vacuous negation absorbs a disjunction; both fixes regressed gates"]
fn a_vacuous_negated_clause_does_not_absorb_a_disjunction() -> Result<()> {
    let rules = r###"
    rule vacuous_ne_absorbs_or {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != 'Owner'
        or
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'safebucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL, from the sibling disjunct that actually got evaluated.
    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// A gate reached through a NAMED RULE, which is the shape that caught the reverted fix.
///
/// Every gate fixture in this file spells the condition inline (`rule r when <clause> {}`),
/// where `eval_when_clause` hardcodes `ClauseRole::Gate`. This one references a rule
/// instead, and that path is different in a way no inline fixture can show:
/// `eval_context.rs:1116` evaluates a named rule's body with `ClauseRole::Assertion`
/// whatever the reference site is, and caches the result per rule name.
///
/// So a fix that keys on `role.is_strict()` inside the clause sees "assertion" even though
/// the rule is being used as a gate. The reverted `EmptyQueryResult(SKIP)` did exactly
/// that: `vac_ne` returned SKIP, `eval_rule` read the non-PASS condition as "does not
/// apply", and the guarded body was dropped -- 19 -> 0, with the violating `publicbucket`
/// never examined and both rules reported `not_applicable`.
///
/// Guards the revert. If someone re-lands a SKIP-based fix without threading the
/// reference-site role through rule evaluation, this fails.
#[test]
fn a_vacuous_negation_inside_a_named_rule_does_not_close_the_gate_referencing_it() -> Result<()> {
    let rules = r###"
    rule vac_ne {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != 'Owner'
    }

    rule body_bad when vac_ne {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'privatebucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucketEmptyTags: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL because the gate opened and the body rejected `publicbucket`. SKIP would mean
    // the gate closed and the violation went unreported at exit 0.
    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// The counterpart that makes the fix above a role split rather than a status change.
///
/// A negated comparison over an empty collection opens its `when` gate *because* it folds
/// to PASS. Reporting SKIP for it unconditionally -- which an earlier version of this fix
/// did -- closes the gate, and `eval_rule` then drops every check in the guarded body
/// (`eval.rs:2082`). Measured at that point: exit 19 -> 0, the rule moved to
/// `not_applicable`, and the violating `publicbucket` was never examined. A worse defect
/// than the wrong PASS being fixed, and it exits 0 so nothing downstream notices.
///
/// So the vacuous PASS is load-bearing in a gate and a defect in a body. `ClauseRole`
/// carries exactly that asymmetry, and `vacuously_satisfied` is only set when
/// `role.is_strict()`.
#[test]
fn a_vacuous_negated_gate_still_opens_and_runs_its_body() -> Result<()> {
    let rules = r###"
    rule gated_by_vacuous_ne when Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != 'Owner' {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'privatebucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    // FAIL because the gate opened and the body ran. SKIP here would mean the gate closed
    // and the violation went unreported.
    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// The SKIP return is guarded on `statues.is_empty()`, and this is why.
///
/// `vacuously_satisfied` is function-scoped: any iteration can set it, and it is read once
/// at the end. When one query result is a vacuous negation and another produces a real
/// comparison, the flag must be ignored -- otherwise one resource with `Tags: []` would
/// suppress a genuine collision on its sibling and take the whole clause to SKIP.
///
/// Here `BucketEmpty` contributes the vacuous case and `BucketOwner` genuinely collides
/// with `!= 'Owner'`. Verified from the JSON that both the real collision on
/// `/Resources/BucketOwner/Properties/Tags/0` *and* the sibling disjunct on
/// `/Resources/BucketEmpty/Properties/Name` were evaluated, so the vacuous result neither
/// suppressed the failure nor absorbed the disjunction.
#[test]
fn a_vacuous_negation_does_not_suppress_a_real_result_from_a_sibling() -> Result<()> {
    let rules = r###"
    rule mixed_ne {
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != 'Owner'
        or
        Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'safebucket'
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucketEmpty: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            },
            bucketOwner: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "alsopublic", Tags: ['Owner'] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    assert_eq!(status, Status::FAIL);

    Ok(())
}

/// A vacuous negation nested inside a `when` block must not leak the SKIP outward.
///
/// The outer gate is unrelated to the empty collection, and the inner gate is the vacuous
/// negation. If the vacuous SKIP closed the inner gate, `privatebucket` would go unchecked
/// and the file would exit 0 -- the same silent-drop shape the top-level gate test pins,
/// one level down, where a `when` inside a `when` composes two gating decisions.
#[test]
fn a_vacuous_negation_nested_in_a_when_block_still_runs_the_inner_body() -> Result<()> {
    let rules = r###"
    rule nested_ne when Resources.*[ Type == 'AWS::S3::Bucket' ] !empty {
        when Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags != 'Owner' {
            Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Name == 'privatebucket'
        }
    }
    "###;

    let input = r#"
    {
        Resources: {
            bucket: {
                Type: 'AWS::S3::Bucket',
                Properties: { Name: "publicbucket", Tags: [] }
            }
        }
    }
    "#;

    let resources = PathAwareValue::try_from(input)?;
    let rules_file = RulesFile::try_from(rules)?;
    let mut root = root_scope(&rules_file, Rc::new(resources));
    let status = eval_rules_file(&rules_file, &mut root, None)?;

    assert_eq!(status, Status::FAIL);

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
    // If this total changes, find the new site, note which variant it records against, and confirm
    // it reaches rendered output before updating the number.
    const SITES_EXPECTED: usize = 19;

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
    // instead of collapsing into "did not match". Unchanged from the merge-base, so none of these is a
    // regression from this branch.
    //
    // No `empty_on_scalar` cell appears here, which is the point of the list: that clause used to
    // disarm its body in every one of these shapes, and it is what a reviewer found by hand.
    //
    // `in_list` has no `string_size` entry, and the reason is worth knowing: `IN` against a type it
    // cannot compare answers FAIL while `NOT IN` answers PASS, so the pair is not recognised as
    // undecidable and the invariant skips those cells. That disagreement between the two operators is
    // itself a defect -- `every_operator_and_operand_shape_agrees_with_a_stated_oracle` records it --
    // and closing it would add two entries here rather than remove any.
    const DISARMED_BY_AN_UNDECIDABLE_COMPARISON: [&str; 22] = [
        "eq_int/gate/absent_property",
        "eq_int/gate/absent_root",
        "eq_int/gate/string_size",
        "eq_int/nested_when/absent_property",
        "eq_int/nested_when/absent_root",
        "eq_int/nested_when/string_size",
        "gt_int/gate/absent_property",
        "gt_int/gate/absent_root",
        "gt_int/gate/string_size",
        "gt_int/nested_when/absent_property",
        "gt_int/nested_when/absent_root",
        "gt_int/nested_when/string_size",
        "in_list/gate/absent_property",
        "in_list/gate/absent_root",
        "in_list/nested_when/absent_property",
        "in_list/nested_when/absent_root",
        "le_float/gate/absent_property",
        "le_float/gate/absent_root",
        "le_float/gate/string_size",
        "le_float/nested_when/absent_property",
        "le_float/nested_when/absent_root",
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

/// A scalar function argument whose query selects nothing gets the diagnostic it already had.
///
/// `resolve_function` pushes the query's result verbatim, and an empty result is legitimate -- a filter
/// that matches no resource produces one. Every scalar-positional argument then indexed `[0]` on it,
/// which panicked at exit 101 *before* reaching the arm that already carried the right message. Five
/// sites: two in `substring`, two in `regex_replace`, one in `join`.
///
/// The first argument was never affected, because it is passed as a slice rather than indexed, which is
/// why this went unnoticed.
#[rstest::rstest]
#[case::substring_from("let r = substring(%s, %empty_sel, 3)", "second")]
#[case::substring_to("let r = substring(%s, 1, %empty_sel)", "third")]
#[case::join_separator("let r = join(%s, %empty_sel)", "second")]
fn a_function_argument_that_selects_nothing_does_not_panic(
    #[case] call: &str,
    #[case] which: &str,
) -> Result<()> {
    const INPUT: &str = r#"
    { Resources: { One: { Type: 'AWS::S3::Bucket' } } }
    "#;

    let rules = "let s = \"hello\"\nlet empty_sel = Resources[ Type == 'AWS::Nonexistent::Type' ]\nrule r {\n    CALL\n    %r == \"unused\"\n}\n"
        .replace("CALL", call);

    let rules_file = RulesFile::try_from(rules.as_str())?;
    let value = PathAwareValue::try_from(INPUT)?;
    let mut root = root_scope(&rules_file, Rc::new(value));
    let outcome = eval_rules_file(&rules_file, &mut root, None);

    let err = outcome.err().map(|e| format!("{}", e)).unwrap_or_default();
    assert!(
        err.contains(which),
        "{} must name the {} argument rather than abort; got {:?}",
        call,
        which,
        err
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
