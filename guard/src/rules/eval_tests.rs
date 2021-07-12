use super::*;
use crate::rules::eval_context::{root_scope, RecordTracker, Scope, EventRecord};
use crate::rules::eval_context::eval_context_tests::BasicQueryTesting;
use std::collections::HashMap;

//
// All unary function simple tests
//

#[test]
fn test_all_unary_functions() -> Result<()> {
    let path_value = PathAwareValue::try_from("{}")?;
    let non_empty_path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        Resources:
          ec2:
            Type: AWS::EC2::Instance
            Properties:
              ImageId: ami-123456789012
              Tags: []
        "#)?
    )?;
    let list_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"[1, 2, 3]"#)?
    )?;
    let empty_list_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"[]"#)?
    )?;
    let string_value = PathAwareValue::try_from(r#""String""#)?;
    let empty_string_value = PathAwareValue::try_from(r#""""#)?;
    let int_value = PathAwareValue::try_from(r#"10"#)?;
    let bool_value = PathAwareValue::try_from(r#"true"#)?;
    let float_value = PathAwareValue::try_from(r#"10.2"#)?;
    let char_range_value = PathAwareValue::try_from(r#"r[a, d)"#)?;
    let int_range_value = PathAwareValue::try_from(r#"r(10, 20)"#)?;
    let float_range_value = PathAwareValue::try_from(r#"r(10.0, 20.5]"#)?;

    let tests : Vec<(Box<dyn Fn(&QueryResult<'_>) -> Result<bool>>, Vec<QueryResult<'_>>, Vec<QueryResult<'_>>)> = vec![
        (
            Box::new(exists_operation),

            // Successful tests
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&non_empty_path_value),
            ],

            // Failure tests
            vec![
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string()
                })
            ]
        ),

        (
            Box::new(element_empty_operation),

            // Successful Tests
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&empty_string_value), // we do check for string empty as well
                QueryResult::Resolved(&empty_list_value),
                QueryResult::UnResolved(UnResolved {
                    remaining_query: "".to_string(),
                    reason: None,
                    traversed_to: &path_value,
                }),
            ],

            // Failure tests
            vec![
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value)
            ]
        ),

        (
            Box::new(is_string_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&string_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_int_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&int_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_list_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&empty_list_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&int_range_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_struct_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&non_empty_path_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&empty_list_value),
                QueryResult::Resolved(&float_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_bool_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&bool_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_float_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&float_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_char_range_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&char_range_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::Resolved(&float_range_value),
                QueryResult::Resolved(&int_range_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_int_range_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&int_range_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::Resolved(&float_range_value),
                QueryResult::Resolved(&char_range_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        ),

        (
            Box::new(is_float_range_operation),

            // Success Case
            vec![
                QueryResult::Resolved(&float_range_value)
            ],

            // Failure Cases
            vec![
                QueryResult::Resolved(&path_value),
                QueryResult::Resolved(&list_value),
                QueryResult::Resolved(&string_value),
                QueryResult::Resolved(&int_value),
                QueryResult::Resolved(&non_empty_path_value),
                QueryResult::Resolved(&char_range_value),
                QueryResult::Resolved(&char_range_value),
                QueryResult::UnResolved(UnResolved {
                    traversed_to: &path_value,
                    reason: None,
                    remaining_query: "".to_string(),
                })
            ]
        )
    ];

    for (index, (func, successes, failures)) in tests.iter().enumerate() {
        println!("Testing Case #{}", index);
        for (idx, each_success) in successes.iter().enumerate() {
            println!("Testing Success Case {}#{}", index, idx);
            assert_eq!((*func)(each_success)?, true);
        }
        for (idx, each_failure) in failures.iter().enumerate() {
            println!("Testing Failure Case {}#{}", index, idx);
            assert_eq!((*func)(each_failure)?, false);
        }
    }

    Ok(())
}

#[test]
fn query_empty_and_non_empty() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    let query = AccessQuery::try_from("Resources.*[ Type == /Bucket/ ]")?.query;
    let status = unary_operation(
        &query,
        (CmpOperator::Empty, true),
        false,
        "".to_string(),
        None,
        &eval)?;
    match status {
        EvaluationResult::QueryValueResult(expected) => {
            assert_eq!(expected.len(), 1);
            let matched = &expected[0].0;
            match matched {
                QueryResult::Resolved(res) => {
                    assert_eq!(res.self_path().0.as_str(), "/Resources/s3");
                },
                _ => unreachable!()
            }
        },

        EvaluationResult::EmptyQueryResult(_) => unreachable!()
    }

    let query = AccessQuery::try_from("Resources.*[ Type == /Broker/ ]")?.query;
    let status = unary_operation(
        &query,
        (CmpOperator::Empty, true),
        false,
        "".to_string(),
        None,
        &eval)?;
    match status {
        EvaluationResult::QueryValueResult(_) => unreachable!(),
        EvaluationResult::EmptyQueryResult(status) => {
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
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        Parameters:
          allowed_images: [ami-123456789012, ami-01234567890]
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    let query_ec2 = AccessQuery::try_from("Resources.ec2.Properties.ImageId")?.query;
    let lhs = eval.query(&query_ec2)?;
    assert_eq!(lhs.len(), 1);
    let lhs = match lhs[0] {
        QueryResult::Resolved(val) => val,
        _ => unreachable!()
    };
    let rhs_query = AccessQuery::try_from("Parameters.allowed_images")?.query;
    let rhs = eval.query(&rhs_query)?;
    let result = each_lhs_compare(
        crate::rules::path_value::compare_eq,
        lhs,
        &rhs
    )?;

    assert_eq!(result.len(), 1);
    let cmp_result = &result[0];
    match cmp_result {
        ComparisonResult::NotComparable(NotComparableResult{rhs: value, lhs: lh_ptr, reason}) => {
            let rhs_ptr = match &rhs[0] {
                QueryResult::Resolved(ptr) => *ptr,
                _ => unreachable!()
            };
            assert_eq!(std::ptr::eq(rhs_ptr, *value), true);
            assert_eq!(std::ptr::eq(lhs, *lh_ptr), true);
        },

        _ => unreachable!()
    }

    let result = each_lhs_compare(
        in_cmp(true), // not in operation
        lhs,
        &rhs
    )?;

    assert_eq!(result.len(), 1);
    let cmp_result = &result[0];
    match cmp_result {
        ComparisonResult::Comparable(ComparisonCheckResult { outcome, .. }) => {
            assert_eq!(*outcome, false);
        },

        _ => unreachable!()
    }

    let result = each_lhs_compare(
        in_cmp(false), // in operation
        lhs,
        &rhs
    )?;

    assert_eq!(result.len(), 1);
    let cmp_result = &result[0];
    match cmp_result {
        ComparisonResult::Comparable(ComparisonCheckResult { outcome, .. }) => {
            assert_eq!(*outcome, true);
        },

        _ => unreachable!()
    }


    Ok(())
}

#[test]
fn each_lhs_value_eq_compare() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        Parameters:
          allowed_images: [ami-123456789012, ami-01234567890]
        Resources:
           s3:
             Type: AWS::S3::Bucket
           ec2:
             Type: AWS::EC2::Instance
             Properties:
               ImageId: ami-123456789012
        "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    let query_ec2 = AccessQuery::try_from("Resources.ec2.Properties.ImageId")?.query;
    let lhs = eval.query(&query_ec2)?;
    assert_eq!(lhs.len(), 1);
    let lhs = match lhs[0] {
        QueryResult::Resolved(val) => val,
        _ => unreachable!()
    };
    let rhs_query = AccessQuery::try_from("Parameters.allowed_images[*]")?.query;
    let rhs = eval.query(&rhs_query)?;
    assert_eq!(rhs.len(), 2);
    let result = each_lhs_compare(
        crate::rules::path_value::compare_eq,
        lhs,
        &rhs
    )?;

    assert_eq!(result.len(), 2);
    for cmp_result in result {
        match cmp_result {
            ComparisonResult::Comparable(ComparisonCheckResult{ rhs, lhs, outcome }) => {
                let rhs = match rhs {
                    QueryResult::Resolved(rhs) => rhs,
                    _ => unreachable!()
                };
                if outcome {
                    match (lhs, rhs) {
                        (PathAwareValue::String((_,s1)), PathAwareValue::String((_, s2)))=> {
                            assert_eq!(s1, s2);
                            assert_eq!(std::ptr::eq(s1,s2), false);
                            assert_eq!(s1.as_str(), "ami-123456789012")
                        },
                        (_, _) => unreachable!()
                    }
                }
                else {
                    match (lhs, rhs) {
                        (PathAwareValue::String((_,s1)), PathAwareValue::String((_, s2)))=> {
                            assert_ne!(s1, s2);
                            assert_eq!(std::ptr::eq(s1,s2), false);
                            assert_eq!(s1.as_str(), "ami-123456789012");
                            assert_eq!(s2.as_str(), "ami-01234567890");
                        },
                        (_, _) => unreachable!()
                    }
                }
            },

            _ => unreachable!()
        }
    }

    Ok(())
}

#[test]
fn each_lhs_value_eq_compare_mixed_comparable() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    //
    // Equivalent of Resources.*.Properties.PolicyDocument.Statement[*].Principal
    //
    let lhs_query = AccessQuery::try_from(
        "Resources.*.Properties.PolicyDocument.Statement[*].Principal")?.query;
    let selected_lhs = eval.query(&lhs_query)?;
    assert_eq!(selected_lhs.len(), 2); // 2 statements present

    let rhs_value= PathAwareValue::try_from(r#""*""#)?;
    let rhs_query_result = vec![QueryResult::Resolved(&rhs_value)];
    for each_lhs in selected_lhs {
        match each_lhs {
            QueryResult::Resolved(lhs) => {
                for cmp_result in each_lhs_compare(
                    not_compare(crate::rules::path_value::compare_eq, true),
                    lhs,
                    &rhs_query_result)? {
                    match cmp_result {
                        ComparisonResult::Comparable(ComparisonCheckResult{ outcome, lhs, rhs}) => {
                            if !outcome {
                                assert_eq!(lhs.self_path().0.as_str(), "/Resources/iam/Properties/PolicyDocument/Statement/0/Principal");
                            }
                            else {
                                assert_eq!(lhs.self_path().0.starts_with("/Resources/iam/Properties/PolicyDocument/Statement/1/Principal"), true);
                            }
                        },

                        _ => unreachable!(),
                    }
                }
            },

            _ => unreachable!()
        }
    }

    Ok(())
}

#[test]
fn each_lhs_value_eq_compare_mixed_single_plus_array_form_correct_exec() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    //
    // Equivalent of Resources.*.Properties.PolicyDocument.Statement[*].Principal[*] == '*'
    //
    let lhs_query = AccessQuery::try_from(
        "Resources.*.Properties.PolicyDocument.Statement[*].Principal[*]")?.query;
    let selected_lhs = eval.query(&lhs_query)?;
    assert_eq!(selected_lhs.len(), 3); // 3 selected values

    let rhs_value= PathAwareValue::try_from(r#""*""#)?;
    let rhs_query_result = vec![QueryResult::Resolved(&rhs_value)];
    for each_lhs in selected_lhs {
        match each_lhs {
            QueryResult::Resolved(lhs) => {
                for cmp_result in each_lhs_compare(
                    crate::rules::path_value::compare_eq,
                    lhs,
                    &rhs_query_result)? {
                    match cmp_result {
                        ComparisonResult::Comparable(ComparisonCheckResult{ outcome, lhs, rhs}) => {
                            if outcome {
                                assert_eq!(lhs.self_path().0.as_str(), "/Resources/iam/Properties/PolicyDocument/Statement/0/Principal");
                            }
                            else {
                                match lhs.self_path().0.as_str() {
                                    "/Resources/iam/Properties/PolicyDocument/Statement/1/Principal/0" |
                                    "/Resources/iam/Properties/PolicyDocument/Statement/1/Principal/1" => {},
                                    _ => unreachable!()
                                }
                            }
                        },

                        _ => unreachable!()

                    }
                }
            },

            _ => unreachable!()
        }
    }

    Ok(())
}

macro_rules! test_case {
    ($rhs_value:expr, $lhs:expr, $eval:ident, $func:expr, $assert:expr) => {
        let lhs_gt_query = AccessQuery::try_from(
            $lhs
        )?.query;
        let rhs_value = $rhs_value;
        let values = $eval.query(&lhs_gt_query)?;
        for each_lhs in values {
            match each_lhs {
                QueryResult::Resolved(res) => {
                    for cmp_result in each_lhs_compare(
                        $func,
                        res,
                        &[QueryResult::Resolved(&rhs_value)]
                    )? {
                        match cmp_result {
                            ComparisonResult::Comparable(ComparisonCheckResult{outcome, lhs, rhs}) => {
                                assert_eq!(outcome, $assert);
                            },

                            _ => {}
                        }
                    }
                },

                _ => unreachable!()
            }
        }
    }
}

#[test]
fn binary_comparisons_gt_ge() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        values:
          int: 10
          ints: [20, 10]
          float: 1.0
          array: [1 ,2]
          string: Hi
    "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    //
    // Testing gt
    //
    test_case!(PathAwareValue::try_from("8")?, r#"values.int"#, eval, crate::rules::path_value::compare_gt, true);
    test_case!(PathAwareValue::try_from("8")?, r#"values.ints"#, eval, crate::rules::path_value::compare_gt, true);
    test_case!(PathAwareValue::try_from("8")?, r#"values.int"#, eval, crate::rules::path_value::compare_ge, true);
    test_case!(PathAwareValue::try_from("8")?, r#"values.ints"#, eval, crate::rules::path_value::compare_ge, true);
    test_case!(PathAwareValue::try_from("10")?, r#"values.ints"#, eval, crate::rules::path_value::compare_ge, true);

    test_case!(PathAwareValue::try_from("15")?, r#"values.int"#, eval, crate::rules::path_value::compare_gt, false);

    test_case!(PathAwareValue::try_from("0.5")?, r#"values.float"#, eval, crate::rules::path_value::compare_gt, true);
    test_case!(PathAwareValue::try_from("1.5")?, r#"values.float"#, eval, crate::rules::path_value::compare_gt, false);
    test_case!(PathAwareValue::try_from("1.0")?, r#"values.float"#, eval, crate::rules::path_value::compare_ge, true);

    test_case!(PathAwareValue::try_from(r#""Hi""#)?, r#"values.string"#, eval, crate::rules::path_value::compare_ge, true);
    test_case!(PathAwareValue::try_from(r#""Di""#)?, r#"values.string"#, eval, crate::rules::path_value::compare_gt, true);
    test_case!(PathAwareValue::try_from(r#""Ji""#)?, r#"values.string"#, eval, crate::rules::path_value::compare_gt, false);
    Ok(())
}

#[test]
fn binary_comparisons_lt_le() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        values:
          int: 10
          ints: [20, 10]
          float: 1.0
          array: [1 ,2]
          string: Hi
    "#)?
    )?;
    let eval = eval_context::eval_context_tests::BasicQueryTesting {
        root: &path_value
    };

    //
    // Testing gt
    //
    test_case!(PathAwareValue::try_from("8")?, r#"values.int"#, eval, crate::rules::path_value::compare_lt, false);
    test_case!(PathAwareValue::try_from("8")?, r#"values.ints"#, eval, crate::rules::path_value::compare_lt, false);
    test_case!(PathAwareValue::try_from("8")?, r#"values.int"#, eval, crate::rules::path_value::compare_le, false);
    test_case!(PathAwareValue::try_from("8")?, r#"values.ints"#, eval, crate::rules::path_value::compare_le, false);

    test_case!(PathAwareValue::try_from("20")?, r#"values.ints"#, eval, crate::rules::path_value::compare_le, true);
    test_case!(PathAwareValue::try_from("15")?, r#"values.int"#, eval, crate::rules::path_value::compare_lt, true);

    test_case!(PathAwareValue::try_from("0.5")?, r#"values.float"#, eval, crate::rules::path_value::compare_lt, false);
    test_case!(PathAwareValue::try_from("1.0")?, r#"values.float"#, eval, crate::rules::path_value::compare_le, true);
    test_case!(PathAwareValue::try_from("1.5")?, r#"values.float"#, eval, crate::rules::path_value::compare_lt, true);

    test_case!(PathAwareValue::try_from(r#""Hi""#)?, r#"values.string"#, eval, crate::rules::path_value::compare_le, true);
    test_case!(PathAwareValue::try_from(r#""Di""#)?, r#"values.string"#, eval, crate::rules::path_value::compare_lt, false);
    test_case!(PathAwareValue::try_from(r#""Ji""#)?, r#"values.string"#, eval, crate::rules::path_value::compare_lt, true);
    Ok(())
}


#[test]
fn test_compare_rulegen() -> Result<()> {
    let rulegen_created = r###"
let aws_ec2_securitygroup_resources = Resources.*[ Type == 'AWS::EC2::SecurityGroup' ]
rule aws_ec2_securitygroup when %aws_ec2_securitygroup_resources !empty {
  %aws_ec2_securitygroup_resources.Properties.SecurityGroupEgress == [{"CidrIp":"0.0.0.0/0","IpProtocol":-1},{"CidrIpv6":"::/0","IpProtocol":-1}]
}"###;
    let template = r###"
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
    "###;
    let rules = RulesFile::try_from(rulegen_created)?;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(template)?)?;
    let root = root_scope(&rules, &value)?;
    let tracker = RecordTracker::new(&root);
    let status = eval_rules_file(&rules, &tracker)?;
    assert_eq!(status, Status::PASS);
    Ok(())
}

#[test]
fn block_guard_pass() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;

    let block_clauses = GuardClause::try_from(
        r#"Resources[ Type == /Role/ ].Properties.PolicyDocument {
      Statement[*] {
         Principal != '*' <<No wildcard allowed for Principals>>
      }
    }
    "#)?;

    let eval = BasicQueryTesting { root: &path_value };
    let tracker = RecordTracker::new(&eval);
    let status = eval_guard_clause(&block_clauses, &tracker)?;
    assert_eq!(status, Status::FAIL);
    let top = tracker.extract();
    match top.container.as_ref() {
        Some(record) => {
            assert_eq!(matches!(record, RecordType::BlockGuardCheck(BlockCheck{ status: Status::FAIL, ..})), true);
            assert_eq!(top.children.len(), 1);
            let top_child = &top.children[0];
            assert_eq!(matches!(top_child.container.as_ref().unwrap(), RecordType::BlockGuardCheck(BlockCheck{ status: Status::FAIL, ..})), true);
            assert_eq!(top_child.children.len(), 2); // There are 2 Statements inside PolicyDocument
            for (idx, each) in top_child.children.iter().enumerate() {
                match each.container.as_ref() {
                    Some(inner) => {
                        if idx == 0 {
                            assert_eq!(matches!(inner, RecordType::GuardClauseBlockCheck(BlockCheck { status: Status::FAIL, ..})), true);
                            assert_eq!(each.children.len(), 1); // only on principal value
                            let guard_rec = &each.children[0];
                            match guard_rec.container.as_ref().unwrap() {
                                RecordType::ClauseValueCheck(
                                    ClauseCheck::Comparison(ComparisonClauseCheck {
                                        status: Status::FAIL,
                                        custom_message: Some(msg),
                                        message: None,
                                        comparison: (CmpOperator::Eq, true),
                                        from: QueryResult::Resolved(fromQ),
                                        to: Some(QueryResult::Resolved(_))
                                    })) => {
                                    assert_eq!(msg, "No wildcard allowed for Principals");
                                    assert_eq!(fromQ.self_path().0.as_str(), "/Resources/iam/Properties/PolicyDocument/Statement/0/Principal");
                                }
                                _ => unreachable!()
                            }
                        }
                        else {
                            assert_eq!(matches!(inner, RecordType::GuardClauseBlockCheck(BlockCheck { status: Status::PASS, ..})), true);
                            assert_eq!(each.children.len(), 2); // there are 2 principal values
                            for each_clause_check in &each.children {
                                match &each_clause_check.container {
                                    Some(clause_rec) => {
                                        match clause_rec {
                                            RecordType::ClauseValueCheck(
                                                ClauseCheck::Success) => {},

                                            _ => unreachable!()
                                        }
                                    },
                                    None => unreachable!()
                                }
                            }
                        }
                    },
                    None => unreachable!()
                }
            }

        },
        None => unreachable!()
    }

    Ok(())
}

#[test]
fn test_guard_10_compatibility_and_diff() -> Result<()> {
    let value_str = r###"
    Statement:
      - Principal: ['*', 's3:*']
    "###;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting { root: &value };

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
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause_str = r#"SOME Statement.*.Principal == '*'"#;
    let clause = GuardClause::try_from(clause_str)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::PASS);

    let value_str = r###"
    Statement:
      - Principal: aws
      - Principal: ['*', 's3:*']
    "###;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting { root: &value };
    //
    // Evaluate the SOME clause again, it must pass with ths value as well
    //
    let status = eval_guard_clause(&clause, &eval)?;
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
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
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
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&clause, &eval)?;
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
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let eval = BasicQueryTesting { root: &value };
    let clause_str = r#"Resources.*[ Type == 'AWS::ApiGateway::RestApi' ].Properties {
        EndpointConfiguration == ["PRIVATE"]
        some Policy.Statement[*] {
            Action == 'Allow'
            Condition[ keys == 'aws:IsSecure' ] !empty
        }
    }
    "#;
    let clause = GuardClause::try_from(clause_str)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);
    Ok(())
}

#[test]
fn variable_projections() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;

    let rules_file = RulesFile::try_from(r#"
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
    "#)?;
    let root_scope = root_scope(&rules_file, &path_value)?;
    let status = eval_rules_file(&rules_file, &root_scope)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn variable_projections_failures() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;

    let rules_file = RulesFile::try_from(r#"
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
    "#)?;
    let root_scope = root_scope(&rules_file, &path_value)?;
    let tracker = RecordTracker::new(&root_scope);
    let status = eval_rules_file(&rules_file, &tracker)?;
    assert_eq!(status, Status::FAIL); // for s3_bucket_policy_2.Properties.Bucket == ""

    let top = tracker.extract();
    assert_eq!(top.children.len(), 1); // one rule
    let rule = &top.children[0];
    assert_eq!(rule.children.len(), 4); // 1 one for rule condition, 3 for rule clauses
    //assert_eq!(matches!(rule_block.container, Some(RecordType::RuleBlock(Status::FAIL))), true);
    for (idx, each_rule_clause) in rule.children.iter().enumerate() {
        if idx == 0 {
            // Condition block
            assert_eq!(
                matches!(
                    each_rule_clause.container,
                    Some(RecordType::RuleCondition(Status::PASS))
                ),
                true
            );
            assert_eq!(each_rule_clause.children.len(), 1); //
            let gbc = &each_rule_clause.children[0];
            assert_eq!(
                matches!(
                    gbc.container,
                    Some(RecordType::GuardClauseBlockCheck(BlockCheck{ status: Status::PASS, ..}))
                ),
                true
            );
        }
        else if idx == 2 {
            assert_eq!(
                matches!(
                    each_rule_clause.container,
                    Some(RecordType::GuardClauseBlockCheck(BlockCheck{ status: Status::FAIL, .. }))),
                true);
            assert_eq!(each_rule_clause.children.len(), 2); //
            let failed_clause = &each_rule_clause.children[1];
            assert_eq!(
                matches!(
                    failed_clause.container,
                    Some(RecordType::ClauseValueCheck(
                        ClauseCheck::Unary(UnaryValueCheck {
                            comparison: (CmpOperator::Empty, true),
                            value: ValueCheck {
                                status: Status::FAIL,
                                ..
                            }
                        })
                    ))
                ),
                true
            );
        }
        else {
            assert_eq!(
                matches!(
                    each_rule_clause.container,
                    Some(RecordType::GuardClauseBlockCheck(BlockCheck{ status: Status::PASS, .. }))),
                true);
        }
    }

    Ok(())
}

#[test]
fn query_cross_joins() -> Result<()> {
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
        Resources:
          s3_bucket:
            Type: AWS::S3::Bucket
          s3_bucket_polocy:
            Type: AWS::S3::BucketPolicy
            Properties:
              Bucket:
                Ref: s3_bucket
        "#)?
    )?;
    let rules_files = RulesFile::try_from(r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#)?;
    let root_scope = root_scope(&rules_files, &path_value)?;
    let status = eval_rules_file(&rules_files, &root_scope)?;
    assert_eq!(status, Status::PASS);

    let rules_files = RulesFile::try_from(r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /NotBucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#)?;
    let root_scope = super::eval_context::root_scope(&rules_files, &path_value)?;
    let status = eval_rules_file(&rules_files, &root_scope)?;
    assert_eq!(status, Status::SKIP);

    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(r#"
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
        "#)?
    )?;

    //
    // NO some present for assignment, hence failure
    //
    let rules_files = RulesFile::try_from(r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#)?;
    let root_scope = super::eval_context::root_scope(&rules_files, &path_value)?;
    let status = eval_rules_file(&rules_files, &root_scope)?;
    assert_eq!(status, Status::FAIL);

    //
    // Using SOME to indicate not all BucketPolicy object will have Bucket References. In
    // our payload s3_bucket_policy_2 is skipped as it does not resolve
    //
    let rules_files = RulesFile::try_from(r#"
    rule s3_cross_query_join {
       let policies = some Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#)?;
    let root_scope = super::eval_context::root_scope(&rules_files, &path_value)?;
    let status = eval_rules_file(&rules_files, &root_scope)?;
    assert_eq!(status, Status::PASS);

    //
    // Using SOME at the block level will yield the same result
    // s3_bucket_policy_2 is skipped
    //
    let rules_files = RulesFile::try_from(r#"
    rule s3_cross_query_join {
       let policies = Resources[ Type == /BucketPolicy$/ ].Properties.Bucket.Ref
       some Resources.%policies {
         Type == 'AWS::S3::Bucket'
       }
    }
    "#)?;
    let root_scope = super::eval_context::root_scope(&rules_files, &path_value)?;
    let status = eval_rules_file(&rules_files, &root_scope)?;
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
    let root = root_scope(&rules, &resources)?;
    let tracker = RecordTracker::new(&root);
    let status = eval_rules_file(&rules, &tracker)?;
    assert_eq!(status, Status::PASS);
    let mut expectations = HashMap::with_capacity(4);
    expectations.insert("skipped".to_string(), Status::SKIP);
    expectations.insert("dependent_on_skipped".to_string(), Status::SKIP);
    expectations.insert("dependent_on_dependent".to_string(), Status::SKIP);
    expectations.insert("dependent_on_not_skipped".to_string(), Status::PASS);
    let rules_results = tracker.extract().children;
    assert_eq!(rules_results.len(), 4);
    for each in rules_results {
        match each.container {
            Some(RecordType::RuleCheck(status)) => {
                assert_eq!(expectations.get(status.name), Some(&status.status));
            },

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
    let root = root_scope(&rules, &resources)?;
    let tracker = RecordTracker::new(&root);
    let status = eval_rules_file(&rules, &tracker)?;
    assert_eq!(status, Status::PASS);
    expectations.clear();
    expectations.insert("skipped".to_string(), Status::PASS);
    expectations.insert("dependent_on_skipped".to_string(), Status::PASS);
    expectations.insert("dependent_on_dependent".to_string(), Status::PASS);
    expectations.insert("dependent_on_not_skipped".to_string(), Status::SKIP);

    let rules_results = tracker.extract().children;
    assert_eq!(rules_results.len(), 4);
    for each in rules_results {
        match each.container {
            Some(RecordType::RuleCheck(status)) => {
                assert_eq!(expectations.get(status.name), Some(&status.status));
            },

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
    let eval = BasicQueryTesting{ root: &path_value };
    let status = eval_guard_clause(&clause, &eval)?;
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
    let eval = BasicQueryTesting{ root: &path_value };
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"Statement[*].Action[*] != '*'"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    // Test old format
    let clause = GuardClause::try_from(r#"Statement.*.Action.* != '*'"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"some Statement[*].Action == '*'"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::PASS);

    let clause = GuardClause::try_from(r#"some Statement[*].Action != '*'"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_for_in_and_not_in() -> Result<()> {
    let statments = r#"
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

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(statments)?)?;
    let eval = BasicQueryTesting{ root: &value };

    let clause = GuardClause::try_from(r#"mainSteps[*].action !IN ["aws:updateSsmAgent", "aws:updateAgent"]"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"mainSteps[*].action IN ["aws:updateSsmAgent", "aws:updateAgent"]"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause = GuardClause::try_from(r#"some mainSteps[*].action IN ["aws:updateSsmAgent", "aws:updateAgent"]"#)?;
    let status = eval_guard_clause(&clause, &eval)?;
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
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting{ root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::PASS);

    let value_str = r#"
    InputParameter:
        TcpBlockedPorts:
            - 21
            - 22
            - 101
            - 100000
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting{ root: &value };
    let status = eval_rule(&rule, &eval)?;
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
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
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
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::SKIP);

    let value_str = r#"
    Resources: {}
    "#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::FAIL);

    let value_str = r#"{}"#;
    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value_str)?)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_multiple_valued_clause_reporting() -> Result<()> {
    struct ReportAssertions<'eval, 'value> {
        parent: &'eval dyn EvalContext<'value>
    };

    impl<'eval, 'value> EvalContext<'value> for ReportAssertions<'eval, 'value> {
        fn query(&self, query: &'value [QueryPart<'_>]) -> Result<Vec<QueryResult<'value>>> {
            self.parent.query(query)
        }

        fn root(&self) -> &'value PathAwareValue {
            self.parent.root()
        }

        fn rule_status(&self, rule_name: &str) -> Result<Status> {
            self.parent.rule_status(rule_name)
        }

        fn start_record(&self, context: &str) -> Result<()> { Ok(()) }

        fn end_record(&self, context: &str, record: RecordType<'value>) -> Result<()> {
            match record {
                RecordType::GuardClauseBlockCheck(BlockCheck{message, status, at_least_one_matches}) => {
                    assert_eq!(message, None);
                    assert_eq!(status, Status::FAIL);
                    assert_eq!(at_least_one_matches, false);
                },

                RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
                    status, from, to, .. })) => {
                    assert_eq!(to.is_some(), true);
                    assert_eq!(status, Status::FAIL);
                        match from {
                            QueryResult::Resolved(res) => {
                                assert_eq!(
                                    res.self_path().0.as_str() == "/Resources/second/Properties/Name" ||
                                    res.self_path().0.as_str() == "/Resources/failed/Properties/Name",
                                    true
                                );
                            },

                            _ => unreachable!()
                        }
                    },

                RecordType::ClauseValueCheck(ClauseCheck::Success) => {},

                RecordType::RuleCheck(NamedStatus{name, status}) => {
                    assert_eq!(name, "name_check");
                    assert_eq!(status, Status::FAIL);
                },

                RecordType::FileCheck(NamedStatus{status, ..}) => {
                    assert_eq!(status, Status::FAIL);
                },

                _ => unreachable!()
            }
            Ok(())
        }

        fn resolve_variable(&self, variable_name: &str) -> Result<Vec<QueryResult<'value>>> {
            self.parent.resolve_variable(variable_name)
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
    let values = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(value)?)?;
    let root = BasicQueryTesting { root: &values };
    let reporter = ReportAssertions { parent: &root };
    let status = eval_rule(&rules, &reporter)?;
    assert_eq!(status, Status::FAIL);

    let rule = r###"
    let resources = Resources.*
    rule name_check { %resources.Properties.Name == /NAME/ }
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

    let rules = RulesFile::try_from(rule)?;
    let root = root_scope(&rules, &values)?;
    let reporter = ReportAssertions{ parent: &root };
    let status = eval_rules_file(&rules, &reporter)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn test_in_comparison_operator_for_list_of_lists() -> Result<()> {
    let template = r###"
Resources:
    MasterRecord:
        Type: AWS::Route53::RecordSet
        Properties:
            HostedZoneName: !Ref 'HostedZoneName'
            Comment: DNS name for my instance.
            Name: !Join ['', [!Ref 'SubdomainMaster', ., !Ref 'HostedZoneName']]
            Type: A
            TTL: '900'
            ResourceRecords:
                - !GetAtt Master.PrivateIp
    InternalRecord:
        Type: AWS::Route53::RecordSet
        Properties:
            HostedZoneName: !Ref 'HostedZoneName'
            Comment: DNS name for my instance.
            Name: !Join ['', [!Ref 'SubdomainInternal', ., !Ref 'HostedZoneName']]
            Type: A
            TTL: '900'
            ResourceRecords:
                - !GetAtt Master.PrivateIp
    SubdomainRecord:
        Type: AWS::Route53::RecordSet
        Properties:
            HostedZoneName: !Ref 'HostedZoneName'
            Comment: DNS name for my instance.
            Name: !Join ['', [!Ref 'SubdomainDefault', ., !Ref 'HostedZoneName']]
            Type: A
            TTL: '900'
            ResourceRecords:
                - !GetAtt Infra1.PrivateIp
    WildcardRecord:
        Type: AWS::Route53::RecordSet
        Properties:
            HostedZoneName: !Ref 'HostedZoneName'
            Comment: DNS name for my instance.
            Name: !Join ['', [!Ref 'SubdomainWild', ., !Ref 'HostedZoneName']]
            Type: A
            TTL: '900'
            ResourceRecords:
                - !GetAtt Infra1.PrivateIp
    "###;

    let rules = r###"
    let aws_route53_recordset_resources = Resources.*[ Type == 'AWS::Route53::RecordSet' ]
    rule aws_route53_recordset when %aws_route53_recordset_resources !empty {
      %aws_route53_recordset_resources.Properties.Comment == "DNS name for my instance."
      let targets = [["",["SubdomainWild",".","HostedZoneName"]], ["",["SubdomainInternal",".","HostedZoneName"]], ["",["SubdomainMaster",".","HostedZoneName"]], ["",["SubdomainDefault",".","HostedZoneName"]]]
      %aws_route53_recordset_resources.Properties.Name IN %targets
      %aws_route53_recordset_resources.Properties.Type == "A"
      %aws_route53_recordset_resources.Properties.ResourceRecords IN [["Master.PrivateIp"], ["Infra1.PrivateIp"]]
      %aws_route53_recordset_resources.Properties.TTL == "900"
      %aws_route53_recordset_resources.Properties.HostedZoneName == "HostedZoneName"
    }
    "###;

    let value = PathAwareValue::try_from(serde_yaml::from_str::<serde_json::Value>(template)?)?;
    let rule_eval = RulesFile::try_from(rules)?;
    let context = root_scope(&rule_eval, &value)?;
    let status = eval_rules_file(&rule_eval, &context)?;
    assert_eq!(status, Status::PASS);

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

    let resources_str = r###"
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
    "###;

    let value = PathAwareValue::try_from(resources_str)?;
    let rules_file = RulesFile::try_from(rule_str)?;
    let eval = root_scope(&rules_file, &value)?;
    let status = eval_rules_file(&rules_file, &eval)?;
    assert_eq!(status, Status::PASS);

    let resources_str = r###"
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
    "###;
    let value = PathAwareValue::try_from(resources_str)?;
    let eval = root_scope(&rules_file, &value)?;
    let status = eval_rules_file(&rules_file, &eval)?;
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
    let eval = root_scope(&parsed, &value)?;
    let selected = eval.resolve_variable("x")?;
    println!("{:?}", selected);
    assert_eq!(selected.len(), 1);

    Ok(())
}

#[test]
fn test_support_for_atleast_one_match_clause() -> Result<()> {
    let clause_some_str  = r#"some Tags[*].Key == /PROD/"#;
    let clause_some = GuardClause::try_from(clause_some_str)?;

    let clause_str  = r#"Tags[*].Key == /PROD/"#;
    let clause = GuardClause::try_from(clause_str)?;

    let values_str  = r#"{
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
    let eval = BasicQueryTesting { root: &values };

    let status = eval_guard_clause(&clause_some, &eval)?;
    assert_eq!(status, Status::PASS);

    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"{ Tags: [] }"#;
    let values = PathAwareValue::try_from(values_str)?;
    let eval = BasicQueryTesting { root: &values };
    let status = eval_guard_clause(&clause_some, &eval)?;
    assert_eq!(status, Status::FAIL);

    let status = eval_guard_clause(&clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    let values_str = r#"{ }"#;
    let values = PathAwareValue::try_from(values_str)?;
    let eval = BasicQueryTesting { root: &values };
    let status = eval_guard_clause(&clause_some, &eval)?;
    assert_eq!(status, Status::FAIL);

    let status = eval_guard_clause(&clause, &eval)?;
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
    let resources = PathAwareValue::try_from(resources_str)?;
    let selection_query = AccessQuery::try_from(selection_str)?;
    let eval = BasicQueryTesting { root: &resources };
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
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
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
    let root = root_scope(&rule, &value)?;
    let tracker = RecordTracker::new(&root);
    let status = eval_rules_file(&rule, &tracker)?;
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
    let value = serde_yaml::from_str::<serde_json::Value>(value_str)?;
    let value = PathAwareValue::try_from(value)?;
    let root = root_scope(&rule, &value)?;
    let status = eval_rules_file(&rule, &root)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn ensure_all_list_value_access_on_empty_fails() -> Result<()> {
    let resources = r#"Tags: []"#;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?)?;
    let claused_failure_spec = GuardClause::try_from(
        r#"Tags[*].Key == /Name/"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(
        r#"some Tags[*].Key == /Name/"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(
        r#"Tags[*] { Key == /Name/ }"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(
        r#"some Tags[*] { Key == /Name/ }"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(
        r#"Tags !empty"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(
        r#"Tags empty"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::PASS);

    let claused_failure_spec = GuardClause::try_from(
        r#"Tags[*] !empty"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let claused_failure_spec = GuardClause::try_from(
        r#"Tags[*] empty"#)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&claused_failure_spec, &eval)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn ensure_all_map_values_access_on_empty_fails() -> Result<()> {
    let resources = r#"Resources: {}"#;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?)?;
    let eval = BasicQueryTesting { root: &value };

    let clause_failure_spec = GuardClause::try_from(
        r#"Resources.*.Properties exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause_failure_spec = GuardClause::try_from(
        r#"Resources.* { Properties exists }"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    let clause_failure_spec = GuardClause::try_from(
        r#"Resources exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &eval)?;
    assert_eq!(status, Status::PASS);

    //
    // Resources is empty, hence FAIL
    //
    let clause_failure_spec = GuardClause::try_from(
        r#"Resources[ Type == /Bucket/ ].Propertiers exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

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
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&clause_failure_spec, &eval)?;
    assert_eq!(status, Status::SKIP);

    //
    // No resources present
    //
    let resources = r#"{}"#;
    let value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?)?;
    let eval = BasicQueryTesting { root: &value };
    let clause_failure_spec = GuardClause::try_from(
        r#"Resources exists"#)?;
    let status = eval_guard_clause(&clause_failure_spec, &eval)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

fn find_failed_clauses<'event, 'value>(
    root: &'event EventRecord<'value>) -> Vec<&'event EventRecord<'value>>
{
    match &root.container {

        Some(RecordType::Filter(_)) |
        Some(RecordType::ClauseValueCheck(ClauseCheck::Success)) => vec![],

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
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?
    )?;
    let eval = root_scope(&rules_file, &path_value)?;
    let tracker = RecordTracker::new(&eval);
    let status = eval_rules_file(&rules_file, &tracker)?;
    assert_eq!(status, Status::FAIL);

    let top = tracker.extract();
    let failed_clauses = find_failed_clauses(&top);
    assert_eq!(failed_clauses.len(), 2);
    for each in failed_clauses {
        if let Some(RecordType::ClauseValueCheck(check)) = &each.container {
            match check {
                ClauseCheck::Comparison(ComparisonClauseCheck { status, from, to, .. }) => {
                    assert_eq!(*status, Status::FAIL);
                    assert_eq!(
                        each.context.contains("Action") ||
                            each.context.contains("Principal"),
                        true
                    );
                    assert_eq!(from.resolved().map_or(false, |res|
                        {
                            let path = res.self_path().0.as_str();
                            path == "/Resources/iam/Properties/PolicyDocument/Statement/Action" ||
                                path == "/Resources/iam/Properties/PolicyDocument/Statement/Principal/0"
                        }
                    ), true)
                },

                _ => unreachable!()
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
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?
    )?;
    let eval = root_scope(&rules_file, &path_value)?;
    let status = eval_rules_file(&rules_file, &eval)?;
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
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?
    )?;
    let eval = eval.reset_root(&path_value)?;
    let status = eval_rules_file(&rules_file, &eval)?;
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
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?
    )?;
    let eval = eval.reset_root(&path_value)?;
    //
    // Let us track failures and assert on what must be observed
    //
    let tracker = RecordTracker::new(&eval);
    let status = eval_rules_file(&rules_file, &tracker)?;
    assert_eq!(status, Status::FAIL);

    let top = tracker.extract();
    let failed_clauses = find_failed_clauses(&top);
    assert_eq!(failed_clauses.len(), 1);
    match &failed_clauses[0].container {
        Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(check))) => {
            assert_eq!(check.status, Status::FAIL);
            assert_eq!(check.from.resolved(), None);
        },
        _ => unreachable!()
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

    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(resources)?
    )?;
    let rules_file = RulesFile::try_from(rules)?;
    let eval = root_scope(&rules_file, &path_value)?;
    let status = eval_rules_file(&rules_file, &eval)?;
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
    let eval = root_scope(&rule, &value)?;
    let status = eval_rules_file(&rule, &eval)?;
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
    let eval = eval.reset_root(&value)?;
    let status = eval_rules_file(&rule, &eval)?;
    assert_eq!(Status::FAIL, status);

    Ok(())
}


#[test]
fn rule_test_type_blocks() -> Result<()> {
    let r = r###"
    rule iam_basic_checks {
  AWS::IAM::Role {
    Properties.AssumeRolePolicyDocument.Version == /(\d{4})-(\d{2})-(\d{2})/
    Properties.PermissionsBoundary == /arn:aws:iam::(\d{12}):policy/
    Properties.Tags[*].Value == /[a-zA-Z0-9]+/
    Properties.Tags[*].Key   == /[a-zA-Z0-9]+/
  }
}"###;

    let value = r###"
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
    "###;

    let root = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value)?
    )?;
    let rules_file = RulesFile::try_from(r)?;
    let root_context = root_scope(&rules_file, &root)?;
    let tracker = RecordTracker::new(&root_context);
    let status = eval_rules_file(&rules_file, &tracker)?;
    assert_eq!(Status::FAIL, status);

    let top = tracker.extract();
    let failed_clause = find_failed_clauses(&top);
    assert_eq!(failed_clause.len(), 2); // For Tag's key and value check for first resource
    for each in failed_clause {
        match &each.container {
            Some(RecordType::ClauseValueCheck(
                ClauseCheck::Comparison(
                   ComparisonClauseCheck{from, status, to, ..}))) => {
                assert_eq!(*status, Status::FAIL);
                assert_eq!(from.resolved(), None);
                assert_eq!(*to, None);
            },

            _ => unreachable!()
        }
    }

    Ok(())
}

#[test]
fn rules_file_tests_the_unituitive_all_clause_that_skips() -> Result<()> {
    let file = r###"
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
}"###;

    let value = r###"
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
    "###;

    let root = PathAwareValue::try_from(value)?;
    let rules_file = RulesFile::try_from(file)?;
    let root_context = root_scope(&rules_file, &root)?;
    let status = eval_rules_file(&rules_file, &root_context)?;
    assert_eq!(Status::PASS, status);

    Ok(())
}

#[test]
fn rules_file_tests_simpler_correct_form_using_newer_constructs() -> Result<()> {
    let file = r###"
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
}"###;

    //
    // Missing Tag properties
    //
    let value = r###"
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
    "###;

    let root = PathAwareValue::try_from(value)?;
    let rules_file = RulesFile::try_from(file)?;
    let root_context = root_scope(&rules_file, &root)?;

    let tracker = RecordTracker::new(&root_context);
    let status = eval_rules_file(&rules_file, &tracker)?;
    assert_eq!(Status::FAIL, status);

    let top = tracker.extract();
    let failed_clause = find_failed_clauses(&top);
    assert_eq!(failed_clause.len(), 1); // There is only one for Tag[*] block
    for each in failed_clause {
        match &each.container {
            Some(RecordType::ClauseValueCheck(
                     ClauseCheck::MissingBlockValue(
                         ValueCheck { status, from, .. }))) => {
                assert_eq!(*status, Status::FAIL);
                assert_eq!(from.resolved(), None);
            },

            _ => unreachable!()
        }
    }

    //
    // Empty Tag properties
    //
    let value = r###"
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
    "###;

    let root = PathAwareValue::try_from(value)?;
    let root_context = root_context.reset_root(&root)?;
    let tracker = RecordTracker::new(&root_context);
    let status = eval_rules_file(&rules_file, &tracker)?;
    assert_eq!(Status::FAIL, status);

    let top = tracker.extract();
    let failed_clause = find_failed_clauses(&top);
    assert_eq!(failed_clause.len(), 1); // There is only one for Tag[*] block
    for each in failed_clause {
        match &each.container {
            Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(ValueCheck{
                status, from, ..
            }))) => {
                assert_eq!(*status, Status::FAIL);
                assert_eq!(from.resolved(), None);
                match from.unresolved_traversed_to() {
                    Some(val) => {
                        assert_eq!(val.self_path().0.as_str(), "/Resources/iamrole/Properties/Tags");
                    },
                    None => unreachable!()
                }

            },

            _ => unreachable!()
        }
    }

    Ok(())
}

const SAMPLE: &str = r###"
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
    "###;

#[test]
fn test_iam_statement_clauses() -> Result<()> {
    let sample = r###"
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
    "###;
    let value = PathAwareValue::try_from(sample)?;
    let eval = BasicQueryTesting { root: &value };

    let clause = r#"Statement[
        Condition EXISTS ].Condition.*[
            this is_struct ][ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY"#;
    // let clause = "Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ]";
    let parsed = GuardClause::try_from(clause)?;
    let status = eval_guard_clause(&parsed, &eval)?;
    assert_eq!(Status::PASS, status);

    let clause = r#"Statement[ Condition EXISTS
                                     Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] NOT EMPTY
    "#;
    let parsed = GuardClause::try_from(clause)?;
    let status = eval_guard_clause(&parsed, &eval)?;
    assert_eq!(Status::PASS, status);

    let parsed = GuardClause::try_from(
        r#"SOME Statement[*].Condition.*[ THIS IS_STRUCT ][ KEYS ==  /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] NOT EMPTY"#)?;
    let status = eval_guard_clause(&parsed, &eval)?;
    assert_eq!(Status::PASS, status);

    let sample = r###"
    {
        "Statement": [
            {
                "Sid": "PrincipalPutObjectIfIpAddress",
                "Effect": "Allow",
                "Action": "s3:PutObject"
            }
        ]
    }"###;
    let value = PathAwareValue::try_from(sample)?;
    let eval = BasicQueryTesting { root: &value };
    let tracker = RecordTracker::new(&eval);
    let status = eval_guard_clause(&parsed, &tracker)?;
    assert_eq!(status, Status::FAIL);

    let sample = r###"
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
    }"###;
    let value = PathAwareValue::try_from(sample)?;
    let eval = BasicQueryTesting { root: &value };
    let tracker = RecordTracker::new(&eval);
    let status = eval_guard_clause(&parsed, &tracker)?;
    assert_eq!(status, Status::FAIL);

    let sample = r###"
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
    }"###;
    let value = PathAwareValue::try_from(sample)?;
    let eval = BasicQueryTesting { root: &value };
    let tracker = RecordTracker::new(&eval);
    let status = eval_guard_clause(&parsed, &tracker)?;
    assert_eq!(status, Status::PASS);


    let value = PathAwareValue::try_from(SAMPLE)?;
    let parsed = GuardClause::try_from(clause)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_guard_clause(&parsed, &eval)?;
    assert_eq!(Status::FAIL, status);

    Ok(())
}

#[test]
fn test_api_gateway() -> Result<()> {
    let rule = r###"
rule check_rest_api_private {
  AWS::ApiGateway::RestApi {
    # Endpoint configuration must only be private
    Properties.EndpointConfiguration == ["PRIVATE"]

    # At least one statement in the resource policy must contain a condition with the key of "aws:sourceVpc" or "aws:sourceVpce"
    Properties.Policy.Statement[ Condition.*[ KEYS == /aws:[sS]ource(Vpc|VPC|Vpce|VPCE)/ ] !EMPTY ] !EMPTY
  }
}
    "###;

    let rule = Rule::try_from(rule)?;

    let resources = r###"
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
    }"###;

    let value = PathAwareValue::try_from(resources)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::PASS);

    Ok(())
}

#[test]
fn test_api_gateway_cleaner_model() -> Result<()> {
    let rule = r###"
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
    "###;

    let rule = Rule::try_from(rule)?;

    let resources = r###"
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
    }"###;

    let value = PathAwareValue::try_from(resources)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::PASS);

    let resources = r###"
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
    }"###;

    let value = PathAwareValue::try_from(resources)?;
    let eval = BasicQueryTesting { root: &value };
    let status = eval_rule(&rule, &eval)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}

#[test]
fn testing_iam_role_prov_serve() -> Result<()> {
    let resources = r###"
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
    "###;

    let rules = r###"
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
    "###;

    let rules_file = RulesFile::try_from(rules)?;
    let value = PathAwareValue::try_from(resources)?;
    let eval = root_scope(&rules_file, &value)?;
    let status = eval_rules_file(&rules_file, &eval)?;

    println!("{}", status);
    Ok(())
}

#[test]
fn testing_sg_rules_pro_serve() -> Result<()> {
    let sgs = r###"
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

    "###;

    let rules = r###"
let sgs = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule deny_egress when %sgs NOT EMPTY {
    # Ensure that none of the security group contain a rule
    # that has Cidr Ip set to any
    %sgs.Properties.SecurityGroupEgress[ CidrIp   == "0.0.0.0/0" or
                                         CidrIpv6 == "::/0" ] EMPTY
}

    "###;

    let rules_file = RulesFile::try_from(rules)?;

    let values = PathAwareValue::try_from(sgs)?;
    let samples = match values {
        PathAwareValue::List((_p, v)) => v,
        _ => unreachable!()
    };

    for (index, each) in samples.iter().enumerate() {
        let root_context = root_scope(&rules_file, &each)?;
        let status = eval_rules_file(&rules_file, &root_context)?;
        println!("{}", format!("Status {} = {}", index, status).underline());
    }

    Ok(())
}

#[test]
fn test_s3_bucket_pro_serv() -> Result<()> {
    let values = r###"
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

    "###;

    let parsed_values = match PathAwareValue::try_from(values)? {
        PathAwareValue::List((_, v)) => v,
        _ => unreachable!()
    };

    let rule = r###"
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

    "###;

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
        let root_scope = root_scope(&s3_rule, each)?;
        let status = eval_rules_file(&s3_rule, &root_scope)?;
        assert_eq!(status, expectations[idx]);
    }
    Ok(())
}

#[test]
fn match_lhs_with_rhs_single_element_pass() -> Result<()> {
    let clause = r#"algorithms == ["KMS"]"#;
    let value = r#"algorithms: KMS"#;
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value)?
    )?;
    let guard_clause = GuardClause::try_from(clause)?;
    let eval = BasicQueryTesting { root: &path_value };
    let status = eval_guard_clause(&guard_clause, &eval)?;
    assert_eq!(status, Status::PASS);

    let clause = r#"algorithms == ["KMS", "SSE"]"#;
    let value = r#"algorithms: KMS"#;
    let path_value = PathAwareValue::try_from(
        serde_yaml::from_str::<serde_json::Value>(value)?
    )?;
    let guard_clause = GuardClause::try_from(clause)?;
    let eval = BasicQueryTesting { root: &path_value };
    let status = eval_guard_clause(&guard_clause, &eval)?;
    assert_eq!(status, Status::FAIL);

    Ok(())
}