// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
#[cfg(test)]
mod functional_tests {
    use pretty_assertions::assert_eq;
    #[test]
    fn test_run_check() {
        let data = String::from(
            r#"
                {
                    "Resources": {
                        "VPC" : {
                            "Type" : "AWS::ApiGateway::Method",
                            "Properties" : {
                                "AuthorizationType" : "10.0.0.0/24"
                            }
                        }
                    }
                }
            "#,
        );
        let rule = "AWS::ApiGateway::Method { Properties.AuthorizationType == \"NONE\"}";
        let expected = r#"{
                  "context": "File(rules=1)",
                  "container": {
                    "FileCheck": {
                      "name": "functional_test.json",
                      "status": "FAIL",
                      "message": null
                    }
                  },
                  "children": [
                    {
                      "context": "functional_test.rule/default",
                      "container": {
                        "RuleCheck": {
                          "name": "functional_test.rule/default",
                          "status": "FAIL",
                          "message": null
                        }
                      },
                      "children": [
                        {
                          "context": "TypeBlock#AWS::ApiGateway::Method",
                          "container": {
                            "TypeCheck": {
                              "type_name": "AWS::ApiGateway::Method",
                              "block": {
                                "at_least_one_matches": false,
                                "status": "FAIL",
                                "message": null
                              }
                            }
                          },
                          "children": [
                            {
                              "context": "Filter/Map#1",
                              "container": {
                                "Filter": "PASS"
                              },
                              "children": [
                                {
                                  "context": "GuardAccessClause#block Type EQUALS  \"AWS::ApiGateway::Method\"",
                                  "container": {
                                    "GuardClauseBlockCheck": {
                                      "at_least_one_matches": false,
                                      "status": "PASS",
                                      "message": null
                                    }
                                  },
                                  "children": [
                                    {
                                      "context": " Type EQUALS  \"AWS::ApiGateway::Method\"",
                                      "container": {
                                        "ClauseValueCheck": "Success"
                                      },
                                      "children": []
                                    }
                                  ]
                                }
                              ]
                            },
                            {
                              "context": "TypeBlock#AWS::ApiGateway::Method/0",
                              "container": {
                                "TypeBlock": "FAIL"
                              },
                              "children": [
                                {
                                  "context": "GuardAccessClause#block Properties.AuthorizationType EQUALS  \"NONE\"",
                                  "container": {
                                    "GuardClauseBlockCheck": {
                                      "at_least_one_matches": false,
                                      "status": "FAIL",
                                      "message": null
                                    }
                                  },
                                  "children": [
                                    {
                                      "context": " Properties.AuthorizationType EQUALS  \"NONE\"",
                                      "container": {
                                        "ClauseValueCheck": {
                                          "Comparison": {
                                            "comparison": [
                                              "Eq",
                                              false
                                            ],
                                            "from": {
                                              "Resolved": {
                                                "path": "/Resources/VPC/Properties/AuthorizationType",
                                                "value": "10.0.0.0/24"
                                              }
                                            },
                                            "to": {
                                              "Resolved": {
                                                "path": "",
                                                "value": "NONE"
                                              }
                                            },
                                            "message": null,
                                            "custom_message": null,
                                            "status": "FAIL"
                                          }
                                        }
                                      },
                                      "children": []
                                    }
                                  ]
                                }
                              ]
                            }
                          ]
                        }
                      ]
                    }
                  ]
                }"#;
        let verbose = true;
        use cfn_guard::*;
        let serialized = run_checks(
            ValidateInput {
                content: &data,
                file_name: "functional_test.json",
            },
            ValidateInput {
                content: rule,
                file_name: "functional_test.rule",
            },
            verbose,
        )
        .unwrap();
        let result = serde_json::from_str::<serde_json::Value>(&serialized)
            .ok()
            .unwrap();
        let expected = serde_json::from_str::<serde_json::Value>(expected)
            .ok()
            .unwrap();
        assert_eq!(expected, result);
    }

    /// The non-verbose `run_checks` output carries the reason a comparison had no answer.
    ///
    /// This is the surface `guard-ffi/src/lib.rs` and `guard-lambda/src/main.rs` both call, and both
    /// default `verbose` to false. Neither has a stderr channel, so the string this returns is the
    /// operator's only record of what happened.
    ///
    /// `test_run_check` above also calls `run_checks`, but with `verbose = true`, which returns the
    /// event-record tree early and never reaches `GenericSummary::report_eval`. So the non-verbose
    /// formatter had no coverage at all, which is why a missing explanation in it went unnoticed:
    /// nothing here would have failed.
    ///
    /// Four comparators over one eighteen-character map key, which is one byte past where
    /// `(?!x)((a+)+)b` exhausts `fancy-regex`'s backtracking budget. The pattern compiles -- the engine
    /// backtracks and accepts the lookahead -- and `is_match` is what gives up. All four are FAIL and
    /// all four return the same status either way, so the assertion is on the text.
    #[test]
    fn non_verbose_run_checks_reports_an_undecided_map_key_comparison() {
        use cfn_guard::*;

        const REASON: &str = "could not be evaluated";
        let data = r#"{ "Cfg": { "aaaaaaaaaaaaaaaaaa": 1, "other": 2 } }"#;

        for (operator, rhs) in [
            ("==", "/(?!x)((a+)+)b/"),
            ("!=", "/(?!x)((a+)+)b/"),
            ("in", "[/(?!x)((a+)+)b/]"),
            ("not in", "[/(?!x)((a+)+)b/]"),
        ] {
            let rule = format!("rule r {{ Cfg[ keys {operator} {rhs} ] !empty }}");
            let serialized = run_checks(
                ValidateInput {
                    content: data,
                    file_name: "functional_test.json",
                },
                ValidateInput {
                    content: &rule,
                    file_name: "functional_test.rule",
                },
                false,
            )
            .unwrap();

            assert!(
                serialized.contains(REASON),
                "`keys {}` must say the comparison had no answer on the non-verbose surface that the \
                 FFI and Lambda entry points use, where the report is the only record; got:\n{}",
                operator,
                serialized
            );
        }
    }

    /// A JSON integer above `i64::MAX` does not answer a numeric guard from a flipped sign.
    ///
    /// `run_checks` tries `serde_json::from_str` first and only falls back to `serde_yaml` when that
    /// fails (`commands/helper.rs:51`). `18446744073709551615` is valid JSON, so it takes the JSON
    /// branch and reaches `TryFrom<&serde_json::Value> for Value`, which is a separate arm from the
    /// `serde_yaml` one. Fixing only the YAML arm left this entry point reading `u64::MAX` as `-1`
    /// through `as i64` -- so `Size < 0` reported PASS on a document whose `Size` is the largest
    /// unsigned 64-bit integer, at exit 0 with nothing on either channel.
    ///
    /// This is the surface `cfn_guard_run_checks` in `guard-ffi/src/lib.rs` and the Lambda handler in
    /// `guard-lambda/src/main.rs` call, so the sign flip was reachable by every caller that is not the
    /// CLI. Neither has a stderr channel, which is why the assertion is on the returned report.
    ///
    /// # What each assertion below can and cannot detect
    ///
    /// `Size < 0` was asserted here before, and it did detect the sign flip: measured against the
    /// released binary it reports PASS, and it reports FAIL once the digits are kept. What it cannot do
    /// is say *which* representation replaced the negative number -- a float, a decimal string and a
    /// clamped integer all report FAIL for it -- so it pins that the value is no longer negative and
    /// nothing about what it now is.
    ///
    /// `Size > 100` discriminates nothing at all. The flipped `-1` fails it and a refusal fails it, for
    /// opposite reasons and with the same verdict; measured, both the released binary and this one
    /// report FAIL.
    ///
    /// The identity comparison is the one that separates the representations, and that is the whole of
    /// what keeping the digits buys: measured, the released binary reports FAIL for it and this one
    /// reports PASS.
    fn wide_integer_report(rule: &str) -> String {
        use cfn_guard::*;

        run_checks(
            ValidateInput {
                content: r#"{ "Size": 18446744073709551615, "Public": true }"#,
                file_name: "functional_test.json",
            },
            ValidateInput {
                content: rule,
                file_name: "functional_test.rule",
            },
            false,
        )
        .unwrap()
    }

    /// The digits survive, exactly, and that is what this representation is for.
    ///
    /// The discriminating assertion. `as u64 as i64` gave `Int(-1)`, which compares against the string
    /// of digits as a kind mismatch and reports FAIL; keeping the digits makes the two equal and
    /// reports PASS. So this is the one shape whose verdict differs between the sign flip and the text,
    /// and it is what the earlier `< 0` assertion should have been.
    #[test]
    fn a_json_integer_above_i64_max_keeps_its_digits_exactly() {
        let serialized = wide_integer_report(r#"rule r { Size == "18446744073709551615" }"#);

        assert!(
            serialized.contains("PASS") && !serialized.contains("FAIL"),
            "the exact digits must survive the JSON conversion -- a FAIL here means the value was \
             turned into some other number on the way in, which is what `as i64` did; got:\n{}",
            serialized
        );
    }

    /// An ordering comparison against a number has no answer, and the guarded body is not evaluated.
    ///
    /// This records a cost, not a behavior worth having. `18446744073709551615 > 100` is true, so the
    /// correct verdict for the bare clause is PASS and the correct outcome for the gate is that the
    /// block runs. Neither happens: the value is a string, `compare_values` has no arm for a string
    /// against an integer, and the clause has no answer -- which fails closed as an assertion and, as a
    /// condition, leaves the rule not applicable so the run exits 0 with the block unevaluated.
    ///
    /// It is asserted so that the cost is visible and cannot change unnoticed. The alternative
    /// representation, resolving the value to a float, answers both of these correctly and in exchange
    /// reports two distinct integers as equal -- measured, `9223372036854775809` and
    /// `9223372036854775810` both become `9.223372036854776e18`, so a clause asserting they differ is
    /// reported non-compliant. Exact identity was chosen over an answerable ordering because a wrong
    /// report of a violation costs more than a rule that declines to answer. Neither option is right;
    /// the value space cannot hold this integer, and that is the part this change does not fix.
    #[test]
    fn an_ordering_comparison_on_a_wide_integer_has_no_answer() {
        let asserted = wide_integer_report("rule r { Size > 100 }");
        assert!(
            asserted.contains("FAIL"),
            "expected the ordering clause to fail closed; got:\n{}",
            asserted
        );

        let gated = wide_integer_report("rule r when Size > 100 { Public == false }");
        assert!(
            !gated.contains("FAIL"),
            "the gate is expected not to apply, so the body must not be reported as failing. A FAIL \
             here would mean the ordering became answerable, which is a fix rather than a break -- \
             delete this assertion and move the case to the discriminating test above; got:\n{}",
            gated
        );
        assert!(
            gated.contains("SKIP") || gated.contains("not_applicable"),
            "the gate must be recorded as not applying rather than silently absent from the report, \
             so an operator reading it can see the rule did not run; got:\n{}",
            gated
        );
    }
}
