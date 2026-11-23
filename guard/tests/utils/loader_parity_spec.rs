// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

// The one reader of a loader-parity spec's verdict table.
//
// A loader-parity spec under `resources/test-command/loader-parity/<shape>/tests.yaml` is the single
// verdict table three routes are held to: the `test` command runs the spec itself, and `validate` and
// the public `run_checks` are each checked against it in `tests/validate.rs`. The coverage check in
// `tests/test_command.rs` reads the same cases. Both test crates reach this file through
// `tests/utils.rs`, which declares it as a module with a `#[path]` attribute, so the two share one
// walk and nothing in the library crate reads it. Plain comments rather than `//!` doc comments,
// which the module declaration does not need and an `include!` could not carry.
//
// Read by text and not through `serde_yaml`, because that reader refuses the spec that holds an
// integer key wider than `u64` ("invalid type: integer as u128"), which is one of the documents under
// test. A case starts at a `- name:` line; its table is the `name: VERDICT` lines indented six spaces
// after the `    rules:` line that follows its `  expectations:` line. The walk skips to
// `  expectations:` first: a document under `input:` may carry its own `rules:` key at the same
// indentation, and the table is the expectations' `rules:`, not the document's.

/// One case of a loader-parity spec: its text, from its `- name:` line to the next, and its table.
pub struct LoaderParityCase {
    pub text: String,
    pub expectations: std::collections::BTreeMap<String, String>,
}

/// Every case of a loader-parity spec, in file order.
pub fn loader_parity_spec_cases(spec: &str) -> Vec<LoaderParityCase> {
    let mut starts: Vec<usize> = spec
        .match_indices("\n- name:")
        .map(|(at, _)| at + 1)
        .chain(spec.starts_with("- name:").then_some(0))
        .collect();
    starts.sort_unstable();
    starts.push(spec.len());
    starts
        .windows(2)
        .map(|window| {
            let text = &spec[window[0]..window[1]];
            let expectations = text
                .lines()
                .skip_while(|line| line.trim_end() != "  expectations:")
                .skip_while(|line| line.trim_end() != "    rules:")
                .skip(1)
                .map_while(|line| {
                    line.strip_prefix("      ")
                        .and_then(|entry| entry.split_once(':'))
                        .map(|(name, verdict)| {
                            (name.trim().to_string(), verdict.trim().to_string())
                        })
                })
                .collect();
            LoaderParityCase {
                text: text.to_string(),
                expectations,
            }
        })
        .collect()
}
