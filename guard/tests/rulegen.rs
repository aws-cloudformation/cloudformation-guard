// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0
pub(crate) mod utils;

#[cfg(test)]
mod rulegen_tests {
    use crate::assert_output_from_file_eq;
    use cfn_guard::commands::{DATA, OUTPUT, RULES, TEMPLATE};
    use cfn_guard::utils::reader::Reader;
    use cfn_guard::utils::writer::{WriteBuffer::Vec as WBVec, Writer};
    use pretty_assertions::assert_eq;
    use std::path::{Path, PathBuf};

    use crate::utils::{get_full_path_for_resource_file, Command, CommandTestRunner, StatusCode};

    #[derive(Default)]
    struct RulegenTestRunner<'args> {
        template: Option<&'args str>,
        output: Option<&'args str>,
    }

    impl<'args> RulegenTestRunner<'args> {
        fn template(&'args mut self, arg: Option<&'args str>) -> &'args mut RulegenTestRunner {
            self.template = arg;
            self
        }

        #[allow(dead_code)]
        fn output(&'args mut self, arg: Option<&'args str>) -> &'args mut RulegenTestRunner {
            self.output = arg;
            self
        }
    }

    impl<'args> CommandTestRunner for RulegenTestRunner<'args> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![Command::Rulegen.to_string()];

            if self.template.is_some() {
                args.push(format!("-{}", TEMPLATE.1));
                args.push(get_full_path_for_resource_file(self.template.unwrap()));
            }

            if self.output.is_some() {
                args.push(format!("-{}", OUTPUT.1));
                args.push(get_full_path_for_resource_file(self.output.unwrap()))
            }

            args
        }
    }

    #[rstest::rstest]
    #[case(
        Some("resources/rulegen/data-dir/s3-public-read-prohibited-template-compliant.json"),
        "resources/rulegen/output-dir/test_rulegen_from_template.out",
        StatusCode::SUCCESS
    )]
    #[case(
        Some("resources/rulegen/data-dir/s3-public-read-prohibited-template-compliant.yaml"),
        "resources/rulegen/output-dir/test_rulegen_from_template.out",
        StatusCode::SUCCESS
    )]
    fn test_rulegen_from_template(
        #[case] template_arg: Option<&str>,
        #[case] expected_output_file_path: &str,
        #[case] expected_status_code: i32,
    ) {
        let mut reader = Reader::default();
        let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
        let status_code = RulegenTestRunner::default()
            .template(template_arg)
            .run(&mut writer, &mut reader);

        assert_eq!(expected_status_code, status_code);
        assert_output_from_file_eq!(expected_output_file_path, writer)
    }

    #[derive(Default)]
    struct ValidateTestRunner<'args> {
        rules: Option<&'args str>,
        data: Option<&'args str>,
    }

    impl CommandTestRunner for ValidateTestRunner<'_> {
        fn build_args(&self) -> Vec<String> {
            let mut args = vec![Command::Validate.to_string()];

            if let Some(rules) = self.rules {
                args.push(format!("-{}", RULES.1));
                args.push(rules.to_string());
            }

            if let Some(data) = self.data {
                args.push(format!("-{}", DATA.1));
                args.push(data.to_string());
            }

            args
        }
    }

    /// Only the shape this walk needs: a `Resources` mapping, its logical ids, and each resource body
    /// left unread.
    ///
    /// Everything else at the root is ignored rather than typed, which is the point -- serde skips an
    /// unknown field through `IgnoredAny` and never asks what shape it has, so an
    /// `AWSTemplateFormatVersion` string or a `Description` does not decide whether the file is a
    /// candidate.
    #[derive(serde::Deserialize)]
    struct Candidate {
        #[serde(rename = "Resources")]
        resources: std::collections::HashMap<String, serde_yaml::Value>,
    }

    /// Does `path` hold a CloudFormation template -- a `Resources` mapping with at least one resource
    /// in it?
    ///
    /// This is only asked to decide whether a file is worth walking; `rulegen` reads the values
    /// itself. It used to be `HashMap<String, serde_json::Value>`, matching what `rulegen` parsed
    /// with, and the reason given was that anything this accepts `rulegen` can parse too, "which
    /// keeps the walk below away from the `process::exit(1)` in that function: an in-process test
    /// cannot survive it".
    ///
    /// Both halves of that are now obsolete, and in opposite directions. `rulegen` reads through the
    /// same loader `validate` does, so `serde_json::Value` is not what it parses with; and it returns
    /// an error instead of exiting, so the walk cannot be killed by a template it cannot read. What
    /// is left is that the old filter was the *narrower* reader, and narrow in the one place that
    /// matters: `serde_yaml` will not deserialise a tagged node into `serde_json::Value` at all, so a
    /// template using a short-form intrinsic -- `!Ref`, `!GetAtt`, `!Sub`, which is most
    /// CloudFormation YAML -- could never be a candidate. `serde_yaml::Value` has a `Tagged` variant
    /// and keeps them. No template under `resources` uses one today, so this widening adds nothing to
    /// the count right now; it stops the walk from silently skipping the first one that does.
    ///
    /// The logical ids go through a `HashMap` and not a `serde_yaml::Value`, because a `Value` refuses
    /// a duplicate mapping key -- `Resources: duplicate entry with key "A"` -- and
    /// `duplicate-logical-id-template.yaml` declares one twice deliberately. A `HashMap` keeps the last
    /// one, which is what the loader does, so that template stays a candidate. Reading it as a `Value`
    /// dropped it, which is the whole difference between 34 candidates and 35.
    ///
    /// No requirement that a resource carry a usable `Type`. A resource with `Properties` and no
    /// `Type` used to panic, so requiring one would drop the templates most worth walking --
    /// `resources/validate/mixed-extension-dir` holds two of them.
    fn is_cloudformation_template(path: &Path) -> bool {
        let Ok(contents) = std::fs::read_to_string(path) else {
            return false;
        };

        let Ok(candidate) = serde_yaml::from_str::<Candidate>(&contents) else {
            return false;
        };

        !candidate.resources.is_empty()
            && candidate
                .resources
                .values()
                .any(serde_yaml::Value::is_mapping)
    }

    fn templates_under_resources() -> Vec<PathBuf> {
        let mut root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        root.push("resources");

        walkdir::WalkDir::new(root)
            .into_iter()
            .filter_map(std::result::Result::ok)
            .map(walkdir::DirEntry::into_path)
            .filter(|path| {
                path.extension().is_some_and(|extension| {
                    matches!(
                        extension.to_str(),
                        Some("yaml" | "yml" | "json" | "template")
                    )
                }) && is_cloudformation_template(path)
            })
            .collect()
    }

    /// Generate rules from every template under `resources`, then validate the generated rules
    /// against the template they came from.
    ///
    /// A generated rule that fails its own source template is a defect, and this one property catches
    /// the whole class at once. It has now caught two generations of the class. When it was written, 3
    /// templates here generated rules that failed their own template and 6 generated nothing while
    /// exiting 0, which `validate` then reported as compliant against zero rules. It then caught the
    /// same 3 again from the other direction: `rulegen` rendered a null as `""`, calibrated against a
    /// loader that resolved an empty node to the empty string, and a sibling change made an empty node
    /// resolve to null. Both times the emitter and the reader disagreed about one value; `rulegen` now
    /// reads the template through the loader, so there is one reading rather than two.
    ///
    /// The only two outcomes allowed: rules that pass their own template, or a non-zero status saying
    /// why there are none. Exiting 0 having written nothing is what this forbids.
    ///
    /// Currently 35 templates match, 28 round-trip and 7 are refused at `PARSING_ERROR`: four carry no
    /// properties at all, two carry properties only on a resource with no `Type`, and
    /// `duplicate-logical-id-template.yaml` holds one boolean property observed both ways, which is
    /// `IN [false, true]` and a clause no boolean value can fail.
    #[test]
    fn test_rulegen_output_validates_against_its_own_template() {
        let templates = templates_under_resources();

        // A floor, so the test cannot pass by walking an empty directory. The bound is loose because
        // adding templates should not break it.
        assert!(
            templates.len() >= 30,
            "expected the resources tree to hold templates to round-trip, found {}",
            templates.len()
        );

        let mut round_tripped = 0;
        let mut refused = vec![];

        for template in &templates {
            let template_path = template.display().to_string();

            let mut writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let status_code = RulegenTestRunner::default()
                .template(Some(&template_path))
                .run(&mut writer, &mut Reader::default());

            if status_code != StatusCode::SUCCESS {
                assert_eq!(
                    StatusCode::PARSING_ERROR, status_code,
                    "rulegen on {template_path} exited {status_code}, which is neither success nor \
                     the documented error code"
                );
                refused.push(template_path);
                continue;
            }

            let generated = writer.into_string().expect("Failed to read writer.");
            assert!(
                !generated.trim().is_empty(),
                "rulegen reported success on {} but wrote no rules",
                template_path
            );

            let mut generated_path = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
            generated_path.push(format!(
                "rulegen-roundtrip-{}.guard",
                template
                    .strip_prefix(env!("CARGO_MANIFEST_DIR"))
                    .unwrap_or(template)
                    .display()
                    .to_string()
                    .replace(['/', '\\', '.'], "_")
            ));
            std::fs::write(&generated_path, &generated).expect("Failed to write generated rules.");

            let mut validate_writer = Writer::new(WBVec(vec![])).expect("Failed to create writer.");
            let validate_status = ValidateTestRunner {
                rules: Some(&generated_path.display().to_string()),
                data: Some(&template_path),
            }
            .run(&mut validate_writer, &mut Reader::default());

            assert_eq!(
                StatusCode::SUCCESS,
                validate_status,
                "rules generated from {template_path} do not pass it:\n{generated}\n{}",
                validate_writer.stripped().unwrap_or_default()
            );

            round_tripped += 1;
        }

        assert!(
            round_tripped >= 25,
            "only {round_tripped} of {} templates generated rules at all; refused: {refused:#?}",
            templates.len()
        );
    }
}
