# CloudFormation Guard language library

`cloudformation-guard-lang` parses and evaluates AWS CloudFormation Guard rules without invoking the `cfn-guard` command-line application.

## Supported entry points

New consumers should import the supported API from the crate root:

- `rules_file` and `Span` parse Guard source.
- `root_scope` and `eval_rules_file` evaluate a parsed rules file.
- `simplified_json_from_root` converts an evaluation record into `FileReport`.
- `Path` and `PathAwareValue` represent the input document.
- `Status`, the Guard AST types, and the report types expose evaluation results.

```rust,no_run
use cloudformation_guard_lang::{
    eval_rules_file, root_scope, rules_file, Path, PathAwareValue, Span, Status,
};
use std::convert::TryFrom;
use std::rc::Rc;

let source = "rule resources_exist { Resources EXISTS }";
let rules = rules_file(Span::new_extra(source, "example.guard"))
    .unwrap()
    .unwrap();
let template = serde_json::json!({ "Resources": {} });
let root = PathAwareValue::try_from((&template, Path::root())).unwrap();
let mut scope = root_scope(&rules, Rc::new(root));

let status = eval_rules_file(&rules, &mut scope, Some("template.json")).unwrap();
assert_eq!(status, Status::PASS);
```

The existing module paths remain available throughout the 1.x series for compatibility with 1.0.0. The crate-root exports define the preferred surface for new integrations and prepare consumers for a narrower next major version.

## Compatibility

Version 1.1 keeps the source API published in 1.0.0 and adds stricter policy-enforcement behavior from `cfn-guard` 3.2.1. Rules that previously passed or skipped when a comparison could not be evaluated may now fail closed. Consumers pinned to `=1.0.0` must opt in to `1.1.0` to receive these fixes.

The `junit` feature enables JUnit report support. It is disabled by default.
