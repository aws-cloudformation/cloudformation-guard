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

The module paths and data types used by `cloudformation-validate` remain available. Other implementation details exposed by 1.0.0 are not part of the supported API.

## Compatibility

The manually published 1.0.0 is a bootstrap release. Subsequent versions are assigned by the coordinated `cfn-guard` release workflow. The next release keeps the `cloudformation-validate` integration source-compatible and includes stricter policy-enforcement behavior from `cfn-guard` 3.2.1. Other 1.0 consumers may need to migrate to the crate-root entry points.

The `junit` feature enables JUnit report support. It is disabled by default.
