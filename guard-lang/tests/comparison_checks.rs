use cloudformation_guard_lang::path_value::Location;
use cloudformation_guard_lang::values::CmpOperator;
use cloudformation_guard_lang::{
    ComparisonClauseCheck, InComparisonCheck, Path, PathAwareValue, QueryResult, Status,
};
use std::rc::Rc;

fn value(path: &str, line: usize, col: usize, value: &str) -> QueryResult {
    QueryResult::Resolved(Rc::new(PathAwareValue::String((
        Path(path.to_string(), Location { line, col }),
        value.to_string(),
    ))))
}

#[test]
fn comparison_checks_are_built_and_destructured_from_their_public_fields() {
    let comparison = ComparisonClauseCheck {
        comparison: (CmpOperator::Eq, false),
        from: value("/Status", 5, 16, "Suspended"),
        to: Some(value("", 0, 0, "Enabled")),
        message: None,
        custom_message: Some("custom".to_string()),
        status: Status::FAIL,
    };
    let ComparisonClauseCheck {
        comparison: compared_with,
        from,
        to,
        message,
        custom_message,
        status,
    } = comparison.clone();
    assert_eq!((CmpOperator::Eq, false), compared_with);
    assert_eq!(value("/Status", 5, 16, "Suspended"), from);
    assert_eq!(Some(value("", 0, 0, "Enabled")), to);
    assert_eq!(None, message);
    assert_eq!(Some("custom".to_string()), custom_message);
    assert_eq!(Status::FAIL, status);

    let membership = InComparisonCheck {
        comparison: (CmpOperator::In, true),
        from: value("", 0, 0, "Disabled"),
        to: vec![value("/Modes/0", 6, 14, "Disabled")],
        message: Some("message".to_string()),
        custom_message: None,
        status: Status::FAIL,
    };
    let InComparisonCheck {
        comparison: compared_with,
        from,
        to,
        message,
        custom_message,
        status,
    } = membership.clone();
    assert_eq!((CmpOperator::In, true), compared_with);
    assert_eq!(value("", 0, 0, "Disabled"), from);
    assert_eq!(vec![value("/Modes/0", 6, 14, "Disabled")], to);
    assert_eq!(Some("message".to_string()), message);
    assert_eq!(None, custom_message);
    assert_eq!(Status::FAIL, status);

    let serialized_fields = |check: serde_json::Value| {
        check
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>()
    };
    let fields = [
        "comparison",
        "from",
        "to",
        "message",
        "custom_message",
        "status",
    ];
    assert_eq!(
        fields.to_vec(),
        serialized_fields(serde_json::to_value(&comparison).unwrap())
    );
    assert_eq!(
        fields.to_vec(),
        serialized_fields(serde_json::to_value(&membership).unwrap())
    );
}
