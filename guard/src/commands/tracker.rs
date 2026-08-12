use crate::rules::values::CmpOperator;
use crate::rules::{path_value::PathAwareValue, EvaluationType, Status};
use serde::Serialize;

/// The per-clause record the validate reporters read.
///
/// Nothing constructs one any more -- `StackTracker`, the `EvaluationContext` implementation
/// that built these, was the old evaluator's recorder and went with it. The type stays
/// because the reporters still destructure it: `common.rs`, `cfn_reporter.rs` and
/// `generic_summary.rs` match on `eval_type` and walk `children`, and `generic_summary.rs` is
/// live (constructed at `helper.rs` and `validate.rs`). The new evaluator records through
/// `RecordType`/`EventRecord` in `eval_context.rs` instead, so those reporter branches are
/// unreachable rather than wrong.
#[derive(Serialize, Debug)]
pub(crate) struct StatusContext {
    pub(crate) eval_type: EvaluationType,
    pub(crate) context: String,
    pub(crate) msg: Option<String>,
    pub(crate) from: Option<PathAwareValue>,
    pub(crate) to: Option<PathAwareValue>,
    pub(crate) status: Option<Status>,
    pub(crate) comparator: Option<(CmpOperator, bool)>,
    pub(crate) children: Vec<StatusContext>,
}
