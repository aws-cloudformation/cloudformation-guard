use crate::rules::{
    EvaluationContext, Result, Status, EvaluationType, path_value::PathAwareValue
};
use crate::rules::values::CmpOperator;

pub(super) struct DummyEval{}
impl EvaluationContext for DummyEval {
    fn resolve_variable(&self, _variable: &str) -> Result<Vec<&PathAwareValue>> {
        unimplemented!()
    }

    fn rule_status(&self, _rule_name: &str) -> Result<Status> {
        unimplemented!()
    }

    fn end_evaluation(&self, _eval_type: EvaluationType, _context: &str, _msg: String, _from: Option<PathAwareValue>, _to: Option<PathAwareValue>, _status: Option<Status>, _cmp: Option<(CmpOperator, bool)>) {
    }

    fn start_evaluation(&self, _eval_type: EvaluationType, _context: &str) {
    }
}

