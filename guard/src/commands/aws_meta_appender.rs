use crate::rules::{EvaluationContext, Status, EvaluationType, Result};
use crate::rules::path_value::{PathAwareValue, QueryResolver};
use crate::rules::exprs::AccessQuery;
use std::convert::TryFrom;
use crate::rules::values::CmpOperator;

pub(super) struct MetadataAppender<'d> {
    pub(super) delegate: &'d dyn EvaluationContext,
    pub(super) root_context: &'d PathAwareValue
}

impl<'d> EvaluationContext for MetadataAppender<'d> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        self.delegate.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.delegate.rule_status(rule_name)
    }

    fn end_evaluation(
        &self,
        eval_type: EvaluationType,
        context: &str,
        msg: String,
        from: Option<PathAwareValue>,
        to: Option<PathAwareValue>,
        status: Option<Status>,
        cmp: Option<(CmpOperator, bool)>)
    {
        let msg = if eval_type == EvaluationType::Clause {
            match status {
                Some(status) => {
                    loop {
                        if status == Status::FAIL {
                            if let Some(value) = &from {
                                let path = value.self_path();
                                if path.0.starts_with("/Resources") {
                                    let parts = path.0.splitn(4, '/').collect::<Vec<&str>>();
                                    if parts.len() == 4 {
                                        let query = format!("Resources['{}'].Metadata[ keys == /^aws/ ]", parts[2]);
                                        let AccessQuery { query: query, match_all: all } =
                                            AccessQuery::try_from(query.as_str()).unwrap();
                                        if let Ok(selected) = self.root_context.select(all, &query, self) {
                                            break format!("{}\nMetadata: {:?}", msg, selected)
                                        }
                                    }
                                }
                            }
                        }
                        break msg
                    }
                },
                None => msg,
            }
        }
        else { msg };
        self.delegate.end_evaluation(eval_type, context, msg, from, to, status, cmp)
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        self.delegate.start_evaluation(eval_type, context)
    }
}

#[cfg(test)]
#[path = "aws_meta_appender_tests.rs"]
mod aws_meta_appender_tests;

