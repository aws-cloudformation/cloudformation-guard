use crate::rules::values::CmpOperator;
use crate::rules::{path_value::PathAwareValue, EvaluationContext, EvaluationType, Result, Status};
use nom::lib::std::fmt::Formatter;
use serde::Serialize;

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

impl StatusContext {
    fn new(eval_type: EvaluationType, context: &str) -> Self {
        StatusContext {
            eval_type,
            context: context.to_string(),
            status: None,
            msg: None,
            from: None,
            to: None,
            comparator: None,
            children: vec![],
        }
    }
}

pub(crate) struct StackTracker<'r> {
    root_context: &'r dyn EvaluationContext,
    stack: std::cell::RefCell<Vec<StatusContext>>,
}

impl<'r> std::fmt::Debug for StackTracker<'r> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.stack.borrow().fmt(f)
    }
}

impl<'r> EvaluationContext for StackTracker<'r> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        self.root_context.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.root_context.rule_status(rule_name)
    }

    fn end_evaluation(
        &self,
        eval_type: EvaluationType,
        context: &str,
        msg: String,
        from: Option<PathAwareValue>,
        to: Option<PathAwareValue>,
        status: Option<Status>,
        cmp: Option<(CmpOperator, bool)>,
    ) {
        if self.stack.borrow().len() == 1 {
            match self.stack.borrow_mut().get_mut(0) {
                Some(top) => {
                    top.status = status;
                    top.from = from;
                    top.to = to;
                    top.msg = Some(msg);
                    top.comparator = cmp;
                }
                None => unreachable!(),
            }
            return;
        }

        let stack = self.stack.borrow_mut().pop();
        if let Some(mut stack) = stack {
            stack.status = status;
            stack.from = from.clone();
            stack.to = to.clone();
            stack.msg = Some(msg.clone());
            stack.comparator = cmp;

            match self.stack.borrow_mut().last_mut() {
                Some(cxt) => cxt.children.push(stack),
                None => unreachable!(),
            }
        }
        self.root_context
            .end_evaluation(eval_type, context, msg, from, to, status, cmp);
    }

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str) {
        let _indent = self.stack.borrow().len();
        self.stack
            .borrow_mut()
            .push(StatusContext::new(eval_type, context));
        self.root_context.start_evaluation(eval_type, context);
    }
}
