use crate::rules::{Evaluate, EvaluationContext, Result, Status, EvaluationType, path_value::PathAwareValue};
use nom::lib::std::fmt::Formatter;
use serde::{Serialize};

#[derive(Serialize, Debug)]
pub(super) struct StatusContext {
    pub(super) eval_type: EvaluationType,
    pub(super) context: String,
    #[serde(skip_serializing)]
    pub(super) msg: Option<String>,
    pub(super) from: Option<PathAwareValue>,
    pub(super) to: Option<PathAwareValue>,
    pub(super) status: Option<Status>,
    pub(super) children: Vec<StatusContext>,
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
            children: vec![]
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

impl<'r> StackTracker<'r> {
    pub(super) fn new(delegate: &'r dyn EvaluationContext) -> Self {
        StackTracker {
            root_context: delegate,
            stack: std::cell::RefCell::new(Vec::new()),
        }
    }

    pub(super) fn stack(self) -> Vec<StatusContext> {
        self.stack.into_inner()
    }
}

impl<'r> EvaluationContext for StackTracker<'r> {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>> {
        self.root_context.resolve_variable(variable)
    }

    fn rule_status(&self, rule_name: &str) -> Result<Status> {
        self.root_context.rule_status(rule_name)
    }

    fn end_evaluation(&self,
                      eval_type: EvaluationType,
                      context: &str,
                      msg: String,
                      from: Option<PathAwareValue>,
                      to: Option<PathAwareValue>,
                      status: Option<Status>) {

        if self.stack.borrow().len() == 1 {
            match self.stack.borrow_mut().get_mut(0) {
                Some(top) => {
                    top.status = status.clone();
                    top.from = from.clone();
                    top.to = to.clone();
                    top.msg = Some(msg.clone());
                },
                None => unreachable!()
            }
            return;
        }

        let stack = self.stack.borrow_mut().pop();
        match stack {
            Some(mut stack) => {
                stack.status = status.clone();
                stack.from = from.clone();
                stack.to = to.clone();
                stack.msg = Some(msg.clone());

                match self.stack.borrow_mut().last_mut() {
                    Some(cxt) =>  {
                        cxt.children.push(stack)
                    }
                    None => unreachable!()
                }
            },
            None => {}
        }
        self.root_context.end_evaluation(eval_type, context, msg, from, to, status);
    }

    fn start_evaluation(&self,
                        eval_type: EvaluationType,
                        context: &str) {
        let indent= self.stack.borrow().len();
        self.stack.borrow_mut().push(
            StatusContext::new(eval_type, context));
        self.root_context.start_evaluation(eval_type, context);
    }

}

