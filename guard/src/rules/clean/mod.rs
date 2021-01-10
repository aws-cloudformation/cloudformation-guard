pub(crate) mod exprs;
pub(crate) mod types;
pub(crate) mod errors;
pub(crate) mod values;
pub(crate) mod evaluate;
pub(crate) mod parser;

pub(crate) use errors::*;
pub(crate) use values::*;

pub(crate) type Result<R> = std::result::Result<R, Error>;

#[derive(Debug, Clone, PartialEq, Copy)]
pub(crate) enum Status {
    PASS,
    FAIL,
    SKIP,
}

pub(crate) trait EvaluationContext {
    fn resolve_variable(&self,
                        variable: &str) -> Result<Vec<&Value>>;

    fn rule_status(&self, rule_name: &str) -> Result<Status>;

    fn report_status(&self, msg: String, from: Option<Value>, to: Option<Value>, status: Status);
}

pub(crate) trait Evaluate {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn EvaluationContext) -> Result<Status>;
}
