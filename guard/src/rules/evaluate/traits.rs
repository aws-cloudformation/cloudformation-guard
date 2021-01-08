use crate::rules::values::Value;
use crate::rules::exprs::QueryPart;
use crate::errors::Error;

pub(crate) type Result<R> = std::result::Result<R, Error>;

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Status {
    PASS,
    FAIL,
    SKIP,
}

pub(crate) trait Resolver {
    fn resolve_variable(&self,
                        variable: &str) -> Result<Vec<&Value>>;

    fn rule_status(&self, rule_name: &str) -> Result<Status>;
}

pub(crate) trait QueryResolver  {
    fn resolve<'r>(&self,
                   index: usize,
                   query: &[QueryPart<'_>],
                   var_resolver: &dyn Resolver,
                   context: &'r Value) -> Result<Vec<&'r Value>>;
}

pub(crate) trait Evaluate {
    fn evaluate(&self,
                context: &Value,
                var_resolver: &dyn Resolver) -> Result<Status>;
}
