use crate::rules::{path_value::PathAwareValue, QueryResult};

pub(crate) fn count(args: &[QueryResult]) -> u32 {
    args.iter().fold(0, |each, entry| match entry {
        QueryResult::Literal(_) | QueryResult::Resolved(_) => each + 1,
        _ => each,
    })
}

pub(crate) fn new_count(args: std::rc::Rc<PathAwareValue>) -> u32 {
    match &*args {
        PathAwareValue::List((_, l)) => l.len() as u32,
        PathAwareValue::Map((_, m)) => m.keys.len() as u32,
        _ => unreachable!(),
    }
}

#[cfg(test)]
#[path = "collections_tests.rs"]
mod collections_tests;
