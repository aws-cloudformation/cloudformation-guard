use crate::rules::path_value::PathAwareValue;
use crate::rules::errors::{Error, ErrorKind};
use lazy_static::lazy_static;
use regex::Regex;
use std::collections::BTreeMap;

lazy_static! {
    static ref RELATIVE_PATH: Regex = Regex::new(r"^(\d+)(#|/.*)").ok().unwrap();
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Traversal<'value> {
    nodes: BTreeMap<&'value str, Node<'value>>,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Node<'value> {
    parent: Option<&'value str>,
    value: &'value PathAwareValue,
}

impl<'value> Node<'value> {
    pub(crate) fn parent(&self) -> Option<&str> {
        self.parent
    }

    pub(crate) fn value(&self) -> &PathAwareValue {
        self.value
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TraversalResult<'a, 'b> {
    Value(&'b Node<'a>),
    Key(&'a str)
}

impl<'a, 'b> TraversalResult<'a, 'b> {

    pub(crate) fn as_value(&self) -> Option<&Node<'_>> {
        match self {
            Self::Value(n) => Some(n),
            _ => None
        }
    }

    pub(crate) fn as_key(&self) -> Option<&str> {
        match self {
            Self::Key(k) => Some(*k),
            _ => None
        }
    }
}

fn from_value<'value>(
    current: &'value PathAwareValue,
    parent: Option<&'value str>,
    nodes: &mut BTreeMap<&'value str, Node<'value>>) {

    match current {
        PathAwareValue::Null(path)                  |
        PathAwareValue::String((path, _))           |
        PathAwareValue::Regex((path, _))            |
        PathAwareValue::Bool((path, _))             |
        PathAwareValue::Int((path, _))              |
        PathAwareValue::Float((path, _))            |
        PathAwareValue::RangeInt((path, _))         |
        PathAwareValue::RangeFloat((path, _))       |
        PathAwareValue::RangeChar((path, _))        |
        PathAwareValue::Char((path, _)) => {
            nodes.insert(&path.0, Node {
                parent,
                value: current
            });
        }

        PathAwareValue::Map((path, map)) => {
            nodes.insert(&path.0, Node {
                value: current, parent
            });
            let parent = Some(path.0.as_str());
            for (_key, each) in map.values.iter() {
                from_value(each, parent.clone(), nodes);
            }
        }

        PathAwareValue::List((path, list)) => {
            nodes.insert(&path.0, Node {
                value: current, parent
            });
            let parent = Some(path.0.as_str());
            for each in list.iter() {
                from_value(each, parent.clone(), nodes);
            }
        },
    }
}

impl<'value> Traversal<'value> {
    pub(crate) fn root(&self) -> Option<&Node>{
        self.nodes.get("/")
    }

    pub(crate) fn at<'traverse>(&'traverse self, pointer: &str, node: &'traverse Node) -> crate::rules::Result<TraversalResult> {
        if pointer.is_empty() || pointer == "0" {
            return Ok(TraversalResult::Value(node))
        }

        if pointer == "0#" {
            return Ok(TraversalResult::Key(node.value.self_path().relative()))
        }

        if let Some(captures) = RELATIVE_PATH.captures(pointer) {
            //
            // Safe to unwrap as we capture ints in regex
            //
            let num = captures.get(1).unwrap().as_str().parse::<u32>().unwrap();
            let mut ancestor = 0;
            let mut current= node;
            while ancestor < num {
                match current.parent() {
                    Some(prev) => {
                        current = match self.nodes.get(prev) {
                            Some(node) => node,
                            None => return Err(Error::new(ErrorKind::RetrievalError(
                                format!(
                                    "No ancestors found at path {}, current value at {}",
                                        prev, current.value.self_path())
                            )))
                        }
                    },

                    None => {
                        return Err(Error::new(ErrorKind::RetrievalError(
                            format!("No more ancestors found. Path {} pointing to beyond root", pointer)
                        )))
                    }
                }
                ancestor += 1;
            }

            match captures.get(2) {
                Some(ch) => {
                    let p = ch.as_str();
                    if p == "#" {
                        return Ok(TraversalResult::Key(current.value.self_path().relative()))
                    }
                    let pointer = format!("{}{}", current.value.self_path().0, p);
                    return self.at(&pointer, current)
                },

                None => {
                    return Ok(TraversalResult::Value(current))
                }
            }
        }

        match self.nodes.get(pointer) {
            Some(node) => Ok(TraversalResult::Value(node)),
            None =>
                return Err(Error::new(ErrorKind::RetrievalError(
                    format!("Path {} did not yield value. Current Path {}, expected sub-paths {:?}",
                            pointer, node.value().self_path().0,
                            self.nodes.range(pointer..)
                ))))
        }
    }
}

impl<'v> From<&'v PathAwareValue> for Traversal<'v> {
    fn from(root: &'v PathAwareValue) -> Self {
        let mut nodes = BTreeMap::new();
        from_value(root, None, &mut nodes);
        nodes.insert("/", Node {
            value: root,
            parent: None
        });
        Traversal { nodes }
    }
}

#[cfg(test)]
#[path = "traversal_tests.rs"]
mod traversal_tests;

