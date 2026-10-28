use crate::rules::errors::Error;
use crate::rules::path_value::{Path, PathAwareValue};
use fancy_regex::Regex;
use lazy_static::lazy_static;
use std::borrow::Cow;
use std::collections::BTreeMap;

lazy_static! {
    static ref RELATIVE_PATH: Regex = Regex::new(r"^(\d+)(#|/.*)").ok().unwrap();
}

/// An index over every node of a document, addressed by pointer.
///
/// Nodes are keyed on a JSON Pointer (RFC 6901) built from the document's structure: segments are
/// joined with `/`, and inside a segment `~` is written `~0` and `/` is written `~1`. Keying on the
/// value's own path string, `Path.0`, which joins segments with a bare `/` and escapes nothing, would
/// send a key `A/B` under `Resources` and a key `B` under `Resources.A` both to `/Resources/A/B`, where
/// the later insert replaces the earlier one: which node `at("/Resources/A/B")` returned would depend
/// on the order the two keys appear in the file, and the console reporter would print one resource's
/// `Type` under the other's name.
///
/// The path strings on the values are not touched; they are what reports print, and an escape there
/// would change every `/paths//pets`-style path a user sees. Only this index spells keys the RFC way,
/// and so must every pointer handed to `at`: a caller that builds one out of a key it holds spells
/// the key through `escape_pointer_segment`. A raw spelling is not retried, because the two
/// spellings overlap wherever a key holds a literal `~0` or `~1`, and a fallback would answer such a
/// miss with a different node.
///
/// Two limits remain. The root is also indexed under `/` so that `at("/", ..)` keeps meaning the
/// document, which is what every caller passes; a top-level key spelled `""` has the same pointer and
/// is shadowed by it, as it always was. And a `#` pointer answers with `Path::relative()`, the text
/// after the last `/` of the path string, which for a key holding a `/` is the key's tail rather
/// than the key; no production caller asks for a key.
///
/// Cost. For a document with no `/` or `~` in any key every pointer is borrowed from the value's own
/// path string and the map is the same set of entries it was; what grew is `Node`, from 24 to 56
/// bytes, for the pointer it now carries and the `Cow` its parent became. A node under an escaped key
/// owns its pointer, and that string is copied for the map key, for the node, and once more into
/// each child as its parent; the copies are confined to the escaped subtree.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Traversal<'value> {
    nodes: BTreeMap<Cow<'value, str>, Node<'value>>,
    /// Whether any key is owned, which is to say whether any path string differs from its pointer.
    /// `pointer_for` scans the map only when this is set; for every other document the pointer is the
    /// path string and one lookup settles it.
    has_escaped_keys: bool,
}

#[derive(Clone, PartialEq)]
pub(crate) struct Node<'value> {
    /// This node's pointer, which is the key it sits under in `Traversal::nodes` for every entry but
    /// one: the alias of the root under `/` carries the root's own pointer, `""`, so that a relative
    /// pointer from `root()` extends the right string. Borrowed from the value's path string when the
    /// two spell the same, which is every node whose ancestry has no `/` or `~` in a key.
    key: Cow<'value, str>,
    /// The parent's pointer, so that `N/..` can climb with a plain lookup.
    parent: Option<Cow<'value, str>>,
    value: &'value PathAwareValue,
}

/// `Node { parent, value }`, as the derive printed before `key` was added.
///
/// Hand-written so that the "expected sub-paths" text a `TraversalError` renders, which the
/// Terraform reporter can propagate to a user, stays byte-identical to what it was for every
/// document without a `/` or `~` in a key. The pointer is the map key the node sits under and is
/// printed there.
impl std::fmt::Debug for Node<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("parent", &self.parent)
            .field("value", &self.value)
            .finish()
    }
}

impl<'value> Node<'value> {
    pub(crate) fn parent(&self) -> Option<&str> {
        self.parent.as_deref()
    }

    pub(crate) fn value(&self) -> &PathAwareValue {
        self.value
    }
}

/// Spell a map key as one segment of a pointer: `~` becomes `~0` and `/` becomes `~1` (RFC 6901).
///
/// Borrowed when there is nothing to escape, which is every segment of an ordinary document. The
/// index builds its keys through this, and every caller that builds a pointer out of a key it holds
/// goes through it too: the console reporter spells `/Resources/<name>` as
/// `format!("/Resources/{}", escape_pointer_segment(name))`, so a resource named `A/B` is looked up
/// as `/Resources/A~1B` and not as a step from `A` into a child `B`.
pub(crate) fn escape_pointer_segment(segment: &str) -> Cow<'_, str> {
    if !segment.contains(['~', '/']) {
        return Cow::Borrowed(segment);
    }
    let mut out = String::with_capacity(segment.len() + 2);
    for ch in segment.chars() {
        match ch {
            '~' => out.push_str("~0"),
            '/' => out.push_str("~1"),
            other => out.push(other),
        }
    }
    Cow::Owned(out)
}

/// The key a pointer segment spells: `~1` back to `/` and `~0` back to `~`, the inverse of
/// `escape_pointer_segment`. A `~` followed by anything else is left as written.
///
/// For a caller that has a segment out of a pointer and wants to show the key it names, which is how
/// the console reporter prints `Resource = A/B` for the segment `A~1B`.
pub(crate) fn unescape_pointer_segment(segment: &str) -> Cow<'_, str> {
    if !segment.contains('~') {
        return Cow::Borrowed(segment);
    }
    let mut out = String::with_capacity(segment.len());
    let mut chars = segment.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '~' {
            match chars.peek() {
                Some('0') => {
                    chars.next();
                    out.push('~');
                }
                Some('1') => {
                    chars.next();
                    out.push('/');
                }
                _ => out.push('~'),
            }
        } else {
            out.push(ch);
        }
    }
    Cow::Owned(out)
}

/// The pointer of a map child: the parent's pointer, `/`, and the escaped key.
///
/// Borrows the child's own path string when that is what the three parts spell, which they do for
/// every node whose ancestry has no `/` or `~` in a key. That case is decided by comparing in place,
/// so for such a node nothing is allocated and the key is the path string, as it was before. Only a
/// node under an escaped key gets an owned key.
fn child_key<'value>(parent: &str, segment: &str, path: &'value str) -> Cow<'value, str> {
    let escaped = escape_pointer_segment(segment);
    let spelled_the_same = path.len() == parent.len() + 1 + escaped.len()
        && path.starts_with(parent)
        && path.as_bytes()[parent.len()] == b'/'
        && path.ends_with(escaped.as_ref());
    if spelled_the_same {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(format!("{}/{}", parent, escaped))
    }
}

/// The pointer of a list element: the parent's pointer, `/`, and the index.
///
/// An index has nothing to escape, so the path string is the pointer whenever its last segment is this
/// index under this parent, which is read off the string with `rsplit_once` rather than by formatting
/// the index: no allocation per element. Only an element under an escaped key gets an owned key.
fn element_key<'value>(parent: &str, index: usize, path: &'value str) -> Cow<'value, str> {
    let spelled_the_same = match path.rsplit_once('/') {
        Some((prefix, last)) => prefix == parent && last.parse::<usize>() == Ok(index),
        None => false,
    };
    if spelled_the_same {
        Cow::Borrowed(path)
    } else {
        Cow::Owned(format!("{}/{}", parent, index))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum TraversalResult<'a, 'b> {
    Value(&'b Node<'a>),
    Key(&'a str),
}

#[cfg(test)]
impl<'a, 'b> TraversalResult<'a, 'b> {
    pub(crate) fn as_value(&self) -> Option<&Node<'_>> {
        match self {
            Self::Value(n) => Some(n),
            _ => None,
        }
    }
}

/// Why `Traversal::at` could not resolve a pointer.
///
/// `at` returned `Error::RetrievalError(String)`, and for a plain miss the string was built with
/// `format!` over `nodes.range(pointer..)`: every node whose path sorts after the pointer, each
/// Debug-printed with its entire subtree. The console reporter matches the `Err` with `_` and throws
/// it away, and produces several such misses per non-compliant resource (one for
/// `Metadata.aws:cdk:path` on every hand-written template), so a report on N failing resources
/// rendered the document's tail a few times per resource for nobody. Measured at a debug build's
/// 11.3 s against 0.5 s for a 1000-resource report.
///
/// This type holds the pointer and a borrow of the traversal instead, and renders the candidates in
/// its `Display`. The text is the same as before, so the one caller that does propagate the error
/// with `?` -- the Terraform reporter -- prints what it printed before; it reaches `Error` through
/// the `From` impl below, which is where the rendering now happens.
///
/// What a miss still costs: `pointer` is owned, because the caller's string does not outlive the
/// call and the relative form builds its absolute pointer in a `format!` of its own; `current` is
/// borrowed from the document. The relative form also runs the `RELATIVE_PATH` regex before anything
/// else. A miss is cheap, then, not free.
///
/// Neither `Clone` nor `PartialEq`: a value that borrows the whole index has no use for either, and a
/// derived `PartialEq` would compare two indexes node by node.
pub(crate) enum TraversalError<'t, 'value> {
    /// A relative pointer `N/...` climbed more levels than the node has ancestors.
    BeyondRoot { pointer: String },
    /// A node named a parent the index does not hold. An index built by `From<&PathAwareValue>`
    /// records every parent it names, so this is a corrupted index rather than a bad pointer.
    MissingAncestor { parent: &'t str, current: &'t Path },
    /// No node at `pointer`. `current` is the path of the node the lookup started from.
    NotFound {
        pointer: String,
        current: &'t str,
        traversal: &'t Traversal<'value>,
    },
}

/// The variant and its strings; the borrowed traversal as its node count.
///
/// Hand-written because a derive would print the whole index behind `NotFound` -- every node of the
/// document -- for a `{:?}` of a miss, which is the eager rendering this type exists to avoid, moved
/// from `Display` to `Debug`.
impl std::fmt::Debug for TraversalError<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraversalError::BeyondRoot { pointer } => f
                .debug_struct("BeyondRoot")
                .field("pointer", pointer)
                .finish(),
            TraversalError::MissingAncestor { parent, current } => f
                .debug_struct("MissingAncestor")
                .field("parent", parent)
                .field("current", current)
                .finish(),
            TraversalError::NotFound {
                pointer,
                current,
                traversal,
            } => f
                .debug_struct("NotFound")
                .field("pointer", pointer)
                .field("current", current)
                .field(
                    "traversal",
                    &format_args!("<{} nodes>", traversal.nodes.len()),
                )
                .finish(),
        }
    }
}

impl std::fmt::Display for TraversalError<'_, '_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraversalError::BeyondRoot { pointer } => write!(
                f,
                "No more ancestors found. Path {} pointing to beyond root",
                pointer
            ),
            TraversalError::MissingAncestor { parent, current } => write!(
                f,
                "No ancestors found at path {}, current value at {}",
                parent, current
            ),
            TraversalError::NotFound {
                pointer,
                current,
                traversal,
            } => write!(
                f,
                "Path {} did not yield value. Current Path {}, expected sub-paths {:?}",
                pointer,
                current,
                traversal.nodes.range::<str, _>((
                    std::ops::Bound::Included(pointer.as_str()),
                    std::ops::Bound::Unbounded,
                ))
            ),
        }
    }
}

impl From<TraversalError<'_, '_>> for Error {
    fn from(err: TraversalError<'_, '_>) -> Self {
        Error::RetrievalError(err.to_string())
    }
}

/// Index `current` under `key`, then its children under pointers built from their segments.
fn from_value<'value>(
    current: &'value PathAwareValue,
    key: Cow<'value, str>,
    parent: Option<Cow<'value, str>>,
    traversal: &mut Traversal<'value>,
) {
    if matches!(key, Cow::Owned(_)) {
        traversal.has_escaped_keys = true;
    }
    let node = Node {
        key: key.clone(),
        parent,
        value: current,
    };
    match current {
        PathAwareValue::Map((_, map)) => {
            for (segment, each) in map.values.iter() {
                let child = child_key(&key, segment, each.self_path().0.as_str());
                from_value(each, child, Some(key.clone()), traversal);
            }
        }
        PathAwareValue::List((_, list)) => {
            for (index, each) in list.iter().enumerate() {
                let child = element_key(&key, index, each.self_path().0.as_str());
                from_value(each, child, Some(key.clone()), traversal);
            }
        }
        _ => {}
    }
    traversal.nodes.insert(key, node);
}

impl<'value> Traversal<'value> {
    /// The document. Its node carries the root's own pointer, `""`, so that a relative pointer from
    /// it (`0/Resources`) extends to `/Resources` rather than to `//Resources`.
    pub(crate) fn root(&self) -> Option<&Node> {
        self.nodes.get("/")
    }

    /// The pointer of the node a value sits at, given the value's path.
    ///
    /// For a reporter that holds a finding and wants to file it by pointer. A finding carries a
    /// `Path` -- the path string and the source position -- and not the node itself: the evaluator
    /// runs over a clone of the document, so the value it recorded is not the one this index holds.
    /// Two nodes can share a path string (a key `A/B` beside a key `A` with a child `B`), and then
    /// the source position is what tells them apart.
    ///
    /// One lookup for every document without an escaped key, where the pointer is the path string.
    /// Otherwise the node whose path string and position both match is found by a scan, and if no
    /// position matches (merged input parameters carry no position) the first node with the path
    /// string, in pointer order. `None` for a path no node has, such as a value computed by a
    /// function, and the caller keeps the path string.
    pub(crate) fn pointer_for(&self, path: &Path) -> Option<&str> {
        let direct = self.nodes.get(path.0.as_str());
        if !self.has_escaped_keys {
            return direct.map(|node| node.key.as_ref());
        }
        if let Some(node) = direct {
            if node.value.self_path() == path {
                return Some(node.key.as_ref());
            }
        }
        let mut first_with_the_string = None;
        for (key, node) in &self.nodes {
            let here = node.value.self_path();
            if here.0 != path.0 {
                continue;
            }
            if here.1 == path.1 {
                return Some(key.as_ref());
            }
            first_with_the_string.get_or_insert(key.as_ref());
        }
        first_with_the_string
    }

    /// Resolve `pointer` from `node`.
    ///
    /// The `Err` borrows this traversal and renders its message only when displayed or converted to
    /// `Error`; see `TraversalError` for what a miss still costs.
    pub(crate) fn at<'traverse>(
        &'traverse self,
        pointer: &str,
        node: &'traverse Node,
    ) -> Result<TraversalResult, TraversalError<'traverse, 'value>> {
        if pointer.is_empty() || pointer == "0" {
            return Ok(TraversalResult::Value(node));
        }

        if pointer == "0#" {
            return Ok(TraversalResult::Key(node.value.self_path().relative()));
        }

        if let Ok(Some(captures)) = RELATIVE_PATH.captures(pointer) {
            //
            // Safe to unwrap as we capture ints in regex
            //
            let num = captures.get(1).unwrap().as_str().parse::<u32>().unwrap();
            let mut ancestor = 0;
            let mut current = node;
            while ancestor < num {
                match current.parent() {
                    Some(prev) => {
                        current = match self.nodes.get(prev) {
                            Some(node) => node,
                            None => {
                                return Err(TraversalError::MissingAncestor {
                                    parent: prev,
                                    current: current.value.self_path(),
                                })
                            }
                        }
                    }

                    None => {
                        return Err(TraversalError::BeyondRoot {
                            pointer: pointer.to_string(),
                        })
                    }
                }
                ancestor += 1;
            }

            match captures.get(2) {
                Some(ch) => {
                    let p = ch.as_str();
                    if p == "#" {
                        return Ok(TraversalResult::Key(current.value.self_path().relative()));
                    }
                    let pointer = format!("{}{}", current.key, p);
                    return self.at(&pointer, current);
                }

                None => return Ok(TraversalResult::Value(current)),
            }
        }

        match self.nodes.get(pointer) {
            Some(node) => Ok(TraversalResult::Value(node)),
            None => Err(TraversalError::NotFound {
                pointer: pointer.to_string(),
                current: node.value.self_path().0.as_str(),
                traversal: self,
            }),
        }
    }
}

impl<'v> From<&'v PathAwareValue> for Traversal<'v> {
    fn from(root: &'v PathAwareValue) -> Self {
        let mut traversal = Traversal {
            nodes: BTreeMap::new(),
            has_escaped_keys: false,
        };
        let root_key = Cow::Borrowed(root.self_path().0.as_str());
        from_value(root, root_key.clone(), None, &mut traversal);
        // The alias `/` for the document: the same node as the root, under a second key, carrying the
        // root's own pointer so that relative pointers from `root()` extend the right string.
        traversal.nodes.insert(
            Cow::Borrowed("/"),
            Node {
                key: root_key,
                parent: None,
                value: root,
            },
        );
        traversal
    }
}

#[cfg(test)]
#[path = "traversal_tests.rs"]
mod traversal_tests;
