use crate::rules::{
    path_value::{Location, Path, PathAwareValue},
    QueryResult, UnResolved,
};

/// Whether a value is a list or map with no members.
fn is_an_empty_collection(value: &PathAwareValue) -> bool {
    match value {
        PathAwareValue::List((_, list)) => list.is_empty(),
        PathAwareValue::Map((_, map)) => map.is_empty(),
        _ => false,
    }
}

/// Whether an unresolved query stopped at a collection that is there and holds nothing, as opposed to
/// at a key or index the data does not have.
///
/// `accumulate` and `accumulate_map` in `eval_context.rs` report an unresolved result when a wildcard
/// reaches a list or map with no members, and the value they hand back is that collection. A key that
/// was not found reports one too, but hands back the struct it searched. The two are told apart by
/// where the query stopped: the unsatisfied part begins with the expansion (`*` or `[*]`) that ran out
/// of members in the first case, and with the key or index that was not found in the second.
///
/// The shape of `traversed_to` alone was the test before, and it is not enough. A struct that is
/// itself empty is a collection with no members, so a key missing from `Properties: {}` read as an
/// empty collection: `count(%b.Properties.Tags[*].Key)` answered 0 and `join(..) != "forbidden"`
/// passed for a bucket with no `Tags` key at all, where the same query against `Properties: { Other:
/// x }` answered nothing and errored. Whether the key was found cannot depend on what else the struct
/// holds.
///
/// Reading the unsatisfied part is reading `SliceDisplay`'s rendering of the remaining query, where
/// `QueryPart::AllValues` prints `*` and the index wildcards print `[*]`; a key is printed as its own
/// text, so a key literally named `*` would be read as an expansion. Marking the case where the
/// result is built, in `accumulate`, would be exact; that function is not changed here.
///
/// `count` and `join` both use this: a wildcard over an empty collection counts 0 and contributes
/// nothing to a join, while a key that was not found is no count and an error, whatever the struct
/// around it holds.
pub(crate) fn stopped_at_an_empty_collection(unresolved: &UnResolved) -> bool {
    let stopped_at_an_expansion = unresolved.remaining_query.starts_with('*')
        || unresolved.remaining_query.starts_with("[*]");
    stopped_at_an_expansion && is_an_empty_collection(&unresolved.traversed_to)
}

/// How many values a query selected, or nothing when the query did not resolve at all.
///
/// Dropping the unresolved results and counting the rest would answer the `Int` 0 for a query naming
/// something absent. That is a value, so it compares, and `count(%b.Properties.Grantz.*) == 0` would
/// pass at exit 0 on a bucket whose correctly spelled `Grants` holds a public grant: one letter between
/// a check and a green build, with nothing in the output saying the path was not found.
///
/// Answering nothing keeps `count` in step with the other functions. Given the same absent path,
/// `to_upper`, `parse_int`, `substring` and `json_parse` all resolve to no values and the clause fails
/// at exit 19, and `join` errors at 19.
///
/// Three cases have to stay apart, and they are distinguishable:
///
/// - A query that selected nothing, such as a filter matching no resource, produces no results at all.
///   Zero is the count of nothing and this is the shape most rules are written in.
/// - A wildcard over a collection with no members produces an unresolved result holding that
///   collection. The query reached it, so zero is the honest count -- `Grants: []` really has no grants.
/// - A key that was not found produces an unresolved result holding the struct that was searched. There
///   is no collection, so there is no count, and this is the one that now answers with nothing.
///
/// A selection that resolved for some values and not for others keeps counting the ones it found. A rule
/// over several buckets where only one carries `Grants` is asking how many grants exist, not whether
/// every bucket has the key, so only a selection where nothing resolved can be a missing path. Where
/// nothing resolved and the reasons are mixed -- one empty collection, one absent key -- the absent key
/// decides it and the answer is nothing, which fails the clause rather than passing it.
pub(crate) fn count(args: &[QueryResult]) -> Option<PathAwareValue> {
    if args.is_empty() {
        return Some(PathAwareValue::Int((Path::root(), 0)));
    }

    let mut resolved = 0;
    let mut absent_path = false;
    for arg in args.iter() {
        match arg {
            QueryResult::Literal(_) | QueryResult::Resolved(_) => resolved += 1,
            QueryResult::UnResolved(ur) => {
                if !stopped_at_an_empty_collection(ur) {
                    absent_path = true;
                }
            }
        }
    }

    if resolved == 0 && absent_path {
        return None;
    }

    Some(PathAwareValue::Int((common_path(args), resolved as i64)))
}

/// Where an answer built from every member of `args` belongs: the longest common prefix of the
/// members' paths.
///
/// `count` and `join` used the first member's path, so `count(%buckets) == 3` over two buckets failed
/// "at" `/Resources/BucketA`, and the report named BucketA as the non-compliant resource for a number
/// that describes both buckets. The same template with the resources in the other order named
/// BucketB. A reader fixing what the report points at fixes the wrong thing.
///
/// The prefix is taken over path segments, not characters, so `/Resources/BucketA` and
/// `/Resources/BucketAB` share `/Resources`, not `/Resources/BucketA`. For a wildcard over one list
/// that is the list; for members spread over several resources it is `/Resources`, which the
/// CloudFormation reporter cannot place under a single resource and so hands to the next reporter,
/// which prints the finding against that path; for one member it is that member's own path. An
/// unresolved member contributes the path it was traversed to, which for an empty collection is the
/// collection itself. Members that share nothing -- `/Resources/A` and `/Outputs/B` -- would share the
/// root's empty path, which would place a finding about two named values at the document; the first
/// member's path is used instead, a place the number was at least computed from. A selection of
/// literals shares the root legitimately and stays there.
///
/// Segments are what the path string holds between `/` characters. A path string spells a key with a
/// `/` in it raw -- `Path::extend_str` joins with a bare `/` and escapes nothing, and nothing else in
/// the crate escapes it either -- so a key such as `app.kubernetes.io/name` spans two segments here
/// and is indistinguishable from two nested keys. Members that are such keys of one parent, with no
/// plainly named sibling among them, share a prefix one segment inside the key, and the answer sits at
/// a path the document has no node for. Telling a `/` that separates keys from one inside a key takes
/// the parent the members came from, which only the query evaluation has; the result is only misplaced,
/// never wrong.
///
/// The location goes with the path. When the shared path is a member's own -- one member, or an empty
/// collection a wildcard reached -- the answer carries that member's location, so the report can point
/// at it. When the shared path is the members' immediate parent -- the collection a wildcard
/// enumerated, every member one segment below it -- the answer carries the first member's location:
/// the container's own position is not among the members, but the first member sits inside it, so a
/// code excerpt opened there shows the members the number describes. When the shared prefix is further
/// up than that, the location is the neutral `L:0,C:0`: no member's position describes a grandparent,
/// and the first member's would point the reader at one branch of a number spanning several.
///
/// The neutral location everywhere a prefix is not a member's own path was tried and rejected: for the
/// documented single-list join, the console reporter's code excerpt for a positionless path opens at
/// line 1 of the file instead of at the collection, which reads worse than the first element's position
/// did.
pub(crate) fn common_path(args: &[QueryResult]) -> Path {
    let members: Vec<&Path> = args
        .iter()
        .map(|arg| match arg {
            QueryResult::Literal(val) | QueryResult::Resolved(val) => val.self_path(),
            QueryResult::UnResolved(ur) => ur.traversed_to.self_path(),
        })
        .collect();

    let first = match members.first() {
        Some(path) => *path,
        None => return Path::root(),
    };

    let mut shared: Vec<&str> = first.0.split('/').collect();
    for path in &members[1..] {
        let kept = shared
            .iter()
            .zip(path.0.split('/'))
            .take_while(|(mine, theirs)| **mine == *theirs)
            .count();
        shared.truncate(kept);
    }
    let shared_segments = shared.len();
    let shared = shared.join("/");

    if shared.is_empty() && !first.0.is_empty() {
        return first.clone();
    }

    if let Some(owner) = members.iter().find(|member| member.0 == shared) {
        return (*owner).clone();
    }

    let shared_is_the_parent_of_every_member = members
        .iter()
        .all(|member| member.0.split('/').count() == shared_segments + 1);
    let location = if shared_is_the_parent_of_every_member {
        first.1
    } else {
        Location::default()
    };

    Path(shared, location)
}

#[cfg(test)]
#[path = "collections_tests.rs"]
mod collections_tests;
