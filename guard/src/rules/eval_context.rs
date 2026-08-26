use crate::rules::errors::Error;
use crate::rules::exprs::{
    block_capture_names, collect_let_value_capture_names, collect_query_capture_names, AccessQuery,
    Block, CaptureNames, Conjunctions, FunctionExpr, GuardClause, LetExpr, LetValue,
    ParameterizedRule, QueryPart, Rule, RulesFile, SliceDisplay,
};
use crate::rules::functions::collections::count;
use crate::rules::functions::converters::{
    parse_bool, parse_char, parse_float, parse_int, parse_str,
};
use crate::rules::functions::strings::{
    join, json_parse, regex_replace, substring, to_lower, to_upper, url_decode,
};
use crate::rules::path_value::{index_offset, list_index_of, Location, MapValue, PathAwareValue};
use crate::rules::values::CmpOperator;
use crate::rules::Result;
use crate::rules::Status::SKIP;
use crate::rules::{
    BlockCheck, ClauseCheck, ComparisonClauseCheck, EvalContext, InComparisonCheck, NamedStatus,
    QueryResult, RecordTracer, RecordType, Status, TypeBlockCheck, UnResolved, UnaryValueCheck,
    UnboundName, ValueCheck,
};
use cruet::case::{camel, kebab, pascal, snake, title, train};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::convert::TryFrom;
use std::rc::Rc;
use std::vec::Vec;

use super::eval::{ClauseRole, Outcome};
use super::functions::date_time::{now, parse_epoch};

pub(crate) struct Scope<'value, 'loc: 'value> {
    root: Rc<PathAwareValue>,
    resolved_variables: HashMap<&'value str, Vec<QueryResult>>,
    literals: HashMap<&'value str, Rc<PathAwareValue>>,
    variable_queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
    function_expressions: HashMap<&'value str, &'value FunctionExpr<'loc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Default)]
pub(crate) struct EventRecord<'value> {
    pub(crate) context: String,
    pub(crate) container: Option<RecordType<'value>>,
    pub(crate) children: Vec<EventRecord<'value>>,
}

/// What a rule answered, memoised, together with the explanation that answer does not carry.
///
/// The reason is here rather than left in the record tree because the tree is not the same for two
/// references to one rule. The first reference misses this cache and re-evaluates the rule, which
/// records the failing clause under the referencing rule's own condition -- where
/// [`RecordTracer::reason_from_last_closed_record`] reads it from. The second reference hits, evaluates
/// nothing, and leaves nothing to read, so it printed the verdict and stopped while the reference above
/// it in the same run printed the reason in full.
///
/// Kept beside the outcome and not inside it for the reason recorded on `Outcome` itself: it is `Copy`,
/// and a payload would break that at every site that folds one.
struct CachedRuleAnswer {
    /// The rule's answer. The only thing any caller reads to decide anything.
    outcome: Outcome,

    /// Why the rule could not be evaluated, when that is what it answered and it said why.
    ///
    /// Read back only to explain a verdict that has already been decided, never to decide one -- the
    /// same one-way rule the accessor it feeds is documented under.
    undecidable_reason: Option<String>,
}

pub(crate) struct RootScope<'value, 'loc: 'value> {
    scope: Scope<'value, 'loc>,
    rules: HashMap<&'value str, Vec<&'value Rule<'loc>>>,
    rules_status: HashMap<(&'value str, super::eval::ClauseRole), CachedRuleAnswer>,
    parameterized_rules: HashMap<&'value str, &'value ParameterizedRule<'loc>>,
    /// Why a rule a memoised undecidable answer was just served for could not be evaluated, and how many
    /// records had closed at the moment it was served.
    ///
    /// Set by [`RootScope::rule_status`] when it answers from the cache, and read by
    /// [`RootScope::reason_from_last_closed_record`] as the fallback for a reference that recorded
    /// nothing. Deliberately not a bare "last reason": the count is what ties it to one record. The
    /// reference closes exactly one record after being answered, so the fallback applies only while
    /// `closed_records()` is that count plus one, and a reason left here by an earlier reference cannot
    /// be read by a later clause. That bound is structural, rather than a clearing discipline for a
    /// future change to get wrong, and it is deliberately not the reference's *name*: a gate reference
    /// records a block check that does not carry one, which is the shape this case actually produces.
    served_from_cache: Option<(String, usize)>,
    recorder: RecordTracker<'value>,
    /// Notes for the author that this run's answer does not carry, collected during evaluation.
    ///
    /// A set rather than a list: a clause inside a type block is evaluated once per matched resource,
    /// and ten identical lines about the same rule tell the reader nothing the first one did not.
    diagnostics: BTreeSet<String>,
    /// Keys captured by a filter, held apart from `scope.resolved_variables` so they can be cleared
    /// without discarding resolved query results.
    ///
    /// A rule's `when` condition is evaluated against this scope, so a capture made there used to land in
    /// the same map for the whole file and outlive its rule. Two rules using the same capture name in
    /// their conditions interfered: the second saw the first's keys, so a clause reading the name failed
    /// on evidence from a rule it has nothing to do with -- and renaming one of them changed the other's
    /// verdict, which is the tell that no rule should have to care about.
    captured: HashMap<&'value str, Vec<QueryResult>>,
    /// Keys handed up by a block that has finished. See `MergedKeys` for why they are not in
    /// `captured`.
    merged: HashMap<&'value str, Vec<QueryResult>>,
    /// Keys captured while a file-level assignment's right-hand side was being resolved.
    ///
    /// Not in `captured`, because the lifetimes disagree and it was the disagreement that showed. A
    /// capture is a side effect of running a query, the query behind an assignment runs once and its
    /// result is memoised for the file, and `reset_captures` clears `captured` between rules. So the
    /// keys existed only in the rule that first forced the assignment: two rules containing the same
    /// two clauses gave PASS and then an unresolved-variable error, and swapping two clauses inside one
    /// rule did the same. These keys belong to the assignment, and the assignment belongs to the file.
    assignment_captures: HashMap<&'value str, Vec<QueryResult>>,
    /// For each name a file-level assignment declares as a filter capture, the assignments declaring
    /// it, sorted. Read from the rule text at construction, so that `bind_assignment_captures` can
    /// resolve them on a read of the capture name rather than waiting for a clause to read the
    /// assignment.
    capture_sources: HashMap<&'value str, Vec<&'value str>>,
    /// The file-level assignments whose right-hand sides are being resolved right now.
    ///
    /// Two jobs, and they are the same fact: while this is non-empty a capture arriving at this scope
    /// came from an assignment and belongs in `assignment_captures`, and an assignment already in here
    /// must not be resolved again on its own behalf. The second is reachable rather than defensive --
    /// `Resources[ nm | Type == %nm ]` has a predicate reading the capture its own filter declares.
    resolving_assignments: BTreeSet<&'value str>,
}

/// Whether a variable lookup may be answered from keys a finished block handed up.
///
/// The two kinds of key have the same content and different reach, so the reach has to be recorded
/// somewhere; splitting the maps and passing this at the lookup is that record.
///
/// A key still in the block that captured it belongs to the iteration that is running, and every
/// clause under that iteration -- including one in a block nested inside it -- is asking about the
/// same resource. Once the block ends, `merge_captures_into_parent` hands its keys up as one list,
/// and that list is a union over the iterations. A clause at the enclosing level reading the name
/// means the union. A clause inside a *different* iterating block does not: it runs once per
/// resource and asks about that resource, so the union would let one resource's key answer for
/// another's.
#[derive(Copy, Clone, Eq, PartialEq)]
enum MergedKeys {
    /// The lookup is a clause at the scope's own level.
    Visible,
    /// The lookup started inside a nested block.
    Hidden,
}

impl<'value, 'loc: 'value> RootScope<'value, 'loc> {
    #[cfg(test)]
    pub fn reset_root(self, new_root: Rc<PathAwareValue>) -> RootScope<'value, 'loc> {
        root_scope_with(
            self.scope.literals,
            self.scope.variable_queries,
            self.rules,
            self.parameterized_rules,
            self.scope.function_expressions,
            new_root,
        )
    }

    pub(crate) fn reset_recorder(&mut self) -> RecordTracker<'value> {
        std::mem::replace(
            &mut self.recorder,
            RecordTracker {
                final_event: None,
                closed: 0,
                events: vec![],
            },
        )
    }

    /// The body of both `resolve_variable` and `resolve_variable_from_nested_block`.
    fn lookup(
        &mut self,
        variable_name: &'value str,
        merged: MergedKeys,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Literal(Rc::clone(val))]);
        }

        self.bind_assignment_captures(variable_name)?;

        // Captures before resolved queries, and held in their own map so `reset_captures` can clear
        // them between rules without discarding anything else.
        if let Some(values) = self.captured.get(variable_name) {
            return Ok(values.clone());
        }

        if merged == MergedKeys::Visible {
            if let Some(values) = self.merged.get(variable_name) {
                return Ok(values.clone());
            }
        }

        if let Some(values) = self.assignment_captures.get(variable_name) {
            return Ok(values.clone());
        }

        if let Some(values) = self.scope.resolved_variables.get(variable_name) {
            return Ok(values.clone());
        }

        if let Some(FunctionExpr {
            parameters, name, ..
        }) = self.scope.function_expressions.get(variable_name)
        {
            // Marked as in progress for the whole resolution, so that a capture a parameter's query
            // makes is filed against this assignment rather than against the rule that read it.
            self.resolving_assignments.insert(variable_name);
            let result = resolve_function(name, parameters, self);
            self.resolving_assignments.remove(variable_name);
            let result = result?;
            self.scope
                .resolved_variables
                .insert(variable_name, result.clone());

            return Ok(result);
        }

        let query = match self.scope.variable_queries.get(variable_name) {
            Some(val) => val,
            None => {
                // The end of the chain, and the only place the unresolved-variable error is produced.
                // Two declarations save a name from it. One is a file-level assignment declaring it as
                // a capture, whose query then captured nothing: the same clause resolves when the query
                // does match, so erroring here makes whether the file produces a report at all depend
                // on the template it was run against. The other is a block the lookup came out of,
                // which is what `unbound` carries -- see `UnboundName` for why the block has to be the
                // one to say so.
                //
                // A name neither declares is still an error.
                if self.capture_sources.contains_key(variable_name)
                    || unbound == UnboundName::EmptySelection
                {
                    return Ok(vec![]);
                }
                return Err(Error::MissingValue(format!(
                    "Could not resolve variable by name {} across scopes",
                    variable_name
                )));
            }
        };

        let match_all = query.match_all;

        self.resolving_assignments.insert(variable_name);
        let result = query_retrieval(0, &query.query, self.root(), self);
        self.resolving_assignments.remove(variable_name);
        let result = result?;
        let result = if !match_all {
            result
                .into_iter()
                .filter(|q| matches!(q, QueryResult::Resolved(_)))
                .collect()
        } else {
            result
        };
        self.scope
            .resolved_variables
            .insert(variable_name, result.clone());
        Ok(result)
    }

    /// Resolve every file-level assignment whose right-hand side declares `variable_name` as a filter
    /// capture, so that reading the capture name is what binds it.
    ///
    /// The alternative, which is what this replaces, is that the name is bound only if some clause
    /// earlier in the same rule read the assignment. That made the value depend on things the author
    /// cannot see from the clause: swapping two clauses in one rule turned a PASS into an
    /// unresolved-variable error, two rules with the same two clauses gave PASS and then that error,
    /// and adding a clause reading an unrelated assignment that happened to spell its capture the same
    /// way changed what the name held.
    ///
    /// Resolving on read is cheap after the first time, because the assignment's result is memoised and
    /// its keys are kept in `assignment_captures` rather than in the map `reset_captures` clears.
    ///
    /// A name more than one assignment declares binds to the union over all of them, so that the value
    /// does not depend on which of them some clause happened to force. Such a file declares one name
    /// twice in one scope, which `docs/QUERY_AND_FILTERING.md` forbids and the parser ought to refuse;
    /// until it does, the union is what keeps the answer the same everywhere it is read.
    fn bind_assignment_captures(&mut self, variable_name: &'value str) -> Result<()> {
        let sources = match self.capture_sources.get(variable_name) {
            Some(sources) => sources.clone(),
            None => return Ok(()),
        };
        for source in sources {
            // An assignment already being resolved is skipped rather than resolved again. A filter
            // predicate can read the capture its own filter declares, and asking for that assignment
            // from inside itself has no answer to wait for.
            if self.resolving_assignments.contains(source) {
                continue;
            }
            self.lookup(source, MergedKeys::Visible, UnboundName::Error)?;
        }
        Ok(())
    }
}

pub(crate) struct BlockScope<'value, 'loc: 'value, 'eval> {
    scope: Scope<'value, 'loc>,
    /// Keys captured by a filter during *this* iteration of the block.
    ///
    /// Held apart from `scope.resolved_variables` so the two can be treated differently on exit: a
    /// resolved query result belongs to the iteration and dies with it, while a captured key has to
    /// survive for a clause that reads it after the block.
    captured: HashMap<&'value str, Vec<QueryResult>>,
    /// Keys handed up by a block nested inside this one, once that block has finished. See
    /// `MergedKeys`.
    merged: HashMap<&'value str, Vec<QueryResult>>,
    /// Every name a filter in this block declares as a capture, read from the rule text at
    /// construction rather than learned as keys arrive. See `resolve_variable` for what it is for and
    /// `block_capture_names` for why it cannot be gathered at runtime.
    capture_names: BTreeSet<&'value str>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

impl<'value, 'loc: 'value, 'eval> BlockScope<'value, 'loc, 'eval> {
    /// Hand this iteration's captures to the enclosing scope, as merged keys.
    ///
    /// Called once the block has been evaluated, which gives a filter capture two readings depending
    /// on where it is read, and both are the ones that were wanted:
    ///
    /// - Inside the block, `resolve_variable` finds `captured` first, so a clause sees the keys
    ///   captured during the iteration it is part of. An iteration that captured nothing under a name
    ///   the block *declares* answers empty instead of reaching the parent, so one resource's key
    ///   cannot satisfy another resource's clause -- see `resolve_variable` for that arm. Three ways
    ///   to capture nothing under a declared name: a filter that matched no entry, a capturing clause
    ///   skipped because an `or` took the other branch, and one inside a `when` block whose condition
    ///   failed. `a_capture_does_not_leak_from_one_iteration_of_a_block_into_the_next` pins the second
    ///   and `a_bare_name_capture_does_not_leak_across_iterations_of_a_block` the third.
    /// - After the block, the keys have been merged upward, so a clause reading the name at the
    ///   enclosing level sees every iteration's keys -- which is what it saw before any of this and
    ///   what such a clause means.
    ///
    /// They arrive in the parent's `merged` map rather than its `captured` one, because there is a
    /// third place the name can be read from and it wants the first reading rather than the second: a
    /// clause inside a *different* iterating block.
    ///
    /// ```text
    /// rule r {
    ///     Resources.*[ Type == 'AWS::S3::Bucket' ] {
    ///         Properties.Config[ cfg | Enabled == true ] !empty
    ///     }
    ///     Resources.*[ Type == 'AWS::S3::Bucket' ] {
    ///         some %cfg == "alpha"
    ///     }
    /// }
    /// ```
    ///
    /// The second block declares no capture, so its lookup defers past itself, and while these keys
    /// went into the parent's `captured` map that deferral found the union of the first block's
    /// iterations. A bucket whose only enabled config is `beta` passed on a different bucket's
    /// `alpha`, at exit 0, in either document order -- and failed correctly when it was alone in the
    /// file, which is the shape that makes a rule like this look tested. Splitting the map is what
    /// lets `resolve_variable_from_nested_block` withhold the union from the second block while a
    /// clause at the parent's own level still reads it.
    ///
    /// Storing captures in the block and stopping there was the first attempt, and it broke the second
    /// reading: the name died with the block while the rule still referenced it, and an unresolvable
    /// variable is an internal error, so one rule took the whole file's report down at exit 255.
    ///
    /// Deferring the merge to after the loop rather than doing it per iteration was considered and is
    /// not needed. It would stop iteration N seeing iterations 1..N-1, but a name the block declares
    /// never reaches the parent from inside the block to begin with, and a name it does not declare is
    /// not one of its own iterations' keys either way.
    pub(in crate::rules) fn merge_captures_into_parent(&mut self) -> Result<()> {
        // Both maps, and everything arrives in the parent as a merged key. A key a nested block handed
        // to this one has to keep travelling: it is read by a clause after *this* block, one level
        // further out again, and it is a union over that nested block's iterations wherever it lands.
        for (name, keys) in std::mem::take(&mut self.captured)
            .into_iter()
            .chain(std::mem::take(&mut self.merged))
        {
            for key in keys {
                if let QueryResult::Resolved(value) = key {
                    self.parent.add_merged_capture_key(name, value)?;
                }
            }
        }
        Ok(())
    }

    /// The body of both `resolve_variable` and `resolve_variable_from_nested_block`.
    fn lookup(
        &mut self,
        variable_name: &'value str,
        merged: MergedKeys,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        if let Some(val) = self.scope.literals.get(variable_name) {
            return Ok(vec![QueryResult::Literal(Rc::clone(val))]);
        }

        // Before `resolved_variables`, so a clause inside the block sees the keys captured during its
        // own iteration rather than an accumulation over all of them.
        if let Some(values) = self.captured.get(variable_name) {
            return Ok(values.clone());
        }

        if merged == MergedKeys::Visible {
            if let Some(values) = self.merged.get(variable_name) {
                return Ok(values.clone());
            }
        }

        if let Some(values) = self.scope.resolved_variables.get(variable_name) {
            return Ok(values.clone());
        }

        if let Some(FunctionExpr {
            parameters, name, ..
        }) = self.scope.function_expressions.get(variable_name)
        {
            let result = resolve_function(name, parameters, self)?;
            self.scope
                .resolved_variables
                .insert(variable_name, result.clone());

            return Ok(result);
        }

        let query = match self.scope.variable_queries.get(variable_name) {
            Some(val) => val,
            None => {
                // Every name defers. What this block contributes is `unbound`: a name it declares as a
                // filter capture, which this iteration did not capture, resolves to an empty selection
                // if no enclosing scope binds it either.
                //
                // Three ways an iteration captures nothing: a filter that matched no entry, a capturing
                // clause skipped because an `or` took the other branch, and one inside a `when` whose
                // condition failed. None of them is an error, so ending the run over one would take
                // every other rule's findings down with it; and none of them is evidence about the
                // value, so the clause reading it fails with the "resolved to no values" reason rather
                // than passing on somebody else's key.
                //
                // Answering empty *here* was the earlier shape, and it went further than the argument
                // for it. An outer `let` or an enclosing parameterized rule's parameter of the same name
                // is a real binding, and this iteration capturing nothing says nothing about it -- so
                // the short-circuit made that binding unreachable for the whole block, in every
                // iteration, and even where the capturing clause provably never ran. A clause then
                // failed on a variable whose `let` sits at the top of the file. Deferring first and
                // keeping the empty selection as the answer of last resort separates the two.
                //
                // The deferral asks for the nested-block reading whatever this lookup was, because it is
                // leaving a block either way: a name this block does not declare is not one of its
                // iterations' keys, so the union a finished block left in an enclosing scope is not an
                // answer about the value being iterated here.
                let unbound = match self.capture_names.contains(variable_name) {
                    true => UnboundName::EmptySelection,
                    false => unbound,
                };
                return self
                    .parent
                    .resolve_variable_from_nested_block(variable_name, unbound);
            }
        };

        let match_all = query.match_all;

        let result = query_retrieval(0, &query.query, self.root(), self)?;
        let result = if !match_all {
            result
                .into_iter()
                .filter(|q| matches!(q, QueryResult::Resolved(_)))
                .collect()
        } else {
            result
        };
        self.scope
            .resolved_variables
            .insert(variable_name, result.clone());

        Ok(result)
    }
}

pub(crate) struct ValueScope<'value, 'eval, 'loc: 'value> {
    pub(crate) root: Rc<PathAwareValue>,
    pub(crate) parent: &'eval mut dyn EvalContext<'value, 'loc>,
}

type ExtractedStatements<'value, 'loc> = (
    HashMap<&'value str, Rc<PathAwareValue>>,
    HashMap<&'value str, &'value AccessQuery<'loc>>,
    HashMap<&'value str, &'value FunctionExpr<'loc>>,
);

fn extract_variables<'value, 'loc: 'value>(
    expressions: &'value Vec<LetExpr<'loc>>,
) -> ExtractedStatements<'value, 'loc> {
    let mut literals = HashMap::with_capacity(expressions.len());
    let mut queries = HashMap::with_capacity(expressions.len());
    let mut functions = HashMap::with_capacity(expressions.len());
    for each in expressions {
        match &each.value {
            LetValue::Value(v) => {
                literals.insert(each.var.as_str(), Rc::new(v.clone()));
            }

            LetValue::AccessClause(query) => {
                queries.insert(each.var.as_str(), query);
            }
            LetValue::FunctionCall(function) => {
                functions.insert(each.var.as_str(), function);
            }
        }
    }

    (literals, queries, functions)
}

/// The keys a variable used in place of a map key denotes, one entry per key.
///
/// `resolve_variable` answers with the results the variable's query produced, and a single result can
/// hold a list -- `let k = Cfg.KeyList` over `KeyList: [Name, Owner]` is one result naming two keys.
/// The loop that consumes these keys already expands a list-valued result into one key per element;
/// this makes the same expansion available to the index that is applied before it.
///
/// One level, which is what that loop does. An element that is itself a list stays a list here and
/// reaches the same "non-string value for key" error it always reached.
fn interpolated_keys(keys: &[QueryResult]) -> Vec<QueryResult> {
    let mut denoted = Vec::with_capacity(keys.len());
    for each in keys {
        let (value, literal) = match each {
            QueryResult::Resolved(value) => (value, false),
            QueryResult::Literal(value) => (value, true),
            QueryResult::UnResolved(_) => {
                denoted.push(each.clone());
                continue;
            }
        };

        match &**value {
            PathAwareValue::List((_, elements)) => {
                denoted.extend(elements.iter().map(|element| {
                    let element = Rc::new(element.clone());
                    match literal {
                        true => QueryResult::Literal(element),
                        false => QueryResult::Resolved(element),
                    }
                }));
            }

            _ => denoted.push(each.clone()),
        }
    }
    denoted
}

fn retrieve_index(
    parent: Rc<PathAwareValue>,
    index: i64,
    elements: &Vec<PathAwareValue>,
    query: &[QueryPart<'_>],
) -> QueryResult {
    // `index_offset` rather than arithmetic here, for two reasons it records: negating `i64::MIN` is
    // not representable, which used to panic in a debug build and wrap in release, and a negative index
    // counts from the end rather than being its own magnitude. Pinned by
    // `an_out_of_range_index_does_not_panic` and `a_negative_index_counts_back_from_the_end`.
    if let Some(check) = index_offset(index, elements.len()) {
        QueryResult::Resolved(Rc::new(elements[check].clone()))
    } else {
        QueryResult::UnResolved(
            UnResolved {
                traversed_to: Rc::clone(&parent),
                remaining_query: format!("{}", SliceDisplay(query)),
                reason: Some(
                    format!("Array Index out of bounds for path = {} on index = {} inside Array = {:?}, remaining query = {}",
                            parent.self_path(), index, elements, SliceDisplay(query))
                )
            }
        )
    }
}

fn accumulate<'value, 'loc: 'value>(
    parent: Rc<PathAwareValue>,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    elements: &[PathAwareValue],
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<QueryResult>> {
    //
    // We are here when we are doing [*] for a list. It is an error if there are no
    // elements
    //
    if elements.is_empty() {
        return to_unresolved_result(
            Rc::clone(&parent),
            format!(
                "No more entries for value at path = {} on type = {} ",
                parent.self_path(),
                parent.type_info()
            ),
            &query[query_index..],
        );
    }

    let mut accumulated = Vec::with_capacity(elements.len());
    for each in elements.iter() {
        // Rebased onto the element, which is what every other expansion helper does and what this one
        // did not. `accumulate_map` builds the same `ValueScope`, and so does the variable-interpolation
        // path above.
        //
        // Without it, anything downstream that consults the scope's *root* rather than the value being
        // traversed saw the whole document. A filter predicate is exactly that, so
        // `Items[*][ Sub == 2 ]` tested `Sub == 2` against the file root, matched nothing, and selected
        // nothing -- while `Items[ Sub == 2 ]`, which reaches the List arm of the filter and rebases
        // there, was right all along. Two spellings of one query disagreed.
        //
        // The damage is not the empty selection, it is what an assertion over one reports: an assertion
        // whose query selects nothing is not applicable, so `Items[*][ Sub == 2 ].Public == false`
        // reported SKIP and a `Public: true` went unflagged at exit 0. The same clause written
        // `Items[ Sub == 2 ].Public == false` fails, as it should.
        //
        // The check that distinguishes a wrong root from a genuine non-match: make the predicate name
        // something only reachable from the document root, such as
        // `Items[*][ Resources.One.Type == 'AWS::S3::Bucket' ]`. That passed, so the root really was
        // the document. `a_filter_after_a_wildcard_resolves_against_the_element` pins it.
        let mut val_resolver = ValueScope {
            root: Rc::new(each.clone()),
            parent: resolver,
        };
        accumulated.extend(query_retrieval_with_converter(
            query_index + 1,
            query,
            Rc::new(each.clone()),
            &mut val_resolver,
            converter,
        )?);
    }
    Ok(accumulated)
}

fn accumulate_map<'value, 'loc: 'value, F>(
    parent: Rc<PathAwareValue>,
    map: &MapValue,
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
    func: F,
) -> Result<Vec<QueryResult>>
where
    F: Fn(
        usize,
        &'value [QueryPart<'loc>],
        Rc<PathAwareValue>,
        Rc<PathAwareValue>,
        &mut dyn EvalContext<'value, 'loc>,
        Option<&dyn Fn(&str) -> String>,
    ) -> Result<Vec<QueryResult>>,
{
    //
    // We are here when we are doing * all values for map. It is an error if there are no
    // elements in the map
    //
    if map.is_empty() {
        return to_unresolved_result(
            Rc::clone(&parent),
            format!(
                "No more entries for value at path = {} on type = {} ",
                parent.self_path(),
                parent.type_info()
            ),
            &query[query_index..],
        );
    }

    let mut resolved = Vec::with_capacity(map.values.len());

    for (key, each) in map.keys.iter().zip(map.values.values()) {
        let mut val_resolver = ValueScope {
            root: Rc::new(each.clone()),
            parent: resolver,
        };
        resolved.extend(func(
            query_index + 1,
            query,
            Rc::new(key.clone()),
            Rc::new(each.clone()),
            &mut val_resolver,
            converter,
        )?)
    }

    Ok(resolved)
}

fn to_unresolved_value(
    current: Rc<PathAwareValue>,
    reason: String,
    query: &[QueryPart<'_>],
) -> QueryResult {
    QueryResult::UnResolved(UnResolved {
        traversed_to: Rc::clone(&current),
        reason: Some(reason),
        remaining_query: format!("{}", SliceDisplay(query)),
    })
}

fn to_unresolved_result(
    current: Rc<PathAwareValue>,
    reason: String,
    query: &[QueryPart],
) -> Result<Vec<QueryResult>> {
    Ok(vec![to_unresolved_value(current, reason, query)])
}

fn map_resolved<F>(
    _current: &PathAwareValue,
    query_result: QueryResult,
    func: F,
) -> Result<Vec<QueryResult>>
where
    F: FnOnce(Rc<PathAwareValue>) -> Result<Vec<QueryResult>>,
{
    match query_result {
        QueryResult::Resolved(res) => func(res),
        rest => Ok(vec![rest]),
    }
}

/// Whether the filter at `index` can apply to `value`, an entry a wildcard has just expanded.
///
/// `[*]` and `.*` over a map hand each entry's *value* to the rest of the query, which is right when the
/// map is a collection -- `Resources.*[ Type == 'AWS::S3::Bucket' ]` tests each resource. It is wrong
/// when the map is a single object and the filter names the object's own fields: for
/// `{ Statement: { Effect: Allow, Action: "s3:*" } }`, `Statement[*][ Effect == 'Allow' ]` expanded the
/// object and tested `Effect == 'Allow'` against the strings "Allow" and "s3:*", matched neither, and
/// selected nothing. An assertion over that empty selection reported SKIP at exit 0 with the violation
/// unflagged, while `Statement.*[ ... ]` on the same input failed -- two spellings of one query
/// disagreeing, and the `[*]` one failing open.
///
/// Reported as unresolved rather than guessed at, for the same reason as the `Rules[0][ ... ]` arm below:
/// what `[*]` followed by a filter should *mean* on a single object is a language question, and an
/// unresolved result fails an assertion closed and names the query instead of settling it by accident.
///
/// Narrow on purpose. The scalar leg of the array-or-single leniency -- `Tags[*][ this == 'x' ]` against
/// `Tags: "x"` -- reaches the filter without going through an expansion at all, and still evaluates the
/// predicate against the scalar. That rule works today and keeps working; only an entry produced by
/// expanding a map is affected, which is the only case where the value under the filter is a field of
/// the thing the author was talking about rather than the thing itself.
fn filter_cannot_apply_to_expanded_entry(
    index: usize,
    query: &[QueryPart<'_>],
    value: &PathAwareValue,
) -> bool {
    matches!(query.get(index), Some(QueryPart::Filter(..)))
        && !matches!(value, PathAwareValue::Map(_) | PathAwareValue::List(_))
}

fn check_and_delegate<'value, 'loc: 'value>(
    conjunctions: &'value Conjunctions<GuardClause<'loc>>,
    name: &'value Option<String>,
) -> impl Fn(
    usize,
    &'value [QueryPart<'loc>],
    Rc<PathAwareValue>,
    Rc<PathAwareValue>,
    &mut dyn EvalContext<'value, 'loc>,
    Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<QueryResult>> {
    move |index, query, key, value, eval_context, converter| {
        let context = format!("Filter/Map#{}", conjunctions.len());
        eval_context.start_record(&context)?;
        match super::eval::eval_conjunction_clauses(
            conjunctions,
            eval_context,
            // Filter predicate: a selection test, not an assertion.
            |gc, r| super::eval::eval_guard_clause(gc, r, super::eval::ClauseRole::Gate),
        ) {
            // A predicate that could not be answered still errors the query, which is the one place
            // the error channel is kept deliberately rather than replaced by the lattice.
            //
            // Selecting nothing would be the alternative, and it is the wrong one here: a filter
            // that quietly drops the resources it could not judge selects fewer of them, and a rule
            // written to catch violations then catches fewer. That is the exact mechanism by which
            // an earlier attempt to fail closed inside a filter turned five registry security rules
            // from FAIL to PASS, so this site keeps the behaviour it has and says why.
            //
            // `Unevaluatable` cannot reach here through a decidable branch: `Outcome::or` absorbs
            // `Satisfied`, so a predicate with one answerable branch that holds is `Satisfied`.
            Ok(Outcome::Unevaluatable) => {
                eval_context.end_record(&context, RecordType::Filter(Status::FAIL))?;
                Err(Error::IncompatibleError(format!(
                    "Filter predicate could not be evaluated for value at {}",
                    value.self_path()
                )))
            }

            Ok(outcome) => {
                let status = outcome.to_status(ClauseRole::Gate);
                eval_context.end_record(&context, RecordType::Filter(status))?;
                let selected = !outcome.closes_gate();
                if let Some(key_name) = name {
                    if selected {
                        eval_context
                            .add_variable_capture_key(key_name.as_ref(), Rc::clone(&key))?;
                    }
                }
                match selected {
                    true => query_retrieval_with_converter(
                        index,
                        query,
                        Rc::clone(&value),
                        eval_context,
                        converter,
                    ),
                    false => Ok(vec![]),
                }
            }

            Err(e) => {
                eval_context.end_record(&context, RecordType::Filter(Status::FAIL))?;
                Err(e)
            }
        }
    }
}

type Converters = &'static [(fn(&str) -> bool, fn(&str) -> String)];

lazy_static! {
    /// Spellings of a key that name the same property, tried when the key is not in the data as
    /// written.
    ///
    /// Every entry is a case convention and nothing more, which is what makes the fallback safe: a
    /// query may say `bucket_encryption` for `BucketEncryption` because those are one property under
    /// two conventions. `cruet`'s "class case" is not one of these. It is Rails' class-name rule,
    /// PascalCase *and singular*, so `to_class_case("Tags")` is `Tag` -- a different property. It was
    /// in this list and answered `Properties.Tags.Name` out of `Properties.Tag` with a
    /// ComparisonError over `/Resources/BucketA/Properties/Tag/Name`, comparing a value the rule
    /// never named. Only one way round: a query for `Tag` against data holding `Tags` reported the
    /// missing property correctly, so the disagreement between the two directions was the tell.
    ///
    /// Its singularising is also not a plural rule. `to_class_case` strips the trailing s from
    /// `Status`, and gives `Analysi` for `Analysis` and `Metadatum` for `Metadata`.
    ///
    /// Dropping it loses no reach, because `to_pascal_case` is the same function without the
    /// singularising and is already here. Measured rather than assumed: across the 193 paired
    /// rule/test pairs in the AWS rule registry, class case won 57 lookups -- `!Ref`, `value`, `key`
    /// -- and pascal, title and train case each produced the identical string for every one of them.
    static ref CONVERTERS: Converters = &[
        (camel::is_camel_case, camel::to_camel_case),
        (kebab::is_kebab_case, kebab::to_kebab_case),
        (pascal::is_pascal_case, pascal::to_pascal_case),
        (snake::is_snake_case, snake::to_snake_case),
        (title::is_title_case, title::to_title_case),
        (train::is_train_case, train::to_train_case),
    ];
}

fn query_retrieval<'value, 'loc: 'value>(
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    current: Rc<PathAwareValue>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<QueryResult>> {
    query_retrieval_with_converter(query_index, query, current, resolver, None)
}

fn query_retrieval_with_converter<'value, 'loc: 'value>(
    query_index: usize,
    query: &'value [QueryPart<'loc>],
    current: Rc<PathAwareValue>,
    resolver: &mut dyn EvalContext<'value, 'loc>,
    converter: Option<&dyn Fn(&str) -> String>,
) -> Result<Vec<QueryResult>> {
    if query_index >= query.len() {
        return Ok(vec![QueryResult::Resolved(Rc::clone(&current))]);
    }

    if query_index == 0 && query[query_index].is_variable() {
        let retrieved = resolver.resolve_variable(query[query_index].variable().unwrap())?;
        let mut resolved = Vec::with_capacity(retrieved.len());
        for each in retrieved {
            match &each {
                QueryResult::UnResolved(ur) => {
                    resolved.push(QueryResult::UnResolved(ur.clone()));
                }
                QueryResult::Literal(value) | QueryResult::Resolved(value) => {
                    let index = if query_index + 1 < query.len() {
                        match &query[query_index + 1] {
                            QueryPart::AllIndices(_name) => query_index + 2,
                            _ => query_index + 1,
                        }
                    } else {
                        query_index + 1
                    };

                    if index < query.len() {
                        let mut scope = ValueScope {
                            root: Rc::clone(value),
                            parent: resolver,
                        };
                        resolved.extend(query_retrieval_with_converter(
                            index,
                            query,
                            Rc::clone(value),
                            &mut scope,
                            converter,
                        )?);
                    } else {
                        resolved.push(each)
                    }
                }
            }
        }
        return Ok(resolved);
    }

    match &query[query_index] {
        QueryPart::This => {
            query_retrieval_with_converter(query_index + 1, query, current, resolver, converter)
        }

        // `list_index_of`, not `key.parse()`: a key that reads as an integer is an index only when
        // the value at hand is a list. See that function for what naming one on a map used to do.
        QueryPart::Key(key) => match list_index_of(&current, key) {
            Some(idx) => match &*current {
                PathAwareValue::List((_, list)) => map_resolved(
                    &current,
                    retrieve_index(Rc::clone(&current), idx, list, query),
                    |val| {
                        query_retrieval_with_converter(
                            query_index + 1,
                            query,
                            val,
                            resolver,
                            converter,
                        )
                    },
                ),

                _ => to_unresolved_result(
                    Rc::clone(&current),
                    format!(
                        "Attempting to retrieve from index {} but type is not an array at path {}",
                        idx,
                        (*current).self_path()
                    ),
                    query,
                ),
            },

            None => {
                if let PathAwareValue::Map((path, map)) = &*current {
                    if query[query_index].is_variable() {
                        let var = query[query_index].variable().unwrap();
                        let keys = resolver.resolve_variable(var)?;
                        // `next_query_index` rather than `query_index + 1` at the recursions
                        // below, because the `Index` arm *consumes* the part after the variable:
                        // there it selects which resolved key to use, so the traversal has to
                        // resume after it.
                        //
                        // Advancing by one applied the index a second time, to the value the key
                        // had just selected. `Resources.%names[0].Type` picked `BucketA` and then
                        // tried to index into it, so the query resolved to nothing and every part
                        // after `[0]` was discarded -- silently, since an unresolved query is
                        // reported as a retrieval failure rather than as a malformed rule. The
                        // form without an index, `Resources.%names.Type`, always worked, which is
                        // why this survived. Pinned by
                        // `an_index_after_an_interpolated_key_is_not_applied_twice`.
                        let (keys, next_query_index) = if query.len() > query_index + 1 {
                            match &query[query_index+1] {
                                    QueryPart::AllIndices(_) | QueryPart::Key(_) => (keys, query_index + 1),
                                    QueryPart::Index(index) => {
                                        // Indexed over the keys the variable denotes, not over the
                                        // results it resolved to. The two differ whenever one result
                                        // holds a list, because the expansion of that list into one key
                                        // per element happens in the loop below -- after this point.
                                        //
                                        // So a variable bound to `Cfg.KeyList` had a length of one:
                                        // `[0]` selected the whole list and the loop then used *every*
                                        // key in it, and `[1]` was out of bounds. Over
                                        // `KeyList: [Name, Owner]` and `Tags: {Name: alpha, Owner: bob}`,
                                        // `some Cfg.Tags.%k[0] == "bob"` passed at exit 0 although the
                                        // 0th key is `Name` and names `alpha`. The index was inert
                                        // rather than off by one: the same rule with no index passed
                                        // too, and under either reading of `[N]` exactly one key must
                                        // come back where two came back.
                                        //
                                        // The element-bound spelling was always right --
                                        // `let k = Cfg.KeyList[*]` makes the projection produce one
                                        // result per key, so there was nothing left to flatten -- which
                                        // is why this survived: the two spellings look interchangeable
                                        // and only one of them was.
                                        //
                                        // See `index_offset` for why this is not arithmetic. It also
                                        // means a negative index counts back from the last key rather
                                        // than from the last result.
                                        let denoted = interpolated_keys(&keys);
                                        if let Some(check) = index_offset(*index, denoted.len()) {
                                            (vec![denoted[check].clone()], query_index + 2)
                                        } else {
                                            return to_unresolved_result(
                                                current,
                                                format!("Index {} on the set of values returned for variable {} on the join, is out of bounds. Length {}, Values = {:?}",
                                                        index, var, denoted.len(), denoted),
                                                &query[query_index..]
                                            )
                                        }
                                    },

                                    _ => return Err(Error::IncompatibleError(
                                        format!("This type of query {} based variable interpolation is not supported {}, {}",
                                                query[1], current.type_info(), SliceDisplay(query))))
                                }
                        } else {
                            (keys, query_index + 1)
                        };

                        let mut acc = Vec::with_capacity(keys.len());
                        for each_key in keys {
                            match each_key {
                                QueryResult::UnResolved(ur) => {
                                    acc.extend(
                                            to_unresolved_result(
                                                Rc::clone(&current),
                                                format!("Keys returned for variable {} could not completely resolve. Path traversed until {}{}",
                                                        var, ur.traversed_to.self_path(), ur.reason.map_or("".to_string(), |msg| msg)
                                                ),
                                                &query[query_index..]
                                            )?
                                        );
                                }
                                QueryResult::Resolved(key) | QueryResult::Literal(key) => {
                                    if let PathAwareValue::String((_, k)) = &*key {
                                        if let Some(next) = map.values.get(k) {
                                            acc.extend(query_retrieval_with_converter(
                                                next_query_index,
                                                query,
                                                Rc::new(next.clone()),
                                                resolver,
                                                converter,
                                            )?);
                                        } else {
                                            acc.extend(
                                                    to_unresolved_result(
                                                Rc::clone(&current),
                                                        format!("Could not locate key = {} inside struct at path = {}", k, path),
                                                        &query[query_index..]
                                                    )?
                                                );
                                        }
                                    } else if let PathAwareValue::List((_, inner)) = &*key {
                                        for each_key in inner {
                                            match &each_key {
                                                    PathAwareValue::String((path, key_to_match)) => {
                                                        if let Some(next) = map.values.get(key_to_match) {
                                                            acc.extend(query_retrieval_with_converter(next_query_index, query, Rc::new(next.clone()), resolver, converter)?);
                                                        } else {
                                                            acc.extend(
                                                                to_unresolved_result(
                                                                Rc::clone(&current),
                                                                    format!("Could not locate key = {} inside struct at path = {}", key_to_match, path),
                                                                    &query[query_index..]
                                                                )?
                                                            );
                                                        }
                                                    },

                                                    _rest => {
                                                        return Err(Error
                                                            ::NotComparable(
                                                                format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                                        SliceDisplay(query),
                                                                        key.type_info(),
                                                                        key.self_value()
                                                                )

                                                        ))
                                                    }
                                                }
                                        }
                                    } else {
                                        return Err(Error
                                               ::NotComparable(
                                                    format!("Variable projections inside Query {}, is returning a non-string value for key {}, {:?}",
                                                            SliceDisplay(query),
                                                            key.type_info(),
                                                            key.self_value()
                                                    )

                                            ));
                                    }
                                }
                            }
                        }
                        Ok(acc)
                    } else {
                        match map.values.get(key) {
                            Some(val) => {
                                return query_retrieval_with_converter(
                                    query_index + 1,
                                    query,
                                    Rc::new(val.clone()),
                                    resolver,
                                    converter,
                                )
                            }

                            None => match converter {
                                Some(func) => {
                                    let converted = func(key.as_str());
                                    if let Some(val) = map.values.get(&converted) {
                                        return query_retrieval_with_converter(
                                            query_index + 1,
                                            query,
                                            Rc::new(val.clone()),
                                            resolver,
                                            converter,
                                        );
                                    }
                                }

                                None => {
                                    for (_, each_converter) in CONVERTERS.iter() {
                                        if let Some(val) =
                                            map.values.get(&each_converter(key.as_str()))
                                        {
                                            return query_retrieval_with_converter(
                                                query_index + 1,
                                                query,
                                                Rc::new(val.clone()),
                                                resolver,
                                                Some(each_converter),
                                            );
                                        }
                                    }
                                }
                            },
                        }

                        to_unresolved_result(
                            Rc::clone(&current),
                            format!("Could not find key {} inside struct at path {}", key, path),
                            &query[query_index..],
                        )
                    }
                } else {
                    to_unresolved_result(
                            Rc::clone(&current),
                            format!("Attempting to retrieve from key {} but type is not an struct type at path {}, Type = {}, Value = {:?}",
                                    key, current.self_path(), current.type_info(), current),
                            &query[query_index..])
                }
            }
        },

        QueryPart::Index(index) => match &*current {
            PathAwareValue::List((_, list)) => map_resolved(
                &current,
                retrieve_index(Rc::clone(&current), *index, list, query),
                |val| {
                    query_retrieval_with_converter(query_index + 1, query, val, resolver, converter)
                },
            ),

            _ => to_unresolved_result(
                Rc::clone(&current),
                format!(
                    "Attempting to retrieve from index {} but type is not an array at path {}, \
                    type {}",
                    index,
                    current.self_path(),
                    current.type_info()
                ),
                &query[query_index..],
            ),
        },

        QueryPart::AllIndices(name) => {
            match &*current {
                PathAwareValue::List((_, elements)) => accumulate(
                    Rc::clone(&current),
                    query_index,
                    query,
                    elements,
                    resolver,
                    converter,
                ),

                PathAwareValue::Map((_, map)) => {
                    // `[*]` on a map is a pass-through by design, not an oversight: a schema field that
                    // accepts "an array or a single value" is written once as `Statement[*].Action`, and
                    // handing the map onward is what makes that resolve when `Statement` is one object
                    // rather than a list. `test_field_type_array_or_single` pins it, and IAM policies are
                    // exactly that shape.
                    //
                    // A *filter* next is the one case where pass-through cannot be what was meant. The
                    // predicate would be tested once against the whole map, match nothing, and select
                    // nothing -- so `Resources[*][ Type == 'AWS::S3::Bucket' ]` selected no resources,
                    // and an assertion over that empty selection reported SKIP with the violation
                    // unflagged, while `Resources.*[ ... ]` was right. The leniency never has a filter
                    // next; it has a key or another wildcard.
                    // `Filter` only. A key filter must NOT be included: its subject is the map whose
                    // keys are being matched, so handing that map through is exactly right, and routing
                    // it into `accumulate_map` moves the subject down a level -- onto each entry's own
                    // keys instead of the logical ids. Including it turned
                    // `Resources[*][ keys == /^Bucket/ ] !empty` from a pass into a false failure, and
                    // the assertion form from FAIL into SKIP: the same silent miss this arm exists to
                    // remove. The discriminator is `keys == /^Type$/`, which matches each resource's own
                    // key rather than its id, and which went the other way.
                    let filter_next =
                        matches!(query.get(query_index + 1), Some(QueryPart::Filter(..)));
                    if name.is_none() && !filter_next {
                        query_retrieval_with_converter(
                            query_index + 1,
                            query,
                            Rc::clone(&current),
                            resolver,
                            converter,
                        )
                    } else {
                        let name = name.as_ref().map(|n| n.as_str());
                        accumulate_map(
                            Rc::clone(&current),
                            map,
                            query_index,
                            query,
                            resolver,
                            converter,
                            |index, query, key, value, context, converter| {
                                if let Some(n) = name {
                                    context.add_variable_capture_key(n, Rc::clone(&key))?;
                                }
                                if filter_cannot_apply_to_expanded_entry(index, query, &value) {
                                    return to_unresolved_result(
                                        Rc::clone(&value),
                                        format!(
                                            "Filter on value type that was not a struct or array {} {}",
                                            value.type_info(),
                                            value.self_path()
                                        ),
                                        &query[index..],
                                    );
                                }
                                // A filter next is evaluated here, where the entry's key is still in
                                // hand, rather than in the filter arm one level down.
                                //
                                // By the time that arm sees an entry the wildcard has already expanded
                                // the map, so the key a capture would bind is gone and it called
                                // `check_and_delegate` with `&None`:
                                // `Resources[*][ nm | Type == 'AWS::S3::Bucket' ]` declared `nm` in a
                                // position the parser accepts and then could not resolve it, ending the
                                // run at exit 255 with no report. `Resources[ nm | ... ]` -- no wildcard,
                                // the filter straight after the key -- always worked, because
                                // `accumulate_map` hands this closure the key. Same call, same records,
                                // same continuation index; only the key and the name are no longer
                                // discarded.
                                //
                                // List elements keep the keyless path: `accumulate` has an index rather
                                // than a key, and a capture over one would bind nothing meaningful.
                                if let Some(QueryPart::Filter(filter_name, conjunctions)) =
                                    query.get(index)
                                {
                                    return check_and_delegate(conjunctions, filter_name)(
                                        index + 1,
                                        query,
                                        Rc::clone(&key),
                                        Rc::clone(&value),
                                        context,
                                        converter,
                                    );
                                }
                                query_retrieval_with_converter(
                                    index,
                                    query,
                                    Rc::clone(&value),
                                    context,
                                    converter,
                                )
                            },
                        )
                    }
                }

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => query_retrieval_with_converter(
                    query_index + 1,
                    query,
                    Rc::new(rest.clone()),
                    resolver,
                    converter,
                ),
            }
        }

        QueryPart::AllValues(name) => {
            match &*current {
                //
                // Supporting old format
                //
                PathAwareValue::List((_path, elements)) => accumulate(
                    Rc::clone(&current),
                    query_index,
                    query,
                    elements,
                    resolver,
                    converter,
                ),

                PathAwareValue::Map((_path, map)) => {
                    let (report, name) = match name {
                        Some(n) => (true, n.as_str()),
                        None => (false, ""),
                    };
                    accumulate_map(
                        Rc::clone(&current),
                        map,
                        query_index,
                        query,
                        resolver,
                        converter,
                        |index, query, key, value, context, converter| {
                            if report {
                                context.add_variable_capture_key(name, Rc::clone(&key))?;
                            }
                            if filter_cannot_apply_to_expanded_entry(index, query, &value) {
                                return to_unresolved_result(
                                    Rc::clone(&value),
                                    format!(
                                        "Filter on value type that was not a struct or array {} {}",
                                        value.type_info(),
                                        value.self_path()
                                    ),
                                    &query[index..],
                                );
                            }
                            // A filter next is evaluated here, where the entry's key is still in
                            // hand, rather than in the filter arm one level down.
                            //
                            // By the time that arm sees an entry the wildcard has already expanded
                            // the map, so the key a capture would bind is gone and it called
                            // `check_and_delegate` with `&None`:
                            // `Resources[*][ nm | Type == 'AWS::S3::Bucket' ]` declared `nm` in a
                            // position the parser accepts and then could not resolve it, ending the
                            // run at exit 255 with no report. `Resources[ nm | ... ]` -- no wildcard,
                            // the filter straight after the key -- always worked, because
                            // `accumulate_map` hands this closure the key. Same call, same records,
                            // same continuation index; only the key and the name are no longer
                            // discarded.
                            //
                            // List elements keep the keyless path: `accumulate` has an index rather
                            // than a key, and a capture over one would bind nothing meaningful.
                            if let Some(QueryPart::Filter(filter_name, conjunctions)) =
                                query.get(index)
                            {
                                return check_and_delegate(conjunctions, filter_name)(
                                    index + 1,
                                    query,
                                    Rc::clone(&key),
                                    Rc::clone(&value),
                                    context,
                                    converter,
                                );
                            }
                            query_retrieval_with_converter(
                                index,
                                query,
                                Rc::clone(&value),
                                context,
                                converter,
                            )
                        },
                    )
                }

                //
                // Often in the place where a list of values is accepted
                // single values often are accepted. So proceed to the next
                // part of your query
                //
                rest => query_retrieval_with_converter(
                    query_index + 1,
                    query,
                    Rc::new(rest.clone()),
                    resolver,
                    converter,
                ),
            }
        }

        QueryPart::Filter(name, conjunctions) => match &*current {
            PathAwareValue::Map((_path, map)) => match &query[query_index - 1] {
                QueryPart::AllValues(_name) | QueryPart::AllIndices(_name) => {
                    check_and_delegate(conjunctions, &None)(
                        query_index + 1,
                        query,
                        Rc::clone(&current),
                        Rc::clone(&current),
                        resolver,
                        converter,
                    )
                }

                QueryPart::Key(_) => {
                    if !map.is_empty() {
                        accumulate_map(
                            Rc::clone(&current),
                            map,
                            query_index,
                            query,
                            resolver,
                            converter,
                            check_and_delegate(conjunctions, name),
                        )
                    } else {
                        Ok(vec![])
                    }
                }

                // Not `unreachable!()`. `predicate_or_index` (parser.rs) lets an array index and a
                // filter sit adjacent, so `Rules[0][ Action == 'allow' ]` parses and arrives here
                // with `Index` as the preceding part -- as do `this` and a map-key filter. All three
                // took the process down at exit 101.
                //
                // Reported as unresolved rather than guessed at. What `[ ... ]` should mean when
                // applied to one already-indexed value is a language question: on a map the operator
                // filters the map's entries, which is not what an author writing `Rules[0][ ... ]`
                // means, and inventing an answer here would settle that question by accident. An
                // unresolved result fails an assertion closed and names the query.
                // An *undecidable* error, not an unresolved result, and the difference is the whole
                // point. An unresolved query means "the value is not there", which `!exists` and `empty`
                // answer with PASS -- so the first version of this fix failed an assertion closed only
                // when it was written positively. `Tags[0][ Key == 'Name' ] exists` failed, and
                // `... !exists` passed at exit 0 on a query the engine had explicitly refused to
                // evaluate.
                //
                // `IncompatibleError` is the branch's channel for "no answer either way": the clause
                // arm fails an assertion closed in both polarities and a gate keeps the error, so it
                // cannot be turned into a pass by negating it.
                rest => Err(Error::IncompatibleError(format!(
                    "Query {} applies a filter directly to {}, which is not supported at path {}",
                    SliceDisplay(&query[query_index..]),
                    match rest {
                        QueryPart::Index(_) => "an indexed value",
                        QueryPart::This => "`this`",
                        _ => "the result of a map key filter",
                    },
                    (*current).self_path(),
                ))),
            },

            PathAwareValue::List((_path, list)) => {
                let mut selected = Vec::with_capacity(list.len());
                for each in list {
                    let context = format!("Filter/List#{}", conjunctions.len());
                    resolver.start_record(&context)?;
                    let mut val_resolver = ValueScope {
                        root: Rc::new(each.clone()),
                        parent: resolver,
                    };
                    let result = match super::eval::eval_conjunction_clauses(
                        conjunctions,
                        &mut val_resolver,
                        // A filter predicate selects values; it is a test, not an
                        // assertion, so a predicate that does not hold selects nothing
                        // rather than failing the enclosing clause.
                        //
                        // A predicate that could not be *answered* is different, and this
                        // comment used to claim it selected nothing too. It errors, and
                        // deliberately: a filter that quietly drops the resources it could
                        // not judge selects fewer of them, and a rule written to catch
                        // violations then catches fewer.
                        |gc, r| {
                            super::eval::eval_guard_clause(gc, r, super::eval::ClauseRole::Gate)
                        },
                    ) {
                        Ok(Outcome::Unevaluatable) => {
                            resolver.end_record(&context, RecordType::Filter(Status::FAIL))?;
                            return Err(Error::IncompatibleError(format!(
                                "Filter predicate could not be evaluated for value at {}",
                                each.self_path()
                            )));
                        }

                        Ok(outcome) => {
                            resolver.end_record(
                                &context,
                                RecordType::Filter(outcome.to_status(ClauseRole::Gate)),
                            )?;
                            match outcome.closes_gate() {
                                false => query_retrieval_with_converter(
                                    query_index + 1,
                                    query,
                                    Rc::new(each.clone()),
                                    resolver,
                                    converter,
                                )?,
                                true => vec![],
                            }
                        }

                        Err(e) => {
                            resolver.end_record(&context, RecordType::Filter(Status::FAIL))?;
                            return Err(e);
                        }
                    };
                    selected.extend(result);
                }
                Ok(selected)
            }

            _ => {
                if let QueryPart::AllIndices(_) = &query[query_index - 1] {
                    let mut val_resolver = ValueScope {
                        root: Rc::clone(&current),
                        parent: resolver,
                    };
                    match super::eval::eval_conjunction_clauses(
                        conjunctions,
                        &mut val_resolver,
                        // A filter predicate selects values; it is a test, not an
                        // assertion, so a predicate that does not hold selects nothing
                        // rather than failing the enclosing clause.
                        //
                        // A predicate that could not be *answered* is different, and this
                        // comment used to claim it selected nothing too. It errors, and
                        // deliberately: a filter that quietly drops the resources it could
                        // not judge selects fewer of them, and a rule written to catch
                        // violations then catches fewer.
                        |gc, r| {
                            super::eval::eval_guard_clause(gc, r, super::eval::ClauseRole::Gate)
                        },
                    ) {
                        Ok(Outcome::Unevaluatable) => Err(Error::IncompatibleError(format!(
                            "Filter predicate could not be evaluated for value at {}",
                            current.self_path()
                        ))),
                        Ok(outcome) => match outcome.closes_gate() {
                            false => query_retrieval_with_converter(
                                query_index + 1,
                                query,
                                Rc::clone(&current),
                                resolver,
                                converter,
                            ),
                            true => Ok(vec![]),
                        },
                        Err(e) => Err(e),
                    }
                } else {
                    to_unresolved_result(
                        Rc::clone(&current),
                        format!(
                            "Filter on value type that was not a struct or array {} {}",
                            current.type_info(),
                            current.self_path()
                        ),
                        &query[query_index..],
                    )
                }
            }
        },

        QueryPart::MapKeyFilter(name, map_key_filter) => match &*current {
            PathAwareValue::Map((_path, map)) => {
                let mut selected = Vec::with_capacity(map.values.len());
                let rhs = match &map_key_filter.compare_with {
                    LetValue::AccessClause(acc_query) => query_retrieval_with_converter(
                        0,
                        &acc_query.query,
                        Rc::clone(&current),
                        resolver,
                        converter,
                    )?,

                    LetValue::Value(path_value) => {
                        vec![QueryResult::Literal(Rc::new(path_value.clone()))]
                    }

                    LetValue::FunctionCall(FunctionExpr {
                        parameters, name, ..
                    }) => resolve_function(name, parameters, resolver)?,
                };

                let lhs = map
                    .keys
                    .iter()
                    .cloned()
                    .map(Rc::new)
                    .map(QueryResult::Resolved)
                    .collect::<Vec<QueryResult>>();

                let results = super::eval::real_binary_operation(
                    &lhs,
                    &rhs,
                    map_key_filter.comparator,
                    "".to_string(),
                    None,
                    resolver,
                )?;

                let results = match results {
                    super::eval::EvaluationResult::QueryValueResult(r) => r,
                    _ => unreachable!(),
                };

                for each_result in results {
                    match each_result {
                        // Matches on Outcome now: the per-value vector carries why each
                        // value reached its answer, and a map-key filter selects on the
                        // ones that actually satisfied the predicate.
                        (QueryResult::Resolved(key), super::eval::Outcome::Satisfied) => {
                            if let PathAwareValue::String((_, key_name)) = &*key {
                                // The capture name was parsed and then dropped -- the arm bound it as
                                // `_name` and no call site ever saw it. `Resources[ mk | keys ==
                                // /^Bucket/ ]` therefore declared `mk` and left it unresolvable, and
                                // the run died at 255 saying "Could not resolve variable by name mk",
                                // which blames the wrong thing: the variable *was* declared.
                                //
                                // A key filter is the one filter shape where the key is what the
                                // predicate tested, so it is right here to capture.
                                if let Some(capture) = name {
                                    resolver.add_variable_capture_key(
                                        capture.as_str(),
                                        Rc::clone(&key),
                                    )?;
                                }
                                selected.push(QueryResult::Resolved(Rc::new(
                                    map.values.get(key_name.as_str()).unwrap().clone(),
                                )));
                            }
                        }

                        (QueryResult::UnResolved(ur), _) => {
                            selected.push(QueryResult::UnResolved(ur));
                        }

                        (_, _) => {
                            continue;
                        }
                    }
                }

                let mut extended = Vec::with_capacity(selected.len());
                for each in selected {
                    match each {
                        QueryResult::Literal(r) | QueryResult::Resolved(r) => {
                            extended.extend(query_retrieval_with_converter(
                                query_index + 1,
                                query,
                                r,
                                resolver,
                                converter,
                            )?);
                        }
                        QueryResult::UnResolved(ur) => {
                            extended.push(QueryResult::UnResolved(ur));
                        }
                    }
                }
                Ok(extended)
            }

            _ => to_unresolved_result(
                Rc::clone(&current),
                format!(
                    "Map Filter for keys was not a struct {} {}",
                    current.type_info(),
                    current.self_path()
                ),
                &query[query_index..],
            ),
        },
    }
}

pub(crate) fn root_scope<'value, 'loc: 'value>(
    rules_file: &'value RulesFile<'loc>,
    root: Rc<PathAwareValue>,
) -> RootScope<'value, 'loc> {
    let (literals, queries, function_expressions) = extract_variables(&rules_file.assignments);
    let mut lookup_cache = HashMap::with_capacity(rules_file.guard_rules.len());
    for rule in &rules_file.guard_rules {
        lookup_cache
            .entry(rule.rule_name.as_str())
            .or_insert(vec![])
            .push(rule);
    }

    let mut parameterized_rules = HashMap::with_capacity(rules_file.parameterized_rules.len());
    for pr in rules_file.parameterized_rules.iter() {
        parameterized_rules.insert(pr.rule.rule_name.as_str(), pr);
    }
    root_scope_with(
        literals,
        queries,
        lookup_cache,
        parameterized_rules,
        function_expressions,
        root,
    )
}

pub(crate) fn root_scope_with<'value, 'loc: 'value>(
    literals: HashMap<&'value str, Rc<PathAwareValue>>,
    queries: HashMap<&'value str, &'value AccessQuery<'loc>>,
    lookup_cache: HashMap<&'value str, Vec<&'value Rule<'loc>>>,
    parameterized_rules: HashMap<&'value str, &'value ParameterizedRule<'loc>>,
    function_expressions: HashMap<&'value str, &'value FunctionExpr<'loc>>,
    root: Rc<PathAwareValue>,
) -> RootScope<'value, 'loc> {
    let mut capture_sources: HashMap<&'value str, Vec<&'value str>> = HashMap::new();
    let mut record = |assignment: &'value str, declared: BTreeSet<&'value str>| {
        for capture in declared {
            capture_sources.entry(capture).or_default().push(assignment);
        }
    };
    for (assignment, query) in &queries {
        let mut declared = BTreeSet::new();
        collect_query_capture_names(&query.query, &mut declared);
        record(assignment, declared);
    }
    for (assignment, function) in &function_expressions {
        let mut declared = BTreeSet::new();
        for parameter in &function.parameters {
            collect_let_value_capture_names(parameter, &mut declared);
        }
        record(assignment, declared);
    }
    // Sorted, because the two maps above are hashed and the order a name's sources are resolved in is
    // the order its keys end up in. A report that lists them must not depend on the hash seed.
    for sources in capture_sources.values_mut() {
        sources.sort_unstable();
    }

    RootScope {
        scope: Scope {
            root,
            literals,
            variable_queries: queries,
            //resolved_variables: std::cell::RefCell::new(HashMap::new()),
            function_expressions,
            resolved_variables: HashMap::new(),
        },
        rules: lookup_cache,
        parameterized_rules,
        rules_status: HashMap::new(),
        recorder: RecordTracker {
            final_event: None,
            closed: 0,
            events: vec![],
        },
        diagnostics: BTreeSet::new(),
        served_from_cache: None,
        captured: HashMap::new(),
        merged: HashMap::new(),
        assignment_captures: HashMap::new(),
        capture_sources,
        resolving_assignments: BTreeSet::new(),
    }
}

pub(crate) fn block_scope<'value, 'block, 'loc: 'value, 'eval, T>(
    block: &'value Block<'loc, T>,
    root: Rc<PathAwareValue>,
    parent: &'eval mut dyn EvalContext<'value, 'loc>,
) -> BlockScope<'value, 'loc, 'eval>
where
    T: CaptureNames<'value>,
{
    let (literals, variable_queries, function_expressions) = extract_variables(&block.assignments);
    BlockScope {
        capture_names: block_capture_names(block),
        scope: Scope {
            literals,
            variable_queries,
            root,
            //resolved_variables: std::cell::RefCell::new(HashMap::new()),
            resolved_variables: HashMap::new(),
            function_expressions,
        },
        captured: HashMap::new(),
        merged: HashMap::new(),
        parent,
    }
}

pub(crate) struct RecordTracker<'value> {
    pub(crate) events: Vec<EventRecord<'value>>,
    pub(crate) final_event: Option<EventRecord<'value>>,
    /// How many records have been closed, counted only so one of them can be named. See
    /// [`RecordTracker::closed_records`].
    closed: usize,
}

impl<'value> RecordTracker<'value> {
    #[cfg(test)]
    pub(crate) fn new() -> RecordTracker<'value> {
        RecordTracker {
            events: vec![],
            final_event: None,
            closed: 0,
        }
    }
    pub(crate) fn extract(mut self) -> EventRecord<'value> {
        self.final_event.take().unwrap()
    }

    /// How many records have been closed so far.
    ///
    /// Monotonic and never reset, so it is an identity for "the record that closed most recently" rather
    /// than a count anyone reads as a quantity. `RootScope` pairs it with a reason served from the
    /// rule-status cache so that reason can only be read back against the one record it belongs to.
    ///
    /// Inherent rather than on [`RecordTracer`]: the only caller is `RootScope`, which holds the recorder
    /// directly, and no forwarding scope has a cache to pair it with.
    fn closed_records(&self) -> usize {
        self.closed
    }
}

/// The explanation a clause recorded, from anywhere under this record.
///
/// Depth-first and first-match, because the caller wants *a* reason and the shallowest one is the most
/// specific available: a condition that could not be evaluated has exactly one clause underneath it that
/// could not be evaluated.
///
/// Unary and binary comparisons only. Those are the two checks that carry the evaluator's own text for an
/// operation it could not perform; a missing property or a dependent rule records a different kind of
/// message, and one of those appearing here would mean the condition failed for a reason that is already
/// reported elsewhere.
fn recorded_clause_reason(record: &EventRecord<'_>) -> Option<String> {
    match &record.container {
        Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(unary))) => {
            if let Some(message) = &unary.value.message {
                return Some(message.clone());
            }
        }
        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(comparison))) => {
            if let Some(message) = &comparison.message {
                return Some(message.clone());
            }
        }
        _ => {}
    }

    record.children.iter().find_map(recorded_clause_reason)
}

/// The reason a comparison under this record could not compare its operands.
///
/// Depth-first and first-match like [`recorded_clause_reason`], and for the weaker reason: the caller
/// wants to know whether such a comparison is down there at all, and any of them answers that. A
/// condition with two of them is one malformed condition either way.
///
/// Filters are not descended into, and that boundary is the whole of what makes this answer about the
/// condition. A filter's comparisons decide *membership* in a selection, and guard's filter semantics
/// treat a candidate the comparator could not answer for as one that was not selected -- so the
/// selection still has a definite size and a condition reading that size was definitely answered.
/// Measured over aws-guard-rules-registry at 6aca96e: without the boundary, 39 of its 193 rule and test
/// pairs grew a note, every one of them for `Metadata.guard.SuppressedRules.* != "<RULE_NAME>"` or its
/// cfn_nag spelling inside the filter that resolves the rule's selection variable. The registry's own
/// suppression fixtures write a suppression as `- RULE_NAME: reason`, so that query resolves to a map
/// and the comparison against a string cannot be made -- which excludes the resource, which is exactly
/// what suppressing it should do. The rules' gates are `%selection !empty`, decidable and decided, and
/// telling their authors their conditions could not be answered would be false.
///
/// Skips a marked comparison that recorded no message and keeps looking, so the answer is always a
/// reason and never an empty one. One incomparable path does record nothing -- the query-against-query
/// arm of `each_lhs_compare` discards the comparator's text before building the record -- and giving it
/// a message would change the report, so a condition holding only that kind of comparison is not
/// described here rather than described badly.
fn recorded_incomparable_reason(record: &EventRecord<'_>) -> Option<String> {
    match &record.container {
        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(comparison))) => {
            if comparison.operands_not_comparable {
                if let Some(message) = &comparison.message {
                    return Some(message.clone());
                }
            }
        }
        Some(RecordType::Filter(_)) => return None,
        _ => {}
    }

    record
        .children
        .iter()
        .find_map(recorded_incomparable_reason)
}

impl<'value> RecordTracer<'value> for RecordTracker<'value> {
    /// The reason recorded under the record that was closed most recently.
    ///
    /// `end_record` pops the finished record and pushes it onto its parent's children, so immediately after
    /// closing one it is the last child of the record still open above it. That is the only moment this is
    /// meaningful.
    ///
    /// Ask it about one clause, not about a condition. `recorded_clause_reason` walks the whole subtree and
    /// returns the first explanation it finds, so asking it about a record with several clauses under it
    /// answers about whichever was written first. The fold in `conjunction_outcome` asks per branch, at the
    /// point that branch's own record closes, and carries the answer out on `ConditionOutcome`; `eval_rule`
    /// reads that instead, and reaches this only as a fallback for a condition that could not be evaluated
    /// with no branch having recorded why.
    ///
    /// This exists because `Outcome` cannot carry it. The parent branch reported *why* a condition could
    /// not be evaluated by interpolating the error into the rule's message, since the answer was the error.
    /// Here the answer is a value, `Outcome` is `Copy`, and giving the variant a payload would break `Copy`
    /// at forty-six sites and force `and` and `or` to choose between two reasons. The reason is already in
    /// the record; this reads it back rather than routing it a second time.
    fn reason_from_last_closed_record(&self) -> Option<String> {
        self.events
            .last()?
            .children
            .last()
            .and_then(recorded_clause_reason)
    }

    fn incomparable_reason_from_last_closed_record(&self) -> Option<String> {
        self.events
            .last()?
            .children
            .last()
            .and_then(recorded_incomparable_reason)
    }

    fn start_record(&mut self, context: &str) -> Result<()> {
        self.events.push(EventRecord {
            context: context.to_string(),
            container: None,
            children: vec![],
        });
        Ok(())
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        let matched = match self.events.pop() {
            Some(mut event) => {
                if event.context != context {
                    return Err(Error::IncompatibleError(format!(
                        "Event Record context start and end does not match {}",
                        context
                    )));
                }

                event.container = Some(record);
                event
            }

            None => {
                return Err(Error::IncompatibleError(format!(
                    "Event Record end with context {} did not have a corresponding start",
                    context
                )))
            }
        };

        self.closed += 1;

        match self.events.last_mut() {
            Some(parent) => {
                parent.children.push(matched);
            }

            None => {
                self.final_event.replace(matched);
            }
        }
        Ok(())
    }
}

impl<'value, 'loc: 'value> RootScope<'value, 'loc> {
    /// The notes collected while evaluating, in a stable order.
    ///
    /// Read by the commands after evaluation so the notes can be written to stderr, which keeps them
    /// out of the report on stdout that pipelines parse.
    pub(crate) fn diagnostics(&self) -> impl Iterator<Item = &String> {
        self.diagnostics.iter()
    }
}

impl<'value, 'loc: 'value> EvalContext<'value, 'loc> for RootScope<'value, 'loc> {
    fn record_diagnostic(&mut self, note: String) {
        self.diagnostics.insert(note);
    }

    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        let root = self.root();
        query_retrieval(0, query, root, self)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        match self.parameterized_rules.get(rule_name) {
            Some(r) => Ok(*r),
            _ => Err(Error::MissingValue(format!(
                "Parameterized Rule with name {} was not found, candidate {:?}",
                rule_name,
                self.parameterized_rules.keys()
            ))),
        }
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.scope.root)
    }

    #[allow(clippy::never_loop)]
    fn rule_status(
        &mut self,
        rule_name: &'value str,
        role: super::eval::ClauseRole,
    ) -> Result<Outcome> {
        // A reference answered from here evaluates nothing, so it records nothing, so the reason its
        // verdict needs is not in the tree. Hand it over beside the answer. Cleared on every call, hit
        // or miss, so the slot never holds anything older than the reference being answered now.
        self.served_from_cache = None;
        if let Some(answered) = self.rules_status.get(&(rule_name, role)) {
            if let (Outcome::Unevaluatable, Some(reason)) =
                (answered.outcome, &answered.undecidable_reason)
            {
                self.served_from_cache = Some((reason.clone(), self.recorder.closed_records()));
            }
            return Ok(answered.outcome);
        }

        let rule = match self.rules.get(rule_name) {
            Some(rule) => rule.clone(),
            None => {
                return Err(Error::MissingValue(format!(
                    "Rule {} by that name does not exist, Rule Names = {:?}",
                    rule_name,
                    self.rules.keys()
                )))
            }
        };

        let outcome = 'done: loop {
            for each_rule in rule {
                // The reference site's role is carried into the rule's own body rather
                // than being fixed at Assertion.
                //
                // This used to pass `ClauseRole::Assertion` unconditionally, which made
                // `ClauseRole` unable to cross the named-rule boundary: a `when` condition
                // referencing a rule whose body contains an unevaluatable clause got a FAIL
                // from that clause, the rule came back non-PASS, and `eval_rule` then
                // dropped every check in the guarded block while still exiting 0. Trading
                // one unenforced clause for a whole disarmed block is the same hazard
                // recorded on the `EmptyLhsCollection` arm in eval.rs, reached one level
                // further out.
                //
                // Propagating the role gives an unevaluatable clause inside the body the
                // strictness the *reference* deserves: a failure when the reference is an
                // assertion, inapplicable when it is a gate. That is exactly the
                // Unevaluatable split `Outcome::to_status` describes.
                // The cache stores a status, so the role is applied here. That is the same
                // answer the rule itself would give a caller in this role, and it keeps the
                // conversion at one place rather than at every reader of the cache.
                // The rule's own answer, kept as one. Converting here with `to_status(role)` is
                // what lost the distinction a gate needs: `Unevaluatable` became SKIP, and the
                // reference then read "did not apply" for a rule that could not be evaluated.
                let outcome = super::eval::eval_rule(each_rule, self, role)?;
                if !matches!(outcome, Outcome::NotApplicable) {
                    break 'done outcome;
                }
            }
            break Outcome::NotApplicable;
        };

        // Read here, at the one moment it is readable. `eval_rule` has just closed the rule's own
        // record, so it is the last child of the reference's record and the walk finds the clause that
        // could not be evaluated. Asking later, from a reference that hit the cache, finds nothing;
        // asking earlier is asking before the clause has recorded anything.
        let undecidable_reason = match outcome {
            Outcome::Unevaluatable => self.recorder.reason_from_last_closed_record(),
            _ => None,
        };

        // Keyed on `(rule, role)`, not the rule name. The same rule referenced from a body
        // and from a `when` condition are two different questions and must not share a
        // cache slot -- whichever reference ran first would otherwise decide the answer for
        // the other, making the outcome depend on evaluation order.
        //
        // The reason is keyed the same way for the same reason. A rule's condition is evaluated at
        // `ClauseRole::Gate` however the rule was reached -- `eval_when_clause` takes no role and
        // hardcodes it on every arm -- but its *body* is evaluated at the reference's role, and a rule
        // can answer `Unevaluatable` from its body. So the explanation is role-dependent even though the
        // condition's is not, and sharing one slot between the roles would quote the wrong one.
        self.rules_status.insert(
            (rule_name, role),
            CachedRuleAnswer {
                outcome,
                undecidable_reason,
            },
        );
        Ok(outcome)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        self.lookup(variable_name, MergedKeys::Visible, UnboundName::Error)
    }

    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        self.lookup(variable_name, MergedKeys::Hidden, unbound)
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        // Filed against the assignment being resolved when there is one. A capture reaching the root
        // scope otherwise came from a rule's `when` condition, which is evaluated here, and that one is
        // the rule's.
        let target = match self.resolving_assignments.is_empty() {
            true => &mut self.captured,
            false => &mut self.assignment_captures,
        };
        target
            .entry(variable_name)
            .or_default()
            .push(QueryResult::Resolved(Rc::clone(&key)));
        Ok(())
    }

    fn add_merged_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.merged
            .entry(variable_name)
            .or_default()
            .push(QueryResult::Resolved(Rc::clone(&key)));
        Ok(())
    }

    /// Forget every key captured by a filter.
    ///
    /// Overrides the trait's no-op, and it has to be here rather than on an inherent impl: the callers
    /// hold a `&mut dyn EvalContext`, so an inherent method of the same name is simply not the one that
    /// gets called. That mistake made the first version of this fix do nothing at all while compiling
    /// and reading correctly.
    ///
    /// `assignment_captures` is deliberately not cleared. Its keys belong to a file-level assignment
    /// whose result is memoised for the whole file, so clearing them here is what made a capture name
    /// resolve in the rule that first forced the assignment and nowhere else.
    fn reset_captures(&mut self) {
        self.captured.clear();
        self.merged.clear();
    }
}

#[derive(Eq, PartialEq, Debug, Clone, Serialize, Deserialize, Hash)]
#[serde(rename_all = "snake_case")]
pub(crate) enum FunctionName {
    Count,
    Join,
    JsonParse,
    Now,
    ParseBoolean,
    ParseChar,
    ParseEpoch,
    ParseFloat,
    ParseInt,
    ParseString,
    RegexReplace,
    Substring,
    ToLower,
    ToUpper,
    UrlDecode,
}

impl FunctionName {
    pub fn get_expected_number_of_args(&self) -> usize {
        match self {
            FunctionName::Join => 2,
            FunctionName::Substring | FunctionName::RegexReplace => 3,
            FunctionName::Count
            | FunctionName::JsonParse
            | FunctionName::ToUpper
            | FunctionName::ToLower
            | FunctionName::UrlDecode
            | FunctionName::ParseString
            | FunctionName::ParseBoolean
            | FunctionName::ParseFloat
            | FunctionName::ParseInt
            | FunctionName::ParseEpoch
            | FunctionName::ParseChar => 1,
            FunctionName::Now => 0,
        }
    }
}

impl std::fmt::Display for FunctionName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            FunctionName::Count => "count",
            FunctionName::Join => "join",
            FunctionName::JsonParse => "json_parse",
            FunctionName::Now => "now",
            FunctionName::ParseBoolean => "parse_boolean",
            FunctionName::ParseChar => "parse_char",
            FunctionName::ParseEpoch => "parse_epoch",
            FunctionName::ParseFloat => "parse_float",
            FunctionName::ParseInt => "parse_int",
            FunctionName::ParseString => "parse_string",
            FunctionName::RegexReplace => "regex_replace",
            FunctionName::Substring => "substring",
            FunctionName::ToLower => "to_lower",
            FunctionName::ToUpper => "to_upper",
            FunctionName::UrlDecode => "url_decode",
        };
        write!(f, "{}", name)
    }
}

impl TryFrom<&str> for FunctionName {
    type Error = Error;

    fn try_from(name: &str) -> std::result::Result<Self, Self::Error> {
        match name {
            "count" => Ok(FunctionName::Count),
            "join" => Ok(FunctionName::Join),
            "json_parse" => Ok(FunctionName::JsonParse),
            "now" => Ok(FunctionName::Now),
            "parse_boolean" => Ok(FunctionName::ParseBoolean),
            "parse_char" => Ok(FunctionName::ParseChar),
            "parse_epoch" => Ok(FunctionName::ParseEpoch),
            "parse_float" => Ok(FunctionName::ParseFloat),
            "parse_int" => Ok(FunctionName::ParseInt),
            "parse_string" => Ok(FunctionName::ParseString),
            "regex_replace" => Ok(FunctionName::RegexReplace),
            "substring" => Ok(FunctionName::Substring),
            "to_lower" => Ok(FunctionName::ToLower),
            "to_upper" => Ok(FunctionName::ToUpper),
            "url_decode" => Ok(FunctionName::UrlDecode),
            _ => Err(Error::ParseError(format!(
                "No function with the name '{name}' exists.",
            ))),
        }
    }
}

struct CountFunction;
struct JsonParseFunction;
struct RegexReplaceFunction;
struct SubstringFunction;
struct ToUpperFunction;
struct ToLowerFunction;
struct JoinFunction;
struct UrlDecodeFunction;
struct ParseIntFunction;
struct ParseFloatFunction;
struct ParseStringFunction;
struct ParseBooleanFunction;
struct ParseCharFunction;
struct ParseEpochFunction;
struct NowFunction;

trait Callable {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>>;
}

impl Callable for FunctionName {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        match self {
            FunctionName::Count => CountFunction.call(args),
            FunctionName::JsonParse => JsonParseFunction.call(args),
            FunctionName::RegexReplace => RegexReplaceFunction.call(args),
            FunctionName::Substring => SubstringFunction.call(args),
            FunctionName::ToUpper => ToUpperFunction.call(args),
            FunctionName::ToLower => ToLowerFunction.call(args),
            FunctionName::Join => JoinFunction.call(args),
            FunctionName::UrlDecode => UrlDecodeFunction.call(args),
            FunctionName::ParseInt => ParseIntFunction.call(args),
            FunctionName::ParseFloat => ParseFloatFunction.call(args),
            FunctionName::ParseString => ParseStringFunction.call(args),
            FunctionName::ParseBoolean => ParseBooleanFunction.call(args),
            FunctionName::ParseChar => ParseCharFunction.call(args),
            FunctionName::ParseEpoch => ParseEpochFunction.call(args),
            FunctionName::Now => NowFunction.call(args),
        }
    }
}

impl Callable for ParseEpochFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        parse_epoch(&args[0])
    }
}

impl Callable for NowFunction {
    fn call(&self, _args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        now()
    }
}

impl Callable for CountFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        Ok(vec![count(&args[0])])
    }
}

impl Callable for JsonParseFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        json_parse(&args[0])
    }
}

/// A scalar function argument the input could not supply is `IncompatibleError`, not `ParseError`.
///
/// `ParseError` is the class for a malformed rules file, and `is_unevaluatable` does not recognise it,
/// so it aborted the evaluation with "bailing" and the run exited 255. But these arguments are read from
/// the *data*: a template that puts `-1` in a field some rule feeds to `substring` is a policy problem,
/// and 255 says the tool broke. A run over such a template still reports every other rule's finding, so
/// the only thing wrong was the exit code -- which is what a CI wrapper reads to decide between blocking
/// a deploy and retrying a broken build. A template author could pick the second branch for their own
/// violation by choosing the right field value.
///
/// `converters.rs` documents this reclassification for the `parse_*` family and the reasoning behind it.
/// `substring`, `join` and `regex_replace` never got it, and `join` disagreed with itself: a delimiter of
/// the wrong type was `ParseError` at 255 while an element of the wrong type was already
/// `IncompatibleError` at 19 (`strings.rs`), both being data-driven type problems in the same call.
///
/// Not covered here: a pattern that is a string but does not compile still reports `RegexError` and exits
/// 255, and its message says "for rules file" even when the pattern came from the data.
fn incompatible_argument(message: String) -> Error {
    Error::IncompatibleError(message)
}

impl Callable for RegexReplaceFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        let substring_err_msg = |index| {
            let arg = match index {
                2 => "second",
                3 => "third",
                _ => unreachable!(),
            };

            format!("regex_replace function requires the {arg} argument to be a string")
        };

        let extracted_expr = match args[1].first() {
            Some(QueryResult::Resolved(r)) | Some(QueryResult::Literal(r)) => match &**r {
                PathAwareValue::String((_, s)) => s,
                _ => return Err(incompatible_argument(substring_err_msg(2))),
            },
            _ => return Err(incompatible_argument(substring_err_msg(2))),
        };

        let replaced_expr = match args[2].first() {
            Some(QueryResult::Resolved(r)) | Some(QueryResult::Literal(r)) => match &**r {
                PathAwareValue::String((_, s)) => s,
                _ => return Err(incompatible_argument(substring_err_msg(3))),
            },
            _ => return Err(incompatible_argument(substring_err_msg(3))),
        };

        regex_replace(&args[0], extracted_expr, replaced_expr)
    }
}

impl Callable for SubstringFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        let substring_err_msg = |index| {
            let arg = match index {
                2 => "second",
                3 => "third",
                _ => unreachable!(),
            };

            format!("substring function requires the {arg} argument to be a number")
        };

        // Rejected rather than narrowed. Both bounds went through `usize::from(n as u16)`, which
        // wraps: `substring(s, 65536, 65539)` became `substring(s, 0, 3)` and returned the first
        // three characters, reporting success for a rule that asked about something else entirely.
        // A negative bound wrapped the other way, so `substring(s, -1, 3)` also answered rather
        // than complaining. A bound that cannot be an offset is an error, not another offset.
        let offset = |index: usize, value: &PathAwareValue| -> Result<usize> {
            let n = match value {
                PathAwareValue::Int((_, n)) => *n,
                // A float bound truncates toward zero, which is what the previous cast did for the
                // values it did not mangle, so this keeps `substring(s, 1.9, 3)` reading from 1.
                PathAwareValue::Float((_, n)) if n.is_finite() => *n as i64,
                _ => return Err(incompatible_argument(substring_err_msg(index))),
            };
            usize::try_from(n).map_err(|_| {
                incompatible_argument(format!(
                    "substring function requires the {} argument to be an offset into the string, \
                     which {} is not",
                    match index {
                        2 => "second",
                        3 => "third",
                        _ => unreachable!(),
                    },
                    n
                ))
            })
        };

        let from = match args[1].first() {
            Some(QueryResult::Literal(r)) | Some(QueryResult::Resolved(r)) => offset(2, r)?,
            _ => return Err(incompatible_argument(substring_err_msg(2))),
        };

        let to = match args[2].first() {
            Some(QueryResult::Literal(r)) | Some(QueryResult::Resolved(r)) => offset(3, r)?,
            _ => return Err(incompatible_argument(substring_err_msg(3))),
        };

        substring(&args[0], from, to)
    }
}

impl Callable for ToUpperFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        to_upper(&args[0])
    }
}

impl Callable for ToLowerFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        to_lower(&args[0])
    }
}

impl Callable for JoinFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        let res =
            match args[1].first() {
                Some(QueryResult::Resolved(r)) | Some(QueryResult::Literal(r)) => match &**r {
                    PathAwareValue::String((_, s)) => join(&args[0], s),
                    PathAwareValue::Char((_, c)) => join(&args[0], &c.to_string()),
                    _ => return Err(incompatible_argument(String::from(
                        "join function requires the second argument to be either a char or string",
                    ))),
                },
                _ => {
                    return Err(incompatible_argument(String::from(
                        "join function requires the second argument to be either a char or string",
                    )))
                }
            }?;

        Ok(vec![Some(res)])
    }
}

impl Callable for UrlDecodeFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        url_decode(&args[0])
    }
}

impl Callable for ParseIntFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        parse_int(&args[0])
    }
}

impl Callable for ParseFloatFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        parse_float(&args[0])
    }
}

impl Callable for ParseStringFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        parse_str(&args[0])
    }
}

impl Callable for ParseBooleanFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        parse_bool(&args[0])
    }
}

impl Callable for ParseCharFunction {
    fn call(&self, args: &[Vec<QueryResult>]) -> Result<Vec<Option<PathAwareValue>>> {
        parse_char(&args[0])
    }
}

impl<'value, 'loc: 'value> RecordTracer<'value> for RootScope<'value, 'loc> {
    /// The recorded reason, falling back to the one the rule-status cache just served.
    ///
    /// A reference answered from that cache evaluated nothing and so recorded nothing, which left the
    /// walk with no clause to read and the verdict with no explanation -- while an identical reference
    /// earlier in the same run, the one that missed the cache and re-evaluated, was explained in full.
    ///
    /// Bounded to one record rather than taken on trust. A reference closes exactly one record after
    /// being answered from the cache, so the fallback applies only while the closed-record count is the
    /// one captured at that moment plus one -- which is the record the reason belongs to and no other.
    /// Without that bound this would be a second read by position, and reading a reason by position
    /// instead of by identity is the defect the commit before this one removed.
    ///
    /// Keyed on the count and not on the referenced rule's name, because a gate reference to a rule that
    /// could not be evaluated records a block check, and a block check does not carry one. That is the
    /// shape this case actually produces: `Unevaluatable.to_status(Gate)` is SKIP, and the SKIP arm of
    /// `eval_guard_named_clause` records `GuardClauseBlockCheck` so the reference contributes nothing to
    /// the failure report.
    fn reason_from_last_closed_record(&self) -> Option<String> {
        if let Some(reason) = self.recorder.reason_from_last_closed_record() {
            return Some(reason);
        }

        let (reason, closed_when_served) = self.served_from_cache.as_ref()?;
        (self.recorder.closed_records() == closed_when_served + 1).then(|| reason.clone())
    }

    fn incomparable_reason_from_last_closed_record(&self) -> Option<String> {
        self.recorder.incomparable_reason_from_last_closed_record()
    }

    fn start_record(&mut self, context: &str) -> Result<()> {
        self.recorder.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.recorder.end_record(context, record)
    }
}

impl<'value, 'loc: 'value, 'eval> EvalContext<'value, 'loc> for ValueScope<'value, 'eval, 'loc> {
    fn record_diagnostic(&mut self, note: String) {
        self.parent.record_diagnostic(note)
    }

    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        query_retrieval(0, query, self.root(), self.parent)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.root)
    }

    fn rule_status(
        &mut self,
        rule_name: &'value str,
        role: super::eval::ClauseRole,
    ) -> Result<Outcome> {
        self.parent.rule_status(rule_name, role)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        self.parent.resolve_variable(variable_name)
    }

    /// Forwarded rather than left to the trait's default, which would call this scope's
    /// `resolve_variable` and so ask the parent for the enclosing-level reading. A `ValueScope` sits
    /// between a block and the scope it defers to, and dropping the distinction here would put the
    /// merged union back in reach of every nested block and turn a capture that matched nothing into an
    /// error again.
    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        self.parent
            .resolve_variable_from_nested_block(variable_name, unbound)
    }

    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.parent.add_variable_capture_key(variable_name, key)
    }

    fn add_merged_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.parent.add_merged_capture_key(variable_name, key)
    }
}

impl<'value, 'loc: 'value, 'eval> RecordTracer<'value> for ValueScope<'value, 'eval, 'loc> {
    fn reason_from_last_closed_record(&self) -> Option<String> {
        self.parent.reason_from_last_closed_record()
    }

    fn incomparable_reason_from_last_closed_record(&self) -> Option<String> {
        self.parent.incomparable_reason_from_last_closed_record()
    }

    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }
}

impl<'value, 'loc: 'value, 'eval> EvalContext<'value, 'loc> for BlockScope<'value, 'loc, 'eval> {
    fn record_diagnostic(&mut self, note: String) {
        self.parent.record_diagnostic(note)
    }

    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>> {
        query_retrieval(0, query, self.root(), self)
    }

    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>> {
        self.parent.find_parameterized_rule(rule_name)
    }

    fn root(&mut self) -> Rc<PathAwareValue> {
        Rc::clone(&self.scope.root)
    }

    fn rule_status(
        &mut self,
        rule_name: &'value str,
        role: super::eval::ClauseRole,
    ) -> Result<Outcome> {
        self.parent.rule_status(rule_name, role)
    }

    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>> {
        self.lookup(variable_name, MergedKeys::Visible, UnboundName::Error)
    }

    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>> {
        self.lookup(variable_name, MergedKeys::Hidden, unbound)
    }

    /// Captured here rather than delegated to the parent, because this is the scope the capture
    /// belongs to.
    ///
    /// `RootScope`'s implementation appends and never resets, and both this scope and `ValueScope`
    /// used to hand captures up to it. So every key captured by a filter outlived the iteration that
    /// produced it and piled up in one list for the whole file -- and `resolve_variable` reads
    /// `resolved_variables` before `variable_queries`, so the grown list is what a later `%name` saw.
    ///
    /// That is a false PASS, not merely untidy. Over two buckets, one with an enabled config named
    /// `alpha` and one with only `beta`:
    ///
    /// ```text
    /// Resources.*[ Type == 'AWS::S3::Bucket' ] {
    ///     Properties.Config[ cfg | Enabled == true ] !empty
    ///     some %cfg == "alpha"
    /// }
    /// ```
    ///
    /// the second bucket saw `["alpha", "beta"]` and satisfied `some %cfg == "alpha"` on the strength
    /// of the first bucket's key. Adding a *compliant* resource made a non-compliant one pass, and
    /// the non-compliant bucket alone failed correctly -- which is the shape that makes this
    /// dangerous, because the rule looks like it works when tested on one resource at a time.
    ///
    /// A fresh `BlockScope` is built per iteration (`eval_guard_block_clause` loops the block's values
    /// and `eval_general_block_clause` builds a new scope for each), so storing the capture here gives
    /// it exactly the lifetime of the iteration that made it. `resolve_variable` already looks in this
    /// scope before asking the parent, so nothing else has to change.
    ///
    /// `ValueScope` still delegates, and must: it carries no scope of its own, so a capture made under
    /// one lands in the nearest enclosing block, which is the iteration boundary that matters.
    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.captured
            .entry(variable_name)
            .or_default()
            .push(QueryResult::Resolved(Rc::clone(&key)));
        Ok(())
    }

    fn add_merged_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.merged
            .entry(variable_name)
            .or_default()
            .push(QueryResult::Resolved(Rc::clone(&key)));
        Ok(())
    }
}

impl<'value, 'loc: 'value, 'eval> RecordTracer<'value> for BlockScope<'value, 'loc, 'eval> {
    fn reason_from_last_closed_record(&self) -> Option<String> {
        self.parent.reason_from_last_closed_record()
    }

    fn incomparable_reason_from_last_closed_record(&self) -> Option<String> {
        self.parent.incomparable_reason_from_last_closed_record()
    }

    fn start_record(&mut self, context: &str) -> Result<()> {
        self.parent.start_record(context)
    }

    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()> {
        self.parent.end_record(context, record)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub(crate) struct Messages {
    pub(crate) custom_message: Option<String>,
    pub(crate) error_message: Option<String>,
    #[serde(skip_serializing)]
    pub(crate) location: Option<Location>,
}

/// The explanation for a rule that did not apply, if the evaluator recorded one.
///
/// A skipped rule reaches the reporters as a name and nothing else, which is why explanations
/// written onto skip records used to be constructed and discarded -- the same defect that had five
/// message-bearing record variants rendering nothing. Walking the rule's own subtree is what makes
/// the message reachable, so a message may now be added to any of the block-shaped records below
/// and it will surface.
///
/// The first explanation found wins rather than all of them being concatenated. A rule that skips
/// usually skips for one reason, and a reporter line that grows without bound with nesting depth is
/// worse than a slightly incomplete one.
///
/// Children are searched before the record's own message, because the deeper message is the more
/// specific one. Taking `own` first made the specific messages unreachable in the case that
/// motivated them: a type block always attaches a summary to its own SKIP ("every X was exempted by
/// the `when` condition"), so the recursion never ran and the undecidable-comparison explanation
/// underneath it -- the one naming `Size: "50"` as a string that cannot be compared against an
/// integer -- was built, recorded, and never read. Pinned by
/// `a_specific_skip_reason_is_not_shadowed_by_the_block_summary`.
pub(crate) fn find_skip_reason(record: &EventRecord<'_>) -> Option<String> {
    record
        .children
        .iter()
        .find_map(find_skip_reason)
        .or_else(|| own_skip_reason(record))
}

/// The explanation this record carries itself, ignoring its children.
///
/// Split out of [`find_skip_reason`] so the recursion order is one readable expression, and so the
/// block-shaped variants share a single body -- they did not, and `clippy::collapsible_match` failed
/// the `cargo clippy -- -D warnings` gate on the duplicate.
fn own_skip_reason(record: &EventRecord<'_>) -> Option<String> {
    match &record.container {
        Some(RecordType::TypeCheck(TypeBlockCheck { block, .. }))
        | Some(RecordType::GuardClauseBlockCheck(block))
        | Some(RecordType::WhenCheck(block))
        | Some(RecordType::BlockGuardCheck(block))
        | Some(RecordType::Disjunction(block)) => match block {
            BlockCheck {
                status: Status::SKIP,
                message,
                ..
            } => message.clone(),
            _ => None,
        },

        // A clause that failed *and* explained itself, reached while walking a rule that skipped.
        //
        // Only two things record an explanation on a comparison: a reference that resolved to no
        // values, and operands that cannot be compared. Both mean the clause could not be decided,
        // as opposed to being decided false -- the ordinary failure arm records `message: None`. So
        // finding one here says the rule did not apply because a condition was undecidable, which
        // is a different situation from a condition that was simply not met, and the only one worth
        // interrupting an operator over.
        //
        // This is the quietest wrong answer left in the evaluator. `when ... Size > 10` against a
        // template carrying `Size: "50"` -- a string, which CloudFormation templates produce
        // routinely -- cannot be decided, so the condition does not pass, so the rule is reported
        // as not applicable and its body never runs. Exit 0, nothing named. The rule still does not
        // enforce, and it cannot be made to from here: both FAIL and SKIP on a condition drop the
        // block it guards, so telling them apart needs a status that means "could not tell", which
        // `Status` does not have. Saying so is what is available, and it turns a silent non-check
        // into a visible one.
        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(ComparisonClauseCheck {
            status: Status::FAIL,
            message: Some(explanation),
            ..
        }))) => Some(format!(
            "the rule did not apply because one of its conditions could not be decided: {}",
            explanation
        )),

        _ => None,
    }
}

pub(crate) type Metadata = HashMap<String, String>;

/// A rules file the parser rejected, named so a machine-readable report can say a policy could not
/// be read.
///
/// A file that fails to parse contributes no rules, so it puts nothing in `not_compliant`,
/// `not_applicable` or `compliant` -- and those three lists are empty on a clean run too. Without
/// this the two are the same document, and the exit code is the only thing that tells them apart.
///
/// Deliberately not one of the three verdict lists and not a `status`: a rules file that failed to
/// parse is not a rule that skipped, and filing it as one is the confusion this exists to end.
#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct RuleFileError {
    pub(crate) file_name: String,
    pub(crate) error: String,
}

#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct FileReport<'value> {
    pub(crate) name: &'value str,
    pub(crate) metadata: Metadata,
    pub(crate) status: Status,
    #[serde(with = "serde_yaml::with::singleton_map_recursive")]
    pub(crate) not_compliant: Vec<ClauseReport<'value>>,
    pub(crate) not_applicable: BTreeSet<String>,
    /// Why each inapplicable rule did not apply, for the ones where the evaluator knows something
    /// a bare "not applicable" does not convey. Omitted when empty, so a run with nothing to
    /// explain serialises to exactly the document consumers parse today.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub(crate) not_applicable_reasons: BTreeMap<String, String>,
    pub(crate) compliant: BTreeSet<String>,
    /// Rules files that could not be read at all. See [`RuleFileError`]. Omitted when empty, for
    /// the same reason `not_applicable_reasons` is: a run whose rules all parsed serialises to
    /// exactly the document consumers parse today.
    ///
    /// Repeated in every record rather than hoisted above them, because the document is an array of
    /// these and there is nowhere above them to put it. The statement is true per data file anyway:
    /// this file went unchecked by those rules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) rule_file_errors: Vec<RuleFileError>,
}

impl<'value> FileReport<'value> {
    pub(crate) fn combine(&mut self, report: FileReport<'value>) {
        if report.name != self.name {
            panic!("Incompatible to merge")
        }
        self.status = self.status.and(report.status);
        self.metadata.extend(report.metadata);
        self.not_compliant.extend(report.not_compliant);
        self.compliant.extend(report.compliant);
        self.not_applicable.extend(report.not_applicable);
        self.not_applicable_reasons
            .extend(report.not_applicable_reasons);
        self.rule_file_errors.extend(report.rule_file_errors);
    }
}

#[derive(Clone, Debug, Serialize, Default)]
pub(crate) struct RuleReport<'value> {
    pub(crate) name: &'value str,
    pub(crate) metadata: Metadata,
    pub(crate) messages: Messages,
    pub(crate) checks: Vec<ClauseReport<'value>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryComparison {
    pub(crate) value: Rc<PathAwareValue>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ValueUnResolved {
    pub(crate) value: UnResolved,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum UnaryCheck {
    UnResolved(ValueUnResolved),
    Resolved(UnaryComparison),
    UnResolvedContext(String),
}

impl ValueComparisons for UnaryCheck {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            UnaryCheck::UnResolved(ur) => Some(ur.value.traversed_to.clone()),
            UnaryCheck::Resolved(uc) => Some(uc.value.clone()),
            UnaryCheck::UnResolvedContext(_) => None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct UnaryReport {
    pub(crate) check: UnaryCheck,
    pub(crate) context: String,
    pub(crate) messages: Messages,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BinaryComparison {
    pub(crate) from: Rc<PathAwareValue>,
    pub(crate) to: Rc<PathAwareValue>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct InComparison {
    pub(crate) from: Rc<PathAwareValue>,
    pub(crate) to: Vec<Rc<PathAwareValue>>,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum BinaryCheck {
    UnResolved(ValueUnResolved),
    Resolved(BinaryComparison),
    InResolved(InComparison),
}

impl ValueComparisons for BinaryCheck {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            BinaryCheck::UnResolved(vur) => Some(vur.value.traversed_to.clone()),
            BinaryCheck::Resolved(res) => Some(res.from.clone()),
            BinaryCheck::InResolved(inr) => Some(inr.from.clone()),
        }
    }

    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            BinaryCheck::Resolved(bc) => Some(bc.to.clone()),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct BinaryReport {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) check: BinaryCheck,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum GuardClauseReport {
    Unary(UnaryReport),
    Binary(BinaryReport),
}

impl GuardClauseReport {
    fn get_message(&self) -> Messages {
        match self {
            GuardClauseReport::Unary(unary_report) => unary_report.messages.clone(),
            GuardClauseReport::Binary(binary_report) => binary_report.messages.clone(),
        }
    }
}

pub(crate) trait ValueComparisons {
    fn value_from(&self) -> Option<Rc<PathAwareValue>>;
    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        None
    }
}

impl ValueComparisons for GuardClauseReport {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            GuardClauseReport::Binary(br) => br.check.value_from(),
            GuardClauseReport::Unary(ur) => ur.check.value_from(),
        }
    }

    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            GuardClauseReport::Binary(br) => br.check.value_to(),
            GuardClauseReport::Unary(ur) => ur.check.value_to(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct DisjunctionsReport<'value> {
    pub(crate) checks: Vec<ClauseReport<'value>>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct GuardBlockReport {
    pub(crate) context: String,
    pub(crate) messages: Messages,
    pub(crate) unresolved: Option<UnResolved>,
}

impl ValueComparisons for GuardBlockReport {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        if let Some(ur) = &self.unresolved {
            return Some(ur.traversed_to.clone());
        }
        None
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) enum ClauseReport<'value> {
    Rule(RuleReport<'value>),
    Block(GuardBlockReport),
    Disjunctions(DisjunctionsReport<'value>),
    Clause(GuardClauseReport),
}

impl<'value> ClauseReport<'value> {
    pub(crate) fn key(&self, parent: &str) -> String {
        match self {
            Self::Rule(RuleReport { name, .. }) => format!("{}/{}", parent, name),
            Self::Block(_) => format!("{}/B[{:p}]", parent, self),
            Self::Disjunctions(_) => format!("{}/Or[{:p}]", parent, self),
            Self::Clause(_) => format!("{}/C[{:p}]", parent, self),
        }
    }

    pub fn get_message(&self) -> Vec<Messages> {
        match self {
            ClauseReport::Rule(rule) => rule.checks.iter().fold(vec![], |mut messages, report| {
                messages.append(&mut report.get_message());
                messages
            }),
            ClauseReport::Block(block) => vec![block.messages.clone()],
            ClauseReport::Disjunctions(disjunctions) => {
                disjunctions
                    .checks
                    .iter()
                    .fold(vec![], |mut messages, report| {
                        messages.append(&mut report.get_message());
                        messages
                    })
            }
            ClauseReport::Clause(clause) => vec![clause.get_message()],
        }
    }
}

impl<'value> ValueComparisons for ClauseReport<'value> {
    fn value_from(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            Self::Block(b) => b.value_from(),
            Self::Clause(c) => c.value_from(),
            _ => None,
        }
    }

    fn value_to(&self) -> Option<Rc<PathAwareValue>> {
        match self {
            Self::Block(b) => b.value_to(),
            Self::Clause(c) => c.value_to(),
            _ => None,
        }
    }
}

pub(crate) fn cmp_str(cmp: (CmpOperator, bool)) -> &'static str {
    let (cmp, not) = cmp;
    if cmp.is_unary() {
        match cmp {
            CmpOperator::Exists => {
                if not {
                    "NOT EXISTS"
                } else {
                    "EXISTS"
                }
            }
            CmpOperator::Empty => {
                if not {
                    "NOT EMPTY"
                } else {
                    "EMPTY"
                }
            }
            CmpOperator::IsList => {
                if not {
                    "NOT LIST"
                } else {
                    "IS LIST"
                }
            }
            CmpOperator::IsMap => {
                if not {
                    "NOT STRUCT"
                } else {
                    "IS STRUCT"
                }
            }
            CmpOperator::IsString => {
                if not {
                    "NOT STRING"
                } else {
                    "IS STRING"
                }
            }
            CmpOperator::IsFloat => {
                if not {
                    "NOT FLOAT"
                } else {
                    "IS FLOAT"
                }
            }
            CmpOperator::IsNull => {
                if not {
                    "NOT NULL"
                } else {
                    "IS NULL"
                }
            }
            CmpOperator::IsBool => {
                if not {
                    "NOT BOOL"
                } else {
                    "IS BOOl"
                }
            }
            CmpOperator::IsInt => {
                if not {
                    "NOT INT"
                } else {
                    "IS INT"
                }
            }
            _ => unreachable!(),
        }
    } else {
        match cmp {
            CmpOperator::Eq => {
                if not {
                    "NOT EQUAL"
                } else {
                    "EQUAL"
                }
            }
            CmpOperator::Le => {
                if not {
                    "NOT LESS THAN EQUAL"
                } else {
                    "LESS THAN EQUAL"
                }
            }
            CmpOperator::Lt => {
                if not {
                    "NOT LESS THAN"
                } else {
                    "LESS THAN"
                }
            }
            CmpOperator::Ge => {
                if not {
                    "NOT GREATER THAN EQUAL"
                } else {
                    "GREATER THAN EQUAL"
                }
            }
            CmpOperator::Gt => {
                if not {
                    "NOT GREATER THAN"
                } else {
                    "GREATER THAN"
                }
            }
            CmpOperator::In => {
                if not {
                    "NOT IN"
                } else {
                    "IN"
                }
            }
            _ => unreachable!(),
        }
    }
}

fn report_all_failed_clauses_for_rules<'value>(
    checks: &[EventRecord<'value>],
) -> Vec<ClauseReport<'value>> {
    let mut clauses = Vec::with_capacity(checks.len());
    for current in checks {
        match &current.container {
            Some(RecordType::RuleCheck(NamedStatus {
                name,
                status: Status::FAIL,
                message,
            })) => {
                clauses.push(ClauseReport::Rule(RuleReport {
                    name,
                    checks: report_all_failed_clauses_for_rules(&current.children),
                    messages: Messages {
                        custom_message: message.clone(),
                        error_message: None,
                        location: None,
                    },
                    ..Default::default()
                }));
            }

            Some(RecordType::BlockGuardCheck(BlockCheck {
                status: Status::FAIL,
                message,
                ..
            })) => {
                if current.children.is_empty() {
                    clauses.push(ClauseReport::Block(GuardBlockReport {
                        context: current.context.clone(),
                        messages: Messages {
                            // The record's own explanation when it carries one. This arm used to
                            // hardcode the generic sentence below and ignore `message` entirely,
                            // so a block that had said precisely why it failed was reported as
                            // though it had merely selected nothing.
                            error_message: Some(message.clone().unwrap_or_else(|| {
                                String::from("query for block clause did not retrieve any value")
                            })),
                            custom_message: None,
                            location: None,
                        },
                        unresolved: None,
                    }));
                } else {
                    clauses.extend(report_all_failed_clauses_for_rules(&current.children));
                }
            }

            // A disjunction records a message only on the error path in `eval_conjunction_clauses`,
            // where it bails before any disjunct produced a child record. Reported as a block
            // rather than as an empty `Disjunctions`, for the same reason as the arms below: an
            // empty list of checks tells the reader nothing, and the message is the only account of
            // what went wrong.
            Some(RecordType::Disjunction(BlockCheck {
                status: Status::FAIL,
                message,
                ..
            })) => {
                let nested = report_all_failed_clauses_for_rules(&current.children);
                if nested.is_empty() {
                    if let Some(explanation) = message {
                        clauses.push(ClauseReport::Block(GuardBlockReport {
                            context: current.context.clone(),
                            messages: Messages {
                                error_message: Some(explanation.clone()),
                                custom_message: None,
                                location: None,
                            },
                            unresolved: None,
                        }));
                    }
                    continue;
                }
                clauses.push(ClauseReport::Disjunctions(DisjunctionsReport {
                    checks: nested,
                }));
            }

            // These four recurse into their children for the per-value detail. Each can also carry
            // a message of its own, and that message used to be discarded: the arm matched with
            // `..`, ignoring the field, and reported whatever the children produced.
            //
            // Nothing is what the children produce when the clause failed *because* there was
            // nothing to compare. An empty-reference comparison records its explanation here and
            // has no per-value results by construction, so the report came back empty, the console
            // printed "Number of non-compliant resources 0", and the structured output carried
            // "checks": [] with a null error_message -- for a run that had correctly exited 19.
            //
            // So: recurse when the children have something to say, and fall back to this record's
            // own message when they do not. A failing clause now always explains itself somewhere.
            Some(RecordType::GuardClauseBlockCheck(BlockCheck {
                status: Status::FAIL,
                message,
                ..
            }))
            | Some(RecordType::TypeCheck(TypeBlockCheck {
                block:
                    BlockCheck {
                        status: Status::FAIL,
                        message,
                        ..
                    },
                ..
            }))
            | Some(RecordType::WhenCheck(BlockCheck {
                status: Status::FAIL,
                message,
                ..
            })) => {
                let nested = report_all_failed_clauses_for_rules(&current.children);
                if nested.is_empty() {
                    if let Some(explanation) = message {
                        clauses.push(ClauseReport::Block(GuardBlockReport {
                            context: current.context.clone(),
                            messages: Messages {
                                error_message: Some(explanation.clone()),
                                custom_message: None,
                                location: None,
                            },
                            unresolved: None,
                        }));
                    }
                } else {
                    clauses.extend(nested);
                }
            }

            // TypeBlock carries a bare Status with no message, so there is nothing to fall back to.
            Some(RecordType::TypeBlock(Status::FAIL)) => {
                clauses.extend(report_all_failed_clauses_for_rules(&current.children));
            }

            Some(RecordType::ClauseValueCheck(clause)) => match clause {
                ClauseCheck::NoValueForEmptyCheck(msg) => {
                    let custom_message = msg
                        .as_ref()
                        .map_or("".to_string(), |s| s.replace('\n', ";"));

                    // Says what happened, which it did not. The text was hardcoded as "was not empty" and
                    // this check is reached from both polarities, so a `!EMPTY` clause that failed *because
                    // its selection was empty* reported that the selection was not empty -- the negation of
                    // the reason. Harmless while nothing printed it; the console reporter now does, and a
                    // section whose whole purpose is to say why must not ship the opposite of why.
                    //
                    // The clause selected nothing either way, so that is what the message says, and the
                    // operator it failed is already in the context beside it.
                    let error_message = format!(
                        "Check was not compliant as the query in context [{}] selected no values to test",
                        current.context
                    );
                    clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                        UnaryReport {
                            context: current.context.clone(),
                            check: UnaryCheck::UnResolvedContext(current.context.to_string()),
                            messages: Messages {
                                custom_message: Some(custom_message),
                                error_message: Some(error_message),
                                location: None,
                            },
                        },
                    )))
                }

                ClauseCheck::Success => {}

                ClauseCheck::DependentRule(missing) => {
                    let message = missing.custom_message.as_ref().map_or("", String::as_str);
                    let error_message = format!(
                            "Check was not compliant as dependent rule [{rule}] did not PASS. Context [{cxt}]",
                            rule=missing.rule,
                            cxt=current.context,
                        );
                    clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                        UnaryReport {
                            messages: Messages {
                                custom_message: Some(message.to_string()),
                                error_message: Some(error_message),
                                location: None,
                            },
                            context: current.context.clone(),
                            check: UnaryCheck::UnResolvedContext(missing.rule.to_string()),
                        },
                    )));
                }

                ClauseCheck::MissingBlockValue(missing) => {
                    let (property, far, ur) = match &missing.from {
                        QueryResult::UnResolved(ur) => {
                            (ur.remaining_query.as_str(), ur.traversed_to.clone(), ur)
                        }
                        _ => unreachable!(),
                    };
                    let message = missing.custom_message.as_ref().map_or("", String::as_str);
                    let error_message = format!(
                            "Check was not compliant as property [{}] is missing. Value traversed to [{}]",
                            property,
                            far
                        );
                    clauses.push(ClauseReport::Block(GuardBlockReport {
                        context: current.context.clone(),
                        messages: Messages {
                            custom_message: Some(message.to_string()),
                            error_message: Some(error_message),
                            location: None,
                        },
                        unresolved: Some(ur.clone()),
                    }));
                }

                ClauseCheck::Unary(UnaryValueCheck {
                    comparison: (cmp, not),
                    value:
                        ValueCheck {
                            status: Status::FAIL,
                            from,
                            message,
                            custom_message,
                        },
                }) => {
                    use CmpOperator::*;
                    let cmp_msg = match cmp {
                        Exists => {
                            if *not {
                                "existed"
                            } else {
                                "did not exist"
                            }
                        }
                        Empty => {
                            if *not {
                                "was empty"
                            } else {
                                "was not empty"
                            }
                        }
                        IsList => {
                            if *not {
                                "was a list "
                            } else {
                                "was not list"
                            }
                        }
                        IsMap => {
                            if *not {
                                "was a struct"
                            } else {
                                "was not struct"
                            }
                        }
                        IsString => {
                            if *not {
                                "was a string "
                            } else {
                                "was not string"
                            }
                        }
                        IsInt => {
                            if *not {
                                "was int"
                            } else {
                                "was not int"
                            }
                        }
                        IsBool => {
                            if *not {
                                "was bool"
                            } else {
                                "was not bool"
                            }
                        }
                        IsNull => {
                            if *not {
                                "was null"
                            } else {
                                "was not null"
                            }
                        }
                        _ => {
                            if *not {
                                "was float"
                            } else {
                                "was not float"
                            }
                        }
                    };

                    let custom_message = custom_message
                        .as_ref()
                        .map_or(String::default(), |s| s.to_string());

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!("Error = [{}]", s));

                    let (message, check) = match from {
                            // A literal reaches here through `let x = 5` followed by a unary check
                            // such as `%x empty`: the operator has no answer for a number, the
                            // clause fails, and this is the message that failure carries. It was
                            // `unreachable!()`, so building the report took the process down at exit
                            // 101 in all four output modes. String and list literals never reached
                            // it, because the operator answers those.
                            //
                            // Reported as a resolved value, which is what it is -- the two variants
                            // carry the same payload, and the only difference is that a literal's
                            // path is the unlocated root.
                            QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                                (
                                    format!(
                                        "Check was not compliant as property [{prop}] {cmp_msg}.{err}",
                                        prop=res.self_path(),
                                        cmp_msg=cmp_msg,
                                        err=error_message
                                    ),
                                    UnaryCheck::Resolved(UnaryComparison {
                                        comparison: (*cmp, *not),
                                        value: res.clone(),
                                    })
                                )

                            },

                            QueryResult::UnResolved(unres) => {
                                (
                                    format!(
                                        "Check was not compliant as property [{remain}] is missing. Value traversed to [{tr}].{err}",
                                        remain=unres.remaining_query,
                                        tr=unres.traversed_to,
                                        err=error_message
                                    ),
                                    UnaryCheck::UnResolved(ValueUnResolved{
                                        value: unres.clone(),
                                        comparison: (*cmp, *not),
                                    })
                                )
                            }
                        };

                    clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                        UnaryReport {
                            messages: Messages {
                                custom_message: Some(custom_message),
                                error_message: Some(message),
                                location: Some(
                                    from.unresolved_traversed_to()
                                        .map_or(Location::default(), |val| val.self_path().1),
                                ),
                            },
                            context: current.context.clone(),
                            check,
                        },
                    )));
                }

                ClauseCheck::Comparison(ComparisonClauseCheck {
                    custom_message,
                    message,
                    comparison: (cmp, not),
                    from,
                    status: Status::FAIL,
                    to,
                    // Not rendered here either, for the reason recorded at the console reporter's
                    // matching arm.
                    ..
                }) => {
                    let custom_message = custom_message
                        .as_ref()
                        .map_or(String::default(), |s| s.to_string());

                    let error_message = message
                        .as_ref()
                        .map_or("".to_string(), |s| format!(" Error = [{}]", s));

                    match from {
                        QueryResult::Literal(_) => unreachable!(),
                        QueryResult::UnResolved(to_unres) => {
                            let message = format!(
                                    "Check was not compliant as property [{remain}] to compare from is missing. Value traversed to [{to}].{err}",
                                    remain=to_unres.remaining_query,
                                    to=to_unres.traversed_to,
                                    err=error_message
                                );
                            clauses.push(ClauseReport::Clause(GuardClauseReport::Binary(
                                BinaryReport {
                                    context: current.context.to_string(),
                                    messages: Messages {
                                        custom_message: Some(custom_message),
                                        error_message: Some(message),
                                        location: Some(to_unres.traversed_to.self_path().1),
                                    },
                                    check: BinaryCheck::UnResolved(ValueUnResolved {
                                        comparison: (*cmp, *not),
                                        value: to_unres.clone(),
                                    }),
                                },
                            )));
                        }

                        QueryResult::Resolved(res) => {
                            if let Some(to) = to {
                                match to {
                                    QueryResult::Literal(_) => unreachable!(),
                                    QueryResult::Resolved(to_res) => {
                                        let message = format!(
                                                "Check was not compliant as property value [{from}] {op_msg} value [{to}].{err}",
                                                from=res,
                                                to=to_res,
                                                op_msg=match cmp {
                                                    CmpOperator::Eq => if *not { "equal to" } else { "not equal to" },
                                                    CmpOperator::Le => if *not { "less than equal to" } else { "not less than equal to" },
                                                    CmpOperator::Lt => if *not { "less than" } else { "not less than" },
                                                    CmpOperator::Ge => if *not { "greater than equal to" } else { "not greater than equal" },
                                                    CmpOperator::Gt => if *not { "greater than" } else { "not greater than" },
                                                    CmpOperator::In => if *not { "in" } else { "not in" },
                                                    _ => unreachable!()
                                                },
                                                err=error_message
                                            );
                                        clauses.push(ClauseReport::Clause(
                                            GuardClauseReport::Binary(BinaryReport {
                                                check: BinaryCheck::Resolved(BinaryComparison {
                                                    to: to_res.clone(),
                                                    from: res.clone(),
                                                    comparison: (*cmp, *not),
                                                }),
                                                context: current.context.to_string(),
                                                messages: Messages {
                                                    location: Some(to_res.clone().self_path().1),
                                                    error_message: Some(message),
                                                    custom_message: Some(custom_message),
                                                },
                                            }),
                                        ))
                                    }

                                    QueryResult::UnResolved(to_unres) => {
                                        let message = format!(
                                                "Check was not compliant as property [{remain}] to compare to is missing. Value traversed to [{to}].{err}",
                                                remain=to_unres.remaining_query,
                                                to=to_unres.traversed_to,
                                                err=error_message
                                            );
                                        clauses.push(ClauseReport::Clause(
                                            GuardClauseReport::Binary(BinaryReport {
                                                context: current.context.to_string(),
                                                messages: Messages {
                                                    custom_message: Some(custom_message),
                                                    error_message: Some(message),
                                                    location: Some(
                                                        to_unres.traversed_to.self_path().1,
                                                    ),
                                                },
                                                check: BinaryCheck::UnResolved(ValueUnResolved {
                                                    comparison: (*cmp, *not),
                                                    value: to_unres.clone(),
                                                }),
                                            }),
                                        ));
                                    }
                                }
                            } else {
                                // A resolved left-hand value with nothing on the right.
                                //
                                // Without this branch the FAIL pushes no ClauseReport at
                                // all, so every reporter shows a blocked deployment with
                                // no stated reason: `checks: []` in JSON and YAML,
                                // `results: []` in SARIF, an empty `<failure/>` in JUnit,
                                // and "Number of non-compliant resources 0" on the
                                // console -- under `Status = FAIL`. The engineer gets an
                                // exit 19 they cannot diagnose, and the message built at
                                // the construction site never reaches any output.
                                //
                                // Reported as Unary rather than Binary because
                                // `BinaryComparison.to` is not an Option and cannot
                                // represent "there was no right-hand value", whereas
                                // `UnaryComparison { value, comparison }` is exactly this
                                // shape. Written against `to == None` generally rather
                                // than against the one operator that currently produces
                                // it, so any future comparison that has a left value and
                                // no right one reports instead of vanishing.
                                clauses.push(ClauseReport::Clause(GuardClauseReport::Unary(
                                    UnaryReport {
                                        context: current.context.to_string(),
                                        messages: Messages {
                                            custom_message: Some(custom_message),
                                            error_message: Some(format!(
                                                "Check was not compliant as property value [{from}] had nothing to compare against.{err}",
                                                from = res,
                                                err = error_message
                                            )),
                                            location: Some(res.clone().self_path().1),
                                        },
                                        check: UnaryCheck::Resolved(UnaryComparison {
                                            value: res.clone(),
                                            comparison: (*cmp, *not),
                                        }),
                                    },
                                )));
                            }
                        }
                    }
                }

                ClauseCheck::InComparison(InComparisonCheck {
                    status: Status::FAIL,
                    from,
                    to,
                    custom_message,
                    comparison,
                    ..
                }) => {
                    let error_message = format!(
                        "Check was not compliant as property [{}] was not present in [{}]",
                        from.resolved().unwrap().self_path(),
                        SliceDisplay(to)
                    );
                    clauses.push(ClauseReport::Clause(GuardClauseReport::Binary(
                        BinaryReport {
                            context: current.context.to_string(),
                            messages: Messages {
                                custom_message: custom_message.clone(),
                                error_message: Some(error_message),
                                location: Some(from.resolved().unwrap().self_path().1),
                            },
                            check: BinaryCheck::InResolved(InComparison {
                                from: match from.resolved() {
                                    Some(val) => val,
                                    None => match from.unresolved_traversed_to() {
                                        Some(val) => val,
                                        None => unreachable!(),
                                    },
                                },
                                to: to
                                    .iter()
                                    .filter(|t| matches!(t, QueryResult::Resolved(_)))
                                    .map(|t| match t {
                                        QueryResult::Resolved(v) => v.clone(),
                                        _ => unreachable!(),
                                    })
                                    .collect::<Vec<_>>(),
                                comparison: *comparison,
                            }),
                        },
                    )));
                }

                _ => {}
            },

            _ => {}
        }
    }
    clauses
}

pub(crate) fn simplified_json_from_root<'value>(
    root: &EventRecord<'value>,
) -> Result<FileReport<'value>> {
    Ok(match &root.container {
        Some(RecordType::FileCheck(NamedStatus { name, status, .. })) => {
            let mut pass: BTreeSet<String> = BTreeSet::new();
            let mut skip: BTreeSet<String> = BTreeSet::new();
            let mut skip_reasons: BTreeMap<String, String> = BTreeMap::new();
            for each in &root.children {
                if let Some(RecordType::RuleCheck(NamedStatus { status, name, .. })) =
                    &each.container
                {
                    match *status {
                        Status::PASS => {
                            pass.insert(name.to_string());
                        }
                        SKIP => {
                            skip.insert(name.to_string());
                            if let Some(reason) = find_skip_reason(each) {
                                skip_reasons.insert(name.to_string(), reason);
                            }
                        }
                        _ => {}
                    }
                }
            }
            FileReport {
                status: *status,
                name,
                not_compliant: report_all_failed_clauses_for_rules(&root.children),
                not_applicable: skip,
                not_applicable_reasons: skip_reasons,
                compliant: pass,
                ..Default::default()
            }
        }
        _ => unreachable!(),
    })
}

pub(crate) fn resolve_function<'value, 'eval, 'loc: 'value>(
    name: &FunctionName,
    parameters: &'value [LetValue<'loc>],
    resolver: &'eval mut dyn EvalContext<'value, 'loc>,
) -> Result<Vec<QueryResult>> {
    let args =
        parameters
            .iter()
            .try_fold(vec![], |mut args, param| -> Result<Vec<Vec<QueryResult>>> {
                match param {
                    LetValue::Value(value) => {
                        args.push(vec![QueryResult::Literal(Rc::new(value.clone()))])
                    }
                    LetValue::AccessClause(clause) => {
                        let resolved_query = resolver.query(&clause.query)?;
                        args.push(resolved_query);
                    }
                    LetValue::FunctionCall(FunctionExpr {
                        parameters, name, ..
                    }) => {
                        let result = resolve_function(name, parameters, resolver)?;
                        args.push(result);
                    }
                }

                Ok(args)
            })?;

    Ok(name
        .call(&args)?
        .into_iter()
        .flatten()
        .map(Rc::new)
        .map(QueryResult::Resolved)
        .collect::<Vec<_>>())
}

#[cfg(test)]
#[path = "eval_context_tests.rs"]
pub(super) mod eval_context_tests;
