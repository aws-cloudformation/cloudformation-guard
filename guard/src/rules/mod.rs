#![allow(deprecated)]
pub(crate) mod display;
pub(crate) mod errors;
pub(crate) mod eval;
pub(crate) mod eval_context;
pub(crate) mod evaluate;
pub(crate) mod exprs;
pub(crate) mod functions;
mod libyaml;
pub(crate) mod parser;
pub(crate) mod path_value;
pub(crate) mod values;

/// Beside the loader because it reads templates through it: see the module's own doc.
#[cfg(test)]
mod rulegen_round_trip_tests;

use errors::Error;

use crate::rules::eval::EntryCandidates;
use crate::rules::eval_context::{EntryCaptures, PassedOn, RhsEnumeration};
use crate::rules::exprs::{AccessQuery, ParameterizedRule, QueryPart};
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use colored::*;
use lazy_static::lazy_static;
use nom::lib::std::convert::TryFrom;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Formatter;
use std::rc::Rc;

pub(crate) type Result<R> = std::result::Result<R, Error>;

lazy_static! {
    pub static ref SHORT_FORM_TO_LONG_MAPPING: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        m.insert("Ref", "Ref");
        m.insert("GetAtt", "Fn::GetAtt");
        m.insert("Base64", "Fn::Base64");
        m.insert("Sub", "Fn::Sub");
        m.insert("GetAZs", "Fn::GetAZs");
        m.insert("ImportValue", "Fn::ImportValue");
        m.insert("Condition", "Condition");
        m.insert("RefAll", "Fn::RefAll");
        m.insert("Select", "Fn::Select");
        m.insert("Split", "Fn::Split");
        m.insert("Join", "Fn::Join");
        m.insert("FindInMap", "Fn::FindInMap");
        m.insert("And", "Fn::And");
        m.insert("Equals", "Fn::Equals");
        m.insert("Contains", "Fn::Contains");
        m.insert("EachMemberIn", "Fn::EachMemberIn");
        m.insert("EachMemberEquals", "Fn::EachMemberEquals");
        m.insert("ValueOf", "Fn::ValueOf");
        m.insert("If", "Fn::If");
        m.insert("Not", "Fn::Not");
        m.insert("Or", "Fn::Or");
        m
    };
    static ref SINGLE_VALUE_FUNC_REF: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("Ref");
        set.insert("Base64");
        set.insert("Sub");
        set.insert("GetAZs");
        set.insert("ImportValue");
        set.insert("GetAtt");
        set.insert("Condition");
        set.insert("RefAll");
        set
    };
    static ref SEQUENCE_VALUE_FUNC_REF: HashSet<&'static str> = {
        let mut set = HashSet::new();
        set.insert("GetAtt");
        set.insert("Sub");
        set.insert("Select");
        set.insert("Split");
        set.insert("Join");
        set.insert("FindInMap");
        set.insert("And");
        set.insert("Equals");
        set.insert("Contains");
        set.insert("EachMemberIn");
        set.insert("EachMemberEquals");
        set.insert("ValueOf");
        set.insert("If");
        set.insert("Not");
        set.insert("Or");
        set
    };
}

#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize, Default)]
#[allow(clippy::upper_case_acronyms)]
pub(crate) enum Status {
    PASS,
    FAIL,
    #[default]
    SKIP,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Status::PASS => f.write_str(&"PASS".green())?,
            Status::SKIP => f.write_str(&"SKIP".yellow())?,
            Status::FAIL => f.write_str(&"FAIL".red())?,
        }
        Ok(())
    }
}

impl TryFrom<&str> for Status {
    type Error = Error;

    fn try_from(value: &str) -> std::result::Result<Self, Self::Error> {
        match value {
            "PASS" => Ok(Status::PASS),
            "FAIL" => Ok(Status::FAIL),
            "SKIP" => Ok(Status::SKIP),
            _ => Err(Error::IncompatibleError(format!(
                "Status code is incorrect {value}",
            ))),
        }
    }
}
impl Status {
    fn and(&self, status: Status) -> Status {
        match self {
            Status::FAIL => Status::FAIL,
            Status::PASS => match status {
                Status::FAIL => status,
                _ => Status::PASS,
            },
            Status::SKIP => status,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy, Serialize)]
pub(crate) enum EvaluationType {
    File,
    Rule,
    Type,
    Condition,
    ConditionBlock,
    Filter,
    Conjunction,
    BlockClause,
    Clause,
}

impl std::fmt::Display for EvaluationType {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationType::File => f.write_str("File")?,
            EvaluationType::Rule => f.write_str("Rule")?,
            EvaluationType::Type => f.write_str("Type")?,
            EvaluationType::Condition => f.write_str("Condition")?,
            EvaluationType::ConditionBlock => f.write_str("ConditionBlock")?,
            EvaluationType::Filter => f.write_str("Filter")?,
            EvaluationType::Conjunction => f.write_str("Conjunction")?,
            EvaluationType::BlockClause => f.write_str("BlockClause")?,
            EvaluationType::Clause => f.write_str("Clause")?,
        }
        Ok(())
    }
}

/// How a retrieval came to stop short of a value, read by the operators that have to tell the cases
/// apart. Not part of the serialized record: the reports print `traversed_to`, `remaining_query` and
/// `reason`, and this is what the engine does with the marker, not what the author sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum UnResolvedKind {
    /// The document lacks the value: a key the map does not have, an index past the end, a function
    /// with no answer. The ordinary case, and the one every operator already reads as "absent".
    #[default]
    Absent,
    /// The query enumerated a collection that holds nothing: `Names[*]` or `Names.*` over `Names: []`
    /// or `{}`. There was no entry to hand on, but nothing was missing either. The marker is left so
    /// an operator still decides (`Tags[*].Key == /PROD/` over `Tags: []` has to fail), and a key
    /// filter reads it as a right-hand side with no value in it rather than one it could not read.
    EmptyEnumeration,
    /// The query could not be decided for this value: a key filter whose right-hand side did not
    /// resolve, or whose comparison the engine could not finish, over one map. The selection for that
    /// map is unknown rather than absent, so an operator over it fails closed in both polarities
    /// (`!exists` over it is not a pass) with `reason` as the explanation, while the query goes on to
    /// its other values and they are reported. Built inside a filter predicate as well: the predicate's
    /// clause raises on it and the enclosing clause fails closed in either polarity, so a selection
    /// nobody could decide is neither silently deselected (which let `Resources.*[ Tags[ keys NOT IN
    /// %allowed ] !empty ] empty` pass with the allowlist missing) nor selected (which a negated predicate
    /// over the earlier `Absent` downgrade did). A scalar met under a key inside a predicate keeps the
    /// ordinary `Absent` reading, deselected or selected by the predicate's polarity. A capture refused
    /// inside a predicate leaves this marker too (`eval_context::to_undecidable_result`), with the reason
    /// naming the capture, and is read the same way: the absent reading would have selected the entry
    /// under `!exists` and `empty` for the capture's sake. A wildcard filter's refusal met inside a
    /// predicate's query leaves it with `refused` set (`eval_context::to_refusal_result`, through
    /// `deliver_wildcard_filter_refusal`): every operator reads the two alike (`is_undecidable`), and only
    /// the filter loop whose walk returned the marker tells them apart (`is_refusal`), cutting its
    /// captures back on a refusal of the rest of its query and not on a marker an inner filter left for
    /// one value it could not decide, since the selection keeps that value's siblings. The flag is data
    /// on the one variant rather than a sibling variant, so a site that matches `Undecidable` has to say
    /// which it reads: a sibling variant was opted out of silently by every existing pattern (one read a
    /// refused capture as a key the map lacks, and a `some` over it passed on a decided sibling).
    Undecidable {
        /// Whether the marker is a refusal delivered inside a predicate, as against a value nobody could
        /// decide.
        refused: bool,
    },
}

impl UnResolvedKind {
    /// Whether the selection for the value is unknown rather than absent: a clause over the marker fails
    /// closed in both polarities, whether a key filter could not decide the value or a refusal was
    /// delivered as the marker.
    pub(crate) fn is_undecidable(&self) -> bool {
        matches!(self, UnResolvedKind::Undecidable { .. })
    }

    /// Whether the marker is a refusal delivered inside a predicate: the one kind a filter loop cuts its
    /// captures back on (`eval_context::ShapeNotes::rebind_to_markers`).
    pub(crate) fn is_refusal(&self) -> bool {
        matches!(self, UnResolvedKind::Undecidable { refused: true })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnResolved {
    pub(crate) traversed_to: Rc<PathAwareValue>,
    pub(crate) remaining_query: String,
    pub(crate) reason: Option<String>,
    #[serde(skip)]
    pub(crate) kind: UnResolvedKind,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum QueryResult {
    Literal(Rc<PathAwareValue>),
    Resolved(Rc<PathAwareValue>),
    UnResolved(UnResolved),
}

impl QueryResult {
    pub(crate) fn resolved(&self) -> Option<Rc<PathAwareValue>> {
        if let QueryResult::Resolved(res) = self {
            return Some(Rc::clone(res));
        }
        None
    }

    pub(crate) fn unresolved_traversed_to(&self) -> Option<Rc<PathAwareValue>> {
        if let QueryResult::UnResolved(res) = self {
            return Some(Rc::clone(&res.traversed_to));
        }
        None
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ComparisonClauseCheck {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult,
    pub(crate) to: Option<QueryResult>, // happens with from is unresolved
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
    /// Whether `message` embeds a REFUSAL's reason: the record of a left-hand value the document lacks
    /// decided beside a refused `%name` among the right-hand values carries the retrieval's own reason
    /// and the refusal's text beside it, the record of a refused `%name` on the left decided by a
    /// right-hand side the document lacks carries that absence's reason and the refusal's text after it,
    /// and the record of a left-hand value paired with the refusal's
    /// marker under a positive `IN` carries the refusal's text as its reason. Set where the record is
    /// written, from the marker's kind (`eval::refused_read_reason`), as [`ValueCheck::refusal`] is set
    /// from the error's; the reporters' `Messages::refusal` is copied from here, so the console prints
    /// such a message whole where it cuts every other to `LONGEST_RECORDED_MESSAGE`, and a refusal's
    /// remedy and path are not cut off its record. A key filter's reason is no refusal and reads
    /// `false`. Not serialized: the record tree `--print-json` writes keeps its shape.
    #[serde(skip)]
    pub(crate) refusal: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct InComparisonCheck {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult,
    pub(crate) to: Vec<QueryResult>, // happens with from is unresolved
    /// `Some` only for a key filter's record against a set, which carries the operator the author
    /// wrote: the elements of `to` that `from` was equal to, in right-hand order. For a written `!=`
    /// that excluded the key these are the elements that excluded it, so a reporter can say "is equal
    /// to \[a\], one of \[a, b\]" rather than a pair it never compared that way; empty for a `==` that
    /// failed (the key equalled none), for a refusal, and for a key kept out only by a right-hand value
    /// the query could not reach, where `message` carries the reason and [`MembershipLead`] reads the
    /// record as not compared. `None` for every other membership record, the scalar `IN` paths
    /// included, whose comparison may also read `Eq` (a `==` decided through the membership
    /// machinery) and whose wording the reporters leave as it is. Not serialized: the renderers read it
    /// through [`InComparisonCheck::lead`], and the serialized tree keeps the shape it had before the
    /// field existed, so a scalar `IN` record carries no `matched` key.
    #[serde(skip)]
    pub(crate) matched: Option<Vec<QueryResult>>,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
    /// Whether `message` embeds a REFUSAL's reason, as [`ComparisonClauseCheck::refusal`] says of its
    /// record. Every site that builds this record writes `false`: the `IN` record that embeds a refused
    /// `%name`'s text (a value no listed entry accepted beside the refusal, or the refusal alone on the
    /// right) is a [`ComparisonClauseCheck`], written where the membership is decided, and it carries
    /// the flag there. The field keeps the two records' shapes alike for the renderers that read
    /// [`Messages::refusal`] from either. Not serialized, for the same reason.
    #[serde(skip)]
    pub(crate) refusal: bool,
}

/// What a failed membership-shaped record says, decided once from the record so that every renderer
/// (the structured report, the console summary, the console reporter) formats the same reading and
/// none of them re-derives the kind of record from its fields.
///
/// A reason outranks everything: a comparison that was never made, because a pairing was refused or a
/// right-hand value could not be reached, is reported as not compared under any operator, never as a
/// key that did or did not match. Only then does the operator the author wrote decide between the
/// equality readings of a key filter's `==` and `!=` against a set and the membership reading of `IN`
/// and `NOT IN`, the scalar `IN` records included, which carry no `matched`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum MembershipLead {
    /// `IN` or `NOT IN`: the value was, or was not, a member of the set.
    Membership,
    /// The comparison could not be made, for the reason carried; nothing about membership is claimed.
    NotCompared(String),
    /// A key filter's written `==` against a set: the key was equal to none of the set's elements.
    NotEqualToAny,
    /// A key filter's written `!=` against a set: the key was equal to these elements of the set, the
    /// ones that excluded it, and the sentence names them rather than the whole set.
    EqualTo(Vec<QueryResult>),
}

impl InComparisonCheck {
    /// The one lead-clause decision for this record; see [`MembershipLead`].
    pub(crate) fn lead(&self) -> MembershipLead {
        match (&self.message, self.comparison, &self.matched) {
            (Some(reason), _, _) => MembershipLead::NotCompared(reason.clone()),
            (None, (CmpOperator::Eq, false), Some(_)) => MembershipLead::NotEqualToAny,
            (None, (CmpOperator::Eq, true), Some(matched)) => {
                MembershipLead::EqualTo(matched.clone())
            }
            _ => MembershipLead::Membership,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct ValueCheck {
    pub(crate) from: QueryResult,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
    /// Whether `message` embeds a refusal (`eval_context::is_refusal`): the evaluator's own sentence about a
    /// read it would not make, whose words the rules file bounds and whose parts taken from the template
    /// are each bounded by `eval_context::LONGEST_TEMPLATE_PART_IN_A_REFUSAL` with a marker where they
    /// are cut (an entry's or a key's name at its end, `template_part`; the path in its middle, keeping
    /// its leaf segments and its location, `template_path`), so no template decides its length. The
    /// console reporter prints such a message whole where it cuts every other to
    /// `LONGEST_RECORDED_MESSAGE`; the kind travels here, beside the text, because the text alone cannot
    /// say (a message that wraps another error displays the same words). Not serialized: the record tree
    /// `--print-json` writes keeps its shape.
    #[serde(skip)]
    pub(crate) refusal: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct UnaryValueCheck {
    pub(crate) value: ValueCheck,
    pub(crate) comparison: (CmpOperator, bool),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct MissingValueCheck<'value> {
    pub(crate) rule: &'value str,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
}

/// A `!empty` whose query selected nothing, so there is no value to record against.
///
/// The reporters build a sentence whose subject is what was tested, and with no value and no path
/// the query is the only thing this check can name. It is carried here, rendered with its filters
/// spelled out, so the reporters do not have to reach for the clause's own rendering, which puts the
/// operator and the clause's `not` in the subject and stands a placeholder in for every filter.
///
/// The query is for the reporters. The record tree that `--print-json` writes serializes this check
/// as it did when the variant held only the message, `null` or the message string, so a consumer of
/// that output sees the same shape; the `Serialize` below is what keeps it so.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct EmptySelectionCheck {
    pub(crate) query: String,
    pub(crate) custom_message: Option<String>,
}

impl Serialize for EmptySelectionCheck {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        self.custom_message.serialize(serializer)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum ClauseCheck<'value> {
    Success,
    Comparison(ComparisonClauseCheck),
    InComparison(InComparisonCheck),
    Unary(UnaryValueCheck),
    NoValueForEmptyCheck(EmptySelectionCheck),
    DependentRule(MissingValueCheck<'value>),
    MissingBlockValue(ValueCheck),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct TypeBlockCheck<'value> {
    pub(crate) type_name: &'value str,
    pub(crate) block: BlockCheck,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct BlockCheck {
    pub(crate) at_least_one_matches: bool,
    pub(crate) status: Status,
    pub(crate) message: Option<String>,
    /// Whether `message` embeds a refusal; see [`ValueCheck::refusal`]. Set from `eval_context::is_refusal`
    /// at every site that writes an error into the message, `false` wherever the message is the
    /// evaluator's own sentence with no error in it.
    #[serde(skip)]
    pub(crate) refusal: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NamedStatus<'value> {
    pub(crate) name: &'value str,
    pub(crate) status: Status,
    pub(crate) message: Option<String>,
    /// Whether `message` embeds a refusal; see [`ValueCheck::refusal`]. A rule whose condition raised
    /// one carries it here, and the console prints that rule's line whole.
    #[serde(skip)]
    pub(crate) refusal: bool,
}

impl<'value> Default for NamedStatus<'value> {
    fn default() -> NamedStatus<'static> {
        NamedStatus {
            name: "",
            status: Status::PASS,
            message: None,
            refusal: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) enum RecordType<'value> {
    //
    // has as many child events for RuleCheck as there are rules in the file
    //
    FileCheck(NamedStatus<'value>),

    //
    // has one optional RuleCondition check if when condition is present
    // has as many child events for each
    // TypeCheck | WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    RuleCheck(NamedStatus<'value>),

    //
    // has as many child events for each GuardClauseBlockCheck | Disjunction
    //
    RuleCondition(Status),

    //
    // has one optional TypeCondition event if when condition is present
    // has one TypeBlock for the block associated
    //
    TypeCheck(TypeBlockCheck<'value>),

    //
    // has as many child events for each GuardClauseBlockCheck | Disjunction
    //
    TypeCondition(Status),

    //
    // has as many child events for each Type value discovered
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    TypeBlock(Status),

    //
    // has many child events for
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    Filter(Status),

    //
    // has one WhenCondition event
    // has as many child events for each
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    WhenCheck(BlockCheck),

    //
    // has as many child events for each GuardClauseBlockCheck | Disjunction
    //
    WhenCondition(Status),

    //
    // has as many child events for each
    // TypeCheck | WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    // TypeCheck is only present as a part of the RuleBlock
    // Used for a IN operator event as well as IN is effectively a short-form for ORs
    //
    Disjunction(BlockCheck), // in operator is a short-form for Disjunctions

    //
    // has as many child events for each
    // WhenCheck | BlockGuardCheck | Disjunction | GuardClauseBlockCheck
    //
    BlockGuardCheck(BlockCheck),

    //
    // has as many child events for each ClauseValueCheck
    //
    GuardClauseBlockCheck(BlockCheck),

    //
    // one per value check, unary or binary
    //
    ClauseValueCheck(ClauseCheck<'value>),
}

pub(crate) trait RecordTracer<'value> {
    fn start_record(&mut self, context: &str) -> Result<()>;
    fn end_record(&mut self, context: &str, record: RecordType<'value>) -> Result<()>;
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
///
/// Carried by both questions a variable-rooted query asks -- what the name resolves to, and which
/// binding produced it. Two chains answering about one name have to agree on which stores are in play,
/// and the merged map is the only store whose reach differs between the two readings, so it is the
/// only one where they could disagree. They did: see [`EvalContext::variable_binding_query`] for what
/// the disagreement cost.
#[derive(Copy, Clone, Eq, PartialEq)]
pub(crate) enum MergedKeys {
    /// The lookup is a clause at the scope's own level.
    Visible,
    /// The lookup started inside a nested block.
    Hidden,
}

/// What a variable lookup answers when no scope on the chain binds the name.
///
/// The two answers are far apart -- a clause that fails, or an error that ends the run and takes every
/// other rule's findings with it -- and which is right depends on whether the name is one the rule text
/// declares. A filter capture that matched no entry has no keys to show and nothing to report: an
/// iteration capturing nothing is not an error, so the clause reading the name fails and the report
/// still names every other rule's findings. A name the rule text never declares is a typo or a name
/// belonging to another rule, which is a broken ruleset rather than a finding about the input.
///
/// Only a block knows which of the two it is, because only a block reads the capture names out of its
/// own clauses, and the error is produced at the far end of the chain. So the answer travels with the
/// lookup rather than being decided where it is needed.
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum UnboundName {
    /// A block the lookup came out of declares the name as a filter capture.
    EmptySelection,
    /// No block does.
    Error,
}

pub(crate) trait EvalContext<'value, 'loc: 'value>: RecordTracer<'value> {
    /// Forget every key captured by a filter so far.
    ///
    /// Only `RootScope` has anything to forget. It is called between top-level rules, which is the
    /// boundary a capture must not cross: a capture belongs to the rule that made it, and to the
    /// iteration inside that rule.
    ///
    /// A scope that does not own captures has nothing to forget, and deliberately does *not* reach up
    /// and clear its parent's -- a rule referenced from inside another rule would otherwise discard the
    /// captures of the rule that referenced it. Such a scope says so with an empty body of its own.
    ///
    /// Merged keys are forgotten along with captured ones. A merged key is a captured key that has
    /// left the block that made it; the rule boundary is the same boundary for both.
    ///
    /// No method of this trait that a wrapping scope is meant to forward has a default. A default is
    /// a decision made for a scope its author never looked at, and a no-op default on a method that
    /// records a notice drops the notice without a trace: `record_deprecation` left to one on
    /// `ResolvedParameterContext` in `eval.rs`, the call scope of a parameterized rule, drops every
    /// notice raised inside such a rule's body, and `record_deprecation_once` left to one on
    /// `FilteredMapFirst` in `eval_context.rs`, the resolver a map-key filter hands its arguments,
    /// drops the `count` list-expansion notice that `resolve_function_tagged` records for a call inside
    /// that filter. Each forwards to its parent instead, and with no defaults the compiler lists every
    /// scope that has to decide.
    fn reset_captures(&mut self);

    fn query(&mut self, query: &'value [QueryPart<'loc>]) -> Result<Vec<QueryResult>>;
    //fn resolve(&self, guard_clause: &GuardAccessClause<'_>) -> Result<Vec<QueryResult>>;
    fn find_parameterized_rule(
        &mut self,
        rule_name: &str,
    ) -> Result<&'value ParameterizedRule<'loc>>;
    fn root(&mut self) -> Rc<PathAwareValue>;
    /// The document every path is absolute from: the file's root scope answers its own root, and every
    /// scope rooted below the document (a value scope at a resource, an element or a bound value; a
    /// block scope; a probe's quiet scope) answers what its parent answers. Read by the member notice
    /// to walk to the value the released engines asked a filter's predicate of
    /// (`eval_context::value_before_the_wildcard`), which may sit above the asking scope's root. Every
    /// scope answers, with no default, for the reason given on `reset_captures`.
    fn document_root(&mut self) -> Rc<PathAwareValue>;
    /// Where a query this scope runs on its own behalf starts: at the document, or at a subject
    /// below it.
    ///
    /// Only one kind of scope starts at the document: the file's root scope, and a block scope
    /// opened from it. Every `ValueScope` starts below it -- at a resource for a type block's
    /// clauses, at an element for a filter's predicate or a `.*` member, at the block's value for a
    /// block clause, at a variable's value for a `%var`-rooted query -- and a block scope opened
    /// inside one of those inherits that answer when it is built. Retrieval does not ask a scope
    /// this; the scope passes it into `query_retrieval` for each query it starts, and a query begun
    /// inside retrieval from a value already reached gets its own answer there. It is read by two
    /// places that have only a scope to ask: `block_scope`, which records the opener's start, and
    /// the parameterized-rule call site, which records whether an argument named the population.
    /// An explicit answer per scope, not a pointer comparison, so a scope that happens to be handed
    /// the document `Rc` still answers for where its queries start.
    fn query_start(&self) -> eval_context::QueryStart;

    /// The one-object filter's note when this scope runs a block body over the EMPTY selection that
    /// filter kept nothing from (`eval_guard_block_clause`): retrieval answers every `this`- or
    /// key-rooted query of the body from the note before any value is reached, a read the inline arm's
    /// shape test refuses as the refusal and every other read as nothing, so each clause is judged where
    /// it reads, as the inline spelling's one part after the filter is. `None` for every other scope. A
    /// block scope nested in the body forwards its parent's answer; a filter predicate's scope and a
    /// bound value's scope answer `None` for their own queries, which read real values. See
    /// `eval_context::LacksKeysNote`.
    fn empty_selection(&self) -> Option<Rc<eval_context::EmptySelection>>;
    /// Whether a query this scope runs on its own behalf is a filter predicate's test of one entry.
    ///
    /// Set once, where a predicate opens: the scope a filter evaluates its predicate in answers true.
    /// Carried, never recomputed: a block scope opened under such a scope, a parameterized rule's call
    /// scope reached from one, a key filter's function-argument scope built inside one, and every
    /// value scope retrieval builds while walking a predicate's query answer what the scope above them
    /// answered. Retrieval reads it at one place, the filter over a scalar under a key: in a
    /// predicate's query that is an unresolved result and the entry is deselected; in a clause's own
    /// query it is refused. The position question (`query_start`) is separate: a predicate's entry is
    /// a subject, and both a resource and a predicate's entry are subjects, so the two answers cannot
    /// be read off one another. Every scope answers, with no default, for the reason given on
    /// `reset_captures`.
    fn in_predicate(&self) -> bool;
    /// Whether a key filter's function argument that the filtered map lacks is read from the scope
    /// beside the map: `FilteredMapFirst`'s fallback, which reads the resource for a filter reached
    /// through `Resources.*` or a block clause and the document for one written at the file's root.
    /// Every evaluating scope answers true, a nested one with the answer of the scope above it. The
    /// grounding probe's quiet scope (`eval_context::QuietScope`) answers false: a probe over one entry
    /// stands in for a run that read the scope outside the filter, and an entry whose own `Tags` differ
    /// from the document's could be grounded through a disjunct the engine itself failed if the probe read
    /// the fallback on its own terms. Under it the in-map miss stands and such a disjunct fails, so a read
    /// that diverges from the real run's can only fail. The one-object probe of the pass-over refusal
    /// answers with the scope above it, since it reads the fallback for real (`fallback_root`). Every
    /// scope answers, with no default, for the reason given on `reset_captures`.
    fn reads_beside_the_map(&self) -> bool;
    /// The value a key filter's function argument is read from when the fallback is taken
    /// (`reads_beside_the_map`): the scope beside the map. Every evaluating scope answers its own root,
    /// since the real run hands the scope beside the map on as the filter's resolver (`ValueScope::query`),
    /// so the resolver `FilteredMapFirst` asks IS that scope. The quiet scope of a probe
    /// (`eval_context::QuietScope`) answers its parent's root: it names itself as its queries' resolver
    /// so that nothing a nested predicate records reaches the run, which puts it where the real run's
    /// `ValueScope` stands, one scope below the one the fallback reads. Every scope answers, with no
    /// default, for the reason given on `reset_captures`.
    fn fallback_root(&mut self) -> Rc<PathAwareValue>;
    /// Whether `variable_name` names the document's own population: bound by `let <name> = <Key>`, a
    /// single plain key (with or without a leading `this.`) and nothing else, in a scope whose
    /// queries start at the document.
    ///
    /// `%r.*[ ... ]` and `%r[ ... ]` over `let r = Resources` are the document's population spelled
    /// through a variable, and get the same empty-selection answer as `Resources.*[ ... ]` and
    /// `Resources[ ... ]`. The answer is
    /// given by the scope that holds the binding, not by the scope that holds the reference, so a
    /// root-level alias reads the same inside a block clause as outside one, and an alias bound
    /// inside a type block's own `let` is not the population because that block's queries start at a
    /// resource. The binding is looked up in the order `resolve_variable` reads it, so a shadowing
    /// `let` of the same name in a nearer scope answers for the value a reference gets: a literal, a
    /// function result (`let r = json_parse(...)`), a captured value, a binding that descends
    /// (`let props = Resources.B.Properties`), filters, or enumerates all answer false, and the
    /// collection such a value hands back stays a property of whatever it named. Nested scopes
    /// forward to their parent. A chain of `let` aliases is followed to the query at its end, as
    /// `variable_binding_query` follows it and under the same `merged` reading, so the two questions
    /// about one name agree on which stores are in play: `let all = Resources` then `let r = %all`
    /// makes `r` the population too, the same answer a parameter passed `%all` gets, unless a key a
    /// finished block merged up under the name `all` is what the asking clause resolves `all` to. A
    /// parameterized rule answers for its own parameters from what the call site recorded about each
    /// argument: `names(Resources)` and `names(%resources)` with such an alias are the population, any
    /// other argument is not. The key's name plays no part: the question is positional, and `let md =
    /// metadata` over a Kubernetes manifest answers true as `let r = Resources` does over a template,
    /// which is why a caller deciding a notice over an empty map from this answer alone keeps a
    /// `metadata: {}` quiet (KNOWN_ISSUES item 11).
    fn is_top_level_alias(&self, variable_name: &str, merged: MergedKeys) -> bool;
    /// Resolve a named rule's status for a reference in the given role.
    ///
    /// `role` is the role of the *reference site*, and it is carried into the rule's own
    /// body: an unevaluatable clause in there is a failure when the reference is an
    /// assertion and merely inapplicable when it is a `when` condition. Implementations
    /// that cache must key on `(rule_name, role)`, since the same rule reached from a body
    /// and from a gate are two different questions.
    fn rule_status(&mut self, rule_name: &'value str, role: eval::ClauseRole) -> Result<Status>;
    fn resolve_variable(&mut self, variable_name: &'value str) -> Result<Vec<QueryResult>>;

    /// The values `variable_name` already HOLDS without anything being evaluated: a `let` bound to a
    /// literal (`let wanted = 'Env'`); a parameter of a called rule holds what its argument holds by this
    /// reading (a literal argument the literal, a bare `%name` argument the caller's answer for `name`, a
    /// query or call argument nothing). `None` for a name bound to a query, a function call or a filter
    /// capture (`[ w | ... ]`, the rule's own or a file-level `let`'s), resolved or not (its resolution is
    /// `resolve_variable`'s, with its memo and its records; this read never starts one, and a capture
    /// holds what the walk bound so far, so it answers the same whether or not an earlier clause warmed
    /// the memo or a rule ran above), for a name an inner block merged up, and for an unbound name.
    /// The one-object filter refusal reads a predicate's `[ Key == %wanted ]` through this, so a literal
    /// `let` names the entry the literal spelling would; a query-bound `let` names nothing HERE. The
    /// `[*]` arm asks `variable_binding_query` whether such a name is bound by a query and, when it is,
    /// resolves it itself under a nested reading, which records nothing (`eval_context::scalar_let_bindings`), so
    /// `[ Key == %forbidden ]` with `let forbidden = Parameters.Forbidden.Default` is read as its literal
    /// spelling `[ Key == 'Secret' ]` is. No scope answers for that read on its own: a resolution is
    /// `resolve_variable`'s, through the scope's own memo, its measurement (a parameter is read as its
    /// `when` measurement reads it) and the cache a probe keeps for the enumeration it runs over.
    fn literal_binding(&self, variable_name: &str) -> Option<Vec<Rc<PathAwareValue>>>;

    /// The query the binding for `variable_name` resolves from, when that binding is a query.
    ///
    /// Two readers, one answer. `query_retrieval_with_converter`'s root-variable arm asks: did resolving
    /// the name already enumerate? A query carrying a projection produces one result per individual, so
    /// a following enumeration has nothing left to do; a query without one produces the single
    /// collection the query named, and the enumeration is still owed; `eval_context::query_projects` is
    /// the one place that reads the answer that way. The one-object filter's `[*]` arm asks: is a
    /// `%name` on a comparison's right BOUND BY A QUERY at all (`eval_context::query_bound_names`)? Such
    /// a name is a literal candidate to the predicate's pair shape; the arm then resolves it quietly
    /// (`eval_context::scalar_let_bindings`), and the twin and `PredicateKeys::of` read what it RESOLVED
    /// TO: one scalar is the literal spelling, anything else leaves the twin undecidable. The arm reads
    /// `Some` as yes and never the query itself. Either way a scope here only has to find the right
    /// binding and never has to interpret it.
    ///
    /// Every implementation must answer, deliberately: there is no default. A scope that forwards
    /// lookups has to forward this one, or a `%var` root reached through it is judged against the wrong
    /// binding -- and `ValueScope` is on the path of every filter predicate and every list expansion,
    /// so a silent default there would take the answer out of reach exactly where the arm is used most.
    ///
    /// `merged` is the reading being asked about, and it is a parameter for the same reason the
    /// resolution takes one: a scope holds keys a finished block handed up, those keys answer a clause
    /// at the scope's own level and not one inside another block, and only the asking side knows which
    /// it is. The chain each implementation walks is the chain a resolution *of that reading* walks --
    /// store for store, including the stores that reading declines to read -- since the binding this
    /// reports has to be the one that produced the values. `resolve_variable` is
    /// [`MergedKeys::Visible`] and [`EvalContext::resolve_variable_from_nested_block`] is
    /// [`MergedKeys::Hidden`]; a block hands its own deferral on as `Hidden` in either, because a name
    /// it does not bind is being read from outside the block either way.
    ///
    /// Answering from one chain about values the other produced is not a near miss. Reading the merged
    /// map unconditionally while the resolution was `Hidden` reported `None` -- "did not enumerate" --
    /// for values a projecting `let` had produced, so the reserved slot was walked instead of consumed,
    /// a following filter ran one level too deep and selected nothing, and an assertion over an empty
    /// selection is not applicable: exit 0 with nothing on either channel, where the same rule with the
    /// capture name dropped exits 19 with four findings.
    ///
    /// `None` means "not resolved from a query", which covers a literal, a function expression, a
    /// filter capture the reading can read, and any scope with no binding for the name. Read as "did
    /// not enumerate", which is what the caller does with it -- after asking
    /// [`EvalContext::binding_is_a_capture`] for the one of those that did: a capture's values are the
    /// members a filter kept, one per element, so the enumeration has happened and the slot is
    /// consumed. For a literal or a function expression the reading is safe rather than merely
    /// convenient, since enumerating a scalar or a string is a pass-through either way -- the answer
    /// is unobservable for them.
    ///
    /// "The reading can read" is the clause that was missing. A key still in the block that captured it
    /// is in reach of both readings; a key merged out of a finished block is in reach of neither the
    /// `Hidden` resolution nor this question asked as `Hidden`, so it says nothing about that reading's
    /// values and `None` for it described a binding that produced none of them.
    fn variable_binding_query(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> Option<&'value AccessQuery<'loc>>;

    /// `query`, reporting as well where the retrieval enumerated: the [`RhsEnumeration`] `IN` reads off
    /// its right-hand side, recorded by the retrieval arms that expanded, selected, or walked a `%v`
    /// root whose binding had, and beside it the maps the last part's `[*]` passed on unchanged
    /// ([`PassedOn`]), which a map-key filter reads and which a parameter bound by the query keeps with
    /// its shape. Each scope runs the same retrieval `query` runs, with the same resolver.
    fn query_with_shape(
        &mut self,
        query: &'value [QueryPart<'loc>],
    ) -> Result<(Vec<QueryResult>, RhsEnumeration, PassedOn)>;

    /// Tell the scope that owns the bound-map probe what a query run by a scope beneath it resolved, so
    /// the probe can judge whether the predicate was grounded in the map; see `QuietScope::grounded`.
    ///
    /// The probe re-runs a filter's predicate through a `QuietScope`, which notes the grounding of the
    /// queries it runs itself. A `when` block or nested block inside that predicate runs its body in a
    /// scope of its own, which runs its queries with itself as the resolver, so without this the body's
    /// lookups were invisible to the probe: `%r[ when Properties !exists { MyBucket exists } ]` over
    /// `let r = Resources` held by the body's `MyBucket` and announced nothing, where the bare clause
    /// `MyBucket exists` grounds. A scope that runs queries beneath another forwards each result here
    /// after its own retrieval, and passes on each result it is handed from a scope beneath it, so a
    /// lookup any number of blocks deep (`%r[ when Properties !exists { when Type !exists { MyBucket
    /// exists } } ]`) climbs to the probe link by link; the root scope, which has nothing above it,
    /// keeps the default and ignores it. Defaulted to a no-op, which is the right answer for the root
    /// alone: every wrapping scope answers it by passing it up, because a wrapper that inherited the
    /// no-op swallowed the body of a `when` nested inside a `when`, and the site read as anchored by
    /// nothing one level deeper than it read as anchored.
    fn note_query_grounding(
        &mut self,
        _query: &'value [QueryPart<'loc>],
        _results: &[QueryResult],
    ) {
    }

    /// Where the values the last resolution of `variable_name` returned enumerated, as the retrieval
    /// that produced them reported.
    ///
    /// A read of what the resolution recorded, never a second resolution: the root-variable arm of
    /// retrieval resolves the name once and then asks this, so no filter record or capture is made
    /// twice and no error is swallowed. `merged` is the reading that resolution used, for the reason
    /// `variable_binding_query` takes it: the stores are consulted in the lookup's order under that
    /// reading, so the shape comes from the binding that produced the values and a block defers to its
    /// parent as `Hidden`. The shape of a `let` bound to a query is that query's; of one bound to a call,
    /// the call's (`resolve_function_with_shape`); of a parameterized rule's argument, the argument's as
    /// the caller resolved it; and `Names` for a literal, a capture, a merged key or an unbound name,
    /// each of which names its value.
    ///
    /// Beside the shape, in the same answer, the record the retrieval kept for the same binding: the
    /// maps the last part's `[*]` passed on unchanged in the resolution that produced `variable_name`'s
    /// values ([`PassedOn`]), read by a map-key filter whose right-hand side is `%variable_name`, so
    /// that `let exempt = Mappings.Exempt.Names[*]` over `Names: { BucketA: true }` is read as the map
    /// the query named, its key set, and not as one member kept whole; empty for a literal, a capture, a
    /// merged key, an unbound name and every resolution whose last part was not the author's `[*]` over
    /// a map. One method for the two, because the store holds them together and a scope that answered
    /// them apart could pair the shape of one binding with the record of another (two lookups that
    /// drifted by one store would compile), or forward one and not the other: a forwarder that dropped
    /// the record would read every passed-on map behind it as a member, and the silent SKIP would be
    /// back with nothing red. No default, for the reason `variable_binding_query` has none: a forwarding
    /// scope that inherited `(Names, empty)` would compile and read every `let x = Types[*]` behind it as
    /// one value, and the substring reading of `IN %x` would be back with nothing red.
    fn variable_shape(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> (RhsEnumeration, PassedOn);

    /// Whether the binding for `variable_name`, under the `merged` reading, is a filter capture.
    ///
    /// The companion of [`EvalContext::variable_binding_query`] for the one binding kind that has no
    /// query to report. A capture holds the entries a filter kept -- keys for a map, elements for a
    /// list -- so its values are already the members and the root-variable arm consumes the reserved
    /// slot for it as it does for a projecting `let`. Reading `None` from `variable_binding_query` as
    /// "did not enumerate" walked the slot instead, which is a pass-through for a key and wrong for an
    /// element: `%t[ Key == 'Name' ]` over a captured tag walked into the tag's own entries and selected
    /// nothing.
    ///
    /// Same chain and same reading rules as `variable_binding_query`, store for store: a scope answers
    /// for the captures it holds, declines for a name it binds some other way, and otherwise defers as
    /// `Hidden`. No default: a resolver that binds nothing says `false` in its own text, and every scope
    /// that holds or forwards bindings answers, for the reason given on `variable_binding_query`.
    fn binding_is_a_capture(&mut self, variable_name: &str, merged: MergedKeys) -> bool;

    /// The key each member of the projection bound to `variable_name` was produced under, indexed by
    /// the member's path (`eval_context::ProjectionKeys`), built from the containers the projection
    /// enumerated: found by the same walk [`EvalContext::variable_binding_query`] makes, run in the
    /// scope where that walk ended, and kept there for as long as the binding is.
    ///
    /// A binding's query was written in the scope that holds it and resolves against that scope's
    /// root: a file-level `let buckets = Resources.*[ ... ]` resolves from the document, whichever
    /// scope reads `%buckets`. The root-variable arm has to re-run the part of that query ahead of its
    /// last expansion to learn which container each member came from, and it has to run it there. Run
    /// through the reader's own `query`, it started at the reader's root, which inside a block clause
    /// or a type block body is one resource, where `Resources` does not exist; and worked out by a
    /// second owner computation beside the walk, it named an alias (`let bs = %buckets`, or a
    /// parameter passed `%buckets`) bound in that resource-rooted scope while the walk had already
    /// followed the alias to the file-level `let`. One walk, one owner: each scope takes the same step
    /// it takes for `variable_binding_query` (`eval_context::BindingStep`), and the scope that holds the
    /// query runs the prefix with its own `query`, once, memoized per binding, so a named filter inside
    /// the prefix captures its ids once rather than per member per iteration, and the index it builds
    /// makes each member's key one lookup rather than a scan of every container's entries.
    ///
    /// `merged` is the reading, exactly as for `variable_binding_query`, and a block hands off as
    /// `Hidden`: a key a sibling nested block merged up under the name is not this reader's binding.
    /// `None` means the name is not bound by a projecting query on the chain. No default, for the reason
    /// given on `variable_binding_query`: a scope that forwards lookups has to forward this one, or a
    /// member reached through it binds its own body again.
    fn projection_member_keys(
        &mut self,
        variable_name: &str,
        merged: MergedKeys,
    ) -> Result<Option<Rc<eval_context::ProjectionKeys>>>;

    /// Resolve `variable_name` for a lookup that started inside a nested block.
    ///
    /// Two things differ from `resolve_variable`.
    ///
    /// Keys merged out of a block that has already finished are withheld. Those keys are a union over
    /// that block's iterations, while the clause asking is one iteration of another block, so answering
    /// from the union lets one resource's key satisfy a second resource's clause. A key captured by a
    /// filter in a scope whose iteration is still running is offered as usual: that key belongs to the
    /// iteration doing the asking.
    ///
    /// `unbound` says what to answer if no scope on the chain binds the name, and it is the block the
    /// lookup came out of that knows: see [`UnboundName`].
    ///
    /// A scope that holds no merged keys and produces no unresolved-variable error answers with its
    /// `resolve_variable`, and says so itself. A scope that only forwards lookups has to forward this
    /// one too, or both distinctions are lost at that link in the chain; see `reset_captures` for why
    /// there is no default to fall back on.
    fn resolve_variable_from_nested_block(
        &mut self,
        variable_name: &'value str,
        unbound: UnboundName,
    ) -> Result<Vec<QueryResult>>;

    /// Take one result a running filter captured under `variable_name`: the entry's key when the
    /// predicate held, or the undecidable marker (`UnResolvedKind::Undecidable`) when the predicate
    /// raised on an entry nobody could decide. The marker travels into the capture so that a clause
    /// reading `%name` fails closed on it, as the clause reading the selection does; a capture that
    /// held only the decided entries let `Resources.%b.Type == 'Y'` pass over a document whose other
    /// entry could not be decided.
    ///
    /// A scope that keeps no captures accepts and drops the result, and says so itself; see
    /// `reset_captures` for why there is no default for the forwarding scopes.
    fn add_variable_capture(
        &mut self,
        variable_name: &'value str,
        result: QueryResult,
    ) -> Result<()>;

    /// How many results this run has filed under `variable_name` in the store `add_variable_capture`
    /// writes to for this scope. A filter loop reads it before it binds a key, so that a refusal raised
    /// from the walk under a held entry can cut the capture back to exactly what stood there
    /// (`truncate_variable_capture`): the keys this loop bound go, and a result another clause filed
    /// under the same name stays. A scope that keeps no captures answers 0.
    fn variable_capture_len(&self, variable_name: &str) -> usize;

    /// Cut what this run filed under `variable_name` back to its first `len` results, `len` being what
    /// `variable_capture_len` answered before a filter loop bound into the capture. The loop pushes the
    /// refusal's marker next, so a clause reading `%name` after a refused walk fails closed on the
    /// marker, as the clause reading the selection does, and not on the keys bound before the walk,
    /// while every result another clause filed under the name stands. Under a measurement the cut
    /// removes only what the reading itself appended since the length was read, which is at or past
    /// the undo log's own point, so the roll-back still restores the real run's keys. A scope that
    /// keeps no captures accepts the call and does nothing, as it does for `add_variable_capture`; no
    /// default for the forwarding scopes, for the reason `reset_captures` gives.
    fn truncate_variable_capture(&mut self, variable_name: &'value str, len: usize) -> Result<()>;

    /// Open a capture frame for one enumeration loop (`.*`, `[*]`, a filter's member loop) on the scope
    /// that keeps the captures `add_variable_capture` writes for this scope. The work done under ONE
    /// entry of the loop is a segment of the frame (`begin_capture_entry`, `end_capture_entry`): what a
    /// segment appends to any capture is parked in the frame when the segment ends, in loop order, and
    /// appended back when the frame closes (`close_capture_frame`), so under entry `i` a reader of
    /// `%name` sees what stood before the loop and entry `i`'s own appends, while after the loop the
    /// accumulation reads as it always has. Without it a capture made inside a predicate under one `.*`
    /// entry (`Resources.*[ Tags[ t | Key == 'Env' ] !empty  M[ keys == %t[*].Value ] !empty ]`) was
    /// read again under the next entry, so a resource's verdict depended on its position in the
    /// document. The scope that keeps the captures answers, every other forwards to its parent, and a
    /// scope that keeps none (the quiet probe's) does nothing; no default, for the reason
    /// `reset_captures` gives.
    fn open_capture_frame(&mut self);

    /// Begin the segment of the innermost open frame for the entry about to be worked under: a bind
    /// made BEFORE this call (the walk's own-key capture) stands below the segment and is never parked,
    /// so a later part of the same query still reads the keys held so far. Nothing without an open frame.
    fn begin_capture_entry(&mut self);

    /// End the innermost frame's running segment, parking what it appended. The entry loops call it from
    /// a guard dropped on every way out of the entry's work (`CaptureSegment` in `eval_context`), the
    /// refused entry and the `?` exits between the predicate and the walk included, so a frame never
    /// keeps a segment open across entries; a segment still running when the frame closes is ended by
    /// the close.
    fn end_capture_entry(&mut self);

    /// `end_capture_entry`, with what the segment parked handed back to the caller instead of kept in
    /// the frame, so the frame's close appends none of it back. The own-key enumeration runs every
    /// entry's predicate before it walks any held entry (`enumerate_under_an_own_key_filter` in
    /// `eval_context`): it ends each predicate's segment this way, carries the captures with the
    /// entry's verdict, and files them back under that entry's own walk (`refile_captures`), so the
    /// continuation reads the entry's own predicate captures there as it does after a filter that binds
    /// and walks per entry. Same owners as `end_capture_entry`; a scope that keeps no captures hands
    /// back nothing.
    fn end_capture_entry_detached(&mut self) -> EntryCaptures<'value>;

    /// File `captures` back into the store they were taken from (`end_capture_entry_detached`): under a
    /// running segment they are that segment's appends, parked again at its end with the segment's own;
    /// outside one they stand, as the close would have left them. Same owners as `end_capture_entry`.
    fn refile_captures(&mut self, captures: EntryCaptures<'value>);

    /// Close the innermost frame, appending every parked slice back in loop order. Called on every exit
    /// of the loop, its error included.
    fn close_capture_frame(&mut self);

    /// `add_variable_capture_key` for the walk's OWN-KEY bind (`Cfg[*][ x | ... ]`'s `x`, `Cfg[ x | ... ]`'s
    /// `x`, a list filter's member), made while the entry's segment is running: the key is filed BELOW
    /// the segment, at the position the name stood at when the segment began, and the segment's start
    /// for the name moves past it, so the key is not parked with the entry's own appends and a later part
    /// of the same query reads the keys held so far under every later entry, while the predicate's
    /// captures made in the same segment stay the entry's alone. Filed below the one segment that runs,
    /// whatever depth its begins have reached: the entry loop that owns the enumeration calls this for
    /// its members' keys (a list member a wildcard expanded included), and a filter over ONE object under
    /// another loop's entry, which has no member loop of its own, calls `add_variable_capture_key`
    /// instead, so its key is that entry's own and is parked with it (`OwnKeyFiling` in `eval_context`).
    /// With no segment running (no loop, or a scope that keeps no captures) it is
    /// `add_variable_capture_key`. No default, for the reason `reset_captures` gives.
    fn add_variable_capture_key_below_the_entry(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()>;

    /// `add_variable_capture` for the key of an entry the predicate held. An adapter, not a forward,
    /// so the default is the one body every scope would write.
    fn add_variable_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.add_variable_capture(variable_name, QueryResult::Resolved(key))
    }

    /// Take a result that a block which has now finished captured: the key of an entry its filter
    /// held, or the undecidable marker of an entry its filter could not decide.
    ///
    /// Kept apart from `add_variable_capture` because the two differ in reach rather than in content:
    /// the first is a result from the iteration that is running, this one a union over the iterations
    /// of a block that has ended. `resolve_variable_from_nested_block` offers the first and withholds
    /// this one.
    ///
    /// Takes the whole `QueryResult`, as `add_variable_capture` does, so the marker travels out of the
    /// block with the keys: when only the resolved keys were handed up, `%b !empty` after
    /// `Resources.* { Properties.Rules[ b | Cfg[ keys == Names[*].Name ] !empty ] !empty or Type exists }`
    /// read the decided resource's rule alone and passed at exit 0 over a document whose other
    /// resource's filter could not be decided, where the same read inside the block fails closed.
    ///
    /// A scope that does not separate the two answers with its `add_variable_capture`, and says so
    /// itself; see `reset_captures` for why there is no default.
    fn add_merged_capture(&mut self, variable_name: &'value str, result: QueryResult)
        -> Result<()>;

    /// `add_merged_capture` for a key a finished block captured. An adapter, not a forward, so the
    /// default is the one body every scope would write.
    fn add_merged_capture_key(
        &mut self,
        variable_name: &'value str,
        key: Rc<PathAwareValue>,
    ) -> Result<()> {
        self.add_merged_capture(variable_name, QueryResult::Resolved(key))
    }

    /// A scope that keeps no index captures accepts and drops the index, and says so itself.
    fn add_variable_capture_index(&mut self, name: &str, index: Rc<PathAwareValue>) -> Result<()>;

    /// Note that a clause took a path whose answer is going to change, without changing this run's
    /// answer.
    ///
    /// Deliberately returns nothing, so a notice cannot influence a verdict: the evaluator can only
    /// deposit a string, and no evaluation path reads one back. `notice` is the body alone; the scope
    /// that owns the set writes the notice prefix in front of it when it stores it, so no builder
    /// spells the prefix. No default: a scope that forwards lookups forwards this, a scope that owns
    /// the set stores it, and a test double says what it does. The call scope of a parameterized rule
    /// once took a no-op default here, and every notice raised inside such a rule's body was dropped
    /// with nothing to flag it.
    fn record_deprecation(&mut self, notice: String);

    /// Note that a clause's reading has already moved: the answer it gives now differs from the one an
    /// earlier release gave, and this run's answer is the new one. Kept apart from `record_deprecation`,
    /// which is about a reading kept for one more release, so a consumer counting either set counts
    /// one kind. The same rules as `record_deprecation`: returns nothing, no evaluation path reads a
    /// warning back, no default.
    ///
    /// Keyed by `site`, the call the warning is about, and `argument`, the call's argument as written:
    /// one argument of one call evaluated over many values is one warning, holding the first text
    /// recorded for it and a count of the further values (`map`, the path of the value the text is
    /// about) it was recorded for, as the once-per-site deprecations are one per site. A call with two
    /// arguments that both moved is two warnings, one per argument, each counting the maps that
    /// argument moved on. The same value read twice under two scopes is one value, not two. Nothing is
    /// recorded during a measurement, as for the deprecations: a `when` re-read under
    /// `Measurement::Quiet` evaluates conditions the run never reached, and a warning about a clause
    /// the run never evaluated is noise.
    fn record_warning(
        &mut self,
        site: &exprs::FileLocation<'_>,
        argument: &str,
        map: &str,
        notice: String,
    );

    /// Note that a capture was declared where nothing can bind it, at the filter whose first predicate
    /// clause is at `site`: the clause is held and fails, and this line is what makes the limitation
    /// visible when an `or` sibling decides past it. The same rules as `record_warning`: returns
    /// nothing, nothing reads it back, nothing is recorded during a measurement, no default.
    ///
    /// Keyed by `site` and `capture`, under its own kind: one capture of one clause is one line
    /// whatever the clause is evaluated over, since the text names no value, and the same text recorded
    /// again (the next resource a block evaluates the clause over) adds neither a line nor a count. Kept
    /// apart from `record_warning`, whose key counts the maps an argument moved on, so a capture
    /// spelled like a moved argument at the same position is its own line, and the count the commands
    /// append across the cases of one spec file speaks of cases that refuse the capture, not of maps
    /// that read a differing value.
    fn record_capture_warning(
        &mut self,
        site: &exprs::FileLocation<'_>,
        capture: &str,
        notice: String,
    );

    /// Note that a comparison at `site` (written as `context`) was decided without raising the REFUSED
    /// reads among its values, on either side (`refusals`, one text each): the clause's verdict
    /// (`verdict`: a value that holds settled it, a value the document lacks decided it, a value that does
    /// not match decided it, or a value that matches a denied entry decided it) never raised them, and the
    /// line is what keeps such a refusal from being silent. Written only after the clause is decided (a
    /// clause raised on an undecided pair carries the refusal in its failure and writes nothing), once per
    /// clause site: the line counts the DISTINCT refusal texts the site met and how many evaluations
    /// decided it each way, so one refusal met beside a pass and beside an absence is one refusal,
    /// whatever order the evaluations came in, names every text met in the order it was met, and ends
    /// with the clause's position and the input it was found in. The same rules as `record_warning`:
    /// returns nothing, nothing reads it back, nothing is recorded during a measurement, no default. Never
    /// for the marker a key filter leaves, which is not a refusal.
    fn record_unraised_refusal(
        &mut self,
        site: &exprs::FileLocation<'_>,
        context: &str,
        verdict: UnraisedVerdict,
        refusals: &[String],
    );

    /// The name of the data file this evaluation reads, for a notice that cites positions in it: with
    /// several data files in one run, a position alone does not say which file it is in. The root
    /// scope is built with it (`root_scope_for`); a scope built without one (`root_scope`, the unit
    /// tests) answers `None`, and so does one built for a `test` case (`root_scope_for_case`), which
    /// reads no data file and answers `case_label` instead. No default, for the reason
    /// `record_deprecation` has none: a forwarding scope that inherited `None` would compile and drop
    /// the name from every notice raised below it.
    fn data_file_name(&self) -> Option<&'value str>;

    /// The `test` case this evaluation runs, named for a notice that cites positions in its input:
    /// "case `<name>` of `<spec file>`", or "case `<n>` of `<spec file>`" for a case with no name. The
    /// root scope is built with it (`root_scope_for_case`); a scope built for a data file or without
    /// an input name answers `None`. A case's input is inline in the spec file, so a position alone
    /// names no file the reader could open, and a spec with twenty cases gives no way to tell which
    /// case a position belongs to. No default, for the reason `data_file_name` has none.
    fn case_label(&self) -> Option<&str>;

    /// Whether `variable_name` is bound to the KEYS a filter captured -- a capture (`Resources[ nm |
    /// ... ]`), a merged key (when `Visible`), or a file-level assignment's capture -- rather than to a
    /// value.
    ///
    /// Read by the interpolation arm of retrieval: `Resources.%nm.Properties.BucketName` over a capture
    /// walks every captured key, which is the enumeration `Resources.*[ Type == ... ].Properties
    /// .BucketName` spells inline, so `IN` against it is membership in the names, not containment in
    /// each. `variable_shape` answers `Names` for the same binding, because the capture names its
    /// values when read bare (`X IN %nm` compares key by key as before), and the two questions are kept
    /// apart rather than folded into one answer. No default, for the reason `variable_shape` has none:
    /// a forwarding scope that inherited `false` would compile and read every interpolated capture
    /// behind it as a haystack with nothing red.
    fn variable_lists_keys(&self, variable_name: &str, merged: MergedKeys) -> bool;

    /// The entry sets `IN` compares against for an enumerating right-hand side resolved to `values`,
    /// built once per distinct right-hand side in this evaluation and shared after that.
    ///
    /// Keyed on the identity of the resolved `Rc`s (`EntryCandidates::same_values`), never on their
    /// contents: a type block or a filter evaluates one clause once per resource, and when its right-hand
    /// side is a `let`-bound allowlist every resource reads the same resolved `Rc`s, so the sets, and
    /// the one copy of the entries each set makes, are built for the first resource and read by the
    /// rest. A right-hand side the walk re-materializes per resource (a `[*]` expanded afresh, a filter
    /// run again) resolves to new `Rc`s and gets its own sets. Defaulted to a fresh build, which is
    /// correct and costs only the sharing; the root scope keeps the cache and the nested scopes forward
    /// to it.
    fn entry_candidates(
        &mut self,
        values: Vec<Rc<PathAwareValue>>,
        shape: RhsEnumeration,
    ) -> Rc<EntryCandidates> {
        Rc::new(EntryCandidates::new(values, shape))
    }

    /// Record `notice` unless a notice of this `kind` has already been recorded for `site`.
    ///
    /// For a notice whose text carries numbers that change from one evaluation of the same clause to
    /// the next, so that the set of notices, which is keyed by text, still prints one line per call
    /// site, the first numbers seen. `resolve_function_tagged` in `eval_context.rs` is a caller: a
    /// `let n = count(Properties.L)` inside a block over resources is evaluated once per resource, with
    /// each resource's own numbers. The key is the pair, so two kinds of notice at one position are two
    /// lines. No default, for the reason `record_deprecation` has none.
    ///
    /// Answers whether this call recorded the notice: `false` when the site already had one of this
    /// kind, or when a measurement is on and nothing is recorded. `eval::announce_a_moved_when` settles
    /// a `when` on `true` and on nothing else; see `settle_when`.
    fn record_deprecation_once(
        &mut self,
        kind: DeprecationKind,
        site: &exprs::FileLocation<'_>,
        notice: String,
    ) -> bool;

    /// Put this evaluation into, or take it out of, a measurement; see [`Measurement`].
    ///
    /// The state belongs to the scope that owns the run's records and bindings, the root scope, and
    /// every other scope forwards both methods to it, so a measurement started through a nested scope
    /// reaches the stores it has to reach. No default, for the reason `record_deprecation` has none.
    fn set_measurement(&mut self, mode: Measurement);

    /// The measurement this evaluation is in; [`Measurement::Off`] outside one.
    fn measurement(&self) -> Measurement;

    /// Whether the `when` at `site` is settled for `direction` in this evaluation: its notice for a
    /// move that way has been recorded, so no further measurement of it can add a line that way.
    ///
    /// `eval::announce_a_moved_when` asks first, for the one direction this release's answer allows
    /// ([`MoveDirection::of_now`]), and returns without measuring on `true`. The notice is one per
    /// `when` and direction through `record_deprecation_once`; without this the measurement that decides
    /// whether the notice is owed was taken for every resource a type block visits, after the line
    /// already existed. A `when` is settled only by `settle_when`, never by being measured on its own:
    /// a resource whose gate did not move, a call whose arguments did not move it, or a measurement that
    /// could not finish leaves a `when` that reads the resource open, so a later resource or call that
    /// does move still gets the line; and a `when` settled one way is still open the other way, so a
    /// resource that could only have moved the other way is measured and gets its own line.
    ///
    /// A `when` whose every name rests on document-level bindings (`binding_owners` answers for each
    /// of them) answers the same for every resource and call that reads the same bindings, so a
    /// finished measurement of it, moved or not, settles it for those bindings: `bindings` is the set
    /// `binding_owners` gave for the names the conditions read, and a `when` reached again with the
    /// same set returns before measuring. A called rule's `when` is one position shared by every
    /// caller, and a `let` in one caller's body is a different binding from the same-named `let` in
    /// another's, so one caller's measurement settles it for that caller's calls and decides nothing for
    /// the next caller's. `None` asks only whether the line was recorded. `site` is the position of the
    /// `when`'s first condition, kept as its file, line and column. The records belong to the root
    /// scope, as the notice sites do; every other scope forwards. No default, for the reason
    /// `record_deprecation` has none.
    fn when_is_settled(
        &self,
        site: &exprs::FileLocation<'loc>,
        direction: MoveDirection,
        bindings: Option<&BTreeSet<eval_context::BindingId<'value>>>,
    ) -> bool;

    /// Whether any finished measurement has settled the `when` at `site` for `direction`, for some set
    /// of bindings; see `when_is_settled`.
    ///
    /// The cheap question `eval::announce_a_moved_when` asks before its pre-check, so that a `when`
    /// settled by a measurement returns in a lookup on every later resource and call that reads the same
    /// bindings: only when a record exists are the conditions walked for the bindings their names rest
    /// on and `when_is_settled` asked with them. Without this, the common gate (`AWS::S3::Bucket when %p
    /// !empty`) paid the pre-check on every resource after the first had settled it: the names read,
    /// the memoized result cloned, the chain and the entries read again, the dropped entries cloned
    /// into a fresh set, where the release before answered in one lookup. Answered by the root scope,
    /// which owns the records; every other scope forwards. No default, for the reason
    /// `record_deprecation` has none.
    fn when_has_settled_measurements(
        &self,
        site: &exprs::FileLocation<'loc>,
        direction: MoveDirection,
    ) -> bool;

    /// Settle the `when` at `site` for `direction` for the rest of this evaluation: with `None`, for
    /// every evaluation of it, because its line for that direction was recorded; with `Some`, for the
    /// evaluations whose names rest on exactly those bindings, because a finished measurement decided
    /// it for them. See `when_is_settled`. Called by `eval::announce_a_moved_when` right after
    /// `record_deprecation_once` answers that it recorded the `when`'s notice for that direction, and
    /// after a finished measurement of a `when` whose every name rests on document-level bindings, and
    /// nowhere else. No default, for the reason `record_deprecation` has none.
    fn settle_when(
        &mut self,
        site: &exprs::FileLocation<'loc>,
        direction: MoveDirection,
        bindings: Option<BTreeSet<eval_context::BindingId<'value>>>,
    );

    /// The document-level bindings the value of `variable_name` rests on, when it rests on nothing
    /// else: `None` for a name bound per resource or per call, or bound nowhere.
    ///
    /// Asked by `eval::announce_a_moved_when` to tell a `when` whose answer cannot change from one
    /// resource of a type block, or one call of a parameterized rule, to the next, from one that reads
    /// the resource: a `let` inside a type block's body is bound once per resource, a capture once per
    /// resource, a parameter once per call, and a bare property path or `this` is the resource itself.
    /// A binding is a [`eval_context::BindingId`]: the `let`'s name as the parsed rules file holds it,
    /// compared by where it sits, which the file holds once per `let` for the run, so two callers'
    /// same-named body `let`s are two bindings and a scope built again over the same `let` names the
    /// same one. A scope that binds the name answers for
    /// it: the root, whose bindings every resource and call reads alike, names the binding itself; a
    /// block whose queries start at the document outside any parameterized rule's call
    /// (`within_parameterized_call`), a rule body's `let`, runs once per evaluation and names the
    /// binding itself too; any other block (a type block's body, a `when` block inside one, a called
    /// rule's body, bound again for every resource or call) answers for a `let` from the `let`'s own
    /// right-hand side, the union of what its `%name`s rest on, since a value computed from
    /// document-level bindings and literals alone is the same however often its block runs, together
    /// with the `let`'s own binding, since what a right-hand side rests on does not tell one `let` from
    /// another of the same name that reads the same roots; a capture or a declared capture name of a
    /// block at the document level is its own binding at that NAME's capture GENERATION in the block
    /// (`BlockScope::document_level_site`): the declared name before its filter has run and the captured keys
    /// after are two ids, a stretch of reads with no new capture of that name is one, and another name's
    /// captures (a type block handing its own up on every resource) leave it, so a `when` over a rule
    /// body's capture settles once the filter has run; and `None` for a capture in any other block,
    /// where it is the resource's or the call's, and for a key a nested block handed up (`merged`)
    /// wherever it is bound, since a call from the body's level and a call from a nested block read it as
    /// two values under one name. A scope that does not bind the name forwards to its
    /// parent. The call scope answers `None` for its parameters and for the names its own conditions
    /// captured, and forwards every other name to its caller, so a name a caller binds in its body
    /// reaches the caller's block and is named as that caller's binding. No default, for the reason
    /// `record_deprecation` has none.
    fn binding_owners(
        &self,
        variable_name: &str,
    ) -> Option<BTreeSet<eval_context::BindingId<'value>>>;

    /// The memo of the `%variable` values and shapes the quiet probes of this evaluation resolved for
    /// bindings whose value rests on document-level bindings alone (`binding_owners` answers `Some` for
    /// the name): see [`eval_context::DocumentBindingMemo`]. Such a value is the same for every resource,
    /// call and enumeration of the evaluation, so a probe that resolves it once keeps it here, keyed by
    /// the set `binding_owners` gave, and the probes over the next resource's enumeration read it instead
    /// of resolving the binding again; a name bound per resource or per call (`None` from
    /// `binding_owners`) is never kept here and stays with the probe's own per-enumeration cache
    /// (`eval_context::ProbeCache`). Owned by the root scope, which clears it around a reading with
    /// function results' unresolved entries dropped (`Measurement::WithoutUnresolved`), whose values
    /// differ; every other scope forwards to the scope above it; a scope with no root behind it answers
    /// `None`, and the probe then keeps its per-enumeration cache alone. No default, for the reason
    /// `record_deprecation` has none.
    fn document_binding_memo(
        &self,
    ) -> Option<Rc<std::cell::RefCell<eval_context::DocumentBindingMemo<'value>>>>;

    /// The latest deep copy the member notice's probe made of a value found below the document root,
    /// with the path of the value it copies (see [`eval_context::ValueBeforeClones`]): the probe reads
    /// the value the released engines asked the predicate of, and under `Statement[*].Condition[*][ f ]`
    /// that value is the resource above every statement's root, so a site whose verdict stays quiet
    /// (recorded per map, not per site) asked for that copy once per statement, a copying cost that grew
    /// with the square of the policy's size; the one copy now serves every statement and every site that
    /// asks for the same value before the walk moves on. Owned by the root scope; every other scope
    /// forwards; a scope with no root behind it answers `None` (the default) and the copy is made on every
    /// ask.
    fn value_before_the_wildcard_clones(
        &self,
    ) -> Option<Rc<std::cell::RefCell<eval_context::ValueBeforeClones>>> {
        None
    }

    /// Whether a binding is being resolved somewhere on this scope's chain: a file-level assignment's
    /// right-hand side at the root (`resolving_assignments`) or a block's `let` in a block
    /// (`resolving_let`). A quiet probe that resolves a `%name` while one is open may read a value the
    /// open resolution has not finished filling (`bind_assignment_captures` skips the assignment being
    /// resolved, so a `let` aliasing its capture reads a partial set), and such a value is not kept in
    /// the `document_binding_memo` for the evaluation. Every scope that is not the root or a block
    /// forwards; a scope with no root behind it answers `false`. No default, for the reason
    /// `document_binding_memo` has none.
    fn resolving_a_binding(&self) -> bool;

    /// The answers this evaluation's `binding_owners` walks have given for the ROOT's bindings, keyed by
    /// the binding's id (its site in the rules text and its capture generation; see
    /// [`eval_context::BindingOwnersMemo`]). A root `let` rests on root `let`s, which have no capture
    /// generation and no caller, so the walk over its right-hand side is paid once per evaluation and read
    /// back for every later ask over the same binding: the `when` settlement over a `let` read on every
    /// resource, the probes' memo key and the member notice's quiet record each asked, and each walked,
    /// before. A block's binding is walked on every ask: its owners rest on other names' capture
    /// generations and, in a called rule's body, on the caller's bindings, which its id does not carry.
    /// Owned by the root scope; every other scope forwards; a scope with no root behind it answers `None`
    /// (the default) and the walk is paid on every ask.
    fn binding_owners_memo(
        &self,
    ) -> Option<Rc<std::cell::RefCell<eval_context::BindingOwnersMemo<'value>>>> {
        None
    }

    /// Told that a `binding_owners` walk gave up at its depth bound (`eval_context::OWNERS_WALK_HOPS`
    /// `let`s followed through their right-hand sides) with the text that names the `let` and the
    /// bound. The walk still answers `None` for that `let` (nobody's binding, the safe side), and the root
    /// keeps the first such text and writes it with the evaluation's notices, so the loss is said rather
    /// than silent; every other scope forwards; a scope with no root behind it drops it (the default).
    fn note_binding_walk_limit(&self, _text: String) {}

    /// Whether this scope, or one it reaches, is the scope of a parameterized rule's call.
    ///
    /// Asked by a block scope answering `binding_owners` for a name it binds. A parameterized rule's
    /// body runs in a block whose queries start where the caller's do, the document for a call from a
    /// rule body, but its `let`s and captures are bound again for every call from that call's arguments
    /// (`let lp = to_lower(%p)`), so the block's start alone would name them as the block's own
    /// bindings and a `when` reading one would be settled by its first call's measurement, with a later
    /// call's move lost. The call scope answers `true`, the root `false`, and every other scope
    /// forwards. No default, for the reason `record_deprecation` has none.
    fn within_parameterized_call(&self) -> bool;

    /// The chain from `variable_name` to the function call it is rooted at, if any: `None` for a name on
    /// no such chain, else the name bound to the call (`root`), whether every hop was an exact alias
    /// (`exact_alias`: `let q = %p`, `let q = %p[*]`, `guarded(%p)`; the shapes
    /// `eval_context::function_result_alias_root` names) and how many `let`s and arguments were followed
    /// (`hops`; 0 for the name bound to the call itself or a parameter handed a call). See
    /// [`eval_context::FunctionChain`].
    ///
    /// The variable-root arm of retrieval passes every unresolved entry the root holds through
    /// unchanged, as clones sharing the result's `Rc`, and the parts after it add their own, for a key
    /// the parsed value lacks, an index past a list's end or an enumeration over an empty list, on values
    /// allocated afresh on every read; so a binding on such a chain mixes the function's entries with the
    /// query's, and only identity tells them apart. Asked by `eval::announce_a_moved_when` for the
    /// conditions of a `when`, to find the names whose reading the measurement changes and to word the
    /// notice ("is a function's result" for an exact alias, "derived from" otherwise), and by
    /// `eval_context::measured_values` under [`Measurement::WithoutUnresolved`].
    ///
    /// A scope that binds nothing answers `None` itself; a scope that forwards lookups forwards this one;
    /// a scope that owns bindings follows its own `let`s first and asks its parent only for a name it
    /// does not bind at all, adding its hops to the parent's answer. A name bound here by anything else
    /// (a literal, a capture, a merged key, a query rooted at no name) is `None` whatever an outer scope
    /// binds. A parameter of a parameterized rule whose argument was a query rooted at a name
    /// (`guarded(%p)`, `guarded(%p.Mode)`) is answered by the parent for that name, with one hop added,
    /// so the answer follows the binding the parent holds rather than a copy taken at the call. No
    /// default; see `reset_captures`.
    fn function_chain(
        &mut self,
        variable_name: &str,
    ) -> Option<eval_context::FunctionChain<'value>>;

    /// The function result's own unresolved entries at the end of `variable_name`'s chain
    /// ([`eval_context::FunctionEntries`]): what a measurement drops from the name, by identity. `None`
    /// for a name on no chain; `Err` when the root could not be read.
    ///
    /// Answered by the scope that BINDS the root, from its own memo, never by the scope that asked: a
    /// walk that leaves a block, or a parameterized rule's call, continues in the parent from the name
    /// it left at, so a same-named binding in the asking scope (a parameter `cfg` over a file-level `let
    /// cfg = json_parse(...)`, a body `let cfg = Resources.A` shadowing it) is never read in the root's
    /// place. A parameter handed a function call is its own root and answers from the values fixed at
    /// the call. Built once per root for the life of the binding scope (its memo is never rewritten) and
    /// shared by `Rc`. No default; see `reset_captures`.
    fn function_result_entries(
        &mut self,
        variable_name: &str,
    ) -> Option<Result<Rc<eval_context::FunctionEntries>>>;

    /// Whether a notice of this `kind` has already been recorded for `site`.
    ///
    /// For an evaluator that has to do work to build a notice -- re-run a predicate, count a selection
    /// -- and would otherwise do it on every evaluation of a clause whose notice is already in the set.
    /// Answered by the root scope, which owns the set; no default, for the reason
    /// `record_deprecation_once` has none.
    fn has_deprecation_site(
        &mut self,
        kind: DeprecationKind,
        site: &exprs::FileLocation<'_>,
    ) -> bool;

    /// The compiled forms of the regex literals of the filter predicate at `site`, one cache per
    /// predicate for the whole evaluation, so a regex literal is compiled once however many maps the
    /// filter meets. Owned by the root scope, keyed by the predicate's position, and reached through
    /// every other scope; an arm visit that started a cache of its own would compile each literal N times
    /// over a template with N map-tagged resources. No default, for the reason
    /// `record_deprecation` has none.
    fn predicate_regexes(
        &self,
        site: &exprs::FileLocation<'_>,
    ) -> Rc<eval_context::CompiledRegexes>;

    /// Whether the filter notice of `kind`, the bound-map filter notice (`FilterOverABoundMap`) or the
    /// member notice after `[*]` (`OwnKeyReadAsAMember`), already decided to stay quiet on the map at
    /// `map_path` for the filter at `site`.
    ///
    /// The quiet sites are not notices: nothing is written for one, and the once-per-site notice table
    /// never holds one, so a reader of that table cannot print one by mistake. They are kept so that the
    /// map's entries are read once per map per site and the next evaluation of the clause over the same
    /// map stops before the probe. Keyed by the map as well as the site, because one site is probed once
    /// per map a binding holds or a wildcard reads, and the verdict on one map says nothing about the
    /// next: a quiet first map must not silence a later map at the same site that lost a selection a rule
    /// relied on. Keyed by the notice's kind as well, because one filter can be read by both notices:
    /// `%r[*][ f ]` through a variable is a filter after the author's `[*]`, which the member notice
    /// reads, and a filter through a bound variable, which the bound-map notice reads, and each probes
    /// and decides on its own. The two cases never decide alike today, since the member exemption needs a
    /// collection whose members share a key name while the bound-map notice's gained path needs an object
    /// of fields (`map_is_an_object_of_fields`), and the kind in the key keeps one notice's quiet verdict
    /// from ending the other's probe when either reading widens. Written and read under the one string
    /// `eval_context::quiet_record_path` gives both callers: the path for a map whose binding chain traces
    /// to the document, the path under the `let`'s name for a function's result a file-level `let` holds
    /// (the path names the function's input, and two results over one string differ), and none for a map
    /// a rules-file literal built, which shares its path with every other literal's and with the
    /// document's at the same depth, or for a function's result nothing file-level holds. Answered by the
    /// root scope, which owns the set and lives for
    /// one data file or test case; no default, for the reason `record_deprecation_once` has none.
    fn has_quiet_filter_site(
        &mut self,
        kind: DeprecationKind,
        site: &exprs::FileLocation<'_>,
        map_path: &str,
    ) -> bool;

    /// Whether the set holds a quiet record of `kind` for the filter at `site` under ANY map: the question
    /// both notices ask before they compute the key a record is read under (`quiet_record_path`,
    /// `member_quiet_record_path`: a provenance walk of up to sixteen hops and one `String` per map per
    /// evaluation), so a site with no record pays no walk. A notice that walked first and asked the set
    /// second would pay that walk on every evaluation of every filter through a bound map, for a reading
    /// nothing reads when the set holds nothing for the site. Answered by the root scope, which owns the
    /// set; no default, for the reason `has_quiet_filter_site` has none.
    fn has_quiet_record_at(
        &mut self,
        kind: DeprecationKind,
        site: &exprs::FileLocation<'_>,
    ) -> bool;

    /// Record that the filter notice of `kind` stays quiet on the map at `map_path` for the filter at
    /// `site`; see [`EvalContext::has_quiet_filter_site`]. Nothing is recorded under a measurement by
    /// either caller, which returns before it asks, so the set needs no measurement check of its own.
    fn record_quiet_filter_site(
        &mut self,
        kind: DeprecationKind,
        site: &exprs::FileLocation<'_>,
        map_path: &str,
    );

    /// Where `variable_name` is bound, as its author wrote it, for a notice that names the binding.
    ///
    /// Distinct from `variable_binding_query`, which answers a different question -- did resolving the
    /// name enumerate -- and so follows a bare `%v` chain to the query at its end and reports a
    /// parameter's call-site argument as the binding. A notice that says `let b = Resources.Metadata`
    /// for a file that reads `let b = %a`, or `let m = ...` for a parameter `m`, names a line that is
    /// not in the file; this reports the `let` the name itself appears in, or the parameter and the rule
    /// it belongs to with the argument the call site bound it to, whatever kind of argument that was.
    /// A `let` bound to a literal or to a function call is reported as that `let`. `None` when the
    /// name is bound by a filter capture in the answering scope -- a capture may shadow an outer `let`
    /// of the same name, and the maps it holds are its own, so the lookup stops at it rather than
    /// reaching the `let` -- or not bound at all. No default, for the reason `record_deprecation_once`
    /// has none: a forwarding scope has to forward it.
    fn variable_binding_source(
        &mut self,
        variable_name: &str,
    ) -> Option<BindingSource<'value, 'loc>>;

    /// How the quiet verdict on a map named by `variable_name` is keyed, read from where the map came
    /// from (see [`eval_context::quiet_record_key`]), with every hop of the binding walk taken in the
    /// scope that OWNS the binding it found. A scope that owns bindings answers for a name it binds
    /// from its own stores ([`eval_context::quiet_record_key_of_binding`]) and continues the walk from
    /// itself, so a file-level `let doc = json_parse(%s)` reads the file-level `s` whatever `s` the
    /// rule body that filters `%doc` binds; asked of the body's scope instead, that `s` was the body's
    /// document query and the parsed rules-file string was keyed by its path. A name this scope binds by
    /// a filter capture or a merged key is a chain that cannot be read (`QuietRecordKey::PathByFallback`);
    /// a name it does not bind is its parent's to answer. A scope that forwards lookups forwards this
    /// one. The called rule's scope (`ResolvedParameterContext`) answers a parameter from its argument
    /// read in the CALLER's scope ([`eval_context::quiet_record_key_of_argument`]): the argument is
    /// written at the call site, so a `%name` at its head is the caller's name, and asked of the called
    /// rule's own scope a name the two rules share (`rule outer(m) { inner(%m) }`) answered the parameter
    /// again and looped to the bound. A scope with no parent answers `PathByFallback` for a name it does
    /// not bind. `hops_left` is the walk's remaining budget, spent one per head followed and carried
    /// across scopes so a cycle through two rules still stops. No default, for the reason
    /// `variable_binding_source` has none: a forwarding scope has to forward it.
    fn quiet_record_key_step(
        &mut self,
        variable_name: &str,
        hops_left: usize,
    ) -> eval_context::QuietRecordKey;

    /// How the quiet verdict on a map reached from THIS scope's root is keyed: the provenance of the
    /// root a `this` or key head reads, asked by the member notice for a filter whose query names no
    /// variable (`eval_context::member_quiet_record_path`), so the record is keyed by provenance
    /// under every spelling, as it is for a `%variable` head. The root scope's root is the document
    /// (`QuietRecordKey::Path`); a scope that rebases the root onto a value a `%variable` held answers
    /// from that binding's chain ([`EvalContext::quiet_record_key_step`], `hops_left` the walk's
    /// budget); one that rebases onto a value the enclosing scope's own root produced (a block over a
    /// document key, a filter's entry, a wildcard's member) asks the scope above it; a scope that
    /// forwards lookups forwards this one. A `%name` head whose binding is a `let` over a `this` or key
    /// query reaches this through the binding walk (`eval_context::quiet_record_key_from_head`), so `%m {
    /// let s = this  %s[*][ f ] empty }` is keyed as `%m { this[*][ f ] empty }` is. Before it was asked,
    /// `rule chk(m) { %m { this[*][ f ] empty } }` called with a rules-file literal's sub-map recorded
    /// quiet at the literal's path and silenced the document's map at the same path on the next call,
    /// and a `[*]` arm inside a nested predicate over `%m.*` did the same; the `let s = this` spelling
    /// did so until the walk asked the owning scope. No default, for the reason `quiet_record_key_step`
    /// has none.
    fn root_quiet_record_key(&mut self, hops_left: usize) -> eval_context::QuietRecordKey;

    /// Whether `variable_name` is held in this scope or one it reaches, so that `resolve_variable`
    /// answers from what is held (a literal, a key a filter captured, a key merged up from a block, a
    /// memoized `let`, a parameter's values as the call site computed them) and computes nothing.
    ///
    /// Asked by `eval::announce_a_moved_when` to decide whether a `when` is measured at all: a name the
    /// real run never reached, because an `or` was decided by its other side, is not computed for that
    /// decision. A scope that owns bindings answers from what it holds for a name it binds, and for a
    /// name it binds by a call or a query it has not read yet answers `false` even when an outer scope
    /// holds a `let` of the same name; it defers to its parent for a name it does not bind. A scope that
    /// forwards lookups forwards this one; a scope that binds nothing answers `false`. No default; see
    /// `reset_captures`.
    fn variable_is_resolved(&self, variable_name: &str) -> bool;
}

/// Where a variable is bound, for a notice that names the binding; see
/// [`EvalContext::variable_binding_source`]. Each variant carries what the scope already holds for the
/// binding, so a notice is rendered from the same stores resolution reads.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum BindingSource<'value, 'loc: 'value> {
    /// A `let` whose value is this query, as written -- `let b = %a` reports `%a`, not what `a` is.
    Let(&'value exprs::AccessQuery<'loc>),
    /// A `let` whose value is a literal: the value the scope resolves the name to. A map written out
    /// in the rules file can lose a filter's selection exactly as a map a key path bound can; the
    /// notice elides it rather than printing it whole.
    Literal(std::rc::Rc<path_value::PathAwareValue>),
    /// A `let` whose value is a function call: `let doc = json_parse(...)` is reported as that call
    /// with its arguments as written, not as the value the call produced.
    FunctionCall(&'value exprs::FunctionExpr<'loc>),
    /// A parameterized rule's parameter, with the rule's name and the argument the call site passed:
    /// a query, a literal or a function call, each losing a filter's selection as the `let` of the
    /// same kind does.
    Parameter {
        rule: &'value str,
        argument: &'value exprs::LetValue<'loc>,
    },
}

/// What the evaluator is doing when it is not evaluating: re-running a `when`'s conditions to learn what
/// they answered before this release.
///
/// `resolve_function` keeps the entries a function has no answer for, so a condition over a function's
/// result reads them along with the values that resolved. To tell a rule author whose `when` answers
/// differently for that reason, `eval::announce_a_moved_when` evaluates the conditions a second time with
/// those entries dropped, through the real scopes and the real query path, and compares. While a
/// measurement is on, the
/// root scope records nothing and raises no notice, and nothing it or any scope writes under it reaches
/// the real run: the run is a reading taken after the real evaluation has written its report, and a
/// reading that wrote into the report, or left a memo or a capture computed from dropped entries for the
/// real run to find, would be measuring itself. What a reading does keep is its own: a scope built for
/// it (a called rule's scope, the block its body builds, the maps set aside for a referenced rule)
/// writes and memoizes, since it is dropped with the reading; and an assignment or block-level `let`
/// the reading is the first to resolve is memoized and its captures written where the real run would
/// write them, with every such write logged and taken back when the reading ends
/// (`eval_context::ReadingUndo`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Measurement {
    /// Evaluating; the only mode that writes.
    Off,
    /// Reading the conditions as written, writing nothing: the per-condition answers of this release.
    Quiet,
    /// Reading with a function result's unresolved entries dropped, writing nothing: the answers of the
    /// release before this one.
    WithoutUnresolved,
}

/// Which way a `when`'s answer moved between the release before this one and this one.
///
/// A `when` evaluated for several resources (a type block's condition, a `when` block in a block's body)
/// or for several calls can move one way for one resource and the other way for the next, and the two
/// are not one fact: a block that ran and is skipped now is a check that went quiet, a block that was
/// skipped and runs now is a check that appeared. The notice and the settled record are keyed on the
/// direction beside the `when`, so each direction gets its line and neither hides the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum MoveDirection {
    /// The `when` passed before this release and does not pass now: its block ran and is skipped.
    RanBeforeSkipsNow,
    /// The `when` did not pass before this release and passes now: its block was skipped and runs.
    SkippedBeforeRunsNow,
}

impl MoveDirection {
    /// The one direction a `when` answering `now` can have moved in. A move is a change between passing
    /// and not, so a `when` that passes now can only have failed before and one that fails now can only
    /// have passed: the direction is known from this release's answer alone, before any measurement.
    pub(crate) fn of_now(now: Status) -> Self {
        if now == Status::PASS {
            MoveDirection::SkippedBeforeRunsNow
        } else {
            MoveDirection::RanBeforeSkipsNow
        }
    }
}

/// How a comparison that left a refused read among its values unraised was decided, for the line that
/// reports it (`EvalContext::record_unraised_refusal`): a value that holds settled it (a listed value
/// under `IN`, another value under `some`), a value the document lacks decided it, a value that does not
/// match decided it (a resolved mismatch under `==`, an ordering or `IN`), a value that MATCHES a denied
/// entry decided it (a resolved collision under `!=` or `NOT IN`, the negated comparators' no), or a value
/// of another KIND decided it (a pair the comparator refused on kinds under `!=` or `NOT IN` beside the
/// marker, `Port != %x` with `Port: 22` and `'ssh'` listed: a decided no that compared nothing, so it
/// matched no denied value; under a positive comparator such a pair "does not match" and keeps that
/// wording). The
/// verdict stands either way; the line says which value decided it so a reader knows why the refusal was
/// not raised, and words the no by the comparator's polarity, since the value that decided `Names[*] NOT
/// IN %x` matched a listed entry and "does not match" would say the opposite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnraisedVerdict {
    Passed,
    DecidedByAbsence,
    DecidedByMismatch,
    DecidedByCollision,
    DecidedByKinds,
}

/// The kinds of one-release notice recorded once per call site; see
/// [`EvalContext::record_deprecation_once`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DeprecationKind {
    /// A `when` over a function's result that answers differently now that the result keeps the entries
    /// the function had no answer for, moving in the given direction. The direction is part of the kind
    /// so that a `when` whose resources moved both ways gets one line per direction and no more.
    FunctionResultGate(MoveDirection),
    /// A function call whose answer moved because a list value among its arguments is read as its
    /// elements.
    ListArgumentExpansion,
    /// A filter through a variable that selected nothing from a map the variable held, where the previous
    /// release selected that map. The sites this notice decided to stay quiet on are not notices and are kept
    /// apart, in the root scope's quiet-site set; see [`EvalContext::record_quiet_filter_site`].
    FilterOverABoundMap,
    /// A key filter whose string right-hand value is read as a value the key is equal to, where the
    /// previous release read it as text the key could be contained in, with the selection moving for a key.
    KeyFilterContainment,
    /// A negated key filter over two or more right-hand values that leaves out a key equal to one of
    /// them under the ALL fold, where the previous release's ANY fold selected it because another differed.
    KeyFilterFold,
    /// A filter after the author's `[*]` whose predicate names a key of the map that is also the name of
    /// one of its members (`Resources[*][ BucketA exists ]` over resources sharing `Type`), read as a
    /// selection among the members where the previous release handed the map on whole and asked the
    /// predicate of the map itself. Not raised after `.*`, which enumerated the entries then as now.
    OwnKeyReadAsAMember,
    /// A pair-shaped filter after `[*]` (`[ Key == 'Env' ]`) that met a one-object map of scalars
    /// (`Tags: { Env: dev }`) and decided it by the map's `{ Key, Value }` list twin, keeping a pair
    /// the previous release's one-object reading did not select. One line per filter site, written for
    /// the first such map the filter met.
    ListTwinOfAScalarMap,
}

impl DeprecationKind {
    /// The kind in words, for a line that refers to a notice without repeating it: the trailer the
    /// single-line `validate` output writes after its data files names which notice at a site the later
    /// files drew. One `when` site holds a notice per direction, so the direction is part of the words,
    /// spelled as the notice itself spells it.
    pub(crate) fn described(&self) -> &'static str {
        match self {
            DeprecationKind::FunctionResultGate(MoveDirection::RanBeforeSkipsNow) => {
                "the gate notice (its block ran before and is skipped now)"
            }
            DeprecationKind::FunctionResultGate(MoveDirection::SkippedBeforeRunsNow) => {
                "the gate notice (its block was skipped before and runs now)"
            }
            DeprecationKind::ListArgumentExpansion => "the list-argument notice",
            DeprecationKind::FilterOverABoundMap => "the filter notice",
            DeprecationKind::KeyFilterContainment => "the key-filter containment notice",
            DeprecationKind::KeyFilterFold => "the key-filter fold notice",
            DeprecationKind::OwnKeyReadAsAMember => "the member notice",
            DeprecationKind::ListTwinOfAScalarMap => "the list-twin notice",
        }
    }
}

pub(crate) trait EvaluationContext {
    fn resolve_variable(&self, variable: &str) -> Result<Vec<&PathAwareValue>>;

    fn rule_status(&self, rule_name: &str) -> Result<Status>;

    #[allow(clippy::too_many_arguments)]
    fn end_evaluation(
        &self,
        eval_type: EvaluationType,
        context: &str,
        msg: String,
        from: Option<PathAwareValue>,
        to: Option<PathAwareValue>,
        status: Option<Status>,
        comparator: Option<(CmpOperator, bool)>,
    );

    fn start_evaluation(&self, eval_type: EvaluationType, context: &str);
}

pub(crate) trait Evaluate {
    fn evaluate<'s>(
        &self,
        context: &'s PathAwareValue,
        var_resolver: &'s dyn EvaluationContext,
    ) -> Result<Status>;
}

/// The long name a `!Foo` short form stands for.
///
/// CloudFormation's rule is that `!Foo` is the short form of `Fn::Foo`, with `Ref` and `Condition`
/// the two names that carry no `Fn::` prefix; `SHORT_FORM_TO_LONG_MAPPING` is that pair plus the
/// names spelled out. The `Fn::` fallback is what makes this total, and total is what it has to be:
/// this replaced a `short_form_to_long` whose miss arm was `unreachable!()`, which was only true
/// because every caller checked one of two hand-written sets first, and those sets had gone stale.
/// Cidr, ForEach, GetStackOutput, Length, ToJsonString, Transform and ValueOfAll are all in the
/// Template Reference and were in neither set, so their short forms lost their tags entirely.
///
/// A name AWS has not published resolves the same way, which is the deliberate consequence: the
/// alternative is to keep a list that has already fallen behind once, and a tag this function cannot
/// name is a tag the loader would otherwise drop. Preserving it under the name CloudFormation would
/// give it is wrong for no template AWS accepts, and right for every intrinsic added after this
/// commit.
pub fn long_form_of(short: &str) -> Cow<'static, str> {
    match SHORT_FORM_TO_LONG_MAPPING.get(short) {
        Some(long) => Cow::Borrowed(long),
        None => Cow::Owned(format!("Fn::{short}")),
    }
}
