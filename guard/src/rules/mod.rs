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
/// `reason`, and this is what the engine does with the marker, not what the author sees. `Debug` is
/// written by hand below so that it does not read the refusal token's count, and no equality is offered
/// (see `reading`).
#[derive(Clone, Copy, Default)]
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
    /// predicate's query leaves it with its refusal token set (`eval_context::to_refusal_result`, through
    /// `deliver_wildcard_filter_refusal`): every operator reads the two alike (`is_undecidable`), and only
    /// the filter loop whose walk returned the marker tells them apart (`is_refusal`), cutting its
    /// captures back on a refusal of the rest of its query and not on a marker an inner filter left for
    /// one value it could not decide, since the selection keeps that value's siblings. The token is data
    /// on the one variant rather than a sibling variant, so a site that matches `Undecidable` has to say
    /// which it reads: a sibling variant was opted out of silently by every existing pattern (one read a
    /// refused capture as a key the map lacks, and a `some` over it passed on a decided sibling).
    Undecidable {
        /// The refusal's token when the marker is a refusal delivered inside a predicate: the number
        /// minted where the refusal was delivered (`eval_context::mint_refusal_token`, counted up on this
        /// thread and never reused), which the error a clause raises over the marker copies
        /// (`eval::undecidable_selection`), so the filter predicate run that error ends can tell a
        /// refusal minted inside it from one minted before it began. `None` for a value nobody could
        /// decide, and for an entry a run left plain because the refusal that ended it was minted
        /// before the run began: that token rides in `carried` instead.
        refusal: Option<errors::RefusalToken>,
        /// A refusal's token the marker hands on without being that refusal's marker: the token of the
        /// error that ended a filter predicate run when the refusal was minted BEFORE the run began (a
        /// capture bound outside the predicate holding a refusal's marker, read inside it), kept here
        /// so the error a clause raises over this marker (`refusal`) carries it to the run that
        /// encloses the one that left the entry plain. Every run decides "a refusal of this run" by
        /// reading the token against the count it opened at (`eval_context::RefusalFrame`), never by
        /// dropping the token, so a refusal minted inside an outer run and read by an inner one marks
        /// the OUTER entry whatever the inner run leaves (`eval_context::to_undecidable_result`). `None`
        /// when `refusal` is set (the token is that one) and for a value nobody could decide.
        carried: Option<errors::RefusalToken>,
    },
}

/// Printed as the two facts a reader of a record dump compares, the kind and whether it is a refusal
/// (`Undecidable { refused: true }`), never the token: the token is a per-thread count that differs between
/// two evaluations of one rules file, and the tests that compare two runs' record dumps record for record
/// must read the same dump for the same verdicts. A token the marker carries for an enclosing run
/// (`carried`) is transport, not a fact about the entry, and is not printed either.
impl std::fmt::Debug for UnResolvedKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, refused) = self.reading();
        match self {
            UnResolvedKind::Undecidable { .. } => {
                f.debug_struct(kind).field("refused", &refused).finish()
            }
            UnResolvedKind::Absent | UnResolvedKind::EmptyEnumeration => f.write_str(kind),
        }
    }
}

/// The evaluator offers no equality for this kind, nor for the `UnResolved`, `QueryResult` and record
/// types that carry it; test builds derive one through `reading` (below). The token decides which marker a
/// fold keeps and whether a run's entry is refused (`eval::would_replace`,
/// `eval_context::RefusalFrame::minted_inside`), so an equality that ignored it, as a hand-written one did
/// in every build (two markers were equal when both were refusals or neither was, whatever count each
/// token carried, the reading `Debug` prints), could stand in for those readers in a `contains` or a dedup
/// over markers, keeping the older-minted one with no test going red; and a derived equality read the
/// counts, so two markers that printed alike compared unequal, and an `assert_eq!` over them failed with
/// identical sides. Neither is what a production caller means by `==`, so production has none: a site
/// that wants the kind and whether it is a refusal reads `reading`, and the token is read through
/// `RefusalToken::later_than`, by `would_replace` alone. Every production comparison over a `QueryResult`,
/// an `UnResolved` or this kind was read for that (`eval.rs`, `eval_context.rs`, `eval/`, this file):
/// `key_filter::stands_for_no_entry` matches a kind against `EmptyEnumeration`, a variant with no token;
/// `FunctionEntries::contains` compares an entry's `remaining_query` and `reason` by field and never its
/// kind; the key filter's rendering of its holders and the operators' membership compare
/// `PathAwareValue`s. No production site compares two `QueryResult`s or two markers whole, and no marker
/// list is searched or deduplicated by equality; the compiler says so now, where this comment said it. The
/// tests that compare two runs' record dumps record for record keep `assert_eq!`: under `cfg(test)` the
/// kind is equal by `reading`, the two facts `Debug` prints, and the carriers derive `PartialEq` over it.
impl UnResolvedKind {
    /// The two facts a reader of a record dump compares, the kind's name and whether an `Undecidable`
    /// marker is a refusal, with no token in either: `("Absent", false)`, `("EmptyEnumeration", false)`,
    /// `("Undecidable", refused)`. `Debug` prints these two and nothing else, and the test-build equality
    /// below compares them, so the two cannot drift apart. Two markers of one refusal read alike though
    /// their tokens were minted apart, and a refused marker and a plain one read apart; a token the marker
    /// carries for an enclosing run (`carried`) is transport, not a fact about the entry, and is not read.
    /// The pin is `two_markers_of_one_refusal_read_alike_whatever_their_tokens_count`.
    pub(crate) fn reading(&self) -> (&'static str, bool) {
        match self {
            UnResolvedKind::Absent => ("Absent", false),
            UnResolvedKind::EmptyEnumeration => ("EmptyEnumeration", false),
            UnResolvedKind::Undecidable { refusal, .. } => ("Undecidable", refusal.is_some()),
        }
    }
}

/// Test builds only: equal by `reading`, so a record-dump test's `assert_eq!` over two runs compares what
/// the dump prints and never the token's count (two markers of one refusal, minted apart, are equal; a
/// refused marker and a plain one are not; `carried` is not read). Production builds have no `==` over
/// this kind or its carriers, which is the point of the gate: see the comment above `reading`.
#[cfg(test)]
impl PartialEq for UnResolvedKind {
    fn eq(&self, other: &Self) -> bool {
        self.reading() == other.reading()
    }
}

#[cfg(test)]
impl Eq for UnResolvedKind {}

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
        matches!(
            self,
            UnResolvedKind::Undecidable {
                refusal: Some(_),
                ..
            }
        )
    }

    /// The refusal's token the marker carries: its own when the marker is a refusal (`is_refusal`), else
    /// the one it hands on for an enclosing filter predicate run (`carried`: a refusal minted before the
    /// run that left this entry plain, or the refusal a key filter's right-hand side raised, whose marker
    /// for the map is rebuilt plain because that arm has no run to read the token against; a right-hand
    /// side refused as unevaluatable, a filter over a string or a one-object map under `[*]`, carries no
    /// token in its error, so the key-filter arm recovers the one `refuse` minted when it registered the
    /// sentence (`token_of_registered`) and the marker carries that; a right-hand query that resolved to
    /// an ABSENCE, a key the filtered map lacks, is no refusal, so that marker carries none and the entry
    /// it is met under stays plain), `None` for a value nobody could decide and for every other kind.
    /// What the error a clause raises over the marker carries in its second field
    /// (`Error::UndecidableComparison`), copied from here so the filter predicate run it ends reads
    /// where the refusal was minted against the count that run opened at, at any depth of nesting.
    pub(crate) fn refusal(&self) -> Option<errors::RefusalToken> {
        match self {
            UnResolvedKind::Undecidable { refusal, carried } => refusal.or(*carried),
            UnResolvedKind::Absent | UnResolvedKind::EmptyEnumeration => None,
        }
    }
}

/// Equality in test builds only: `kind` carries the refusal token, which `eval::would_replace` and
/// `eval_context::RefusalFrame::minted_inside` decide on, so the evaluator offers no whole-value equality
/// that could stand in for those readers (see `UnResolvedKind::reading` and the `PartialEq` under
/// `cfg(test)` beside it, which the record-dump tests compare through).
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct UnResolved {
    pub(crate) traversed_to: Rc<PathAwareValue>,
    pub(crate) remaining_query: String,
    pub(crate) reason: Option<String>,
    #[serde(skip)]
    pub(crate) kind: UnResolvedKind,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) struct ComparisonClauseCheck {
    pub(crate) comparison: (CmpOperator, bool),
    pub(crate) from: QueryResult,
    /// `None` for an unresolved `from` with nothing to show beside it; a left-hand marker decided by a
    /// right-hand side the document lacks carries the first absent right-hand value here, so the record
    /// names what the marker was compared against (`eval::binary_operation`, the `LhsUnresolved` arm).
    pub(crate) to: Option<QueryResult>,
    pub(crate) message: Option<String>,
    pub(crate) custom_message: Option<String>,
    pub(crate) status: Status,
    /// Whether `message` embeds a REFUSAL's reason: the record of a left-hand value the document lacks
    /// decided beside a refused `%name` among the right-hand values carries the retrieval's own reason
    /// and the refusal's text beside it, the record of a refused `%name` on the left decided by a
    /// right-hand side the document lacks carries that absence's reason and the refusal's text after it,
    /// the record of a left-hand value paired with the refusal's marker under a positive `IN` carries the
    /// refusal's text as its reason, and the record of a left-hand value that is itself a refusal's
    /// marker (the `LhsUnresolved` arm of `eval::binary_operation`: the refused map's marker,
    /// `UnResolvedKind::is_refusal`) carries the marker's reason, the refusal's own sentence. Set where
    /// the record is written, by the ONE reading of a marker as a refused read (`eval::is_refused_read`,
    /// `eval::refused_read_text`: a refusal's marker by kind, or a plain marker whose reason the registry
    /// holds), on either side of the comparison alike, as [`ValueCheck::refusal`] is set from the error's;
    /// the reporters' `Messages::refusal` is copied from here, so the console prints such a message whole
    /// where it cuts every other to `LONGEST_RECORDED_MESSAGE`, and a refusal's remedy and path are not cut
    /// off its record. A key filter's marker whose reason the registry does not hold (a spent regex budget,
    /// a map nobody could decide) is no refusal and reads `false`; the key filter's marker for a map whose
    /// right-hand query was refused carries the refusal's registered sentence and reads `true`, on the
    /// left as on the right, so `some %s != Properties.Name` and `some Properties.Name != %s` over one
    /// such marker in `%s` record one flag. Not serialized: the record tree `--print-json` writes keeps
    /// its shape.
    #[serde(skip)]
    pub(crate) refusal: bool,
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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
#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
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

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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
    /// The error the reference failed on, stored once: `Some` exactly where `message` carries the error's
    /// account, `None` for a reference that merely did not pass. Every reader keys on this one field, so
    /// the record cannot say "raised" through one reader and "not raised" through another. Not part of any
    /// structured output (`serde(skip)`).
    #[serde(skip)]
    pub(crate) failure: Option<ReferenceFailure>,
}

/// The error a failed rule reference raised: its own text, the refusal token it carried, and whether it is
/// a refusal (`eval_context::is_refusal`). The console keeps a refusal's remedy past the bound a plain
/// message gets, from `refusal` (no structured report serializes the flag); a failed condition's walk names
/// the refusal from `text` and `token`, never recovered from the words of `MissingValueCheck::message`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ReferenceFailure {
    pub(crate) text: String,
    pub(crate) token: Option<crate::rules::errors::RefusalToken>,
    pub(crate) refusal: bool,
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

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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
    /// Whether the record was written on a RAISE (an error the clause met and handled: a clause-error
    /// record, a refused read, a fail-closed negation) and not for a DECIDED answer (a missing property, a
    /// comparison that did not hold, an empty selection explained). The reporters' walk of a failed
    /// condition keeps a block record by this flag, by its children or by its refusal flag, never by the
    /// mere presence of `message`: a decided empty selection keeps its explanatory message and is still no
    /// finding. Not part of any structured output (`serde(skip)`).
    #[serde(skip)]
    pub(crate) raised: bool,
    /// The author's own `<< >>` message on the clause the record closes, set wherever the clause carries
    /// one and the block shape is the record of that clause: the fail-closed `not` over a reference (`not r
    /// << msg >>`, `eval::record_fail_closed_negation`, whose record is a block check so the message can
    /// carry the refusal flag the `DependentRule` value check has no field for), an access clause decided
    /// over an empty selection or whose query or comparison raised, a call whose argument could not be
    /// evaluated. Read by the reporters where they read a dependent rule's (`custom_message` of the
    /// structured output and the console summary's finding). `None` on the reference's SKIP record (the
    /// author's text explains a failure, and that record's sentence is the rule's skip reason) and on every
    /// block check the grammar gives no message (a block, a `when`, a type block, a disjunction); the record
    /// tree `--print-json` writes keeps its shape for those, since the key is written only where it is set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) custom_message: Option<String>,
    /// Whether the record is the GATE role's mark for one refused body: a childless failed record that
    /// carries the refusal's bare sentence beneath a block (`eval::refused_body_block_check`). Read by
    /// `eval_context::is_gate_mark`, so a mark is told by this field and never by the shape of the
    /// records of the strict role, which are childless, failed, raised refusals with a sentence in the
    /// same context and are findings of their own. Not part of any structured output (`serde(skip)`), and
    /// the context string of a mark is the block's own, so the `--print-json` tree keeps its shape.
    #[serde(skip)]
    pub(crate) gate_mark: bool,
    /// The refused reads the entries of the condition of an inline `when` or a type block carried when the
    /// condition raised an unevaluatable error and the block failed closed on it
    /// (`eval::convert_condition_raise`: the frame's `AbsorbedRaise::reads`), as `NamedStatus::frame_reads`
    /// carries them for a rule's own `when`. Compared by the report walk with the refusals it collected
    /// (`eval_context::assert_frame_reads_told`). Empty for a record that converted nothing. Not part of any
    /// structured output.
    #[serde(skip)]
    pub(crate) frame_reads: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub(crate) struct NamedStatus<'value> {
    pub(crate) name: &'value str,
    pub(crate) status: Status,
    pub(crate) message: Option<String>,
    /// Whose text `message` holds; see [`CustomSlot`]. Set once, where the record is built: a rule whose
    /// condition raised a refusal writes [`CustomSlot::Refusal`] (the console prints that rule's line
    /// whole), the evaluator's call-site copy of a `<< >>` body writes [`CustomSlot::Author`].
    #[serde(skip)]
    pub(crate) slot: CustomSlot,
    /// The rule's own sentence a calling clause's `<< >>` body displaced from `message` (the sentence a
    /// rule whose own `when` could not be evaluated writes, `eval::judged_rule_body`), with its kind
    /// ([`CustomSlot::Evaluator`] or [`CustomSlot::Refusal`]): the record reports the body as `message`, as
    /// every reader of a rule record's message expects, and keeps the sentence beside it so a refusal is
    /// not reported as an ordinary failure of the author's rule. `None` where nothing was displaced.
    /// Reported as the rule report's error message (`eval_context::report_all_failed_clauses_for_rules`).
    /// The record tree (`--print-json`) writes the sentence under `displaced_message` where one was
    /// displaced and nothing otherwise; the kind stays in memory (`serialize_displaced_text`).
    #[serde(
        rename = "displaced_message",
        skip_serializing_if = "Option::is_none",
        serialize_with = "serialize_displaced_text"
    )]
    pub(crate) displaced: Option<(CustomSlot, String)>,
    /// The refused reads the entries of a rule's own `when` carried when its condition raised an
    /// unevaluatable error and the rule failed closed on it (`eval::convert_condition_raise`: the frame's
    /// `AbsorbedRaise::reads`). No refused-read line is written for them any more; the report walk tells
    /// them from the condition's records, and compares them with what it collected, so a read that the
    /// frame held and no record names is caught (`eval_context::assert_frame_reads_told`, a debug
    /// assertion). Empty for a record that converted nothing. Not part of any structured output.
    #[serde(skip)]
    pub(crate) frame_reads: Vec<String>,
    /// Whether an error ended the evaluation of the rule's body: the record was closed on the `Err` of the
    /// body (`eval::judged_rule_body`), not on a decided status. The report states "the rule failed on an
    /// error" from this signal alone, whatever the refusal lists hold (`eval_context::RULE_FAILED_ON_AN_ERROR_HEAD`).
    /// Carried onto the record a calling clause's body rebuilds (`ResolvedParameterContext::end_record`).
    /// Not part of any structured output.
    #[serde(skip)]
    pub(crate) ended_by_error: bool,
}

/// The text of a message slot when it says something: not absent, not empty and not only whitespace
/// (`<<   >>` parses and says nothing). The one test for a blank message, read by the evaluator when it
/// decides whether a call carries a body (`eval::ResolvedParameterContext::end_record`), by the rule
/// report's own-message reader and its silence test (`eval_context::RuleReport`), and by the console and
/// JUnit reporters, so no reader keeps a blank body that another drops.
pub(crate) fn non_blank(message: &Option<String>) -> Option<&str> {
    message.as_deref().filter(|text| !text.trim().is_empty())
}

/// Writes the text of a displaced sentence and not its kind (`NamedStatus::displaced`); a record with
/// nothing displaced is skipped before this is reached.
fn serialize_displaced_text<S: serde::Serializer>(
    displaced: &Option<(CustomSlot, String)>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    match displaced {
        Some((_, text)) => serializer.serialize_str(text),
        None => serializer.serialize_none(),
    }
}

/// Whose text a rule record's `message` slot holds. The slot holds exactly one of three things and the
/// text cannot say which (an error that wraps another error displays the same wrapper a refusal does, and
/// an author's prose can quote anything), so the record does. The console picks the escape set and the
/// cut from it: the relaxed set and no refusal bound for an author's prose (a joiner or a mark in prose is
/// ordinary text), the strict set for the evaluator's sentence, which quotes keys from the rules file and
/// the template, and the refusal pipeline for a refusal. One value, so a record cannot say "refusal" and
/// "author" at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum CustomSlot {
    /// The evaluator's own sentence, or no message at all.
    #[default]
    Evaluator,
    /// The rule author's own `<< >>` body, copied onto the record of a called rule by the evaluator
    /// (`eval::ResolvedParameterContext::end_record`).
    Author,
    /// The evaluator's sentence about a read it refused (`eval_context::is_refusal`); see
    /// [`ValueCheck::refusal`].
    Refusal,
}

impl<'value> Default for NamedStatus<'value> {
    fn default() -> NamedStatus<'static> {
        NamedStatus {
            name: "",
            status: Status::PASS,
            message: None,
            slot: CustomSlot::Evaluator,
            displaced: None,
            frame_reads: Vec::new(),
            ended_by_error: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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
    ///
    /// The answer is the rule's `Judged`: a PASS, a SKIP, or a FAIL with the BASIS it rests on
    /// (`FailBasis`: whether the rule's folds decided a no, or the FAIL rests on reads the rule could not
    /// decide, with those reads). The basis travels with the outcome, never as state on the context, so
    /// every site that answers FAIL names its basis and a cache stores the judged answer; a reference's
    /// `not` reads it (`eval::negate_a_failed_rule`).
    fn rule_status(&mut self, rule_name: &'value str, role: eval::ClauseRole) -> Result<Judged>;
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
    ///
    /// Returns whether a line now stands for this capture at this site: `true` from the root scope
    /// evaluating (the first text, or the one already there), `false` under a measurement and from a
    /// quiet probe, which record nothing. The caller that keys a refusal as announced
    /// (`eval_context::refuse_unbound_capture`) reads it, so the announced set holds a reason only where
    /// the warning channel names it.
    fn record_capture_warning(
        &mut self,
        site: &exprs::FileLocation<'_>,
        capture: &str,
        notice: String,
    ) -> bool;

    /// Note that a filter through a variable at `site` (its first predicate clause) read the mixed map at
    /// `map` as one object where the same filter on the map's own path keeps one or more of its entries
    /// (`eval_context::announce_a_mixed_map_read_as_one_object`). The same rules as `record_warning`:
    /// nothing is recorded during a measurement, no default. Keyed by the site alone, under its own kind
    /// (`WarningKind::MixedMapReadAsOneObject`): one line per filter site, the first map's text, with a
    /// count of the further maps read as one object at the site. A warning and not a deprecation: the
    /// two spellings' disagreement is a lasting difference, not a reading being retired.
    fn record_mixed_map_warning(
        &mut self,
        site: &exprs::FileLocation<'_>,
        map: &str,
        notice: String,
    );

    /// Note that a comparison at `site` (written as `context`) was decided without raising the REFUSED
    /// reads among its values, on either side (`refusals`, one text each): the clause's verdict
    /// (`verdict`, one per `UnraisedVerdict` variant: a value that holds settled it, a value the document
    /// lacks decided it, a
    /// value that does not match decided it, a value that matches a denied entry decided it, a value of
    /// another kind decided it; a sibling entry's failure decided the every-entry block whose body raised
    /// beside the refused read, or a sibling entry's pass settled the `some` block, the block fold's own
    /// calls; a sibling clause's failure decided the conjunction past the raise, or a sibling clause's
    /// pass decided the disjunction past it, the conjunction fold's own calls; the negation of a referenced
    /// rule that failed passed its leaf FAIL; or a fold found an entry where its invariant says none can be,
    /// the neutral word) never raised them, and the
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

    /// Open a frame that collects the raises a block body makes beside a refused read while it is the
    /// innermost open frame: the channel by which a comparison's raise reaches the block fold that may
    /// absorb it (`eval::eval_guard_block_clause` opens one around each value's body and closes it after,
    /// whatever the body answered; `eval::eval_conjunction_clauses` opens one around each conjunction it
    /// folds, since a sibling clause decides past a raise there). The raise itself cannot carry what the
    /// fold needs: the error's variant holds a text and a refusal token, and every `match` on it would
    /// widen with a third field; a frame is held by
    /// the root and reached through the resolver chain the fold and the raise site already share, so the
    /// clause as written, its own position and the reads it met travel out of band and arrive at the one
    /// fold that opened the frame. Nested frames stack: a block inside a value's body opens its own and
    /// closes it before the outer closes, so a raise is collected by the innermost body around it. The
    /// same rules as `record_warning`: returns nothing, no default (a forwarding scope that inherited a
    /// no-op would compile and drop every raise under it).
    fn open_absorbed_frame(&mut self);

    /// Close the innermost open frame and hand back what it collected, in the order the raises were made:
    /// empty when nothing inside raised beside a refused read, and empty with a debug assertion when no
    /// frame is open (a pairing fault of the caller, the class `RecordTracker` asserts for an `end_record`
    /// with no `start_record`). No default, as `open_absorbed_frame` has none.
    fn close_absorbed_frame(&mut self) -> Vec<AbsorbedRaise<'loc>>;

    /// Note a raise made beside a refused read (`reads`, one text each) by the clause written as `clause`
    /// at `site`, into the innermost open frame; a no-op with none open (a top-level clause's raise has
    /// no absorber: the raise itself reports the reads, and its own writer, the `record_unraised_refusal`
    /// call where the clause is decided, is its line). Called for EVERY raise a clause builds beside a
    /// refused read, whatever its kind and role: the raise sites of `eval::binary_operation` (the plain
    /// undecidable comparison a fold absorbs, and the strict raise the access clause turns into a leaf
    /// FAIL, which a `some` block or a disjunction may pass past), the unary operators' raise over a
    /// refused read among their values, and a fold that could not decide (a block's, a conjunction's),
    /// which hands the frame it collected up to the frame around it so an outer fold that decides reports
    /// every read. The fold that reads a frame decides by its arm and role what to write for each entry;
    /// this call records what was met. Never for a raise beside no refused read (there is no line to write
    /// for it) and never for a probe's or a discovery's raise (`QuietScope` notes nothing; the root notes
    /// nothing under a running measurement). No default, as `open_absorbed_frame` has none.
    fn note_absorbed_raise(
        &mut self,
        clause: &str,
        site: &exprs::FileLocation<'loc>,
        reads: &[String],
        kind: RaiseKind,
    );

    /// How many raises the innermost open frame holds now (0 with none open): the mark a site that
    /// DECIDES past a raise takes before the clauses it decides over run, so it can TAKE their notes
    /// (`truncate_absorbed_frame`) when its decision settles the raise and write each as decided past by
    /// the clause that decided: a disjunction one disjunct passed (`A or B` with `A` raised and `B` true
    /// is decided by `B`, as the hold is dropped; `eval::eval_conjunction_clauses` takes TWO marks there,
    /// one before the disjunction and one before each disjunct, so the entries before the passing
    /// disjunct's own mark are its siblings', "passed by a sibling clause that holds", and the entries
    /// from it are the passing disjunct's own, a `some` clause passing on another of its values past its
    /// refused read, "passed by a value that holds"); a reference whose rule FAILed, whose `not` takes the
    /// rule's entries and judges them by the basis of the rule's FAIL (`eval::eval_guard_named_clause`,
    /// `eval::negate_a_failed_rule`: "passed by the negation of a rule that failed" past a decided no; where
    /// the FAIL rests on undecidables alone the entries are handed up with the `not` clause's own FAIL).
    /// The pair for a site that decides INSIDE the clauses a frame collects over, where
    /// `open_absorbed_frame`/`close_absorbed_frame` is the pair for a body whose raises belong to the fold
    /// around it. Without the mark a note the deciding site dropped the raise of stayed in the frame and
    /// the fold around it reported the read as decided by a sibling entry when the `or` had decided it.
    /// Each entry carries its kind (`RaiseKind`), which the deciding site reads where the two kinds part.
    /// No default, as `open_absorbed_frame` has none.
    fn absorbed_frame_mark(&self) -> usize;

    /// Remove every raise noted into the innermost open frame since `mark` (`absorbed_frame_mark`) and
    /// hand them back in the order they were noted, for the deciding site to write; empty with none open,
    /// or with no entry past `mark`. No default, as `open_absorbed_frame` has none.
    fn truncate_absorbed_frame(&mut self, mark: usize) -> Vec<AbsorbedRaise<'loc>>;

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

    /// Hold the in-predicate scalar-filter notice (`DeprecationKind::ScalarFilterInsideAPredicate`) for
    /// the refusal `token` mints, to be written by the clause whose verdict rests on the marker that
    /// carries it, once that verdict is known and only where the marker's pair contributed to it (a strict
    /// FAIL, or a raise that fails its rule closed): a clause decided without the marker (`some` passing on
    /// a kept member, a `when` settled by a sibling's decided failure) moved no verdict and writes nothing.
    /// `reason` is the marker's own sentence as the producer stored it: the predicate clause that reads
    /// the marker as its OPERAND confirms the notice by that text (`undecided_member_read` in the filter
    /// role), so a key filter's wrap of the same refusal, or a function argument that met it, confirms
    /// nothing and the notice is never written for them (there the clause already failed closed and no
    /// verdict moved). `site` is the scalar filter's own predicate position, the key the notice is written
    /// once under. One hold per token: a second hold for the same token (the same sentence delivered again
    /// under one mint) is MERGED into the first, which keeps its confirmation and its readers (a raise a
    /// clause has not yet settled is never erased by a re-pend) and takes the later site, reason and
    /// notice. `binding` says which binding, if any, was resolving when the marker was produced
    /// (`resolving_binding`), and the hold's lifetime follows it: a file-level assignment's marker
    /// (`MarkerBinding::RootAssignment`: resolved once and read by every rule that names it) keeps its
    /// hold past the rule boundary; every other marker's readers are inside one rule (a block's `let`,
    /// the clause's own query, a filter capture that carries it to a later clause, a parameterized
    /// rule's argument read by its body), so its hold stays for them through the rule and goes at the
    /// rule's end (`reset_captures`), which bounds the holds a run keeps by one rule's markers plus the
    /// file-level `let`-bound ones rather than by every refused member the run met; read as a flag that
    /// any binding set, a type block's per-resource `let` over N resources left N holds alive to the
    /// scope's end. A re-pend keeps the greater binding. No default: the root scope keeps the holds, a
    /// scope that forwards lookups forwards this, and the scopes that drop every notice (a probe's run,
    /// the test doubles) say so with a body of their own, so a new scope cannot inherit a silent drop
    /// (the drift `record_deprecation_once` guards against the same way).
    fn pend_scalar_filter_notice(
        &mut self,
        token: errors::RefusalToken,
        site: &exprs::FileLocation<'_>,
        reason: &str,
        notice: String,
        binding: MarkerBinding,
    );

    /// A clause at `at` read an undecided marker as its role reads one (a strict FAIL on it, a gate's or
    /// a filter predicate's raise), not passing it over: in the filter role the marker is the predicate
    /// clause's operand and a held notice for its token whose reason is the marker's own is CONFIRMED; in
    /// the assertion and gate roles a confirmed hold for its token is marked READ by the clause, to be
    /// written or dropped when the clause's verdict is known (`undecided_reads_decided`), and an
    /// unconfirmed hold is dropped (no predicate clause read the marker as its operand, so nothing moved
    /// for it). `token` is the marker's own refusal token or the one it carries
    /// (`UnResolvedKind::Undecidable`), `reason` its stored sentence. No default, as
    /// `pend_scalar_filter_notice` has none.
    fn undecided_member_read(
        &mut self,
        token: errors::RefusalToken,
        reason: Option<&str>,
        role: eval::ClauseRole,
        at: &exprs::FileLocation<'_>,
    );

    /// The clause at `at` whose reads `undecided_member_read` marked is decided, for ITS reads alone (a
    /// hold is read by several clauses when a `let`-bound selection is read by several rules; another
    /// clause's read of the same hold is untouched): on `Failed` (a strict FAIL that RESTS on the marked
    /// reads, `FailBasis::Undecidable`: no decided no beside them) its read becomes a FAIL at its site, for
    /// the rule around the clause to settle (written where that rule FAILs, `held_fails_judged`; withdrawn
    /// where a disjunct or a `some` block passes past it and writes the clause's refused-read line,
    /// `record_unraised_refusal`); on `Decided` (the clause passed, or a decided no fails it whatever the
    /// marker holds, in either role) its read is withdrawn and the hold stays confirmed for the next
    /// reader (a capture or a call's argument can carry the marker to a later clause of the rule; the
    /// rule's end drops what no reader took, `reset_captures`); on `Raised` (the gate role's raise) its read becomes a RAISE at its site, for the fold
    /// around the clause to settle: written where the raise fails a rule closed
    /// (`held_raises_failed_closed`), withdrawn where a sibling decides past it (the root scope drops the
    /// raise when the refused-read line for that site is written). The two roles are symmetric: a FAIL or
    /// a raise a sibling decides past moved no verdict. Called once per clause, after its fold, when the
    /// clause marked a read. No default, as `pend_scalar_filter_notice` has none.
    fn undecided_reads_decided(
        &mut self,
        at: &exprs::FileLocation<'_>,
        decision: UndecidedReadsDecision,
    );

    /// A raise that reached a condition site in the strict role fails its rule closed
    /// (`eval::convert_condition_raise`): every hold RAISED at one of `sites` (the frame entries' sites,
    /// else the condition's own, `FileLocation::to_string`) is written once per site and dropped. No
    /// default, as `pend_scalar_filter_notice` has none.
    fn held_raises_failed_closed(&mut self, sites: &[String]);

    /// The mark a rule takes as its judgment opens (`eval::judged_rule`): every strict FAIL a clause marks
    /// from here on (`undecided_reads_decided` with `Failed`) is stamped past it, so the rule's exit settles
    /// ITS clauses' FAILs alone (`held_fails_judged`) and never an enclosing rule's, marked before this rule
    /// was entered. A referenced rule on a cache miss and every parameterized call enter `judged_rule`
    /// inside the referencing rule's run, so a settlement that read every FAILED reader in the scope let
    /// a nested rule's PASS withdraw the enclosing rule's FAIL, and a nested rule's FAIL write a notice the
    /// enclosing `or` or `not` then passed past. No default, as `pend_scalar_filter_notice` has none.
    fn held_fails_mark(&self) -> u64;

    /// A rule was judged, settling the strict FAILs stamped past `since` (its own clauses', and the
    /// FAILs a nested rule whose FAIL rested on an undecidable handed up to it, as the leaf-FAIL frame
    /// hands its entries up): with `rests_on` the refused reads the rule's own FAIL rests on
    /// (`FailBasis::Undecidable`, at the TOP-LEVEL run of the rule in `eval::eval_rules_file`, the one
    /// site with no fold above it), every such hold the reads name (by the marker's sentence, or its
    /// token) is written once per site and dropped, the clause's FAIL being part of the rule's; every
    /// other FAIL marked since `since` is withdrawn (the rule passed past it, was not applicable, raised,
    /// or FAILed on a decided no beside it, `FailBasis::Decided`, in which case the marker moved no verdict
    /// and the roles read alike: a gate shape settled by a sibling's decided failure writes nothing
    /// either); the holds stay, and a hold goes at the rule boundary (`reset_captures`) unless its marker
    /// is a file-level assignment's (`MarkerBinding::RootAssignment`). A call with no FAIL marked since
    /// `since` returns before it walks the holds.
    /// A nested rule whose FAIL rests on an undecidable calls neither: its FAILs are handed up to the
    /// enclosing rule's judgment, whose basis folds them. Raised and undecided reads are left alone. No
    /// default, as `pend_scalar_filter_notice` has none.
    fn held_fails_judged(&mut self, since: u64, rests_on: Option<&[RefusedRead]>);

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

    /// The reason texts of the captures this evaluation refused inside filter predicates
    /// (`eval_context::refuse_unbound_capture`) whose warning WAS recorded where they were refused
    /// (`eval_context::announce_unbound_capture`, once per clause and input; `record_capture_warning`
    /// says whether a line stands, and a refusal met under a measurement or a quiet probe, which record
    /// no line, is not in the set): read by the comparison's refused-read line (`eval::binary_operation`)
    /// to leave an announced refusal off it, so one refusal is not reported twice at one clause in two
    /// wordings, and a refusal no line names is reported there. Owned by the root scope and gone with it;
    /// every scope with a root behind it forwards; a scope with none answers `None` (the test doubles),
    /// and the line then names every refused read it met.
    fn announced_capture_refusals(&self) -> Option<Rc<std::cell::RefCell<HashSet<String>>>> {
        None
    }

    /// The deep copies the member notice's probe made of values found below the document root during the
    /// top-level clause being evaluated, keyed by the node each copies (see
    /// [`eval_context::ValueBeforeClones`]): the probe reads the value the released engines asked the
    /// predicate of, and under `Statement[*].Condition[*][ f ]` that value is the resource above every
    /// statement's root, so a site whose verdict stays quiet (recorded per map, not per site) asked for
    /// that copy once per statement, a copying cost that grew with the square of the policy's size; one
    /// copy now serves every statement and every site that asks for the same value within the clause, and
    /// the clause evaluator clears the table as the outermost clause ends
    /// ([`eval_context::ClauseCopies`]). Owned by the root scope; every other scope forwards; a scope with
    /// no root behind it answers `None` (the default) and the copy is made on every ask.
    fn value_before_the_wildcard_clones(
        &self,
    ) -> Option<Rc<std::cell::RefCell<eval_context::ValueBeforeClones>>> {
        None
    }

    /// Which binding is being resolved somewhere on this scope's chain (`MarkerBinding`): a file-level
    /// assignment at the root (`resolving_assignments`, `RootAssignment`), a block's `let` in a block
    /// (`resolving_let`, `BlockLet`), or none (`Clause`). A chain with both open (a block's `let` whose
    /// right-hand side forces a file-level assignment) answers the outermost, `RootAssignment`. Every
    /// scope that is not the root or a block forwards; a scope with no root behind it answers `Clause`.
    /// Two readers: the quiet probes' memo, which keeps nothing read while any binding is open
    /// (`eval_context::resolving_a_binding`, a free function over this method), and the in-predicate
    /// scalar-filter holds, whose lifetime follows the KIND of binding open when the marker was produced
    /// (`pend_scalar_filter_notice`). No default, for the reason `document_binding_memo` has none.
    fn resolving_binding(&self) -> MarkerBinding;

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

    /// The frames of the filter predicate runs open on this evaluation, outermost first
    /// (`eval_context::RefusalFrames`, each frame the refusal token counter and the scope event as its run
    /// opened), empty outside every run, as a copy. A run pushes its frame as its body starts and pops it
    /// as the body ends (`eval_context::with_refusal_frame`, in `run_filter_predicate` and
    /// `select_list_members`), and every fold that ranks refusal tokens reads the stack off the context it
    /// runs under (`eval::ranking_under`): the conjunction fold, the block's value fold and its
    /// refused-body fold, the comparison's evidence and its right-hand marker folds, the key filter's
    /// per-key fold, the refused-read collection. So the ranking a run marks its entry by reaches a fold
    /// through whatever scope stands between them, a block body or a comparison inside the predicate
    /// included; handed into the top fold as an argument it reached the two folds someone remembered to
    /// thread it through, and the resource-order swap it closes survived in a block shape and in a
    /// comparison with the binding on the left. The whole stack, not the innermost frame alone: a fold
    /// ranks a token by how many of the live runs can read it as their own (`RefusalFrames::rank`), so a
    /// nested run's fold keeps, among tokens it cannot read as its own, the one the enclosing run can,
    /// where the innermost frame alone kept the later-minted and carried up a token the enclosing run
    /// could not read either. The root holds the stack; every other scope forwards both methods, so a
    /// scope built inside a run reads the run's frames. Explicit state on the context a test builds,
    /// which a test of a nested fold can set, where a thread-local would be an ambient dependency the test
    /// did not plant. No default, for the reason `record_deprecation` has none.
    fn refusal_frames(&self) -> eval_context::RefusalFrames;

    /// The stack `refusal_frames` copies, for the run to push onto and pop from; see `refusal_frames`.
    /// Every scope but the root forwards.
    fn refusal_frames_mut(&mut self) -> &mut eval_context::RefusalFrames;

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
/// IN %x` matched a listed entry and "does not match" would say the opposite. Four more verdicts name the
/// SIBLING that decided past a raise made beside a refused read, two per deciding mechanism and each by its
/// polarity as the five above are: a sibling ENTRY of a block (`DecidedBySibling`, `PassedBySibling`) and a
/// sibling CLAUSE of a conjunction or a disjunction (`DecidedBySiblingClause`, `PassedBySiblingClause`).
/// A tenth names the NEGATION that turned a referenced rule's leaf FAIL into the referencing rule's pass
/// (`PassedByNegation`); the negation that refuses to, over a rule whose FAIL rests on undecidables alone,
/// fails closed and reports the refusal in its own FAIL record, not on this line (failing closed IS acting
/// on the refusal, so "was not raised" would be false of it; `eval::negate_a_failed_rule`). An eleventh is
/// the neutral word a fold writes for an entry it found left where its own invariant says none can be, so
/// a release build never fabricates a reason (`DecidedPastUnrecorded`). Eleven in all, counted apart
/// (`eval_context::UnraisedCounts`) and worded apart on the line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UnraisedVerdict {
    Passed,
    DecidedByAbsence,
    DecidedByMismatch,
    DecidedByCollision,
    DecidedByKinds,
    /// A block body (`Items.* { .. }`) raised beside a refused read for one entry while a sibling
    /// entry's decided failure settled the every-entry block, so the fold absorbed the raise into its
    /// FAIL (`eval::eval_guard_block_clause`'s decided branch): the refused read was not raised, and the
    /// line says the sibling decided it.
    DecidedBySibling,
    /// A `some` block (`some Items.* { .. }`) whose body raised beside a refused read for one entry, or
    /// FAILed at the leaf on the refusal in the assertion role, while a sibling entry's pass settled the
    /// block (the decided branch's `some` arm, and the strict leaf FAILs the fold keeps for a `some` that
    /// passed on another entry): the refused read was not raised, and the line says the sibling entry
    /// holds. Not `Passed`, which is the comparison's own wording for a pass on its own values: at one
    /// site the two are counted apart, so a reader can tell an entry that passed from one whose raise a
    /// sibling's pass swallowed.
    PassedBySibling,
    /// A conjunction (a block body, a rule body, a `when` body, a filter predicate) decided FAIL by one
    /// clause's failure past another clause's raise beside a refused read (`AND(no, unknown)` is `no`,
    /// `eval::eval_conjunction_clauses`'s FAIL exit with a held raise): the raise was dropped with the
    /// hold, and the line says the sibling clause decided it.
    DecidedBySiblingClause,
    /// A disjunction (`A or B`) decided PASS by one disjunct that holds past another disjunct's raise
    /// beside a refused read, or past its leaf FAIL on the refusal in the assertion role
    /// (`eval::eval_conjunction_clauses`'s disjunct-PASS arm): the raise was dropped with the hold, and
    /// the line says the sibling clause holds.
    PassedBySiblingClause,
    /// A referenced rule's strict leaf FAIL on a refusal (`rule check { some %y NOT IN %m }`), handed to
    /// the reference site with the rule's FAIL (`EvalContext::rule_status`, the parameterized call) and
    /// turned into the referencing rule's PASS by the reference's `not` (`eval::eval_guard_named_clause`,
    /// `eval::eval_parameterized_rule_call`): the refused read is unseen under a passing rule, and the line
    /// says the negation of a rule that failed passed it. Not `Passed`, which would say the refused read's
    /// own clause passed. Written only where the referenced rule's FAIL is a DECIDED no by the structure
    /// of its folds (`FailBasis::Decided`); a FAIL that rests on undecidables alone fails the `not`
    /// closed, with the refusals named in the `not` clause's own FAIL record and no line here.
    PassedByNegation,
    /// The neutral word for an entry a fold found left where its own invariant says none can be (a
    /// conjunction, a body, a referenced or called rule that answered PASS or SKIP with an entry still
    /// in its frame; a `when` condition that did not match with a refused read's entry among what its
    /// gate-role clauses noted, which the roles never produce): a debug build asserts the invariant, and
    /// a release build writes the entry with this word rather than dropping it or naming a value that
    /// holds, which the fold cannot know.
    DecidedPastUnrecorded,
}

/// Why a FAIL is a FAIL, carried INSIDE the FAIL by every site that answers one (`Judged::Fail`, the
/// evaluation chain's results, `EvalContext::rule_status` and its cache): a DECIDED no, or a FAIL that
/// rests on reads the evaluator could not decide (a refused read, a selection nobody could decide, a spent
/// regex budget), with the refused reads it rests on. Every strict site that turns an undecidable into a
/// FAIL names `Undecidable` (`eval::fail_closed_or_raise`, the block, `when`, type-block and rule folds'
/// strict arms, the comparison and the unary operator over their own pairs), every fold combines its
/// branches' bases (`and_under`, `or_under`), and a reference's `not` reads the basis of the rule it negates
/// (`eval::negate_a_failed_rule`): a decided no is inverted to a PASS, an undecidable-born FAIL fails the
/// `not` closed, since a PASS there would be a verdict the undecidable manufactured. Carried with the
/// outcome and never as state on the context, so a site that forgets to choose does not compile, nothing
/// is saved or restored around a probe or a measurement, and the frames (`AbsorbedRaise`), which a quiet
/// probe and a running measurement leave empty, carry no part of the answer. The reads are what the
/// fail-closed `not`'s record names; empty for an undecidable that is no refusal (a spent budget), whose
/// record then reads no refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FailBasis {
    /// A decided no: a comparison that answered no, a value the document lacks, a block over a selection
    /// every entry of which failed, `not <rule that passed>`.
    Decided,
    /// A FAIL that rests on undecidables alone, with the refused reads it rests on (each text once, in
    /// the order met, with the token its raise carried where it carried one, so a refusal known by its
    /// token alone, whose text no registry holds, keeps the token through every fold; empty for an
    /// undecidable that is no refusal), and the texts of the undecidables met that are NO refusal (a
    /// spent regex budget, a value the engine could not read), each once in the order met: the cause a
    /// fail-closed `not` names when no refused read is there to name, which flags no refusal. At most
    /// `MARKER_REASONS_NAMED` causes are named (the first met, in order); every further distinct cause
    /// is kept in `unnamed_causes`, an ordered set, and counted once in the sentence that names the rest
    /// (a set and not a bare count: a cause met again, named or not, must not be counted again).
    /// The payload is a struct with private fields (`UndecidableBasis`), built and changed through its
    /// own constructors and join alone, so the index of the reads (`read_positions`, which lets a join
    /// look each read of the basis it adds up in one step instead of scanning the running list) cannot
    /// be left stale by a struct literal or by a change of the list made outside it.
    Undecidable(UndecidableBasis),
}

/// The payload of `FailBasis::Undecidable`. Its fields are private to this module, so the one index it
/// keeps beside the ordered list of refused reads is changed only where the list is, and the equality and
/// the debug text read the ordered fields alone, never the index, whose order is run-dependent.
mod undecidable_basis {
    use super::eval::Ranking;
    use super::{errors, RefusedRead, MARKER_REASONS_NAMED};
    use std::collections::{BTreeSet, HashMap};

    /// The refused reads and the causes an undecidable-born FAIL rests on, in the order met.
    /// `read_positions` indexes `refused_reads` by text; it is derived from the list and never differs
    /// from it, since the list changes through `add_read` only. Cloning copies each text twice (the list
    /// and the index), which the cost of a join accepts: a clone is made once per basis a fold keeps.
    #[derive(Clone)]
    pub(crate) struct UndecidableBasis {
        refused_reads: Vec<RefusedRead>,
        read_positions: HashMap<String, usize>,
        other_causes: Vec<String>,
        unnamed_causes: BTreeSet<String>,
    }

    impl UndecidableBasis {
        /// A basis over `reads`, each text once in the order met; a text met twice keeps its first position
        /// and the token `ranking` ranks higher, the later-minted at a tie (`add_read`).
        pub(crate) fn from_reads(reads: Vec<RefusedRead>, ranking: Ranking<'_>) -> Self {
            let mut basis = UndecidableBasis {
                refused_reads: Vec::with_capacity(reads.len()),
                read_positions: HashMap::with_capacity(reads.len()),
                other_causes: Vec::new(),
                unnamed_causes: BTreeSet::new(),
            };
            for (text, token) in reads {
                basis.add_read(text, token, ranking);
            }
            basis
        }

        /// A basis that rests on one undecidable that is no refusal, with the text of its error as the cause.
        pub(crate) fn from_cause(cause: String) -> Self {
            UndecidableBasis {
                refused_reads: Vec::new(),
                read_positions: HashMap::new(),
                other_causes: vec![cause],
                unnamed_causes: BTreeSet::new(),
            }
        }

        /// Add one read to the list and its index: a text met before keeps its position and the token
        /// `ranking` ranks higher, the later-minted at a tie (`eval::later_token`, the pair rule the
        /// comparison's collection keeps its reads by), so the token a basis carries for a sentence is the
        /// one the run reads as its own whatever order the reads arrive in; a new text goes last. The
        /// ranking is handed in by the caller that holds the frames of its runs; a caller with none hands
        /// the live runs' (`eval_context::live_runs_ranking`).
        fn add_read(
            &mut self,
            text: String,
            token: Option<errors::RefusalToken>,
            ranking: Ranking<'_>,
        ) {
            match self.read_positions.get(&text) {
                Some(&at) => {
                    self.refused_reads[at].1 =
                        super::eval::later_token(self.refused_reads[at].1, token, ranking);
                }
                None => {
                    self.read_positions
                        .insert(text.clone(), self.refused_reads.len());
                    self.refused_reads.push((text, token));
                }
            }
        }

        /// The refused reads, each with its token, in the order met.
        pub(crate) fn refused_reads(&self) -> &[RefusedRead] {
            &self.refused_reads
        }

        /// The named causes that are no refusal, in the order met, at most `MARKER_REASONS_NAMED`. A cause
        /// that IS a refusal is held in `refused_reads` instead, so where the lead cause is a refusal it is
        /// not counted here: a caller that adds `other_causes` and `causes_not_named` counts the distinct
        /// causes only for a basis with no refused read (`has_several_causes` in `eval.rs` reads it so).
        pub(crate) fn other_causes(&self) -> &[String] {
            &self.other_causes
        }

        /// How many further distinct causes the basis rests on beyond the named ones.
        pub(crate) fn causes_not_named(&self) -> usize {
            self.unnamed_causes.len()
        }

        /// Two bases as one: the reads of both in order, each once, tokens kept; the causes of both in
        /// order, each once, the first `MARKER_REASONS_NAMED` named and the rest kept in the ordered set
        /// of the unnamed. `self` is the running total and is extended in place: only the reads and the
        /// causes of `other` are looked up (the reads in the index, the causes among the named four and in
        /// the ordered set), so a fold over N failing resources costs the size of each basis it adds, not
        /// the size of the total built so far. A read both bases hold keeps the token `ranking` ranks
        /// higher (`add_read`).
        pub(crate) fn joined_with(
            mut self,
            other: UndecidableBasis,
            ranking: Ranking<'_>,
        ) -> UndecidableBasis {
            let UndecidableBasis {
                refused_reads: added_reads,
                other_causes: added_causes,
                unnamed_causes: added_unnamed,
                ..
            } = other;
            for (text, token) in added_reads {
                self.add_read(text, token, ranking);
            }
            for cause in added_causes.into_iter().chain(added_unnamed) {
                if self.other_causes.contains(&cause) || self.unnamed_causes.contains(&cause) {
                    continue;
                }
                match self.other_causes.len() < MARKER_REASONS_NAMED {
                    true => self.other_causes.push(cause),
                    false => {
                        self.unnamed_causes.insert(cause);
                    }
                }
            }
            self
        }
    }

    /// Equal by the ordered reads and causes, never by the index (derived from the reads).
    impl PartialEq for UndecidableBasis {
        fn eq(&self, other: &Self) -> bool {
            self.refused_reads == other.refused_reads
                && self.other_causes == other.other_causes
                && self.unnamed_causes == other.unnamed_causes
        }
    }

    impl Eq for UndecidableBasis {}

    /// The ordered fields alone: a derived `Debug` printed the index, a map whose order differs from run to
    /// run, into every assertion message and cell failure that showed a basis.
    impl std::fmt::Debug for UndecidableBasis {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("UndecidableBasis")
                .field("refused_reads", &self.refused_reads)
                .field("other_causes", &self.other_causes)
                .field("unnamed_causes", &self.unnamed_causes)
                .finish()
        }
    }
}

pub(crate) use undecidable_basis::UndecidableBasis;

/// How many undecidable reasons a sentence names before it counts the rest once: the markers' reasons a
/// raise joins beside a refusal (`eval::binary_operation`) and the causes a fail-closed negation names
/// (`FailBasis::other_causes`), one bound so a template of many failing resources cannot grow either text.
pub(crate) const MARKER_REASONS_NAMED: usize = 4;

/// One refused read a FAIL rests on: its text and the token the raise that met it carried (`None` for a
/// read known by its registered text alone).
pub(crate) type RefusedRead = (String, Option<errors::RefusalToken>);

impl FailBasis {
    /// An undecidable-born basis over `refused_reads` known by text alone, deduplicated in order. For the
    /// cells that build bases from texts; production code names its reads with their tokens.
    #[cfg(test)]
    pub(crate) fn undecidable(refused_reads: Vec<String>) -> Self {
        // No token to rank: the texts carry none.
        FailBasis::undecidable_reads_under(
            refused_reads.into_iter().map(|text| (text, None)).collect(),
            &eval::no_frame_ranking,
        )
    }

    /// An undecidable-born basis over `refused_reads` with their tokens, each text once in the order met;
    /// a text met twice keeps its first position and the token the LIVE runs rank higher, the
    /// later-minted at a tie (`UndecidableBasis::add_read`). For the cells that build bases directly and
    /// hold no frames; production code hands the ranking it has (`undecidable_reads_under`).
    #[cfg(test)]
    pub(crate) fn undecidable_reads(refused_reads: Vec<RefusedRead>) -> Self {
        FailBasis::undecidable_reads_under(refused_reads, &eval_context::live_runs_ranking())
    }

    /// The basis of `undecidable_reads` (the test-only form that reads the live runs) under the ranking of
    /// the frames the caller holds.
    pub(crate) fn undecidable_reads_under(
        refused_reads: Vec<RefusedRead>,
        ranking: eval::Ranking<'_>,
    ) -> Self {
        FailBasis::Undecidable(UndecidableBasis::from_reads(refused_reads, ranking))
    }

    /// An undecidable-born basis that rests on an undecidable that is no refusal, with the text of the
    /// error it was made from as its cause.
    pub(crate) fn undecidable_for_cause(cause: String) -> Self {
        FailBasis::Undecidable(UndecidableBasis::from_cause(cause))
    }

    /// The texts of the undecidables this FAIL rests on that are no refusal, in the order met, at most
    /// `MARKER_REASONS_NAMED` of them; none for a decided no.
    pub(crate) fn other_causes(&self) -> &[String] {
        match self {
            FailBasis::Decided => &[],
            FailBasis::Undecidable(basis) => basis.other_causes(),
        }
    }

    /// How many further distinct causes the FAIL rests on beyond the named ones.
    pub(crate) fn causes_not_named(&self) -> usize {
        match self {
            FailBasis::Decided => 0,
            FailBasis::Undecidable(basis) => basis.causes_not_named(),
        }
    }

    pub(crate) fn is_decided(&self) -> bool {
        matches!(self, FailBasis::Decided)
    }

    /// Whether an undecidable-born FAIL rests on at least one REFUSAL (a read the registry holds), as
    /// against a budget-only undecidable: the refusal flag of the record that reports it.
    pub(crate) fn rests_on_a_refusal(&self) -> bool {
        matches!(self, FailBasis::Undecidable(basis) if !basis.refused_reads().is_empty())
    }

    /// The refused reads an undecidable-born FAIL rests on, each with its token; none for a decided no.
    pub(crate) fn refused_reads(&self) -> &[RefusedRead] {
        match self {
            FailBasis::Decided => &[],
            FailBasis::Undecidable(basis) => basis.refused_reads(),
        }
    }

    /// The texts of the refused reads, in order: what a record names and a frame entry carries.
    pub(crate) fn refused_texts(&self) -> Vec<String> {
        self.refused_reads()
            .iter()
            .map(|(text, _)| text.clone())
            .collect()
    }

    /// The basis of a conjunction's FAIL from two failing branches' (`AND(no, unknown)` is `no`): decided
    /// when either is, else undecidable over both branches' reads.
    /// A read both hold keeps the token the LIVE runs rank higher. For the cells that build bases directly;
    /// every production fold holds frames and hands their ranking (`and_under`).
    #[cfg(test)]
    pub(crate) fn and(self, other: FailBasis) -> FailBasis {
        self.and_under(other, &eval_context::live_runs_ranking())
    }

    /// The fold of two bases for a conjunction (`and`, the test-only form that reads the live runs) under
    /// the ranking of the frames the caller holds.
    pub(crate) fn and_under(self, other: FailBasis, ranking: eval::Ranking<'_>) -> FailBasis {
        match (self, other) {
            (FailBasis::Decided, _) | (_, FailBasis::Decided) => FailBasis::Decided,
            (a, b) => a.joined_with(b, ranking),
        }
    }

    /// The basis of a disjunction's, a `some` block's or a `some` clause's FAIL from two failing branches'
    /// (`OR(no, unknown)` is unknown): decided only when both are, else undecidable over the undecidable
    /// branches' reads.
    /// A read both hold keeps the token the LIVE runs rank higher. For the cells that build bases directly;
    /// every production fold holds frames and hands their ranking (`or_under`).
    #[cfg(test)]
    pub(crate) fn or(self, other: FailBasis) -> FailBasis {
        self.or_under(other, &eval_context::live_runs_ranking())
    }

    /// The fold of two bases for a disjunction (`or`, the test-only form that reads the live runs) under
    /// the ranking of the frames the caller holds.
    pub(crate) fn or_under(self, other: FailBasis, ranking: eval::Ranking<'_>) -> FailBasis {
        match (self, other) {
            (FailBasis::Decided, FailBasis::Decided) => FailBasis::Decided,
            (FailBasis::Decided, undecidable) | (undecidable, FailBasis::Decided) => undecidable,
            (a, b) => a.joined_with(b, ranking),
        }
    }

    /// Two undecidable bases as one, the reads of both in order, each once, tokens kept; the causes of
    /// both in order, each once, the first `MARKER_REASONS_NAMED` named and the rest kept in the ordered
    /// set of the unnamed. `self` is the running total and is extended in place: only the reads and the
    /// causes of `other` are looked up (the reads in the index, the causes among the named four and in the
    /// ordered set), so a fold over N failing resources costs the size of each basis it adds, not the size
    /// of the total built so far.
    fn joined_with(self, other: FailBasis, ranking: eval::Ranking<'_>) -> FailBasis {
        match (self, other) {
            (FailBasis::Undecidable(running), FailBasis::Undecidable(added)) => {
                FailBasis::Undecidable(running.joined_with(added, ranking))
            }
            // A decided basis adds nothing to a join.
            (FailBasis::Undecidable(basis), FailBasis::Decided)
            | (FailBasis::Decided, FailBasis::Undecidable(basis)) => FailBasis::Undecidable(basis),
            (FailBasis::Decided, FailBasis::Decided) => FailBasis::Undecidable(
                UndecidableBasis::from_reads(Vec::new(), &eval::no_frame_ranking),
            ),
        }
    }
}

/// What a site of the evaluation chain answers for a clause, a block, a rule or a reference: a PASS, a
/// SKIP, or a FAIL WITH the basis it rests on (`FailBasis`). A basis exists on a FAIL alone, so every site
/// that answers FAIL names one by construction and no PASS or SKIP can carry an undecidable into a cache or
/// a fold (a status beside a basis admitted both). Carried by every function of the chain, answered and
/// cached by `EvalContext::rule_status`, and read by the folds (`FailBasis::and_under`, `::or_under`) and by a
/// reference's `not` (`eval::negate_a_failed_rule`); the status-only wrappers (`eval::eval_guard_clause`,
/// `eval_conjunction_clauses`, `eval_rule`, the cells') read `status` at leaves that feed no fold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Judged {
    Pass,
    Skip,
    Fail(FailBasis),
}

impl Judged {
    /// The status alone, for a reader that has no fold to carry a basis to.
    pub(crate) fn status(&self) -> Status {
        match self {
            Judged::Pass => Status::PASS,
            Judged::Skip => Status::SKIP,
            Judged::Fail(_) => Status::FAIL,
        }
    }

    /// A status decided on nothing the evaluator could fail to read (an empty selection, an empty
    /// reference, a block over a selection every entry of which was decided): a FAIL here is a decided no.
    pub(crate) fn decided(status: Status) -> Judged {
        match status {
            Status::PASS => Judged::Pass,
            Status::SKIP => Judged::Skip,
            Status::FAIL => Judged::Fail(FailBasis::Decided),
        }
    }

    /// A fold's status with the basis its failing branches folded (`basis`, `None` while none failed):
    /// a FAIL carries the folded basis, a PASS or a SKIP none. A FAIL whose fold named no basis for any
    /// branch (a count of FAILs that no branch folded a basis for) is undecidable with no read, which
    /// fails closed: read as a decided no, one unpaired count of a FAIL over refused reads would make a
    /// `not` over the rule pass. Both callers pair every FAIL they count with a folded basis, so a debug
    /// build asserts it here, and the default is a floor and not a path: a release build keeps the
    /// fail-closed answer, with the neutral cause [`UNRECORDED_BASIS_CAUSE`] rather than an empty basis,
    /// so the record that reports the FAIL never says its undecided reads are reported where the rule met
    /// them when none was met.
    pub(crate) fn folded(status: Status, basis: Option<FailBasis>) -> Judged {
        debug_assert!(
            status != Status::FAIL || basis.is_some(),
            "a FAIL was counted with no folded basis"
        );
        Judged::folded_or_floor(status, basis)
    }

    /// What [`Judged::folded`] returns once its debug assertion has passed, and all it returns in a
    /// release build: the FAIL's folded basis, else the floor ([`unrecorded_basis`]). Separate and
    /// non-asserting so both builds exercise the shipped fail-closed path.
    pub(crate) fn folded_or_floor(status: Status, basis: Option<FailBasis>) -> Judged {
        match status {
            Status::FAIL => Judged::Fail(basis.unwrap_or_else(unrecorded_basis)),
            other => Judged::decided(other),
        }
    }
}

/// The basis a FAIL carries when a fold counted it and named none (`Judged::folded`'s release floor): an
/// undecidable with the neutral cause [`UNRECORDED_BASIS_CAUSE`]. A function of its own so a cell reads the
/// floor in a debug build too, where `folded` asserts before it reaches it.
pub(crate) fn unrecorded_basis() -> FailBasis {
    FailBasis::undecidable_for_cause(UNRECORDED_BASIS_CAUSE.to_string())
}

/// The cause a FAIL carries when a fold counted it and named no basis for it (`Judged::folded`): neutral,
/// since the fold cannot know what the FAIL rests on. It flags no refusal and is named by a fail-closed
/// `not` in place of a refused read.
pub(crate) const UNRECORDED_BASIS_CAUSE: &str =
    "no basis was recorded for this FAIL, so it is not read as a decided no";

/// What a frame entry (`AbsorbedRaise`) was when it was noted, decided by the role of the clause that
/// raised (`eval::kind_for`): every fold that meets an entry decides by this kind, never by which of its
/// arms it is in, since a strict leaf FAIL and a gate-role raise leave the same entry otherwise. Whether a
/// FAIL rests on undecidables alone is not read off the entries (a quiet probe and a running measurement
/// note none): it travels with the status as its `FailBasis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RaiseKind {
    /// A gate-role or filter-predicate raise: an `Err` the fold above may absorb into a decided sibling's
    /// verdict or decide past (a conjunct's failure, a disjunct's pass), and otherwise hands up or raises.
    Raised,
    /// A strict-role raise the leaf turned into its own FAIL status, recorded `refusal: true` at the leaf:
    /// its FAIL is part of every FAIL above it, never decided past by a failing sibling, and is written
    /// only where a `some` block, a disjunct that holds or a `not` turns that FAIL into a pass. Every
    /// `LeafFail` entry is refusal-born: it carries the refused reads its FAIL rests on.
    LeafFail,
}

/// How a clause whose values held undecided markers it read (`EvalContext::undecided_member_read`) came
/// out, for the in-predicate scalar-filter notices held on those markers
/// (`EvalContext::undecided_reads_decided`): the notice is written only where the verdict MOVED, and a
/// verdict moved where the marker's pair contributed to a FAIL or to a raise that fails a rule closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UndecidedReadsDecision {
    /// The clause FAILed in the strict role and its FAIL rests on the marked reads (no value answered a
    /// decided no beside them): the member once deselected with the clause passing, or selected with it
    /// passing, now fails it. Written where the rule around the clause FAILs; withdrawn where a disjunct or
    /// a `some` block passes past the FAIL.
    Failed,
    /// The clause was decided without the marked reads: it passed (`some` on a kept member that holds), a
    /// decided no fails it whatever the marker holds, or in the gate role it raised nothing (the reads
    /// stood beside values that settled it). Withdrawn.
    Decided,
    /// The clause raised in the gate or filter-predicate role: the fold around it settles the raise, and
    /// the hold with it (written where the raise fails a rule closed, dropped where a sibling decides past
    /// it). Kept, as raised at the clause's site.
    Raised,
}

/// Which binding, if any, was resolving when an undecided marker was produced, as
/// `EvalContext::resolving_binding` reads the scope chain and `EvalContext::pend_scalar_filter_notice`
/// records it on the marker's hold: the hold's lifetime follows it. A file-level assignment
/// (`RootAssignment`, the root's `resolving_assignments`) is resolved once and read by every rule that
/// names it, so its hold outlives the rule boundary; a block's `let` (`BlockLet`, a block's
/// `resolving_let`: a rule body's, a type block's per-resource, a called rule's body's) is read inside
/// its rule alone, so its hold goes at the boundary as a clause's own does; a marker from no binding
/// (`Clause`: the clause's own query, a filter capture carrying it to a later clause, a parameterized
/// rule's argument read by its body) has every reader inside the rule too. Ordered so that a chain
/// with two resolutions open (a block's `let` whose right-hand side forces a file-level assignment)
/// reads as the outermost binding's, the one every rule reads: `RootAssignment` is the greatest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum MarkerBinding {
    Clause,
    BlockLet,
    RootAssignment,
}

/// One raise a block body made beside a refused read, as the frame `EvalContext::open_absorbed_frame`
/// collects it for the fold that may absorb it: the comparison as the author wrote it (`clause`, the text
/// the refused-read line opens with; a block's own text where the block is the raising clause, the marker
/// its query delivered or the selection it refused), the position of that clause (`site`, the key the
/// line is stored under, so a comparison absorbed under one value and decided past under another is one
/// line at its own position, and two comparisons absorbed by one block are two), the refused reads
/// the raise met (`reads`, the texts the line names) and what the raise was (`kind`: a raise a fold may
/// decide past, or a strict leaf's own FAIL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AbsorbedRaise<'loc> {
    pub(crate) clause: String,
    pub(crate) site: exprs::FileLocation<'loc>,
    pub(crate) reads: Vec<String>,
    pub(crate) kind: RaiseKind,
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
    /// A filter over a scalar met inside a filter predicate as the predicate clause's own operand
    /// (`Resources.*[ Properties.Tags[ Key == 'Env' ] exists ]` over a string `Tags`), where the previous
    /// release read the scalar as an absence to the predicate (the member deselected under `exists`,
    /// selected under `!exists`, nothing reported) and the member is now undecided, carried beside the
    /// kept members, on which the clause over the selection fails closed whatever the kept members hold.
    /// Written once per filter site, after the clause's verdict is known, and only where that verdict
    /// MOVED: the clause failed in the strict role on the undecided member, or raised on it and the raise
    /// failed its rule closed. A `some` that passes on a kept member, or a `when` a sibling's decided
    /// failure settles, moved no verdict and writes nothing (`EvalContext::pend_scalar_filter_notice`,
    /// `EvalContext::undecided_member_read`, `EvalContext::undecided_reads_decided`).
    ScalarFilterInsideAPredicate,
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
            DeprecationKind::ScalarFilterInsideAPredicate => {
                "the in-predicate scalar-filter notice"
            }
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
