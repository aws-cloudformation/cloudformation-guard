use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::rules::eval_context::{
    find_skip_reason, BinaryCheck, BinaryComparison, ClauseReport, EventRecord, FileReport,
    GuardClauseReport, InComparison, Messages, UnaryCheck, UnaryComparison, ValueComparisons,
    ValueUnResolved,
};

use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use crate::rules::{
    BlockCheck, ClauseCheck, EvaluationType, MembershipLead, NamedStatus, QueryResult, RecordType,
    Status, UnResolved,
};
use fancy_regex::Regex;
use lazy_static::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::convert::TryInto;
use std::fmt::Debug;
use std::hash::{Hash, Hasher};
use std::io::Write;

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct Comparison {
    pub(super) operator: CmpOperator,
    pub(super) not_operator_exists: bool,
}

impl From<(CmpOperator, bool)> for Comparison {
    fn from(input: (CmpOperator, bool)) -> Self {
        Comparison {
            operator: input.0,
            not_operator_exists: input.1,
        }
    }
}

/// The message, if it says anything.
///
/// A clause that carries no custom message records `Some("")` rather than `None`, so a plain `or` over
/// the two message slots reports a blank reason -- which reads as a rendering bug rather than as a
/// message nobody wrote.
///
/// A function rather than a closure: a closure taking `&Option<String>` and returning `Option<&str>`
/// cannot express that the two lifetimes are the same one, and rustc rejects it.
fn non_empty_message(message: &Option<String>) -> Option<&str> {
    message.as_deref().filter(|text| !text.trim().is_empty())
}

/// The text as one line, so that nothing an author wrote can pass for a line this section writes itself.
///
/// A `<< >>` message arrives with the author's own line breaks in it, and so does a clause context holding
/// a quoted literal that spans lines. This section writes an entry as a line of context indented by two
/// and a line of explanation indented by four, under a heading at column zero. Written raw, a line break
/// inside either one puts a further line into the output at whatever column the author chose: at column
/// zero it is shaped exactly like a heading, and at two exactly like an entry's context. A rule whose
/// message holds
///
/// ```text
/// Could not be evaluated:
///   some_other_rule: Fabricated EXISTS
/// ```
///
/// therefore printed a heading the tool never emitted, and under it an entry naming a rule that does not
/// exist and never failed. The same reads back from `Description == "alpha<newline>Could not be
/// evaluated:"`, where the forgery is in the context rather than in the message.
///
/// Collapsed onto one line rather than re-indented, which is the other way to keep the shapes apart.
/// `emit_messages` re-indents, because a per-resource entry is a brace block with a line per message and
/// has a shape to re-indent into; an entry here is two lines by construction. Collapsing is also what
/// the other message writers reached from the validate reporter chain do -- `print_name_info` below and
/// `generic_summary` -- each replacing a break with a semicolon. The only divergence is the separator:
/// those two write `";"` and this writes `"; "`.
///
/// `\r` as well as `\n`. A bare carriage return does not begin a line in a file, but it returns the cursor
/// to column zero in a terminal and overwrites what was there, which forges a line just as well.
///
/// Rule names are not put through this. A name is an identifier, so it cannot hold a line break, and
/// pretending otherwise would suggest to a reader that it can.
///
/// No defence against a terminal control sequence. An author who writes an ANSI cursor movement into a
/// message can still move the cursor -- here and through every other reporter in this file, none of which
/// escapes one either. That is a property of the writer rather than of this section.
fn one_line(text: &str) -> String {
    text.split(['\n', '\r'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// What the per-resource output showed, in the two forms the unattributed section has to ask about.
///
/// `pprint_clauses` renders a clause only when it is in that resource's own set, so the union of those sets
/// is exactly the set of nodes shown, and node identity is what answers "was this finding shown".
///
/// This was a set of trimmed context *strings*, which cannot tell one clause from another when the two
/// render as the same text. `two_clauses_that_share_a_context.guard` is a rule with a placed clause and a
/// pathless one whose rendered text is byte-identical; the placed one made the pathless one count as
/// already shown, so it appeared nowhere while the JSON carried its reason. Exit 19 either way, so nothing
/// was misreported and a real finding was simply missing -- which is the class of fault this section exists
/// to remove. Counted over the fixture corpus and the AWS rule registry, 2940 rule/data pairs produce 47
/// groups of clauses sharing a context and exactly one of them mixes a placed member with an unplaced one.
///
/// Identity alone is not enough, and `in_comparisons` is why the string set was there. For
/// `"a,b" == join(%collection, ",")` the evaluator records two reports under one context: an `UnResolved`
/// one for the literal on the left, whose value is the unlocated document root and which is therefore
/// placed nowhere, and an `InResolved` one for the comparison that ran, whose value has a path under
/// `/Resources/`. Only the second is rendered, so by identity the first is unshown, and printing it
/// restates a finding already on screen. That one group is the mixed one above.
///
/// The two cases look alike on every field this code can read -- both are two separate `ClauseReport` nodes,
/// adjacent siblings of one rule, with identical `context`, identical `custom_message`, differing
/// `error_message`, one member placed and one not -- and differ only in the check they carry. That
/// difference is not incidental. An `InResolved` report is produced by one arm of `simplified_json_from_root`
/// and only for a clause the evaluator ran an in-comparison for, so an `UnResolved` report sharing its
/// context is that same clause's other half. Two distinct clauses have to render as the same text to
/// collide, which means they are the same clause text written twice, and each then contributes its own pair.
pub(super) struct Rendered<'record, 'value: 'record> {
    nodes: HashSet<IdentityHash<'record, ClauseReport<'value>>>,
    in_comparisons: HashSet<String>,
}

impl<'record, 'value: 'record> Rendered<'record, 'value> {
    pub(super) fn of<'a>(
        resources: impl Iterator<Item = &'a LocalResourceAggr<'record, 'value>>,
    ) -> Self
    where
        'record: 'a,
    {
        let mut nodes = HashSet::new();
        let mut in_comparisons = HashSet::new();
        for resource in resources {
            for held in &resource.clauses {
                nodes.insert(held.clone());
                if let ClauseReport::Clause(GuardClauseReport::Binary(binary)) = held.key {
                    if matches!(binary.check, BinaryCheck::InResolved(_)) {
                        in_comparisons.insert(binary.context.trim().to_string());
                    }
                }
            }
        }
        Rendered {
            nodes,
            in_comparisons,
        }
    }

    /// Whether the per-resource output already accounted for this finding.
    fn shows(&self, clause: &'record ClauseReport<'value>) -> bool {
        if self.nodes.contains(&IdentityHash { key: clause }) {
            return true;
        }
        match clause {
            ClauseReport::Clause(GuardClauseReport::Binary(binary)) => {
                matches!(binary.check, BinaryCheck::UnResolved(_))
                    && self.in_comparisons.contains(binary.context.trim())
            }
            _ => false,
        }
    }
}

/// Collect `(context, explanation)` for failed blocks the per-resource output did not render.
///
/// The gate is what the reporter actually showed, not what a path predicts it will show. A gate on
/// `unresolved.is_none()` rests on the reasoning that a block which failed while traversing a query keeps
/// the value it got to and is rendered through it; that holds only when the value has a path: of the four
/// constructors of a block report, `MissingBlockValue` sets `unresolved: Some(..)`, and when the query fails
/// at the *document root* the value it traversed to has an empty path. Such a block is rendered by nobody --
/// `pprint_clauses` has no bucket for it -- and a gate that skipped it here too would leave a rule querying
/// a top-level property against a CloudFormation template exiting 19 saying nothing at all. That is the
/// everyday shape of the very defect this section exists for, in block syntax.
///
/// What it recovers is the evaluator's account and not the author's message. A block report's
/// `custom_message` is always absent: three of the four constructors set it to
/// `None` outright, and the fourth, `MissingBlockValue`, copies a field whose one producer at `eval.rs`
/// sets `None` as well -- which is why the JSON for `block_query_at_the_document_root.guard` shows the empty
/// string there rather than a message. `non_empty_message` drops it, so the arm below reads a half that is
/// never there. Left in place rather than deleted: the block arm's shape is the clause arm's, and carrying
/// an author's message through to it is a change to what the section prints for every block finding, so it
/// wants its own commit and its own verification. A `<< >>` written on a clause inside the block is a
/// different message again, recorded on that clause, and a block whose query fails never runs it.
///
/// Here rather than in one reporter because every reporter that groups findings by resource needs it, and
/// for the same reason: a finding that belongs to no resource has no bucket to be rendered in, so a reporter
/// that only walks buckets exits 19 having said nothing. `cfn.rs` grew this first; `tf.rs` had the identical
/// gap and no fixture reaching it.
///
/// Each block is labelled with the rule it came from, which `collect_clause_explanations` says of a clause
/// in words that hold here unaltered: without the label the section repeats itself for no reason a reader
/// can see, and two rules spelling the same failing block clause produce byte-identical entries. Threaded
/// down the same way, from the rule arm rather than read off the block, because a block does not know which
/// rule contains it and a disjunction between them does not change the answer.
///
/// The label was clause-only, so a run could show a labelled clause entry and an unlabelled block entry
/// under one heading, and three (rules file, rule) pairs over the fixture cross product reported FAIL with
/// the rule named nowhere below the summary. All three are blocks whose entry read `GuardAccessClause#block
/// ...` or `GuardBlockAccessClause#Location[...]`, which names the file and line but not the rule.
///
/// `<rule>: <context>` and not `rule <rule>`, which the arm below writes. The difference is what the entry
/// is about. A block and a clause each have a context of their own, and the label answers which rule it sits
/// in; a rule that failed on its own condition has no clause text to print, so `rule` is there to say that
/// the entry's subject is the rule itself.
pub(super) fn collect_unattributed_explanations<'record, 'value: 'record>(
    clause: &'record ClauseReport<'value>,
    rule_name: Option<&str>,
    rendered: &Rendered<'record, 'value>,
    out: &mut Vec<(String, String)>,
) {
    match clause {
        ClauseReport::Block(blk) => {
            let context = match rule_name {
                Some(name) => format!("{name}: {}", one_line(&blk.context)),
                None => one_line(&blk.context),
            };
            if !rendered.shows(clause) {
                let explanation = explanation_of(&blk.messages);
                if !explanation.is_empty() {
                    out.push((context, explanation));
                }
            }
        }

        // Not here. A clause is collected by `collect_clause_explanations`, which the caller reaches for
        // every clause the reporter did not render rather than for every clause under an unrendered rule.
        ClauseReport::Clause(_) => {}
        ClauseReport::Rule(rule) => {
            // A rule that failed on its own condition has no clause findings underneath it, so the
            // per-resource output has nothing to render and this message is the only account of why
            // the rule failed. `checks.is_empty()` is the discriminator: a rule whose clauses produced
            // findings has them rendered per resource already, and repeating the rule-level message
            // there would duplicate rather than explain.
            //
            // Reached when a condition cannot be answered across a rule boundary -- a gate whose
            // referenced or parameterized rule is undecidable. The evaluator records the explanation
            // on the rule, the JSON reporter has always printed it, and the console reporter printed
            // "Number of non-compliant resources 0" and nothing else: a run that exits 19 and does
            // not say why.
            //
            // Through `bounded_for_the_console` like the other two arms (a refusal's explanation is
            // printed whole, any other message is cut), rather than written as recorded. This was the
            // one arm that wrote its message neither collapsed onto a line nor bounded, and the text it
            // writes is not always the evaluator's own: `eval.rs` replaces a called rule's status message
            // with the calling clause's `<< >>` body, so a rule node here can carry an author's message
            // with the author's line breaks still in it. Leaving one arm raw is a difference with nothing
            // behind it. `non_empty_message` for the same reason the arms above use it -- an entry whose
            // explanation is blank reads as a rendering fault rather than as a message nobody wrote.
            if rule.checks.is_empty() {
                if let Some(explanation) = non_empty_message(&rule.messages.custom_message) {
                    out.push((
                        format!("rule {}", rule.name),
                        // The rule record's kind travels with its message: a rule whose condition
                        // raised a refusal prints the refusal whole, one whose condition raised a
                        // converter's error over a template value is held to the cap.
                        bounded_for_the_console(explanation, rule.messages.refusal),
                    ));
                }
            }
            for child in &rule.checks {
                collect_unattributed_explanations(child, Some(rule.name), rendered, out);
            }
        }
        ClauseReport::Disjunctions(ors) => {
            for child in &ors.checks {
                collect_unattributed_explanations(child, rule_name, rendered, out);
            }
        }
    }
}

/// The longest one recorded message this section prints, in characters.
///
/// One message and not one line. An entry's explanation is the author's message and the evaluator's
/// account joined, each cut to this length on its own, so a line carrying both reaches twice it: 647
/// characters at the most, since a cut message is this many plus the three of the ellipsis and the two
/// halves are joined by a space. Measured, a rule whose `<< >>` message is 400 characters against a
/// twelve-bucket template prints 621, of which the author's half is 323 and the evaluator's 297.
///
/// Bounding the joined line instead would have to take the room from one half or the other, and both
/// carry something: the author's message is the half a reader can act on, and the evaluator's names the
/// property and the value it traversed to. At a 320-character line an author who writes 320 characters
/// erases the evaluator's account entirely, and silently -- which is a worse fault than a long line, and
/// the same class of fault as the ellipsis this cap once printed over content nobody had dropped. So the
/// cap stays per message and this comment says which.
///
/// A clause's `error_message` embeds the value its query traversed to, and for a query that resolved to
/// nothing at the document root that value is the whole document -- tens of kilobytes on one line, which
/// is not a report. The reason is at the front of the message, so a prefix carries it. Chosen to hold the
/// longest whole message in the fixture corpus. Only that half can carry a document, so bounding each
/// half bounds the line by a constant rather than by the size of the input, which is what the cap is for.
///
/// Nothing is lost by it: the JSON and YAML reports print the message untruncated and always have.
///
/// 320 because the cap has to clear the longest explanation that carries no embedded value, and clipping
/// one of those is a real loss rather than a saving. Measured over every rule/data pair in the fixture
/// corpus, that is 292 characters: what a failed comparison against an empty selection says, which ends by
/// naming what `when <reference> !empty { ... }` would actually do. At 240 that last sentence was cut off
/// mid-way. An embedded document has no length to clear, so any cap bounds it.
///
/// The 292 was 261 while the same explanation named the `!empty` guard as the remedy. It no longer does --
/// guarding the clause skips the check rather than satisfying it, so the advice disarmed the rule it was
/// printed for -- and saying what the guard does instead costs the difference. Anyone re-tuning this
/// number should re-measure rather than trust either figure, since it tracks a message that changes.
///
/// Counted over the content and not over the indentation around it. A `<< >>` message is written inside
/// the clause that carries it, so every line of it is indented to that clause's nesting depth, and the
/// evaluator records those spaces as part of the string. Charged against the cap, they make the length an
/// author may write depend on how deeply their rule is nested rather than on what the cap is for, which
/// defeats the "longest whole message" the paragraph above chose it to hold.
///
/// Measured over the 233 messages in the AWS rule registry and this repository's fixtures: 9 are longer
/// than 320 characters as written, and 5 are longer once trimmed. The four in between were cut, and
/// marked with an ellipsis as though content had been dropped, on account of their own indentation
/// alone -- the message in `elasticsearch_application_logging_enabled.guard` at 322 characters as written
/// and 276 trimmed, and the one in `opensearch_application_logging_enabled.guard` at 326 and 280, each
/// appearing twice. Median whitespace across all 233 messages is 8 characters and the most is 54.
const LONGEST_RECORDED_MESSAGE: usize = 320;

/// One recorded message, cut to a length a console can show.
///
/// Cut at whitespace, so a word is never split in half. That also drops a *compactly serialised* value
/// whole, because such a value contains no whitespace and is therefore one word -- but only such a value.
/// A document containing a string with a space in it, which is any template with a `Description` or a tag
/// value, has whitespace inside the blob and the cut lands there instead, so up to the cap of unrelated
/// content can still appear. The length is what bounds the output; the whitespace rule only decides where
/// within that bound the cut falls.
///
/// Cutting mid-word would also put half a word into the fixture output, where the spell checker reads it
/// as a misspelling and fails the build. Half of "ServerSideEncryptionConfiguration" did exactly that.
///
/// By character rather than by byte, so a multi-byte character straddling the cut cannot panic.
///
/// Collapsed onto one line by `one_line` before it is measured, which is also what sets the indentation
/// aside: an explanation that fits once its own whitespace is gone comes out whole and carries no ellipsis.
/// An ellipsis is a claim that something was dropped, and a message shortened only because of the spaces
/// around it makes that claim falsely -- the smaller half of the same defect. Measuring the collapsed line
/// rather than the recorded string is measuring what the section actually prints, which is the only length
/// a cap on console output can be about.
///
/// Measured against the raw string the leading whitespace is spent from the same budget as the words, and a
/// message indented far enough spends all of it:
///
/// ```text
/// <<          ... 350 spaces ...          REALREASON>>
/// ```
///
/// The first 320 characters are then all whitespace, the cut at the last whitespace within them leaves 319
/// spaces, `trim_end` empties what is left, and the line renders as a bare `...` with the author's only word
/// gone. Nothing about the length of what they wrote put it there.
fn shortened(message: &str) -> String {
    cut_to(message, LONGEST_RECORDED_MESSAGE)
}

/// The longest refusal explanation the console section prints, in characters. A refusal is the
/// evaluator's own sentence about a read it would not make (`eval_context::refuse`): its definition of `X`, the
/// remedy and the predicate, bounded by the author's query and predicate, and the parts it takes from the
/// template (the path, an entry's or a key's name), each cut on its own at
/// `eval_context::LONGEST_TEMPLATE_PART_IN_A_REFUSAL` characters with a marker, so no template decides its
/// length and it is printed whole. This bound is only a backstop that keeps the line finite
/// whatever a future refusal's sentence holds; the longest refusal text in the fixtures and tests is
/// under a third of it.
///
/// Which messages are refusals is the evaluator's to say, and it says so on the record
/// (`Messages::refusal`, copied from `BlockCheck::refusal`, `ValueCheck::refusal` or
/// `NamedStatus::refusal`, each set from `eval_context::is_refusal` where the error was written into the
/// message). The text cannot say: every `Error::Unevaluatable` displays the same `Clause could not be
/// evaluated against the incoming context` wrapper a refusal does, and the sentences that wrap another
/// error under it ("the body could not be read over the empty selection, so the read is refused: {e}";
/// a converter's "failed to convert a string: {val} into an int at {path}") carry a traversed value.
/// This section once read the wrapper to pick the bound, and a `when` over `parse_int` of a 2 KB
/// template string printed the whole string on its "Could not be evaluated" line, 2205 characters
/// against a 320-character cap written for exactly that value.
const LONGEST_REFUSAL_MESSAGE: usize = 4096;

/// What a refusal explanation cut at `LONGEST_REFUSAL_MESSAGE` ends with, after the ellipsis, so the cut is
/// never silent: it names the bound and where the whole text is.
const REFUSAL_CUT_MARKER: &str =
    "[explanation cut at 4096 characters; `-o json` carries the whole text]";

/// A recorded message, cut to the length its kind allows: a refusal explanation to
/// `LONGEST_REFUSAL_MESSAGE`, anything else to `LONGEST_RECORDED_MESSAGE`.
///
/// A refusal explanation is cut later than any other message because the remedy is the part a reader
/// acts on, and a cut at `LONGEST_RECORDED_MESSAGE`, wrappers counted, would leave a refusal raised inside
/// a `when` condition with about 150 characters of its text: the key's sentence and, for a long query,
/// none of the remedy. The cap exists for a message that embeds a document; a refusal does not, so it is
/// not held to it.
///
/// `refusal` is the kind the evaluator recorded beside the message (`Messages::refusal`), and is the only
/// thing read: a text that happens to carry a refusal's wrapper is cut like any other when the record
/// does not say it is one, and a refusal is printed whole whatever words it uses (the tests under
/// `explanation_tests` hold both). `LONGEST_REFUSAL_MESSAGE` says why the text was not enough.
fn bounded_for_the_console(message: &str, refusal: bool) -> String {
    if refusal {
        let cut = cut_to(message, LONGEST_REFUSAL_MESSAGE);
        // A refusal cut at its backstop says so: the ellipsis alone does not tell a reader the explanation
        // was shortened by the reporter and that `-o json` carries the whole text.
        if one_line(message).chars().count() > LONGEST_REFUSAL_MESSAGE {
            format!("{cut} {REFUSAL_CUT_MARKER}")
        } else {
            cut
        }
    } else {
        shortened(message)
    }
}

/// `message` on one line and no longer than `limit` characters, cut at whitespace and marked with an
/// ellipsis when something was dropped; see `shortened` for why each of those holds.
fn cut_to(message: &str, limit: usize) -> String {
    let collapsed = one_line(message);
    let message = collapsed.as_str();
    let cut = match message.char_indices().nth(limit) {
        Some((at, _)) => at,
        None => return message.to_string(),
    };

    let kept = &message[..cut];
    let kept = match kept.rfind(char::is_whitespace) {
        Some(at) => &kept[..at],
        None => kept,
    };

    format!("{}...", kept.trim_end())
}

/// One entry's explanation: the author's message, then the evaluator's account, each bounded on its own.
///
/// Both messages, in the order a reader wants them, and both bounded. The author's `<< >>` text is the half
/// a reader can act on, and the evaluator's names the property and the value the query traversed to -- which
/// for a query that failed at the document root is the whole document, so it is the half that has to be
/// bounded. `.or_else` over the two was dead code for its second arm: every clause arm records a non-empty
/// `error_message`, so the author's message could never win and never appeared here at all, though the
/// per-resource output prints both.
///
/// The author's half arrives from a clause and never from a block, which records no `custom_message` on any
/// of its four constructors. `collect_unattributed_explanations` says where that is decided.
///
/// Bounded per message rather than over the join. The author's half is at most `LONGEST_RECORDED_MESSAGE`
/// characters plus the ellipsis; the evaluator's half is the same unless the record says it is a refusal
/// (`Messages::refusal`), when it is at most `LONGEST_REFUSAL_MESSAGE` plus the ellipsis, a space and
/// `REFUSAL_CUT_MARKER`; a line carrying both halves is the two joined by one space, so
/// `2 * (LONGEST_RECORDED_MESSAGE + 3) + 1` when neither is a refusal, and
/// `(LONGEST_RECORDED_MESSAGE + 3) + 1 + (LONGEST_REFUSAL_MESSAGE + 3 + 1 + REFUSAL_CUT_MARKER.len())`
/// at the widest. Taking the room from one half or the other instead would let an author who writes a long
/// message erase the evaluator's account, and say nothing about having done it.
///
/// The refusal kind applies to the evaluator's half only: the author's `<< >>` text is never a refusal,
/// and a long one is cut whatever the record says about the error beside it. A rule-level record carries
/// the evaluator's sentence in the custom slot instead (`report_all_failed_clauses_for_rules`), and
/// `collect_unattributed_explanations` reads that slot with the record's kind itself; this function sees
/// clause and block reports.
///
/// One function rather than the same expression in the block arm and the clause arm, which is where the
/// `Messages` in both cases comes from, so that the bound above has somewhere to be asserted.
fn explanation_of(messages: &Messages) -> String {
    [
        (non_empty_message(&messages.custom_message), false),
        (non_empty_message(&messages.error_message), messages.refusal),
    ]
    .iter()
    .filter_map(|(message, refusal)| message.map(|text| bounded_for_the_console(text, *refusal)))
    .collect::<Vec<_>>()
    .join(" ")
}

/// Collect `(context, explanation)` for every clause the per-resource output did not render.
///
/// Per clause, against the set of contexts the reporter showed, not per *rule*. A rule-level gate rests on
/// one placed sibling rendering the whole rule and carrying its pathless siblings with it, and that is false:
/// `pprint_clauses` gates every clause individually on membership of the resource's own set, so a clause
/// with no path is skipped there even when its rule renders -- and a rule-level gate here would suppress the
/// only other place it could appear. A rule with one located finding and one pathless one would show the
/// first and lose the second entirely, from the console and from the section both, while the JSON carried
/// its reason.
///
/// Deciding per clause on its own would print a second entry for a clause already shown, because the
/// evaluator emits two reports for one comparison it resolved one way and could not resolve another -- the
/// `join_with_message.guard` fixture has exactly that, and it is what fails when the rule-level gate is
/// simply removed. `Rendered` is what separates the two cases, and by node identity rather than by rendered
/// text: two clauses that render as the same string are still two findings.
///
/// Each entry is labelled with the rule it came from, because without that the section repeats itself for
/// no reason a reader can see. Two rules that share a clause -- `seven-compliant-rules.guard` has three
/// spelling `Region == "us-east-1"` -- produce identical context and identical message, so an unlabelled
/// section printed the same two lines three times over and said nothing about which rules failed.
/// Deduplicating instead would have hidden that three rules failed rather than one, which is the fact the
/// reader is here for.
fn collect_clause_explanations<'record, 'value: 'record>(
    report: &'record ClauseReport<'value>,
    rule_name: Option<&str>,
    rendered: &Rendered<'record, 'value>,
    out: &mut Vec<(String, String)>,
) {
    match report {
        ClauseReport::Clause(clause) => {
            let (context, messages) = match clause {
                GuardClauseReport::Unary(unary) => (&unary.context, &unary.messages),
                GuardClauseReport::Binary(binary) => (&binary.context, &binary.messages),
            };
            let context = one_line(context);
            if rendered.shows(report) {
                return;
            }
            let explanation = explanation_of(messages);
            if !explanation.is_empty() {
                let labelled = match rule_name {
                    Some(name) => format!("{name}: {context}"),
                    None => context,
                };
                out.push((labelled, explanation));
            }
        }
        // A nested rule relabels: the clause belongs to the rule that spells it out, not to whichever
        // rule referred to that one.
        ClauseReport::Rule(rule) => {
            for child in &rule.checks {
                collect_clause_explanations(child, Some(rule.name), rendered, out);
            }
        }
        ClauseReport::Disjunctions(ors) => {
            for child in &ors.checks {
                collect_clause_explanations(child, rule_name, rendered, out);
            }
        }
        // Handled by `collect_unattributed_explanations`, which asks the same question of a block.
        ClauseReport::Block(_) => {}
    }
}

/// One heading at column zero, then two lines per entry: the context indented by two and the explanation
/// by four.
///
/// Both halves of every entry arrive as one line, because the collectors put every context and every
/// message through `one_line`. That invariant is what makes the indentation mean anything: a further line
/// at column zero would read as a heading and one at two spaces as another entry's context, and the entry
/// this function is writing would have written both.
fn write_section(
    writer: &mut dyn Write,
    heading: &str,
    explanations: Vec<(String, String)>,
) -> crate::rules::Result<()> {
    if explanations.is_empty() {
        return Ok(());
    }

    writeln!(writer, "{heading}")?;
    for (context, message) in explanations {
        writeln!(writer, "  {context}")?;
        writeln!(writer, "    {message}")?;
    }

    Ok(())
}

/// Render the findings the per-resource output has nowhere to put, after it.
///
/// Writes nothing when there are none, so a reporter can call it unconditionally.
///
/// Two headings, because there are two reasons a finding ends up here and they are not the same answer.
/// A block or rule that failed on a condition nobody could decide has no verdict to report about the
/// data -- `Could not be evaluated`. A clause under a rule that no resource claimed was decided
/// perfectly well and merely has no bucket to be printed in; calling that "could not be evaluated" would
/// report an ordinary missing property as an undecidable one, which is the class of misreport this
/// section exists to remove.
///
/// The second case: a rule none of whose findings has a path is rendered nowhere at all, because both
/// console reporters match a rule to a resource through its findings' paths. `let numeric = 5` followed
/// by `%numeric empty` records a serviceable explanation -- "Attempting EMPTY operation on type int that
/// does not support it" -- and the JSON reporter has always printed it. The console reporter dropped it:
/// the operand is a literal, so the value has an empty path, the aggregation consumes only keys under
/// `/Resources/`, and the demotion check leaves the file here because an empty key is not a *located*
/// path outside `/Resources/`. The run exited 19 saying "Number of non-compliant resources 0" and
/// nothing else. A rule querying a top-level property against a CloudFormation template reaches it the
/// same way, which is how four fixture pairs in `output-dir/rules_dir_against_data_dir.out` exited 19
/// without a reason.
///
/// Asked of every clause and block against `rendered`, the set of contexts the per-resource output showed.
/// Asking once per rule and predicting the answer from the findings' paths would be wrong in both
/// directions: it would suppress a pathless clause whose rule happens to have a located sibling, and it
/// could not see a block whose query failed at the document root.
pub(super) fn write_unattributed_explanations<'record, 'value: 'record>(
    writer: &mut dyn Write,
    not_compliant: &'record [ClauseReport<'value>],
    rendered: &Rendered<'record, 'value>,
) -> crate::rules::Result<()> {
    let mut undecidable = Vec::new();
    let mut unplaceable = Vec::new();
    for each_rule in not_compliant {
        collect_unattributed_explanations(each_rule, None, rendered, &mut undecidable);
        collect_clause_explanations(each_rule, None, rendered, &mut unplaceable);
    }

    write_section(writer, "Could not be evaluated:", undecidable)?;
    write_section(writer, "Findings that belong to no resource:", unplaceable)?;

    Ok(())
}

#[derive(Debug, PartialEq, Serialize)]
pub(super) struct NameInfo<'a> {
    pub(super) rule: &'a str,
    pub(super) path: String,
    pub(super) provided: Option<serde_json::Value>,
    pub(super) expected: Option<serde_json::Value>,
    pub(super) comparison: Option<Comparison>,
    pub(super) message: String,
    pub(super) error: Option<String>,
    /// `Some` for a membership-shaped failure: what [`crate::rules::InComparisonCheck::lead`] decided the sentence
    /// leads with, taken from the record and never re-derived here. A plain comparison, including a
    /// `Val == [1, 2]` whose expected value happens to be a list, has no lead and keeps its own
    /// sentence. Not serialized: the renderers read it, the reports do not carry it.
    #[serde(skip)]
    pub(super) lead: Option<MembershipLead>,
}

/// The verdict clause of a membership-shaped failure, or `None` when the failure is not one and the
/// renderer's plain comparison wording applies.
///
/// One sentence per lead, and the lead is the record's own ([`crate::rules::InComparisonCheck::lead`]), so the
/// console and the structured report cannot disagree on which state a record is in:
/// - not compared, under any operator: a refused pairing, or a right-hand value the query could not
///   reach, reads "could not be compared with expected value in", and the reason follows as the
///   error message. "was not present in" would assert an answer the comparison never had;
/// - a failed `==` over a set was equal to none of it, "is not equal to any of";
/// - a failed `!=` over a set was equal to the elements the lead names, "is equal to \[a\], one of",
///   which states the pair that excluded the key and no other. A record per right-hand value, each
///   stamped with the key's one verdict, said "a did match b" for an element the key was not equal
///   to, and that is the sentence this replaces;
/// - a decided `IN` or `NOT IN` failure keeps its wording to the byte, "{op_msg} match expected
///   value in".
pub(super) fn membership_lead_verdict(
    op_msg: &str,
    info: &NameInfo<'_>,
) -> crate::rules::Result<Option<String>> {
    Ok(Some(match &info.lead {
        None => return Ok(None),
        Some(MembershipLead::NotCompared(_)) => {
            "could not be compared with expected value in".to_string()
        }
        Some(MembershipLead::NotEqualToAny) => "is not equal to any of".to_string(),
        Some(MembershipLead::EqualTo(matched)) => {
            format!("is equal to {}, one of", values_of(matched)?)
        }
        Some(MembershipLead::Membership) => format!("{op_msg} match expected value in"),
    }))
}

/// The JSON array of a record's right-hand values, an unresolved one standing as the value the
/// query reached.
pub(super) fn values_of(results: &[QueryResult]) -> crate::rules::Result<serde_json::Value> {
    let mut values = Vec::new();
    for each in results {
        let (_, value): (String, serde_json::Value) = match each {
            QueryResult::Literal(l) => (&**l).try_into()?,
            QueryResult::Resolved(v) => (&**v).try_into()?,
            QueryResult::UnResolved(ur) => (&*ur.traversed_to).try_into()?,
        };
        values.push(value);
    }
    Ok(serde_json::Value::Array(values))
}

impl<'a> Default for NameInfo<'a> {
    fn default() -> Self {
        NameInfo {
            rule: "",
            path: "".to_string(),
            lead: None,
            provided: None,
            expected: None,
            comparison: None,
            message: "".to_string(),
            error: None,
        }
    }
}

/// Rules that did not apply, each with the evaluator's reason when it recorded one.
///
/// One map rather than a name set plus a parallel reason map: the reason belongs to the skip, and
/// two collections keyed by rule name can drift. `None` is the ordinary case -- most skips are a
/// condition that legitimately did not match -- and `Some` is for the skips where the evaluator
/// knows something the reader cannot infer from a bare "not applicable".
pub(super) type SkippedRules = HashMap<String, Option<String>>;

pub(super) trait GenericReporter: Debug {
    #[allow(clippy::too_many_arguments)]
    fn report(
        &self,
        writer: &mut dyn Write,
        rules_file_name: &str,
        data_file_name: &str,
        failed: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: SkippedRules,
        longest_rule_len: usize,
    ) -> crate::rules::Result<()>;
}

#[derive(Debug)]
#[allow(clippy::upper_case_acronyms)]
pub(super) enum StructureType {
    JSON,
    YAML,
}

#[derive(Debug)]
pub(super) struct StructuredSummary {
    hierarchy_type: StructureType,
}

impl StructuredSummary {
    pub(super) fn new(hierarchy_type: StructureType) -> Self {
        StructuredSummary { hierarchy_type }
    }
}

#[derive(Debug, Serialize)]
struct DataOutput<'a> {
    data_from: &'a str,
    rules_from: &'a str,
    not_compliant: HashMap<String, Vec<NameInfo<'a>>>,
    not_applicable: HashSet<String>,
    /// Omitted entirely when no skip carried a reason, which keeps the document shape identical
    /// to what consumers parse today. BTreeMap rather than HashMap so the order is stable across
    /// runs -- a reporter that reshuffles its own output on every invocation is unusable in a
    /// diff.
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    not_applicable_reasons: BTreeMap<String, String>,
    compliant: HashSet<String>,
}

impl GenericReporter for StructuredSummary {
    fn report(
        &self,
        writer: &mut dyn Write,
        rules_file_name: &str,
        data_file_name: &str,
        failed: HashMap<String, Vec<NameInfo<'_>>>,
        passed: HashSet<String>,
        skipped: SkippedRules,
        _: usize,
    ) -> crate::rules::Result<()> {
        let not_applicable_reasons = skipped
            .iter()
            .filter_map(|(rule, reason)| reason.clone().map(|reason| (rule.clone(), reason)))
            .collect::<BTreeMap<String, String>>();
        let value = DataOutput {
            rules_from: rules_file_name,
            data_from: data_file_name,
            not_compliant: failed,
            compliant: passed,
            not_applicable: skipped.into_keys().collect(),
            not_applicable_reasons,
        };

        match &self.hierarchy_type {
            StructureType::JSON => writeln!(writer, "{}", serde_json::to_string(&value)?),
            StructureType::YAML => writeln!(writer, "{}", serde_yaml::to_string(&value)?),
        }?;
        Ok(())
    }
}

lazy_static! {
    static ref PATH_FROM_MSG: Regex = Regex::new(r"path\s+=\s+(?P<path>[^ ]+)").ok().unwrap();
}

pub(super) fn find_failing_clauses<'record, 'value>(
    current: &'record EventRecord<'value>,
) -> Vec<&'record EventRecord<'value>> {
    match &current.container {
        Some(RecordType::Filter(_)) | Some(RecordType::ClauseValueCheck(ClauseCheck::Success)) => {
            vec![]
        }

        Some(RecordType::ClauseValueCheck(_)) => vec![current],
        Some(RecordType::RuleCheck(NamedStatus {
            message: Some(_),
            status: Status::FAIL,
            ..
        })) => vec![current],

        // A clause that failed without producing any per-value result carries its explanation on the
        // block record instead, and there is no `ClauseValueCheck` underneath it to find. The
        // empty-reference failures are the case that matters: the comparison never ran, so nothing
        // was recorded per value, and a reporter that walks past the block reports nothing at all -- a
        // run that exits 19 and prints an empty violation section.
        //
        // Children first, so a block that does have per-value findings still reports those. Reporting
        // the block instead would replace a path and a value with a one-line summary, which is the
        // opposite of the intent.
        Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            message: Some(_),
            status: Status::FAIL,
            ..
        })) => {
            let mut from_children = Vec::new();
            for child in &current.children {
                from_children.extend(find_failing_clauses(child));
            }
            match from_children.is_empty() {
                true => vec![current],
                false => from_children,
            }
        }

        _ => {
            let mut acc = Vec::new();
            for child in &current.children {
                acc.extend(find_failing_clauses(child));
            }
            acc
        }
    }
}

pub(super) fn extract_name_info_from_record<'record>(
    rule_name: &'record str,
    clause: &'record EventRecord<'_>,
) -> crate::rules::Result<NameInfo<'record>> {
    Ok(match &clause.container {
        Some(RecordType::RuleCheck(NamedStatus {
            message: Some(msg),
            name,
            ..
        })) => NameInfo {
            message: msg.clone(),
            rule: name,
            ..Default::default()
        },

        // The block-level counterpart of the arms below: no path and no value, because the comparison
        // never ran against one. The explanation is all there is, and printing it beats printing
        // nothing.
        Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            message: Some(msg), ..
        })) => NameInfo {
            error: Some(msg.clone()),
            rule: rule_name,
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::DependentRule(missing))) => NameInfo {
            error: missing.message.clone(),
            message: missing
                .custom_message
                .as_ref()
                .map_or("".to_string(), |m| m.clone()),
            rule: rule_name,
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::MissingBlockValue(missing))) => NameInfo {
            rule: rule_name,
            error: missing.message.clone(),
            message: missing
                .custom_message
                .as_ref()
                .map_or("".to_string(), |s| s.clone()),
            path: missing
                .from
                .unresolved_traversed_to()
                .map_or("".to_string(), |s| s.self_path().0.clone()),
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::Unary(check))) => match &check.value.from {
            // A literal is reported as the resolved value it is. The two variants carry the same payload
            // and differ only in that a literal's path is the unlocated root.
            //
            // These three arms were `unreachable!()` and a reachability triage could not construct inputs
            // for them, for a precise reason worth recording: a unary clause with a literal left-hand side
            // died earlier, in `eval_context`, which *shadowed* these. Fixing that one made these
            // reachable -- `let numeric = 5` plus `%numeric empty` now arrives here -- so the panic simply
            // moved one layer out until this was fixed too.
            QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                let (path, provided): (String, serde_json::Value) = (&**res).try_into()?;
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: check.value.message.clone(),
                    message: check
                        .value
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    path,
                    ..Default::default()
                }
            }

            QueryResult::UnResolved(unres) => {
                let (path, provided): (String, serde_json::Value) =
                    (&*unres.traversed_to).try_into()?;
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: Some(check.value.message.as_ref().map_or(
                        unres.reason.as_ref().map_or("".to_string(), |r| r.clone()),
                        |msg| msg.clone(),
                    )),
                    message: check
                        .value
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    path,
                    ..Default::default()
                }
            }
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(check))) => match &check.from {
            QueryResult::Literal(res) | QueryResult::Resolved(res) => {
                let (path, provided): (String, serde_json::Value) = (&**res).try_into()?;
                let expected: Option<(String, serde_json::Value)> = match &check.to {
                    Some(to) => match to {
                        QueryResult::Literal(v) | QueryResult::Resolved(v) => {
                            Some((&**v).try_into()?)
                        }
                        QueryResult::UnResolved(ur) => Some((&*ur.traversed_to).try_into()?),
                    },
                    None => None,
                };
                let expected = expected.map(|(_, ex)| ex);
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: check.message.clone(),
                    message: check
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    expected,
                    path,
                    ..Default::default()
                }
            }

            QueryResult::UnResolved(unres) => {
                let (path, provided): (String, serde_json::Value) =
                    (&*unres.traversed_to).try_into()?;
                NameInfo {
                    rule: rule_name,
                    comparison: Some(check.comparison.into()),
                    error: Some(check.message.as_ref().map_or(
                        unres.reason.as_ref().map_or("".to_string(), |r| r.clone()),
                        |msg| msg.clone(),
                    )),
                    message: check
                        .custom_message
                        .as_ref()
                        .map_or("".to_string(), |msg| msg.clone()),
                    provided: Some(provided),
                    path,
                    ..Default::default()
                }
            }
        },

        // A filter-ending `!empty` whose selection was empty, or a lone variable (`%v !empty`) bound to
        // one; the evaluator writes this record on both paths. The record carries no value and no
        // polarity, and defaulting the polarity to the positive operator would make the summary read
        // "needed value at [null] was not empty" -- the opposite of why the clause failed -- under a
        // blank "Property []". The evaluator writes this record only for the
        // negated form over an empty selection (the positive form over nothing passes), so the operator
        // that failed is known to be NOT EMPTY, the value is the empty selection itself, and the query is
        // the closest thing the clause has to a path. The sentence the unary closures build from these
        // three reads "Property [<query>] ... needed value at [[]] was empty".
        //
        // The path is the query the record carries, not the clause's own rendering. That rendering is
        // the whole clause -- its `not`, its query, and its operator -- so the subject read "Property
        // [Items. (filter-clauses) not EMPTY]": the operator appeared twice in one sentence, the
        // `not Items[..] empty` spelling put the `not` in front of the query, and `(filter-clauses)`
        // stood in for every filter, so two clauses filtering the same collection differently were
        // reported under one subject. The record's query spells its filters out.
        Some(RecordType::ClauseValueCheck(ClauseCheck::NoValueForEmptyCheck(check))) => NameInfo {
            rule: rule_name,
            path: check.query.clone(),
            provided: Some(serde_json::Value::Array(vec![])),
            comparison: Some(Comparison {
                not_operator_exists: true,
                operator: CmpOperator::Empty,
            }),
            message: String::from(check.custom_message.as_ref().map_or("", |s| s.as_str())),
            ..Default::default()
        },

        Some(RecordType::ClauseValueCheck(ClauseCheck::InComparison(incomp))) => {
            let provided = match incomp.from.resolved() {
                Some(val) => {
                    let (_, value): (String, serde_json::Value) = (&*val).try_into()?;
                    Some(value)
                }
                None => None,
            };
            NameInfo {
                rule: rule_name,
                comparison: Some(Comparison {
                    not_operator_exists: incomp.comparison.1,
                    operator: incomp.comparison.0,
                }),
                provided,
                expected: Some(values_of(&incomp.to)?),
                // The record decides its own lead; the renderers only format it.
                lead: Some(incomp.lead()),
                message: String::from(incomp.message.as_ref().map_or("", |s| s.as_str())),
                ..Default::default()
            }
        }

        _ => unreachable!(),
    })
}

pub(super) fn report_from_events(
    root_record: &EventRecord<'_>,
    writer: &mut dyn Write,
    data_file_name: &str,
    rules_file_name: &str,
    renderer: &dyn GenericReporter,
) -> crate::rules::Result<()> {
    let mut longest_rule_length = 0;
    let mut failed = HashMap::new();
    let mut skipped = SkippedRules::new();
    let mut success = HashSet::new();
    for each_rule in &root_record.children {
        if let Some(RecordType::RuleCheck(NamedStatus { status, name, .. })) = &each_rule.container
        {
            if name.len() > longest_rule_length {
                longest_rule_length = name.len();
            }
            match status {
                Status::FAIL => {
                    let mut clauses = Vec::new();
                    for each_clause in find_failing_clauses(each_rule) {
                        clauses.push(extract_name_info_from_record(name, each_clause)?);
                    }
                    failed.insert(name.to_string(), clauses);
                }

                Status::PASS => {
                    success.insert(name.to_string());
                }

                Status::SKIP => {
                    skipped.insert(name.to_string(), find_skip_reason(each_rule));
                }
            }
        }
    }

    renderer.report(
        writer,
        rules_file_name,
        data_file_name,
        failed,
        success,
        skipped,
        longest_rule_length,
    )?;
    Ok(())
}

pub(super) fn extract_name_info<'a>(
    rule_name: &'a str,
    each_failing_clause: &StatusContext,
) -> crate::rules::Result<NameInfo<'a>> {
    if each_failing_clause.from.is_some() {
        let value = each_failing_clause.from.as_ref().unwrap();
        let (path, from): (String, serde_json::Value) = value.try_into()?;
        Ok(NameInfo {
            rule: rule_name,
            path,
            // The pre-record path has no record to ask. The one membership state it can carry is a
            // decided `IN` or `NOT IN` failure, so that is the lead a membership operator gets here,
            // and the wording of this path is unchanged.
            lead: each_failing_clause
                .comparator
                .filter(|(operator, _)| *operator == CmpOperator::In)
                .map(|_| MembershipLead::Membership),
            provided: Some(from),
            expected: match &each_failing_clause.to {
                Some(to) => {
                    let (_, val): (String, serde_json::Value) = to.try_into()?;
                    Some(val)
                }
                None => None,
            },
            comparison: each_failing_clause.comparator.map(|input| input.into()),
            message: each_failing_clause
                .msg
                .as_ref()
                .map_or("".to_string(), |e| {
                    if !e.contains("DEFAULT") {
                        e.clone()
                    } else {
                        "".to_string()
                    }
                }),
            error: None,
        })
    } else {
        //
        // This is crappy, but we are going to extract information from the retrieval error message
        // see path_value.rs for retrieval error messages.
        // TODO merge the query interface to retrieve partial results along with errored one ones and then
        //      change this logic based on the reporting changes. Today we bail out for the first
        //      retrieval error, fast fail semantics
        //

        //
        // No from is how we indicate retrieval errors.
        //
        let (path, error) =
            each_failing_clause
                .msg
                .as_ref()
                .map_or(
                    ("".to_string(), "".to_string()),
                    |msg| match PATH_FROM_MSG.captures(msg) {
                        Ok(Some(cap)) => (cap["path"].to_string(), msg.clone()),
                        Ok(None) => ("".to_string(), msg.clone()),
                        Err(_) => panic!("Error while parsing retrieval errors"),
                    },
                );

        Ok(NameInfo {
            rule: rule_name,
            path,
            error: Some(error),
            ..Default::default()
        })
    }
}

pub(super) fn colored_string(status: Option<Status>) -> ColoredString {
    let status = match status {
        Some(s) => s,
        None => Status::SKIP,
    };
    match status {
        Status::PASS => "PASS".green(),
        Status::FAIL => "FAIL".red().bold(),
        Status::SKIP => "SKIP".yellow().bold(),
    }
}

pub(super) fn find_all_failing_clauses(context: &StatusContext) -> Vec<&StatusContext> {
    let mut failed = Vec::with_capacity(context.children.len());
    for each in &context.children {
        if each.status.map_or(false, |s| s == Status::FAIL) {
            match each.eval_type {
                EvaluationType::Clause | EvaluationType::BlockClause => {
                    failed.push(each);
                    if each.eval_type == EvaluationType::BlockClause {
                        failed.extend(find_all_failing_clauses(each));
                    }
                }

                EvaluationType::Filter | EvaluationType::Condition => {
                    continue;
                }

                _ => failed.extend(find_all_failing_clauses(each)),
            }
        }
    }
    failed
}

pub(super) fn print_compliant_skipped_info(
    writer: &mut dyn Write,
    passed: &HashSet<String>,
    skipped: &HashSet<String>,
    _: &str,
    data_file_name: &str,
) -> crate::rules::Result<()> {
    if !passed.is_empty() {
        writeln!(writer, "--")?;
    }
    for pass in passed {
        writeln!(
            writer,
            "Rule [{}] is compliant for template [{}]",
            pass, data_file_name
        )?;
    }
    if !skipped.is_empty() {
        writeln!(writer, "--")?;
    }
    for skip in skipped {
        writeln!(
            writer,
            "Rule [{}] is not applicable for template [{}]",
            skip, data_file_name
        )?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn print_name_info<R, U, B>(
    writer: &mut dyn Write,
    info: &[NameInfo<'_>],
    _: usize,
    rules_file_name: &str,
    data_file_name: &str,
    retrieval_error: R,
    unary_message: U,
    binary_message: B,
) -> crate::rules::Result<()>
where
    R: Fn(&str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
    U: Fn(&str, &str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
    B: Fn(&str, &str, &str, &NameInfo<'_>) -> crate::rules::Result<String>,
{
    for each in info {
        let _ = match &each.comparison {
            Some(cmp) => (Some(cmp.operator), cmp.not_operator_exists),
            None => (None, false),
        };
        // CFN = Resource [<name>] was not compliant with [<rule-name>] for property [<path>] because provided value [<value>] did not match expected value [<value>]. Error Message [<msg>]
        // General = Violation of [<rule-name>] for property [<path>] because provided value [<value>] did not match expected value [<value>]. Error Message [<msg>]
        // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
        match each.error {
            Some(_) => {
                // Block Clause retrieval error
                writeln!(
                    writer,
                    "{}",
                    retrieval_error(rules_file_name, data_file_name, each)?
                )?;
            }

            None => {
                let (cmp, not) = match &each.comparison {
                    Some(cmp) => (cmp.operator, cmp.not_operator_exists),
                    None => {
                        // "Rule", not "Parameterized Rule". This is the arm for a failure carried on
                        // the rule rather than on a clause comparison. An ordinary rule arrives here
                        // too, with a rule-level message -- a condition that could not be evaluated --
                        // so naming the arm after parameterized rules would announce it as something
                        // it is not. A parameterized rule is still a rule, so the shorter word is
                        // correct for both rather than a trade between them.
                        writeln!(
                            writer,
                            "Rule {rule_name} failed for {data}. Reason {msg}",
                            data = data_file_name,
                            rule_name = each.rule,
                            msg = each.message.replace('\n', "; ")
                        )?;
                        continue;
                    }
                };
                if cmp.is_unary() {
                    use CmpOperator::*;
                    writeln!(
                        writer,
                        "{}",
                        unary_message(
                            rules_file_name,
                            data_file_name,
                            match cmp {
                                Exists =>
                                    if !not {
                                        "did not exist"
                                    } else {
                                        "existed"
                                    },
                                Empty =>
                                    if !not {
                                        "was not empty"
                                    } else {
                                        "was empty"
                                    },
                                IsList =>
                                    if !not {
                                        "was not a list "
                                    } else {
                                        "was list"
                                    },
                                IsMap =>
                                    if !not {
                                        "was not a struct"
                                    } else {
                                        "was struct"
                                    },
                                IsString =>
                                    if !not {
                                        "was not a string "
                                    } else {
                                        "was string"
                                    },
                                IsBool =>
                                    if !not {
                                        "was not a bool"
                                    } else {
                                        "was bool"
                                    },
                                IsInt =>
                                    if !not {
                                        "was not an int"
                                    } else {
                                        "was int"
                                    },
                                IsNull =>
                                    if !not {
                                        "was not null"
                                    } else {
                                        "was null"
                                    },
                                IsFloat =>
                                    if !not {
                                        "was not a float"
                                    } else {
                                        "was float"
                                    },
                                Eq | In | Gt | Lt | Le | Ge => unreachable!(),
                            },
                            each
                        )?,
                    )?;
                } else {
                    // EQUALS failed at property path Properties.Encrypted because provided value [false] did not match with expected value [true].
                    writeln!(
                        writer,
                        "{}",
                        binary_message(
                            rules_file_name,
                            data_file_name,
                            if not { "did" } else { "did not" },
                            each
                        )?,
                    )?;
                }
            }
        }
    }

    Ok(())
}

#[derive(Debug, Serialize)]
struct DataOutputNewForm<'a, 'v> {
    data_from: &'a str,
    rules_from: &'a str,
    report: FileReport<'v>,
}

#[derive(Clone, Debug)]
pub(super) struct LocalResourceAggr<'record, 'value: 'record> {
    pub(super) name: String,
    pub(super) resource_type: &'value str,
    pub(super) cdk_path: Option<&'value str>,
    pub(super) clauses: HashSet<IdentityHash<'record, ClauseReport<'value>>>,
    pub(super) paths: BTreeSet<String>,
}

#[derive(Clone, Debug)]
pub(super) struct IdentityHash<'key, T> {
    pub(super) key: &'key T,
}

impl<'key, T> Hash for IdentityHash<'key, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        std::ptr::hash(self.key, state)
    }
}

impl<'key, T> Eq for IdentityHash<'key, T> {}
impl<'key, T> PartialEq for IdentityHash<'key, T> {
    fn eq(&self, other: &Self) -> bool {
        std::ptr::eq(self.key, other.key)
    }
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub(super) struct Node<'report, 'value: 'report> {
    pub(super) parent: std::rc::Rc<String>,
    pub(super) path: std::rc::Rc<String>,
    pub(super) clause: &'report ClauseReport<'value>,
}

pub(super) type RuleHierarchy<'report, 'value> =
    BTreeMap<std::rc::Rc<String>, std::rc::Rc<Node<'report, 'value>>>;

pub(super) type PathTree<'report, 'value> =
    BTreeMap<String, Vec<std::rc::Rc<Node<'report, 'value>>>>;

/// The key a finding's value is filed under in the path tree: the pointer of its node in `data`,
/// or its path string when no node has that path (a literal, a value a function computed).
///
/// The path string alone was the key, and two nodes can share one -- a resource named `A/B` and a
/// key `B` under a resource `A` -- so their findings were filed together and the resource loops below
/// attributed both to whichever one the lookup found. The pointer spells the `/` inside a key as `~1`
/// and so names one node; the index resolves the path by its string and source position.
fn path_tree_key(data: &Traversal<'_>, value: &PathAwareValue) -> String {
    let path = value.self_path();
    match data.pointer_for(path) {
        Some(pointer) => pointer.to_string(),
        None => path.0.to_string(),
    }
}

pub(super) fn insert_into_trees<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    parent: std::rc::Rc<String>,
    data: &Traversal<'_>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>,
) {
    let path = std::rc::Rc::new(clause.key(&parent));
    let node = std::rc::Rc::new(Node {
        parent,
        path: path.clone(),
        clause,
    });
    hierarchy.insert(path, node.clone());

    if let Some(from) = clause.value_from() {
        let path = path_tree_key(data, &from);
        path_tree.entry(path).or_default().push(node.clone());
    }

    // The value a finding was compared WITH is filed under its path only when that path names a
    // resource, which is what the resource aggregation in `cfn.rs` consumes: `A.Prop == B.Prop` is then
    // reported under both resources. A reference that lives elsewhere -- a `Mappings` entry, a `Parameters`
    // default, an element of a `let`-bound literal list (path `/0`, no location) -- is where the
    // comparison's reference is, not where the finding is, so it is not filed: filed, it demoted the whole
    // file to the generic reporter, because `single_line` reads every located path outside `/Resources/`
    // as a finding it cannot place. The finding itself is filed above, under the value it is about.
    // The test is on the path string, whose first segment escaping never touches; the key it is filed
    // under is the node's pointer, as for the value the finding is about.
    if let Some(to) = clause.value_to() {
        if to.self_path().0.starts_with("/Resources/") {
            let path = path_tree_key(data, &to);
            path_tree.entry(path).or_default().push(node);
        }
    }
}

pub(super) fn insert_into_trees_from_parent<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    children: &'report [ClauseReport<'value>],
    parent: std::rc::Rc<String>,
    data: &Traversal<'_>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>,
) {
    let path = std::rc::Rc::new(clause.key(&parent));
    let node = std::rc::Rc::new(Node {
        parent,
        path: path.clone(),
        clause,
    });
    hierarchy.insert(path.clone(), node);

    for each in children {
        populate_hierarchy_path_trees(each, path.clone(), data, path_tree, hierarchy);
    }
}

pub(super) fn populate_hierarchy_path_trees<'report, 'value: 'report>(
    clause: &'report ClauseReport<'value>,
    parent: std::rc::Rc<String>,
    data: &Traversal<'_>,
    path_tree: &mut PathTree<'report, 'value>,
    hierarchy: &mut RuleHierarchy<'report, 'value>,
) {
    match clause {
        ClauseReport::Clause(_) | ClauseReport::Block(_) => {
            insert_into_trees(clause, parent, data, path_tree, hierarchy)
        }

        ClauseReport::Disjunctions(ors) => {
            insert_into_trees_from_parent(clause, &ors.checks, parent, data, path_tree, hierarchy)
        }

        ClauseReport::Rule(rr) => {
            insert_into_trees_from_parent(clause, &rr.checks, parent, data, path_tree, hierarchy)
        }
    }
}

/// The `Message` and `Error` lines of a clause's report.
///
/// The guard decides on the filtered pieces rather than on the raw string, and matches on them instead
/// of indexing. Emptiness everywhere else here is `trim`-based, and a `!message.is_empty()` guard on the
/// raw string disagrees with it on exactly one input: a message that holds something but nothing that
/// survives trimming. `<<  >>` is such a message, and so is `<<;>>`. The split produces pieces, the
/// filter drops all of them, and `message[0]` on the empty vector panics -- turning a clause failure that
/// should report at exit 19 into an abort at exit 101. A policy tool that crashes where it should record
/// a violation is worse than one that reports nothing, because a caller reading only the status sees a
/// broken run rather than a failed check.
///
/// Matching rather than indexing makes the empty case one the compiler makes us handle rather than one a
/// future reader has to remember. A guard added next to an index would leave the two notions of
/// emptiness disagreeing.
///
/// A whitespace-only message renders as absent, which is the answer the two neighbouring sites already
/// give: `non_empty_message` filters on `!text.trim().is_empty()`, and `one_line` collapses such a
/// message to nothing so that "`non_empty_message` and this function agree about what counts as a
/// message". Preserving it verbatim was the alternative and is rejected for the reason
/// `non_empty_message`'s own comment gives: a blank reason reads as a rendering fault rather than as a
/// message nobody wrote.
///
/// This does *not* bring the default output into line with the structured ones. `-o json` and `-o yaml`
/// exit 19 and emit the message **verbatim**. There are two `custom_message` fields per document and only
/// the deeper one carries it:
///
/// ```text
/// .not_compliant[0].Rule.messages.custom_message                         = null
/// .not_compliant[0].Rule.checks[0].Clause.Binary.messages.custom_message = '  '
/// ```
///
/// The structured formats never decided this question, and the consequence runs the other way: the
/// default writes nothing where json and yaml carry `'  '`, so the formats disagree about whether a
/// message exists. That is a real cost of the choice, accepted because a report beats an abort and
/// because the two sites above had already settled what counts as a message. Reading only the first
/// `custom_message` in the document shows `null` and makes the formats look like they agree; they do not.
///
/// The error half is reachable whatever the message holds: a clause carrying a whitespace-only custom
/// message and a real evaluator error keeps the error.
fn emit_messages(
    writer: &mut dyn Write,
    prefix: &str,
    message: &str,
    error: &str,
    width: usize,
) -> crate::rules::Result<()> {
    let pieces: Vec<&str> = if message.contains(';') {
        message.split(';').collect()
    } else if message.contains('\n') {
        message.split('\n').collect()
    } else {
        vec![message]
    };
    let pieces: Vec<&str> = pieces
        .iter()
        .map(|s| s.trim_start().trim_end())
        .filter(|s| !s.is_empty())
        .collect();

    match pieces.as_slice() {
        // No message. Nothing an author wrote survived, so nothing is written.
        [] => {}
        [only] => {
            writeln!(
                writer,
                "{prefix}{mh:<width$} = {message}",
                prefix = prefix,
                message = only,
                mh = "Message",
                width = width
            )?;
        }
        many => {
            writeln!(
                writer,
                "{prefix}{mh:<width$} {{",
                prefix = prefix,
                mh = "Message",
                width = width
            )?;
            for each in many {
                writeln!(
                    writer,
                    "{prefix}  {message}",
                    prefix = prefix,
                    message = each,
                )?;
            }
            writeln!(writer, "{prefix}}}", prefix = prefix,)?;
        }
    }

    if !error.is_empty() {
        writeln!(
            writer,
            "{prefix}{eh:<width$} = {error}",
            prefix = prefix,
            error = error,
            eh = "Error",
            width = width
        )?;
    }

    Ok(())
}

fn emit_retrieval_error(
    writer: &mut dyn Write,
    prefix: &str,
    vur: &ValueUnResolved,
    clause: &ClauseReport<'_>,
    context: &str,
    message: &str,
    err_emitter: &mut dyn ComparisonErrorWriter,
) -> crate::rules::Result<()> {
    writeln!(
        writer,
        "{prefix}Check = {cxt} {{",
        prefix = prefix,
        cxt = context
    )?;
    let check_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    emit_messages(writer, &prefix, message, "", 0)?;

    // An unresolved result with nothing left of its query is a value that was found and that a
    // function had no answer for (`resolve_function`), not a property that is missing, so it is printed
    // as `NoAnswerError` with no `MissingProperty` line: `MissingProperty = to_lower(..)` would name a
    // key that was never asked for. The reason line carries what happened.
    let value_found = vur.value.remaining_query.is_empty();
    let kind = match value_found {
        true => "NoAnswerError",
        false => "RequiredPropertyError",
    };
    writeln!(writer, "{prefix}{kind} {{", prefix = prefix)?;
    let rpe_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    writeln!(
        writer,
        "{prefix}PropertyPath = {path}",
        prefix = prefix,
        path = vur.value.traversed_to.self_path()
    )?;

    if !value_found {
        writeln!(
            writer,
            "{prefix}MissingProperty = {prop}",
            prefix = prefix,
            prop = vur.value.remaining_query
        )?;
    }

    let reason = vur.value.reason.as_ref().map_or("", String::as_str);
    if !reason.is_empty() {
        writeln!(
            writer,
            "{prefix}Reason = {reason}",
            prefix = prefix,
            reason = reason
        )?;
    }
    err_emitter.missing_property_msg(writer, clause, Some(&vur.value), &prefix)?;
    writeln!(writer, "{}", rpe_end)?;
    writeln!(writer, "{}", check_end)?;
    Ok(())
}

pub(super) trait ComparisonErrorWriter {
    fn missing_property_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: Option<&UnResolved>,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }

    fn binary_error_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: &BinaryComparison,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }

    fn binary_error_in_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: &InComparison,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }

    fn unary_error_msg(
        &mut self,
        _writer: &mut dyn Write,
        _cr: &ClauseReport<'_>,
        _bc: &UnaryComparison,
        _prefix: &str,
    ) -> crate::rules::Result<usize> {
        Ok(0)
    }
}

pub(super) fn pprint_clauses<'report, 'value: 'report>(
    writer: &mut dyn Write,
    clause: &'report ClauseReport<'value>,
    resource: &LocalResourceAggr<'report, 'value>,
    prefix: String,
    err_writer: &mut dyn ComparisonErrorWriter,
) -> crate::rules::Result<()> {
    match clause {
        ClauseReport::Rule(rr) => {
            writeln!(
                writer,
                "{prefix}Rule = {rule} {{",
                prefix = prefix,
                rule = rr.name.bright_magenta()
            )?;
            let rule_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            let message = rr
                .messages
                .custom_message
                .as_ref()
                .map_or("", String::as_str);
            let error = rr
                .messages
                .error_message
                .as_ref()
                .map_or("", String::as_str);
            emit_messages(writer, &prefix, message, error, 0)?;
            writeln!(writer, "{prefix}ALL {{", prefix = prefix)?;
            let all_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            for child in &rr.checks {
                pprint_clauses(writer, child, resource, prefix.clone(), err_writer)?;
            }
            writeln!(writer, "{}", all_end)?;
            writeln!(writer, "{}", rule_end)?;
        }

        ClauseReport::Disjunctions(ors) => {
            writeln!(writer, "{prefix}ANY {{", prefix = prefix)?;
            let end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            for child in &ors.checks {
                pprint_clauses(writer, child, resource, prefix.clone(), err_writer)?;
            }
            writeln!(writer, "{}", end)?;
        }

        ClauseReport::Block(blk) => {
            if !resource.clauses.contains(&IdentityHash { key: clause }) {
                return Ok(());
            }
            writeln!(
                writer,
                "{prefix}Check = {cxt} {{",
                prefix = prefix,
                cxt = blk.context
            )?;
            let check_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            writeln!(writer, "{prefix}RequiredPropertyError {{", prefix = prefix)?;
            let mpv_end = format!("{}}}", prefix);
            let prefix = format!("{}  ", prefix);
            let (traversed_to, query) = blk.unresolved.as_ref().map_or(("", ""), |val| {
                (&val.traversed_to.self_path().0, &val.remaining_query)
            });
            let width = if !traversed_to.is_empty() {
                let width = "MissingProperty".len() + 4;
                writeln!(
                    writer,
                    "{prefix}{pp:<width$}= {path}\n{prefix}{mp:<width$}= {q}",
                    prefix = prefix,
                    pp = "PropertyPath",
                    width = width,
                    path = traversed_to,
                    mp = "MissingProperty",
                    q = query
                )?;
                width
            } else {
                "Message".len() + 4
            };
            let mut post_message: Vec<u8> = Vec::new();
            let width = std::cmp::max(
                width,
                err_writer.missing_property_msg(
                    &mut post_message,
                    clause,
                    blk.unresolved.as_ref(),
                    &prefix,
                )?,
            );
            let message = blk
                .messages
                .custom_message
                .as_ref()
                .map_or("", String::as_str);
            let error = blk
                .messages
                .error_message
                .as_ref()
                .map_or("", String::as_str);
            emit_messages(writer, &prefix, message, error, width)?;
            writeln!(
                writer,
                "{}",
                match String::from_utf8(post_message) {
                    Ok(msg) => msg,
                    Err(_) => "".to_string(),
                }
            )?;
            writeln!(writer, "{}", mpv_end)?;
            writeln!(writer, "{}", check_end)?;
        }

        ClauseReport::Clause(gac) => {
            if !resource.clauses.contains(&IdentityHash { key: clause }) {
                return Ok(());
            }
            match gac {
                GuardClauseReport::Unary(ur) => match &ur.check {
                    UnaryCheck::UnResolved(vur) => {
                        emit_retrieval_error(
                            writer,
                            &prefix,
                            vur,
                            clause,
                            &ur.context,
                            ur.messages
                                .custom_message
                                .as_ref()
                                .map_or("", String::as_str),
                            err_writer,
                        )?;
                    }

                    UnaryCheck::Resolved(re) => {
                        writeln!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = ur.context
                        )?;
                        let check_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        writeln!(writer, "{prefix}ComparisonError {{", prefix = prefix)?;
                        let ce_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        let mut post_message: Vec<u8> = Vec::new();
                        let width =
                            err_writer.unary_error_msg(&mut post_message, clause, re, &prefix)?;
                        let message = ur
                            .messages
                            .custom_message
                            .as_ref()
                            .map_or("", String::as_str);
                        let error = ur
                            .messages
                            .error_message
                            .as_ref()
                            .map_or("", String::as_str);
                        emit_messages(writer, &prefix, message, error, width)?;
                        writeln!(
                            writer,
                            "{}",
                            match String::from_utf8(post_message) {
                                Ok(msg) => msg,
                                Err(_) => "".to_string(),
                            }
                        )?;
                        writeln!(writer, "{}", ce_end)?;
                        writeln!(writer, "{}", check_end)?;
                    }

                    _ => {}
                },

                GuardClauseReport::Binary(br) => match &br.check {
                    BinaryCheck::UnResolved(vur) => {
                        emit_retrieval_error(
                            writer,
                            &prefix,
                            vur,
                            clause,
                            &br.context,
                            br.messages
                                .custom_message
                                .as_ref()
                                .map_or("", String::as_str),
                            err_writer,
                        )?;
                    }

                    BinaryCheck::Resolved(bc) => {
                        writeln!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = br.context
                        )?;
                        let check_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        writeln!(writer, "{prefix}ComparisonError {{", prefix = prefix)?;
                        let ce_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        let mut post_message: Vec<u8> = Vec::new();
                        let width =
                            err_writer.binary_error_msg(&mut post_message, clause, bc, &prefix)?;
                        let message = br
                            .messages
                            .custom_message
                            .as_ref()
                            .map_or("", String::as_str);
                        let error = br
                            .messages
                            .error_message
                            .as_ref()
                            .map_or("", String::as_str);
                        emit_messages(writer, &prefix, message, error, width)?;
                        writeln!(
                            writer,
                            "{}",
                            match String::from_utf8(post_message) {
                                Ok(msg) => msg,
                                Err(_) => "".to_string(),
                            }
                        )?;

                        writeln!(writer, "{}", ce_end)?;
                        writeln!(writer, "{}", check_end)?;
                    }

                    BinaryCheck::InResolved(inr) => {
                        writeln!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = br.context
                        )?;
                        let check_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        writeln!(writer, "{prefix}ComparisonError {{", prefix = prefix)?;
                        let ce_end = format!("{}}}", prefix);
                        let prefix = format!("{}  ", prefix);
                        let mut post_message: Vec<u8> = Vec::new();
                        let width = err_writer.binary_error_in_msg(
                            &mut post_message,
                            clause,
                            inr,
                            &prefix,
                        )?;
                        let message = br
                            .messages
                            .custom_message
                            .as_ref()
                            .map_or("", String::as_str);
                        let error = br
                            .messages
                            .error_message
                            .as_ref()
                            .map_or("", String::as_str);
                        emit_messages(writer, &prefix, message, error, width)?;
                        writeln!(writer, "{}", ce_end)?;
                        writeln!(
                            writer,
                            "{}",
                            match String::from_utf8(post_message) {
                                Ok(msg) => msg,
                                Err(_) => "".to_string(),
                            }
                        )?;
                        writeln!(writer, "{}", check_end)?;
                    }
                },
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod emit_messages_tests {
    use super::emit_messages;

    fn emit(message: &str, error: &str) -> String {
        let mut written: Vec<u8> = Vec::new();
        emit_messages(&mut written, "", message, error, 0).expect("writing to a Vec cannot fail");
        String::from_utf8(written).expect("the output is UTF-8")
    }

    /// A message that holds something but nothing that survives trimming writes no message.
    ///
    /// This is the panic, in the shape a rule author writes it. `rule one { ... <<  >> }` against a
    /// template the clause fails aborted at exit 101 -- `index out of bounds` in `emit_messages` -- where
    /// the same run with a real message, or with `-o json`, exits 19. A policy tool that crashes where it
    /// should record a violation reports a broken run rather than a failed check, and a caller reading
    /// only the status cannot tell those apart.
    ///
    /// An `emit_messages` that indexed the filtered pieces without checking for none would fail this
    /// test by panicking rather than by comparing wrong output: the harness catches the panic and marks
    /// the cell failed, so no `#[should_panic]` and no out-of-process run is needed to see it.
    ///
    /// Every case below is a real input. The whitespace ones are `char::is_whitespace`, which is what
    /// `trim` uses -- U+00A0, U+0085, U+2028 and U+3000 are all `White_Space=yes`. The separators are
    /// included because splitting happens before filtering, so a lone `;` yields two empty pieces and
    /// reaches the same index.
    #[test]
    fn a_message_that_trims_to_nothing_writes_no_message() {
        for (name, message) in [
            ("two spaces, as `<<  >>` gives", "  "),
            ("a tab", "\t"),
            ("a lone semicolon, which splits into two empty pieces", ";"),
            ("semicolons and spaces", " ; ; "),
            ("a newline", "\n"),
            ("U+00A0 no-break space", "\u{00A0}"),
            ("U+0085 next line", "\u{0085}"),
            ("U+2028 line separator", "\u{2028}"),
            ("U+3000 ideographic space", "\u{3000}"),
            ("the empty string, which was always handled", ""),
        ] {
            assert_eq!(
                "",
                emit(message, ""),
                "{} is not a message, so nothing is written for it",
                name
            );
        }
    }

    /// U+FEFF is not whitespace, so it is a message and is written.
    ///
    /// `char::is_whitespace` follows `White_Space`, and the zero-width no-break space is not in it. The
    /// distinction is worth pinning: it is the nearest input to the panicking ones that must still
    /// produce a line, so a fix that reached for "looks blank to me" instead of `trim` would fail here.
    #[test]
    fn a_zero_width_no_break_space_is_still_a_message() {
        assert_eq!("Message = \u{FEFF}\n", emit("\u{FEFF}", ""));
    }

    /// The error is written even when the message is not, which it was not before.
    ///
    /// `emit_messages` panicked on the message half and never reached the error half, so a clause
    /// carrying a whitespace-only custom message and a real evaluator account lost the account as well.
    #[test]
    fn an_error_survives_a_message_that_trims_to_nothing() {
        assert_eq!(
            "Error = Check was not compliant.\n",
            emit("  ", "Check was not compliant.")
        );
    }

    /// The ordinary shapes are untouched: one piece is a line, more than one is a brace block.
    ///
    /// Here because the empty-message guard sits in the code path these shapes take, and the empty case
    /// is the only one meant to behave differently. A trailing separator still leaves one piece rather
    /// than promoting the message to a block.
    #[test]
    fn the_ordinary_shapes_are_unchanged() {
        assert_eq!(
            "Message = Encryption is required.\n",
            emit("Encryption is required.", "")
        );
        assert_eq!(
            "Message = Encryption is required.\n",
            emit("Encryption is required.;", ""),
            "a trailing separator leaves one piece, not two"
        );
        assert_eq!(
            "Message {\n  Violation: no.\n  Fix: yes.\n}\n",
            emit("Violation: no.;Fix: yes.", "")
        );
        assert_eq!(
            "Message {\n  Violation: no.\n  Fix: yes.\n}\n",
            emit("Violation: no.\nFix: yes.", ""),
            "and a newline splits the same way a semicolon does"
        );
        assert_eq!(
            "Message = Encryption is required.\nError = Check was not compliant.\n",
            emit("Encryption is required.", "Check was not compliant.")
        );
    }
}

#[cfg(test)]
mod one_line_tests {
    use super::one_line;

    /// The forgery this exists to stop, in the shape a rule author writes it. Two of the three lines
    /// are indistinguishable from lines the section writes itself: `Could not be evaluated:` at column
    /// zero is a heading, and `some_other_rule: Fabricated EXISTS` at two spaces is an entry naming a
    /// rule. Neither the rule nor the failure is real.
    #[test]
    fn a_message_cannot_forge_a_heading_or_an_entry() {
        let message = "\nCould not be evaluated:\n  some_other_rule: Fabricated EXISTS\n    a reason nobody recorded\n  ";

        let line = one_line(message);

        assert_eq!(
            "Could not be evaluated:; some_other_rule: Fabricated EXISTS; a reason nobody recorded",
            line
        );
        assert!(!line.contains('\n'), "one line: {}", line);
    }

    /// A bare carriage return. It begins no line in a file, so a reader of a redirected run sees one
    /// line either way, but in a terminal it returns the cursor to column zero and what follows
    /// overwrites what came before -- which is a forged line for the reader who is actually watching.
    #[test]
    fn a_carriage_return_is_a_line_break_too() {
        assert_eq!(
            "before; Could not be evaluated:",
            one_line("before\rCould not be evaluated:")
        );
        assert_eq!("a; b", one_line("a\r\nb"), "and CRLF is one break, not two");
    }

    /// Each line's own indentation goes with it. The author of a `<< >>` message indents it to the
    /// depth of the clause carrying it, and joining those spaces onto the previous sentence would put
    /// a run of them mid-line for no reason a reader could see.
    #[test]
    fn each_line_is_trimmed_and_a_blank_one_is_dropped() {
        assert_eq!(
            "Violation: no.; Fix: yes.",
            one_line("\n    Violation: no.\n\n    Fix: yes.\n  ")
        );
    }

    /// A message with nothing in it stays with nothing in it, so that `non_empty_message` and this
    /// function agree about what counts as a message. An entry whose explanation is a lone `; ` would
    /// read as a rendering fault.
    #[test]
    fn whitespace_alone_collapses_to_nothing() {
        assert_eq!("", one_line("  \n\n \r\n "));
    }

    /// The ordinary case is left exactly as it was, which is what keeps this off the output of every
    /// run that had nothing wrong with it.
    #[test]
    fn a_message_already_on_one_line_is_unchanged() {
        let message = "Check was not compliant as property [Name] is missing.";
        assert_eq!(message, one_line(message));
    }
}

#[cfg(test)]
mod explanation_tests {
    use super::{
        explanation_of, LONGEST_RECORDED_MESSAGE, LONGEST_REFUSAL_MESSAGE, REFUSAL_CUT_MARKER,
    };
    use crate::rules::errors::Error;
    use crate::rules::eval_context::{is_refusal, refuse, root_scope_for, Messages};
    use crate::rules::exprs::RulesFile;
    use crate::rules::path_value::PathAwareValue;
    use std::convert::TryFrom;
    use std::rc::Rc;

    /// The wrapper every `Error::Unevaluatable` displays, a refusal included. Named in the tests so that
    /// the rows which plant it in a text the record does NOT call a refusal read as what they are.
    const UNEVALUATABLE_WRAPPER: &str =
        "Clause could not be evaluated against the incoming context `";

    fn messages(custom: &str, error: &str) -> Messages {
        Messages {
            custom_message: Some(custom.to_string()),
            error_message: Some(error.to_string()),
            location: None,
            refusal: false,
        }
    }

    /// The evaluator's message with the record's word that it embeds a refusal.
    fn refusal(error: &str) -> Messages {
        Messages {
            refusal: true,
            ..messages("", error)
        }
    }

    /// The cap bounds one message, so a line carrying two reaches twice it plus the space between them.
    /// Asserted here because the constant's own comment says so, and because a reader who trusts the name
    /// alone would expect 320. Both halves are cut to the cap and marked, so the arithmetic is exact rather
    /// than an upper bound: two ellipses and one space.
    #[test]
    fn a_line_carrying_two_messages_is_twice_the_cap() {
        let line = explanation_of(&messages(&"a".repeat(500), &"b".repeat(500)));

        assert_eq!(2 * (LONGEST_RECORDED_MESSAGE + 3) + 1, line.chars().count());
        assert_eq!(647, line.chars().count(), "which is 647 characters");
    }

    /// And neither half is spent on the other. This is why the cap is per message: the author's text is the
    /// half a reader can act on, the evaluator's names the property, and a bound over the join would have to
    /// take one's room from the other -- silently, and by however much the author wrote.
    #[test]
    fn a_long_author_message_does_not_erase_the_evaluators_account() {
        let line = explanation_of(&messages(
            &"WRITTEN ".repeat(80),
            "Check was not compliant as property [Name] is missing.",
        ));

        assert!(line.starts_with("WRITTEN"), "the author's half is first");
        assert!(
            line.ends_with("Check was not compliant as property [Name] is missing."),
            "and the evaluator's account is whole behind it: {}",
            line
        );
    }

    /// A refusal and any other unevaluatable clause display the same wrapper, so the text of a message
    /// cannot say which it embeds. This is why the kind travels on the record (`Messages::refusal`) and
    /// why the section reads that and not the words; the two rows after this one hold each half.
    #[test]
    fn a_refusal_and_any_other_unevaluatable_clause_display_alike() {
        // The registry registers under a live root scope only, so the test holds one for its span.
        let scope_rules =
            RulesFile::try_from("rule r { Resources exists }").expect("one rule parses");
        let _scope = root_scope_for(
            &scope_rules,
            Rc::new(PathAwareValue::try_from("{ Resources: { A: 1 } }").expect("one map parses")),
            None,
        );
        let refused = refuse("the console's sentence, refused".to_string()).to_string();
        let unevaluatable =
            Error::Unevaluatable("the console's sentence, refused".to_string()).to_string();

        assert_eq!(refused, unevaluatable);
        assert!(
            refused.starts_with(UNEVALUATABLE_WRAPPER)
                && refused.ends_with("the console's sentence, refused`"),
            "the displayed error is {:?}",
            refused
        );
        // The registered text is a refusal, by exact text; a text the evaluator never registered is not,
        // however close it comes.
        assert!(is_refusal(&refuse(
            "the console's sentence, refused".to_string()
        )));
        assert!(!is_refusal(&Error::Unevaluatable(
            "the console's sentence, refused by nobody".to_string()
        )));
    }

    /// The wrapper alone lifts nothing. An unevaluatable clause whose text carries a traversed value, a
    /// converter's message over a 2 KB template string here, wears the same wrapper a refusal does, and the
    /// record does not call it a refusal, so the line is cut at the cap and the value is gone from it.
    /// The section once read the wrapper and printed such a line whole, about thirteen times the cap.
    #[test]
    fn the_wrapper_alone_does_not_lift_the_cap() {
        let value = "0123456789abcdef".repeat(128);
        assert_eq!(2048, value.len());
        let text = format!(
            "The rule's condition could not be evaluated, so the rule fails rather than being treated \
             as not applicable: {UNEVALUATABLE_WRAPPER}failed to convert a string: {value} into an int \
             at /Resources/Big/Properties/Size`"
        );

        let line = explanation_of(&messages("", &text));

        assert!(line.ends_with("..."), "{}", line);
        assert!(
            line.chars().count() <= LONGEST_RECORDED_MESSAGE + 3,
            "{} characters: {}",
            line.chars().count(),
            line
        );
        assert!(
            !line.contains(&value),
            "the value is dropped whole: {}",
            line
        );
        assert!(!line.contains(REFUSAL_CUT_MARKER), "{}", line);
    }

    /// And the record's word is what lifts it: a message the record calls a refusal is printed whole
    /// past the cap whatever words it uses, the wrapper absent here on purpose.
    #[test]
    fn the_records_kind_lifts_the_cap_without_the_wrapper() {
        let text = format!("The read was refused. {}", "word ".repeat(100))
            .trim_end()
            .to_string();
        assert!(text.chars().count() > LONGEST_RECORDED_MESSAGE);

        let line = explanation_of(&refusal(&text));

        assert_eq!(text, line);
    }

    /// A refusal explanation is printed whole. Its definition, remedy and path run well past the 320
    /// characters every other message is held to, and the remedy is the part a reader acts on; behind the
    /// condition site's wrapper and the error's own, a cap cut it away for a realistic query.
    #[test]
    fn a_refusal_explanation_past_the_cap_is_printed_whole() {
        let sentence = format!(
            "`[*]` then no kept entry holds a key the predicate names. Write `X[*] {{ Key == value }}` or \
             `X[*].Key == value`, where `X` is `{}`. At path /Resources/A.",
            "Resources.WebServer.Properties.Configuration.Settings".repeat(4)
        );
        let text = format!(
            "The rule's condition could not be evaluated: {UNEVALUATABLE_WRAPPER}{sentence}`"
        );
        assert!(text.chars().count() > LONGEST_RECORDED_MESSAGE);

        let line = explanation_of(&refusal(&text));

        assert_eq!(text, line);
        assert!(!line.ends_with("..."), "{}", line);
    }

    /// The same length without the record's word is cut: the cap is for a message that may embed a
    /// document, and only a refusal is exempt from it.
    #[test]
    fn a_message_that_is_not_a_refusal_keeps_the_cap() {
        let line = explanation_of(&messages(
            "",
            &format!("Check was not compliant {}", "word ".repeat(200)),
        ));

        assert!(line.ends_with("..."), "{}", line);
        assert!(line.chars().count() <= LONGEST_RECORDED_MESSAGE + 3);
    }

    /// The author's half is never a refusal: a long `<< >>` text beside a refusal is cut at the cap while
    /// the refusal beside it is whole, so the record's kind lifts one half and not the other.
    #[test]
    fn the_authors_half_keeps_the_cap_beside_a_refusal() {
        let author = "WRITTEN ".repeat(80);
        let text = format!("The read was refused. {}", "word ".repeat(100))
            .trim_end()
            .to_string();
        let line = explanation_of(&Messages {
            refusal: true,
            ..messages(&author, &text)
        });

        assert!(line.starts_with("WRITTEN WRITTEN"), "{}", line);
        assert!(line.contains("... The read was refused."), "{}", line);
        assert!(line.ends_with(&text), "{}", line);
    }

    /// A refusal that embeds a value is still bounded, by a constant and not by the size of the input, and
    /// the cut is marked: the ellipsis, then a marker that names the bound and where the whole text is.
    #[test]
    fn a_refusal_is_bounded_by_the_backstop_and_the_cut_is_marked() {
        let text = format!("{UNEVALUATABLE_WRAPPER}{}`", "word ".repeat(5000));

        let line = explanation_of(&refusal(&text));

        assert!(
            line.ends_with(&format!("... {}", REFUSAL_CUT_MARKER)),
            "{}",
            line
        );
        assert!(
            line.chars().count()
                <= LONGEST_REFUSAL_MESSAGE + 3 + 1 + REFUSAL_CUT_MARKER.chars().count()
        );
        assert!(
            REFUSAL_CUT_MARKER.contains(&LONGEST_REFUSAL_MESSAGE.to_string()),
            "the marker names the bound it is written for: {}",
            REFUSAL_CUT_MARKER
        );
    }

    /// A refusal that fits its bound carries no marker.
    #[test]
    fn a_refusal_within_the_bound_carries_no_cut_marker() {
        let text = format!("{UNEVALUATABLE_WRAPPER}{}`", "word ".repeat(100));

        let line = explanation_of(&refusal(&text));

        assert!(!line.contains(REFUSAL_CUT_MARKER), "{}", line);
    }

    /// One message on its own is not joined to anything, so it carries no trailing separator. A blank
    /// second message is no message, which is what `non_empty_message` is for.
    #[test]
    fn one_message_alone_is_not_joined() {
        let only = explanation_of(&messages("", "Check was not compliant."));

        assert_eq!("Check was not compliant.", only);
    }
}

#[cfg(test)]
mod shortened_tests {
    use super::{shortened, LONGEST_RECORDED_MESSAGE};

    #[test]
    fn leaves_a_message_that_fits_alone() {
        let message = "Check was not compliant as property [Name] is missing.";
        assert_eq!(message, shortened(message));
    }

    /// The case this exists for. A value the evaluator embedded is compact JSON, so it holds no
    /// whitespace and the cut lands in front of all of it -- the property is still named and the
    /// document is gone, rather than the first 240 bytes of the document being printed.
    #[test]
    fn drops_an_embedded_document_whole() {
        let document = format!(r#"{{"Resources":{{"{}":{{}}}}}}"#, "A".repeat(400));
        let message = format!("Property [Name] is missing. Value traversed to [{document}]");

        let short = shortened(&message);

        assert!(
            short.starts_with("Property [Name] is missing. Value traversed to"),
            "the sentence naming the property survives: {}",
            short
        );
        assert!(
            !short.contains("AAAA"),
            "and none of the document does: {}",
            short
        );
    }

    /// A cut inside a multi-byte character is a panic, not a truncation, so the boundary is found by
    /// character. The `e` is one byte and the `é` two, which puts a character boundary off every
    /// multiple of the cap.
    #[test]
    fn does_not_split_a_multi_byte_character() {
        let message = "é".repeat(LONGEST_RECORDED_MESSAGE * 2);

        let short = shortened(&message);

        assert!(short.ends_with("..."), "it was truncated: {}", short);
        assert!(
            short.chars().filter(|c| *c == 'é').count() <= LONGEST_RECORDED_MESSAGE,
            "to no more than the cap in characters: {}",
            short
        );
    }

    /// No whitespace to cut at leaves the hard limit, which is the point of having one.
    #[test]
    fn still_bounds_a_message_that_is_one_word() {
        let short = shortened(&"x".repeat(LONGEST_RECORDED_MESSAGE * 3));

        assert_eq!(LONGEST_RECORDED_MESSAGE + 3, short.len());
    }

    /// One of the four registry messages the cap was cutting on account of its own indentation, verbatim
    /// from `elasticsearch_application_logging_enabled.guard`. The clause carrying it sits six blocks deep,
    /// so each line arrives with 24 leading spaces and the string the evaluator records is 322 characters
    /// where the author's sentences are 276. Measured raw, that was cut and given an ellipsis -- a report
    /// that content was dropped when none was.
    ///
    /// The three length assertions pin the literal to the registry file, so a transcription slip here
    /// fails as a wrong length rather than passing against a message that is not the one measured. The
    /// third is the length the section prints: the two sentences are one line each in the rule file and
    /// arrive as one line here, so the 25 characters of break and indentation between them become the
    /// two of `; `.
    #[test]
    fn a_message_that_fits_on_one_line_is_left_whole() {
        let message = "\n                        Violation: Elasticsearch domains are are configured to send application logs to Amazon CloudWatch Logs\n                        Fix: In LogPublishingOptions.ES_APPLICATION_LOGS, set Enabled to true and CloudWatchLogsLogGroupArn to the ARN of a Amazon CloudWatch Logs log group.\n                    ";
        let printed = "Violation: Elasticsearch domains are are configured to send application logs to Amazon CloudWatch Logs; Fix: In LogPublishingOptions.ES_APPLICATION_LOGS, set Enabled to true and CloudWatchLogsLogGroupArn to the ARN of a Amazon CloudWatch Logs log group.";

        assert_eq!(
            322,
            message.chars().count(),
            "the message as the evaluator records it, indentation included"
        );
        assert_eq!(
            276,
            message.trim().chars().count(),
            "the part of it the author wrote"
        );
        assert_eq!(
            253,
            printed.chars().count(),
            "and what one line of it is, which fits under the cap"
        );

        let short = shortened(message);

        assert_eq!(
            printed, short,
            "an explanation that fits once collapsed comes out whole"
        );
        assert!(
            !short.ends_with("..."),
            "and unmarked, because nothing was dropped: {}",
            short
        );
    }

    /// The control for the test above: the cap still cuts, and still says so, when the content itself is
    /// over it. Verbatim from `lambda_inside_vpc.guard`, one of the five registry messages that exceed 320
    /// characters after trimming -- 342 as written and 334 trimmed.
    ///
    /// Where it cuts is the discriminator. Charged for its 8 characters of whitespace the message lost
    /// `function's`, the last word of the sentence explaining why the fix is what it is; measured over the
    /// content, that word is inside the cap and survives. Both forms end in an ellipsis, so asserting only
    /// on that would not tell the two apart.
    ///
    /// Three sentences on three lines, so collapsing them onto one saves 6 characters of the 22 this is
    /// over by, and 328 is still over the cap. That is what makes this the control: the message is cut for
    /// its length and not for the space around it.
    #[test]
    fn a_message_over_the_cap_on_one_line_is_still_cut() {
        let message = "\n    Violation:  All AWS Lambda Functions must be configured with access to a VPC\n    Fix: set the VpcConfig.SecurityGroupIds and VpcConfig.SubnetIds parameters with a list of security groups and subnets.\n    Lambda creates an elastic network interface for each combination of security group and subnet in the function's VPC configuration.\n  ";

        assert_eq!(342, message.chars().count());
        assert_eq!(
            334,
            message.trim().chars().count(),
            "over the cap even with the outer indentation set aside"
        );
        assert_eq!(
            328,
            super::one_line(message).chars().count(),
            "and over it on one line, which is the length the cap is applied to"
        );

        let short = shortened(message);

        assert!(short.ends_with("..."), "it was cut, and says so: {}", short);
        assert!(
            short.chars().count() < message.trim().chars().count(),
            "and is shorter than what it was cut from: {}",
            short
        );
        assert!(
            short.contains("in the function's"),
            "the cap measured the content, so this word is inside it: {}",
            short
        );
    }

    /// The pathological form, which makes the mechanism plain. Every character of the cap is whitespace, so
    /// the cut at the last whitespace leaves only spaces, `trim_end` empties them, and the line rendered as
    /// a bare ellipsis -- the author's one word of reason deleted by their own indentation. Reproduced end
    /// to end by a rule whose `<< >>` message is 350 spaces followed by `REALREASON`, which printed a
    /// leading `...` and no reason at all.
    #[test]
    fn leading_whitespace_does_not_swallow_the_message() {
        let message = format!("{}REALREASON", " ".repeat(350));

        let short = shortened(&message);

        assert_eq!("REALREASON", short);
    }
}
