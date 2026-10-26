use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::rules::eval_context::{
    find_skip_reason, BinaryCheck, BinaryComparison, ClauseReport, EventRecord, FileReport,
    GuardClauseReport, InComparison, Messages, RuleReport, UnaryCheck, UnaryComparison,
    ValueComparisons, ValueUnResolved,
};

use crate::rules::path_value::traversal::Traversal;
use crate::rules::path_value::PathAwareValue;
use crate::rules::values::CmpOperator;
use crate::rules::{
    BlockCheck, ClauseCheck, CustomSlot, EvaluationType, MembershipLead, NamedStatus, QueryResult,
    RecordType, Status, UnResolved,
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

/// The message, if it says anything: `crate::rules::non_blank`, which holds the rule (a blank text is no
/// text).
///
/// A clause that carries no custom message records `Some("")` rather than `None`, so a plain `or` over
/// the two message slots reports a blank reason -- which reads as a rendering bug rather than as a
/// message nobody wrote.
fn non_empty_message(message: &Option<String>) -> Option<&str> {
    crate::rules::non_blank(message)
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
/// No defence against a terminal control sequence of its own: an ANSI cursor movement in a message
/// survives the collapse. Every line that prints a recorded message writes the controls as their escapes
/// after it. The STRICT set (`escaped_controls_for_display`) is the default on every console line and
/// field: a key, a path, a context (the rules file path a record context names, through
/// `FileLocation`'s display, is escaped where the position is built, as a file name is), a value, an
/// excerpt, an `Error =` or a `Reason =` text, because an
/// evaluator's sentence quotes keys from the rules file and the template and the record stores it the same
/// way (`reason_backstop`, `write_console_line`). The RELAXED set (`escaped_controls_for_console`), under
/// which a joiner or a mark is ordinary text, applies only to the rule author's `<< >>` message text where
/// it is printed (`plain_author_message`, the `Message =` lines through `write_text_line`, and a rule
/// record's custom slot when the record says the slot holds the author's body, `custom_slot_origin`). Each finished
/// line is escaped once. A line break inside a field is collapsed here first, since both sinks write one
/// line: a context is collapsed at its `Check =` line (`context_line`), and a line feed left in any other
/// field is escaped as `\n` there, never written.
/// The comparison writers format their own lines (`ComparisonErrorWriter`) and escape each field they take
/// from the template before it is formatted in (`console_field`), because their lines also carry the
/// writer's colour, which an escape of the whole line would print as text. The clause arm then applies a
/// backstop to what a writer wrote (`writer_output`), which writes every control as its escape except the
/// text's own layout and the writer's two colour sequences, so a field a writer forgot cannot reach the
/// terminal raw.
fn one_line(text: &str) -> String {
    text.split(['\n', '\r'])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("; ")
}

/// A clause's context for its `Check =` line: as it is, with the spacing the rules file gave it (the
/// context of a clause can open and close with spaces, and the line has always printed them), except a
/// context that spans lines, which is joined as the unattributed section joins it (`one_line`), since the
/// sink writes one line. `one_line` alone trimmed the spaces of every context, and the printed line moved.
/// A break at an end of the text does not span lines: a rules file with CRLF line endings leaves a `\r`
/// after a one-line context, and the context is that one piece as it was written, spacing kept. The
/// join is made only where a break sits between two pieces that hold text.
fn context_line(context: &str) -> String {
    if !context.contains(['\n', '\r']) {
        return context.to_string();
    }
    let mut pieces = context
        .split(['\n', '\r'])
        .filter(|piece| !piece.trim().is_empty());
    match (pieces.next(), pieces.next()) {
        (Some(only), None) => only.to_string(),
        _ => one_line(context),
    }
}

/// Writes one finished console line that prints a KEY, a PATH or a CONTEXT: `line` with every control that
/// breaks or hides a line written as its escape by the strict set (`escaped_controls_for_display`: the
/// joiners and marks included, so a rule key with a pasted joiner does not print like the template's key
/// without it), then a line feed. A field no helper bounded or escaped (a data key holding an ESC, a
/// rules-file context) cannot reach the console raw through it. The escape is idempotent, so a field a
/// caller already escaped (`template_path`) prints unchanged. The line is ONE line: a field that can hold
/// a line break is collapsed (`one_line`) by its caller first, since a line feed in `line` is escaped here
/// and not written.
pub(super) fn write_console_line(
    writer: &mut dyn Write,
    line: std::fmt::Arguments<'_>,
) -> crate::rules::Result<()> {
    let line = line.to_string();
    writeln!(
        writer,
        "{}",
        crate::utils::writer::escaped_controls_for_display(&line)
    )?;
    Ok(())
}

/// Writes one finished console line that prints the rule AUTHOR's message text: as
/// [`write_console_line`], with the relaxed set (`escaped_controls_for_console`), under which a joiner or
/// a mark is ordinary text. An evaluator's error and a reason are not the author's prose and go through
/// [`write_console_line`].
pub(super) fn write_text_line(
    writer: &mut dyn Write,
    line: std::fmt::Arguments<'_>,
) -> crate::rules::Result<()> {
    let line = line.to_string();
    writeln!(
        writer,
        "{}",
        crate::utils::writer::escaped_controls_for_console(&line)
    )?;
    Ok(())
}

/// What a comparison writer wrote into its buffer, as the clause arm prints it: the writer's own lines,
/// run through a BACKSTOP. Every control that breaks or hides a line is written as its escape, except the
/// line feeds and tabs of the text's layout and the two colour sequences a writer wraps around an excerpt
/// line (green and reset, the exact forms; `escaped_but_for_colour_and_layout`), so any other sequence,
/// a conceal included, is written as its escape. The writers escape what they take from
/// the template themselves (`console_field`), so for them this changes nothing; a writer that forgets one
/// field still cannot send a raw control to the terminal.
pub(super) fn writer_output(buffer: Vec<u8>) -> String {
    crate::utils::writer::escaped_but_for_colour_and_layout(
        &String::from_utf8(buffer).unwrap_or_default(),
    )
}

/// A value, a path or a key a comparison writer takes from the template, as one console field: the strict
/// escape (`escaped_controls_for_display`), which also writes a line feed in it as the characters `\n`, so
/// a data string cannot end the writer's line and forge the next. The writers escape each field with this
/// before it is formatted into their lines, and leave the lines' own colour and layout alone.
pub(super) fn console_field(field: &dyn std::fmt::Display) -> String {
    crate::utils::writer::escaped_controls_for_display(&field.to_string())
}

/// Writes one finished console line made of a BODY and the rule author's MESSAGE, which is the last piece
/// of the line: the body goes through the strict set (`escaped_controls_for_display`) as a whole, whatever
/// it holds, and `message` is appended through the relaxed set (`escaped_controls_for_console`), under
/// which a joiner or a mark in the author's prose is ordinary text. The body is escaped as a whole, not
/// field by field, so a field added to a line later cannot print a joiner raw; the message is the one
/// piece the relaxed set reaches, and it stays last so the strict escape of the body cannot reach into it.
/// `message` carries its own delimiters (` Message = [..]`), which hold no control. Both escapes are
/// idempotent, so a piece a caller already escaped prints unchanged.
pub(super) fn write_console_line_with_message(
    writer: &mut dyn Write,
    body: std::fmt::Arguments<'_>,
    message: &str,
) -> crate::rules::Result<()> {
    let body = body.to_string();
    writeln!(
        writer,
        "{}{}",
        crate::utils::writer::escaped_controls_for_display(&body),
        crate::utils::writer::escaped_controls_for_console(message)
    )?;
    Ok(())
}

/// [`write_console_line`] with `format!`'s arguments.
macro_rules! console_line {
    ($writer:expr, $($arg:tt)*) => {
        write_console_line($writer, format_args!($($arg)*))
    };
}

/// [`write_text_line`] with `format!`'s arguments.
macro_rules! text_line {
    ($writer:expr, $($arg:tt)*) => {
        write_text_line($writer, format_args!($($arg)*))
    };
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
/// What it recovers is the evaluator's account, and the author's message where the record carries one. A
/// block report's `custom_message` is the author's `<< >>` text on the CLAUSE whose record took the block
/// shape (`BlockCheck::custom_message`: a `not` over a reference that failed closed, an access clause
/// decided over an empty selection or whose query or comparison raised, a call whose argument could not be
/// evaluated), and absent for a block, a `when`, a type block or a disjunction, which the grammar gives no
/// message (`MissingBlockValue` copies a field whose one producer at `eval.rs` sets `None` as well, which is
/// why the JSON for `block_query_at_the_document_root.guard` shows the empty string there). `non_empty_message`
/// drops the absent half, so the arm below prints the author's half exactly where a clause wrote one. A
/// `<< >>` written on a clause inside a block is a different message again, recorded on that clause, and a
/// block whose query fails never runs it.
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
            // The context is the rules file's text, collapsed onto one line and escaped by the strict
            // set like every context the per-resource output prints.
            let one_context =
                crate::utils::writer::escaped_controls_for_display(&one_line(&blk.context));
            let context = match rule_name {
                Some(name) => format!("{name}: {one_context}"),
                None => one_context,
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
            // findings has them rendered per resource already, under a `Rule =` block that prints the
            // rule's own `Message` line, and repeating the rule-level message there would duplicate
            // rather than explain. This is narrower than `eval_context::speaks_for_itself`, the JUnit
            // failure text's test, which also takes a rule whose checks are all silent: the JUnit report
            // has no per-resource rendering that prints the rule's own message beside them.
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
            // with the author's line breaks still in it. The record says whose text the slot holds
            // (`RuleReport::custom_slot`, read by `custom_slot_origin`), and the escape set follows:
            // the relaxed one for the author's prose, the strict one for the evaluator's sentence.
            // Leaving one arm raw is a difference with nothing
            // behind it. `non_empty_message` for the same reason the arms above use it -- an entry whose
            // explanation is blank reads as a rendering fault rather than as a message nobody wrote.
            if rule.checks.is_empty() {
                if let Some(explanation) = non_empty_message(&rule.messages.custom_message) {
                    out.push((
                        format!("rule {}", rule.name),
                        // The rule record's kind travels with its message: a rule whose condition
                        // raised a refusal prints the refusal whole, one whose condition raised a
                        // converter's error over a template value is held to the cap. A call's
                        // `<< >>` body is the author's half and the rule's own sentence, which the
                        // body displaced, the evaluator's half, joined as a clause's two halves are
                        // (`explanation_of`): the author's prose under the relaxed set, the
                        // sentence under its own kind's bound.
                        match custom_slot_origin(rule) {
                            Origin::Author => explanation_of(&rule.messages),
                            origin => bounded_for_the_console(explanation, origin),
                        },
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

/// The longest refusal explanation the console section prints, in characters. A refusal is the
/// evaluator's own sentence about a read it would not make (`eval_context::refuse`): its definition of
/// `X`, the remedy and the predicate, bounded by the author's query and predicate, and the parts it takes
/// from the template (the path, an entry's or a key's name), each bounded on its own by
/// `eval_context::LONGEST_TEMPLATE_PART_IN_A_REFUSAL` (whose doc gives the effective ceiling of a part
/// kept whole and the marker a longer one carries), so no template decides its length and it is printed
/// whole. This bound is only a backstop that keeps the line finite whatever a future refusal's sentence
/// holds, and it is this reporter's own: every console line that prints a refusal's sentence goes
/// through `bounded_for_the_console`, the unattributed section's explanation (`explanation_of`), a
/// retrieval error's two lines under a resource (`refusal_lines`), the `Error =` line of a block, a
/// unary check and a decided comparison under a resource (`error_line_text`) and the two lines of a
/// rule's own record under a rendered parent (`rule_line_texts`) alike, so no line's length
/// rests on the evaluator having bounded the text. The one exception is the verbose tree
/// (`console_reporter.rs`, the `ClauseCheck::Comparison` arm), which writes each record's message as
/// recorded, bounded by nothing: it is the tree a reader asks for to see the records whole, and it is
/// left as it is. The longest refusal text in the fixtures and tests is under a third of it.
///
/// Which messages are refusals is the evaluator's to say, and it says so on the record
/// (`Messages::refusal`, copied from `BlockCheck::refusal`, `ValueCheck::refusal` or
/// `ComparisonClauseCheck::refusal`, and for a rule record `RuleReport::custom_slot`, copied from
/// `NamedStatus::slot`, each set where the error was written into the message, from
/// `eval_context::is_refusal` or from the kind of the marker the record carries: a refusal beside an
/// absence after the retrieval's own reason, or a refusal beside a value no listed entry accepted under a
/// positive `IN`, both written as comparison records; `InComparisonCheck::refusal` keeps the two records'
/// shapes alike and is never written true). The text cannot say: every `Error::Unevaluatable` displays the same `Clause could not be
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

/// What a `Reason =` line that is NO refusal's ends with when cut at the same backstop
/// (`reason_backstop`): a retrieval's reason is no explanation of a refused read, so the marker names
/// it as the reason it is. The refusal's marker on a plain reason called a retrieval error an
/// explanation it never was.
const REASON_CUT_MARKER: &str = "[reason cut at 4096 characters; `-o json` carries the whole text]";

/// Whose text a console line prints, which decides how its raw controls are written and where it is cut.
/// The one argument of [`bounded_for_the_console`], so a caller names the origin of the text it hands over
/// and cannot pick an escape set by passing a bare flag. A rule record's origin is read off the record
/// (`custom_slot_origin`, from `RuleReport::custom_slot`) and a clause record's error text's off its own
/// (`error_slot_origin`, from `Messages::refusal`); no caller builds one from a loose `bool`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Origin {
    /// The rule author's own `<< >>` prose: the relaxed escape set (`escaped_controls_for_console`), under
    /// which a zero-width joiner or a direction mark is ordinary text. Cut at the recorded-message bound
    /// where an entry of the section for findings that belong to no resource is bounded
    /// (`bounded_for_the_console`, `explanation_of`); printed whole on the per-resource `Rule = { }`
    /// block's `Message` line (`rule_line_texts`), as a clause's message is. Never a refusal.
    Author,
    /// The evaluator's own sentence, or text it quoted from the rules file or the template (a converter's
    /// error, the sentence of a refusal-free record): the strict set (`escaped_controls_for_display`), as
    /// every other line that names a key prints it, and the recorded-message cut.
    Evaluator,
    /// The evaluator's sentence about a read it refused (`Messages::refusal`, `CustomSlot::Refusal`): the
    /// console's one refusal pipeline (`reason_backstop`, strict set), cut at the later refusal bound and
    /// marked.
    Refusal,
}

/// The origin of the evaluator's error text in a clause's or block's `messages`: a refusal when the
/// record says so, the evaluator's sentence otherwise. The author's half of such a record is
/// [`Origin::Author`] by position and needs no record to say it.
fn error_slot_origin(messages: &Messages) -> Origin {
    match messages.refusal {
        true => Origin::Refusal,
        false => Origin::Evaluator,
    }
}

/// A recorded message, cut to the length its kind allows: a refusal explanation to
/// `LONGEST_REFUSAL_MESSAGE`, anything else to `LONGEST_RECORDED_MESSAGE`. Either way the text is put on
/// one line and its raw controls are written as their escapes before the cut: the refusal through
/// `reason_backstop`, an author's text through `plain_author_message` and the evaluator's through
/// `plain_evaluator_message`, so a control sequence in an author's `<< >>` text or in a converter's
/// sentence never reaches the terminal raw from the unattributed section.
///
/// A refusal explanation is cut later than any other message because the remedy is the part a reader
/// acts on, and a cut at `LONGEST_RECORDED_MESSAGE`, wrappers counted, would leave a refusal raised inside
/// a `when` condition with about 150 characters of its text: the key's sentence and, for a long query,
/// none of the remedy. The cap exists for a message that embeds a document; a refusal does not, so it is
/// not held to it.
///
/// `origin` is what the record says (`Messages::refusal` through `error_slot_origin`, and for a rule
/// record's slot `RuleReport::custom_slot` through `custom_slot_origin`), and is the only thing
/// read: a text that happens to carry a refusal's wrapper is cut like any other when the record does not
/// say it is one, and a refusal is printed whole whatever words it uses (the tests under
/// `explanation_tests` hold both). `LONGEST_REFUSAL_MESSAGE` says why the text was not enough.
///
/// A refusal's text takes the console's ONE pipeline for a refusal line (`reason_backstop`: collapsed
/// onto one line, its remaining raw controls written as their escapes, cut on the printed width last,
/// with the refusal's marker), so the `Error =` line of a block, a unary check and a decided comparison
/// (`error_line_text`), the unattributed section's entries (`explanation_of`, the rule-level record) and
/// the retrieval-error arm's lines (`refusal_lines`) are one pipeline. Cut here with no escape, those
/// arms printed a raw ESC or a bidi override the evaluator had not bounded while the retrieval arm
/// escaped it.
///
/// Only the author's prose takes the relaxed set. A pathless clause whose error quotes the key
/// `Bucket<joiner>Name` prints the key's escape on its `Error =` line and in the unattributed section
/// alike, since both are the evaluator's text.
fn bounded_for_the_console(message: &str, origin: Origin) -> String {
    match origin {
        Origin::Refusal => reason_backstop(message, REFUSAL_CUT_MARKER),
        Origin::Author => plain_author_message(message).0,
        Origin::Evaluator => plain_evaluator_message(message).0,
    }
}

/// The origin of a rule record's custom slot, from the one value the record carries for it
/// (`RuleReport::custom_slot`): a refusal's record holds the evaluator's refusal sentence there, an
/// author's body the record says it copied, and anything else is the evaluator's own sentence.
fn custom_slot_origin(rule: &RuleReport<'_>) -> Origin {
    match rule.custom_slot {
        CustomSlot::Refusal => Origin::Refusal,
        CustomSlot::Author => Origin::Author,
        CustomSlot::Evaluator => Origin::Evaluator,
    }
}

/// `text` on one line and cut at the console's one backstop for a refusal's text or a reason,
/// `LONGEST_REFUSAL_MESSAGE`, with `marker` after the ellipsis where something was cut
/// (`REFUSAL_CUT_MARKER` for a refusal's explanation, `REASON_CUT_MARKER` for a reason that is no
/// refusal's): the ellipsis alone does not tell a reader the text was shortened by the reporter and
/// that `-o json` carries the whole text. The one cut `reason_backstop` takes, which every refusal
/// line and every reason line reaches (`bounded_for_the_console`'s refusal branch goes through it),
/// so the bound and the marker's place are spelled once; the caller names the marker, so the call says
/// which kind of text it bounds. A cut that lands inside a `\u{..}` escape the text carries (the escapes
/// `reason_backstop` writes for a raw control come before the cut, so the cut counts their characters)
/// is moved back to the escape's start (`before_a_split_escape`): the fragment was no part of the
/// author's text, and a line ending `\u{1... [explanation cut` read as a cut escape where nothing was
/// cut but the reporter's own spelling.
fn backstop(text: &str, marker: &str) -> String {
    let (cut, was_cut) = cut_to(text, LONGEST_REFUSAL_MESSAGE);
    if was_cut {
        format!("{} {marker}", before_a_split_escape(&cut))
    } else {
        cut
    }
}

/// `cut`, a `cut_to` result that ends in the ellipsis, with the cut moved back to the start of an
/// escape it fell inside: when the tail of the kept text from its LAST backslash is a proper prefix of
/// an escape `escaped_controls_for_display` writes (`\` alone, the first character of any escape; `\u`,
/// `\u{`, `\u{` and up to six hex digits with no closing brace), the cut split an escape, so the kept
/// text ends before that backslash (trailing whitespace trimmed, as `cut_to` trims) and the ellipsis
/// follows. The tail is bounded by the longest escape without its brace, `\u{10ffff`, so the move back
/// is at most nine characters: a literal backslash the author wrote anywhere earlier (a path, a key
/// `a\users`) is no split escape, whatever follows it, and the text keeps every character up to the cut.
/// A kept text whose last backslash opens a whole escape, or has none, is returned as it is; so is a
/// text not cut at all (no ellipsis to strip). The one false positive left is a literal backslash, or a
/// literal `\u` with a brace and hex digits after it, within those nine characters of the cut: a few
/// characters fewer on a line already cut. Read from the last backslash, not the last `\u`: a cut that
/// left the backslash of `\t` or of `\u{1b}` alone found the earlier, whole escape and kept the lone
/// backslash; and read over the whole kept text, a literal `\u` thousands of characters back with no
/// `}` after it cut the line back to there, remedy included, under a marker that claimed the bound.
fn before_a_split_escape(cut: &str) -> String {
    const LONGEST_SPLIT_ESCAPE: usize = "\\u{10ffff".len();
    let Some(kept) = cut.strip_suffix("...") else {
        return cut.to_string();
    };
    let Some(at) = kept.rfind('\\') else {
        return cut.to_string();
    };
    let tail = &kept[at..];
    if tail.len() > LONGEST_SPLIT_ESCAPE || !is_a_split_escape(tail) {
        return cut.to_string();
    }
    format!("{}...", kept[..at].trim_end())
}

/// Whether `tail`, a text opening with a backslash, is a proper prefix of an escape and not a whole one:
/// `\`, `\u`, `\u{`, or `\u{` followed by hex digits only (a whole `\u{..}` carries its brace; `\t`, `\r`
/// and `\n` are whole at two characters, so their only split is the lone backslash).
fn is_a_split_escape(tail: &str) -> bool {
    let Some(rest) = tail.strip_prefix('\\') else {
        return false;
    };
    match rest.strip_prefix('u') {
        None => rest.is_empty(),
        Some(after_u) => match after_u.strip_prefix('{') {
            None => after_u.is_empty(),
            Some(hex) => hex.chars().all(|c| c.is_ascii_hexdigit()),
        },
    }
}

/// `message` on one line and no longer than `limit` characters, cut at whitespace and marked with an
/// ellipsis when something was dropped. The second element says whether anything was dropped, set in the
/// one branch that drops it, so a caller that needs to know (`backstop`, `plain_author_message`) reads the
/// cutter's own answer and keeps no second count of the collapsed text to agree with it. The cells that
/// pin the bound read it through `plain_author_message`, the author's form of the plain pipeline; a
/// recorded message of the evaluator's takes `plain_evaluator_message`, which cuts at the same bound.
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
/// Collapsed onto one line by `one_line` before its length is taken, which is also what sets the indentation
/// aside: an explanation that fits once its own whitespace is gone comes out whole and carries no ellipsis.
/// An ellipsis is a claim that something was dropped, and a message shortened only because of the spaces
/// around it makes that claim falsely -- the smaller half of the same defect. Measuring the collapsed line
/// rather than the recorded string is measuring what the section actually prints, which is the only length
/// a cap on console output can be about.
///
/// Counted against the raw string the leading whitespace is spent from the same budget as the words, and a
/// message indented far enough spends all of it:
///
/// ```text
/// <<          ... 350 spaces ...          REALREASON>>
/// ```
///
/// The first 320 characters are then all whitespace, the cut at the last whitespace within them leaves 319
/// spaces, `trim_end` empties what is left, and the line renders as a bare `...` with the author's only word
/// gone. Nothing about the length of what they wrote put it there.
fn cut_to(message: &str, limit: usize) -> (String, bool) {
    let collapsed = one_line(message);
    let message = collapsed.as_str();
    let cut = match message.char_indices().nth(limit) {
        Some((at, _)) => at,
        None => return (message.to_string(), false),
    };

    let kept = &message[..cut];
    let kept = match kept.rfind(char::is_whitespace) {
        Some(at) => &kept[..at],
        None => kept,
    };

    (format!("{}...", kept.trim_end()), true)
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
/// The author's half arrives from a clause: from its own value checks, and from the block-shaped records a
/// clause that carries a `<< >>` message writes (`BlockCheck::custom_message`); a block, a `when`, a type
/// block and a disjunction carry none. `collect_unattributed_explanations` says where that is decided.
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
/// either the evaluator's sentence or the author's copied body in the custom slot instead
/// (`report_all_failed_clauses_for_rules`), and `collect_unattributed_explanations` reads that slot with
/// the record's own origin (`custom_slot_origin`); this function sees
/// clause and block reports.
///
/// One function rather than the same expression in the block arm and the clause arm, which is where the
/// `Messages` in both cases comes from, so that the bound above has somewhere to be asserted.
fn explanation_of(messages: &Messages) -> String {
    // The author's half takes the relaxed set, the evaluator's half the strict one.
    let author = non_empty_message(&messages.custom_message)
        .map(|text| bounded_for_the_console(text, Origin::Author));
    let evaluator = non_empty_message(&messages.error_message)
        .map(|text| bounded_for_the_console(text, error_slot_origin(messages)));
    vec![author, evaluator]
        .into_iter()
        .flatten()
        .collect::<Vec<String>>()
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
            let context = crate::utils::writer::escaped_controls_for_display(&one_line(context));
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

#[derive(Debug, Serialize)]
#[cfg_attr(test, derive(PartialEq))]
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
        // nothing; the author's `<< >>` message rides with it where the record carries one (a `not`
        // over a reference that failed closed), as it does on a dependent rule's record below.
        Some(RecordType::GuardClauseBlockCheck(BlockCheck {
            message: Some(msg),
            custom_message,
            ..
        })) => NameInfo {
            error: Some(msg.clone()),
            message: custom_message.clone().unwrap_or_default(),
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
///
/// The message is collapsed before anything is escaped, as the one-line forms of the same text are
/// (`plain_author_message`, `reason_backstop`): it is divided at every `;`, line feed and carriage return
/// together (a line break inside a piece that holds a `;` is a break too, and a CRLF file's pairs are one
/// break), and the error is joined into one line (`one_line`). The `Message` lines then go through the
/// text sink (`write_text_line`, the relaxed set, for the author's prose) and the `Error` line through the
/// strict sink (`write_console_line`), which write the raw controls that are left (an ESC, a tab, a bidi
/// override) as their escapes. Escaped first, a line break would print as the two
/// characters `\n` beside the `; ` the rest of the console joins it with. A rule author's `<< >>` text and
/// a converter's error reach this function as the evaluator recorded them, so an ESC in either would
/// otherwise print raw on the `Message =` and `Error =` lines of every clause arm and of the retrieval
/// arm, while the unattributed section printed the same text escaped. The escape is idempotent, so a
/// caller that already bounded its text prints unchanged.
fn emit_messages(
    writer: &mut dyn Write,
    prefix: &str,
    message: &str,
    error: &str,
    width: usize,
) -> crate::rules::Result<()> {
    let pieces: Vec<&str> = message
        .split([';', '\n', '\r'])
        .map(str::trim)
        .filter(|piece| !piece.is_empty())
        .collect();
    let error = one_line(error);
    let error = error.as_str();

    match pieces.as_slice() {
        // No message. Nothing an author wrote survived, so nothing is written.
        [] => {}
        [only] => {
            text_line!(
                writer,
                "{prefix}{mh:<width$} = {message}",
                prefix = prefix,
                message = only,
                mh = "Message",
                width = width
            )?;
        }
        many => {
            text_line!(
                writer,
                "{prefix}{mh:<width$} {{",
                prefix = prefix,
                mh = "Message",
                width = width
            )?;
            for each in many {
                text_line!(
                    writer,
                    "{prefix}  {message}",
                    prefix = prefix,
                    message = each
                )?;
            }
            text_line!(writer, "{prefix}}}", prefix = prefix)?;
        }
    }

    if !error.is_empty() {
        console_line!(
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

/// The two lines a retrieval error's finding prints for a REFUSAL record, decided from the record: the
/// text of its `Error =` line, and the text of its `Reason =` line when one is written. Every text is
/// one line and bounded by this reporter (`bounded_for_the_console`: `LONGEST_REFUSAL_MESSAGE` and
/// `REFUSAL_CUT_MARKER`), whatever the evaluator wrote; a record that is no refusal's takes neither
/// (`refusal_lines` is asked for refusal records alone; the plain finding prints its `Reason =` line
/// through the same pipeline, on one line with its controls escaped and cut only at the 4096-character
/// backstop, with its own marker, `reason_backstop`).
///
/// The record carries its sentence's parts as fields (`Messages::parts`: the report builder's `head`
/// and the evaluator's `message`, which the recorded sentence wraps in `Error = [ ... ]` after the
/// head), so this reporter joins fields and never parses the recorded sentence, in which a template
/// value quoted in the head can hold `Error = [` as well. The unresolved value's `reason` stands in the
/// message in one of the places the evaluator writes it, each read as a relation between the two
/// fields:
///
/// - The message IS the reason (a refusal's marker on either side: a right-hand value the evaluator
///   refused to read, a left-hand value that is a refusal's marker; a unary check refused over a value):
///   the head is printed on `Error =` and the refusal on `Reason =`, each bounded on its own, so the
///   refusal is printed exactly once however long it is. Printed whole on one `Error =` line, a refusal
///   longer than the bound was cut inside its own text, and a `Reason =` test on the cut line could not
///   find it and printed a second cut copy.
/// - The message ENDS with the reason after `: ` (a left-hand marker beside a right-hand value the
///   document lacks: the absence's lead, then the marker's reason): the head and the lead are printed on
///   `Error =` and the refusal on `Reason =`, each bounded.
/// - Otherwise the message LEADS with the reason: an absent value beside a refused read, whose message
///   the evaluator writes as the retrieval's own reason, the template value it quotes bounded and
///   escaped (`eval_context::marker_part` and `template_path`), then the refusal. That lead is the
///   evaluator's to write, and
///   this reporter does not rebuild it to compare: the three shapes above are every message a refusal
///   record's unresolved value carries (its own refusal, the absence's lead ending in its refusal, the
///   lead of its own reason), so a message that is neither of the first two is the third. The head and
///   the message are printed joined on `Error =` when they fit the bound whole, with no `Reason =` line,
///   since the reason is the first thing the message says; when they do not fit, the head goes on
///   `Error =` and the message, the reason leading, bounded on `Reason =`, so the refusal in it is
///   printed once and never cut away. Rebuilt and compared, a lead over the template-part bound, a lead
///   quoting a long value, or a key holding a backslash missed the rebuilt text and fell to a fallback
///   that printed the recorded sentence, its nested `Error = [` inside, and the reason again.
/// - No parts (a record whose sentence carries no message, a producer that set none, a report read
///   back): the sentence as recorded, bounded, on `Error =`, and the reason bounded on `Reason =`.
///
/// The head and the message joined by one space rather than the sentence as recorded: this line is
/// itself the finding's `Error =` line, so the tail's own `Error = [` written inside it named the field
/// twice. The structured outputs keep the sentence as recorded.
fn refusal_lines(messages: &Messages, reason: &str) -> (String, Option<String>) {
    // Every `Error =` text this function prints takes the one pipeline a `Reason =` line takes
    // (`reason_backstop`: collapsed onto one line, then escaped, then cut on the PRINTED width with the
    // refusal's marker): the evaluator writes the record's sentence with its template parts escaped, and
    // this is the console's own defense for a sentence that reaches it with a raw control, so no branch
    // below prints one. Escaped before the collapse, a raw line break became a literal `\n` where the
    // pipeline joins the parts with `; `.
    let bounded = |text: &str| reason_backstop(text, REFUSAL_CUT_MARKER);
    let displayed_whole =
        |text: &str| crate::utils::writer::escaped_controls_for_display(&one_line(text));
    // The reason is stored as its builder wrote it (raw controls included) and printed through the
    // console's one pipeline (`reason_backstop`): on one line, the controls escaped, cut on the printed
    // width last. Every reason this function prints is a refusal's (the record is flagged one), so the
    // cut, where it falls, carries the refusal's marker.
    let reason_line = || match reason.is_empty() {
        true => None,
        false => Some(reason_backstop(reason, REFUSAL_CUT_MARKER)),
    };
    let Some(parts) = &messages.parts else {
        let sentence = messages.error_message.as_deref().unwrap_or("");
        return (bounded(sentence), reason_line());
    };
    let (head, message) = (parts.head.as_str(), parts.message.as_str());
    let joined = format!("{head} {message}");
    if reason.is_empty() {
        return (bounded(&joined), None);
    }
    // The message is the reason.
    if message == reason {
        return (bounded(head), reason_line());
    }
    // The message ends with the reason: the lead before it stays with the head. The record writes the
    // marker's reason ESCAPED (`eval::absence_beside_a_marker`: controls as their Rust escapes, never
    // cut) while the record's unresolved value stores it as its builder wrote it, byte for byte (the
    // registry matches a stored reason by exact text, so escaping is display, not storage), so the
    // suffix to strip is the escaped form; the escape is idempotent, so a reason an older record stored
    // escaped matches too. The `Reason =` line prints that same escaped form, one text with the record.
    let displayed = crate::utils::writer::escaped_controls_for_display(reason);
    if let Some(lead) = message.strip_suffix(&format!(": {displayed}")) {
        return (
            bounded(&format!("{head} {lead}:")),
            Some(reason_backstop(reason, REFUSAL_CUT_MARKER)),
        );
    }
    // The message leads with the reason, as the evaluator writes a lead: joined on `Error =` where the
    // collapsed and ESCAPED line fits the bound (its printed width, as every line here is held to), else
    // the head on `Error =` and the message on `Reason =` through the same pipeline as every other
    // reason. Written `one_line(&joined)` and `bounded(message)` here, both branches printed a lead's
    // controls raw and the under-the-bound branch read the raw width.
    let opened = displayed_whole(&joined);
    match opened.chars().count() <= LONGEST_REFUSAL_MESSAGE {
        true => (opened, None),
        false => (
            bounded(head),
            Some(reason_backstop(message, REFUSAL_CUT_MARKER)),
        ),
    }
}

/// A record's stored reason as the console's `Reason =` line prints it, through the one pipeline every
/// console line of a reason takes, whatever the record's kind, in this order: collapsed onto one line
/// (`one_line`: the parts trimmed and joined by `; `, as the unattributed section collapses a sentence,
/// so a line break the author put inside a reason cannot put a line at an indentation of its own inside
/// the `Check = { }` block), then every remaining raw control written as its escape
/// (`escaped_controls_for_display`, idempotent: an ESC or a bidi override; a line break is already
/// `; `), and LAST the cut on the PRINTED width at the console's one backstop for a reason,
/// `LONGEST_REFUSAL_MESSAGE`, with `marker` after it, named by the caller for the reason's KIND as the
/// record says it (`Messages::refusal`, the one thing read, as `bounded_for_the_console` reads it): a
/// refusal's cut names the explanation (`REFUSAL_CUT_MARKER`) and a plain reason's names the reason
/// (`REASON_CUT_MARKER`). A reason that is no refusal's is held to the same backstop and never to the
/// 320-character cut of a recorded message, so a retrieval reason keeps its trailing position, and no
/// console line depends on the evaluator having bounded the text. The order matters twice: escaped
/// before `one_line`, a raw line break became the two characters `\n` and nothing was left to join, so
/// the line read the literal escape where the reporter's own cells pin the join; and cut before the
/// escape, each raw control grew into a six-character escape after the cut, so a line of three ESCs near
/// the bound printed past it. The store holds the builder's bytes; every escape is display. The cut is
/// the one every bounded refusal text takes (`backstop`), so the kind reaches the marker: through
/// `bounded_for_the_console(_, Origin::Refusal)` a plain reason over the bound was marked as an
/// explanation.
fn reason_backstop(reason: &str, marker: &str) -> String {
    backstop(
        &crate::utils::writer::escaped_controls_for_display(&one_line(reason)),
        marker,
    )
}

/// The text a per-resource arm prints on its `Error =` line for `messages`: the recorded sentence as
/// recorded for a record that is no refusal's (returned as it is; `emit_messages` joins its line breaks
/// and the console's sink escapes its controls when it prints), and for a refusal's
/// the console's one refusal pipeline (`bounded_for_the_console`, through `reason_backstop`: one line,
/// the remaining raw controls escaped, cut on the printed width last), so no console line that prints a
/// refusal's sentence rests on the evaluator having bounded or escaped the text. For the arms that print
/// a resolved comparison, a block and a unary check; the retrieval-error arm decides its lines from the
/// record (`refusal_lines`), through the same pipeline.
fn error_line_text(messages: &Messages) -> String {
    let error = messages.error_message.as_deref().unwrap_or("");
    match messages.refusal {
        true => bounded_for_the_console(error, Origin::Refusal),
        false => error.to_string(),
    }
}

/// The two texts the `Rule = { }` arm of the per-resource output prints for a rule's own record
/// (`pprint_clauses`, the `ClauseReport::Rule` arm, through `emit_rule_messages`): its `Message` line's
/// text, then its `Error` line's. The origin of the CUSTOM slot is read off the record
/// (`custom_slot_origin`), so a caller cannot hand a refusal's record another origin's pipeline. A
/// rule-level record carries the evaluator's sentence there (a condition that raised a refusal across a
/// rule boundary, `report_all_failed_clauses_for_rules`) or the author's body copied onto a called rule,
/// so for a refusal's record BOTH slots take the console's one refusal pipeline (`bounded_for_the_console`,
/// through `reason_backstop`: one line, the remaining raw controls escaped, cut on the printed width last,
/// with the refusal's marker). For the evaluator's sentence the custom slot is collapsed onto one line,
/// its raw controls escaped by the strict set, and cut at the recorded-message bound
/// (`LONGEST_RECORDED_MESSAGE`, `cut_to`'s ellipsis), the cut the unattributed section gives the same
/// slot of the same record (`collect_unattributed_explanations`): the sentence quotes a template value
/// where a converter's error raised over one, and that bound exists for exactly such a value (a 2 KB
/// string printed whole on one line before it). The author's body is collapsed and escaped by the relaxed
/// set and NOT cut: the cut exists for text the evaluator quoted from the template, the author's prose is
/// the author's to size, and the clause arms print it whole on their `Message =` lines, so the rule line
/// of a call prints what the clause line prints (the unattributed section still bounds it, as it bounds
/// every entry it prints). The error slot, which holds the rule's own sentence a call body displaced,
/// is the evaluator's text and takes the pipeline of its kind (`bounded_for_the_console` over
/// `error_slot_origin`: collapsed, escaped and cut at the recorded-message bound, or the refusal pipeline
/// for a refusal's sentence), as the unattributed section prints the same sentence. The arm is reached: it renders
/// under a rendered parent with no
/// resource-membership gate of its own and recurses into the rule's checks, so a nested rule's record
/// whose condition raised a refusal, printed under an outer rule rendering per resource, reaches it;
/// printed through `emit_messages` before that function escaped, that record was the one per-resource line that put the
/// evaluator's sentence out with a raw ESC or a line break in it while the clause arms beside it escaped
/// theirs, and the one line that printed a 2 KB template value whole where the unattributed section cut
/// the same slot. The unattributed section takes the same collapse, escape and cut for a text that is no
/// refusal's (`bounded_for_the_console`, through `plain_author_message` or `plain_evaluator_message`),
/// since a raw control in a line moves the cursor wherever it is printed. The third element
/// says whether a plain record's custom slot was CUT at the recorded-message bound, as the cutter
/// reports it (`plain_evaluator_message`): `Some(cut)` for the evaluator's sentence, `Some(false)` for
/// the author's body, which is never cut here, `None` for a refusal's, whose cut
/// is the refusal pipeline's own and marked in the text, so the flag cannot be read for a record it
/// does not describe.
fn rule_line_texts(rule: &RuleReport<'_>) -> (String, String, Option<bool>) {
    let messages = &rule.messages;
    let released = |slot: &Option<String>| slot.as_deref().unwrap_or("").to_string();
    match custom_slot_origin(rule) {
        Origin::Refusal => (
            bounded_for_the_console(&released(&messages.custom_message), Origin::Refusal),
            bounded_for_the_console(&released(&messages.error_message), Origin::Refusal),
            None,
        ),
        Origin::Author => (
            crate::utils::writer::escaped_controls_for_console(&one_line(&released(
                &messages.custom_message,
            ))),
            bounded_for_the_console(
                &released(&messages.error_message),
                error_slot_origin(messages),
            ),
            Some(false),
        ),
        Origin::Evaluator => {
            let (message, cut) = plain_evaluator_message(&released(&messages.custom_message));
            (message, released(&messages.error_message), Some(cut))
        }
    }
}

/// The rule author's `<< >>` text as the unattributed section prints it (the author's half of an entry,
/// and a rule record's custom slot the record marks as the author's), collapsed onto one line, its raw
/// controls escaped by the relaxed set and cut at the recorded-message bound, and whether the cut happened, as `cut_to`
/// says it: the flag is the cutter's own answer for the one text the cut is made from, not a second
/// count beside it. `emit_rule_messages` used to rebuild the collapse and compare the two strings to
/// learn the same thing, two copies of one computation that drifted (the rebuilt side was not escaped,
/// so a short message holding a control compared as cut).
fn plain_author_message(slot: &str) -> (String, bool) {
    collapsed_escaped_and_cut(slot, crate::utils::writer::escaped_controls_for_console)
}

/// [`plain_author_message`] for text the EVALUATOR wrote or quoted from the template (a converter's error,
/// the sentence of a refusal-free record, a rule-level slot the record does not mark as the author's), with
/// the strict set (`escaped_controls_for_display`): a key with a pasted joiner in a quoted sentence
/// prints its escape, as it does on every other line that names a key. The relaxed set is the rule
/// author's prose alone.
fn plain_evaluator_message(slot: &str) -> (String, bool) {
    collapsed_escaped_and_cut(slot, crate::utils::writer::escaped_controls_for_display)
}

/// The one pipeline both plain forms take: `slot` on one line, escaped by `escape`, then cut at the
/// recorded-message bound, with whether it was cut.
fn collapsed_escaped_and_cut(slot: &str, escape: fn(&str) -> String) -> (String, bool) {
    let collapsed = escape(&one_line(slot));
    let (cut, was_cut) = cut_to(&collapsed, LONGEST_RECORDED_MESSAGE);
    if was_cut {
        (before_a_split_escape(&cut), true)
    } else {
        (cut, false)
    }
}

/// The `Message` and `Error` lines of a rule's own record (`rule_line_texts`). A refusal's record has
/// both texts on ONE line each already (collapsed, escaped and cut by the refusal pipeline), and they are
/// written as one line each, `Message = ...` and `Error = ...`, never through `emit_messages`, which
/// splits a message on every `;`: the collapse joins a line break as `; ` and the cut's marker holds a
/// `;` too, so through it a cut refusal printed its marker across two lines and a collapsed sentence
/// came apart at every join. A record that is no refusal's whose custom slot was CUT at the
/// recorded-message bound is written as one `Message = ...` line too (the collapse's joins would come
/// apart the same way); every other plain record is written as every other record's messages are
/// (`emit_messages`), the author's `;` list included. Whether the slot was cut is what `rule_line_texts`
/// reports beside the two texts, read once where the cut is made; an earlier form of this function
/// rebuilt the collapse and compared the two strings, and compared with the UNESCAPED collapse, a short
/// plain message holding a raw control (a tab, an ESC) read as cut and took the one-line form the doc
/// reserves for a cut. The rule-level record's custom slot holds
/// EITHER the evaluator's sentence OR an author's `<< >>` message copied onto a called rule by the
/// evaluator, and the record says which (`RuleReport::custom_slot`, read by `custom_slot_origin` inside
/// `rule_line_texts`): the author's body takes the relaxed escape set and is printed whole, as the clause
/// arms print an author's message, and the evaluator's sentence takes the strict one and is cut at the
/// recorded-message bound.
fn emit_rule_messages(
    writer: &mut dyn Write,
    prefix: &str,
    rule: &RuleReport<'_>,
) -> crate::rules::Result<()> {
    let (message, error, cut) = rule_line_texts(rule);
    match cut {
        Some(false) => return emit_messages(writer, prefix, &message, &error, 0),
        Some(true) => {
            text_line!(writer, "{prefix}Message = {message}")?;
            return emit_messages(writer, prefix, "", &error, 0);
        }
        None => {}
    }
    if !message.trim().is_empty() {
        text_line!(writer, "{prefix}Message = {message}")?;
    }
    if !error.is_empty() {
        console_line!(writer, "{prefix}Error = {error}")?;
    }
    Ok(())
}

/// `messages` is the record's: its custom message is printed through `emit_messages` (its line breaks
/// joined, its controls escaped), and for a refusal's record
/// alone its sentence's head is printed on an `Error =` line before the property block, as a decided
/// comparison's finding prints its sentence (`BinaryCheck::Resolved` below), with the refusal on the
/// block's `Reason =` line or joined to the head, as the record decides (`refusal_lines`).
fn emit_retrieval_error(
    writer: &mut dyn Write,
    prefix: &str,
    vur: &ValueUnResolved,
    clause: &ClauseReport<'_>,
    context: &str,
    messages: &Messages,
    err_emitter: &mut dyn ComparisonErrorWriter,
) -> crate::rules::Result<()> {
    console_line!(
        writer,
        "{prefix}Check = {cxt} {{",
        prefix = prefix,
        cxt = context_line(context)
    )?;
    let check_end = format!("{}}}", prefix);
    let prefix = format!("{}  ", prefix);
    let message = messages.custom_message.as_deref().unwrap_or("");
    // A refusal record's two lines, decided from the record (`refusal_lines`); a record that is no
    // refusal's prints no sentence here, as released, and its `Reason =` line below is the reason through
    // the console's one pipeline (`reason_backstop`: on one line, the remaining controls escaped, and cut
    // only at the 4096-character backstop every Reason line shares, with the plain reason's own marker,
    // never at the 320-character cut of a recorded message, so a retrieval reason keeps its trailing
    // position), where it was printed as recorded and a raw line break in it printed a second console
    // line.
    let reason = vur.value.reason.as_ref().map_or("", String::as_str);
    let (sentence, reason_line) = match messages.refusal {
        true => refusal_lines(messages, reason),
        false => (
            String::new(),
            match reason.is_empty() {
                true => None,
                false => Some(reason_backstop(reason, REASON_CUT_MARKER)),
            },
        ),
    };
    emit_messages(writer, &prefix, message, &sentence, 0)?;

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
    let inside_the_check = prefix.clone();
    let prefix = format!("{}  ", prefix);
    console_line!(
        writer,
        "{prefix}PropertyPath = {path}",
        prefix = prefix,
        path = crate::rules::eval_context::template_path(vur.value.traversed_to.self_path())
    )?;

    if !value_found {
        console_line!(
            writer,
            "{prefix}MissingProperty = {prop}",
            prefix = prefix,
            prop = vur.value.remaining_query
        )?;
    }

    // The `Reason =` line as the record decided it above: for a refusal record, the refusal bounded on
    // one line where the `Error =` line printed the head alone, and no line where the `Error =` line
    // already leads with the reason (`refusal_lines`); for every other record, the reason through the same
    // pipeline (`reason_backstop`, with the plain reason's own marker). Both arrive here finished.
    if let Some(reason) = reason_line {
        console_line!(
            writer,
            "{prefix}Reason = {reason}",
            prefix = prefix,
            reason = reason
        )?;
    }
    // The comparison writer writes its own lines, and escapes the fields it takes from the template and
    // the source excerpt itself (`console_field`), since an excerpt line carries the writer's own
    // colour: an escape of the whole line would print the sequence as text. What it wrote then goes
    // through the backstop (`writer_output`), which keeps the layout and the writer's two colour
    // sequences and writes any other control as its escape.
    let mut missing_property: Vec<u8> = Vec::new();
    err_emitter.missing_property_msg(&mut missing_property, clause, Some(&vur.value), &prefix)?;
    write!(writer, "{}", writer_output(missing_property))?;
    writeln!(writer, "{}", rpe_end)?;
    // The operand the record was compared WITH, where the record carries one (`ValueUnResolved::to`: the
    // absent right-hand value a left-hand marker was decided by, and nothing for any other record): its
    // path and the key the document lacks, in a block of their own, so the finding names both operands
    // where the block above is the marker's alone and the right side was named only in the prose of the
    // `Error =` line's lead. Its reason is that lead and is not printed a second time. The path is
    // written as the `Error =` lead writes it (`template_path`: bounded on its printed width, its
    // controls escaped), never raw: a key holding a bidi override or a line feed would otherwise reach
    // the console here as written.
    if let Some(to) = &vur.to {
        writeln!(writer, "{inside_the_check}ComparedWith {{")?;
        console_line!(
            writer,
            "{inside_the_check}  PropertyPath = {path}",
            path = crate::rules::eval_context::template_path(to.traversed_to.self_path())
        )?;
        if !to.remaining_query.is_empty() {
            console_line!(
                writer,
                "{inside_the_check}  MissingProperty = {prop}",
                prop = to.remaining_query
            )?;
        }
        writeln!(writer, "{inside_the_check}}}")?;
    }
    writeln!(writer, "{}", check_end)?;
    Ok(())
}

/// The lines a reporter adds to a clause's finding (the property path, the operator, the value, the
/// compared-with side, a source excerpt).
///
/// OBLIGATION: an implementation wraps every field it takes from the template or the data (a path, a
/// value, a key, a source line) in [`console_field`], or in `escaped_controls_for_excerpt` for a source
/// line it colours, BEFORE it formats the field into a line, and colours a line only after that. The clause
/// arm writes the output behind a backstop that escapes any control except layout and the writer's two
/// colour sequences (`writer_output`), so a field an implementation forgets cannot reach the terminal
/// raw, but it is escaped without the strict set's care for a line feed in a value (the backstop keeps
/// line feeds as the layout). The backstop escapes a joiner or a mark too, as the strict set does
/// (`breaks_or_hides_a_line` names U+200C to U+200F).
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
            emit_rule_messages(writer, &prefix, rr)?;
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
            console_line!(
                writer,
                "{prefix}Check = {cxt} {{",
                prefix = prefix,
                cxt = context_line(&blk.context)
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
                // Two lines, each finished and escaped on its own: a key in the path or the query holding
                // an ESC or a bidi override reaches the console as its escape, as on the retrieval arm's
                // `PropertyPath =` line. The path is printed as recorded, with no location and no cut
                // (`template_path` adds both), so the lines read as they did.
                console_line!(
                    writer,
                    "{prefix}{pp:<width$}= {path}",
                    prefix = prefix,
                    pp = "PropertyPath",
                    width = width,
                    path = traversed_to
                )?;
                console_line!(
                    writer,
                    "{prefix}{mp:<width$}= {q}",
                    prefix = prefix,
                    width = width,
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
            let error = error_line_text(&blk.messages);
            emit_messages(writer, &prefix, message, &error, width)?;
            writeln!(writer, "{}", writer_output(post_message))?;
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
                            &ur.messages,
                            err_writer,
                        )?;
                    }

                    UnaryCheck::Resolved(re) => {
                        console_line!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = context_line(&ur.context)
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
                        let error = error_line_text(&ur.messages);
                        emit_messages(writer, &prefix, message, &error, width)?;
                        writeln!(writer, "{}", writer_output(post_message))?;
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
                            &br.messages,
                            err_writer,
                        )?;
                    }

                    BinaryCheck::Resolved(bc) => {
                        console_line!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = context_line(&br.context)
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
                        let error = error_line_text(&br.messages);
                        emit_messages(writer, &prefix, message, &error, width)?;
                        writeln!(writer, "{}", writer_output(post_message))?;

                        writeln!(writer, "{}", ce_end)?;
                        writeln!(writer, "{}", check_end)?;
                    }

                    BinaryCheck::InResolved(inr) => {
                        console_line!(
                            writer,
                            "{prefix}Check = {cxt} {{",
                            prefix = prefix,
                            cxt = context_line(&br.context)
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
                        let error = error_line_text(&br.messages);
                        emit_messages(writer, &prefix, message, &error, width)?;
                        writeln!(writer, "{}", ce_end)?;
                        writeln!(writer, "{}", writer_output(post_message))?;
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
    /// The line writes the character as its escape, as it does every control that hides a line.
    #[test]
    fn a_zero_width_no_break_space_is_still_a_message() {
        assert_eq!("Message = \\u{feff}\n", emit("\u{FEFF}", ""));
    }

    /// A raw ESC in a message is written as its escape on a single-message line. The ESC is built with
    /// `char::from`, since the source holds no raw control.
    ///
    /// Expected, not yet run. Red: the line carries the ESC byte itself.
    #[test]
    fn a_control_in_a_single_message_is_written_as_its_escape() {
        let esc = char::from(0x1b);
        let out = emit(&format!("{esc}[2J"), "");
        assert_eq!("Message = \\u{1b}[2J\n", out);
        assert!(!out.contains(esc), "no raw ESC is written: {:?}", out);
    }

    /// The items of a `;` list are escaped one by one, after the split: the separators still divide the
    /// message and a tab or an ESC inside an item is written as its escape.
    ///
    /// Expected, not yet run. Red: an item carries the ESC or the tab byte itself.
    #[test]
    fn the_items_of_a_message_list_are_escaped_after_the_split() {
        let esc = char::from(0x1b);
        let out = emit(&format!("a{esc}[1m;b\tc"), "");
        assert_eq!("Message {\n  a\\u{1b}[1m\n  b\\tc\n}\n", out);
        assert!(!out.contains(esc), "no raw ESC is written: {:?}", out);
        assert!(!out.contains('\t'), "no raw tab is written: {:?}", out);
    }

    /// The error half is escaped as the message half is, and a text a caller already escaped is
    /// written as it is (the escape is idempotent).
    ///
    /// Expected, not yet run. Red: the `Error =` line carries the ESC byte, or an escaped text is
    /// escaped a second time.
    #[test]
    fn an_error_with_a_control_is_written_as_its_escape_once() {
        let esc = char::from(0x1b);
        let out = emit("", &format!("failed at {esc}[1mpath"));
        assert_eq!("Error = failed at \\u{1b}[1mpath\n", out);
        assert!(!out.contains(esc), "no raw ESC is written: {:?}", out);
        assert_eq!(
            "Error = failed at \\u{1b}[1mpath\n",
            emit("", "failed at \\u{1b}[1mpath"),
            "an escaped text is not escaped again"
        );
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

    /// A line break inside a message that also holds a `;` divides the message too, as the one-line forms
    /// of the same text join it (`one_line`): the pieces are cut at every `;`, line feed and carriage
    /// return together, and a CRLF pair is one break. Cut at the `;` alone, the break inside a piece was
    /// written as the two characters `\n` (or `\r\n`) beside the `; ` the rest of the console prints.
    ///
    /// Expected, not yet run. Red: a piece holds the characters `\n` or `\r`, or a CRLF text gives an
    /// empty or doubled item.
    #[test]
    fn a_line_break_in_a_piece_that_holds_a_semicolon_divides_the_message() {
        assert_eq!(
            "Message {\n  a\n  b\n  c\n}\n",
            emit("a; b\nc", ""),
            "a line feed after a semicolon divides the piece"
        );
        assert_eq!(
            "Message {\n  Violation: encrypt\n  use KMS\n  Fix: set it\n}\n",
            emit("Violation: encrypt; use KMS\r\n  Fix: set it\r\n", ""),
            "a CRLF text divides at its breaks and writes no carriage return"
        );
    }

    /// The error half is joined into one line before it is escaped, as a refusal's is: a line break in a
    /// plain record's error prints as `; `, not as the characters `\n`.
    ///
    /// Expected, not yet run. Red: the `Error =` line holds the characters `\n` or `\r`.
    #[test]
    fn a_line_break_in_an_error_is_joined_not_escaped() {
        assert_eq!(
            "Error = first; second; third\n",
            emit("", "first\nsecond\r\nthird")
        );
    }

    /// A joiner or a mark between printable characters is text, not a control: a zero-width joiner in an
    /// emoji sequence and a right-to-left mark in Hebrew prose print as typed, and so do a zero-width
    /// non-joiner and a left-to-right mark. The characters that hide or reorder a line (a zero-width
    /// space, a word joiner, a bidi override) stay escaped.
    ///
    /// Expected, not yet run. Red: the ZWJ or the RLM line holds the characters `\u{200d}` or `\u{200f}`,
    /// or a zero-width space or an override is written raw.
    #[test]
    fn joiners_and_marks_in_a_message_are_written_as_typed() {
        let zwj = format!("owner{}tag required", '\u{200D}');
        assert_eq!(format!("Message = {zwj}\n"), emit(&zwj, ""));
        let rlm = format!("shalom{}world", '\u{200F}');
        assert_eq!(format!("Message = {rlm}\n"), emit(&rlm, ""));
        let others = format!("a{}b{}c", '\u{200C}', '\u{200E}');
        assert_eq!(format!("Message = {others}\n"), emit(&others, ""));
        assert_eq!(
            "Message = a\\u{200b}b\\u{202e}c\\u{2060}d\n",
            emit("a\u{200B}b\u{202E}c\u{2060}d", ""),
            "a zero-width space, an override and a word joiner stay escaped"
        );
    }
}

/// The `Message =` and `Error =` lines of each arm of `pprint_clauses` that prints a clause's recorded
/// texts through `emit_messages`: a block, a unary check, a decided comparison, a membership comparison
/// and a retrieval error. The unit cell for each prints a record whose author's message and error hold a
/// raw ESC and reads the whole output for the byte. The ESC is built with `char::from`, since the
/// source holds no raw control.
#[cfg(test)]
mod clause_arm_escape_tests {
    use super::{pprint_clauses, ComparisonErrorWriter, IdentityHash, LocalResourceAggr};
    use crate::rules::eval_context::{
        BinaryCheck, BinaryComparison, BinaryReport, ClauseReport, GuardBlockReport,
        GuardClauseReport, InComparison, Messages, UnaryCheck, UnaryComparison, UnaryReport,
        ValueUnResolved,
    };
    use crate::rules::path_value::PathAwareValue;
    use crate::rules::values::CmpOperator;
    use crate::rules::{UnResolved, UnResolvedKind};
    use std::collections::{BTreeSet, HashSet};
    use std::convert::TryFrom;
    use std::io::Write;
    use std::rc::Rc;

    struct NoExcerpt;
    impl ComparisonErrorWriter for NoExcerpt {}

    fn esc() -> char {
        char::from(0x1b)
    }

    /// A plain (non-refusal) record whose author's message and evaluator's error each hold an ESC.
    fn messages() -> Messages {
        Messages {
            custom_message: Some(format!("{}[2J", esc())),
            error_message: Some(format!("bad {}[1mvalue", esc())),
            location: None,
            refusal: false,
            parts: None,
        }
    }

    /// A string scalar: the value grammar reads a bare word as a fragment it cannot parse, so the scalar
    /// is quoted.
    fn value() -> Rc<PathAwareValue> {
        Rc::new(PathAwareValue::try_from("'a'").expect("one scalar parses"))
    }

    /// `clause` as `pprint_clauses` writes it under a resource that shows it.
    fn rendered(clause: &ClauseReport<'_>) -> String {
        let mut clauses = HashSet::new();
        clauses.insert(IdentityHash { key: clause });
        let resource = LocalResourceAggr {
            name: "R".to_string(),
            resource_type: "AWS::Example::Thing",
            cdk_path: None,
            clauses,
            paths: BTreeSet::new(),
        };
        let mut written: Vec<u8> = Vec::new();
        pprint_clauses(
            &mut written,
            clause,
            &resource,
            "  ".to_string(),
            &mut NoExcerpt,
        )
        .expect("writing to a Vec cannot fail");
        String::from_utf8(written).expect("the output is UTF-8")
    }

    /// The record's halves are written as escapes: neither the message's nor the error's ESC reaches the
    /// output as a byte. `with_error` is false for an arm that prints no sentence for a plain record.
    fn assert_both_halves_escaped(out: &str, with_error: bool) {
        assert!(!out.contains(esc()), "no raw ESC is written:\n{:?}", out);
        assert!(
            out.contains("\\u{1b}[2J"),
            "the message is written, escaped:\n{}",
            out
        );
        if with_error {
            assert!(
                out.contains("bad \\u{1b}[1mvalue"),
                "the error is written, escaped:\n{}",
                out
            );
        }
    }

    /// Expected, not yet run. Red: the block's `Message =` line carries the ESC byte.
    #[test]
    fn a_blocks_message_is_written_escaped() {
        let clause = ClauseReport::Block(GuardBlockReport {
            context: "Resources.*.Properties".to_string(),
            messages: messages(),
            unresolved: None,
        });
        let out = rendered(&clause);
        assert_both_halves_escaped(&out, true);
    }

    /// Expected, not yet run. Red: the unary check's `Message =` or `Error =` line carries the ESC byte.
    #[test]
    fn a_unary_checks_message_is_written_escaped() {
        let clause = ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport {
            check: UnaryCheck::Resolved(UnaryComparison {
                value: value(),
                comparison: (CmpOperator::Exists, false),
            }),
            context: "Resources.*.Properties exists".to_string(),
            messages: messages(),
        }));
        let out = rendered(&clause);
        assert_both_halves_escaped(&out, true);
    }

    /// Expected, not yet run. Red: the decided comparison's `Message =` or `Error =` line carries the
    /// ESC byte.
    #[test]
    fn a_decided_comparisons_message_is_written_escaped() {
        let clause = ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
            context: "Name == 'x'".to_string(),
            messages: messages(),
            check: BinaryCheck::Resolved(BinaryComparison {
                from: value(),
                to: value(),
                comparison: (CmpOperator::Eq, false),
            }),
        }));
        let out = rendered(&clause);
        assert_both_halves_escaped(&out, true);
    }

    /// Expected, not yet run. Red: the membership comparison's `Message =` or `Error =` line carries
    /// the ESC byte.
    #[test]
    fn a_membership_comparisons_message_is_written_escaped() {
        let clause = ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
            context: "Name IN ['x']".to_string(),
            messages: messages(),
            check: BinaryCheck::InResolved(InComparison {
                from: value(),
                to: vec![value()],
                comparison: (CmpOperator::In, false),
            }),
        }));
        let out = rendered(&clause);
        assert_both_halves_escaped(&out, true);
    }

    /// The retrieval arm prints the author's message through `emit_messages` too. A plain record's
    /// sentence is not printed there (`refusal_lines` decides it for a refusal alone), so the cell reads
    /// the message half.
    ///
    /// Expected, not yet run. Red: the retrieval error's `Message =` line carries the ESC byte.
    #[test]
    fn a_retrieval_errors_message_is_written_escaped() {
        let clause = ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
            context: "Name == 'x'".to_string(),
            messages: messages(),
            check: BinaryCheck::UnResolved(ValueUnResolved {
                value: UnResolved {
                    traversed_to: value(),
                    remaining_query: "Name".to_string(),
                    reason: None,
                    kind: UnResolvedKind::Absent,
                },
                comparison: (CmpOperator::Eq, false),
                to: None,
            }),
        }));
        let out = rendered(&clause);
        assert_both_halves_escaped(&out, false);
    }

    /// A comparison writer's own colour and layout reach the output as they are. The CloudFormation writer
    /// colours each source line of its `Code:` excerpt, so the strict escape of the finished line would
    /// print the colour sequence as text and a tab-indented template as `\t`; the writers escape what they
    /// take from the template themselves, before the colour, and the clause arm's backstop
    /// (`writer_output`) then leaves the layout and the two colour sequences alone. The writer here emits
    /// a coloured, tab-indented excerpt line the way that writer does; a field it takes from the template
    /// goes through `console_field`, which also writes a line feed in it as the characters `\n`.
    ///
    /// Expected, not yet run. Red: the output holds the characters `\u{1b}[92m` (the colour printed as
    /// text) or the excerpt's tab as `\t`, the template field's ESC byte reaches the output raw, or a
    /// line feed in the field starts a second line.
    #[test]
    fn a_comparison_writers_colour_and_tab_are_not_escaped_by_the_clause_arm() {
        struct ColouredExcerpt;
        impl ComparisonErrorWriter for ColouredExcerpt {
            fn unary_error_msg(
                &mut self,
                writer: &mut dyn Write,
                _cr: &ClauseReport<'_>,
                _bc: &UnaryComparison,
                prefix: &str,
            ) -> crate::rules::Result<usize> {
                let field = format!("a{}[1mb\nforged = 1", esc());
                writeln!(
                    writer,
                    "{prefix}PropertyPath = {}",
                    super::console_field(&field)
                )?;
                writeln!(writer, "{prefix}\u{1b}[92m    3.\tType: X\u{1b}[0m")?;
                Ok(0)
            }
        }
        let clause = ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport {
            check: UnaryCheck::Resolved(UnaryComparison {
                value: value(),
                comparison: (CmpOperator::Exists, false),
            }),
            context: "Name exists".to_string(),
            messages: Messages {
                custom_message: None,
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
        }));
        let mut clauses = HashSet::new();
        clauses.insert(IdentityHash { key: &clause });
        let resource = LocalResourceAggr {
            name: "R".to_string(),
            resource_type: "AWS::Example::Thing",
            cdk_path: None,
            clauses,
            paths: BTreeSet::new(),
        };
        let mut written: Vec<u8> = Vec::new();
        pprint_clauses(
            &mut written,
            &clause,
            &resource,
            "  ".to_string(),
            &mut ColouredExcerpt,
        )
        .expect("writing to a Vec cannot fail");
        let out = String::from_utf8(written).expect("the output is UTF-8");
        assert!(
            out.contains("\u{1b}[92m    3.\tType: X\u{1b}[0m"),
            "the writer's colour and tab are written as they are:\n{:?}",
            out
        );
        assert!(
            out.contains("PropertyPath = a\\u{1b}[1mb\\nforged = 1\n"),
            "the field the writer took from the template is escaped, one line:\n{:?}",
            out
        );
    }

    /// A writer that forgets to escape a field it took from the template still cannot reach the terminal
    /// raw: the clause arm's backstop (`writer_output`) writes a cursor movement (`ESC [2J`) and an
    /// operating-system command as their escapes, keeps the layout (a line feed, a tab) and keeps a
    /// well-formed colour sequence. The writer here formats an unescaped field, a coloured line and a
    /// tab-indented line.
    ///
    /// Expected, not yet run. Red: the output holds the ESC byte of the cursor movement, the colour
    /// sequence is written as text, or the tab is written as `\t`.
    #[test]
    fn a_writer_that_forgets_to_escape_a_field_is_caught_by_the_backstop() {
        struct Forgetful;
        impl ComparisonErrorWriter for Forgetful {
            fn unary_error_msg(
                &mut self,
                writer: &mut dyn Write,
                _cr: &ClauseReport<'_>,
                _bc: &UnaryComparison,
                prefix: &str,
            ) -> crate::rules::Result<usize> {
                writeln!(
                    writer,
                    "{prefix}PropertyPath = a{}[2Jb{}]0;title",
                    esc(),
                    esc()
                )?;
                writeln!(writer, "{prefix}\u{1b}[92m    3.\tType: X\u{1b}[0m")?;
                Ok(0)
            }
        }
        let clause = ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport {
            check: UnaryCheck::Resolved(UnaryComparison {
                value: value(),
                comparison: (CmpOperator::Exists, false),
            }),
            context: "Name exists".to_string(),
            messages: Messages {
                custom_message: None,
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
        }));
        let mut clauses = HashSet::new();
        clauses.insert(IdentityHash { key: &clause });
        let resource = LocalResourceAggr {
            name: "R".to_string(),
            resource_type: "AWS::Example::Thing",
            cdk_path: None,
            clauses,
            paths: BTreeSet::new(),
        };
        let mut written: Vec<u8> = Vec::new();
        pprint_clauses(
            &mut written,
            &clause,
            &resource,
            "  ".to_string(),
            &mut Forgetful,
        )
        .expect("writing to a Vec cannot fail");
        let out = String::from_utf8(written).expect("the output is UTF-8");
        let without_colour = out.replace("\u{1b}[92m", "").replace("\u{1b}[0m", "");
        assert!(
            !without_colour.contains(esc()),
            "no ESC byte but the colour reaches the output:\n{:?}",
            out
        );
        assert!(
            out.contains("PropertyPath = a\\u{1b}[2Jb\\u{1b}]0;title\n"),
            "the forgotten field is written as its escapes:\n{:?}",
            out
        );
        assert!(
            out.contains("\u{1b}[92m    3.\tType: X\u{1b}[0m"),
            "the colour and the tab are kept:\n{:?}",
            out
        );
    }

    /// The strict set holds for a line that prints a KEY, a PATH or a CONTEXT: a rule key with a pasted
    /// zero-width joiner would print like the key without it if the line were written with the relaxed
    /// set, which is for text. The same joiner in the rule's message prints as typed.
    ///
    /// Expected, not yet run. Red: the `Check =` line holds the joiner raw, or the `Message =` line holds
    /// the characters `\u{200d}`.
    #[test]
    fn a_joiner_is_escaped_in_a_context_and_typed_in_a_message() {
        let clause = ClauseReport::Block(GuardBlockReport {
            context: format!("Bucket{}Name exists", '\u{200D}'),
            messages: Messages {
                custom_message: Some(format!("owner{}tag required", '\u{200D}')),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            unresolved: None,
        });
        let out = rendered(&clause);
        assert!(
            out.contains("Check = Bucket\\u{200d}Name exists {\n"),
            "the context is escaped by the strict set:\n{:?}",
            out
        );
        // The block arm pads the label to the property block's width, so the message is read after the
        // `=`, not after one space.
        assert!(
            out.contains(&format!("= owner{}tag required\n", '\u{200D}')),
            "the message is typed:\n{:?}",
            out
        );
    }

    /// The `Check =` line prints the context with the spacing the rules file gave it: a context that opens
    /// and closes with spaces keeps them, as the line has always printed it, so the goldens that read these
    /// lines byte for byte stay as they are. Only a context that spans lines is joined.
    ///
    /// Expected, not yet run. Red: the spaces around the context are trimmed or doubled.
    #[test]
    fn a_context_keeps_the_spacing_the_rules_file_gave_it_on_the_check_line() {
        let clause = ClauseReport::Block(GuardBlockReport {
            context: " %s3_bucket[*].Properties EXISTS  ".to_string(),
            messages: Messages {
                custom_message: None,
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            unresolved: None,
        });
        let out = rendered(&clause);
        assert!(
            out.starts_with("  Check =  %s3_bucket[*].Properties EXISTS   {\n"),
            "the context's own spaces are printed:\n{:?}",
            out
        );
    }

    /// A context that spans lines is joined on its `Check =` line as `; `, as the unattributed section
    /// joins the same text, and is not written as the characters `\n` by the sink.
    ///
    /// Expected, not yet run. Red: the line holds the characters `\n` or a second console line.
    #[test]
    fn a_context_with_a_line_break_is_joined_on_the_check_line() {
        let clause = ClauseReport::Block(GuardBlockReport {
            context: "Resources.*\n{ Type == 'x' }".to_string(),
            messages: Messages {
                custom_message: None,
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            unresolved: None,
        });
        let out = rendered(&clause);
        assert!(
            out.contains("Check = Resources.*; { Type == 'x' } {\n"),
            "the context is on one line, joined:\n{:?}",
            out
        );
        assert!(!out.contains("\\n"), "no escaped line feed:\n{:?}", out);
    }

    /// The `Check =` line of every arm prints the clause's context, text the rules file holds, and the
    /// retrieval arm's `MissingProperty =` line prints the key the template lacks: neither is a field
    /// any helper bounded, so a raw ESC in either would reach the console as a byte. Both go through
    /// the sink (`write_console_line`) that escapes each finished line.
    ///
    /// Expected, not yet run. Red: an arm's output carries the ESC byte, or a context's escape reads
    /// differently from the one written for a message.
    #[test]
    fn a_context_and_a_missing_key_with_a_control_are_written_escaped() {
        let context = format!("Name == '{}[31mx'", esc());
        let plain = || Messages {
            custom_message: None,
            error_message: None,
            location: None,
            refusal: false,
            parts: None,
        };
        let clauses = [
            ClauseReport::Block(GuardBlockReport {
                context: context.clone(),
                messages: plain(),
                unresolved: None,
            }),
            ClauseReport::Clause(GuardClauseReport::Unary(UnaryReport {
                check: UnaryCheck::Resolved(UnaryComparison {
                    value: value(),
                    comparison: (CmpOperator::Exists, false),
                }),
                context: context.clone(),
                messages: plain(),
            })),
            ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
                context: context.clone(),
                messages: plain(),
                check: BinaryCheck::Resolved(BinaryComparison {
                    from: value(),
                    to: value(),
                    comparison: (CmpOperator::Eq, false),
                }),
            })),
            ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
                context: context.clone(),
                messages: plain(),
                check: BinaryCheck::InResolved(InComparison {
                    from: value(),
                    to: vec![value()],
                    comparison: (CmpOperator::In, false),
                }),
            })),
            ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
                context: context.clone(),
                messages: plain(),
                check: BinaryCheck::UnResolved(ValueUnResolved {
                    value: UnResolved {
                        traversed_to: value(),
                        remaining_query: format!("Na{}[1mme", esc()),
                        reason: None,
                        kind: UnResolvedKind::Absent,
                    },
                    comparison: (CmpOperator::Eq, false),
                    to: None,
                }),
            })),
        ];
        for (index, clause) in clauses.iter().enumerate() {
            let out = rendered(clause);
            assert!(
                !out.contains(esc()),
                "arm {}: no raw ESC is written:\n{:?}",
                index,
                out
            );
            assert!(
                out.contains("Name == '\\u{1b}[31mx'"),
                "arm {}: the context is written, escaped:\n{}",
                index,
                out
            );
        }
        let out = rendered(&clauses[4]);
        assert!(
            out.contains("MissingProperty = Na\\u{1b}[1mme"),
            "the missing key is written, escaped:\n{}",
            out
        );
    }
}

#[cfg(test)]
mod retrieval_error_tests {
    use super::{
        emit_retrieval_error, one_line, ComparisonErrorWriter, LONGEST_REFUSAL_MESSAGE,
        REFUSAL_CUT_MARKER,
    };
    use crate::rules::eval::left_marker_beside_an_absence;
    use crate::rules::eval_context::{
        marker_part, report_all_failed_clauses_for_rules, BinaryCheck, BinaryReport, ClauseReport,
        EventRecord, GuardClauseReport, Messages, SentenceParts, ValueUnResolved,
    };
    use crate::rules::path_value::PathAwareValue;
    use crate::rules::values::CmpOperator;
    use crate::rules::{
        ClauseCheck, ComparisonClauseCheck, QueryResult, RecordType, Status, UnResolved,
        UnResolvedKind,
    };
    use std::convert::TryFrom;
    use std::rc::Rc;

    /// The console summary's reading of a block check that carries the author's `<< >>` message (a `not`
    /// over a reference that failed closed): `extract_name_info_from_record`, which every renderer of
    /// `report_from_events` prints from, gives the author's text as the finding's `message` and the record's
    /// sentence as its `error`, as it does for a dependent rule's record; a block check with no author's
    /// message gives an empty `message`, as before.
    #[test]
    fn a_block_checks_authors_message_reaches_the_console_summarys_name_info() {
        const AUTHORS: &str = "the author's own words on the reference";
        const SENTENCE: &str = "the negated rule [check] failed only on reads it could not decide";
        let record = |custom_message: Option<&str>, refusal: bool| EventRecord {
            context: String::from("not check"),
            container: Some(RecordType::GuardClauseBlockCheck(
                crate::rules::BlockCheck {
                    status: Status::FAIL,
                    at_least_one_matches: false,
                    message: Some(SENTENCE.to_string()),
                    refusal,
                    custom_message: custom_message.map(str::to_string),
                },
            )),
            children: vec![],
        };
        // Flagged (the basis rests on a refusal) and unflagged (a budget-only basis) alike.
        for refusal in [true, false] {
            let with_record = record(Some(AUTHORS), refusal);
            let with = super::extract_name_info_from_record("main", &with_record)
                .expect("a block check is a finding the summary reads");
            assert_eq!(
                (AUTHORS, Some(SENTENCE.to_string()), "main"),
                (with.message.as_str(), with.error.clone(), with.rule),
                "the author's message is the finding's message, the sentence its error (refusal: {})",
                refusal
            );
        }
        let without_record = record(None, true);
        let without = super::extract_name_info_from_record("main", &without_record)
            .expect("a block check is a finding the summary reads");
        assert_eq!(
            ("", Some(SENTENCE.to_string())),
            (without.message.as_str(), without.error.clone()),
            "no author's message reads as the empty message, as before"
        );
    }

    /// The console reporter's code excerpt, which these cells do without: every line under test is one
    /// this file writes itself.
    struct NoExcerpt;
    impl ComparisonErrorWriter for NoExcerpt {}

    /// The clause of a right-hand refused marker's record: a capture holding the marker, compared under a
    /// positive `IN`.
    const RHS_CONTEXT: &str = "Resources.R.Properties.Cfg.Mode.Ref IN %x";
    /// The clause of a left-hand refused marker's record: the capture compared from.
    const LHS_CONTEXT: &str = "%x == 'k'";
    /// The clause of an absent value's record beside a refused read.
    const ABSENCE_CONTEXT: &str = "Resources.R.Properties.Cfg.Missing == %x";

    /// A refusal's text as the evaluator registers one, its path included.
    const REFUSAL: &str = "then no kept entry holds a key the predicate names, at path /Resources/R/Properties/Cfg/A/Sub";
    /// The retrieval's own reason for a key the document lacks.
    const RETRIEVAL_REASON: &str =
        "Could not find key Missing inside struct at path /Resources/R/Properties/Cfg";

    /// One record's unresolved value: `reason` and `kind` as the evaluator left them, `remaining_query`
    /// empty for a marker that stands at its entry and the missing key for an absence.
    fn unresolved(reason: &str, remaining_query: &str, kind: UnResolvedKind) -> ValueUnResolved {
        ValueUnResolved {
            value: UnResolved {
                traversed_to: Rc::new(
                    PathAwareValue::try_from("{ Resources: { R: { Properties: { Cfg: {} } } } }")
                        .expect("one document parses"),
                ),
                remaining_query: remaining_query.to_string(),
                reason: Some(reason.to_string()),
                kind,
            },
            comparison: (CmpOperator::In, false),
            to: None,
        }
    }

    /// The report builder's head for an unresolved right-hand value the evaluator refused to read.
    const RHS_HEAD_TEXT: &str =
        "Check was not compliant as the value to compare to could not be read.";
    /// The report builder's head for an unresolved left-hand value the evaluator refused to read.
    const LHS_HEAD_TEXT: &str =
        "Check was not compliant as the value to compare from could not be read.";

    /// The record's `Messages` as the report builder writes them for a clause record with the head
    /// `head` and the evaluator's `message`: the joined sentence (`<head> Error = [<message>]`, the head
    /// alone with no message) as `error_message`, the parts beside it, flagged `refusal`.
    fn record(head: &str, message: Option<&str>, refusal: bool) -> Messages {
        Messages {
            custom_message: Some(String::new()),
            error_message: Some(match message {
                Some(message) => format!("{head} Error = [{message}]"),
                None => head.to_string(),
            }),
            location: None,
            refusal,
            parts: message.map(|message| SentenceParts {
                head: head.to_string(),
                message: message.to_string(),
            }),
        }
    }

    /// One retrieval error's finding as `pprint_clauses` writes it under a resource for the clause
    /// `context`, over the unresolved value `vur`, for the record `messages`. Four spaces of prefix,
    /// the depth of a clause under `Rule = r { ALL { } }`.
    fn finding_of(context: &str, messages: Messages, vur: &ValueUnResolved) -> String {
        let clause = ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
            context: context.to_string(),
            messages: messages.clone(),
            check: BinaryCheck::UnResolved(vur.clone()),
        }));
        let mut written: Vec<u8> = Vec::new();
        emit_retrieval_error(
            &mut written,
            "    ",
            vur,
            &clause,
            context,
            &messages,
            &mut NoExcerpt,
        )
        .expect("writing to a Vec cannot fail");
        String::from_utf8(written).expect("the output is UTF-8")
    }

    /// The finding of the record the report builder writes from `head` and `message`, flagged `refusal`.
    fn finding(
        context: &str,
        head: &str,
        message: Option<&str>,
        refusal: bool,
        vur: &ValueUnResolved,
    ) -> String {
        finding_of(context, record(head, message, refusal), vur)
    }

    /// The finding of a right-hand refused marker's record: the marker's reason is the refusal, and the
    /// record's message is the refusal.
    fn refused_marker_finding(refusal: &str) -> String {
        finding(
            RHS_CONTEXT,
            RHS_HEAD_TEXT,
            Some(refusal),
            true,
            &unresolved(
                refusal,
                "",
                UnResolvedKind::Undecidable {
                    refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                    carried: None,
                },
            ),
        )
    }

    /// The `PropertyPath =` line of a finding over `vur`, as the reporter renders the value's path; the
    /// path's rendering is not what these cells pin.
    fn property_path_line(vur: &ValueUnResolved) -> String {
        format!(
            "        PropertyPath = {}",
            vur.value.traversed_to.self_path()
        )
    }

    /// The `Error =` line of a finding, the one line of it that carries the record's sentence.
    fn error_line(finding: &str) -> String {
        let lines: Vec<&str> = finding
            .lines()
            .filter(|line| line.trim_start().starts_with("Error = "))
            .collect();
        assert_eq!(1, lines.len(), "one `Error =` line:\n{}", finding);
        lines[0].to_string()
    }

    /// The `Reason =` line of a finding, the one line of it that carries the unresolved value's reason.
    fn reason_line(finding: &str) -> String {
        let lines: Vec<&str> = finding
            .lines()
            .filter(|line| line.trim_start().starts_with("Reason = "))
            .collect();
        assert_eq!(1, lines.len(), "one `Reason =` line:\n{}", finding);
        lines[0].to_string()
    }

    /// The head of a right-hand refused marker's sentence, the `Error =` line of its block.
    const RHS_HEAD: &str =
        "      Error = Check was not compliant as the value to compare to could not be read.";
    /// The head of a left-hand refused marker's sentence, the `Error =` line of its block.
    const LHS_HEAD: &str =
        "      Error = Check was not compliant as the value to compare from could not be read.";

    /// A refusal holding a raw ESC AND a line break takes the console's one pipeline in its order
    /// (`reason_backstop`): the break is collapsed to `; ` first and the ESC is written as its
    /// escape after it, on one bounded `Reason =` line. Escaped before the collapse, the break became a
    /// literal `\n` and nothing was joined.
    #[test]
    fn a_refusal_holding_an_escape_and_a_line_break_is_one_escaped_reason_line() {
        let refusal = "the key `\u{1b}[31ma\nb\u{1b}[0m` could not be read\n  define `X` by hand";
        let out = refused_marker_finding(refusal);

        assert_eq!(RHS_HEAD, error_line(&out));
        assert_eq!(
            "        Reason = the key `\\u{1b}[31ma; b\\u{1b}[0m` could not be read; define `X` by hand",
            reason_line(&out)
        );
        assert!(
            !out.contains('\u{1b}') && !out.contains("\\n"),
            "no raw ESC and no literal line-break escape reach the console:\n{}",
            out
        );
    }

    /// A refusal's `Reason =` line is cut on its PRINTED width: three raw ESCs in a reason a few characters
    /// under `LONGEST_REFUSAL_MESSAGE` each grow into a six-character escape, so the escaped line passes
    /// the bound and is cut with the marker, within the bound; cut before the escape, the reason read as
    /// within the bound and the printed line ran past it. The control, the same reason with the ESCs
    /// removed, is under the bound and prints whole with no marker. The raw text has to be UNDER the
    /// bound for the cell to show the property: the filler is twenty under it and the three sequences are
    /// four raw characters each (ESC, `[`, a digit, `m`), 4088 raw, and each ESC grows by five when
    /// escaped, 4103 printed; a filler ten under the bound made the raw text 4098 and the cell failed its
    /// own first assertion.
    #[test]
    fn a_refusals_reason_is_cut_on_its_printed_width_after_its_controls_are_escaped() {
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let filler = "x".repeat(bound - 20);
        let with_escapes = format!("{filler}\u{1b}[1m\u{1b}[2m\u{1b}[0m");
        assert!(with_escapes.chars().count() < bound);
        assert!(
            crate::utils::writer::escaped_controls_for_display(&with_escapes)
                .chars()
                .count()
                > bound
        );
        let out = refused_marker_finding(&with_escapes);
        let reason = reason_line(&out);
        let printed = reason
            .trim_start()
            .strip_prefix("Reason = ")
            .expect("the Reason line");
        assert!(
            printed.ends_with(super::REFUSAL_CUT_MARKER),
            "the escaped line passed the bound and was cut with the marker:\n{}",
            reason
        );
        let text = printed
            .strip_suffix(super::REFUSAL_CUT_MARKER)
            .expect("the marker")
            .trim_end();
        assert!(
            text.chars().count() <= bound + 3 && text.ends_with("..."),
            "the printed text is within the bound plus the ellipsis: {} characters",
            text.chars().count()
        );
        assert!(!out.contains('\u{1b}'), "no raw ESC reaches the console");

        let control = refused_marker_finding(&filler);
        let control_reason = reason_line(&control);
        assert!(
            !control_reason.contains(super::REFUSAL_CUT_MARKER)
                && control_reason.ends_with(&filler),
            "the control under the bound prints whole:\n{}",
            control_reason
        );
    }

    /// A reason that is no refusal's takes the same pipeline and the same backstop: over the
    /// recorded-message cut of 320 characters it prints whole (a retrieval reason keeps its trailing
    /// position), and over `LONGEST_REFUSAL_MESSAGE` it is cut on its printed width with the plain
    /// reason's OWN marker (`REASON_CUT_MARKER`), never the refusal's, so no console line depends on the
    /// evaluator having bounded the text and no retrieval error is called an explanation. An earlier cut
    /// of this cell pinned the refusal's marker on the plain reason, the one pipeline then reading every
    /// reason as a refusal's.
    #[test]
    fn a_plain_reasons_line_is_held_to_the_backstop_with_its_own_marker() {
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let over_the_message_cut = format!(
            "Could not find key Missing inside struct at path /Resources/R/Properties/Cfg {} [L:9,C:3]",
            "x".repeat(super::LONGEST_RECORDED_MESSAGE)
        );
        let vur = unresolved(&over_the_message_cut, "Missing", UnResolvedKind::Absent);
        let out = finding(
            RHS_CONTEXT,
            RHS_HEAD_TEXT,
            Some("the sentence"),
            false,
            &vur,
        );
        let reason = reason_line(&out);
        assert!(
            reason.ends_with("[L:9,C:3]") && !reason.contains("..."),
            "a plain reason over the recorded-message cut prints whole:\n{}",
            reason
        );

        let over_the_backstop = "y".repeat(bound + 20);
        let vur = unresolved(&over_the_backstop, "Missing", UnResolvedKind::Absent);
        let out = finding(
            RHS_CONTEXT,
            RHS_HEAD_TEXT,
            Some("the sentence"),
            false,
            &vur,
        );
        let reason = reason_line(&out);
        let printed = reason
            .trim_start()
            .strip_prefix("Reason = ")
            .expect("the Reason line");
        assert!(
            printed.ends_with(super::REASON_CUT_MARKER)
                && !printed.contains(super::REFUSAL_CUT_MARKER)
                && printed.chars().count() <= bound + 3 + 1 + super::REASON_CUT_MARKER.len(),
            "a plain reason over the backstop is cut on its printed width with the plain reason's own marker:\n{}",
            reason
        );
    }

    /// A refusal record whose message LEADS with the reason (an absent value beside a refused read: the
    /// retrieval's reason first, the refusal after it) and does not fit the `Error =` line whole goes on
    /// `Reason =` through the one pipeline (`reason_backstop`): the raw ESC in the reason prints as its
    /// escape and the line is cut on its printed width with the refusal's marker. Written through the
    /// bare bound, that one branch printed the lead's controls raw. The evaluator writes a lead with its
    /// template parts escaped; this cell and its under-the-bound twin pin the console's own defense for a
    /// sentence that reaches it raw.
    #[test]
    fn a_lead_first_message_over_the_bound_prints_escaped_on_the_reason_line() {
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let reason =
            "Could not find key \u{1b}[31mMissing\u{1b}[0m inside struct at path /Resources/R";
        let message = format!("{reason}, then the refusal: {}", "r".repeat(bound));
        let vur = unresolved(reason, "Missing", UnResolvedKind::Absent);
        let out = finding(RHS_CONTEXT, RHS_HEAD_TEXT, Some(&message), true, &vur);
        assert_eq!(RHS_HEAD, error_line(&out));
        let line = reason_line(&out);
        assert!(
            line.contains("key \\u{1b}[31mMissing\\u{1b}[0m inside")
                && !out.contains('\u{1b}')
                && line.ends_with(super::REFUSAL_CUT_MARKER),
            "the lead-first message prints escaped and cut with the marker on `Reason =`:\n{}",
            out.escape_debug()
        );
    }

    /// The under-the-bound twin: a lead-first message that fits is joined to the head on `Error =`
    /// through the same pipeline, the raw line break in the reason joined as `; ` and the raw ESC printed
    /// as its escape after it, with no `Reason =` line; its width taken and its text printed raw, that
    /// branch put the control on the console while the over-the-bound branch escaped it, and escaped
    /// before the collapse it would print the break as a literal `\n`.
    #[test]
    fn a_lead_first_message_under_the_bound_prints_escaped_on_the_error_line() {
        let reason =
            "Could not find key \u{1b}[31mMissing\u{1b}[0m\ninside struct at path /Resources/R";
        let message = format!("{reason}, then the refusal");
        let vur = unresolved(reason, "Missing", UnResolvedKind::Absent);
        let out = finding(RHS_CONTEXT, RHS_HEAD_TEXT, Some(&message), true, &vur);
        let error = error_line(&out);
        assert!(
            error.contains("key \\u{1b}[31mMissing\\u{1b}[0m; inside")
                && error.ends_with(", then the refusal")
                && !out.contains('\u{1b}')
                && !out.contains("\\n")
                && !out.lines().any(|line| line.trim_start().starts_with("Reason = ")),
            "the lead-first message under the bound prints collapsed, escaped and whole on `Error =`, with no `Reason =` line:\n{}",
            out.escape_debug()
        );
    }

    /// The `Error =` line of a refusal record on the arms that print a block, a unary check and a decided
    /// comparison (`error_line_text`, the one text those call sites print) takes the console's one
    /// refusal pipeline: a raw line break in the recorded sentence is joined as `; ` first, a raw ESC is
    /// written as its escape after it, and a sentence over the bound is cut on its PRINTED width with the
    /// refusal's marker. Bounded with no escape, those arms printed the control raw while the
    /// retrieval-error arm escaped it. The control: a record that is no refusal's returns its sentence as
    /// recorded, controls and all, from `error_line_text`; `emit_messages` collapses and escapes it when
    /// it prints.
    #[test]
    fn a_refusal_records_error_line_on_the_block_and_comparison_arms_is_escaped_and_bounded() {
        let sentence = "the key `\u{1b}[31ma\nb\u{1b}[0m` could not be read";
        let refusal = Messages {
            custom_message: Some(String::new()),
            error_message: Some(sentence.to_string()),
            location: None,
            refusal: true,
            parts: None,
        };
        assert_eq!(
            "the key `\\u{1b}[31ma; b\\u{1b}[0m` could not be read",
            super::error_line_text(&refusal),
            "the refusal's sentence is collapsed, then escaped"
        );

        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let over_the_bound = format!("{}\u{1b}[1m\u{1b}[2m\u{1b}[0m", "x".repeat(bound - 20));
        let line = super::error_line_text(&Messages {
            error_message: Some(over_the_bound),
            ..refusal.clone()
        });
        assert!(
            line.ends_with(super::REFUSAL_CUT_MARKER) && !line.contains('\u{1b}'),
            "three ESCs under the raw bound pass the printed bound and the line is cut with the marker, no raw ESC left:\n{}",
            line.escape_debug()
        );
        // The cut on the printed width lands inside the third escape (`bound - 20` x's, then 27
        // characters of escapes: the first `bound` characters end in `\u`, the first two of the third
        // escape's six), and is moved back to that escape's start: the kept text ends with the second
        // escape's whole sequence, no `\u` fragment stands before the ellipsis, and every `\u` kept is a
        // whole `\u{..}`. `a_cut_inside_an_escape_at_any_offset_is_moved_back_to_its_start` reads every
        // other offset.
        let kept = line
            .strip_suffix(&format!("... {}", super::REFUSAL_CUT_MARKER))
            .expect("the cut line ends with the ellipsis, a space and the marker");
        assert!(
            kept.ends_with("\\u{1b}[2m"),
            "the cut is moved back to the start of the escape it split: {}",
            kept.escape_debug()
        );
        assert!(
            kept.match_indices("\\u")
                .all(|(at, _)| kept[at..].starts_with("\\u{") && kept[at..].contains('}')),
            "every `\\u` kept is a whole escape, none a fragment the cut left: {}",
            kept.escape_debug()
        );

        let plain = Messages {
            refusal: false,
            ..refusal.clone()
        };
        assert_eq!(
            sentence,
            super::error_line_text(&plain),
            "a record that is no refusal's prints its sentence as released"
        );
    }

    /// A cut that lands INSIDE an escape, at any offset, is moved back to the escape's start, and a cut
    /// that lands right after a whole escape keeps it: `bound - k` x's, one raw control and a `y` after
    /// it (a trailing control alone would be trimmed by `one_line`, which trims each part, before any
    /// escaping: a tab at the very end never reaches the escape), so the escape's first `k` characters
    /// are the last `k` of the first `bound`; for a raw ESC (`\u{1b}`, six characters) k runs 1 to 5, the
    /// kept text is the x's alone (the lone backslash, `\u`, `\u{`, `\u{1` and `\u{1b` all moved back),
    /// and at k = 6 the escape ends exactly at the bound, so the cut drops the `y` alone and the whole
    /// escape stands before the ellipsis; for a raw tab (`\t`, two characters) k = 1 leaves the lone
    /// backslash, moved back, and k = 2 keeps the whole escape. A literal backslash the author wrote is no split
    /// escape: `\users` at the head of an over-bound line, and `\u` followed by seven letters just before
    /// the cut (a tail of nine, the longest an escape can be, that is no escape), each keep every
    /// character up to the bound; reading the last `\u` of the whole kept text cut the first back to its
    /// first character. The expected values are reasoned from the code.
    #[test]
    fn a_cut_inside_an_escape_at_any_offset_is_moved_back_to_its_start() {
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let marker = super::REFUSAL_CUT_MARKER;
        for (control, escape) in [('\u{1b}', "\\u{1b}"), ('\t', "\\t")] {
            for offset in 1..=escape.len() {
                let xs = "x".repeat(bound - offset);
                let line = super::reason_backstop(&format!("{xs}{control}y"), marker);
                if offset == escape.len() {
                    assert_eq!(
                        format!("{xs}{escape}... {marker}"),
                        line,
                        "the whole escape ends exactly at the bound and stands before the cut (offset {offset} into `{escape}`)"
                    );
                    continue;
                }
                assert_eq!(
                    format!("{xs}... {marker}"),
                    line,
                    "the cut at offset {offset} into `{escape}` is moved back to the escape's start"
                );
            }
        }
        for (label, raw) in [
            (
                "`\\users` at the head",
                format!("\\users{}", "y".repeat(bound)),
            ),
            (
                "`\\u` and seven letters just before the cut",
                format!("{}\\uyyyyyyyz", "y".repeat(bound - 9)),
            ),
        ] {
            let line = super::reason_backstop(&raw, marker);
            let kept = line
                .strip_suffix(&format!("... {marker}"))
                .expect("the over-bound line is cut with the marker");
            assert_eq!(
                (bound, &raw[..bound]),
                (kept.chars().count(), kept),
                "{label}: a literal backslash is no split escape, so the text keeps every character up to the bound"
            );
        }
    }

    /// The `Rule = { }` arm's two lines for a rule's own record take the same pipeline when the record is
    /// a refusal's (`rule_line_texts`): a rule-level record carries the evaluator's sentence in the custom
    /// slot, so BOTH slots are collapsed, escaped and bounded, where the clause arms bound the error slot
    /// alone; a record that is no refusal's has its custom slot collapsed onto one line, escaped and cut
    /// at the recorded-message bound (the cut the unattributed section gives that slot: here it is the
    /// evaluator's sentence, which can quote a 2 KB template value), and its error slot as released. A
    /// raw ESC and a line break in each slot: the refusal's are written as `\u{1b}` and `; `; the plain
    /// record's custom slot is written the same way, its error slot stands; a plain custom slot of 4000
    /// characters is cut at the bound with the ellipsis, and a control-free one reads as the unattributed
    /// section reads the same record. The last two rows hold an author's record whose error slot is the
    /// sentence the body displaced: a 4000-character sentence that is no refusal's is cut like the
    /// section cuts it, and a refusal's sentence takes the refusal pipeline. Red for those two rows is
    /// the sentence printed whole or with a raw ESC.
    #[test]
    fn a_refusal_rule_records_two_lines_are_escaped_and_bounded_and_a_plain_ones_are_released() {
        use crate::rules::eval_context::RuleReport;
        use crate::rules::CustomSlot;
        let rule_of = |messages: Messages, custom_slot: CustomSlot| RuleReport {
            name: "nested",
            messages,
            custom_slot,
            ..Default::default()
        };
        let custom = "the condition `\u{1b}[31mgate\u{1b}[0m` could not be\nanswered";
        let error = "the key `\u{1b}[31ma\nb\u{1b}[0m` could not be read";
        // The two texts a rule report can hold; what differs between the rows is the record's slot, not
        // the messages (a rule report's flag is not what the printer reads).
        let both_texts = Messages {
            custom_message: Some(custom.to_string()),
            error_message: Some(error.to_string()),
            location: None,
            refusal: false,
            parts: None,
        };
        assert_eq!(
            (
                "the condition `\\u{1b}[31mgate\\u{1b}[0m` could not be; answered".to_string(),
                "the key `\\u{1b}[31ma; b\\u{1b}[0m` could not be read".to_string(),
                None,
            ),
            super::rule_line_texts(&rule_of(both_texts.clone(), CustomSlot::Refusal)),
            "a refusal's record: both slots collapsed, then escaped; it carries no plain cut flag"
        );

        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let (message, _, _) = super::rule_line_texts(&rule_of(
            Messages {
                custom_message: Some(format!("{}\u{1b}[1m", "y".repeat(bound))),
                ..both_texts.clone()
            },
            CustomSlot::Refusal,
        ));
        assert!(
            message.ends_with(super::REFUSAL_CUT_MARKER) && !message.contains('\u{1b}'),
            "the custom slot over the bound is cut with the marker and no raw ESC is left:\n{}",
            message.escape_debug()
        );

        let plain = both_texts;
        assert_eq!(
            (
                "the condition `\\u{1b}[31mgate\\u{1b}[0m` could not be; answered".to_string(),
                error.to_string(),
                Some(false),
            ),
            super::rule_line_texts(&rule_of(plain.clone(), CustomSlot::Evaluator)),
            "a record that is no refusal's: the custom slot collapsed and escaped, uncut, the error slot as released"
        );
        let long = format!("{} {}", "y".repeat(300), "z".repeat(3700));
        let (long_custom, _, cut) = super::rule_line_texts(&rule_of(
            Messages {
                custom_message: Some(long.clone()),
                ..plain.clone()
            },
            CustomSlot::Evaluator,
        ));
        assert_eq!(
            (format!("{}...", "y".repeat(300)), Some(true)),
            (long_custom.clone(), cut),
            "a plain record's custom slot of 4000 characters is cut at the recorded-message bound, and says so"
        );
        assert_eq!(
            super::bounded_for_the_console(&long, super::Origin::Evaluator),
            long_custom,
            "a control-free plain custom slot reads as the unattributed section reads the same record"
        );
        assert_eq!(
            (String::new(), String::new(), Some(false)),
            super::rule_line_texts(&rule_of(Messages::default(), CustomSlot::Evaluator)),
            "an empty record prints nothing on either line"
        );
        let (author_text, _, author_cut) = super::rule_line_texts(&rule_of(
            Messages {
                custom_message: Some(long.clone()),
                ..plain
            },
            CustomSlot::Author,
        ));
        assert_eq!(
            (long.clone(), Some(false)),
            (author_text, author_cut),
            "an author's body of 4000 characters is printed whole on the rule line, as a clause's Message = line prints it"
        );
        let (_, displaced, _) = super::rule_line_texts(&rule_of(
            Messages {
                custom_message: Some("the author's body".to_string()),
                error_message: Some(long.clone()),
                refusal: false,
                ..Messages::default()
            },
            CustomSlot::Author,
        ));
        assert_eq!(
            format!("{}...", "y".repeat(300)),
            displaced,
            "the sentence a body displaced, when it is no refusal's, is cut at the recorded-message bound as the section cuts it"
        );
        let (_, displaced_refusal, _) = super::rule_line_texts(&rule_of(
            Messages {
                custom_message: Some("the author's body".to_string()),
                error_message: Some(format!("{}\u{1b}[1m", "y".repeat(bound))),
                refusal: true,
                ..Messages::default()
            },
            CustomSlot::Author,
        ));
        assert!(
            displaced_refusal.ends_with(super::REFUSAL_CUT_MARKER)
                && !displaced_refusal.contains('\u{1b}'),
            "a displaced refusal's sentence takes the refusal pipeline: cut with the marker, no raw ESC:\n{}",
            displaced_refusal.escape_debug()
        );
        let whole = format!("{} {}", "y".repeat(500), "z".repeat(500));
        let (_, displaced_whole, _) = super::rule_line_texts(&rule_of(
            Messages {
                custom_message: Some("the author's body".to_string()),
                error_message: Some(whole.clone()),
                refusal: true,
                ..Messages::default()
            },
            CustomSlot::Author,
        ));
        assert_eq!(
            whole, displaced_whole,
            "a displaced refusal's sentence under the refusal bound is printed whole, where a plain one is cut"
        );
    }

    /// `cut_to` says whether it dropped anything, from the branch that drops it, and its two readers take
    /// that answer: text of exactly the bound (after the collapse) is returned whole and unflagged, one
    /// character more is cut and flagged, and whitespace around a short text is no cut. `backstop` marks
    /// a text only when the cutter flagged it, and `plain_author_message` passes the flag on. Expected, not
    /// yet run; a red is a flag that disagrees with the ellipsis (a cut text unflagged, or a whole text
    /// flagged) or a marker on a text the cutter returned whole.
    #[test]
    fn the_cutter_says_whether_it_cut_and_its_readers_take_its_answer() {
        let bound = super::LONGEST_RECORDED_MESSAGE;
        let at_the_bound = "w".repeat(bound);
        let over_the_bound = format!("{at_the_bound}w");
        assert_eq!(
            (at_the_bound.clone(), false),
            super::cut_to(&at_the_bound, bound),
            "a text of exactly the bound is returned whole and unflagged"
        );
        let (over_text, over_cut) = super::cut_to(&over_the_bound, bound);
        assert_eq!(
            (true, true),
            (over_cut, over_text.ends_with("...")),
            "one character over the bound is cut, flagged, and ends in the ellipsis"
        );
        assert_eq!(
            ("a".to_string(), false),
            super::cut_to(
                &format!("{}a{}", " ".repeat(2 * bound), " ".repeat(2 * bound)),
                bound
            ),
            "whitespace around a short text is collapsed away and is no cut"
        );
        assert_eq!(
            (at_the_bound.clone(), false),
            super::plain_author_message(&at_the_bound),
            "a plain rule message of exactly the bound is whole and unflagged"
        );
        assert!(
            super::plain_author_message(&over_the_bound).1,
            "a plain rule message over the bound carries the cutter's flag"
        );
        let refusal_bound = super::LONGEST_REFUSAL_MESSAGE;
        assert_eq!(
            "w".repeat(refusal_bound),
            super::backstop(&"w".repeat(refusal_bound), super::REFUSAL_CUT_MARKER),
            "a text of exactly the refusal bound takes no marker"
        );
        assert!(
            super::backstop(&"w".repeat(refusal_bound + 1), super::REFUSAL_CUT_MARKER)
                .ends_with(super::REFUSAL_CUT_MARKER),
            "one character over the refusal bound takes the marker"
        );
    }

    /// The `Rule = { }` arm WRITES a refusal record's two texts as one line each (`emit_rule_messages`):
    /// a custom slot over the bound, holding `;` throughout, prints as ONE `Message = ...` line ending
    /// with the cut's marker, and an error slot with a line break as ONE `Error = ...` line with the break
    /// joined, where `emit_messages` split the message on every `;` and so printed the marker, and every
    /// join, across lines. The rule's record is rendered with no checks under it, so the output is the
    /// rule's opening line, the two message lines, `ALL {`, and the two closing braces. A record that is no
    /// refusal's still goes through `emit_messages`, so its `;` list prints as a `Message {` block.
    #[test]
    fn a_refusal_rule_records_two_lines_print_as_one_line_each() {
        use super::{pprint_clauses, LocalResourceAggr};
        use crate::rules::eval_context::RuleReport;
        use std::collections::{BTreeSet, HashSet};
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let marker = super::REFUSAL_CUT_MARKER;
        let resource = LocalResourceAggr {
            name: "R".to_string(),
            resource_type: "AWS::Example::Thing",
            cdk_path: None,
            clauses: HashSet::new(),
            paths: BTreeSet::new(),
        };
        let render = |messages: Messages, custom_slot: crate::rules::CustomSlot| -> Vec<String> {
            let report = ClauseReport::Rule(RuleReport {
                name: "nested",
                messages,
                custom_slot,
                ..Default::default()
            });
            let mut written: Vec<u8> = Vec::new();
            pprint_clauses(
                &mut written,
                &report,
                &resource,
                "  ".to_string(),
                &mut NoExcerpt,
            )
            .expect("writing to a Vec cannot fail");
            String::from_utf8(written)
                .expect("the output is UTF-8")
                .lines()
                .map(str::to_string)
                .collect()
        };

        let lines = render(
            Messages {
                custom_message: Some("word; ".repeat(bound / 3)),
                error_message: Some("the key `a\nb` could not be read".to_string()),
                location: None,
                refusal: false,
                parts: None,
            },
            crate::rules::CustomSlot::Refusal,
        );
        let messages: Vec<&String> = lines
            .iter()
            .filter(|line| line.trim_start().starts_with("Message"))
            .collect();
        let errors: Vec<&String> = lines
            .iter()
            .filter(|line| line.trim_start().starts_with("Error"))
            .collect();
        assert_eq!(
            (6, 1, 1),
            (lines.len(), messages.len(), errors.len()),
            "the rule's line, one Message line, one Error line, `ALL {{`, and the two closing braces:\n{}",
            lines.join("\n")
        );
        assert!(
            messages[0].starts_with("    Message = word; word;") && messages[0].ends_with(marker),
            "the cut custom slot is one line ending with the marker: {}",
            messages[0]
        );
        assert_eq!(
            "    Error = the key `a; b` could not be read", errors[0],
            "the error slot is one line with its break joined"
        );

        let lines = render(
            Messages {
                custom_message: Some("one; two".to_string()),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            crate::rules::CustomSlot::Evaluator,
        );
        assert!(
            lines.iter().any(|line| line.trim_start() == "Message {")
                && lines.iter().any(|line| line.trim() == "one")
                && lines.iter().any(|line| line.trim() == "two"),
            "a plain record's `;` list prints as the message block it always did:\n{}",
            lines.join("\n")
        );

        // A plain record's custom slot over the recorded-message bound: cut with the ellipsis and printed
        // as ONE `Message = ...` line, the joins of the collapse never split into items. The long run
        // carries spaces: `cut_to` backs off to the last whitespace inside the bound (`cut_to`'s
        // rule, so no word is split), and a run of 400 `z`s with no space in it would be dropped whole,
        // the line reading `a; b;...` with nothing of the run kept.
        let lines = render(
            Messages {
                custom_message: Some(format!("a; b\n{}", "z ".repeat(200))),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            crate::rules::CustomSlot::Evaluator,
        );
        let messages: Vec<&String> = lines
            .iter()
            .filter(|line| line.trim_start().starts_with("Message"))
            .collect();
        assert!(
            messages.len() == 1
                && messages[0].starts_with("    Message = a; b; z z")
                && messages[0].ends_with("...")
                && !lines.iter().any(|line| line.trim() == "b"),
            "a cut plain custom slot prints as one Message line ending with the ellipsis:\n{}",
            lines.join("\n")
        );

        // A plain record's custom slot UNDER the bound that holds a raw control: the control is escaped
        // and the message still prints as the `Message { }` block with its `;` items, since only a CUT
        // slot takes the one-line form. Read against the unescaped collapse, the escaped text differed
        // and every short plain message with a control took the one-line branch. The raw-ESC check reads
        // the lines under the header only: `pprint_clauses` colours the rule's name on its `Rule = {`
        // line, so with colour forced on that one line carries escapes of its own, which say nothing
        // about the slot.
        let lines = render(
            Messages {
                custom_message: Some("one\u{1b}[1m; two".to_string()),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            crate::rules::CustomSlot::Evaluator,
        );
        let under_the_header: Vec<&String> = lines
            .iter()
            .filter(|line| !line.trim_start().starts_with("Rule ="))
            .collect();
        assert!(
            lines.iter().any(|line| line.trim() == "two")
                && lines.iter().any(|line| line.contains("\\u{1b}[1m"))
                && !under_the_header.iter().any(|line| line.contains('\u{1b}'))
                && !lines
                    .iter()
                    .any(|line| line.trim_start().starts_with("Message = ")),
            "an uncut plain slot with a control prints as the message block, escaped:\n{}",
            lines.join("\n")
        );
    }

    /// A refusal holding a line break is one `Reason =` line, collapsed as the unattributed section
    /// collapses a sentence (`one_line`: the parts trimmed and joined by `; `), so the break cannot put a
    /// line at an indentation the author chose inside the `Check = { }` block, where a line at the block's
    /// own depth reads as one of the block's lines. The refusal is the evaluator's, its template parts
    /// escaped; a break is the one shape the escape does not cover, and the line's shape is the reporter's
    /// to hold whatever a future refusal carries. The `Error =` line is the sentence's head.
    #[test]
    fn a_refusal_holding_a_line_break_is_one_reason_line() {
        let refusal = "the key `a\nb` could not be read as the predicate asks:\n  define `X` by hand\n  then compare it";
        let out = refused_marker_finding(refusal);

        assert_eq!(RHS_HEAD, error_line(&out));
        let line = reason_line(&out);
        assert_eq!(
            "        Reason = the key `a; b` could not be read as the predicate asks:; define `X` by \
             hand; then compare it",
            line
        );
        assert_eq!(
            format!("        Reason = {}", one_line(refusal)),
            line,
            "collapsed exactly as the unattributed section collapses a sentence"
        );
        assert!(
            out.lines()
                .all(|line| line.starts_with("    ") && !line.trim_start().starts_with("define")),
            "no line of the finding is the author's second line at its own indentation:\n{}",
            out
        );
    }

    /// A refusal over `LONGEST_REFUSAL_MESSAGE` characters is printed once, on the `Reason =` line, cut
    /// at the reporter's own bound and ending with `REFUSAL_CUT_MARKER`, as the unattributed section cuts
    /// it; the `Error =` line is the sentence's head. Printed whole on the `Error =` line, such a refusal
    /// was cut inside its own text, a test of that cut line for the whole refusal failed, and the
    /// `Reason =` line printed a second cut copy: two lines of the bound each.
    #[test]
    fn a_refusal_over_the_bound_is_cut_with_the_marker_once() {
        let refusal = "word ".repeat(1000).trim_end().to_string();
        assert!(refusal.chars().count() > LONGEST_REFUSAL_MESSAGE);
        let out = refused_marker_finding(&refusal);

        assert_eq!(RHS_HEAD, error_line(&out));
        let line = reason_line(&out);
        let text = line
            .trim_start()
            .strip_prefix("Reason = ")
            .expect("the line is the `Reason =` line");
        assert!(
            text.ends_with(&format!("... {REFUSAL_CUT_MARKER}")),
            "the cut is marked, after the ellipsis: {}",
            text
        );
        assert!(
            text.chars().count()
                <= LONGEST_REFUSAL_MESSAGE + 3 + 1 + REFUSAL_CUT_MARKER.chars().count(),
            "{} characters, over the bound plus the ellipsis, a space and the marker: {}",
            text.chars().count(),
            text
        );
        assert_eq!(
            1,
            out.lines()
                .filter(|line| line.contains("word word"))
                .count(),
            "the refusal is on exactly one line of the block:\n{}",
            out
        );
        assert!(
            !out.contains(&refusal),
            "the refusal is never printed whole:\n{}",
            out
        );
    }

    /// A unary check refused over an undecidable marker has an EMPTY head (the report builder's unary
    /// arm, `report_all_failed_clauses_for_rules`): the record's sentence is `Error = [<refusal>]` alone,
    /// so the finding writes no `Error =` line of its own and the refusal once, on the `Reason =` line,
    /// where a head that wrote the bracketed refusal too printed it twice. The record is built as the
    /// builder builds it (`joined_sentence` with the unary arm's opener, no space before the bracket), so
    /// the layout read here is the one a real unary record gets; a hand-built record with a space before
    /// the opener was a sentence the builder never writes.
    #[test]
    fn a_unary_refusals_empty_head_writes_the_refusal_once_on_the_reason_line() {
        let (error_message, parts) = crate::rules::eval_context::joined_sentence(
            "",
            Some(&REFUSAL.to_string()),
            "Error = [",
        );
        assert_eq!(
            format!("Error = [{REFUSAL}]"),
            error_message,
            "the builder's unary sentence opens with the bracket"
        );
        let messages = Messages {
            custom_message: Some(String::new()),
            error_message: Some(error_message),
            location: None,
            refusal: true,
            parts,
        };
        let out = finding_of(
            "Resources[ Cfg[*].Limits exists ] !empty",
            messages,
            &unresolved(
                REFUSAL,
                "",
                UnResolvedKind::Undecidable {
                    refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                    carried: None,
                },
            ),
        );
        assert!(
            out.lines()
                .all(|line| !line.trim_start().starts_with("Error = ")),
            "no `Error =` line for an empty head:\n{}",
            out
        );
        assert_eq!(
            format!("        Reason = {}", one_line(REFUSAL)),
            reason_line(&out)
        );
        assert_eq!(
            1,
            out.matches(REFUSAL).count(),
            "the refusal is printed once:\n{}",
            out
        );
    }

    /// The whole block as written, the lines joined with their line feeds and the trailing one.
    fn block(lines: &[String]) -> String {
        lines.iter().fold(String::new(), |mut whole, line| {
            whole.push_str(line);
            whole.push('\n');
            whole
        })
    }

    /// Every refusal-bearing block names its field once and carries the refusal once: one `Error =` on
    /// the block's own line and none nested inside it, the refusal's text on one line of the block.
    fn once(out: &str) {
        assert_eq!(
            1,
            out.matches("Error = ").count(),
            "one `Error =`:\n{}",
            out
        );
        assert_eq!(
            1,
            out.lines().filter(|line| line.contains(REFUSAL)).count(),
            "the refusal on one line:\n{}",
            out
        );
    }

    /// A right-hand refused marker's record (`X IN %x` with the marker among listed keys, `X` accepted by
    /// none): the record's message is the refusal, which is the unresolved value's reason, so the block is
    /// the `Check = { }` block with the sentence's head on its `Error =` line and the refusal, once, on
    /// its `Reason =` line, each bounded on its own; no second `Error =` is nested in the first. Written
    /// as recorded, the line read `Error = ... Error = [<refusal>]` and the `Reason =` line repeated the
    /// refusal; printed opened and whole on the `Error =` line, a refusal over the bound was cut inside
    /// its text and a second cut copy followed on `Reason =`.
    #[test]
    fn a_right_hand_refused_markers_block_names_the_refusal_once() {
        let vur = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let out = finding(RHS_CONTEXT, RHS_HEAD_TEXT, Some(REFUSAL), true, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {RHS_CONTEXT} {{"),
                RHS_HEAD.to_string(),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        once(&out);
    }

    /// A left-hand refused marker's record (`%x == 'k'` with the marker in `%x`, no marker on the right):
    /// the record carries the refusal's own text as its message, the sentence names the value compared
    /// from as unread, and the block is the right-hand one's shape: the head on `Error =`, the refusal
    /// once on `Reason =`.
    #[test]
    fn a_left_hand_refused_markers_block_names_the_refusal_once() {
        let vur = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let out = finding(LHS_CONTEXT, LHS_HEAD_TEXT, Some(REFUSAL), true, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {LHS_CONTEXT} {{"),
                LHS_HEAD.to_string(),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        once(&out);
    }

    /// The record of a left-hand refused marker beside an absence is split by the console on the
    /// marker's reason (`refusal_lines` strips `: <reason>` off the message's end): the evaluator writes
    /// that reason into the record ESCAPED and never cut (`absence_beside_a_marker`), the record's
    /// unresolved value STORES it as its builder wrote it, byte for byte (the registry matches a stored
    /// reason by exact text), and the console strips and prints the escaped form
    /// (`escaped_controls_for_display`, idempotent), so the two meet whatever the stored bytes hold: a
    /// refusal of about three thousand characters (rules-file text quoted as written runs past any lead
    /// net) prints whole on `Reason =` and nowhere cut, and a refusal that holds a RAW line break and a
    /// raw ESC, stored raw as the evaluator stores it, prints on one `Reason =` line through the console's
    /// one pipeline (`reason_backstop`: the break collapsed to `; ` first, then the ESC as its
    /// escape) and no raw control. A net on the marker's text at the record changed the
    /// message's end, the split missed, the `Reason =` line vanished and the refusal printed on
    /// `Error =` under the net's cut; a console that stripped the raw stored bytes off an escaped record
    /// missed the same way for a reason holding a control.
    #[test]
    fn a_left_hand_refused_markers_long_or_broken_reason_prints_whole_on_its_reason_line() {
        const CONTEXT: &str = "%x != Resources.R.Properties.Cfg.Missing";
        let absent = unresolved(RETRIEVAL_REASON, "Missing", UnResolvedKind::Absent).value;
        let long = format!("{REFUSAL}{}", " and more".repeat(320));
        assert!(long.chars().count() > 2500 && long.chars().count() < 4096);
        // Stored as the evaluator stores a reason, the controls raw; printed through the console's one
        // pipeline, the break as `; ` and the ESC as its escape (`reason_backstop`'s order; an
        // earlier cut of this cell expected the break escaped as `\n`, the order before the pipeline).
        let broken = format!("{REFUSAL}\nthe remedy on a second line \u{1b}[0m");
        let broken_displayed =
            crate::utils::writer::escaped_controls_for_display(&one_line(&broken));
        assert!(
            !broken_displayed.contains('\n')
                && !broken_displayed.contains("\\n")
                && !broken_displayed.contains('\u{1b}')
                && broken_displayed.contains("; the remedy")
        );
        for (label, reason, on_the_reason_line) in [
            (
                "a refusal of about three thousand characters",
                long.clone(),
                long.clone(),
            ),
            (
                "a refusal holding a raw line break and a raw ESC, stored raw",
                broken.clone(),
                broken_displayed.clone(),
            ),
        ] {
            let vur = unresolved(
                &reason,
                "",
                UnResolvedKind::Undecidable {
                    refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                    carried: None,
                },
            );
            // Two record shapes: the message ENDING with the reason (the absence's lead before it), and
            // the message that IS the reason (a left-hand refused marker against a present value).
            let ending_with = left_marker_beside_an_absence(&reason, absent.reason.as_deref());
            for message in [ending_with, reason.clone()] {
                let out = finding_of(CONTEXT, record(LHS_HEAD_TEXT, Some(&message), true), &vur);
                assert!(
                    out.lines().any(
                        |line| line.contains("Reason = ") && line.contains(&on_the_reason_line)
                    ),
                    "{label}: the `Reason =` line carries the refusal whole:\n{}",
                    out
                );
                assert!(
                    !out.contains("more characters cut]"),
                    "{label}: nothing is cut:\n{}",
                    out
                );
                assert!(
                    !out.contains('\u{1b}'),
                    "{label}: no raw control reaches the console:\n{}",
                    out.escape_debug()
                );
                assert_eq!(
                    1,
                    out.matches(REFUSAL).count(),
                    "{label}: the refusal's head is printed once, on its own line:\n{}",
                    out
                );
            }
        }
    }

    /// The record of a left-hand refused marker beside a right-hand value the document lacks, built as
    /// the evaluator and the report build it rather than from a hand-written copy of the text: the
    /// message by the evaluator's own writer (`left_marker_beside_an_absence`: the absence's lead, named
    /// with its side, then the marker's reason), and the report by the REPORT BUILDER itself
    /// (`report_all_failed_clauses_for_rules`, over the evaluator's record), which puts the head of the
    /// shared sentence builder (`unresolved_comparison_sentence`: the refused left-hand read first), the
    /// sentence and its parts, the record's kind and the absent right-hand value as the value compared
    /// with into the clause report the console reads. The block prints the head and the lead on `Error
    /// =`, the refusal once on `Reason =` inside the marker's own block, and then the compared-with operand
    /// as a `ComparedWith` block of its own: the absent value's path and the key the document lacks.
    /// Before, the block printed the marker's lines alone, so a reader saw the right key named in the
    /// `Error =` line's prose and no line that said where in the document it was missed; the cell beside
    /// this one hand-builds its sentence, so a builder that changed its head would not have moved it; and
    /// this cell once hand-built the report's `Messages` and `ValueUnResolved` from the builder's pieces,
    /// so a builder that stopped carrying the compared-with value would have left it green.
    #[test]
    fn a_left_hand_refused_marker_beside_an_absence_prints_the_compared_with_operand() {
        const CONTEXT: &str = "%x != Resources.R.Properties.Cfg.Missing";
        let marker = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        )
        .value;
        let absent = unresolved(RETRIEVAL_REASON, "Missing", UnResolvedKind::Absent).value;
        let message = left_marker_beside_an_absence(REFUSAL, absent.reason.as_deref());
        let record = EventRecord {
            context: CONTEXT.to_string(),
            container: Some(RecordType::ClauseValueCheck(ClauseCheck::Comparison(
                ComparisonClauseCheck {
                    comparison: (CmpOperator::Eq, true),
                    from: QueryResult::UnResolved(marker.clone()),
                    to: Some(QueryResult::UnResolved(absent.clone())),
                    message: Some(message.clone()),
                    custom_message: None,
                    status: Status::FAIL,
                    refusal: true,
                },
            ))),
            children: vec![],
        };
        let clauses = report_all_failed_clauses_for_rules(&[record]);
        let (messages, vur) = match clauses.as_slice() {
            [ClauseReport::Clause(GuardClauseReport::Binary(BinaryReport {
                messages,
                check: BinaryCheck::UnResolved(vur),
                ..
            }))] => (messages.clone(), vur.clone()),
            other => panic!(
                "one binary clause report for one record, got {} report(s)",
                other.len()
            ),
        };
        assert!(messages.refusal, "the report keeps the record's kind");
        let head = messages
            .parts
            .as_ref()
            .map(|parts| parts.head.as_str())
            .unwrap_or_default();
        assert_eq!(
            LHS_HEAD_TEXT, head,
            "the builder names the refused left-hand read first"
        );
        assert_eq!(
            Some(marker.traversed_to.self_path().1),
            messages.location,
            "and the operand the builder names (the record's location) is the marker's"
        );
        // The marker and the absent operand are built at one node, so the location alone cannot tell
        // them apart: the operand the report carries is the MARKER by its own fields, the refusal's kind
        // and no query left to walk, where the absent operand carries `Missing` and the `Absent` kind.
        assert!(
            vur.value.remaining_query.is_empty() && vur.value.kind.is_refusal(),
            "the report's unresolved operand is the refused marker (no remaining query, the refusal's kind), not the absent value: {:?}",
            vur.value
        );
        assert_eq!(
            Some("Missing"),
            vur.to.as_ref().map(|to| to.remaining_query.as_str()),
            "the report carries the absent right-hand value as the value compared with"
        );
        let out = finding_of(CONTEXT, messages, &vur);
        let lead = message
            .strip_suffix(&format!(": {REFUSAL}"))
            .expect("the evaluator's message ends with the marker's reason");
        assert!(
            lead.starts_with(&format!(
                "The right-hand value is absent: {RETRIEVAL_REASON}"
            )),
            "the lead names the right side and the retrieval's reason:\n{}",
            lead
        );
        assert_eq!(
            block(&[
                format!("    Check = {CONTEXT} {{"),
                format!("{LHS_HEAD} {lead}:"),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "      ComparedWith {".to_string(),
                format!("        PropertyPath = {}", absent.traversed_to.self_path()),
                "        MissingProperty = Missing".to_string(),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        once(&out);
    }

    /// A left-hand refused marker's record beside a right-hand value the document lacks (`%x !=
    /// Cfg.Mode.Ref.Missing` with the marker in `%x`): the record's message is the absence's lead, the
    /// retrieval's own reason cut and control-escaped (the backslash kept) as the evaluator writes it,
    /// then the marker's reason,
    /// so the tail ends with the unresolved value's reason. The block prints the head and the lead on
    /// `Error =` and the refusal, once, on `Reason =`. Printed opened and whole on the `Error =` line, the
    /// refusal sat at the end of a line whose length the lead decided. The record is hand-built here with
    /// no `to`, so no `ComparedWith` block follows the marker's; the cell above builds the same shape
    /// through the evaluator's writer and the report's builder, `to` included.
    #[test]
    fn a_left_hand_refused_marker_beside_an_absence_prints_the_refusal_on_the_reason_line() {
        let vur = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let lead =
            "Attempting to retrieve from key Missing but type is not an struct type at path \
                    /Resources/R/Properties/Cfg/Mode/Ref, Type = String, Value = ModeParam";
        let message = format!(
            "{lead} A refused or undecided selection stands among the left-hand values, reported here \
             so it is not silent: {REFUSAL}"
        );
        let out = finding(
            "%x != Resources.R.Properties.Cfg.Mode.Ref.Missing",
            LHS_HEAD_TEXT,
            Some(&message),
            true,
            &vur,
        );
        assert_eq!(
            block(&[
                "    Check = %x != Resources.R.Properties.Cfg.Mode.Ref.Missing {".to_string(),
                format!(
                    "{LHS_HEAD} {lead} A refused or undecided selection stands among the left-hand \
                     values, reported here so it is not silent:"
                ),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        once(&out);
    }

    /// A refusal record whose sentence has no bracketed tail, and whose reason holds a line break (a
    /// refusal the evaluator wrote nowhere into the sentence): the sentence is printed bounded on
    /// `Error =` and the reason bounded and collapsed on `Reason =`, because the record is a refusal's,
    /// whatever the sentence holds. A reason written raw there put its second line inside the block at
    /// the author's indentation.
    #[test]
    fn a_refusal_record_with_no_tail_prints_its_reason_bounded_on_the_reason_line() {
        let refusal =
            "the key `a\nb` could not be read as the predicate asks:\n  define `X` by hand";
        let vur = unresolved(
            refusal,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let sentence =
            "Check was not compliant as property [Ref] is missing. Value traversed to [{}].";
        let out = finding(RHS_CONTEXT, sentence, None, true, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {RHS_CONTEXT} {{"),
                format!("      Error = {sentence}"),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {}", one_line(refusal)),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        assert!(
            out.lines()
                .all(|line| line.starts_with("    ") && !line.trim_start().starts_with("define")),
            "no line of the block is the author's second line at its own indentation:\n{}",
            out
        );
    }

    /// An absent value's record beside a refused read whose traversed-to value holds `Error = [` itself
    /// (a `Note` property quoting documentation): the tail is found by the record's own reason, from the
    /// right, so the value stays in the head where the evaluator put it and the block prints the sentence
    /// opened and whole on `Error =`, the refusal once. A split at the first `Error = [` landed inside the
    /// value and printed the tail twice over.
    #[test]
    fn a_template_value_holding_the_tails_opener_stays_in_the_head() {
        let vur = unresolved(RETRIEVAL_REASON, "Missing", UnResolvedKind::Absent);
        let value = r#"{"Note":"see Error = [docs]","Mode":"fast"}"#;
        let message = format!(
            "{RETRIEVAL_REASON} A refused or undecided selection stands among the right-hand values, \
             reported here so it is not silent: {REFUSAL}"
        );
        let head = format!(
            "Check was not compliant as property [Missing] to compare from is missing. Value \
             traversed to [{value}]."
        );
        let out = finding(ABSENCE_CONTEXT, &head, Some(&message), true, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {ABSENCE_CONTEXT} {{"),
                format!("      Error = {head} {message}"),
                "      RequiredPropertyError {".to_string(),
                property_path_line(&vur),
                "        MissingProperty = Missing".to_string(),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        assert_eq!(
            1,
            out.lines().filter(|line| line.contains(REFUSAL)).count(),
            "the refusal on one line:\n{}",
            out
        );
    }

    /// An absent value's record beside a refused read whose sentence does not fit the bound (a
    /// traversed-to value the evaluator did not bound): the head is printed bounded on `Error =`, cut
    /// with the marker, and the tail, the retrieval's reason leading and the refusal after it, bounded on
    /// `Reason =`, so the refusal is printed once and never cut away. Printed opened on one line, the cut
    /// fell before the refusal and a `Reason =` line restated the retrieval's reason alone: the refusal
    /// was shown nowhere in the block.
    #[test]
    fn an_absent_values_block_that_does_not_fit_prints_its_tail_on_the_reason_line() {
        let vur = unresolved(RETRIEVAL_REASON, "Missing", UnResolvedKind::Absent);
        let message = format!(
            "{RETRIEVAL_REASON} A refused or undecided selection stands among the right-hand values, \
             reported here so it is not silent: {REFUSAL}"
        );
        let head = format!(
            "Check was not compliant as property [Missing] to compare from is missing. Value \
             traversed to [{}].",
            "y".repeat(5000)
        );
        let out = finding(ABSENCE_CONTEXT, &head, Some(&message), true, &vur);
        assert_eq!(format!("        Reason = {message}"), reason_line(&out));
        let error = error_line(&out);
        assert!(
            error.ends_with(REFUSAL_CUT_MARKER) && !error.contains(REFUSAL),
            "the `Error =` line is the head, cut at the bound before the tail:\n{}",
            error
        );
        once(&out);
    }

    /// A refused marker's record whose sentence leads with a long template value: the head is cut at the
    /// bound on the `Error =` line and the refusal is the `Reason =` line, whole, its one appearance in
    /// the block, the layout decided from the record and not from what the cut left. Decided on the
    /// recorded sentence, the `Reason =` line was left out because the recorded message was the reason,
    /// and the block printed the refusal zero times. The control, the same record with a short lead,
    /// prints the same two lines, the head whole.
    #[test]
    fn a_refusal_the_cut_dropped_from_the_error_line_is_printed_on_the_reason_line() {
        let vur = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let lead = format!(
            "Check was not compliant as the value to compare from could not be read. Value traversed to \
             [{}].",
            "y".repeat(5000)
        );
        let out = finding(LHS_CONTEXT, &lead, Some(REFUSAL), true, &vur);
        let carrying: Vec<&str> = out.lines().filter(|l| l.contains(REFUSAL)).collect();
        assert_eq!(
            vec![format!("        Reason = {REFUSAL}")],
            carrying,
            "the refusal is on one line of the block, the `Reason =` line:\n{}",
            out
        );
        let error = error_line(&out);
        assert!(
            error.ends_with(REFUSAL_CUT_MARKER) && !error.contains(REFUSAL),
            "the `Error =` line is cut at the bound before the refusal:\n{}",
            error
        );
        assert_eq!(1, out.matches("Error = ").count(), "{}", out);

        let out = finding(LHS_CONTEXT, LHS_HEAD_TEXT, Some(REFUSAL), true, &vur);
        assert_eq!(
            LHS_HEAD,
            error_line(&out),
            "with a short lead the head is printed whole:\n{}",
            out
        );
        assert_eq!(
            format!("        Reason = {REFUSAL}"),
            reason_line(&out),
            "and the refusal is the `Reason =` line, as with the long lead:\n{}",
            out
        );
    }

    /// An absent value's record beside a refused read (`Cfg.Missing == %x` with the marker in `%x`): the
    /// record's reason is the retrieval's own and its message leads with that reason before the
    /// refusal, so the `Error =` line is the sentence with the message after it, opened, and already
    /// carries the reason; the `RequiredPropertyError` block keeps its `MissingProperty` line and prints
    /// no `Reason =` line, which would restate the reason the line above carries. Written as recorded,
    /// the `Error =` line nested a second `Error = [...]` and the `Reason =` line printed the reason a
    /// second time. The control, a plain absent value with no refusal beside it, prints the block as
    /// released: no `Error =` line, the `Reason =` line.
    #[test]
    fn an_absent_values_block_beside_a_refusal_opens_its_sentence_and_prints_its_reason_once() {
        let vur = unresolved(RETRIEVAL_REASON, "Missing", UnResolvedKind::Absent);
        let message = format!(
            "{RETRIEVAL_REASON} A refused or undecided selection stands among the right-hand values, \
             reported here so it is not silent: {REFUSAL}"
        );
        let head =
            "Check was not compliant as property [Missing] to compare from is missing. Value \
                    traversed to [{}].";
        let out = finding(ABSENCE_CONTEXT, head, Some(&message), true, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {ABSENCE_CONTEXT} {{"),
                format!("      Error = {head} {message}"),
                "      RequiredPropertyError {".to_string(),
                property_path_line(&vur),
                "        MissingProperty = Missing".to_string(),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        once(&out);
        assert_eq!(
            1,
            out.matches(RETRIEVAL_REASON).count(),
            "the retrieval's reason is printed once, as the lead of the opened message:\n{}",
            out
        );

        let out = finding(ABSENCE_CONTEXT, head, None, false, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {ABSENCE_CONTEXT} {{"),
                "      RequiredPropertyError {".to_string(),
                property_path_line(&vur),
                "        MissingProperty = Missing".to_string(),
                format!("        Reason = {RETRIEVAL_REASON}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out,
            "a record that is no refusal's prints its reason and no sentence"
        );
    }

    /// A left-hand refused marker's record beside an absent right-hand value whose head quotes a
    /// template value holding `Error = [` (the right-hand side's missing-property sentence, its
    /// traversed-to value a `Note` quoting documentation): the layout is read from the record's parts,
    /// so the value stays in the head where the report builder put it, the lead follows the head on
    /// `Error =`, and the refusal is the `Reason =` line. Read by splitting the recorded sentence at its
    /// first `Error = [`, the split landed inside the value: the head was cut short and the value's tail,
    /// the opener inside it, was joined to the lead.
    #[test]
    fn a_template_value_holding_the_tails_opener_stays_in_the_head_beside_a_left_marker() {
        let vur = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let head = r#"Check was not compliant as property [Missing] to compare to is missing. Value traversed to [{"Note":"see Error = [docs]"}]."#;
        let lead =
            "Attempting to retrieve from key Missing but type is not an struct type at path \
                    /Resources/R/Properties/Cfg/Mode/Ref";
        let message = format!(
            "{lead} A refused or undecided selection stands among the left-hand values, reported here \
             so it is not silent: {REFUSAL}"
        );
        let out = finding(
            "%x != Resources.R.Properties.Cfg.Mode.Ref.Missing",
            head,
            Some(&message),
            true,
            &vur,
        );
        assert_eq!(
            block(&[
                "    Check = %x != Resources.R.Properties.Cfg.Mode.Ref.Missing {".to_string(),
                format!(
                    "      Error = {head} {lead} A refused or undecided selection stands among the \
                     left-hand values, reported here so it is not silent:"
                ),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        assert_eq!(
            1,
            out.lines().filter(|line| line.contains(REFUSAL)).count(),
            "the refusal on one line:\n{}",
            out
        );
    }

    /// A refusal record with no parts (a producer that set none, a report read back from its serialized
    /// form) falls back to the sentence as recorded: bounded on `Error =`, the bracketed tail as it was
    /// written, and the reason bounded on `Reason =`. The parts are what let the console open the tail;
    /// without them it prints what it has and parses nothing.
    #[test]
    fn a_refusal_record_with_no_parts_prints_its_sentence_as_recorded() {
        let vur = unresolved(
            REFUSAL,
            "",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let sentence = format!("{RHS_HEAD_TEXT} Error = [{REFUSAL}]");
        let messages = Messages {
            custom_message: Some(String::new()),
            error_message: Some(sentence.clone()),
            location: None,
            refusal: true,
            parts: None,
        };
        let out = finding_of(RHS_CONTEXT, messages, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {RHS_CONTEXT} {{"),
                format!("      Error = {sentence}"),
                "      NoAnswerError {".to_string(),
                property_path_line(&vur),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
    }

    /// The message the evaluator writes for an absent value beside a refused read: the retrieval's
    /// reason as its lead, the template value it quotes (the text after `Value = `) bounded where the
    /// retrieval wrote it (`marker_part`: cut at the part bound, controls escaped, the backslash kept),
    /// the key and the path whole, then the refusal.
    fn absence_message(reason: &str, side: &str) -> String {
        let lead = match reason.split_once("Value = ") {
            Some((prefix, value)) => format!("{prefix}Value = {}", marker_part(value)),
            None => reason.to_string(),
        };
        format!(
            "{lead} A refused or undecided selection stands among the {side}-hand values, reported \
             here so it is not silent: {REFUSAL}"
        )
    }

    /// The block of an absent value beside a refused read whose lead is `reason`, with the refusal
    /// once on its `Error =` line and no `Reason =` line: the asserted shape of the three cells below.
    fn absence_block_once(reason: &str) -> String {
        let vur = unresolved(reason, "Missing", UnResolvedKind::Absent);
        let head =
            "Check was not compliant as property [Missing] to compare from is missing. Value \
                    traversed to [{}].";
        let message = absence_message(reason, "right");
        let out = finding(ABSENCE_CONTEXT, head, Some(&message), true, &vur);
        assert_eq!(
            block(&[
                format!("    Check = {ABSENCE_CONTEXT} {{"),
                format!("      Error = {head} {message}"),
                "      RequiredPropertyError {".to_string(),
                property_path_line(&vur),
                "        MissingProperty = Missing".to_string(),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        assert!(
            !out.contains("Error = ["),
            "no nested `Error = [` on the console:\n{}",
            out
        );
        once(&out);
        out
    }

    /// An absent value beside a refused read whose retrieval reason runs past the template-part bound (a
    /// path of about 330 characters, kept whole by the evaluator): the lead is the reason as written, and
    /// the block prints the sentence with the lead and the refusal once on `Error =`, no nested
    /// `Error = [`, no `Reason =` line. Laid out by rebuilding the lead as a bounded template part and
    /// anchoring on it, the rebuilt text was cut at 256 characters, missed, and the block fell to the
    /// recorded sentence, its nested opener inside, with the reason printed again on `Reason =`.
    #[test]
    fn an_absent_values_block_with_a_long_path_lead_prints_the_refusal_once() {
        let reason = format!(
            "Could not find key Missing inside struct at path /Resources/R/Properties/{}Deep",
            "Cfg/".repeat(80)
        );
        assert!(reason.chars().count() > 256);
        let out = absence_block_once(&reason);
        assert_eq!(
            1,
            out.matches(&reason).count(),
            "the whole reason, its path included, is printed once:\n{}",
            out
        );
    }

    /// An absent value beside a refused read whose key holds a backslash: the evaluator's lead keeps the
    /// key as written (only a quoted value is escaped), and the block prints it as written with the
    /// refusal once, no nested `Error = [`, no `Reason =` line. Laid out by anchoring on an escaped
    /// rebuild of the reason, the rebuilt text carried the backslash's escape, missed, and the block
    /// fell to the recorded sentence.
    #[test]
    fn an_absent_values_block_with_a_backslash_in_the_key_prints_the_refusal_once() {
        let reason =
            r"Could not find key C:\Temp inside struct at path /Resources/R/Properties/Cfg";
        let out = absence_block_once(reason);
        assert_eq!(1, out.matches(reason).count(), "{}", out);
        assert!(
            !out.contains(r"C:\\Temp"),
            "the key is printed as written, not escaped twice:\n{}",
            out
        );
    }

    /// The mirror of the long-string cell for an absent value beside a refused read: a key read off a
    /// 5000-character string, whose retrieval reason quotes the whole string after `Value = `. The
    /// evaluator's lead cuts that value at the template-part bound with a marker; the block prints the
    /// sentence with the cut lead and the refusal once on `Error =`, the string never whole, no nested
    /// `Error = [`, no `Reason =` line. Laid out by anchoring on a rebuild cut at 256 characters of the
    /// WHOLE reason, the block fell to the recorded sentence and printed the raw reason, up to 4096
    /// characters of the string, on `Reason =`.
    #[test]
    fn an_absent_values_block_with_a_long_quoted_value_prints_the_refusal_once() {
        let value = "y".repeat(5000);
        let reason = format!(
            "Attempting to retrieve from key Missing but type is not an struct type at path \
             /Resources/R/Properties/Cfg/Mode/Ref, Type = String, Value = {value:?}"
        );
        let out = absence_block_once(&reason);
        assert!(
            !out.contains(&value) && out.contains(" more characters cut]"),
            "the quoted value is printed cut with the evaluator's marker, never whole:\n{}",
            out
        );
        assert!(
            out.lines().all(|line| line.chars().count() < 1024),
            "no line of the block carries the value:\n{}",
            out
        );
    }

    /// A unary check refused over a value the document lacks: the report builder joins its sentence with
    /// no space before `Error = [`, unlike the comparison arms, and the record carries the parts all the
    /// same, so the block is laid out from them: the head on `Error =`, the refusal once on `Reason =`.
    /// Laid out by anchoring on the comparison arms' ` Error = [`, the unary sentence matched nothing and
    /// kept its nested opener on the console.
    #[test]
    fn a_unary_refusal_record_prints_its_head_and_its_refusal_once() {
        let vur = unresolved(
            REFUSAL,
            "Ref",
            UnResolvedKind::Undecidable {
                refusal: Some(crate::rules::errors::RefusalToken::minted(1)),
                carried: None,
            },
        );
        let head = "Check was not compliant as property [Ref] is missing. Value traversed to [{}].";
        let messages = Messages {
            custom_message: Some(String::new()),
            error_message: Some(format!("{head}Error = [{REFUSAL}]")),
            location: None,
            refusal: true,
            parts: Some(SentenceParts {
                head: head.to_string(),
                message: REFUSAL.to_string(),
            }),
        };
        let out = finding_of("%x exists", messages, &vur);
        assert_eq!(
            block(&[
                "    Check = %x exists {".to_string(),
                format!("      Error = {head}"),
                "      RequiredPropertyError {".to_string(),
                property_path_line(&vur),
                "        MissingProperty = Ref".to_string(),
                format!("        Reason = {REFUSAL}"),
                "      }".to_string(),
                "    }".to_string(),
            ]),
            out
        );
        once(&out);
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
        explanation_of, plain_author_message, rule_line_texts, LONGEST_RECORDED_MESSAGE,
        LONGEST_REFUSAL_MESSAGE, REFUSAL_CUT_MARKER,
    };
    use crate::rules::errors::Error;
    use crate::rules::eval_context::{is_refusal, refuse, root_scope_for, Messages, RuleReport};
    use crate::rules::exprs::RulesFile;
    use crate::rules::path_value::PathAwareValue;
    use crate::rules::CustomSlot;
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
            parts: None,
        }
    }

    /// The evaluator's message with the record's word that it embeds a refusal.
    fn refusal(error: &str) -> Messages {
        Messages {
            refusal: true,
            ..messages("", error)
        }
    }

    /// The author's `<< >>` message text prints a zero-width joiner and a right-to-left mark as typed on the
    /// one-line form (`plain_author_message`) as it does on a clause's `Message =` line, and a zero-width
    /// space is escaped. An evaluator's sentence or a reason is not the author's prose: it quotes keys from
    /// the rules file and the template, so `reason_backstop` writes the same joiner as its escape (the
    /// strict set, one text with the record that stores it).
    ///
    /// Expected, not yet run. Red: the author's joiner or mark is written as `\u{200d}` or `\u{200f}`, the
    /// zero-width space is written raw, or the reason keeps the joiner raw.
    #[test]
    fn the_authors_prose_keeps_joiners_as_typed_and_a_reason_escapes_them() {
        let typed = format!("owner{}tag{}x", '\u{200D}', '\u{200F}');
        assert_eq!((typed.clone(), false), plain_author_message(&typed));
        assert_eq!(
            format!("a\\u{{200b}}b"),
            plain_author_message("a\u{200B}b").0,
            "a zero-width space stays escaped"
        );
        assert_eq!(
            "owner\\u{200d}tag\\u{200f}x",
            super::reason_backstop(&typed, "..."),
            "a reason is written by the strict set"
        );
    }

    /// The unattributed section's entry for a refusal record takes the console's one refusal pipeline
    /// (`bounded_for_the_console` through `reason_backstop`): a raw line break in the evaluator's half
    /// is joined as `; ` and a raw ESC is written as its escape after it, as the per-resource arms print
    /// the same record. Bounded with no escape, the section printed the control raw. The author's half
    /// is no refusal's and keeps its own cap; this cell pins the evaluator's half alone.
    #[test]
    fn a_refusals_explanation_in_the_section_is_collapsed_and_escaped() {
        let line = explanation_of(&refusal(
            "the key `\u{1b}[31ma\nb\u{1b}[0m` could not be read",
        ));

        assert_eq!(
            "the key `\\u{1b}[31ma; b\\u{1b}[0m` could not be read",
            line
        );
        assert!(!line.contains('\u{1b}'), "no raw ESC reaches the section");
    }

    /// A refusal's sentence followed by `; ` and a converter's cause cut to a template part (the shape a
    /// held error takes when a refusal that came with a token and no registered text arrives after it,
    /// joined and registered under the token) reads as a refusal in the evaluator (`is_refusal`: the joined
    /// text is registered), so the record carries the refusal flag and the section prints the joined text
    /// whole under `LONGEST_REFUSAL_MESSAGE`, past `LONGEST_RECORDED_MESSAGE`, with the refusal's sentence
    /// first and intact. The same text under a record that does not say it is a refusal's is cut at
    /// `LONGEST_RECORDED_MESSAGE`, inside the refusal's sentence: what the registration and the sentence
    /// leading the cause prevent. The `-o json` report carries the text whole either way and no flag
    /// (`Messages::refusal` is not serialized), so the section's reading of the flag is the one the text
    /// depends on.
    ///
    /// Expected, not yet run. Red: the joined text is not registered (`is_refusal` false), the section
    /// prints it cut mid-sentence under the refusal flag, or the plain-flag copy is not cut at the plain
    /// bound.
    #[test]
    fn a_refusal_sentence_joined_to_a_cut_cause_is_printed_whole_and_flagged() {
        let held = format!(
            "failed to convert a string: {} into an int",
            "9".repeat(2000)
        );
        let sentence = format!(
            "the read of `X` is refused: {}",
            "word ".repeat(80).trim_end()
        );
        // The registry registers under a live root scope only, so the cell holds one for its span.
        let scope_rules =
            RulesFile::try_from("rule r { Resources exists }").expect("one rule parses");
        let _scope = root_scope_for(
            &scope_rules,
            Rc::new(PathAwareValue::try_from("{ Resources: { A: 1 } }").expect("one map parses")),
            None,
        );
        // The join is built by the evaluator (`with_the_refusal_named`), which registers it under the
        // token: the sentence no one registered leads the held cause, cut to a part.
        let joined_error = crate::rules::eval::the_join_for_a_reporter_cell(
            Error::Unevaluatable(held),
            sentence.clone(),
            Some(crate::rules::errors::RefusalToken::minted(1)),
        );
        let joined = match &joined_error {
            Error::Unevaluatable(text) => text.clone(),
            other => panic!("the join keeps the held error's variant: {}", other),
        };
        assert!(
            joined.starts_with(&format!("{sentence}; failed to convert a string: ")),
            "the sentence leads and the cause follows it: {:?}",
            joined
        );
        assert!(
            joined.chars().count() > LONGEST_RECORDED_MESSAGE,
            "the joined text is longer than the plain bound"
        );
        assert!(
            joined.chars().count() < LONGEST_REFUSAL_MESSAGE,
            "the joined text is under the refusal bound"
        );
        assert!(
            is_refusal(&joined_error),
            "the evaluator registered the join, so it reads as a refusal's"
        );

        let flagged = explanation_of(&refusal(&joined));
        assert_eq!(
            joined, flagged,
            "printed whole, the refusal's sentence first and intact"
        );
        assert!(flagged.starts_with(sentence.as_str()));

        let unflagged = explanation_of(&messages("", &joined));
        assert!(
            unflagged.ends_with("..."),
            "a record that does not say refusal is cut at the plain bound"
        );
        assert!(!unflagged.contains(sentence.as_str()));
    }

    /// A message that is no refusal's takes the same collapse, escape and cut in the section as in the
    /// rule's own record under a resource (`plain_author_message` for the author's text and
    /// `plain_evaluator_message` for the evaluator's, read by `rule_line_texts` and by
    /// `bounded_for_the_console`): an author's `<< >>` text and a plain error half with a raw ESC in each
    /// are written as their escapes, the rule record's custom slot reads as the section reads the same
    /// text, and a cut that would end inside an escape ends before it. An ESC alone cannot tell the
    /// relaxed set from the strict one (both write it as an escape), so a zero-width joiner row follows:
    /// the section's author half keeps it as typed, the rule record's slot keeps it for the author's
    /// origin and escapes it for the evaluator's (the record-level routing is pinned by
    /// `a_rule_records_slot_takes_the_escape_set_of_whose_text_it_holds`). The ESC is built with
    /// `char::from`, since the source holds no raw control.
    ///
    /// Expected, not yet run. Red: the section prints the ESC raw (an uncut message was passed through
    /// the cutter alone), the two readings of the rule record's slot differ, the joiner row reads a set
    /// other than the origin's, or the cut leaves `\u{` at the end of the line.
    #[test]
    fn a_plain_explanation_in_the_section_is_escaped_as_the_rule_record_under_a_resource_is() {
        let esc = char::from(0x1b);
        let author = format!("<< {esc}[31mred{esc}[0m >>");
        let error = format!("failed at {esc}[1mpath{esc}[0m");
        let line = explanation_of(&messages(&author, &error));
        assert_eq!(
            "<< \\u{1b}[31mred\\u{1b}[0m >> failed at \\u{1b}[1mpath\\u{1b}[0m",
            line
        );
        assert!(!line.contains(esc), "no raw ESC reaches the section");

        let record = Messages {
            custom_message: Some(author.clone()),
            ..Messages::default()
        };
        let (under_a_resource, _, _) = rule_line_texts(&RuleReport {
            messages: record,
            custom_slot: CustomSlot::Author,
            ..Default::default()
        });
        assert_eq!(
            "<< \\u{1b}[31mred\\u{1b}[0m >>", under_a_resource,
            "the rule record's custom slot reads as the section reads the same text"
        );

        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let typed = format!("owner{joiner}tag");
        let slot_of = |custom_slot: CustomSlot| RuleReport {
            messages: Messages {
                custom_message: Some(typed.clone()),
                ..Messages::default()
            },
            custom_slot,
            ..Default::default()
        };
        assert_eq!(
            typed,
            explanation_of(&messages(&typed, "")),
            "the section's author half keeps the joiner as typed"
        );
        assert_eq!(
            typed,
            rule_line_texts(&slot_of(CustomSlot::Author)).0,
            "the rule record's slot keeps it for the author's origin"
        );
        assert_eq!(
            "owner\\u{200d}tag",
            rule_line_texts(&slot_of(CustomSlot::Evaluator)).0,
            "and escapes it for the evaluator's"
        );

        let bound = LONGEST_RECORDED_MESSAGE;
        let split = format!("{}{esc}[1m", "y".repeat(bound - 3));
        assert_eq!(
            (format!("{}...", "y".repeat(bound - 3)), true),
            plain_author_message(&split),
            "a cut inside an escape ends before the escape"
        );
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

/// The evaluator's text and the writers' backstop on the console: a key with a pasted joiner in an
/// evaluator's sentence prints its escape on every line that carries the sentence, a concealing colour
/// sequence in a field a writer forgot is written as its escape, and a context from a file with CRLF line
/// endings prints as written.
#[cfg(test)]
mod evaluator_text_tests {
    use super::{
        collect_unattributed_explanations, context_line, emit_messages, explanation_of,
        rule_line_texts, writer_output, LocalResourceAggr, Rendered,
    };
    use crate::rules::eval_context::{ClauseReport, Messages, RuleReport};
    use crate::rules::CustomSlot;

    fn evaluator_record(error: &str) -> Messages {
        Messages {
            custom_message: None,
            error_message: Some(error.to_string()),
            location: None,
            refusal: false,
            parts: None,
        }
    }

    /// A pathless clause whose error quotes the key `Bucket<joiner>Name` prints the key's escape on its
    /// `Error =` line and in the unattributed section alike, and the rule-level slot of a plain record
    /// takes the same escape: the evaluator's sentence is not the author's prose, so none of the three
    /// reads the joiner as typed.
    ///
    /// Expected, not yet run. Red: the unattributed entry or the rule-level slot holds the joiner raw
    /// while the `Error =` line holds its escape.
    #[test]
    fn a_look_alike_key_in_an_evaluator_sentence_is_escaped_on_every_line_that_carries_it() {
        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let sentence = format!("the key Bucket{}Name could not be read", joiner);
        let escaped = "the key Bucket\\u{200d}Name could not be read";

        let mut line = Vec::new();
        emit_messages(&mut line, "", "", &sentence, 0).expect("writing to a Vec cannot fail");
        let line = String::from_utf8(line).expect("the line is UTF-8");
        assert_eq!(format!("Error = {}\n", escaped), line);

        assert_eq!(
            escaped,
            explanation_of(&evaluator_record(&sentence)),
            "the unattributed section's entry"
        );

        let rule_level = RuleReport {
            messages: Messages {
                custom_message: Some(sentence.clone()),
                ..evaluator_record("")
            },
            custom_slot: CustomSlot::Evaluator,
            ..Default::default()
        };
        assert_eq!(
            escaped,
            rule_line_texts(&rule_level).0,
            "the rule-level slot of a plain record"
        );
    }

    /// A rule record's custom slot holds EITHER the author's `<< >>` body copied onto a called rule OR the
    /// evaluator's sentence, and the record says which (`RuleReport::custom_slot`). The author's body
    /// keeps a zero-width joiner as typed on the `Rule = { }` arm's `Message` text (`rule_line_texts`) and
    /// in the unattributed section's `rule <name>` entry (the `ClauseReport::Rule` arm of
    /// `collect_unattributed_explanations`, reached with no checks under the rule); the same text marked as
    /// the evaluator's prints the joiner as its escape in both places. The rows run the section's Rule arm
    /// itself, so reverting that arm to one set for both origins turns a row red.
    ///
    /// Expected, not yet run. Red: the author's row prints `\u{200d}` on either line (the arm or the
    /// printer reads the strict set for the author's body), or the evaluator's row keeps the joiner raw.
    #[test]
    fn a_rule_records_slot_takes_the_escape_set_of_whose_text_it_holds() {
        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let typed = format!("owner{}tag", joiner);
        let escaped = "owner\\u{200d}tag".to_string();
        for (slot, expected) in [
            (CustomSlot::Author, typed.clone()),
            (CustomSlot::Evaluator, escaped),
        ] {
            let rule = RuleReport {
                name: "check",
                messages: Messages {
                    custom_message: Some(typed.clone()),
                    ..evaluator_record("")
                },
                custom_slot: slot,
                ..Default::default()
            };
            let (under_a_resource, _, _) = rule_line_texts(&rule);
            assert_eq!(
                expected, under_a_resource,
                "the Rule arm's Message text, record marked {:?}",
                slot
            );

            let report = ClauseReport::Rule(rule);
            let rendered = Rendered::of(std::iter::empty::<&LocalResourceAggr>());
            let mut entries = Vec::new();
            collect_unattributed_explanations(&report, None, &rendered, &mut entries);
            assert_eq!(
                vec![("rule check".to_string(), expected)],
                entries,
                "the unattributed section's entry, record marked {:?}",
                slot
            );
        }
    }

    /// The producer side of a rule record's slot origin: the records are built by the evaluator, not by
    /// hand. A call whose `<< >>` body holds a zero-width joiner, over data the called rule fails on, writes
    /// the joiner raw on the called rule's `Rule = check` block (the `Message` line of
    /// `pprint_clauses`), and the same call over a called rule that fails on its own `when` writes it raw
    /// in the unattributed section's `rule check` entry. Both runs go through the evaluator
    /// (`eval_rules_file`), the report builder (`simplified_json_from_root`, which reads the record's
    /// slot into `RuleReport::custom_slot`) and the console printers. Reverting the evaluator's mark of
    /// the author's body (`ResolvedParameterContext::end_record`) or the report builder's copy of it turns
    /// both rows red: the joiner then prints as its escape. The second row's entry holds the rule's own
    /// sentence after the body, naming the refusal (the body displaces the sentence in the record's
    /// message and the report keeps it as the error message). Two more runs, with no body, count the
    /// section's entries that name the refusal: `not check(..)`, whose negation record carries the refusal
    /// of its own, and `rule r when check(..)`. The gate reads one entry naming the refusal. The negation
    /// reads two, because two records each explain themselves: the called rule's own refusal (an entry
    /// that starts "The rule's condition could not be evaluated") and the negation's fail-closed block
    /// (an entry that starts "the negated rule"); the cell asserts the two texts differ. A body on the
    /// negated call (`not check(..) << >>`) reads the same two entries, each starting with the body as
    /// typed, the first followed by the sentence the body displaced and the second by the negation's.
    ///
    /// Red: either row prints `\u{200d}` where the joiner stands, the section
    /// holds no `rule check` entry (the second rule's `when` did not fail the rule closed with nothing
    /// under it) or one without the refusal's sentence, or a count reads other than its row's (two for
    /// the negation, one for the gate), or the negation's two entries do not start with those two
    /// sentences, in which case the dump names the entries.
    #[test]
    fn an_authors_joiner_on_a_rule_call_reaches_the_console_raw_from_the_evaluator() {
        use super::ComparisonErrorWriter;
        use crate::rules::eval::eval_rules_file;
        use crate::rules::eval_context::{root_scope, simplified_json_from_root};
        use std::collections::{BTreeSet, HashSet};
        use std::convert::TryFrom;
        use std::rc::Rc;

        struct NoExcerpt;
        impl ComparisonErrorWriter for NoExcerpt {}

        /// The first rule report named `name` among `reports`, depth first.
        fn rule_named<'r, 'v>(
            reports: &'r [ClauseReport<'v>],
            name: &str,
        ) -> Option<&'r ClauseReport<'v>> {
            reports.iter().find_map(|report| match report {
                ClauseReport::Rule(rule) if rule.name == name => Some(report),
                ClauseReport::Rule(rule) => rule_named(&rule.checks, name),
                ClauseReport::Disjunctions(ors) => rule_named(&ors.checks, name),
                ClauseReport::Block(_) | ClauseReport::Clause(_) => None,
            })
        }

        const OWN_KEY_TEXT: &str = "is a key of that map";
        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let typed = format!("owner{joiner}tag");
        let escaped = "owner\\u{200d}tag";

        // Row one: the called rule fails on the data, and the body is printed under its `Rule =` block.
        let rules = format!(
            "rule check(p) {{ %p == 'x' }}\nrule r {{ check(Resources.A.Properties.Name) << {typed} >> }}"
        );
        let rules_file =
            crate::rules::exprs::RulesFile::try_from(rules.as_str()).expect("the rules parse");
        let mut root = root_scope(
            &rules_file,
            Rc::new(
                crate::rules::path_value::PathAwareValue::try_from(
                    "{ Resources: { A: { Properties: { Name: 'y' } } } }",
                )
                .expect("the data parses"),
            ),
        );
        eval_rules_file(&rules_file, &mut root, None).expect("the run answers");
        let tree = root.reset_recorder().extract();
        let report = simplified_json_from_root(&tree).expect("the report builds");
        let check = rule_named(&report.not_compliant, "check")
            .expect("the called rule has a report of its own");
        let resource = LocalResourceAggr {
            name: "A".to_string(),
            resource_type: "AWS::Example::Thing",
            cdk_path: None,
            clauses: HashSet::new(),
            paths: BTreeSet::new(),
        };
        let mut written: Vec<u8> = Vec::new();
        super::pprint_clauses(
            &mut written,
            check,
            &resource,
            String::new(),
            &mut NoExcerpt,
        )
        .expect("writing to a Vec cannot fail");
        let printed = String::from_utf8(written).expect("the output is UTF-8");
        let message_lines: Vec<&str> = printed
            .lines()
            .filter(|line| line.trim_start().starts_with("Message"))
            .collect();
        assert!(
            message_lines.iter().any(|line| line.contains(&typed)) && !printed.contains(escaped),
            "the called rule's Message line keeps the joiner raw:\n{}",
            printed
        );

        // Row two: the called rule fails on its own `when` with nothing under it, and the section prints
        // the body raw.
        let rules = format!(
            "rule check(p) when Resources.R1.Properties.List[*].Grp[ keys == /(?!x)((a+)+)b/ ][*].Type exists {{ %p exists }}\nrule r {{ check(Resources.R1) << {typed} >> }}"
        );
        let rules_file =
            crate::rules::exprs::RulesFile::try_from(rules.as_str()).expect("the rules parse");
        let mut root = root_scope(
            &rules_file,
            Rc::new(
                crate::rules::path_value::PathAwareValue::try_from(
                    "{ Resources: { R1: { Properties: { List: [ { Grp: { aab: { Type: { Name: 't', Size: '1' }, B: { Type: 'T', Name: 'b' } } } }, { Grp: { aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: { k: '1' } } } ] } } } }",
                )
                .expect("the data parses"),
            ),
        );
        eval_rules_file(&rules_file, &mut root, None).expect("the run answers");
        let tree = root.reset_recorder().extract();
        let report = simplified_json_from_root(&tree).expect("the report builds");
        let rendered = Rendered::of(std::iter::empty::<&LocalResourceAggr>());
        let mut entries = Vec::new();
        for failure in &report.not_compliant {
            collect_unattributed_explanations(failure, None, &rendered, &mut entries);
        }
        // The entry holds both halves, as a clause's two halves are joined: the author's body first, with
        // the joiner as typed, then the rule's own sentence the body displaced, which names the refusal.
        assert!(
            entries.iter().any(|(context, text)| context == "rule check"
                && text.starts_with(&typed)
                && text.contains(OWN_KEY_TEXT)
                && !text.contains(escaped)),
            "the section's `rule check` entry keeps the joiner raw and names the refusal: {:?}",
            entries
        );
        let naming_the_refusal = entries
            .iter()
            .filter(|(_, text)| text.contains(OWN_KEY_TEXT))
            .count();
        assert_eq!(
            1, naming_the_refusal,
            "a call with a body reads exactly one entry naming the refusal, as a call with none does: {:?}",
            entries
        );

        // A call with no body, negated, and a call as a `when` gate. The gate's section names the refusal
        // in one entry. The negation's section holds two entries, each with a sentence of its own: the
        // called rule's refusal (`rule check`) and the negation's fail-closed block (the rule `r`'s
        // entry), each explaining its own record, so both name the refusal and the texts differ. With a
        // body on the negated call, the `rule check` entry holds the body and the sentence the body
        // displaced, and the negation's entry holds the body and the negation's sentence: still two
        // entries, still distinct texts, both starting with the body as typed.
        const GATED_RULE: &str = "rule check(p) when Resources.R1.Properties.List[*].Grp[ keys == /(?!x)((a+)+)b/ ][*].Type exists { %p exists }\n";
        for (label, rules, expected_entries, with_body) in [
            (
                "`not check(..)` with no body",
                format!("{GATED_RULE}rule r {{ not check(Resources.R1) }}"),
                2,
                false,
            ),
            (
                "`not check(..) << >>` with a body",
                format!("{GATED_RULE}rule r {{ not check(Resources.R1) << {typed} >> }}"),
                2,
                true,
            ),
            (
                "`rule r when check(..)`",
                format!("{GATED_RULE}rule r when check(Resources.R1) {{ Resources exists }}"),
                1,
                false,
            ),
        ] {
            let rules_file =
                crate::rules::exprs::RulesFile::try_from(rules.as_str()).expect("the rules parse");
            let mut root = root_scope(
                &rules_file,
                Rc::new(
                    crate::rules::path_value::PathAwareValue::try_from(
                        "{ Resources: { R1: { Properties: { List: [ { Grp: { aab: { Type: { Name: 't', Size: '1' }, B: { Type: 'T', Name: 'b' } } } }, { Grp: { aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa: { k: '1' } } } ] } } } }",
                    )
                    .expect("the data parses"),
                ),
            );
            let _ = eval_rules_file(&rules_file, &mut root, None);
            let tree = root.reset_recorder().extract();
            let report = simplified_json_from_root(&tree).expect("the report builds");
            let rendered = Rendered::of(std::iter::empty::<&LocalResourceAggr>());
            let mut entries = Vec::new();
            for failure in &report.not_compliant {
                collect_unattributed_explanations(failure, None, &rendered, &mut entries);
            }
            let naming_the_refusal = entries
                .iter()
                .filter(|(_, text)| text.contains(OWN_KEY_TEXT))
                .count();
            assert_eq!(
                expected_entries, naming_the_refusal,
                "{}: the entries naming the refusal: {:?}",
                label, entries
            );
            if expected_entries == 2 {
                let texts: Vec<&str> = entries
                    .iter()
                    .map(|(_, text)| text.as_str())
                    .filter(|text| text.contains(OWN_KEY_TEXT))
                    .collect();
                let sentence_of = |opening: &str| {
                    texts.iter().any(|text| match with_body {
                        true => text.starts_with(&typed) && text.contains(opening),
                        false => text.starts_with(opening),
                    })
                };
                assert!(
                    sentence_of("The rule's condition could not be evaluated")
                        && sentence_of("the negated rule")
                        && texts[0] != texts[1],
                    "{}: the two entries carry different sentences: {:?}",
                    label,
                    texts
                );
            }
        }
    }

    /// The author's half of an entry keeps the joiner as typed while the evaluator's half beside it is
    /// escaped, in the one explanation.
    ///
    /// Expected, not yet run. Red: the author's joiner is written as its escape, or the evaluator's
    /// joiner is written raw.
    #[test]
    fn an_entry_keeps_the_authors_joiner_and_escapes_the_evaluators() {
        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let record = Messages {
            custom_message: Some(format!("owner{}tag", joiner)),
            ..evaluator_record(&format!("key Bucket{}Name", joiner))
        };
        assert_eq!(
            format!("owner{}tag key Bucket\\u{{200d}}Name", joiner),
            explanation_of(&record)
        );
    }

    /// The backstop on a comparison writer's buffer keeps the two colour sequences the writers emit and
    /// the text's layout, and writes every other escape sequence as its escape, a well-formed one
    /// included: a conceal (`ESC [8m`) in a field a writer forgot to escape would hide the text after it.
    ///
    /// Expected, not yet run. Red: the output holds the ESC byte of the conceal, or the green or the
    /// reset is written as text.
    #[test]
    fn the_backstop_writes_a_forgotten_conceal_as_its_escape_and_keeps_the_writers_colour() {
        let esc = char::from(0x1b);
        let buffer = format!("a{esc}[8mhidden\n{esc}[92m    3.\tType: X{esc}[0m\n");
        let written = writer_output(buffer.into_bytes());
        assert_eq!(
            format!("a\\u{{1b}}[8mhidden\n{esc}[92m    3.\tType: X{esc}[0m\n"),
            written
        );
    }

    /// A context that ends with a carriage return (a rules file with CRLF line endings) is the one-line
    /// context it was written as, spacing kept; a context that spans lines is joined where a break sits
    /// between two pieces that hold text.
    ///
    /// Expected, not yet run. Red: the first two rows are trimmed or joined, or the third is not joined.
    #[test]
    fn a_trailing_carriage_return_does_not_trim_a_one_line_context() {
        assert_eq!("Name == 'x'", context_line("Name == 'x'\r"));
        assert_eq!("  Name == 'x'  ", context_line("  Name == 'x'  \r\n"));
        assert_eq!("Name; exists", context_line("Name\r\nexists"));
        assert_eq!(" Name ", context_line(" Name "));
    }
}

#[cfg(test)]
mod cut_message_tests {
    use super::{plain_author_message, LONGEST_RECORDED_MESSAGE};

    #[test]
    fn leaves_a_message_that_fits_alone() {
        let message = "Check was not compliant as property [Name] is missing.";
        assert_eq!(message, plain_author_message(message).0);
    }

    /// The case this exists for. A value the evaluator embedded is compact JSON, so it holds no
    /// whitespace and the cut lands in front of all of it -- the property is still named and the
    /// document is gone, rather than the first 240 bytes of the document being printed.
    #[test]
    fn drops_an_embedded_document_whole() {
        let document = format!(r#"{{"Resources":{{"{}":{{}}}}}}"#, "A".repeat(400));
        let message = format!("Property [Name] is missing. Value traversed to [{document}]");

        let short = plain_author_message(&message).0;

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

        let short = plain_author_message(&message).0;

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
        let short = plain_author_message(&"x".repeat(LONGEST_RECORDED_MESSAGE * 3)).0;

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

        let short = plain_author_message(message).0;

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

        let short = plain_author_message(message).0;

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

        let short = plain_author_message(&message).0;

        assert_eq!("REALREASON", short);
    }
}
