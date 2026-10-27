//! What the console reporters write for a template's and a rules file's text.
//!
//! Every line that prints a recorded message writes the controls in it as their escapes. The STRICT set
//! (`escaped_controls_for_display`) is the default on every console line and field: a key, a path, a
//! context (the rules file path a record context names, through `FileLocation`'s display, is escaped where
//! the position is built, as a file name is), a value, an excerpt, an `Error =` or a `Reason =` text,
//! because an evaluator's sentence quotes keys from the rules file and the template and the record stores
//! it the same way (`reason_backstop`, `write_console_line`). The RELAXED set
//! (`escaped_controls_for_console`), under which a joiner or a mark is ordinary text, applies only to the
//! rule author's `<< >>` message text where it is printed (`plain_author_message`, the `Message =` lines
//! through `write_text_line`, and a rule record's custom slot when the record says the slot holds the
//! author's body, `custom_slot_origin`).
//!
//! A finished line is escaped AT LEAST once, and every escape is idempotent: some paths escape a piece
//! early and the line again as a whole (`reason_backstop` then `console_line!`, `plain_evaluator_message`
//! then `text_line!`, the author slot then `emit_messages`), and a second pass over text that is already
//! escaped changes nothing. A line break inside a field is collapsed first (`one_line`), since both sinks
//! write one line: a context is collapsed at its `Check =` line (`context_line`), and a line feed left in
//! any other field is escaped as `\n` there, never written.
//!
//! The comparison writers format their own lines (`ComparisonErrorWriter`) and escape each field they take
//! from the template before it is formatted in (`console_field`), because their lines also carry the
//! writer's colour, which an escape of the whole line would print as text. The clause arm then applies a
//! backstop to what a writer wrote (`writer_output`), which writes every control as its escape except the
//! text's own layout and the writer's two colour sequences, so a field a writer forgot cannot reach the
//! terminal raw.

use colored::*;
use serde::Serialize;

use crate::commands::tracker::StatusContext;
use crate::rules::eval_context::{
    find_skip_reason, BinaryCheck, BinaryComparison, ClauseReport, EventRecord, FileReport,
    GuardClauseReport, InComparison, Messages, PartsJoin, RuleReport, SentenceParts, SentenceSlot,
    UnaryCheck, UnaryComparison, ValueComparisons, ValueUnResolved,
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
/// survives the collapse. The escaping every console line takes is described in the module's own doc.
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
/// after a one-line context, and the context is that one piece with the break itself dropped (the other
/// fields of the section write a `\r` as its escape; here the trailing break is not part of the line) and
/// its spaces kept, as they were written. The join is made only where a break sits between two pieces that
/// hold text.
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
    // Lossy, not `unwrap_or_default`: one invalid byte (a template's lossily-read text, a writer that sliced
    // a character) keeps the rest of the excerpt, with the replacement character where the byte was.
    crate::utils::writer::escaped_but_for_colour_and_layout(&String::from_utf8_lossy(&buffer))
}

/// A value, a path or a key a comparison writer takes from the template, as one console field: the strict
/// escape (`escaped_controls_for_display`), which also writes a line feed in it as the characters `\n`, so
/// a data string cannot end the writer's line and forge the next. The writers escape each field with this
/// before it is formatted into their lines, and leave the lines' own colour and layout alone.
pub(super) fn console_field(field: &dyn std::fmt::Display) -> String {
    crate::utils::writer::escaped_controls_for_display(&field.to_string())
}

/// The per-resource header both resource-organized reporters write: `Resource = <name> {`, then the `Type`
/// line and, when the template has one, the `CDK-Path` line. Every field is template text (a logical id is
/// a map key, `Type` and `aws:cdk:path` are values), so each passes the strict escape (`console_field`)
/// BEFORE the name is coloured, as the other writers' fields do; the only escape byte left in the header is
/// the writer's own colour, and `colour` says whether the name gets it (the process setting in the
/// reporters; a cell passes it).
pub(super) fn write_resource_header(
    writer: &mut dyn Write,
    name: &str,
    resource_type: &str,
    cdk_path: &str,
    colour: bool,
) -> crate::rules::Result<()> {
    let name = console_field(&name);
    match colour {
        true => writeln!(writer, "Resource = {} {{", name.yellow().bold())?,
        false => writeln!(writer, "Resource = {} {{", name)?,
    }
    let prefix = "  ";
    writeln!(
        writer,
        "{prefix}{0:<width$}= {rt}",
        "Type",
        prefix = prefix,
        width = 10,
        rt = console_field(&resource_type),
    )?;
    if !cdk_path.is_empty() {
        writeln!(
            writer,
            "{prefix}{0:<width$}= {cdk}",
            "CDK-Path",
            prefix = prefix,
            width = 10,
            cdk = console_field(&cdk_path)
        )?;
    }
    Ok(())
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

    /// Whether the per-resource output accounted for this check or for anything beneath it: a block or a
    /// clause it rendered, found through the disjunctions and the called rules that hold them, since the
    /// per-resource printer places only block and clause nodes (`shows` is an identity lookup, which a
    /// disjunction or a nested rule never passes). A rule whose body sits in such a check is rendered by
    /// the descendant, and its decided failure goes with the clause entries, never into the list of what
    /// could not be evaluated.
    fn shows_any(&self, check: &'record ClauseReport<'value>) -> bool {
        match check {
            ClauseReport::Disjunctions(ors) => ors.checks.iter().any(|child| self.shows_any(child)),
            ClauseReport::Rule(rule) => rule.checks.iter().any(|child| self.shows_any(child)),
            other => self.shows(other),
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
            // the rule failed. The discriminator is that NO block or clause beneath the rule is rendered
            // per resource (`checks` empty, or nothing under them shown, `Rendered::shows_any`, which
            // looks through disjunctions and called rules): a rule whose clauses produced
            // findings has them rendered per resource already, under a `Rule =` block that prints the
            // rule's own `Message` line, and repeating the rule-level message there would duplicate
            // rather than explain. A rule that failed on its own condition has no checks only when it
            // carries a message (its failed condition is then not walked); a failed rule with no message
            // has its condition's raise-carrying records as checks, so it is not recognized here and the
            // checks speak for it. This is narrower than `eval_context::speaks_for_itself`, the JUnit
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
            // Also when none of its checks is rendered per resource: those checks then do not speak
            // for the rule, and an author's body on the call would be lost.
            if rule.checks.is_empty() || !rule.checks.iter().any(|check| rendered.shows_any(check))
            {
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
                            // A sentence that gained refusals prints each part under its own kind.
                            origin => joined_console_text(
                                &rule.messages,
                                SentenceSlot::Custom,
                                HeadBound::Plain,
                            )
                            .unwrap_or_else(|| bounded_for_the_console(explanation, origin)),
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
/// rule's own record under a rendered parent (`rule_line_parts`) alike, so no line's length
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
    /// block's `Message` line (`rule_line_parts`), as a clause's message is. Never a refusal.
    Author,
    /// The evaluator's own sentence, or text it quoted from the rules file or the template (a converter's
    /// error, the sentence of a refusal-free record): the strict set (`escaped_controls_for_display`), as
    /// every other line that names a key prints it, and the recorded-message cut.
    Evaluator,
    /// The evaluator's sentence about a read it refused (`Messages::refusal`, `CustomSlot::Refusal`): the
    /// console's refusal pipeline (`refusal_backstop`, strict set: every `; ` and every known joiner in the
    /// text is a floor of the cut), cut at the later refusal bound and marked.
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
/// `refusal_backstop`, an author's text through `plain_author_message` and the evaluator's through
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
/// A refusal's text takes the console's pipeline for a refusal line (`refusal_backstop`: collapsed
/// onto one line, its remaining raw controls written as their escapes, cut on the printed width last with
/// every `; ` and known joiner a floor, with the refusal's marker; the joined sentence of a record with
/// parts takes the same cut through `reason_backstop_joined`). There are two pipelines with different cut
/// rules, and this is the refusal one: the lines that carry a refusal floor at every `; ` and every known
/// joiner, while a reason that is no refusal's (`reason_backstop` with `REASON_CUT_MARKER`) has floor 0.
/// So the `Error =` line of a block, a unary check and a decided comparison
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
        Origin::Refusal => refusal_backstop(message),
        Origin::Author => plain_author_message(message).0,
        Origin::Evaluator => plain_evaluator_message(message).0,
    }
}

/// The least a head keeps when the per-resource block line cuts it to make room for the refusals: a quarter
/// of the plain bound, counted on the PRINTED head, ellipsis included (the cutter's floor is this less the
/// three characters of the ellipsis, so a back-off to a word never leaves a printed head under it). Under
/// it (the join and the refusals leave the head less than this, or nothing) the
/// head is not cut to the room, since a head of a few characters, or only its ellipsis, says nothing and
/// would hide the plain error that decided the verdict; the head's budget is this floor instead and the
/// backstop cuts the end of the line, so the refusals lose min(head, floor) - room, plus up to
/// `BACKSTOP_BACKOFF` characters to a word boundary, plus whatever the join and refusals already exceed
/// the backstop by, plus up to one split escape.
const HEAD_FLOOR: usize = LONGEST_RECORDED_MESSAGE / 4;

/// How the head of a joined sentence is bounded on the console line it is printed on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HeadBound {
    /// A plain head goes through the plain pipeline (collapsed, escaped, cut at the recorded-message bound):
    /// the lines that print a rule's sentence and a block's entry in the unattributed section.
    Plain,
    /// The per-resource block line (`error_line_text`): a plain head with no refusal joined prints whole, the
    /// recorded text as it is, and a joined line that fits the refusal backstop keeps its head whole too. A line
    /// that carries a refusal and would exceed the backstop has its HEAD cut first, to the smaller of the
    /// plain bound and what the backstop leaves after the join and the refusals, so the refusals and their
    /// remedy stay whole, as long as that room is at least [`HEAD_FLOOR`]. Under the floor (the join and the
    /// refusals fill the backstop, or leave the head less than the floor, where a cut to a few characters or
    /// to its ellipsis alone would hide the plain error) the head's budget is the floor and the backstop cuts
    /// the line's end, which carries the refusal marker: the remedy loses min(head, floor) - room, plus up
    /// to 16 characters (`BACKSTOP_BACKOFF`) to a word boundary, plus whatever the join and refusals
    /// already exceed the backstop by, plus up to one split escape (never the plain bound's worth). Every
    /// cut on this arm is `cut_bounded`: it backs up to a word boundary at most 16 characters, never
    /// across a joiner, and otherwise cuts by count. The head prints whole when it is no longer than the
    /// room, otherwise as at most `room - 3` characters (at most 320) and an ellipsis; the line is
    /// `LONGEST_REFUSAL_MESSAGE` characters at most before its ellipsis and marker. The `Plain` arm keeps
    /// the released word-boundary cut for its head. A line the head's cut made fit carries the head's
    /// ellipsis and no refusal marker. There is a cliff at the backstop: a head prints the same text with and without a
    /// joined refusal only while the joined line fits, and one character past it the head may lose
    /// everything the room does not hold (a 399-character head beside 3,800 characters of refusals keeps
    /// about 270). The head yields rather than the remedy because the remedy is what a reader acts on;
    /// the larger of the plain bound and the room would cut the remedy by up to the plain bound in the band
    /// just under the backstop.
    Whole,
}

/// The console text of a rule's or block's sentence that gained refusals, when `slot` is the slot of the
/// record that holds that joined sentence (`Messages::parts` holds the sentence and the refusals, each whole,
/// and says which slot): ONE cap per console line. On the rule and unattributed lines (`HeadBound::Plain`) a
/// plain head is cut at the plain bound, the refusals follow joined whole, and ONE `reason_backstop`
/// (`LONGEST_REFUSAL_MESSAGE` and the refusal's marker) runs over the refusal part; on the per-resource block
/// line (`HeadBound::Whole`) the head is whole while the joined line fits the backstop, and is cut first
/// when it would not (`cut_bounded`), to the smaller of the plain bound and the room the backstop leaves
/// after the join and the refusals, and never to less than the floor (`HEAD_FLOOR`). A refusal-headed
/// sentence is one line under the backstop, cut once (`backstop`). So a long value quoted
/// by a plain head never carries a refusal's remedy away: on the `Whole` arm the remedy is cut only when the
/// join and the refusals alone exceed the backstop, and a line carries the head's ellipsis or the refusal
/// marker, the head's ellipsis alone when the head's cut made the line fit. The exact bounds: on the `Plain`
/// arm the head is bounded by the plain bound (`LONGEST_RECORDED_MESSAGE` plus its ellipsis) always and the
/// refusals are bounded once by the backstop (`LONGEST_REFUSAL_MESSAGE` plus an ellipsis, a space and the
/// marker), so a `Plain` line can be as long as the two bounds and the join together and can carry both
/// the head's ellipsis and the refusal marker; a `Whole` line never exceeds one backstop with its ellipsis,
/// space and marker, and can carry both when the head is cut and the line, with the floor in place of
/// the room, still exceeds the backstop (a 320-character head, a 4,017-character tail).
/// Every structured output carries both parts whole.
/// `None` for any other slot: the caller prints it under its record's one kind.
fn joined_console_text(
    messages: &Messages,
    slot: SentenceSlot,
    bound: HeadBound,
) -> Option<String> {
    joined_console_parts(messages, slot, bound).map(|(joined, _)| joined)
}

/// The sentence a rule's failure rests on when a refusal decided it, through the console's one pipeline, for
/// the PLAIN reporter of `test`, which prints a verdict per rule and no messages: the sentence is the rule's
/// `Reason`, on one line, escaped and bounded as the console bounds it. Two shapes carry one. A sentence
/// that gained refusals (`Messages::parts`, the refusals joined beside the error that decided the rule,
/// whatever that error's kind) goes through `joined_console_text`, the plain head cut at its bound and the
/// refusals bounded once. A rule that failed closed on ONE refusal has nothing joined and its sentence in
/// `custom_message` with the refusal's slot (`own_refusal_sentence`): that sentence goes through the
/// refusal pipeline whole, as a refusal-headed line does. `None` for a rule whose sentence is neither: a
/// plain error with nothing joined, or an author's `<< >>` text, is no reason. The structured reporters of
/// `test` carry the same sentences raw (`joined_rule_sentence_raw`).
pub(crate) fn joined_rule_sentence(rule: &RuleReport<'_>) -> Option<String> {
    match rule.messages.parts.as_ref().map(SentenceParts::join) {
        Some(PartsJoin::Refusals { slot }) => {
            joined_console_text(&rule.messages, slot, HeadBound::Plain)
        }
        _ => own_refusal_sentence(rule)
            .map(|sentence| bounded_for_the_console(sentence, Origin::Refusal)),
    }
}

/// The sentence a rule's failure rests on when a refusal decided it, raw and whole, for the STRUCTURED
/// reporters of `test` (`json`, `yaml`, `junit`): no cut and no console escape, since the serializer or the
/// junit writer does its own escaping and the structured outputs carry every part whole. The two shapes of
/// [`joined_rule_sentence`]: the joined sentence (the head, the join, the refusals), else the rule's own
/// refusal sentence (`own_refusal_sentence`). `None` for a rule whose sentence is neither.
pub(crate) fn joined_rule_sentence_raw(rule: &RuleReport<'_>) -> Option<String> {
    match rule.messages.parts.as_ref().map(SentenceParts::join) {
        Some(PartsJoin::Refusals { .. }) => rule
            .messages
            .parts
            .as_ref()
            .map(SentenceParts::refusals_text),
        _ => own_refusal_sentence(rule).map(str::to_string),
    }
}

/// A rule's own sentence where it is a refusal's and nothing is joined to it: the `custom_message` when the
/// record says that slot holds a refusal's text (`RuleReport::custom_slot`, `CustomSlot::Refusal`), which is
/// how a rule that failed closed on one refusal in its own `when` is recorded. An author's `<< >>` body
/// (`CustomSlot::Author`) and an evaluator's sentence that is no refusal's (`CustomSlot::Evaluator`) are
/// not a reason: the first is the author's prose, the second named no refusal.
fn own_refusal_sentence<'report>(rule: &'report RuleReport<'_>) -> Option<&'report str> {
    match rule.custom_slot {
        CustomSlot::Refusal => rule.messages.custom_message.as_deref(),
        CustomSlot::Author | CustomSlot::Evaluator => None,
    }
}

/// [`joined_console_text`] and whether the HEAD was cut: on the `Plain` arm at the recorded-message bound, as
/// the cutter says it (`plain_evaluator_message`, a word-boundary cut); on the `Whole` arm by `cut_bounded`
/// to the room the backstop leaves, never to a printed head of fewer than `HEAD_FLOOR` characters (its
/// ellipsis included; the cutter's floor is `HEAD_FLOOR - 3` of kept text) and at most the plain bound
/// before the ellipsis. The refusals are never cut at the head's bound,
/// so the flag is the head's alone.
fn joined_console_parts(
    messages: &Messages,
    slot: SentenceSlot,
    bound: HeadBound,
) -> Option<(String, bool)> {
    let parts = messages.parts.as_ref()?;
    // The parts say which shape they are in and which slot holds the sentence (`PartsJoin`): no string is
    // rebuilt to find out.
    if parts.join() != (PartsJoin::Refusals { slot }) {
        return None;
    }
    // The slot the parts name holds exactly the sentence they rebuild: the old guard against a builder that
    // tagged the wrong slot or wrote a text of its own, kept as an assertion and not as a branch.
    debug_assert_eq!(
        match slot {
            SentenceSlot::Custom => messages.custom_message.as_deref(),
            SentenceSlot::Error => messages.error_message.as_deref(),
        },
        Some(parts.refusals_text().as_str()),
        "the parts of a joined sentence rebuild the text of the slot they name"
    );
    // The head, and below the groups of refusals as the sentence lists them (`SentenceParts::groups`),
    // each behind its own joiner.
    let head = parts.head();
    // The head's kind is the record's (`Messages::refusal`). A refusal's head is held to the refusal bound,
    // and the whole line is cut ONCE.
    if error_slot_origin(messages) == Origin::Refusal {
        let mut pieces = vec![("", head)];
        pieces.extend(parts.groups());
        return Some((reason_backstop_joined(&pieces, REFUSAL_CUT_MARKER), false));
    }
    match bound {
        HeadBound::Plain => {
            let (head, head_was_cut) = plain_evaluator_message(head);
            // The refusals as listed: the first group has no joiner of its own here (the head's joiner
            // precedes it), each later group keeps its own.
            let mut pieces = parts.groups();
            if let Some(first) = pieces.first_mut() {
                first.0 = "";
            }
            Some((
                format!(
                    "{head}{}{}",
                    parts.joiner(),
                    reason_backstop_joined(&pieces, REFUSAL_CUT_MARKER)
                ),
                head_was_cut,
            ))
        }
        // The per-resource block line: a plain head with no refusal joined prints whole (it did before any
        // refusal was joined), and a joined line that fits the backstop keeps its head whole too. A line that
        // CARRIES a refusal and would exceed the backstop cuts the HEAD to the room the backstop leaves after
        // the join and the refusals, so the join and every refusal with its remedy stay whole, when that room
        // is at least `HEAD_FLOOR`. Under the floor (the join and the refusals fill the backstop, or leave
        // less than the floor) the head's budget is the floor and the backstop cuts the END of the line,
        // which carries the refusal marker: the refusals already overflow, and a head cut to a few
        // characters would say nothing.
        HeadBound::Whole => {
            // The line when it fits is built the way every other arm and the cut path build it, piece by
            // piece (`joined_line`), so one sentence reads the same whether it fits or is cut.
            let mut whole_pieces = vec![("", head)];
            whole_pieces.extend(parts.groups());
            let whole = joined_line(&whole_pieces).0;
            match whole.chars().count() <= LONGEST_REFUSAL_MESSAGE {
                true => Some((whole, false)),
                false => {
                    let (tail, tail_ends) = joined_line(&parts.groups());
                    let room = LONGEST_REFUSAL_MESSAGE.saturating_sub(tail.chars().count());
                    // The head yields: it prints whole when it is no longer than the room (at least the floor,
                    // at most the plain bound); otherwise it is cut by `cut_bounded` (the same bounded
                    // back-off to a word boundary, else by count) to the room less its ellipsis (never fewer
                    // than the floor less the ellipsis), and at most the plain bound before the ellipsis.
                    // Over the floor the line then fits and carries the head's ellipsis and no refusal
                    // marker; under it the head keeps the floor and the line, longer than the backstop, is
                    // cut at the backstop by the same cutter: the remedy loses min(head, floor) - room, plus
                    // up to `BACKSTOP_BACKOFF` characters to a word boundary, plus whatever the join and
                    // refusals already exceed the backstop by, plus up to one split escape; the ellipsis and
                    // the marker follow, spelled once in `backstop`.
                    let head_room = room.max(HEAD_FLOOR);
                    let head_line =
                        crate::utils::writer::escaped_controls_for_display(&one_line(head));
                    let (head_text, head_was_cut) = match head_line.chars().count()
                        <= head_room.min(LONGEST_RECORDED_MESSAGE)
                    {
                        true => (head_line, false),
                        false => {
                            let kept = head_room.saturating_sub(3).min(LONGEST_RECORDED_MESSAGE);
                            // The head keeps at least `HEAD_FLOOR` printed characters (its ellipsis counts):
                            // a back-off to a word boundary never lands below the floor less the ellipsis.
                            let floor = HEAD_FLOOR.saturating_sub(3);
                            (cut_bounded(&head_line, kept, floor).0, true)
                        }
                    };
                    let head_len = head_text.chars().count();
                    let line_ends: Vec<usize> =
                        tail_ends.iter().map(|end| end + head_len).collect();
                    let line = format!("{head_text}{tail}");
                    Some((
                        match line.chars().count() <= LONGEST_REFUSAL_MESSAGE {
                            true => line,
                            false => backstop_with(&line, REFUSAL_CUT_MARKER, &line_ends),
                        },
                        head_was_cut,
                    ))
                }
            }
        }
    }
}

/// The origin of a rule record's custom slot, from the one value the record carries for it
/// (`RuleReport::custom_slot`): a refusal's record holds the evaluator's refusal sentence there, an
/// author's body the record says it copied, and anything else is the evaluator's own sentence.
fn custom_slot_origin(rule: &RuleReport<'_>) -> Origin {
    // The report builder derives both from the record's one `NamedStatus` slot (`report_failed_clauses`): when
    // the slot is not the author's, the only message is the slot's own and `Messages::refusal` is its kind.
    // With the author's body in the slot the flag belongs to the displaced sentence in the error slot.
    debug_assert!(
        rule.custom_slot == CustomSlot::Author
            || rule.messages.refusal == (rule.custom_slot == CustomSlot::Refusal),
        "a rule report whose slot is {:?} carries refusal={}",
        rule.custom_slot,
        rule.messages.refusal
    );
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
/// that `-o json` carries the whole text. The one cut both pipelines take: `reason_backstop` (a reason that
/// is no refusal's, floor 0) and `refusal_backstop` / `reason_backstop_joined` (every line that carries a
/// refusal, with a floor at every `; ` and known joiner) end here, so the bound and the marker's place
/// are spelled once; the caller names the marker, so the call says which kind of text it bounds. A cut that lands inside a `\u{..}` escape the text carries (the escapes
/// `reason_backstop` writes for a raw control come before the cut, so the cut counts their characters)
/// is moved back to the escape's start (`before_a_split_escape`): the fragment was no part of the
/// author's text, and a line ending `\u{1... [explanation cut` read as a cut escape where nothing was
/// cut but the reporter's own spelling.
///
/// The cut is [`cut_bounded`], the one cutter of every refusal line and of the head on the per-resource
/// block line: it backs up to a word boundary at most `BACKSTOP_BACKOFF` characters, never to a boundary
/// before the last joiner end the caller named (`joiner_ends`), and otherwise cuts by count, so an
/// unbroken remedy is never dropped whole.
fn backstop(text: &str, marker: &str) -> String {
    backstop_with(text, marker, &[])
}

/// [`backstop`] for a line whose joiners the caller knows: `joiner_ends` are the character offsets right
/// after each joiner in `text` (`joined_line`), the floors the cut does not back up past.
fn backstop_with(text: &str, marker: &str, joiner_ends: &[usize]) -> String {
    let floor = joiner_ends
        .iter()
        .copied()
        .filter(|end| *end <= LONGEST_REFUSAL_MESSAGE)
        .max()
        .unwrap_or(0);
    let (cut, was_cut) = cut_bounded(text, LONGEST_REFUSAL_MESSAGE, floor);
    if was_cut {
        format!("{cut} {marker}")
    } else {
        cut
    }
}

/// The one-line, escaped text of `pieces`, each `(joiner, body)` as a joiner followed by its body (each body
/// collapsed and escaped, `one_line`, `escaped_controls_for_display`; the joiners are the sentence's own and
/// hold no control), and the character offsets of every floor the cut does not back up past
/// (`floor_ends`), read off the ASSEMBLED line and never off the pieces: the same escaped text yields the
/// same floors whether it arrives as a joined sentence's pieces or as one string (`refusal_backstop`: a rule
/// reference's "text; callee error" whose callee's sentence opens with a head after the `; `, or carries a
/// joined refusal), so both routes take the same cut by construction. The cell
/// `the_same_text_yields_the_same_floors_as_pieces_and_as_one_string` pins the two routes' equality and, for
/// a head that opens a group right after its joiner, the floors themselves, computed from the text's own
/// character lengths: the `; ` that opens the joiner, the joiner's end, the head's end right after it, the
/// `; ` that opens the next joiner and that joiner's end, and no other. The one place the assembled
/// lines can differ is whitespace at a piece boundary: `one_line` trims each body at both ends, so a body's
/// leading or trailing whitespace is gone on the pieces route, while the one-string route trims the ends of
/// the whole text only and keeps such whitespace inside it as written; the writers put none there (a joiner
/// ends in `: `, a refusal starts with its first word), and the two routes agree on a text with no such
/// whitespace at a boundary.
fn joined_line(pieces: &[(&str, &str)]) -> (String, Vec<usize>) {
    let mut line = String::new();
    for (joiner, body) in pieces {
        line.push_str(joiner);
        line.push_str(&crate::utils::writer::escaped_controls_for_display(
            &one_line(body),
        ));
    }
    let ends = floor_ends(&line);
    (line, ends)
}

/// The character offsets of the floors in `line`, a one-line escaped refusal text, each once and in order,
/// none past the backstop (`backstop_with` keeps the greatest at or below it): the offset right after each
/// `; ` (the separator between listed refusals, and the opening of each joiner text), the offset right after
/// each joiner text the line holds (`SENTENCE_JOINERS`), and the offset right after a known head the
/// evaluator writes before the error it quotes (`PARENT_SENTENCE_HEADS`) where the head stands at a
/// BOUNDARY: the start of the line, right after a `; `, or right after a joiner text. The one floor rule for
/// every refusal line. The joiners and heads are the writers' own texts, so the floors are the real
/// boundaries and no punctuation is guessed from the text; a refusal whose own text holds a `; ` counts as a
/// separator too, which only makes the cut count the characters (never drop a refusal) where it could have
/// used a word boundary. Every offset is found in bytes and converted to characters with one cursor over the
/// line, so a multi-byte text before a floor is counted as the characters it prints.
fn floor_ends(line: &str) -> Vec<usize> {
    use crate::rules::eval::PARENT_SENTENCE_HEADS;
    use crate::rules::eval_context::SENTENCE_JOINERS;
    let mut floors: Vec<usize> = Vec::new();
    let mut boundaries: Vec<usize> = vec![0];
    for (at, _) in line.match_indices("; ") {
        floors.push(at + 2);
        boundaries.push(at + 2);
    }
    for joiner in SENTENCE_JOINERS {
        for (at, _) in line.match_indices(joiner) {
            floors.push(at + joiner.len());
            boundaries.push(at + joiner.len());
        }
    }
    for at in boundaries {
        for head in PARENT_SENTENCE_HEADS {
            if line[at..].starts_with(head) {
                floors.push(at + head.len());
            }
        }
    }
    floors.sort_unstable();
    floors.dedup();
    // Bytes to characters with one cursor, in offset order; nothing past the backstop is a floor.
    let (mut cursor, mut count, mut ends) = (0usize, 0usize, Vec::new());
    for at in floors {
        count += line[cursor..at].chars().count();
        cursor = at;
        if !chars_below_the_backstop(count) {
            break;
        }
        ends.push(count);
    }
    ends
}

/// Whether a character offset is still within the backstop, so a floor at it can matter.
fn chars_below_the_backstop(offset: usize) -> bool {
    offset <= LONGEST_REFUSAL_MESSAGE
}

/// The console's one bound for a refusal's text that arrives as a single string (an entry that lists
/// refusals alone, a rule reference's "text; callee error", a numbered raise): [`reason_backstop_joined`]
/// over the text as one body with the refusal's marker, so every `; ` in the text, every known joiner text
/// it holds and every known head at its start or right after a `; ` is a floor (`joined_line`, the one floor
/// rule), and the same text takes the same cut whether it reaches the console as a joined sentence's body or
/// as one string (given no whitespace at a piece boundary, which the pieces route trims and this route keeps;
/// `joined_line`). A refusal's own `; ` counts as a boundary too, which can only turn a word cut into a count
/// cut, never drop a refusal.
fn refusal_backstop(text: &str) -> String {
    reason_backstop_joined(&[("", text)], REFUSAL_CUT_MARKER)
}

/// [`reason_backstop`] over the pieces of a joined sentence (`joined_line`), so the cut knows the joiners.
fn reason_backstop_joined(pieces: &[(&str, &str)], marker: &str) -> String {
    let (line, ends) = joined_line(pieces);
    backstop_with(&line, marker, &ends)
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
    let Some(kept) = cut.strip_suffix("...") else {
        return cut.to_string();
    };
    match split_escape_start(kept) {
        Some(at) => format!("{}...", kept[..at].trim_end()),
        None => cut.to_string(),
    }
}

/// The byte offset of the backslash that opens the split escape `kept` ends in (the rule of
/// [`before_a_split_escape`]), or `None` when the kept text ends in no split escape.
fn split_escape_start(kept: &str) -> Option<usize> {
    const LONGEST_SPLIT_ESCAPE: usize = "\\u{10ffff".len();
    let at = kept.rfind('\\')?;
    let tail = &kept[at..];
    match tail.len() > LONGEST_SPLIT_ESCAPE || !is_a_split_escape(tail) {
        true => None,
        false => Some(at),
    }
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

/// How far [`cut_bounded`] backs up to a word boundary before it cuts by count.
const BACKSTOP_BACKOFF: usize = 16;

/// `text`, put on one line (`one_line`, idempotent), cut to at most `limit` characters before the ellipsis,
/// and whether anything was cut. The one cutter of every refusal line (`backstop`) and of the head on the
/// per-resource block line, so the bound and the layout are spelled once. The cut backs up to the nearest
/// word boundary within `BACKSTOP_BACKOFF` characters, but only to a boundary at or above `floor` (a
/// character offset), and otherwise cuts by count: an unbroken remedy is never dropped whole, as the
/// released word-boundary cut `cut_to` dropped it back to the joiner. The caller sets the floor: the head
/// on the block line passes what it must keep (`HEAD_FLOOR`, less its ellipsis), a joined refusal line the
/// last real joiner end at or below the limit (`backstop_with`, from the offsets `joined_line` computes),
/// a refusal line that arrives as one string the last `; ` or known joiner end in it (`refusal_backstop`),
/// and a reason that is no refusal's (`reason_backstop`) 0. Prose with a `: ` in a line that carries no
/// refusal is no joiner and backs up to its word boundary; in a refusal line every `; ` is a floor. Trailing whitespace is trimmed before the ellipsis, and a cut
/// inside a `\u{..}` escape moves back to the escape's start (`before_a_split_escape`, up to nine
/// characters more), but neither takes the kept text under `floor`: the floor is applied last, and a split
/// escape whose move back would fall under the floor is cut at its start, untrimmed, when that keeps the
/// floor (no fragment is printed), and by count inside it only when even that is under the floor. A cut by
/// count can end inside a word: only when the window holds no boundary at or above the floor. The plain
/// arm keeps `cut_to` for its head because a half word in fixture output fails the spell checker.
fn cut_bounded(text: &str, limit: usize, floor: usize) -> (String, bool) {
    let collapsed = one_line(text);
    let text = collapsed.as_str();
    let Some((at, _)) = text.char_indices().nth(limit) else {
        return (text.to_string(), false);
    };
    let kept = &text[..at];
    let kept = if text[at..].starts_with(char::is_whitespace) {
        kept
    } else {
        let window = kept
            .char_indices()
            .rev()
            .nth(BACKSTOP_BACKOFF - 1)
            .map_or(0, |(i, _)| i);
        match kept[window..].rfind(char::is_whitespace) {
            Some(rel) => {
                let head = &kept[..window + rel];
                let below_the_floor = head.chars().count() < floor;
                match head.trim().is_empty() || below_the_floor {
                    true => kept,
                    false => head,
                }
            }
            None => kept,
        }
    };
    // The floor is applied LAST, after the trim and after the move back out of a split escape: each of them
    // only shortens the cut, and the floor is a promise about what is printed. A trim that would take the
    // kept text under the floor is not taken, and neither is a move back out of an escape that would: such
    // an escape is cut at its start UNTRIMMED where that keeps the floor (the joiner's space stays and no
    // fragment of the escape prints; the branch below), and by count inside it (`\u{1...`) only where even
    // its start is under the floor.
    let trimmed = kept.trim_end();
    let cut = match trimmed.chars().count() < floor {
        true => kept,
        false => trimmed,
    };
    let plain = format!("{cut}...");
    let moved = before_a_split_escape(&plain);
    let moved_kept = moved.chars().count().saturating_sub(3);
    if moved_kept >= floor {
        return (moved, true);
    }
    // The move back out of a split escape would take the cut under the floor (the joiner's trimmed space).
    // Cut at the escape's start UNTRIMMED instead, when that keeps the floor: no fragment of the escape is
    // printed and the joiner's space stays. Only when even that is under the floor is the escape cut by count.
    match split_escape_start(cut) {
        Some(at) if cut[..at].chars().count() >= floor => (format!("{}...", &cut[..at]), true),
        _ => (plain, true),
    }
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
    let evaluator = non_empty_message(&messages.error_message).map(|text| {
        joined_console_text(messages, SentenceSlot::Error, HeadBound::Plain)
            .unwrap_or_else(|| bounded_for_the_console(text, error_slot_origin(messages)))
    });
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

        // An `or` one disjunct decided: the arms it decided past (a raise held and dropped when a sibling
        // disjunct passed) are no part of the rule's failure, and a refused read among them is the
        // refused-read line's to report, so the summary lists nothing beneath a passing disjunction.
        // Listed, a refusal's raise under a passing `or` printed the refusal's sentence a second time
        // beside the leaf record that carries it as the rule's own failure.
        Some(RecordType::Disjunction(BlockCheck {
            status: Status::PASS,
            ..
        })) => vec![],

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
    // Every `Error =` text this function prints takes the refusal pipeline a `Reason =` line of a refusal
    // takes (`refusal_backstop`: collapsed onto one line, then escaped, then cut on the PRINTED width with
    // every `; ` and known joiner a floor and the refusal's marker): the evaluator writes the record's sentence with its template parts escaped, and
    // this is the console's own defense for a sentence that reaches it with a raw control, so no branch
    // below prints one. Escaped before the collapse, a raw line break became a literal `\n` where the
    // pipeline joins the parts with `; `.
    let bounded = refusal_backstop;
    let displayed_whole =
        |text: &str| crate::utils::writer::escaped_controls_for_display(&one_line(text));
    // The reason is stored as its builder wrote it (raw controls included) and printed through the
    // console's refusal pipeline (`refusal_backstop`): on one line, the controls escaped, cut on the
    // printed width last. Every reason this function prints is a refusal's (the record is flagged one), so
    // the cut, where it falls, carries the refusal's marker.
    let reason_line = || match reason.is_empty() {
        true => None,
        false => Some(refusal_backstop(reason)),
    };
    // Clause-shaped parts only (`PartsJoin::Clause`, the head and the evaluator's message of a clause
    // record): a rule's or block's sentence that joined refusals has no `Reason =` block to lay out.
    let Some(parts) = messages
        .parts
        .as_ref()
        .filter(|parts| parts.join() == PartsJoin::Clause)
    else {
        let sentence = messages.error_message.as_deref().unwrap_or("");
        return (bounded(sentence), reason_line());
    };
    let (head, message) = (parts.head(), parts.message());
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
            Some(refusal_backstop(reason)),
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
        false => (bounded(head), Some(refusal_backstop(message))),
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
/// the console's refusal pipeline (`bounded_for_the_console`, through `refusal_backstop`: one line,
/// the remaining raw controls escaped, cut on the printed width last), so no console line that prints a
/// refusal's sentence rests on the evaluator having bounded or escaped the text. For the arms that print
/// a resolved comparison, a block and a unary check; the retrieval-error arm decides its lines from the
/// record (`refusal_lines`), through the same pipeline.
fn error_line_text(messages: &Messages) -> String {
    let error = messages.error_message.as_deref().unwrap_or("");
    // A block's sentence that gained refusals prints as one line (`joined_console_text`, `HeadBound::Whole`):
    // the head stays whole while the joined line (head, the join, the refusals) fits the refusal backstop;
    // when it would exceed it, the head is cut first (`cut_bounded`) to the smaller of the plain bound
    // and the room the backstop leaves after the join and the refusals (never to less than the head floor,
    // under which the end of the line is cut and the refusals lose min(head, floor) - room, up to 16
    // characters to a word boundary, and what the join and refusals already exceed the backstop by), so the
    // refusals stay whole above the floor, and the refusal marker appears only when the line still exceeds
    // the backstop. A block line with no joined refusal prints the recorded text as it is for a plain
    // record, and through the refusal pipeline for a refusal's.
    if let Some(joined) = joined_console_text(messages, SentenceSlot::Error, HeadBound::Whole) {
        return joined;
    }
    match messages.refusal {
        true => bounded_for_the_console(error, Origin::Refusal),
        false => error.to_string(),
    }
}

/// The first three values of [`rule_line_parts`] (its doc holds the contract), for the cells that do not read
/// the layout.
#[cfg(test)]
fn rule_line_texts(rule: &RuleReport<'_>) -> (String, String, Option<bool>) {
    let (message, error, cut, _) = rule_line_parts(rule);
    (message, error, cut)
}

/// How `emit_rule_messages` writes the two texts of `rule_line_parts`, decided with the texts and apart from
/// the cut flag, which says only whether the text was cut.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleLineLayout {
    /// Both texts through `emit_messages`: the message divided at every `;`, the error joined into one line.
    Messages,
    /// The message as one `Message = ...` line (its text holds `; ` joins and a cut's marker that
    /// `emit_messages` would divide), then the error through `emit_messages`: a custom slot that was cut at
    /// the recorded-message bound, and one that is a sentence joined with the refusals its condition met.
    OneLineMessage,
    /// One `Message = ...` and one `Error = ...` line, each whole: a refusal's record.
    RefusalLines,
}

/// The two texts the `Rule = { }` arm of the per-resource output prints for a rule's own record
/// (`pprint_clauses`, the `ClauseReport::Rule` arm, through `emit_rule_messages`): its `Message` line's
/// text, then its `Error` line's. The origin of the CUSTOM slot is read off the record
/// (`custom_slot_origin`), so a caller cannot hand a refusal's record another origin's pipeline. A
/// rule-level record carries the evaluator's sentence there (a condition that raised a refusal across a
/// rule boundary, `report_all_failed_clauses_for_rules`) or the author's body copied onto a called rule,
/// so for a refusal's record BOTH slots take the console's refusal pipeline (`bounded_for_the_console`,
/// through `refusal_backstop`: one line, the remaining raw controls escaped, cut on the printed width last,
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
///
/// The fourth value is the layout the lines are written in (`RuleLineLayout`). The cut flag stays what is
/// said above (the cutter's own answer, `None` for a refusal's record): a sentence joined with refusals
/// reports whether its head was cut, and asks for the one-line layout through the layout value, so the flag
/// is never set to get a layout.
fn rule_line_parts(rule: &RuleReport<'_>) -> (String, String, Option<bool>, RuleLineLayout) {
    let messages = &rule.messages;
    let released = |slot: &Option<String>| slot.as_deref().unwrap_or("").to_string();
    match custom_slot_origin(rule) {
        Origin::Refusal => (
            // A refusal's sentence that gained refusals prints as ONE line, cut once at the refusal
            // backstop with one marker; any other is the refusal pipeline's whole, also one cut.
            joined_console_text(messages, SentenceSlot::Custom, HeadBound::Plain).unwrap_or_else(
                || bounded_for_the_console(&released(&messages.custom_message), Origin::Refusal),
            ),
            bounded_for_the_console(&released(&messages.error_message), Origin::Refusal),
            None,
            RuleLineLayout::RefusalLines,
        ),
        Origin::Author => (
            crate::utils::writer::escaped_controls_for_console(&one_line(&released(
                &messages.custom_message,
            ))),
            // The displaced sentence that gained refusals prints part by part; any other under its kind.
            joined_console_text(messages, SentenceSlot::Error, HeadBound::Plain).unwrap_or_else(
                || {
                    bounded_for_the_console(
                        &released(&messages.error_message),
                        error_slot_origin(messages),
                    )
                },
            ),
            Some(false),
            RuleLineLayout::Messages,
        ),
        Origin::Evaluator => {
            let custom = released(&messages.custom_message);
            match joined_console_parts(messages, SentenceSlot::Custom, HeadBound::Plain) {
                // One line with the join's own `; ` in it, as a cut sentence is written.
                Some((joined, head_was_cut)) => (
                    joined,
                    released(&messages.error_message),
                    Some(head_was_cut),
                    RuleLineLayout::OneLineMessage,
                ),
                None => {
                    let (message, cut) = plain_evaluator_message(&custom);
                    let layout = match cut {
                        true => RuleLineLayout::OneLineMessage,
                        false => RuleLineLayout::Messages,
                    };
                    (
                        message,
                        released(&messages.error_message),
                        Some(cut),
                        layout,
                    )
                }
            }
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

/// The `Message` and `Error` lines of a rule's own record (`rule_line_parts`). A refusal's record has
/// both texts on ONE line each already (collapsed, escaped and cut by the refusal pipeline), and they are
/// written as one line each, `Message = ...` and `Error = ...`, never through `emit_messages`, which
/// splits a message on every `;`: the collapse joins a line break as `; ` and the cut's marker holds a
/// `;` too, so through it a cut refusal printed its marker across two lines and a collapsed sentence
/// came apart at every join. A record that is no refusal's whose custom slot was CUT at the
/// recorded-message bound is written as one `Message = ...` line too (the collapse's joins would come
/// apart the same way); every other plain record is written as every other record's messages are
/// (`emit_messages`), the author's `;` list included. The layout is `rule_line_parts`' fourth value,
/// decided where the text is made: a slot cut at the bound, and a sentence joined with refusals, take the
/// one-line form, and the cut flag beside the texts stays the cutter's own answer; an earlier form of this
/// function rebuilt the collapse and compared the two strings, and compared with the UNESCAPED collapse, a
/// short plain message holding a raw control (a tab, an ESC) read as cut and took the one-line form the doc
/// reserves for a cut. The rule-level record's custom slot holds
/// EITHER the evaluator's sentence OR an author's `<< >>` message copied onto a called rule by the
/// evaluator, and the record says which (`RuleReport::custom_slot`, read by `custom_slot_origin` inside
/// `rule_line_parts`): the author's body takes the relaxed escape set and is printed whole, as the clause
/// arms print an author's message, and the evaluator's sentence takes the strict one and is cut at the
/// recorded-message bound.
fn emit_rule_messages(
    writer: &mut dyn Write,
    prefix: &str,
    rule: &RuleReport<'_>,
) -> crate::rules::Result<()> {
    let (message, error, _, layout) = rule_line_parts(rule);
    match layout {
        RuleLineLayout::Messages => return emit_messages(writer, prefix, &message, &error, 0),
        RuleLineLayout::OneLineMessage => {
            text_line!(writer, "{prefix}Message = {message}")?;
            return emit_messages(writer, prefix, "", &error, 0);
        }
        RuleLineLayout::RefusalLines => {}
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
    /// Fails when the line carries the ESC byte itself.
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
    /// Fails when an item carries the ESC or the tab byte itself.
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
    /// Fails when the `Error =` line carries the ESC byte, or when an escaped text is escaped a
    /// second time.
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
    /// Fails when a piece holds the characters `\n` or `\r`, or when a CRLF text gives an empty or
    /// doubled item.
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
    /// Fails when the `Error =` line holds the characters `\n` or `\r`.
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
    /// Fails when the ZWJ or the RLM line holds the characters `\u{200d}` or `\u{200f}`, or when a
    /// zero-width space or an override is written raw.
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

    /// Fails when the block's `Message =` line carries the ESC byte.
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

    /// Fails when the unary check's `Message =` or `Error =` line carries the ESC byte.
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

    /// Fails when the decided comparison's `Message =` or `Error =` line carries the ESC byte.
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

    /// Fails when the membership comparison's `Message =` or `Error =` line carries the ESC byte.
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
    /// Fails when the retrieval error's `Message =` line carries the ESC byte.
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
    /// Fails when the output holds the characters `\u{1b}[92m` (the colour printed as text) or
    /// the excerpt's tab as `\t`, when the template field's ESC byte reaches the output raw, or
    /// when a line feed in the field starts a second line.
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
    /// Fails when the output holds the ESC byte of the cursor movement, when the colour sequence is
    /// written as text, or when the tab is written as `\t`.
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
    /// Fails when the `Check =` line holds the joiner raw, or when the `Message =` line holds the
    /// characters `\u{200d}`.
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
    /// Fails when the spaces around the context are trimmed or doubled.
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
    /// Fails when the line holds the characters `\n` or a second console line.
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
    /// Fails when an arm's output carries the ESC byte, or when a context's escape reads
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
                    raised: true,
                    message: Some(SENTENCE.to_string()),
                    refusal,
                    custom_message: custom_message.map(str::to_string),
                    gate_mark: false,
                    frame_reads: Vec::new(),
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
            parts: message.map(|message| SentenceParts::clause(head, message)),
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
        // A record built by the report builder holds a flag that agrees with its slot (unless the slot is
        // the author's body, where the flag is the displaced sentence's), so the cell's records do too.
        let rule_of = |messages: Messages, custom_slot: CustomSlot| RuleReport {
            name: "nested",
            messages: match custom_slot {
                CustomSlot::Author => messages,
                _ => Messages {
                    refusal: custom_slot == CustomSlot::Refusal,
                    ..messages
                },
            },
            custom_slot,
            ..Default::default()
        };
        let custom = "the condition `\u{1b}[31mgate\u{1b}[0m` could not be\nanswered";
        let error = "the key `\u{1b}[31ma\nb\u{1b}[0m` could not be read";
        // The two texts a rule report can hold; what differs between the rows is the record's slot, not
        // the texts. The flag follows the slot (`rule_of`), as the report builder writes it: the printer
        // reads the slot for the custom message and the flag for the displaced sentence in the error slot
        // (the last rows depend on `refusal: true` there).
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

    /// A rule record's custom slot that is a sentence joined with the refusals its condition met is written
    /// as one `Message = ...` line (its `; ` joins would come apart through `emit_messages`), and the cut
    /// flag beside the text stays what the cutter says: `Some(false)` for a head under the recorded-message
    /// bound, `Some(true)` for a head cut there, the refusal whole in both. The layout is its own value.
    ///
    /// Fails when the flag reads `Some(true)` for the uncut head (set to get the layout), when the
    /// layout is `Messages`, or when the refusal after a cut head is cut too.
    #[test]
    fn a_joined_rule_sentence_takes_the_one_line_layout_and_keeps_the_cut_flag_truthful() {
        use super::RuleLineLayout;
        use crate::rules::eval_context::{RuleReport, SentenceParts, ALSO_MET};
        use crate::rules::CustomSlot;
        let rule_of = |head: &str, message: &str| RuleReport {
            name: "gated",
            messages: Messages {
                custom_message: Some(format!("{head}{ALSO_MET}{message}")),
                error_message: None,
                location: None,
                refusal: false,
                parts: Some(SentenceParts::refusals_beside(
                    head,
                    message,
                    crate::rules::eval_context::SentenceSlot::Custom,
                )),
            },
            custom_slot: CustomSlot::Evaluator,
            ..Default::default()
        };
        let refusal = "the read of `A` was refused, at path /Resources/A/Tags";
        let short_head = "the condition could not be evaluated";
        let (text, _, cut, layout) = super::rule_line_parts(&rule_of(short_head, refusal));
        assert_eq!(
            (
                format!("{short_head}{ALSO_MET}{refusal}"),
                Some(false),
                RuleLineLayout::OneLineMessage
            ),
            (text, cut, layout),
            "an uncut head: the joined text whole, the flag false, the one-line layout"
        );
        let long_head = format!("{} {}", "y".repeat(300), "z".repeat(300));
        let (text, _, cut, layout) = super::rule_line_parts(&rule_of(&long_head, refusal));
        assert_eq!(
            (
                format!("{}...{ALSO_MET}{refusal}", "y".repeat(300)),
                Some(true),
                RuleLineLayout::OneLineMessage
            ),
            (text, cut, layout),
            "a head over the bound is cut at it, the flag says so, and the refusal stays whole"
        );
    }

    /// The `test` command's reason for a rule (`joined_rule_sentence` for the plain reporter,
    /// `joined_rule_sentence_raw` for the structured ones) is read from two shapes and nothing else, over
    /// the record's custom slot kind crossed with whether its sentence joined refusals. With refusals
    /// joined (`SentenceParts`, the Refusals join), every slot kind yields the joined text, whole in both
    /// forms for a short control-free sentence. With nothing joined, only a record whose slot holds a
    /// REFUSAL's sentence yields it: the raw form is the sentence as recorded, and the console form goes
    /// through the refusal pipeline (one line, its line break as `; `, a raw ESC as its escape, and a
    /// sentence over the refusal backstop cut there with the refusal marker). An author's `<< >>` body and
    /// an evaluator's sentence that is no refusal's yield `None` with nothing joined: the first is the
    /// author's prose, the second named no refusal.
    ///
    /// Fails when the Refusal-slot row with nothing joined yields `None` (the fallback removed), when an
    /// Author or Evaluator row with nothing joined yields a text (the slot test widened), when a joined
    /// row's text differs between the slots, when the console form keeps a raw ESC or a line break, or when
    /// the over-backstop sentence is printed whole or without the marker.
    #[test]
    fn a_rules_test_reason_is_its_joined_sentence_or_its_own_refusal_sentence_and_nothing_else() {
        use crate::rules::eval_context::{RuleReport, SentenceParts, SentenceSlot, ALSO_MET};
        use crate::rules::CustomSlot;
        let head = "the condition could not be evaluated";
        let refusal = "the read of `A` was refused, at path /Resources/A/Tags";
        let own = "the read of `\u{1b}[31mA\u{1b}[0m` was\nrefused, at path /Resources/A/Tags";
        let own_console =
            "the read of `\\u{1b}[31mA\\u{1b}[0m` was; refused, at path /Resources/A/Tags";
        // The record as the report builder writes it: the flag agrees with the slot, except under an
        // author's body, where the flag is the displaced sentence's and stays false here.
        let rule_of = |custom_slot: CustomSlot, joined: bool, sentence: &str| RuleReport {
            name: "gated",
            messages: Messages {
                custom_message: Some(match joined {
                    true => format!("{head}{ALSO_MET}{refusal}"),
                    false => sentence.to_string(),
                }),
                error_message: None,
                location: None,
                refusal: custom_slot == CustomSlot::Refusal,
                parts: match joined {
                    true => Some(SentenceParts::refusals_beside(
                        head,
                        refusal,
                        SentenceSlot::Custom,
                    )),
                    false => None,
                },
            },
            custom_slot,
            ..Default::default()
        };
        let joined_text = format!("{head}{ALSO_MET}{refusal}");
        let slots = [
            CustomSlot::Refusal,
            CustomSlot::Author,
            CustomSlot::Evaluator,
        ];
        for custom_slot in slots.iter().copied() {
            let rule = rule_of(custom_slot, true, own);
            assert_eq!(
                (Some(joined_text.clone()), Some(joined_text.clone())),
                (
                    super::joined_rule_sentence(&rule),
                    super::joined_rule_sentence_raw(&rule)
                ),
                "{custom_slot:?} with refusals joined: the joined text, whole in both forms"
            );
            let rule = rule_of(custom_slot, false, own);
            let expected = match custom_slot {
                CustomSlot::Refusal => (Some(own_console.to_string()), Some(own.to_string())),
                CustomSlot::Author | CustomSlot::Evaluator => (None, None),
            };
            assert_eq!(
                expected,
                (
                    super::joined_rule_sentence(&rule),
                    super::joined_rule_sentence_raw(&rule)
                ),
                "{custom_slot:?} with nothing joined: only a refusal's own sentence is a reason"
            );
        }
        // A thousand characters over the backstop, so the cut removes far more than the marker adds; a
        // sentence a few characters over is cut too, but its console form is then LONGER than the raw
        // one (the ellipsis and the marker outweigh the few characters removed), so the length alone
        // would not show the cut. The count of `x` does: the console form keeps fewer than the raw.
        let long_own = format!(
            "the read of `A` was refused: {}",
            "x".repeat(super::LONGEST_REFUSAL_MESSAGE + 1000)
        );
        let rule = rule_of(CustomSlot::Refusal, false, &long_own);
        let console =
            super::joined_rule_sentence(&rule).expect("a refusal's own sentence is a reason");
        let count_x = |text: &str| text.matches('x').count();
        assert!(
            count_x(&console) < count_x(&long_own)
                && console.chars().count() < long_own.chars().count()
                && console.ends_with(super::REFUSAL_CUT_MARKER)
                && super::joined_rule_sentence_raw(&rule).as_deref() == Some(long_own.as_str()),
            "the console form of an over-backstop sentence is cut with the refusal marker, the raw form is whole: {}",
            console
        );
    }

    /// A refusal's own head that gained refusals is held to ONE cap per console line: the joined line is cut
    /// once, at the refusal backstop, with one marker, whichever of the three paths prints it (a block's
    /// `Error =` line, a refusal-headed rule's `Message =` line, and a displaced sentence under an author's
    /// body). The head and the refusals are each long enough that the joined line is over the backstop, so
    /// a cut applied per part would leave two markers, and a line cut at the plain bound would be far
    /// shorter than the backstop.
    ///
    /// Fails when a line carries two markers, no marker, or is cut at the plain bound (shorter
    /// than the backstop), or is longer than the backstop and its marker.
    #[test]
    fn a_refusal_head_over_the_backstop_with_a_long_joined_refusal_is_cut_once_with_one_marker() {
        use crate::rules::eval_context::{RuleReport, SentenceParts, SentenceSlot, ALSO_MET};
        let head = "head words ".repeat(300);
        let refusals = "remedy words ".repeat(300);
        let joined = format!("{head}{ALSO_MET}{refusals}");
        let marker = super::REFUSAL_CUT_MARKER;
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        // The exact ceiling is the backstop, the ellipsis (3 characters), one space and the marker; the
        // `+ 4` below is the ellipsis and the space.
        let one_cut = |label: &str, text: &str| {
            assert_eq!(
                1,
                text.matches(marker).count(),
                "({label}) exactly one marker, in: {text}"
            );
            assert!(
                text.ends_with(marker)
                    && text.chars().count() <= bound + marker.chars().count() + 4
                    && text.chars().count() > super::LONGEST_RECORDED_MESSAGE * 2,
                "({label}) cut once at the backstop, not at the plain bound and not past the backstop: {} characters",
                text.chars().count()
            );
        };
        let block = Messages {
            custom_message: None,
            error_message: Some(joined.clone()),
            location: None,
            refusal: true,
            parts: Some(SentenceParts::refusals_beside(
                &head,
                &refusals,
                SentenceSlot::Error,
            )),
        };
        one_cut("a block's Error line", &super::error_line_text(&block));
        // The per-resource block line of a PLAIN head: it prints whole when no refusal is joined, but a
        // line that carries a refusal and would exceed the backstop cuts the HEAD to the room the join and
        // the refusals leave (here 3,925 characters of tail leave 171), so the refusals and their remedy
        // stay whole, the line fits the backstop, and it carries the head's ellipsis and no refusal marker.
        let plain_block = Messages {
            custom_message: None,
            error_message: Some(joined.clone()),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside(
                &head,
                &refusals,
                SentenceSlot::Error,
            )),
        };
        let plain_line = super::error_line_text(&plain_block);
        assert_eq!(
            (0, true, true, true),
            (
                plain_line.matches(marker).count(),
                plain_line.ends_with(refusals.trim_end()),
                plain_line.chars().count() <= bound,
                plain_line.contains(&format!("...{ALSO_MET}"))
            ),
            "a plain-headed block's Error line: the head cut to the room, the remedy whole, no refusal marker: {} characters",
            plain_line.chars().count()
        );
        let refusal_rule = RuleReport {
            name: "gated",
            messages: Messages {
                custom_message: Some(joined.clone()),
                error_message: None,
                location: None,
                refusal: true,
                parts: Some(SentenceParts::refusals_beside(
                    &head,
                    &refusals,
                    SentenceSlot::Custom,
                )),
            },
            custom_slot: crate::rules::CustomSlot::Refusal,
            ..Default::default()
        };
        let (message, _, cut, layout) = super::rule_line_parts(&refusal_rule);
        one_cut("a refusal-headed rule's Message line", &message);
        assert_eq!(
            (None, super::RuleLineLayout::RefusalLines),
            (cut, layout),
            "a refusal's record reports no head cut and takes the refusal layout"
        );
        // A refusal-headed sentence displaced by an author's body sits in the error slot.
        let displaced = RuleReport {
            name: "gated",
            messages: Messages {
                custom_message: Some("the author's body".to_string()),
                error_message: Some(joined.clone()),
                location: None,
                refusal: true,
                parts: Some(SentenceParts::refusals_beside(
                    &head,
                    &refusals,
                    SentenceSlot::Error,
                )),
            },
            custom_slot: crate::rules::CustomSlot::Author,
            ..Default::default()
        };
        let (_, error, _, _) = super::rule_line_parts(&displaced);
        one_cut("the displaced sentence under a body", &error);
        // The sentence the plain reporter of `test` prints for the same refusal-headed rule is the same
        // single-cut line, and the raw one for the structured reporters is whole.
        one_cut(
            "the test reporter's plain reason",
            &super::joined_rule_sentence(&refusal_rule).expect("the rule joined refusals"),
        );
        assert_eq!(
            Some(joined.clone()),
            super::joined_rule_sentence_raw(&refusal_rule),
            "the structured reporters carry the joined sentence whole"
        );
    }

    /// A plain block head prints the same text whether or not a refusal was joined to it WHILE THE JOINED LINE
    /// FITS the backstop: the per-resource block line prints the head WHOLE (no plain-bound cut), as it did
    /// before any refusal was joined, and the refusal follows after the join. The head is over the plain
    /// bound, so a cut that depended on a sibling's refusal being appended would show here as a head that
    /// changed. Past the backstop the head yields to the refusals (the cliff, `HeadBound::Whole`): a
    /// 399-character head beside 3,800 characters of refusals is cut to the room that is left, shorter than
    /// the same head alone, and the remedy stays whole. The second row pins that side.
    ///
    /// Fails when the head is cut at the plain bound only when the refusal is joined (the two rows
    /// print different heads), or when the joined row's refusal is not after the head whole.
    #[test]
    fn a_plain_block_head_prints_the_same_with_and_without_a_joined_refusal() {
        use crate::rules::eval_context::{SentenceParts, ALSO_MET};
        // No trailing space: the joined line is collapsed to single spaces and trimmed, as the line without a
        // refusal is printed by the sink, so the two rows compare the head itself.
        let head = format!("failed to convert a string: {}", "word ".repeat(100))
            .trim_end()
            .to_string();
        let refusal = "the read of `Tags` was refused, at path /Resources/M/Tags";
        assert!(
            head.chars().count() > super::LONGEST_RECORDED_MESSAGE,
            "the head is past the plain bound"
        );
        let alone = Messages {
            custom_message: None,
            error_message: Some(head.clone()),
            location: None,
            refusal: false,
            parts: None,
        };
        let joined = Messages {
            custom_message: None,
            error_message: Some(format!("{head}{ALSO_MET}{refusal}")),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside(
                &head,
                refusal,
                crate::rules::eval_context::SentenceSlot::Error,
            )),
        };
        assert_eq!(
            (head.clone(), format!("{head}{ALSO_MET}{refusal}")),
            (
                super::error_line_text(&alone),
                super::error_line_text(&joined)
            ),
            "the same head whole on both rows, the refusal after the join on the second"
        );
        // Past the backstop the head yields: shorter than the same head alone, the remedy whole.
        let long_head = "word ".repeat(80).trim_end().to_string();
        let long_refusals = "remedy ".repeat(543).trim_end().to_string();
        assert_eq!(399, long_head.chars().count());
        let cut = super::error_line_text(&Messages {
            custom_message: None,
            error_message: Some(format!("{long_head}{ALSO_MET}{long_refusals}")),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside(
                &long_head,
                &long_refusals,
                crate::rules::eval_context::SentenceSlot::Error,
            )),
        });
        assert_eq!(
            (true, true, true),
            (
                cut.starts_with("word word") && cut.contains(&format!("...{ALSO_MET}")),
                cut.ends_with(&long_refusals),
                cut.chars().count() <= super::LONGEST_REFUSAL_MESSAGE
            ),
            "head 399 + refusals 3,800: the head cut to the room left, the remedy whole: {} characters",
            cut.chars().count()
        );
    }

    /// A plain head longer than the whole backstop, with one refusal joined: the per-resource block line
    /// cuts the HEAD first (to the room the backstop leaves, at most the plain bound), so the refusal and its
    /// remedy are present whole behind it and at most one marker appears; the same head with no refusal
    /// joined prints whole.
    ///
    /// Fails when the refusal or its remedy is gone behind the cut marker (the head spent the whole
    /// backstop), when the head is printed whole beside a refusal, or when the head alone is cut.
    #[test]
    fn a_head_longer_than_the_backstop_is_cut_first_and_the_refusal_stays_whole() {
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, ALSO_MET};
        let head = "word ".repeat(1000).trim_end().to_string();
        let refusal = "the read of `Tags` was refused, at path /Resources/M/Tags, where `X` is `Resources.*.Properties.Tags`: read it as the map's own entries";
        assert!(
            head.chars().count() > super::LONGEST_REFUSAL_MESSAGE,
            "the head is past the whole backstop"
        );
        let alone = Messages {
            custom_message: None,
            error_message: Some(head.clone()),
            location: None,
            refusal: false,
            parts: None,
        };
        let joined = Messages {
            custom_message: None,
            error_message: Some(format!("{head}{ALSO_MET}{refusal}")),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside(
                &head,
                refusal,
                SentenceSlot::Error,
            )),
        };
        let line = super::error_line_text(&joined);
        assert_eq!(
            (true, true, true),
            (
                line.contains(&format!("{ALSO_MET}{refusal}")),
                line.matches("word").count() < 1000,
                line.matches(super::REFUSAL_CUT_MARKER).count() <= 1,
            ),
            "the refusal and its remedy whole, the head cut, at most one marker: {}",
            line
        );
        assert_eq!(
            head,
            super::error_line_text(&alone),
            "the head with no refusal joined prints whole"
        );
    }

    /// The block line as it is PRINTED (through `emit_messages`, the console write path of the per-resource
    /// output), for a head that carries a line break and doubled spaces and is longer than the backstop, with
    /// one refusal joined: the printed lines hold the refusal and its remedy whole, the head is cut (it is
    /// the head that the cut names, not the refusal), and no more than one cut marker is printed. A text
    /// compared before the write step would not see what the write does to a break or a doubled space.
    ///
    /// Fails when the printed output lacks the refusal or its remedy, holds the whole head, or
    /// holds two markers.
    #[test]
    fn a_printed_block_line_with_a_broken_long_head_keeps_the_refusal_whole() {
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, ALSO_MET};
        let head = "word  word\nword ".repeat(500).trim_end().to_string();
        let refusal = "the read of `Tags` was refused, at path /Resources/M/Tags, where `X` is `Resources.*.Properties.Tags`: read it as the map's own entries";
        let joined = Messages {
            custom_message: None,
            error_message: Some(format!("{head}{ALSO_MET}{refusal}")),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside(
                &head,
                refusal,
                SentenceSlot::Error,
            )),
        };
        let mut written: Vec<u8> = Vec::new();
        super::emit_messages(&mut written, "  ", "", &super::error_line_text(&joined), 0)
            .expect("writing to a Vec cannot fail");
        let printed = String::from_utf8(written).expect("the output is UTF-8");
        assert_eq!(
            (true, true, true),
            (
                printed.contains(refusal),
                printed.matches("word").count() < 1000,
                printed.matches(super::REFUSAL_CUT_MARKER).count() <= 1,
            ),
            "the refusal whole, the head cut, at most one marker, as printed: {}",
            printed
        );
    }

    /// The head yields to the refusals on the block line. Three lines, each counted for both ends of a cut,
    /// the head's ellipsis before the join and the refusal marker at the end:
    /// - a head under the plain bound (299 characters) beside 3,800 characters of refusals, which together
    ///   with the join exceed the backstop by about 30: the head is cut to the room that is left, the
    ///   remedy is whole to its last character, and there is no refusal marker;
    /// - a head of 1,999 characters beside the same refusals: the head's ellipsis only, the remedy whole;
    /// - refusals of 4,500 characters beside a short head: the head whole, the refusal marker once at the
    ///   end, and no head ellipsis.
    #[test]
    fn the_head_yields_to_the_refusals_and_the_refusal_marker_is_for_refusals_that_exceed_the_backstop(
    ) {
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, ALSO_MET};
        let line_of = |head: &str, refusals: &str| {
            super::error_line_text(&Messages {
                custom_message: None,
                error_message: Some(format!("{head}{ALSO_MET}{refusals}")),
                location: None,
                refusal: false,
                parts: Some(SentenceParts::refusals_beside(
                    head,
                    refusals,
                    SentenceSlot::Error,
                )),
            })
        };
        let words = |word: &str, times: usize| word.repeat(times).trim_end().to_string();
        let counts = |line: &str| {
            (
                line.matches(super::REFUSAL_CUT_MARKER).count(),
                line.matches(&format!("...{ALSO_MET}")).count(),
            )
        };
        let medium_refusals = words("remedy ", 543);
        assert_eq!(3800, medium_refusals.chars().count());

        let head_300 = words("word ", 60);
        let line = line_of(&head_300, &medium_refusals);
        assert_eq!(
            ((0, 1), true, true),
            (
                counts(&line),
                line.ends_with(&medium_refusals),
                line.chars().count() <= super::LONGEST_REFUSAL_MESSAGE
            ),
            "head 300 + refusals 3,800: head ellipsis only, remedy whole, within the backstop: {} characters",
            line.chars().count()
        );

        let head_2000 = words("word ", 400);
        let line = line_of(&head_2000, &medium_refusals);
        assert_eq!(
            ((0, 1), true, true),
            (
                counts(&line),
                line.ends_with(&medium_refusals),
                line.chars().count() <= super::LONGEST_REFUSAL_MESSAGE
            ),
            "head 2,000 + refusals 3,800: head ellipsis only, remedy whole: {} characters",
            line.chars().count()
        );

        let long_refusals = words("remedy ", 643);
        assert_eq!(4500, long_refusals.chars().count());
        let short_head = "the head, short";
        let line = line_of(short_head, &long_refusals);
        assert_eq!(
            ((1, 0), true, true),
            (
                counts(&line),
                line.starts_with(&format!("{short_head}{ALSO_MET}")),
                line.ends_with(super::REFUSAL_CUT_MARKER)
            ),
            "refusals alone past the backstop: the marker once, the head whole, no head ellipsis"
        );

        // The floor: a tail of 4,090 characters leaves the head 6, under the floor of 80, so the head is
        // not cut to the room (it would be a fragment) and the backstop cuts the end of the line.
        let near_refusals = format!("{}abcd", "remedy ".repeat(580));
        assert_eq!(4064, near_refusals.chars().count());
        let head_50 = "word ".repeat(10).trim_end().to_string();
        let line = line_of(&head_50, &near_refusals);
        assert_eq!(
            ((1, 0), true),
            (
                counts(&line),
                line.starts_with(&format!("{head_50}{ALSO_MET}"))
            ),
            "tail 4,090, head 50: the head whole, no fragment, the marker once at the end: {} characters",
            line.chars().count()
        );
    }

    /// A sentence that gained only body marks joins them behind `a body clause also met` on the console in
    /// both bounds. Plain (the rule line and the unattributed section): a head over the plain bound is cut
    /// with its ellipsis and the marks follow whole behind the body joiner. Whole (the per-resource block
    /// line): the head stays whole while the line fits the backstop, and past it the head is cut to the room
    /// and the marks stay whole behind the same joiner. Fails when either bound words the marks with the
    /// condition joiner, or loses the marks.
    #[test]
    fn body_marks_keep_their_joiner_on_the_plain_and_the_whole_console_lines() {
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, BODY_ALSO_MET};
        let messages = |head: &str, marks: &str| Messages {
            custom_message: None,
            error_message: Some(format!("{head}{BODY_ALSO_MET}{marks}")),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside_groups(
                head,
                "",
                "",
                marks,
                SentenceSlot::Error,
            )),
        };
        let marks = "the read of `Tags` was refused, at path /Resources/M/Tags";
        let long_head = "word ".repeat(100).trim_end().to_string();
        let plain = super::joined_console_text(
            &messages(&long_head, marks),
            SentenceSlot::Error,
            super::HeadBound::Plain,
        )
        .expect("the plain line joins");
        assert_eq!(
            (true, true, false),
            (
                plain.contains(&format!("...{BODY_ALSO_MET}{marks}")),
                plain.ends_with(marks),
                plain.contains(crate::rules::eval_context::ALSO_MET)
            ),
            "plain: the head cut with its ellipsis, the marks whole behind the body joiner: {}",
            plain
        );
        let whole = super::error_line_text(&messages(&long_head, marks));
        assert_eq!(
            (true, false),
            (
                whole == format!("{long_head}{BODY_ALSO_MET}{marks}"),
                whole.contains(crate::rules::eval_context::ALSO_MET)
            ),
            "whole: the joined line fits the backstop, so the head stays whole: {}",
            whole
        );
        let remedy = "remedy ".repeat(543).trim_end().to_string();
        let past = super::error_line_text(&messages(&long_head, &remedy));
        assert_eq!(
            (true, true, true),
            (
                past.contains(&format!("...{BODY_ALSO_MET}")),
                past.ends_with(&remedy),
                past.chars().count() <= super::LONGEST_REFUSAL_MESSAGE
            ),
            "whole, past the backstop: the head cut to the room, the marks whole behind the body joiner"
        );
    }

    /// The head's budget under the floor is the floor, never the plain bound: a 320-character head beside
    /// refusals that leave it room 80 prints as 77 characters and an ellipsis with the remedy whole and no
    /// refusal marker; at room 79 the head prints the same 77 and an ellipsis and the remedy loses exactly
    /// one character to the backstop (an unbroken run has no word boundary within `BACKSTOP_BACKOFF`, so
    /// the cut is by count; a remedy of words would lose up to 16 more), where a budget that jumped to the plain bound would have cut about 240. A head longer than
    /// the floor beside a tail of 4,090 keeps the floor too, and a 500-character head with room 400 prints
    /// 320 characters and the ellipsis, as the released line does.
    ///
    /// Fails when the head at room 79 is longer than at room 80 (the cliff), when the remedy at room 80
    /// loses a character or carries the marker, when the remedy at room 79 loses other than one character,
    /// or when the head under the floor or over the room is not cut to the stated width.
    #[test]
    fn under_the_floor_the_head_keeps_the_floor_and_the_remedy_loses_only_the_shortfall() {
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, ALSO_MET};
        let line_of = |head: &str, refusals: &str| {
            super::error_line_text(&Messages {
                custom_message: None,
                error_message: Some(format!("{head}{ALSO_MET}{refusals}")),
                location: None,
                refusal: false,
                parts: Some(SentenceParts::refusals_beside(
                    head,
                    refusals,
                    SentenceSlot::Error,
                )),
            })
        };
        let head = "x".repeat(320);
        let kept_head = format!("{}...{ALSO_MET}", "x".repeat(77));
        let at_80 = "r".repeat(super::LONGEST_REFUSAL_MESSAGE - ALSO_MET.chars().count() - 80);
        let at_79 = "r".repeat(at_80.chars().count() + 1);
        let (line_80, line_79) = (line_of(&head, &at_80), line_of(&head, &at_79));
        assert_eq!(
            (true, true, 0, true, 1),
            (
                line_80.starts_with(&kept_head),
                line_80.ends_with(&at_80),
                line_80.matches(super::REFUSAL_CUT_MARKER).count(),
                line_79.starts_with(&kept_head),
                line_79.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "room 80: head 77 + ellipsis, remedy whole, no marker; room 79: the same head, the marker once"
        );
        // At room 79 the line is one over the backstop, so the remedy loses exactly one character (no
        // word boundary within the back-off, so the cut is by count), then the ellipsis and the marker.
        let kept_remedy = &at_79[..at_79.len() - 1];
        assert_eq!(
            (true, false),
            (
                line_79.contains(&format!("{kept_remedy}... {}", super::REFUSAL_CUT_MARKER)),
                line_79.contains(&at_79)
            ),
            "room 79: the remedy short by exactly one character, the marker after the ellipsis"
        );
        // A head over the plain bound beside room for more than 323 keeps the released shape: 320 characters
        // and the ellipsis, no marker, the remedy whole.
        let at_400 = "r".repeat(super::LONGEST_REFUSAL_MESSAGE - ALSO_MET.chars().count() - 400);
        let long_head = "x".repeat(500);
        let line_400 = line_of(&long_head, &at_400);
        assert_eq!(
            (
                true,
                true,
                0,
                320 + 3 + ALSO_MET.chars().count() + at_400.chars().count()
            ),
            (
                line_400.starts_with(&format!("{}...{ALSO_MET}", "x".repeat(320))),
                line_400.ends_with(&at_400),
                line_400.matches(super::REFUSAL_CUT_MARKER).count(),
                line_400.chars().count()
            ),
            "room 400: the head 320 and its ellipsis (323), the remedy whole, no marker"
        );
        let near = format!("{}abcd", "remedy ".repeat(580));
        let line = line_of(&head, &near);
        assert_eq!(
            (true, 1),
            (
                line.starts_with(&kept_head),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "tail 4,090, head 320: the head keeps the floor and the end of the line carries the marker"
        );
        // A head of WORDS under the floor: the word back-off may not take it below the floor, so at room 80
        // it prints the same 77 characters and an ellipsis as the unbroken head (a back-off alone would
        // have ended it at a word 61 or so characters in), and with room for more it ends at a word
        // boundary that is still at or above the floor.
        let words_head = "abcdefg ".repeat(40);
        let kept_words = format!("{}...{ALSO_MET}", &words_head[..77]);
        let line_words_80 = line_of(&words_head, &at_80);
        assert!(
            line_words_80.starts_with(&kept_words),
            "room 80, a head of words: 77 characters by count and the ellipsis, not a shorter word back-off: {:?}",
            line_words_80
        );
        let at_120 = "r".repeat(super::LONGEST_REFUSAL_MESSAGE - ALSO_MET.chars().count() - 120);
        let line_words_120 = line_of(&words_head, &at_120);
        let head_part = line_words_120
            .split_once(&format!("...{ALSO_MET}"))
            .map(|(head, _)| head.to_string())
            .expect("the head was cut and its ellipsis precedes the joiner");
        assert_eq!(
            (true, true),
            (
                head_part.chars().count() + 3 >= super::HEAD_FLOOR,
                head_part.ends_with("abcdefg")
            ),
            "room 120, a head of words: cut at a word boundary, printed width at least the floor: {head_part:?}"
        );
    }

    /// Every refusal line takes the one bounded cut (`backstop`, through `cut_bounded`): it backs up to a
    /// word boundary at most 16 characters, never before the last real joiner, and otherwise cuts by
    /// count, so the remedy is present and the marker appears once. Each row names the cutter it refutes
    /// (`cut_to`: the released walk back to the last whitespace; the punctuation guard: a cutter that took
    /// any `:` or `;` before a space for a joiner; the early floor: one that applied the floor before the
    /// trim and the move back out of an escape; the floor-0 line: one that gave a single-string refusal
    /// line no floors) and is green on this one:
    /// - path 1, a refusal-headed joined sentence on the block line with an unbroken refusal (refutes
    ///   `cut_to`): it walked back to the head joiner's trailing space and printed
    ///   `head; the condition also met:...`;
    /// - path 2, the plain arm's refusal part with two listed refusals, `R1; ` then an unbroken one
    ///   (refutes `cut_to`): it walked back to the space after `R1;` and dropped the second whole;
    /// - path 3, an unjoined refusal `fix: ` and an unbroken remedy (refutes `cut_to`): it walked back to
    ///   `fix:`;
    /// - path 4, prose with `: ` inside the window (passes on `cut_to`, whose walk back also ends at
    ///   ` see Tags:`; refutes the punctuation guard): it cut a half word; only the sentence's real
    ///   joiners are floors, so the cut is at the word boundary;
    /// - path 5, the joiner ending 5 characters before the bound (refutes `cut_to`): the cut is not backed
    ///   into the joiner;
    /// - path 6, an escape right behind the joiner, cut inside (refutes the early floor): the move back
    ///   would take the joiner's space;
    /// - path 7, a line with no parts, `R1; ` and an unbroken second refusal near the bound (refutes the
    ///   floor-0 line): the second refusal's prefix stays;
    /// - path 7 again, the same shape as `A; B` with `A` of 4,087 characters, so the space after `A;` sits
    ///   inside the window (refutes the floor-0 line): `B` keeps its prefix behind the boundary;
    /// - path 8, a head with a space at its 77th character at room 80 (refutes the early floor): the head
    ///   prints exactly 80 with its ellipsis;
    /// - path 9, the text of path 5 as ONE string with no parts (refutes a cutter that gave a single
    ///   string no joiner floors): the joiner text inside the string is a floor, so the cut is the one the
    ///   joined form takes. A head after a `; ` inside one string is the next cell's.
    ///
    /// Ten assertion blocks in all, one per path above and two for path 7, in the body's order 1, 2, 3, 5,
    /// 9, 6, 7, 7, 8, 4. Fails when a line loses its refusal whole, keeps other than the bound's characters
    /// on paths 1 to 3 and 7, carries the marker other than once, prints a head under 80, cuts the
    /// single-string form of path 9 other than the joined form, or ends in a half word on path 4.
    #[test]
    fn every_refusal_line_keeps_its_remedy_to_within_the_back_off_and_the_marker_once() {
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, ALSO_MET};
        let marker = format!(" {}", super::REFUSAL_CUT_MARKER);
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        // The text kept before the ellipsis and the marker, or None when the line was not cut.
        let kept_of = |line: &str| {
            line.strip_suffix(marker.as_str())
                .and_then(|cut| cut.strip_suffix("..."))
                .map(str::to_string)
        };
        let messages_of = |head: &str, refusals: &str, refusal: bool| Messages {
            custom_message: None,
            error_message: Some(format!("{head}{ALSO_MET}{refusals}")),
            location: None,
            refusal,
            parts: Some(SentenceParts::refusals_beside(
                head,
                refusals,
                SentenceSlot::Error,
            )),
        };
        let head = "the condition could not be evaluated";
        let unbroken = "r".repeat(bound + 900);

        // Path 1, a refusal-headed sentence on the block line, an unbroken refusal behind the head's
        // joiner. A cutter that backed up to the last whitespace would stop at the joiner's own trailing
        // space and print `head; the condition also met:...` with the whole refusal gone.
        let line = super::error_line_text(&messages_of(head, &unbroken, true));
        let kept =
            kept_of(&line).expect("a refusal-headed line over the backstop is cut and marked");
        let prefix = format!("{head}{ALSO_MET}");
        assert_eq!(
            (true, bound, 1),
            (
                kept.starts_with(&format!("{prefix}rrrr")),
                kept.chars().count(),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "refusal-headed block line: the unbroken refusal is cut by count behind the joiner, never dropped"
        );

        // Path 2, the plain arm's refusal part, two listed refusals: `R1; ` and an unbroken one. A cutter
        // that backed up to the space after `R1;` would drop the second refusal whole.
        let listed = format!("R1; {unbroken}");
        let (plain, _) = super::joined_console_parts(
            &messages_of(head, &listed, false),
            SentenceSlot::Error,
            super::HeadBound::Plain,
        )
        .expect("the parts join refusals");
        let kept = plain
            .strip_prefix(&prefix)
            .and_then(kept_of)
            .expect("the plain arm keeps the head and the joiner and marks the cut refusals");
        assert_eq!(
            (true, bound, 1),
            (
                kept.starts_with("R1; rrrr"),
                kept.chars().count(),
                plain.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "plain arm: the second, unbroken refusal keeps the bound behind `R1; ` and the marker follows once"
        );

        // Path 3, an unjoined refusal's Error line: a prefix with a space, then an unbroken remedy.
        let unjoined = Messages {
            custom_message: None,
            error_message: Some(format!("fix: {unbroken}")),
            location: None,
            refusal: true,
            parts: None,
        };
        let line = super::error_line_text(&unjoined);
        let kept = kept_of(&line).expect("an unjoined refusal over the backstop is cut and marked");
        assert_eq!(
            (true, bound, 1),
            (
                kept.starts_with("fix: rrrr"),
                kept.chars().count(),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "unjoined Error line: the remedy is present up to the bound, never walked back to the prefix"
        );

        // Path 5, the joiner's space 5 characters before the bound: the floor holds, the cut is not backed
        // into the joiner and the five characters after it stay (marker once).
        let near_head = "h".repeat(bound - 5 - ALSO_MET.chars().count());
        let line = super::error_line_text(&messages_of(&near_head, &unbroken, true));
        let kept = kept_of(&line).expect("the line is cut and marked");
        assert_eq!(
            (true, bound, 1),
            (
                kept.ends_with(&format!("{ALSO_MET}rrrrr")),
                kept.chars().count(),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "the joiner ends 5 characters before the bound: the cut stays after it"
        );

        // Path 9, the text of path 5 as ONE string with no parts (a rule reference's "text; callee error"
        // where the callee's sentence carries a joined refusal): the joiner text it holds is a floor, so
        // the cut is the one the joined form takes and R's prefix stays.
        let one_string = Messages {
            custom_message: None,
            error_message: Some(format!("{near_head}{ALSO_MET}{unbroken}")),
            location: None,
            refusal: true,
            parts: None,
        };
        let partless = kept_of(&super::error_line_text(&one_string)).expect("the line is cut");
        let joined = kept_of(&super::error_line_text(&messages_of(
            &near_head, &unbroken, true,
        )))
        .expect("the line is cut");
        assert_eq!(
            (true, joined),
            (partless.ends_with(&format!("{ALSO_MET}rrrrr")), partless),
            "a joiner inside a single string is a floor: the parts-less text is cut as the joined form is"
        );

        // Path 6, a refusal that starts with an escape right behind the joiner, the count cut inside the
        // escape: the move back out of the escape would land on the joiner's end and its trim would take the
        // joiner's space (`... also met:... [explanation cut ...]`). The floor is applied last, so the cut is
        // at the escape's start, untrimmed: the joiner's space stays and no fragment of the escape prints.
        let esc_head = "h".repeat(bound - 3 - ALSO_MET.chars().count());
        let escapes = "\u{1b}".repeat(40);
        let line = super::error_line_text(&messages_of(&esc_head, &escapes, true));
        let kept = kept_of(&line).expect("the line is cut and marked");
        assert_eq!(
            (true, false, 1),
            (
                kept.ends_with(ALSO_MET),
                kept.contains("\\u{"),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "an escape right behind the joiner, cut inside: cut at its start with the joiner's space, no fragment"
        );

        // Path 7, a line with no parts, `R1; ` and an unbroken second refusal starting within 16 of the bound:
        // the `; ` is a boundary, so the cut keeps the second refusal's first characters, as a joined
        // sentence's body does (a cutter that backed up to the space after `R1;` would drop it whole).
        let unjoined_refusals = Messages {
            custom_message: None,
            error_message: Some(format!("{}R1; {}", "f".repeat(bound - 9), "r".repeat(900))),
            location: None,
            refusal: true,
            parts: None,
        };
        let line = super::error_line_text(&unjoined_refusals);
        let kept = kept_of(&line).expect("the line is cut and marked");
        assert_eq!(
            (true, bound, 1),
            (
                kept.ends_with("R1; rrrrr"),
                kept.chars().count(),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "a refusal line without parts: the boundary after `R1;` is a floor, the second refusal keeps its prefix"
        );

        // Path 7, the same text as `A; B` with A of 4,087 characters: the space after `A;` sits in the window.
        let a_then_b = Messages {
            custom_message: None,
            error_message: Some(format!("{}; {}", "a".repeat(4087), "b".repeat(900))),
            location: None,
            refusal: true,
            parts: None,
        };
        let line = super::error_line_text(&a_then_b);
        let kept = kept_of(&line).expect("the line is cut and marked");
        assert_eq!(
            (true, 1),
            (
                kept.ends_with("; bbbbbbb"),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "`A; B`: B keeps its prefix behind the boundary"
        );

        // Path 8, a block-line head whose space is at its 77th character, at room 80: the trim would print 79
        // characters with the ellipsis; the floor is applied last, so the head prints exactly 80.
        let space_head = format!("{} {}", "a".repeat(76), "b".repeat(300));
        let at_80 = "r".repeat(bound - ALSO_MET.chars().count() - 80);
        let line = super::error_line_text(&Messages {
            custom_message: None,
            error_message: Some(format!("{space_head}{ALSO_MET}{at_80}")),
            location: None,
            refusal: false,
            parts: Some(SentenceParts::refusals_beside(
                &space_head,
                &at_80,
                SentenceSlot::Error,
            )),
        });
        assert!(
            line.starts_with(&format!("{} ...{ALSO_MET}", "a".repeat(76))),
            "the head prints 80 characters with its ellipsis, the space at 77 kept: {:?}",
            &line[..90.min(line.len())]
        );

        // Path 4, ordinary prose with a `: ` inside the window is no joiner: the cut backs up to the word
        // boundary and prints no half word (`... see Tags: re...` was the output of a cutter that took
        // any `:` before a space for a joiner).
        let prose = Messages {
            custom_message: None,
            error_message: Some(format!(
                "{}{}",
                "r".repeat(bound - 13),
                " see Tags: remedy words"
            )),
            location: None,
            refusal: true,
            parts: None,
        };
        let line = super::error_line_text(&prose);
        let kept = kept_of(&line).expect("a refusal over the backstop is cut and marked");
        assert_eq!(
            (true, 1),
            (
                kept.ends_with(" see Tags:"),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "prose with a colon in the window: cut at the word boundary, no half word"
        );
    }

    /// A rule reference's text, `<reference text>; <callee error>`, arrives as ONE string, and the callee's
    /// error opens with a head the evaluator writes before the error it quotes (`WHEN_UNEVALUATED_HEAD`,
    /// which ends in `: `). The head's end stands right after the `; ` boundary, 5 characters before the
    /// bound, and the refusal behind it is unbroken: the head's end is a floor (`joined_line`: a known head
    /// at the start of a body or right after a `; `), so the cut stays 5 characters into the refusal and
    /// its prefix prints, with the marker once. The callee error as a GROUP of a joined sentence (the
    /// reference text as the head, the group behind a joiner) is cut at the same place: 5 characters into
    /// the refusal, at the bound. Fails when the cut backs off to the head's trailing space (the floor taken
    /// only for a head at the string's start) and the refusal's first characters are dropped, or the two
    /// routes cut differently.
    #[test]
    fn a_head_after_a_boundary_inside_one_string_keeps_the_refusals_prefix() {
        use crate::rules::eval::WHEN_UNEVALUATED_HEAD;
        use crate::rules::eval_context::{SentenceParts, SentenceSlot, ALSO_MET};
        let marker = format!(" {}", super::REFUSAL_CUT_MARKER);
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let kept_of = |line: &str| {
            line.strip_suffix(marker.as_str())
                .and_then(|cut| cut.strip_suffix("..."))
                .map(str::to_string)
        };
        let head = WHEN_UNEVALUATED_HEAD;
        let unbroken = "r".repeat(bound + 900);
        // `<reference>; <head><refusal>`, the head ending 5 characters before the bound.
        let reference = "f".repeat(bound - 5 - head.chars().count() - 2);
        let one_string = Messages {
            custom_message: None,
            error_message: Some(format!("{reference}; {head}{unbroken}")),
            location: None,
            refusal: true,
            parts: None,
        };
        let line = super::error_line_text(&one_string);
        let kept = kept_of(&line).expect("the line is cut and marked");
        assert_eq!(
            (true, bound, 1),
            (
                kept.ends_with(&format!("{head}rrrrr")),
                kept.chars().count(),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "a head right after the `; ` boundary is a floor: the refusal keeps its first characters"
        );
        // The same text as a joined sentence's pieces: the reference text as the head, the callee error as
        // the condition group behind a joiner of the same width as `; ` plus the head. The kept text is the
        // same as the one string's, since both routes read one floor rule.
        let joiner_width = ALSO_MET.chars().count();
        let reference = "f".repeat(bound - 5 - head.chars().count() - joiner_width);
        let callee = format!("{head}{unbroken}");
        let as_pieces = Messages {
            custom_message: None,
            error_message: Some(format!("{reference}{ALSO_MET}{callee}")),
            location: None,
            refusal: true,
            parts: Some(SentenceParts::refusals_beside(
                &reference,
                &callee,
                SentenceSlot::Error,
            )),
        };
        let joined = kept_of(&super::error_line_text(&as_pieces)).expect("the line is cut");
        assert_eq!(
            (true, bound),
            (
                joined.ends_with(&format!("{head}rrrrr")),
                joined.chars().count()
            ),
            "the joined route reads the same head floor inside its group"
        );
    }

    /// The path-9 shape with NON-ASCII text before the joiner: a head of two-, three- and four-byte
    /// characters (accented letters, CJK, a mathematical letter) so that the joiner inside the one string
    /// ends 5 characters before the bound while its BYTE offset lies far past the bound. The floor at the
    /// joiner's end is a character offset (`joined_line` counts the bytes before it as characters before it
    /// tests the backstop), so the cut stays 5 characters into the refusal: the kept text ends
    /// `<joiner>rrrrr`, counts exactly the bound in characters, and the marker appears once. The first
    /// non-ASCII row of the cutter: every other row is ASCII, where bytes and characters agree. Fails when a
    /// byte offset is tested against the character limit and the floor is skipped, so the cut backs off into
    /// the joiner's trailing space and the refusal's prefix is dropped.
    #[test]
    fn a_joiner_after_multi_byte_text_inside_one_string_is_still_a_floor() {
        use crate::rules::eval_context::ALSO_MET;
        let marker = format!(" {}", super::REFUSAL_CUT_MARKER);
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let kept_of = |line: &str| {
            line.strip_suffix(marker.as_str())
                .and_then(|cut| cut.strip_suffix("..."))
                .map(str::to_string)
        };
        let wide_head: String = ['\u{e9}', '\u{4e2d}', '\u{1d538}']
            .iter()
            .cycle()
            .take(bound - 5 - ALSO_MET.chars().count())
            .collect();
        assert!(
            wide_head.len() > bound,
            "the head's bytes exceed the bound while its characters stay under it: {} bytes",
            wide_head.len()
        );
        let unbroken = "r".repeat(bound + 900);
        let one_string = Messages {
            custom_message: None,
            error_message: Some(format!("{wide_head}{ALSO_MET}{unbroken}")),
            location: None,
            refusal: true,
            parts: None,
        };
        let line = super::error_line_text(&one_string);
        let kept = kept_of(&line).expect("the line is cut and marked");
        assert_eq!(
            (true, bound, 1),
            (
                kept.ends_with(&format!("{ALSO_MET}rrrrr")),
                kept.chars().count(),
                line.matches(super::REFUSAL_CUT_MARKER).count()
            ),
            "a joiner after multi-byte text: its end is a floor in characters, the refusal's prefix stays"
        );
    }

    /// One floor set for one text, however it arrives: the same sentence built as the pieces of a joined
    /// sentence (a head, then each group behind its joiner) and as ONE string yields the same line and the
    /// same floors from `joined_line`, because the floors are read off the assembled line and not off the
    /// pieces. Three texts: an ASCII head with two groups whose second refusal opens with a known head after
    /// a `; ` (a head floor at a boundary inside a body, where the pieces route sees a piece start and the
    /// one-string route a `; `); the same with a head that opens a group right after a joiner (a boundary
    /// the pieces route sees as a piece start and the one-string route as a joiner end); and the non-ASCII
    /// head of the cell above. No body here starts or ends in whitespace: the pieces route trims each body
    /// (`one_line`) while the one-string route keeps interior whitespace as written, so the two assembled
    /// lines agree only for a text with no such whitespace at a boundary, which is every text the writers
    /// produce. Fails when either route records a floor the other does not.
    #[test]
    fn the_same_text_yields_the_same_floors_as_pieces_and_as_one_string() {
        use crate::rules::eval::WHEN_UNEVALUATED_HEAD;
        use crate::rules::eval_context::{ALSO_MET, BODY_ALSO_MET};
        let bound = super::LONGEST_REFUSAL_MESSAGE;
        let head = WHEN_UNEVALUATED_HEAD;
        let wide_head: String = ['\u{e9}', '\u{4e2d}', '\u{1d538}']
            .iter()
            .cycle()
            .take(bound - 5 - ALSO_MET.chars().count())
            .collect();
        let texts: Vec<(&str, Vec<(&str, String)>)> = vec![
            (
                "a head after a `; ` inside a group, two groups",
                vec![
                    ("", String::from("the rule failed")),
                    (ALSO_MET, format!("R1; {head}R2")),
                    (BODY_ALSO_MET, String::from("B1; B2")),
                ],
            ),
            (
                "a head opening a group right after its joiner",
                vec![
                    ("", String::from("the rule failed")),
                    (ALSO_MET, format!("{head}R1")),
                    (BODY_ALSO_MET, String::from("B1")),
                ],
            ),
            (
                "a multi-byte head before the joiner",
                vec![("", wide_head), (ALSO_MET, "r".repeat(bound + 900))],
            ),
        ];
        for (label, pieces) in &texts {
            let as_pieces: Vec<(&str, &str)> = pieces
                .iter()
                .map(|(joiner, body)| (*joiner, body.as_str()))
                .collect();
            let mut one_string = String::new();
            for (joiner, body) in pieces {
                one_string.push_str(joiner);
                one_string.push_str(body);
            }
            let (line_from_pieces, ends_from_pieces) = super::joined_line(&as_pieces);
            let (line_from_string, ends_from_string) = super::joined_line(&[("", &one_string)]);
            assert_eq!(
                (line_from_pieces, ends_from_pieces),
                (line_from_string, ends_from_string),
                "{label}: the line and its floors read the same from the pieces and from one string"
            );
        }
        // The floors themselves for the head that opens a group right after its joiner, from the text's own
        // character lengths, so an equality of two empty or two short vectors cannot pass: the `; ` that
        // opens the condition joiner, that joiner's end, the head's end right after it, the `; ` that opens
        // the body joiner, and that joiner's end; nothing else (the head and the refusals hold no `; `).
        let (_, ends) = super::joined_line(&[
            ("", "the rule failed"),
            (ALSO_MET, &format!("{head}R1")),
            (BODY_ALSO_MET, "B1"),
        ]);
        let joiner_end = "the rule failed".chars().count() + ALSO_MET.chars().count();
        let head_end = joiner_end + head.chars().count();
        let body_joiner_start = head_end + "R1".chars().count();
        assert_eq!(
            vec![
                "the rule failed".chars().count() + 2,
                joiner_end,
                head_end,
                body_joiner_start + 2,
                body_joiner_start + BODY_ALSO_MET.chars().count(),
            ],
            ends,
            "the floors of a head opening a group right after its joiner, in character offsets"
        );
    }

    /// A rule's `Error` line for a refusal-shaped record whose parts joined refusals is the recorded
    /// sentence through the refusal pipeline, never a clause-shaped rebuild of "head message": the retrieval
    /// error arm's `refusal_lines` filters to clause-shaped parts, and a record whose parts are a join takes
    /// the sentence as recorded. The sentence an author's body displaced prints through the console's one
    /// pipeline under its kind too.
    ///
    /// Fails when `refusal_lines` returns the head and the message joined by a space (the clause
    /// rebuild), or drops the sentence.
    #[test]
    fn a_joined_sentence_is_never_laid_out_as_a_clause_shaped_head_and_message() {
        use crate::rules::eval_context::{RuleReport, SentenceParts, ALSO_MET};
        let head = "the condition could not be evaluated";
        let refusal = "the read of `A` was refused, at path /Resources/A/Tags";
        let sentence = format!("{head}{ALSO_MET}{refusal}");
        let messages = Messages {
            custom_message: None,
            error_message: Some(sentence.clone()),
            location: None,
            refusal: true,
            parts: Some(SentenceParts::refusals_beside(
                head,
                refusal,
                crate::rules::eval_context::SentenceSlot::Error,
            )),
        };
        let (error, reason) = super::refusal_lines(&messages, "");
        assert_eq!(
            (sentence.clone(), None),
            (error, reason),
            "the recorded sentence, not `head message`"
        );
        let body = RuleReport {
            name: "gated",
            messages: Messages {
                custom_message: Some("the author's body".to_string()),
                error_message: Some(sentence.clone()),
                location: None,
                refusal: false,
                parts: Some(SentenceParts::refusals_beside(
                    head,
                    refusal,
                    crate::rules::eval_context::SentenceSlot::Error,
                )),
            },
            custom_slot: crate::rules::CustomSlot::Author,
            ..Default::default()
        };
        assert_eq!(
            Some(sentence),
            super::joined_rule_sentence(&body),
            "an author's body on the call: the displaced sentence is the one joined, in the error slot"
        );
    }

    /// A plain head over the recorded-message bound with a long refusal joined to it is cut at the plain
    /// bound and the refusal is printed whole, remedy included, at BOTH places the console prints a rule's
    /// sentence: the per-resource `Rule = { }` arm and the unattributed section's entry, and with or without a
    /// `<< >>` body on the call (the body takes the author's slot and the sentence moves to the error slot).
    ///
    /// Fails when a row prints the head whole (the run of words survives), cuts the refusal, or
    /// loses the ellipsis before the join.
    #[test]
    fn a_long_plain_head_is_cut_and_its_joined_refusal_is_whole_in_both_arms_with_and_without_a_body(
    ) {
        use super::{
            collect_unattributed_explanations, pprint_clauses, LocalResourceAggr, Rendered,
        };
        use crate::rules::eval_context::{RuleReport, SentenceParts, ALSO_MET};
        use std::collections::{BTreeSet, HashSet};
        let head = format!("failed to convert a string: {}", "word ".repeat(100));
        // Longer than the plain bound (its remedy padded), so a regression that cuts every part at the plain
        // bound cuts it here and the cell reads it.
        let refusal = format!(
            "the read of `Tags` was refused, at path /Resources/M/Tags, where `X` is `Resources.*.Properties.Tags`: read it as the map's own entries; {}",
            "then name each entry in the clause, one at a time, ".repeat(8).trim_end()
        );
        assert!(
            refusal.chars().count() > super::LONGEST_RECORDED_MESSAGE,
            "the refusal is past the plain bound, or the cell proves nothing about it"
        );
        let refusal = refusal.as_str();
        let whole = format!("{head}{ALSO_MET}{refusal}");
        let in_slot = |slot| SentenceParts::refusals_beside(&head, refusal, slot);
        let resource = LocalResourceAggr {
            name: "R".to_string(),
            resource_type: "AWS::Example::Thing",
            cdk_path: None,
            clauses: HashSet::new(),
            paths: BTreeSet::new(),
        };
        let rows = [
            (
                "no body",
                Messages {
                    custom_message: Some(whole.clone()),
                    error_message: None,
                    location: None,
                    refusal: false,
                    parts: Some(in_slot(crate::rules::eval_context::SentenceSlot::Custom)),
                },
                crate::rules::CustomSlot::Evaluator,
            ),
            (
                "a body",
                Messages {
                    custom_message: Some("the author's body".to_string()),
                    error_message: Some(whole.clone()),
                    location: None,
                    refusal: false,
                    parts: Some(in_slot(crate::rules::eval_context::SentenceSlot::Error)),
                },
                crate::rules::CustomSlot::Author,
            ),
        ];
        for (label, messages, custom_slot) in rows {
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
            let per_resource = String::from_utf8(written).expect("the output is UTF-8");
            let rendered = Rendered::of(std::iter::empty::<&LocalResourceAggr>());
            let mut entries = Vec::new();
            collect_unattributed_explanations(&report, None, &rendered, &mut entries);
            let unattributed = entries
                .iter()
                .map(|(_, text)| text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            for (arm, text) in [
                ("per-resource", per_resource.as_str()),
                ("unattributed", unattributed.as_str()),
            ] {
                // Counted, not searched for the whole run of words: the line is collapsed to one space
                // between words and trimmed, so a search for the full run (with its trailing space) is
                // vacuous. A head cut at the plain bound keeps well under the hundred words it quotes.
                assert!(
                    text.matches("word").count() < 100
                        && text.contains(&format!("...{ALSO_MET}{refusal}")),
                    "({}, {}) the head is cut at the plain bound with the ellipsis before the join, and the refusal is whole with its remedy:\n{}",
                    label,
                    arm,
                    text
                );
            }
        }
    }

    /// `cut_to` says whether it dropped anything, from the branch that drops it, and its two readers take
    /// that answer: text of exactly the bound (after the collapse) is returned whole and unflagged, one
    /// character more is cut and flagged, and whitespace around a short text is no cut. `backstop` marks
    /// a text only when the cutter flagged it, and `plain_author_message` passes the flag on.
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
                // The flag follows the slot, as the report builder writes it.
                messages: match custom_slot {
                    crate::rules::CustomSlot::Author => messages,
                    _ => Messages {
                        refusal: custom_slot == crate::rules::CustomSlot::Refusal,
                        ..messages
                    },
                },
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
            .map(|parts| parts.head())
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
            parts: Some(SentenceParts::clause(head, REFUSAL)),
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
    /// Fails when the author's joiner or mark is written as `\u{200d}` or `\u{200f}`, when the
    /// zero-width space is written raw, or when the reason keeps the joiner raw.
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
    /// Fails when the joined text is not registered (`is_refusal` false), when the section
    /// prints it cut mid-sentence under the refusal flag, or when the plain-flag copy is not
    /// cut at the plain bound.
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
    /// Fails when the section prints the ESC raw (an uncut message was passed through the
    /// cutter alone), when the two readings of the rule record's slot differ, when the joiner
    /// row reads a set other than the origin's, or when the cut leaves `\u{` at the end of the
    /// line.
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
    /// Fails when the unattributed entry or the rule-level slot holds the joiner raw while the
    /// `Error =` line holds its escape.
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
    /// Fails when the author's row prints `\u{200d}` on either line (the arm or the printer
    /// reads the strict set for the author's body), or when the evaluator's row keeps the
    /// joiner raw.
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

    /// A rule's body is listed as undecidable only when nothing beneath the rule is rendered per resource.
    /// The per-resource printer places block and clause nodes alone, so a check that is a disjunction or a
    /// called rule is never "shown" itself; the test looks through them for a rendered block or clause. Rows:
    /// a block check nothing rendered (listed); the same block rendered (not listed); a disjunction holding
    /// a block nothing rendered (listed); the same block rendered (not listed: a decided body goes with the
    /// clause entries and is not announced as undecidable).
    ///
    /// Fails when a rule whose descendant block is rendered is listed too (the test looks one level
    /// down), or when a rule with nothing rendered is not listed.
    #[test]
    fn a_rules_body_is_listed_as_undecidable_only_when_no_descendant_is_rendered() {
        use super::IdentityHash;
        use crate::rules::eval_context::{DisjunctionsReport, GuardBlockReport};
        use std::collections::{BTreeSet, HashSet};
        let block = || {
            ClauseReport::Block(GuardBlockReport {
                context: String::from("Resources.*.Properties.A == 'x'"),
                messages: Messages {
                    custom_message: None,
                    error_message: Some(String::from("a decided failure")),
                    location: None,
                    refusal: false,
                    parts: None,
                },
                unresolved: None,
            })
        };
        let rule_over = |checks: Vec<ClauseReport<'static>>| {
            ClauseReport::Rule(RuleReport {
                name: "check",
                messages: Messages {
                    custom_message: Some(String::from("the body")),
                    error_message: None,
                    location: None,
                    refusal: false,
                    parts: None,
                },
                checks,
                custom_slot: CustomSlot::Author,
                ..Default::default()
            })
        };
        fn first_block<'a>(check: &'a ClauseReport<'static>) -> &'a ClauseReport<'static> {
            match check {
                ClauseReport::Rule(rule) => first_block(&rule.checks[0]),
                ClauseReport::Disjunctions(ors) => first_block(&ors.checks[0]),
                other => other,
            }
        }
        let listed = |report: &ClauseReport<'static>, rendered_block: bool| {
            let mut aggr = LocalResourceAggr {
                name: String::new(),
                resource_type: "",
                cdk_path: None,
                clauses: HashSet::new(),
                paths: BTreeSet::new(),
            };
            if rendered_block {
                aggr.clauses.insert(IdentityHash {
                    key: first_block(report),
                });
            }
            let rendered = Rendered::of(std::iter::once(&aggr));
            let mut entries = Vec::new();
            collect_unattributed_explanations(report, None, &rendered, &mut entries);
            entries.iter().any(|(context, _)| context == "rule check")
        };
        let direct = rule_over(vec![block()]);
        let through_a_disjunction =
            rule_over(vec![ClauseReport::Disjunctions(DisjunctionsReport {
                checks: vec![block()],
            })]);
        // The block under a CALLED rule, the inner rule named differently from the outer ("callee" under
        // "check"), so the `rule check` entry probed for is the outer rule's alone and can never be the
        // inner entry: deleting the called-rule arm of `Rendered::shows_any` lists the outer rule though
        // the callee's block was rendered.
        let through_a_callee = rule_over(vec![ClauseReport::Rule(RuleReport {
            name: "callee",
            messages: Messages {
                custom_message: Some(String::from("the callee's body")),
                error_message: None,
                location: None,
                refusal: false,
                parts: None,
            },
            checks: vec![block()],
            custom_slot: CustomSlot::Author,
            ..Default::default()
        })]);
        assert_eq!(
            vec![true, false, true, false, true, false],
            vec![
                listed(&direct, false),
                listed(&direct, true),
                listed(&through_a_disjunction, false),
                listed(&through_a_disjunction, true),
                listed(&through_a_callee, false),
                listed(&through_a_callee, true),
            ],
            "the body is listed as undecidable exactly when no block beneath it is rendered, through a disjunction or a called rule as directly"
        );
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
    /// Fails when the author's joiner is written as its escape, or when the evaluator's joiner is
    /// written raw.
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
    /// Fails when the output holds the ESC byte of the conceal, or when the green or the reset is
    /// written as text.
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
    /// Fails when the first two rows are trimmed or joined, or when the third is not joined.
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

#[cfg(test)]
mod resource_header_tests {
    use super::write_resource_header;

    /// The header's three template fields (the logical id, the `Type`, the `aws:cdk:path`) reach the console
    /// as their escapes: an ESC and a C1 control in each is written as text, no raw control is left in the
    /// output, and the escaped spelling of each appears. The controls are built with `char::from`, since the
    /// source holds no raw control; the colour is off, so the output depends on no global setting.
    ///
    /// Fails when a raw ESC byte appears in the output, or when a field is written without its
    /// escape.
    #[test]
    fn the_resource_header_escapes_its_template_fields() {
        let esc = char::from(0x1b);
        let c1 = char::from(0x9b);
        let name = format!("Id{esc}[31m{c1}x");
        let resource_type = format!("AWS::T{esc}[8m{c1}y");
        let cdk_path = format!("Stack/Path{esc}[2J{c1}z");
        let mut out: Vec<u8> = Vec::new();
        write_resource_header(&mut out, &name, &resource_type, &cdk_path, false)
            .expect("writing to a Vec cannot fail");
        let written = String::from_utf8(out).expect("utf8");
        assert!(
            !written.contains(esc) && !written.contains(c1),
            "no raw control is left in the header: {:?}",
            written
        );
        for (field, spelled) in [
            ("logical id", "Id\\u{1b}[31m\\u{9b}x"),
            ("Type", "AWS::T\\u{1b}[8m\\u{9b}y"),
            ("CDK-Path", "Stack/Path\\u{1b}[2J\\u{9b}z"),
        ] {
            assert!(
                written.contains(spelled),
                "the {} is written as its escape {:?}: {:?}",
                field,
                spelled,
                written
            );
        }
    }

    /// With `colour` true the header differs from the plain one by the colour sequences around the name
    /// alone. Whether `colored` writes those sequences depends on the process setting (`SHOULD_COLORIZE`,
    /// which the environment and a parallel test can change), so the cell does not look for them: it
    /// removes every `ESC [ .. m` sequence from the coloured output and requires what is left to equal
    /// the plain output, which holds whether or not the process colours. The fields are escaped before
    /// the colour is applied, so the template's own ESC bytes never survive as a sequence that this
    /// removal could mistake for the writer's.
    ///
    /// Fails when a raw ESC from a field is left in the coloured output, or when a field is written
    /// differently by the colour branch than by the plain one.
    #[test]
    fn the_coloured_header_differs_from_the_plain_one_by_colour_sequences_alone() {
        let esc = char::from(0x1b);
        let name = format!("Id{esc}[31mx");
        let resource_type = format!("AWS::T{esc}[8my");
        let cdk_path = format!("Stack/Path{esc}[2Jz");
        let write = |colour: bool| {
            let mut out: Vec<u8> = Vec::new();
            write_resource_header(&mut out, &name, &resource_type, &cdk_path, colour)
                .expect("writing to a Vec cannot fail");
            String::from_utf8(out).expect("utf8")
        };
        fn without_sequences(text: &str) -> String {
            let mut kept = String::new();
            let mut chars = text.chars().peekable();
            while let Some(c) = chars.next() {
                if c == char::from(0x1b) && chars.peek() == Some(&'[') {
                    for inner in chars.by_ref() {
                        if inner == 'm' {
                            break;
                        }
                    }
                } else {
                    kept.push(c);
                }
            }
            kept
        }
        let plain = write(false);
        let coloured = write(true);
        assert!(
            !plain.contains(esc),
            "the plain header holds no raw ESC: {:?}",
            plain
        );
        assert_eq!(
            plain,
            without_sequences(&coloured),
            "the coloured header is the plain one plus colour sequences: {:?}",
            coloured
        );
    }
}

#[cfg(test)]
mod writer_output_tests {
    use super::{emit_messages, writer_output};

    /// The backstop writes U+200D as an escape, and the author's `Message =` text never goes through it:
    /// `emit_messages` writes a woman-technologist emoji (a woman, a zero-width joiner, a laptop) intact,
    /// where `writer_output` over the same text would escape the joiner. The first half shows the backstop
    /// does escape it, so the second half's intact joiner is a measurement and not an absent check.
    ///
    /// Fails when `emit_messages` writes the joiner as its escape (the author's text took the
    /// backstop), or when the backstop leaves the joiner raw (the first half proves nothing).
    #[test]
    fn a_message_with_a_zero_width_joiner_does_not_pass_through_the_backstop() {
        let joiner = char::from_u32(0x200d).expect("a scalar value");
        let emoji = format!("\u{1f469}{joiner}\u{1f4bb}");
        assert_eq!(
            "\u{1f469}\\u{200d}\u{1f4bb}",
            writer_output(emoji.clone().into_bytes()),
            "the backstop escapes the joiner"
        );
        let mut out: Vec<u8> = Vec::new();
        emit_messages(&mut out, "  ", &emoji, "", 10).expect("writing to a Vec cannot fail");
        let written = String::from_utf8(out).expect("utf8");
        assert!(
            written.contains(&emoji),
            "the author's message keeps its joiner: {:?}",
            written
        );
    }

    /// One invalid byte in a comparison writer's buffer keeps the rest of the excerpt: the byte is written
    /// as the replacement character, and the lines on either side of it are printed. A buffer dropped
    /// whole (the old `unwrap_or_default`) printed nothing for the whole `Code:` excerpt.
    ///
    /// Fails when the output is empty or lacks a line on either side of the bad byte.
    #[test]
    fn a_buffer_with_one_invalid_byte_keeps_the_rest_of_the_excerpt() {
        let mut buffer = b"    1. first line\n    2. bad ".to_vec();
        buffer.push(0xff);
        buffer.extend_from_slice(b" byte\n    3. last line\n");
        let written = writer_output(buffer);
        assert!(
            written.contains("1. first line") && written.contains("3. last line"),
            "the lines around the invalid byte are kept: {:?}",
            written
        );
        assert!(
            written.contains("2. bad \u{fffd} byte"),
            "the invalid byte is the replacement character: {:?}",
            written
        );
    }
}
