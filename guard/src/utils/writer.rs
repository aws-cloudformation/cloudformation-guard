use crate::rules::errors::InternalError;
use crate::rules::errors::InternalError::{
    FromUtf8Error, IncompatibleWriterError, UnsupportedBufferError, UnsupportedOperationError,
};
use crate::Error;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Stderr, Stdout, Write};

/// The prefix of a warning on the error stream: a condition the run noticed and went on from, such
/// as a duplicate key in a data document or a run that evaluated no file.
///
/// Every writer of a warning builds its text through [`warning`], which opens it with this constant,
/// and hands it to [`Writer::write_notice`], which checks for it, so the stream has one spelling and
/// no writer carries a prefix argument of its own. Nothing in the language holds the writers to the
/// constant; one source scan does. The evaluator's tests parse every non-test source of the crate as
/// Rust (`no_notice_builder_spells_the_prefix_itself` in `rules/eval_tests.rs`) and report any literal
/// whose value opens with a prefix and any use of these constants outside this file, so the two
/// constructors below stay their only users. The writer's record of notices (`Writer::notices`) is what
/// the library entry reads, so a notice never has to be told from a failure by its first word.
pub(crate) const WARNING_PREFIX: &str = "Warning:";

/// The prefix of a deprecation notice on the error stream. The evaluator's notice builders write only
/// a notice's body; the root scope that stores notices puts this in front of each one through
/// [`deprecation`], so it is spelled here and nowhere else, and held there by the same scan.
pub(crate) const DEPRECATION_PREFIX: &str = "DEPRECATION:";

/// The prefix of a note on the error stream: a line about the run's own output rather than about the
/// data or the rules, today the trailer the single-line `validate` output writes after its last data
/// file to name the later files that drew a notice the run announced once
/// ([`repeated_notice_trailer`]). Its own prefix because it is neither a warning nor a deprecation: a
/// reader counting or collecting `DEPRECATION:` lines must not count it, and the library entry still
/// keeps it out of a failure text because [`is_notice`] accepts it.
pub(crate) const NOTE_PREFIX: &str = "NOTE:";

/// The prefix a line on the error stream opens with, for the lines that are not failures: a warning
/// ([`WARNING_PREFIX`]), a deprecation ([`DEPRECATION_PREFIX`]) and a note ([`NOTE_PREFIX`]). A failure
/// has no prefix and no class here. This classifies the text as written; the path a line is written
/// down (a notice, an informational line or a failure) is the reporters' `StderrLineKind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StderrPrefix {
    Warning,
    Deprecation,
    Note,
}

impl StderrPrefix {
    /// The kind a text written to the error stream is, by its prefix, or `None` for a failure.
    pub(crate) fn of(text: &str) -> Option<Self> {
        if text.starts_with(WARNING_PREFIX) {
            Some(StderrPrefix::Warning)
        } else if text.starts_with(DEPRECATION_PREFIX) {
            Some(StderrPrefix::Deprecation)
        } else if text.starts_with(NOTE_PREFIX) {
            Some(StderrPrefix::Note)
        } else {
            None
        }
    }

    /// The prefix a line of this kind opens with.
    pub(crate) fn prefix(self) -> &'static str {
        match self {
            StderrPrefix::Warning => WARNING_PREFIX,
            StderrPrefix::Deprecation => DEPRECATION_PREFIX,
            StderrPrefix::Note => NOTE_PREFIX,
        }
    }
}

/// Whether a text written to the error stream is a notice (a warning, a deprecation or a note) rather
/// than a failure. A notice opens with one of the three prefixes. Every notice is one line as written
/// today: a clause a deprecation quotes is rendered from the parsed rule, never from the source text,
/// so a clause the author wrote over several lines is one line in the notice, and a line feed inside
/// quoted data is written as its escape. The record a reader takes notices from would carry a line
/// feed a body held as written (see [`deprecation`]), so a reader of the stream still takes a notice
/// from the record, not line by line.
pub(crate) fn is_notice(text: &str) -> bool {
    StderrPrefix::of(text).is_some()
}

/// A warning: the prefix, one space, and the body the caller formats with `format_args!`. The one
/// place the prefix is joined to a warning's body, so a writer keeps its own argument list and cannot
/// shift it by a prefix argument. A warning is one line by design, and every piece of a body that
/// comes from outside the program goes through [`escaped_for_display`] (document text: a key's path, a
/// tag, a test case's name) or [`escaped_controls_for_display`] (a file name, or text built from
/// several sources) at the point it is written in, so no raw control character reaches the line. A
/// debug build holds a writer to that: a body still carrying a character that breaks or hides a line
/// is a data point that was not escaped. A release build, which is what the command line, the FFI
/// crate and the Lambda ship as, runs the whole body through [`escaped_controls_for_display`] as its
/// last resort instead: a body whose data was escaped at its points holds no such character and is
/// left as it is, and a missed point costs the reader the backslash rule's exactness and never a raw
/// ESC, tab, bidi control or second, unprefixed line.
pub(crate) fn warning(body: std::fmt::Arguments<'_>) -> String {
    let body = body.to_string();
    debug_assert!(
        !body.chars().any(breaks_or_hides_a_line),
        "a warning is one line; escape the data it quotes with `escaped_for_display` or \
         `escaped_controls_for_display`: {:?}",
        body
    );
    format!("{WARNING_PREFIX} {}", escaped_controls_for_display(&body))
}

/// Whether a character ends, hides or reorders a line on the error stream: every control character
/// (`\n`, `\r`, `\t`, ESC, and U+0085, which is a control character to `char::is_control`); the Unicode
/// line and paragraph separators U+2028 and U+2029, which are not control characters but which libyaml
/// and most terminals break the line at; the bidirectional controls, the marks U+061C, U+200E and
/// U+200F, the embeddings and overrides U+202A to U+202E and the isolates U+2066 to U+2069, which a
/// bidi-aware terminal reorders the rest of the line by, so a key holding U+202E shows the text after
/// it reversed and a notice reads as saying something it does not; and the zero-width format
/// characters U+200B to U+200D, U+2060 and U+FEFF, which print as nothing, so two keys that differ by
/// one read as one. Every one of these is a format character (Unicode category Cf) or a separator, so
/// none is text a reader can see, and each is written as its `\u{...}` escape instead.
fn breaks_or_hides_a_line(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{2028}'
                | '\u{2029}'
                | '\u{061C}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'
                | '\u{2066}'..='\u{2069}'
                | '\u{FEFF}'
        )
}

/// `s` with each character that breaks or hides a line ([`breaks_or_hides_a_line`]) and each backslash
/// written as its Rust escape (`\n`, `\r`, `\t`, `\u{1b}`, `\u{85}`, `\u{2028}`, `\u{2029}`, `\u{202e}`,
/// `\u{200b}`, `\\`), and everything else as it is: the escaping for text a notice quotes from the
/// document (a key's path, a tag, a test case's name), applied at the point the text is written in,
/// never over a whole formatted body.
///
/// Control characters, because they reach the error stream unchanged otherwise: a line feed splits a
/// warning in two, so a reader going line by line meets an unprefixed second line; an ESC opens a
/// terminal escape sequence, so `ESC ]` hides what follows on a terminal and some terminals act on
/// what it carries, and the stream's own escape stripping then swallows everything to the next
/// terminator, the failure written after the notice included. The backslash too, so that the escaped
/// form maps back to one text: a key named `a<LF>b` and one named with the two characters `\` `n`
/// would otherwise both print as `a\nb`. A file name is not escaped this way; see
/// [`escaped_controls_for_display`]. Applied at the data points rather than over the body so that a
/// path the program itself formats is escaped once, and so that a deprecation notice quoting a clause
/// written over several lines keeps its line breaks.
pub(crate) fn escaped_for_display(s: &str) -> String {
    escaped(s, true)
}

/// `s` with each character that breaks or hides a line written as its Rust escape and everything else,
/// the backslash included, as it is: the escaping for a file name, for a position in the rules file
/// ([`location_for_notice`]), and for text built from several sources, in a notice. A file name is read
/// back against the file system and against the other streams, which print it as written: on Windows
/// a canonical path is `\\?\C:\dir\t.yaml`, and a warning that doubled its backslashes would name one
/// file two ways on one run's streams and leave the warning's path unpasteable. Text built from
/// several sources, such as the reason a function had no answer for an entry, which quotes a key from
/// the rules file beside a path from the data, is kept as its builder wrote it for the same reason.
/// What this gives up is the one-to-one mapping [`escaped_for_display`] keeps: a name holding a line
/// feed and a name holding the two characters `\` `n` both print as `\n` here, and a reader of the
/// stream cannot tell them apart. That is accepted for a file name, which the reader resolves against
/// the file system, and for built text, which the reader resolves against the notice's other fields.
pub(crate) fn escaped_controls_for_display(s: &str) -> String {
    escaped(s, false)
}

/// `name`, a file name, as [`escaped_controls_for_display`] writes it, borrowed as it is when it holds no
/// character that breaks or hides a line (the usual path: no allocation for the position every clause's
/// record context carries). The one place a rules file's path is escaped where the position is
/// displayed (`FileLocation`'s `Display`), so a path holding an ESC or a line feed reaches no record
/// context, report line or terminal raw, whichever writer prints the context.
pub(crate) fn file_name_for_display(name: &str) -> std::borrow::Cow<'_, str> {
    match name.chars().any(breaks_or_hides_a_line) {
        true => std::borrow::Cow::Owned(escaped_controls_for_display(name)),
        false => std::borrow::Cow::Borrowed(name),
    }
}

/// A position in the rules file as a notice names it: the `Location[file:..., line:..., column:...]`
/// display with the file's path escaped as a file name is ([`escaped_controls_for_display`]), since
/// the path is the one given on the command line and a path may hold a line feed, or an ESC, on Linux.
/// Every notice builder that names a clause's or a call's position goes through this one function, so
/// the rule cannot drift site by site: a builder that wrote `{location}` raw sent the path's ESC to
/// the terminal from a deprecation notice while the warning beside it escaped it.
pub(crate) fn location_for_notice(location: &crate::rules::exprs::FileLocation<'_>) -> String {
    escaped_controls_for_display(&location.to_string())
}

/// Whether a character is escaped on a console line that prints a rule author's message
/// ([`escaped_controls_for_console`]): everything [`breaks_or_hides_a_line`] names except the
/// joiners and marks U+200C to U+200F (zero-width non-joiner and joiner, left-to-right and right-to-left
/// marks). Those are ordinary text in an emoji sequence (a woman, U+200D, a laptop: one technologist
/// emoji) and in Hebrew, Arabic and Persian prose, where a right-to-left mark or a non-joiner changes how
/// a word is shaped, and writing them as `\u{200d}` would break a message that was typed correctly. The characters that end a line,
/// reorder the rest of it (the embeddings, overrides and isolates, U+061C) or print as nothing at all
/// (U+200B, U+2060, U+FEFF) stay escaped. The stderr notices keep the stricter predicate, since a name in
/// a notice is compared by eye against another name, and so do the console lines that print a key, a path,
/// a context, a value from the template or the data, or an evaluator's error or reason: the relaxed set
/// is for the rule author's prose alone.
fn breaks_or_hides_a_console_line(c: char) -> bool {
    breaks_or_hides_a_line(c) && !matches!(c, '\u{200C}'..='\u{200F}')
}

/// `s` with each character that breaks or hides a console line ([`breaks_or_hides_a_console_line`])
/// written as its Rust escape and everything else, the backslash included, as it is: the escaping for
/// the TEXT the rule author wrote on the console (a rule's `Message =` lines and the one-line forms of
/// that message), where a joiner or a mark is ordinary text. Idempotent: a backslash is left alone, so
/// escaping an escaped text changes nothing. Everything else is escaped by
/// [`escaped_controls_for_display`], the strict set, so a name with a pasted joiner does not print like
/// the name without it: a key, a path, a context, a value taken from the template or the data, and an
/// evaluator's `Error =` or `Reason =` text, which quotes keys.
pub(crate) fn escaped_controls_for_console(s: &str) -> String {
    escaped_by(s, false, breaks_or_hides_a_console_line)
}

/// [`escaped_controls_for_display`] for a line of the template's own source quoted under a finding (the
/// `Code:` excerpt): the strict set, except that a tab is kept as it is. A tab neither ends nor hides a
/// line and is how an indented template reads, so the excerpt shows the source as it is written.
pub(crate) fn escaped_controls_for_excerpt(s: &str) -> String {
    escaped_by(s, false, |c| c != '\t' && breaks_or_hides_a_line(c))
}

/// Whether XML 1.0 forbids `c` in a document whatever its position: the two noncharacters U+FFFE and
/// U+FFFF (the controls below U+0020 other than the tab, line feed and carriage return are forbidden too,
/// and [`breaks_or_hides_a_line`] already names them). The JSON reader keeps both code points, so a text
/// that reached a JUnit report through it can hold them.
fn forbidden_in_xml(c: char) -> bool {
    matches!(c, '\u{FFFE}' | '\u{FFFF}')
}

/// [`escaped_controls_for_excerpt`] for an XML text node of a JUnit report: the strict set with the tab
/// kept, and U+FFFE and U+FFFF, which XML 1.0 forbids, written as their escapes as well, so the node is
/// well-formed whatever the text holds.
pub(crate) fn escaped_controls_for_xml_text(s: &str) -> String {
    escaped_by(s, false, |c| {
        (c != '\t' && breaks_or_hides_a_line(c)) || forbidden_in_xml(c)
    })
}

/// [`escaped_controls_for_xml_text`] for a rule author's own prose in an XML text node of a JUnit report
/// (a `<< >>` message): the relaxed set of the console ([`escaped_controls_for_console`]), under which a
/// zero-width joiner and the direction marks U+200C to U+200F are ordinary text, with the tab kept and
/// U+FFFE and U+FFFF, which XML 1.0 forbids, written as their escapes.
pub(crate) fn escaped_controls_for_xml_author_text(s: &str) -> String {
    escaped_by(s, false, |c| {
        (c != '\t' && breaks_or_hides_a_console_line(c)) || forbidden_in_xml(c)
    })
}

/// `s` as the value of an XML attribute of a JUnit report, ready to be written between the quotes: the
/// strict set ([`escaped_controls_for_display`]) with U+FFFE and U+FFFF added, except that a tab and a line
/// feed are written as the character references `&#9;` and `&#10;`, which a parser reads back as the
/// character and not as the space a raw one in a value becomes, so a name that holds a tab and a name that
/// holds a backslash and a `t` stay two names. A carriage return is written as its escape `\r`, like
/// every other control: a reference to it (`&#13;`) decodes to a raw carriage return for every consumer,
/// which a terminal reading a CI tool's output acts on. A carriage return and line feed pair is not
/// folded, as it is in a text node (`xml_text_with_escaped_controls_by`, whose fold exists for a parser
/// that reads a literal pair as one line feed): it is written as the escape and the reference, `\r&#10;`,
/// and reads back as `\r` followed by a line feed. A backslash is written as it is, not doubled, since a
/// name in a report is a file name or a rule name that a reader compares against the file system and
/// against the other streams (`escaped_controls_for_display` gives the same reason), so a Windows path
/// `templates\a.yaml` reads back as `templates\a.yaml`.
///
/// The decision: no control other than the tab and the line feed reaches a consumer of the report raw (those
/// two stay character references, which a parser decodes to the character, so that a name holding a tab and
/// a name holding a backslash and a `t` stay two names), and a name reads back as
/// typed except that a control other than the tab and the line feed reads as its escape. So a name that
/// holds a control and a name that holds the typed characters of its escape (a carriage return and a
/// backslash with an `r`, an ESC and `\u{1b}`) read alike in the report: the class of collision that was
/// already accepted for the ESC, the joiners and the bidirectional marks, and the escaping does not keep
/// every pair of names apart. The alternative, a character reference for every escape, would keep them
/// apart and hand a raw ESC, a raw carriage return and the bidirectional marks to every consumer, the
/// exact hazard the escapes exist to close; it is refused.
///
/// The `test` command's spec case names take this path as well: a case name reads as typed in the
/// attribute, while a warning that names the same case routes it through [`escaped_for_display`], which
/// doubles its backslash (`a\b` reads `a\\b` on the error stream and `a\b` here). The characters XML
/// itself needs escaped (`&`, `<`, `>`, both quotes) are written as their entities. The joiners and the
/// bidirectional marks are written as escapes: a name is an identifier read against other names. One
/// function, so the reference characters are produced where the controls are decided and no caller holds
/// a half-escaped value.
pub(crate) fn xml_attribute_value(s: &str) -> String {
    let escaped = escaped_by(s, false, |c| {
        (!matches!(c, '\t' | '\n') && breaks_or_hides_a_line(c)) || forbidden_in_xml(c)
    });
    let mut out = String::with_capacity(escaped.len());
    for c in escaped.chars() {
        match c {
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            c => out.push(c),
        }
    }
    out
}

/// `s` as a backstop for text a caller formatted itself and may have coloured: every character that breaks
/// or hides a line is written as its escape by the strict set, except the line feed and the tab, which are
/// the text's own layout, and except the two colour sequences the colouring writers emit around a line
/// (`WRITER_COLOUR_SEQUENCES`: the green that opens an excerpt line and the reset that closes it), which
/// move nothing on the screen. Any other ESC is written as its escape, a cursor movement, an
/// operating-system command and any other colour or text attribute included (a conceal, `ESC [8m`, would
/// hide the text after it, and a well-formed sequence is no more harmless than a malformed one for being
/// well-formed). A writer that escapes its own fields (`console_field`) is unchanged by this; one that
/// forgets cannot reach the terminal raw through it. One of the two sequences a template string carried
/// itself would pass: it recolours the line and nothing else.
///
/// It escapes U+200C to U+200F (the joiners and marks the author's prose keeps,
/// [`escaped_controls_for_console`]) like every other character the strict set names, which is right
/// only because the backstop never runs over the author's prose: its one caller is `writer_output`, over a
/// comparison writer's buffer, and a writer's lines hold the template's paths, values and source excerpt,
/// never the rule author's `Message =` text, which `emit_messages` and `write_text_line` write through the
/// relaxed set on their own. A ZWJ emoji in a `<< >>` body therefore reaches the console intact
/// (`a_message_with_a_zero_width_joiner_does_not_pass_through_the_backstop`).
pub(crate) fn escaped_but_for_colour_and_layout(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(c) = rest.chars().next() {
        if c == '\u{1b}' {
            if let Some(sequence) = WRITER_COLOUR_SEQUENCES
                .iter()
                .find(|sequence| rest.starts_with(**sequence))
            {
                out.push_str(sequence);
                rest = &rest[sequence.len()..];
                continue;
            }
            out.push_str(&c.escape_debug().to_string());
        } else if c != '\n' && c != '\t' && breaks_or_hides_a_line(c) {
            out.push_str(&c.escape_debug().to_string());
        } else {
            out.push(c);
        }
        rest = &rest[c.len_utf8()..];
    }
    out
}

/// The green that opens a `Code:` excerpt line. Defined here and used by the writer that emits it
/// (`validate::cfn::emit_code`) and by the backstop that lets it through
/// (`escaped_but_for_colour_and_layout`), so a change to the colour is one change and the backstop cannot
/// keep passing a sequence no writer emits, or escape one that a writer does.
pub(crate) const WRITER_COLOUR_GREEN: &str = "\u{1b}[92m";

/// The reset that closes a `Code:` excerpt line; see [`WRITER_COLOUR_GREEN`].
pub(crate) const WRITER_COLOUR_RESET: &str = "\u{1b}[0m";

/// The two escape sequences the comparison writers put in their buffers: [`WRITER_COLOUR_GREEN`] and
/// [`WRITER_COLOUR_RESET`]. The backstop keeps these exact forms and nothing else.
const WRITER_COLOUR_SEQUENCES: [&str; 2] = [WRITER_COLOUR_GREEN, WRITER_COLOUR_RESET];

fn escaped(s: &str, backslash_too: bool) -> String {
    escaped_by(s, backslash_too, breaks_or_hides_a_line)
}

/// The one escape: each character `hides` names, and a backslash when `backslash_too`, written as its Rust
/// escape. The sets above differ in `hides` alone, so they sit side by side and cannot drift in how a
/// character is written.
fn escaped_by(s: &str, backslash_too: bool, hides: impl Fn(char) -> bool) -> String {
    s.chars()
        .map(|c| {
            if hides(c) || (backslash_too && c == '\\') {
                c.escape_debug().to_string()
            } else {
                c.to_string()
            }
        })
        .collect()
}

/// A deprecation notice: the prefix, one space, and the body with its leading whitespace trimmed. The
/// one place the prefix is joined to a notice's body, called by the root scope at the one sink every
/// notice reaches; a builder that spelled it for itself would be a second definition free to drift.
/// The trim is for a body that opens with a clause's display, which starts with a space of its own;
/// without it the membership notice printed two spaces between the colon and the clause. A body that
/// already opens with the prefix is a builder spelling it again, from the constant or a copy, and the
/// debug assertion catches that under every test that drives the builder, however it was spelled. A
/// line feed a body carries is kept as written, because the readers of the error stream take notices
/// from the writer's record, not line by line; no builder writes one today, since every clause a notice
/// quotes is rendered from the parsed rule (one line, whatever the author's layout) and a line feed
/// inside quoted data is written as its escape (`\n`). Every other character that breaks or hides a line is held to the
/// rule [`warning`] holds its body to: a builder escapes the data it quotes at the point it is written
/// in, a debug build asserts that none reached the body, and a release build runs the body through
/// [`escaped_controls_for_display`] as its last resort, line feeds excepted, so a missed point costs the
/// reader the backslash rule's exactness and never a raw ESC, tab or bidi control from a `when` literal.
pub(crate) fn deprecation(body: &str) -> String {
    let body = body.trim_start();
    debug_assert!(
        !body.starts_with(DEPRECATION_PREFIX),
        "notice body already carries the prefix: {}",
        body
    );
    debug_assert!(
        !body.chars().any(hides_a_notice_line),
        "a deprecation notice carries no control but a line feed; escape the data it quotes with \
         `escaped_for_display` or `escaped_controls_for_display`: {:?}",
        body
    );
    let body = if body.chars().any(hides_a_notice_line) {
        body.split('\n')
            .map(escaped_controls_for_display)
            .collect::<Vec<_>>()
            .join("\n")
    } else {
        body.to_string()
    };
    format!("{DEPRECATION_PREFIX} {body}")
}

/// [`breaks_or_hides_a_line`] for a deprecation notice, whose line feeds are its own: every such
/// character but `\n`.
fn hides_a_notice_line(c: char) -> bool {
    c != '\n' && breaks_or_hides_a_line(c)
}

/// What a command wrote for an input it found none of: the notices naming the files it passed over,
/// in the order written, and the warning that it evaluated none. Recorded by
/// [`Writer::write_nothing_checked`]; an entry's existence is the fact a reader branches on, and its
/// lines are what the reader shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NothingChecked {
    pub(crate) skipped: Vec<String>,
    pub(crate) warning: String,
}

/// How many of the later files a trailer names before counting the rest; see [`trailer_file_list`].
pub(crate) const TRAILER_NAMED_FILES: usize = 3;

/// The files a trailer names: the first [`TRAILER_NAMED_FILES`] of `later_files` and a count of the rest,
/// always, so the line stays bounded whatever the run's size. The count keeps the run the trailer exists
/// for, a directory of templates over one `let`, from ending in a line that lists every template after
/// the first: the line trained to be skipped that the once-per-site collapse removed, in a new form.
/// `apart` holds what tells this list from another trailer's that would read the same shortened (the
/// same first names and the same count, as for two sites each missed by one different template): one
/// phrase per such neighbor, the first name where the two lists differ (`not t60`, a file the other
/// list holds and this one lacks), appended after the count so the line stays bounded by the number of
/// neighbors, never by the number of files.
pub(crate) fn trailer_file_list(later_files: &[String], apart: &[String]) -> String {
    let mut named = if later_files.len() <= TRAILER_NAMED_FILES {
        later_files.join(", ")
    } else {
        format!(
            "{} and {} more",
            later_files[..TRAILER_NAMED_FILES].join(", "),
            later_files.len() - TRAILER_NAMED_FILES
        )
    };
    for phrase in apart {
        named.push_str(", ");
        named.push_str(phrase);
    }
    named
}

/// The trailer the single-line `validate` output writes after its last data file for the notices it
/// announced once that later files drew too. `later_files` are the files after the first that drew
/// every notice in `notices`, in run order, named as [`trailer_file_list`] names them with `apart`;
/// `notices` describe those notices, a once-per-site notice by its kind and site
/// (`DeprecationKind::described`) and a plain notice by its opening words and position
/// ([`notice_opening`]). One trailer per distinct list of later files, so sites the same files hit share
/// a line. A note ([`NOTE_PREFIX`]), built here where the prefix is spelled: a notice line, so the
/// library entry drops it from a failure text as it drops the notices, and not a deprecation, so a
/// reader counting `DEPRECATION:` lines counts the notices alone.
pub(crate) fn repeated_notice_trailer(
    notices: &[String],
    later_files: &[String],
    apart: &[String],
) -> String {
    format!(
        "{NOTE_PREFIX} also drawn by {}: {}",
        trailer_file_list(later_files, apart),
        notices.join("; ")
    )
}

/// How a trailer names a notice that has no site of its own: by its first `words` words, so a reader
/// finds the once-written line above by them, and by the position the notice ends with when it has one
/// (the last `Location[...]` in its text), since two notices of one kind drawn by two clauses open with
/// the same words and differ in that position alone. `line` is the notice as written, prefix included;
/// the prefix is dropped, and an ellipsis marks a body that goes on past the words kept. Words rather
/// than a byte count so a quoted expression is cut at a space, never inside a character. A caller whose
/// two descriptions still read the same asks again with more words.
pub(crate) fn notice_opening(line: &str, words: usize) -> String {
    let body = StderrPrefix::of(line)
        .and_then(|kind| line.strip_prefix(kind.prefix()))
        .unwrap_or(line);
    let mut rest = body.split_whitespace();
    let opening = rest.by_ref().take(words).collect::<Vec<_>>().join(" ");
    let goes_on = rest.next().is_some();
    let position = body.rfind("Location[").and_then(|start| {
        body[start..]
            .find(']')
            .map(|end| &body[start..=start + end])
    });
    match (goes_on, position) {
        (false, _) => format!("the notice \"{opening}\""),
        (true, Some(position)) => format!("the notice opening \"{opening} ...\" at {position}"),
        (true, None) => format!("the notice opening \"{opening} ...\""),
    }
}

#[derive(Debug)]
pub struct Writer {
    buffer: WriteBuffer,
    err: WriteBuffer,
    /// Whether `err` is a buffer that is read back afterwards (a `Vec` or a `File`), which is when
    /// the records below are kept. The process's own stderr is never read back, so a console run
    /// over a large directory holds none of its notice strings.
    records_err: bool,
    /// Every notice written to `err` through [`write_notice`](Self::write_notice) or
    /// [`write_nothing_checked`](Self::write_nothing_checked), in the order written and as written.
    notices: Vec<String>,
    /// Every failure written to `err` through [`write_err`](Self::write_err), in the order written
    /// and as written. The error stream holds notices and failures interleaved, and once they are in
    /// it nothing in their shape says where a notice ends and a failure begins, so a reader that has
    /// to pick the failure out of a run takes it from here rather than out of the stream.
    failures: Vec<String>,
    /// What the run wrote for each input it found none of, in the order written. An entry here is
    /// the fact a reader branches on; its lines are what the reader shows, and the wording is the
    /// command's to change.
    nothing_checked: Vec<NothingChecked>,
}

impl Default for Writer {
    fn default() -> Self {
        Self {
            buffer: WriteBuffer::Stdout(std::io::stdout()),
            err: WriteBuffer::Stderr(std::io::stderr()),
            records_err: false,
            notices: Vec::new(),
            failures: Vec::new(),
            nothing_checked: Vec::new(),
        }
    }
}

impl Writer {
    pub fn new(buffer: WriteBuffer) -> crate::rules::Result<Self> {
        if buffer.is_err() {
            return Err(Error::from(IncompatibleWriterError(
                "Unable to use stderr as a regular buffer.".to_string(),
            )));
        }

        Ok(Self {
            buffer,
            err: WriteBuffer::Stderr(std::io::stderr()),
            records_err: false,
            notices: Vec::new(),
            failures: Vec::new(),
            nothing_checked: Vec::new(),
        })
    }

    pub fn new_with_err(buffer: WriteBuffer, err: WriteBuffer) -> crate::rules::Result<Self> {
        if buffer.is_err() {
            return Err(Error::from(IncompatibleWriterError(
                "Unable to use stderr as a regular buffer.".to_string(),
            )));
        }

        let records_err = err.is_read_back();
        Ok(Self {
            buffer,
            err,
            records_err,
            notices: Vec::new(),
            failures: Vec::new(),
            nothing_checked: Vec::new(),
        })
    }

    /// Writes what a command says when it found none of one input: the notices naming the files it
    /// passed over on the way, if any, then the warning that it evaluated none, each as
    /// [`write_notice`](Self::write_notice) writes a notice. Beside them it records those lines, in
    /// its own record apart from the other notices. That record is the fact a reader that has to
    /// report such a run as an error branches on: an entry means the run checked nothing of one
    /// input, whatever the lines say, and the reader shows what the command wrote, names included.
    /// The warning is a parameter of its own, so a report always has one and the reader is never
    /// handed an empty text. The wording is the command's to change.
    ///
    /// Each passed-over line is written as the iterator yields it. Only a writer that keeps a record
    /// holds them too; one writing to the process's stderr, the console case, has no record to fill
    /// and so holds nothing between one line and the next.
    pub(crate) fn write_nothing_checked(
        &mut self,
        skipped: impl IntoIterator<Item = String>,
        warning: String,
    ) -> std::io::Result<()> {
        let mut recorded = Vec::new();
        for line in skipped {
            if self.records_err {
                self.write_notice(line.clone())?;
                recorded.push(line);
            } else {
                self.write_notice(line)?;
            }
        }
        self.write_notice(warning.clone())?;
        if self.records_err {
            self.nothing_checked.push(NothingChecked {
                skipped: recorded,
                warning,
            });
        }
        Ok(())
    }

    /// The reports written through [`write_nothing_checked`](Self::write_nothing_checked), in the
    /// order written: one per input the run found none of. Empty for a writer whose error stream is
    /// the process's stderr, and for a run that checked something of both.
    pub(crate) fn nothing_checked(&self) -> &[NothingChecked] {
        &self.nothing_checked
    }

    /// Writes a failure to the error stream, and keeps a copy in the record
    /// `failures` returns when the stream is one that is read back.
    pub fn write_err(&mut self, s: String) -> std::io::Result<()> {
        writeln!(self.err, "{s}")?;
        if self.records_err {
            self.failures.push(s);
        }
        Ok(())
    }

    /// Writes a line that is neither a failure nor a notice to the error stream, where it lands as
    /// `write_err` would put it, and records nothing: information for the reader, such as a test file
    /// no rules file claimed, which is not a problem with the run and so is not a failure, and not a
    /// condition the run went on from either.
    pub(crate) fn write_message(&mut self, s: String) -> std::io::Result<()> {
        writeln!(self.err, "{s}")
    }

    /// Writes a notice to the error stream, where it lands as `write_err` would put it, and keeps a
    /// copy in the record [`notices`](Self::notices) returns when the stream is one that is read
    /// back. A notice is a warning, a deprecation or a note ([`StderrPrefix`]), a condition the run
    /// went on from or a line about its own output; a failure goes through `write_err`, and a message
    /// that is neither through `write_message`. Every writer of a notice uses this, and spells its
    /// prefix through [`WARNING_PREFIX`], [`DEPRECATION_PREFIX`] or [`NOTE_PREFIX`], which the debug
    /// assertion holds it to.
    pub(crate) fn write_notice(&mut self, notice: String) -> std::io::Result<()> {
        debug_assert!(
            is_notice(&notice),
            "a notice opens with {}, {} or {}: {:?}",
            WARNING_PREFIX,
            DEPRECATION_PREFIX,
            NOTE_PREFIX,
            notice
        );
        writeln!(self.err, "{notice}")?;
        if self.records_err {
            self.notices.push(notice);
        }
        Ok(())
    }

    /// The notices written so far through [`write_notice`](Self::write_notice), in order. Empty
    /// for a writer whose error stream is the process's stderr, which keeps no record. Read by the
    /// crate's tests alone, so it is compiled for them alone: no command reads a writer's record back.
    #[cfg(test)]
    pub(crate) fn notices(&self) -> &[String] {
        &self.notices
    }

    /// The notices of one kind written so far, in order: a reader that wants the deprecations alone
    /// reads them here and is not handed the trailer the single-line output writes as a note. A test
    /// reader, like [`notices`](Self::notices).
    #[cfg(test)]
    pub(crate) fn notices_of(&self, kind: StderrPrefix) -> impl Iterator<Item = &String> {
        self.notices
            .iter()
            .filter(move |notice| StderrPrefix::of(notice) == Some(kind))
    }

    /// The failures written so far through [`write_err`](Self::write_err), in order, as written
    /// (escape sequences included). Empty for a writer whose error stream is the process's stderr.
    pub(crate) fn failures(&self) -> &[String] {
        &self.failures
    }

    /// The error buffer with escape sequences removed and every other byte kept. It must be readable
    /// back (a `Vec` or a `File`); a process stream is refused with an error naming this method and
    /// the error buffer, as the `UnsupportedOperationError` this method has always returned for one.
    pub fn err_to_stripped(self) -> crate::rules::Result<String> {
        self.err.into_stripped_string(
            "err_to_stripped",
            BufferRole::Err,
            UnsupportedOperationError,
        )
    }

    /// The regular buffer as written. It must be readable back (a `Vec` or a `File`); a process
    /// stream is refused with an error naming this method and the regular buffer, as the
    /// `UnsupportedOperationError` this method has always returned for one.
    pub fn into_string(self) -> crate::rules::Result<String> {
        utf8(self.buffer.read_bytes(
            "into_string",
            BufferRole::Regular,
            UnsupportedOperationError,
        )?)
    }

    /// The regular buffer with escape sequences removed and every other byte kept, read the same
    /// way `err_to_stripped` reads the error buffer. A process stream is refused with an error
    /// naming this method and the regular buffer, as the `UnsupportedBufferError` this method has
    /// always returned for one.
    ///
    /// One caller prints what this returns as a run's output: the library example in
    /// `guard-examples/library/src/main.rs`. Every other caller compares it against an expected
    /// text in a test: the integration tests under `guard/tests` (`parse_tree.rs`, `rulegen.rs`,
    /// `test_command.rs`, `validate.rs`, and the helpers in `utils.rs`) and this module's own tests.
    pub fn stripped(self) -> crate::rules::Result<String> {
        self.buffer
            .into_stripped_string("stripped", BufferRole::Regular, UnsupportedBufferError)
    }

    /// Both streams, stripped of ANSI escapes, from one run: what `stripped` and `err_to_stripped`
    /// each return, together, the regular buffer first. Escape sequences are removed and every other
    /// byte is kept. Both buffers must be readable back (a `Vec` or a `File`); a process stream is
    /// refused the same way `err_to_stripped` refuses it.
    ///
    /// Each of those consumes the writer, so a test that wanted stdout and stderr ran the command
    /// twice and read one stream from each run. The heavy runs -- a spec file that spends the alias
    /// expansion budget -- then cost twice, and the two streams came from two executions rather than
    /// one.
    ///
    /// Each buffer is read through `WriteBuffer::into_stripped_string` directly; no intermediate
    /// `Writer` is built around either of them. The method's own name goes to each read, so that a
    /// process stream's refusal names it, whichever buffer the stream is; the pair has refused a
    /// stream as an `UnsupportedOperationError` since it was written. Both buffers are looked at
    /// before either is read: when both are process streams, as `Writer::default()`'s are, the
    /// refusal names both, so a caller is not refused for the regular buffer, gives it a `Vec`, and
    /// is refused again for the error buffer.
    ///
    /// Crate-visible and test-only: the crate's own tests read both buffers of one run through it,
    /// no command does, and nothing public hands the pair out. A test in another crate puts both
    /// buffers on files and reads each through a `Writer` of its own, with `stripped` and
    /// `err_to_stripped`.
    #[cfg(test)]
    pub(crate) fn into_stripped_parts(self) -> crate::rules::Result<(String, String)> {
        self.stripped_pair("into_stripped_parts")
    }

    /// The body behind `into_stripped_parts`: both buffers, each read through
    /// `WriteBuffer::into_stripped_string` directly, with no intermediate `Writer` built around
    /// either. `method` is the name the caller called, so that a process stream's refusal names it,
    /// and one place for the reading whatever name a caller reaches it by.
    #[cfg(test)]
    fn stripped_pair(self, method: &str) -> crate::rules::Result<(String, String)> {
        if let (Some(regular), Some(err)) = (self.buffer.stream_name(), self.err.stream_name()) {
            return Err(both_cannot_be_read_back(
                method,
                regular,
                err,
                UnsupportedOperationError,
            ));
        }
        Ok((
            self.buffer.into_stripped_string(
                method,
                BufferRole::Regular,
                UnsupportedOperationError,
            )?,
            self.err
                .into_stripped_string(method, BufferRole::Err, UnsupportedOperationError)?,
        ))
    }
}

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buffer.write(String::from_utf8_lossy(buf).as_bytes())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.buffer.flush()
    }
}

#[derive(Debug)]
pub enum WriteBuffer {
    Stdout(Stdout),
    Vec(Vec<u8>),
    File(File),
    Stderr(Stderr),
}

/// Which of a `Writer`'s two buffers a read-back is reading, so that the error a process stream
/// gets can say which one it was.
#[derive(Clone, Copy)]
enum BufferRole {
    Regular,
    Err,
}

impl BufferRole {
    /// The error for a read-back of a process stream, which has no content to read. The text names
    /// the `Writer` method the caller called, the buffer's role and the stream it is, and the
    /// reason. `variant` is the `InternalError` constructor that method has returned for a stream
    /// since it was written, so that what a caller matches on does not change.
    fn cannot_read_back(
        self,
        method: &str,
        stream: &str,
        variant: fn(String) -> InternalError,
    ) -> Error {
        let role = match self {
            BufferRole::Regular => "regular",
            BufferRole::Err => "error",
        };
        Error::from(variant(format!(
            "Unable to call {method}(): the {role} buffer is {stream}, which cannot be read back."
        )))
    }
}

/// The error for a read-back of both buffers when both are process streams, naming each so that one
/// refusal says everything there is to fix. `method` and `variant` are as for
/// [`BufferRole::cannot_read_back`]. Reached from the test-only pair read-back alone, so compiled
/// with it.
#[cfg(test)]
fn both_cannot_be_read_back(
    method: &str,
    regular: &str,
    err: &str,
    variant: fn(String) -> InternalError,
) -> Error {
    Error::from(variant(format!(
        "Unable to call {method}(): both buffers are process streams: regular is {regular}, error \
         is {err}, which cannot be read back."
    )))
}

/// Removes the escape sequences a terminal would interpret and keeps every other byte.
///
/// Two kinds are removed: CSI (`ESC [`, its parameter and intermediate bytes, and the final byte in
/// `@`..`~`), which is how color and style are written, and OSC (`ESC ]` through BEL or `ESC \`),
/// which carries a title or a hyperlink. A lone ESC that opens neither stays, as does every control
/// byte: a tab aligning columns or a carriage return rewriting a progress line is part of the
/// message. This replaced the `strip_ansi_escapes` crate, whose parser routed every control byte
/// other than newline to a handler that dropped it.
/// `pub(crate)` for the reporters' tests, which strip what a report writer colored before comparing
/// the text, through the same function the writer uses.
pub(crate) fn strip_escape_sequences(bytes: &[u8]) -> Vec<u8> {
    const ESC: u8 = 0x1b;
    const BEL: u8 = 0x07;

    let mut plain = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != ESC {
            plain.push(bytes[i]);
            i += 1;
            continue;
        }

        match bytes.get(i + 1) {
            Some(b'[') => {
                i += 2;
                while i < bytes.len() && (0x20..=0x3f).contains(&bytes[i]) {
                    i += 1;
                }
                if i < bytes.len() && (0x40..=0x7e).contains(&bytes[i]) {
                    i += 1;
                }
            }
            Some(b']') => {
                i += 2;
                loop {
                    match bytes.get(i) {
                        None => break,
                        Some(&BEL) => {
                            i += 1;
                            break;
                        }
                        Some(&ESC) if bytes.get(i + 1) == Some(&b'\\') => {
                            i += 2;
                            break;
                        }
                        Some(_) => i += 1,
                    }
                }
            }
            _ => {
                plain.push(ESC);
                i += 1;
            }
        }
    }

    plain
}

/// Everything written to a file buffer, read back through the same handle.
///
/// Writing leaves the handle at the end of the file, so a read from there returns nothing; the
/// read starts from the beginning. A handle that was opened without read access, or that the
/// operating system refuses to read for any other reason, is an `Err` rather than a panic.
fn read_back(mut file: File) -> crate::rules::Result<Vec<u8>> {
    file.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    Ok(data)
}

fn utf8(bytes: Vec<u8>) -> crate::rules::Result<String> {
    String::from_utf8(bytes).map_err(|e| Error::from(FromUtf8Error(e)))
}

impl WriteBuffer {
    fn is_err(&self) -> bool {
        matches!(self, WriteBuffer::Stderr(_))
    }

    /// Whether the buffer is one a caller reads back after the run (a `Vec` or a `File`), as
    /// opposed to one of the process's own streams.
    fn is_read_back(&self) -> bool {
        matches!(self, WriteBuffer::Vec(_) | WriteBuffer::File(_))
    }

    /// The process stream this buffer is, by name, or `None` for a buffer that is read back. Read by
    /// the test-only pair read-back alone, so compiled with it.
    #[cfg(test)]
    fn stream_name(&self) -> Option<&'static str> {
        match self {
            WriteBuffer::Stdout(..) => Some("stdout"),
            WriteBuffer::Stderr(..) => Some("stderr"),
            WriteBuffer::Vec(..) | WriteBuffer::File(..) => None,
        }
    }

    /// The bytes written to the buffer, which is the one place a read-back meets a process stream:
    /// a `Vec` gives its bytes, a `File` is rewound and read, and a stream is refused. `method`,
    /// `role` and `variant` are the caller's: the public `Writer` method the caller called, the
    /// buffer it is reading and the error that method returns for a stream, so that the refusal
    /// names what was asked of which buffer and comes as the error its callers match on.
    fn read_bytes(
        self,
        method: &str,
        role: BufferRole,
        variant: fn(String) -> InternalError,
    ) -> crate::rules::Result<Vec<u8>> {
        match self {
            WriteBuffer::Vec(vec) => Ok(vec),
            WriteBuffer::File(file) => read_back(file),
            WriteBuffer::Stdout(..) => Err(role.cannot_read_back(method, "stdout", variant)),
            WriteBuffer::Stderr(..) => Err(role.cannot_read_back(method, "stderr", variant)),
        }
    }

    /// The buffer as written with escape sequences removed and every other byte kept. The one body
    /// behind every stripped read of a `Writer`'s buffers; `method`, `role` and `variant` are the
    /// caller's, as for [`read_bytes`](Self::read_bytes).
    fn into_stripped_string(
        self,
        method: &str,
        role: BufferRole,
        variant: fn(String) -> InternalError,
    ) -> crate::rules::Result<String> {
        utf8(strip_escape_sequences(
            &self.read_bytes(method, role, variant)?,
        ))
    }
}

impl Write for WriteBuffer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.write(buf),
            WriteBuffer::Stderr(stderr) => stderr.write(buf),
            WriteBuffer::Vec(vec) => vec.write(buf),
            WriteBuffer::File(file) => file.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            WriteBuffer::Stdout(stdout) => stdout.flush(),
            WriteBuffer::Stderr(stderr) => stderr.flush(),
            WriteBuffer::Vec(vec) => vec.flush(),
            WriteBuffer::File(file) => file.flush(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        deprecation, escaped_but_for_colour_and_layout, escaped_controls_for_display,
        escaped_for_display, is_notice, location_for_notice, repeated_notice_trailer,
        trailer_file_list, warning, BufferRole, StderrPrefix, WriteBuffer, Writer,
        DEPRECATION_PREFIX, NOTE_PREFIX, WARNING_PREFIX,
    };
    use crate::rules::errors::InternalError::{self, UnsupportedBufferError};
    use crate::Error;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::PathBuf;

    #[test]
    fn a_notice_is_written_to_the_error_stream_and_recorded_as_written() {
        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![])).unwrap();
        writer
            .write_notice(format!("{} first\n  continued", super::WARNING_PREFIX))
            .unwrap();
        writer.write_err("a failure".to_string()).unwrap();
        writer
            .write_notice(format!("{} second", super::DEPRECATION_PREFIX))
            .unwrap();

        assert_eq!(
            writer.notices(),
            ["Warning: first\n  continued", "DEPRECATION: second"]
        );
        assert_eq!(writer.failures(), ["a failure"]);
        let (_, err) = writer.into_stripped_parts().unwrap();
        assert_eq!(
            err,
            "Warning: first\n  continued\na failure\nDEPRECATION: second\n"
        );
    }

    #[test]
    fn a_writer_on_the_process_stderr_keeps_no_record() {
        // The records exist for a caller that reads the error buffer back. The process's own stderr
        // is never read back, so a long console run must not hold its notices until exit.
        let mut writer = Writer::new(WriteBuffer::Vec(vec![])).unwrap();
        writer
            .write_notice(format!("{} not kept", super::WARNING_PREFIX))
            .unwrap();
        writer.write_err("not kept either".to_string()).unwrap();

        assert!(writer.notices().is_empty());
        assert!(writer.failures().is_empty());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "a notice opens with Warning:, DEPRECATION: or NOTE:")]
    fn a_notice_without_the_shared_prefix_is_refused() {
        // The one check that a writer of a notice has not drifted from the shared spelling. It holds
        // in the test build, which is where a drifted writer is first run.
        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![])).unwrap();
        let _ = writer.write_notice("WARN: spelled another way".to_string());
    }

    #[test]
    fn a_plain_read_back_names_the_caller_and_the_role_it_is_given() {
        // `WriteBuffer::read_bytes` knows no caller of its own: whatever reads a stream through it
        // names itself and the buffer it reads, so a reader of the error buffer added later is
        // refused under its own name and role, not under `into_string`'s.
        let err = WriteBuffer::Stdout(std::io::stdout())
            .read_bytes("err_into_string", BufferRole::Err, UnsupportedBufferError)
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call err_into_string(): the error buffer is stdout, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedBufferError(_))
        ));
    }

    #[test]
    fn the_passed_over_lines_are_written_as_they_come_not_collected_first() {
        // What the streaming buys: on the nothing-checked path the formatted lines are written as
        // the iterator yields them and no copy of the whole formatted list is made first, so when
        // the iterator yields its second line the first is already on the stream. (The walk's own
        // list of names is the caller's, and the caller drops it as soon as a file is found.)
        // Observed through a file-backed error buffer whose length is read from inside the iterator.
        // A file-backed writer records, so it does hold the lines after writing them; that a console
        // writer holds nothing is the next cell's.
        let path = scratch_path("stream-passed-over");
        let file = File::create(&path).unwrap();
        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::File(file)).unwrap();
        let seen = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
        let lengths = seen.clone();
        let observed_path = path.clone();
        let lines = (1..=3).map(move |n| {
            lengths
                .borrow_mut()
                .push(fs::metadata(&observed_path).unwrap().len());
            format!("{} file-{n}.txt was not evaluated", super::WARNING_PREFIX)
        });

        writer
            .write_nothing_checked(
                lines,
                format!("{} nothing was evaluated", super::WARNING_PREFIX),
            )
            .unwrap();

        let lengths = seen.borrow();
        assert_eq!(lengths.len(), 3, "{:?}", lengths);
        assert_eq!(
            lengths[0], 0,
            "nothing is on the stream before the first line: {:?}",
            lengths
        );
        assert!(
            lengths[1] > 0 && lengths[2] > lengths[1],
            "each line is on the stream before the next is pulled: {:?}",
            lengths
        );
        assert_eq!(writer.nothing_checked().len(), 1);
        assert_eq!(writer.nothing_checked()[0].skipped.len(), 3);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_console_writer_keeps_no_record_of_the_passed_over_lines() {
        // The console case: the error buffer is the process's stderr, which is not read back, so
        // the writer records neither the passed-over lines nor the report. What it wrote is on
        // stderr and nowhere else.
        let mut writer = Writer::new_with_err(
            WriteBuffer::Vec(vec![]),
            WriteBuffer::Stderr(std::io::stderr()),
        )
        .unwrap();
        let lines =
            (1..=3).map(|n| format!("{} file-{n}.txt was not evaluated", super::WARNING_PREFIX));

        writer
            .write_nothing_checked(
                lines,
                format!("{} nothing was evaluated", super::WARNING_PREFIX),
            )
            .unwrap();

        assert!(writer.nothing_checked().is_empty());
        assert!(writer.notices().is_empty());
    }

    /// A path of this process's own under the temp dir, removed by the test that made it.
    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cfn-guard-writer-{name}-{}.txt",
            std::process::id()
        ))
    }

    #[test]
    fn file_buffers_read_back_what_was_written_to_them() {
        // Reading starts wherever the handle was left, which after writing is the end of the file,
        // so a read-back that does not rewind first returns nothing and calls that the content.
        let path = scratch_path("read-back");
        let open = || {
            OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(true)
                .open(&path)
                .unwrap()
        };

        let mut writer =
            Writer::new_with_err(WriteBuffer::File(open()), WriteBuffer::Vec(vec![])).unwrap();
        write!(writer, "the report").unwrap();
        assert_eq!(writer.into_string().unwrap(), "the report");

        let mut writer = Writer::new(WriteBuffer::File(open())).unwrap();
        write!(writer, "\u{1b}[4munderlined\u{1b}[0m").unwrap();
        assert_eq!(writer.stripped().unwrap(), "underlined");

        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::File(open())).unwrap();
        writer
            .write_err(String::from("\u{1b}[31mthe error\u{1b}[0m"))
            .unwrap();
        assert_eq!(writer.err_to_stripped().unwrap(), "the error\n");

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn stripping_removes_escape_sequences_and_keeps_every_other_byte() {
        // A console message can carry a tab (column alignment) or a carriage return (a progress
        // line rewriting itself). Stripping is for the color and style sequences a terminal would
        // interpret; it must not eat the message's own bytes.
        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![])).unwrap();
        writer
            .write_err(String::from(
                "\u{1b}[31mred\u{1b}[0m\tcol2\rend \u{1b}]0;title\u{7}plain \u{1b}]8;;x\u{1b}\\link",
            ))
            .unwrap();
        assert_eq!(
            writer.err_to_stripped().unwrap(),
            "red\tcol2\rend plain link\n"
        );
    }

    #[test]
    fn stripped_keeps_a_tab_and_a_carriage_return_in_the_regular_buffer() {
        // The example program prints what `stripped` returns as the run's output, so what holds
        // for the error buffer has to hold here: color goes, the message's own bytes stay.
        let mut writer = Writer::new(WriteBuffer::Vec(vec![])).unwrap();
        write!(writer, "\u{1b}[32mPASS\u{1b}[0m\tcol2\rend").unwrap();
        assert_eq!(writer.stripped().unwrap(), "PASS\tcol2\rend");
    }

    #[test]
    fn into_stripped_parts_strips_both_buffers() {
        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![])).unwrap();
        write!(writer, "\u{1b}[1mdoc\u{1b}[0m\tend").unwrap();
        writer
            .write_err(String::from("\u{1b}[31merr\u{1b}[0m"))
            .unwrap();
        assert_eq!(
            writer.into_stripped_parts().unwrap(),
            (String::from("doc\tend"), String::from("err\n"))
        );
    }

    #[test]
    fn a_process_stream_refuses_a_read_back_naming_the_method_called_and_the_buffer() {
        // `Writer::default()` writes to the process's own stdout and stderr, which cannot be read
        // back. Every accessor's refusal names the method the caller called, which of the two
        // buffers is a stream, and why, and carries the variant that accessor returned before. A
        // pair read of the default writer names both streams at once, so a caller who then gives
        // the regular buffer a `Vec` is not refused a second time for the error buffer.
        let err = Writer::default().into_stripped_parts().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call into_stripped_parts(): both buffers are process streams: regular is \
             stdout, error is stderr, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedOperationError(_))
        ));

        let err = Writer::default().stripped().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call stripped(): the regular buffer is stdout, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedBufferError(_))
        ));

        let err = Writer::default().err_to_stripped().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call err_to_stripped(): the error buffer is stderr, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedOperationError(_))
        ));

        let err = Writer::default().into_string().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call into_string(): the regular buffer is stdout, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedOperationError(_))
        ));

        // A readable regular buffer beside a stream error buffer: the pair fails on its second read,
        // and the refusal says so.
        let writer = Writer::new_with_err(
            WriteBuffer::Vec(vec![]),
            WriteBuffer::Stderr(std::io::stderr()),
        )
        .unwrap();
        let err = writer.into_stripped_parts().unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call into_stripped_parts(): the error buffer is stderr, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedOperationError(_))
        ));

        // The same shape through `Writer::new`, whose error buffer defaults to the process's
        // stderr: the one stream is named, and only it.
        let err = Writer::new(WriteBuffer::Vec(vec![]))
            .unwrap()
            .into_stripped_parts()
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            "Unable to call into_stripped_parts(): the error buffer is stderr, which cannot be read back."
        );
        assert!(matches!(
            err,
            Error::InternalError(InternalError::UnsupportedOperationError(_))
        ));
    }

    #[test]
    fn stripped_reads_the_regular_buffer_the_way_the_error_buffer_is_read() {
        // One body strips both buffers, so every byte the error buffer keeps, the regular buffer
        // keeps too, whichever accessor reads it.
        let text =
            "\u{1b}[31mred\u{1b}[0m\tcol2\rend \u{1b}]0;title\u{7}plain \u{1b}]8;;x\u{1b}\\link";
        let mut writer =
            Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![])).unwrap();
        write!(writer, "{text}").unwrap();
        writer.write_err(String::from(text)).unwrap();
        let (document, diagnostics) = writer.into_stripped_parts().unwrap();
        assert_eq!(document, "red\tcol2\rend plain link");
        assert_eq!(diagnostics, format!("{document}\n"));

        let mut writer = Writer::new(WriteBuffer::Vec(vec![])).unwrap();
        write!(writer, "{text}").unwrap();
        assert_eq!(writer.stripped().unwrap(), document);
    }

    #[test]
    fn a_file_buffer_that_cannot_be_read_is_an_error_not_a_panic() {
        let path = scratch_path("write-only");
        let writer = Writer::new(WriteBuffer::File(File::create(&path).unwrap())).unwrap();
        assert!(writer.into_string().is_err());
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn a_text_built_from_a_prefix_constant_is_a_notice() {
        // The constants are what every notice writer opens with, and what `Writer::write_notice`
        // admits; a text built from either must read as a notice, and one that re-spaces the prefix,
        // or carries none, must not. Formatting through the constant is the contract the writers hold
        // to, so the matcher is tested through it and through the two constructors.
        assert!(is_notice(&format!(
            "{DEPRECATION_PREFIX} the clause at 1:1 moved"
        )));
        assert!(is_notice(&format!(
            "{WARNING_PREFIX} duplicate key /A in data file f"
        )));
        assert!(is_notice(&warning(format_args!(
            "duplicate key /A in data file f"
        ))));
        assert!(is_notice(&deprecation("the clause at 1:1 moved")));
        assert!(!is_notice("DEPRECATION : the clause at 1:1 moved"));
        assert!(!is_notice("Warning : duplicate key /A in data file f"));
        assert!(!is_notice("Error handling rule file = f, Error = x"));
        assert!(!is_notice(""));
    }

    /// Text a notice quotes from outside the program is escaped at the point it is written in: every
    /// control character (a line feed, a carriage return, an ESC that would open a terminal escape
    /// sequence), the backslash, U+0085 and the two Unicode line separators come out as their Rust
    /// escapes and everything else is kept, so a warning built from the escaped text is one line with
    /// no raw control character, and two keys that would print alike without the backslash escape
    /// (`a<LF>b` and the four characters `a\nb`) print apart.
    #[test]
    fn data_quoted_by_a_notice_is_escaped_at_its_point() {
        assert_eq!("/a\\nb", escaped_for_display("/a\nb"));
        assert_eq!("/a\\\\nb", escaped_for_display("/a\\nb"));
        assert_ne!(escaped_for_display("/a\nb"), escaped_for_display("/a\\nb"));
        assert_eq!("x\\r\\ny", escaped_for_display("x\r\ny"));
        assert_eq!("a\\u{1b}]b", escaped_for_display("a\u{1b}]b"));
        assert_eq!(
            "a\\u{85}b\\u{2028}c\\u{2029}d\\te",
            escaped_for_display("a\u{85}b\u{2028}c\u{2029}d\te")
        );
        assert_eq!(
            "plain /Resources/A",
            escaped_for_display("plain /Resources/A")
        );
        assert_eq!("ünïcödé 日本", escaped_for_display("ünïcödé 日本"));

        let line = warning(format_args!(
            "duplicate key {} in data file {}",
            escaped_for_display("/a\u{1b}]b"),
            escaped_for_display("f\nile")
        ));
        assert_eq!(1, line.lines().count(), "{:?}", line);
        assert!(!line.contains('\u{1b}'), "{:?}", line);
        assert_eq!(
            format!(
                "{} duplicate key /a\\u{{1b}}]b in data file f\\nile",
                WARNING_PREFIX
            ),
            line
        );
        assert!(is_notice(&line));
    }

    /// A file name, and text built from several sources, keep their backslashes: only the characters
    /// that break or hide a line are escaped, so a Windows path reads once, the same way, on every
    /// stream, and a name holding a line feed still gives a one-line warning.
    #[test]
    fn a_file_name_keeps_its_backslashes_and_escapes_its_control_characters() {
        assert_eq!(
            "\\\\?\\C:\\dir\\t.yaml",
            escaped_controls_for_display("\\\\?\\C:\\dir\\t.yaml")
        );
        assert_ne!(
            escaped_for_display("\\\\?\\C:\\dir\\t.yaml"),
            escaped_controls_for_display("\\\\?\\C:\\dir\\t.yaml")
        );
        assert_eq!("li\\nne.yaml", escaped_controls_for_display("li\nne.yaml"));
        assert_eq!(
            "a\\u{1b}]b\\u{85}c\\u{2028}d\\u{2029}e\\tf",
            escaped_controls_for_display("a\u{1b}]b\u{85}c\u{2028}d\u{2029}e\tf")
        );
        let line = warning(format_args!(
            "{} was not evaluated",
            escaped_controls_for_display("C:\\di\nr\\t.yaml")
        ));
        assert_eq!(
            format!("{} C:\\di\\nr\\t.yaml was not evaluated", WARNING_PREFIX),
            line
        );
    }

    /// A bidirectional control or a zero-width format character is escaped by both escapings, as a
    /// control character is: a key holding U+202E would otherwise reverse the rest of the warning on a
    /// bidi-aware terminal, and one holding U+200B would print as a key it is not. The escape is the
    /// `\u{...}` form, so the reader sees which character it was. Red before: `char::is_control` is
    /// category Cc only, and both passed through raw.
    #[test]
    fn a_bidi_control_or_zero_width_character_is_escaped() {
        assert_eq!(
            "a\\u{202e}b\\u{2066}c\\u{200b}d\\u{200d}e\\u{2060}f\\u{feff}g\\u{61c}h\\u{200e}i",
            escaped_for_display(
                "a\u{202E}b\u{2066}c\u{200B}d\u{200D}e\u{2060}f\u{FEFF}g\u{061C}h\u{200E}i"
            )
        );
        assert_eq!(
            "a\\u{202e}b\\u{2069}c\\u{200c}d\\u{200f}e",
            escaped_controls_for_display("a\u{202E}b\u{2069}c\u{200C}d\u{200F}e")
        );
        let line = warning(format_args!(
            "duplicate key {} in data file {}",
            escaped_for_display("/a\u{202E}b"),
            escaped_controls_for_display("f\u{200B}ile.yaml")
        ));
        assert_eq!(
            format!(
                "{} duplicate key /a\\u{{202e}}b in data file f\\u{{200b}}ile.yaml",
                WARNING_PREFIX
            ),
            line
        );
        // Letters, digits, punctuation and combining marks outside the two sets stay as written.
        assert_eq!(
            "ünïcödé 日本 e\u{301}",
            escaped_for_display("ünïcödé 日本 e\u{301}")
        );
    }

    /// A rules file position is named in a notice with its path escaped as a file name: the line feed
    /// and the ESC become their escapes, the backslashes stay, and the line and column are untouched.
    #[test]
    fn a_location_is_named_with_its_path_escaped_as_a_file_name() {
        let location = crate::rules::exprs::FileLocation {
            file_name: "C:\\ru\nles\u{1b}.guard",
            line: 3,
            column: 7,
        };
        assert_eq!(
            "Location[file:C:\\ru\\nles\\u{1b}.guard, line:3, column:7]",
            location_for_notice(&location)
        );
        assert_eq!(1, location_for_notice(&location).lines().count());
    }

    /// A rules file position DISPLAYS with its path escaped as a file name, wherever it is printed (a record
    /// context, a refusal's text), and a plain path is displayed as it is. The notice form is unchanged
    /// (escaping an escaped text changes nothing: a backslash is written as it is).
    ///
    /// Fails when the display carries the raw ESC or line feed, doubles a backslash, or changes
    /// a path with nothing to escape.
    #[test]
    fn a_locations_display_escapes_its_path_and_leaves_a_plain_one_alone() {
        let hidden = crate::rules::exprs::FileLocation {
            file_name: "C:\\ru\nles\u{1b}.guard",
            line: 3,
            column: 7,
        };
        assert_eq!(
            "Location[file:C:\\ru\\nles\\u{1b}.guard, line:3, column:7]",
            hidden.to_string()
        );
        assert_eq!(location_for_notice(&hidden), hidden.to_string());
        let plain = crate::rules::exprs::FileLocation {
            file_name: "rules/main.guard",
            line: 1,
            column: 2,
        };
        assert_eq!(
            "Location[file:rules/main.guard, line:1, column:2]",
            plain.to_string()
        );
    }

    /// In a debug build the warning constructor refuses a body that still holds a line break: the
    /// data in it was not escaped at its point.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a warning is one line")]
    fn a_warning_body_still_holding_a_line_break_is_refused_in_a_debug_build() {
        warning(format_args!("duplicate key /a\nb in data file f"));
    }

    /// The same refusal for every character that breaks or hides a line, not only `\n` and `\r`: an
    /// ESC that would open a terminal escape sequence, and a Unicode line separator.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a warning is one line")]
    fn a_warning_body_still_holding_an_escape_character_is_refused_in_a_debug_build() {
        warning(format_args!("duplicate key /a\u{1b}]b in data file f"));
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "a warning is one line")]
    fn a_warning_body_still_holding_a_line_separator_is_refused_in_a_debug_build() {
        warning(format_args!("duplicate key /a\u{2028}b in data file f"));
    }

    /// A deprecation notice keeps its body as written, line breaks included, after the leading
    /// whitespace a clause's display opens with is trimmed: the readers of the error stream take
    /// notices from the writer's record, so a second line of one is never read as failure text, and
    /// a notice that quotes a clause written over several lines quotes it as written.
    #[test]
    fn a_deprecation_keeps_its_body_as_written_after_the_trim() {
        let line = deprecation(" the clause\n  Sizes == 50\npassed");
        assert_eq!(
            format!("{} the clause\n  Sizes == 50\npassed", DEPRECATION_PREFIX),
            line
        );
        assert_eq!(3, line.lines().count(), "{:?}", line);
        assert!(is_notice(&line));
    }

    /// A body that already opens with the prefix is a builder spelling it for itself; a debug build
    /// refuses it where it is joined, so no notice reads "DEPRECATION: DEPRECATION: ...".
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "already carries the prefix")]
    fn a_deprecation_body_that_already_carries_the_prefix_is_refused_in_a_debug_build() {
        deprecation(&format!("{DEPRECATION_PREFIX} the clause at 1:1 moved"));
    }

    /// A note is a notice of its own kind: `is_notice` accepts it, so the library entry keeps it out of
    /// a failure text, and the writer's record tells it from a warning and a deprecation, so a reader
    /// that wants the deprecations alone is not handed the trailer. The trailer the single-line
    /// `validate` output writes is a note, never a deprecation.
    #[test]
    fn a_note_is_a_notice_of_its_own_kind() {
        let note =
            format!("{NOTE_PREFIX} also drawn by b.yaml: the filter notice for the site at L");
        assert!(is_notice(&note));
        assert_eq!(Some(StderrPrefix::Note), StderrPrefix::of(&note));
        assert_eq!(
            Some(StderrPrefix::Deprecation),
            StderrPrefix::of(&format!("{DEPRECATION_PREFIX} a clause moved"))
        );
        assert_eq!(
            Some(StderrPrefix::Warning),
            StderrPrefix::of(&format!("{WARNING_PREFIX} duplicate key"))
        );
        assert_eq!(None, StderrPrefix::of("Error handling rule file"));

        let trailer = repeated_notice_trailer(
            &["the filter notice for the site at L".to_string()],
            &["b.yaml".to_string()],
            &[],
        );
        assert_eq!(note, trailer);
        assert_eq!(Some(StderrPrefix::Note), StderrPrefix::of(&trailer));

        let mut writer = Writer::new_with_err(WriteBuffer::Vec(vec![]), WriteBuffer::Vec(vec![]))
            .expect("Failed to create writer.");
        writer
            .write_notice(format!("{DEPRECATION_PREFIX} first"))
            .expect("written");
        writer.write_notice(trailer.clone()).expect("written");
        writer
            .write_notice(format!("{WARNING_PREFIX} duplicate key /A in data file f"))
            .expect("written");
        assert_eq!(3, writer.notices().len());
        assert_eq!(
            vec![&format!("{DEPRECATION_PREFIX} first")],
            writer
                .notices_of(StderrPrefix::Deprecation)
                .collect::<Vec<_>>(),
            "the deprecations alone, without the note"
        );
        assert_eq!(
            vec![&trailer],
            writer.notices_of(StderrPrefix::Note).collect::<Vec<_>>()
        );
    }

    /// The files a trailer names are always shortened past three, and two lists that would read the same
    /// shortened are told apart by the first name where they differ, appended after the count, so a
    /// trailer's length is bounded by the number of such neighbors and never by the number of files.
    #[test]
    fn the_trailer_file_list_is_always_shortened_and_told_apart_by_a_name() {
        let files: Vec<String> = (2..=200).map(|i| format!("t{i}.yaml")).collect();
        let without = |skip: &str| -> Vec<String> {
            files
                .iter()
                .filter(|f| f.as_str() != skip)
                .cloned()
                .collect()
        };
        assert_eq!(
            "t2.yaml, t3.yaml, t4.yaml and 195 more",
            trailer_file_list(&without("t50.yaml"), &[])
        );
        assert_eq!(
            "t2.yaml, t3.yaml, t4.yaml and 195 more, not t60.yaml",
            trailer_file_list(&without("t50.yaml"), &["not t60.yaml".to_string()])
        );
        assert_eq!(
            "a.yaml, b.yaml",
            trailer_file_list(&["a.yaml".to_string(), "b.yaml".to_string()], &[])
        );
        assert_eq!(
            "a.yaml, b.yaml, c.yaml",
            trailer_file_list(
                &[
                    "a.yaml".to_string(),
                    "b.yaml".to_string(),
                    "c.yaml".to_string()
                ],
                &[]
            )
        );
    }

    /// The backstop keeps the two colour sequences the writers emit, a line feed and a tab, and writes
    /// every other escape sequence as its escape: a conceal, a 256-colour form, an empty parameter list,
    /// a sequence cut short (an ESC at the end of the text, or `ESC [` with no final letter), and an ESC
    /// that opens an operating-system command. Text that is already escaped passes unchanged.
    ///
    /// Fails when a row keeps its ESC byte (the backstop kept a well-formed sequence of any
    /// kind), or when a kept sequence, the tab or the line feed is written as an escape.
    #[test]
    fn the_backstop_keeps_only_the_writers_two_colour_sequences() {
        let esc = char::from(0x1b);
        let rows: Vec<(&str, String, String)> = vec![
            (
                "the green and the reset, with a tab and a line feed",
                format!("{esc}[92m 3.\tType: X{esc}[0m\n"),
                format!("{esc}[92m 3.\tType: X{esc}[0m\n"),
            ),
            (
                "a conceal",
                format!("a{esc}[8mb"),
                "a\\u{1b}[8mb".to_string(),
            ),
            (
                "a 256-colour form",
                format!("a{esc}[38;5;196mb"),
                "a\\u{1b}[38;5;196mb".to_string(),
            ),
            (
                "an empty parameter list",
                format!("a{esc}[mb"),
                "a\\u{1b}[mb".to_string(),
            ),
            (
                "an ESC at the end of the text",
                format!("ab{esc}"),
                "ab\\u{1b}".to_string(),
            ),
            (
                "ESC [ with no final letter",
                format!("a{esc}[b"),
                "a\\u{1b}[b".to_string(),
            ),
            (
                "an operating-system command",
                format!("a{esc}]0;title"),
                "a\\u{1b}]0;title".to_string(),
            ),
            (
                "text that is already escaped",
                "a\\u{1b}[8mb".to_string(),
                "a\\u{1b}[8mb".to_string(),
            ),
        ];
        for (label, given, expected) in rows {
            assert_eq!(
                expected,
                escaped_but_for_colour_and_layout(&given),
                "{}",
                label
            );
        }
    }
}
