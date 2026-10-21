use fancy_regex::Regex;
use std::convert::TryFrom;
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

use indexmap::map::IndexMap;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_till};
use nom::bytes::complete::{take_while, take_while1};
use nom::character::complete::{alpha1, space1};
use nom::character::complete::{anychar, digit1, one_of};
use nom::character::complete::{char, multispace0, multispace1, space0};
use nom::combinator::{cut, peek};
use nom::combinator::{map, opt, recognize, value};
use nom::error::context;
use nom::error::ErrorKind;
use nom::multi::{fold_many1, separated_list0, separated_list1};
use nom::multi::{many0, many1};
use nom::number::complete::double;
use nom::sequence::{delimited, preceded};
use nom::sequence::{pair, terminated};
use nom::sequence::{separated_pair, tuple};
use nom::InputTake;
use nom_locate::LocatedSpan;

use crate::rules::errors::Error;
use crate::rules::eval_context::FunctionName;
use crate::rules::exprs::*;
use crate::rules::path_value::{Path, PathAwareValue};
use crate::rules::values::*;

pub(crate) type Span<'a> = LocatedSpan<&'a str, &'a str>;
const DEFAULT_RULE_NAME: &str = "default";

pub(crate) fn from_str2(in_str: &str) -> Span {
    Span::new_extra(in_str, "")
}

thread_local! {
    /// Where each line of the rules file being parsed starts, or `None` outside a [`rules_file`] call.
    ///
    /// Parse-scoped state, for the same reason `NESTING_DEPTH` is: `nom`'s combinator signatures carry a
    /// `Span` and nothing else, so a parser deep in the grammar cannot be handed the whole file, and this is
    /// the only thing that can tell it where a byte offset sits. Set and restored by [`SourceScope`]. It
    /// shapes error text only, never what the grammar accepts.
    ///
    /// The analogy is to being parse-scoped and stops there. `NESTING_DEPTH` is a counter, so it composes
    /// under nesting on its own; this is a single slot, so a nested writer has to put back what it
    /// displaced rather than clear it. [`SourceScope`] carries that difference.
    static SOURCE: std::cell::RefCell<Option<LineIndex>> =
        const { std::cell::RefCell::new(None) };
}

/// Where every line of a rules file starts, so that a byte offset can be turned into a line and a column.
///
/// `nom_locate` already answers that question -- `location_line()` and `get_utf8_column()` -- but it answers
/// it by counting `\n` alone, and this parser reads a bare `\r` as a line ending too: `multispace1` accepts
/// `" \t\r\n"`, `comment2` ends a comment at either, and `newline` and `extract_message` both take either.
/// So in a file whose lines end with a bare CR, the file parsed correctly and then reported every position
/// in it wrongly -- one error physically on line 6 came out as *line 1, column 119*, 119 being the whole-file
/// byte offset, because with no `\n` anywhere the file is one line and the column degenerates into the
/// offset. Every clause `FileLocation`, the nesting-depth refusal, and the parse-error message all reported
/// that way, and nothing in the output said so: "line 1 column 119" is a position, just not the error's.
///
/// Counting here rather than fixing it at each of the ten reporting sites, because a position computed one
/// way in nine places and another way in the tenth is the defect again. `position_of` is the only place any
/// of them now asks.
///
/// The `String` is a copy of the file. One allocation of a few KB per parse, which buys a `line_starts` scan
/// done once instead of a backwards search per position: the column needs the text to count characters
/// rather than bytes, and a UTF-8 aware count cannot be reconstructed from offsets alone.
struct LineIndex {
    text: String,
    /// Byte offset of the first character of each line, ascending, always starting with 0.
    line_starts: Vec<usize>,
}

impl LineIndex {
    fn of(text: &str) -> LineIndex {
        let bytes = text.as_bytes();
        let mut line_starts = vec![0];
        for (at, byte) in bytes.iter().enumerate() {
            // `\r\n` is one line ending, not two: the `\r` starts nothing, the `\n` after it does.
            let ends_a_line = match *byte {
                b'\n' => true,
                b'\r' => bytes.get(at + 1) != Some(&b'\n'),
                _ => false,
            };
            if ends_a_line {
                line_starts.push(at + 1);
            }
        }

        LineIndex {
            text: text.to_string(),
            line_starts,
        }
    }

    /// The one-based line and character column of a byte offset.
    ///
    /// Identical to what `nom_locate` reports for a file whose only line ending is `\n`, which is what keeps
    /// this from moving every position in every existing rules file: the line is one plus the number of line
    /// endings before the offset, and the column is one plus the number of characters since the last one.
    fn position(&self, offset: usize) -> (u32, u32) {
        let offset = offset.min(self.text.len());
        let line = self.line_starts.partition_point(|start| *start <= offset);
        let start = self.line_starts[line - 1];
        let column = self.text[start..offset].chars().count() + 1;
        (line as u32, column as u32)
    }
}

/// One rules file held open for position reporting, restored to what it displaced when it goes out of scope.
///
/// `Drop` rather than an explicit clear, so that the early return on a parse error cannot leave a previous
/// file's index behind for the next parse on this thread to read positions out of.
///
/// Restores rather than clears, and the difference is the whole reason this holds a field. `enter` opens
/// nothing when handed an advanced span, and a `Drop` that cleared `SOURCE` either way would have the two
/// halves disagree about whether this scope owned the slot. A nested or re-entrant [`rules_file`] would
/// then, on the inner call's return, leave the *outer* parse with `SOURCE = None` for the rest of its own
/// parse --
/// silently reverting every position after that point to `nom_locate`'s `\n`-only answer, which is the
/// defect [`LineIndex`] exists to fix, reappearing partway through one file's positions.
///
/// Unreachable today, and checked rather than assumed: the only in-file caller of [`rules_file`] is
/// `TryFrom<&str> for RulesFile`, which is outside the grammar, and the four in-grammar
/// `PathAwareValue::try_from` calls take an already-parsed `Value` rather than a `&str`. Neither
/// `Cargo.toml` sets `panic = "abort"`, so an unwind runs this `Drop` and is not a leak path either. It is
/// a future-caller exposure, which is exactly what `enter`'s offset-0 gate is there to protect against --
/// a gate that guards one direction while `Drop` gives the other away is not a gate.
///
/// The `NESTING_DEPTH` analogy in `SOURCE`'s own comment covers parse-scoping and does not extend to this:
/// `NESTING_DEPTH` increments and decrements, so it composes under nesting by construction, while a slot
/// holds one value and a nested writer has to put back what it displaced.
struct SourceScope {
    /// What `SOURCE` held before this scope replaced it, or `None` if this scope replaced nothing and
    /// `Drop` must therefore leave `SOURCE` exactly as it found it.
    ///
    /// `Option<Option<LineIndex>>`, because "this scope opened nothing" and "this scope displaced nothing"
    /// are different states and only the first one means `Drop` must keep its hands off.
    previous: Option<Option<LineIndex>>,
}

impl SourceScope {
    /// Opens `span`'s file for position reporting, if `span` is the whole of it.
    ///
    /// The offsets a position is looked up by are absolute, so an index built from a span that has already
    /// consumed something would answer against the wrong text -- and answer plausibly, which is worse than
    /// refusing. An advanced span therefore opens nothing and leaves `position_of` on its `nom_locate`
    /// fallback. Every caller of [`rules_file`] passes a fresh span; this is what keeps a future one that
    /// does not from silently reporting positions into the middle of its own file.
    fn enter(span: &Span) -> SourceScope {
        let previous = if span.location_offset() == 0 {
            let index = LineIndex::of(span.fragment());
            Some(SOURCE.with(|source| source.borrow_mut().replace(index)))
        } else {
            None
        };
        SourceScope { previous }
    }
}

impl Drop for SourceScope {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            SOURCE.with(|source| *source.borrow_mut() = previous);
        }
    }
}

/// The line and column to report for `span`, counting a bare `\r` as a line ending like the rest of this
/// parser does.
///
/// Falls back to `nom_locate`'s own answer when no file is open, which is what the parsers reached directly
/// rather than through [`rules_file`] get: `Value::try_from(&str)` parsing one value, and the unit tests that
/// call a single combinator. Those inputs are a value or a clause rather than a file, so the fallback is the
/// same answer this would give -- and it is the answer they got before this existed.
pub(in crate::rules) fn position_of(span: &Span) -> (u32, u32) {
    SOURCE.with(|source| match source.borrow().as_ref() {
        Some(index) => index.position(span.location_offset()),
        None => (span.location_line(), span.get_utf8_column() as u32),
    })
}

/// Whether `span` sits on the terminator line of a block message, right after its `>>`: the text of its
/// line before it ends in `>>`, spaces and tabs aside, and that line holds no `<<`. `false` when no file is
/// open, and `false` for an offset that is not a character boundary of the open file (a span taken from
/// some other string), rather than a slice panic.
///
/// Read by `rule_clause` only to word an error (see `extract_message`); it never decides what the grammar
/// accepts.
fn block_terminator_precedes(span: &Span) -> bool {
    SOURCE.with(|source| {
        source.borrow().as_ref().is_some_and(|index| {
            let offset = span.location_offset();
            let Some(before) = index.text.get(..offset) else {
                return false;
            };
            if !before.trim_end_matches([' ', '\t']).ends_with(">>") {
                return false;
            }
            let line = index.line_starts.partition_point(|start| *start <= offset);
            !before[index.line_starts[line - 1]..].contains("<<")
        })
    })
}

/// Where a clause begins, as it will be reported.
///
/// One function for the seven places that stamp a position onto a parsed expression, so that none spells it
/// out itself. Spelled out at each site, six would ask for `get_utf8_column` and the seventh --
/// `function_expr` -- for `get_column`, a byte column, so a file with a multi-byte character in a line would
/// report that one clause at a different column than the six around it. That is what duplicated position
/// code costs: nothing looks wrong at any one of the seven.
fn file_location_of<'loc>(input: &Span<'loc>) -> FileLocation<'loc> {
    let (line, column) = position_of(input);
    FileLocation {
        file_name: input.extra,
        line,
        column,
    }
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ParserError<'a> {
    pub(crate) context: String,
    pub(crate) span: Span<'a>,
    pub(crate) kind: ErrorKind,
}

pub(crate) type IResult<'a, I, O> = nom::IResult<I, O, ParserError<'a>>;

impl<'a> nom::error::ContextError<Span<'a>> for ParserError<'a> {
    fn add_context(input: Span<'a>, ctx: &'static str, other: Self) -> Self {
        let context = if other.context.is_empty() {
            ctx.to_string()
        } else {
            format!("{}/{}", ctx, other.context)
        };

        ParserError {
            context,
            span: input,
            kind: other.kind,
        }
    }
}

impl<'a> nom::error::ParseError<Span<'a>> for ParserError<'a> {
    fn from_error_kind(input: Span<'a>, kind: ErrorKind) -> Self {
        ParserError {
            context: "".to_string(),
            span: input,
            kind,
        }
    }

    fn append(_input: Span<'a>, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}

impl<'a> std::fmt::Display for ParserError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let (line, column) = position_of(&self.span);
        let fragment = *self.span.fragment();
        // U+FEFF renders as nothing, so a fragment that begins with one reads as text that parses and
        // the message says the file is wrong at a position where nothing looks wrong. The one place the
        // mark is accepted is ahead of the first character, and `rules_file` strips it there before any
        // parser runs; a fragment starting with it is therefore a mark somewhere else in the file --
        // two files concatenated, say -- and is named as the cause.
        let byte_order_mark = if fragment.starts_with('\u{feff}') {
            " a UTF-8 byte order mark (U+FEFF), which is not whitespace and has to be removed, at"
        } else {
            ""
        };
        let message = format!(
            "Error parsing file {} at line {} at column {}, when handling {},{} fragment {}",
            self.span.extra, line, column, self.context, byte_order_mark, fragment
        );
        f.write_str(&message)?;
        Ok(())
    }
}

/// How many nesting constructs a rules file may nest inside one another: blocks, list and map literals,
/// query filters, key filters and function calls.
///
/// There has to be a bound, because the recursive descent recurses once per level and overflows the
/// stack. Measured on a release build of this repository *without* the bound -- which is the only build
/// the number is measurable on, since with it the file is refused at 129 -- `parse-tree --rules` on a
/// file of nested block clauses (`rule a { Resources { ... Type exists ... } }`): level 1602 parses,
/// level 1603 aborts with SIGABRT and "fatal runtime error: stack overflow" on stderr, reported as 134
/// by a shell. 134 is
/// outside the set this tool documents (0 pass, 5 rules-file or data error, 19 validation failure), so
/// a caller saw neither a pass nor a failure it could report. `validate` and `test` abort at the same
/// depth on the same file. This is the same defect class, and the same argument, as the `let` cycle and
/// rule-reference cycle checks: an authoring mistake that killed the process rather than being refused.
///
/// Nested blocks are not the only recursion that reaches it. Ten spellings were measured to abort, at
/// depths spread over two orders of magnitude, so a bound on any one of them would have left the rest
/// fatal:
///
/// ```text
/// nested block clauses     Resources { Resources { ... } }        parses 1602, aborts 1603
/// nested `when` blocks     when Type == "x" { when ... { } }      parses 2000, aborts 4000
/// nested map literals      Type == {k: {k: ... } }                parses 2000, aborts 4000
/// nested list literals     Type == [[[ ... ]]]                    parses 4000, aborts 8000
/// nested query filters     A[ A[ ... ] exists ] exists            parses 1112, aborts 1114  <- nearest
/// the same under a `let`   let q = A[ A[ ... ] exists ]           parses 1112, aborts 1114
/// nested key filters       Tags[ keys == a[ keys == a ] ] exists  parses  129, aborts 2000
/// a call in an assignment  let x = to_upper(to_upper( ... ))      parses 2000, aborts 3000
/// a call as an argument    b(to_upper(to_upper( ... )))           parses 2000, aborts 3000
/// a call as a right side   Type == to_upper(to_upper( ... ))      parses 2000, aborts 3000
/// ```
///
/// Every shape above is written so that it parses as it stands, which five of them did not. The
/// query-filter and key-filter rows each dropped the trailing `exists`, and a filter query with no operator
/// after the closing bracket is a syntax error rather than a deep file: anyone re-deriving these numbers
/// renders the row, gets "There were no clauses present", and concludes the construct does not exist. The
/// three function-call rows spelled the function `f`, which is not one -- `FunctionName::try_from` accepts
/// fifteen names and rejects the rest -- so those rows were refused at 5 on the `(`, `access` having taken
/// `f` as a query, with a fragment in the message where a reader expects a depth. `to_upper` is a real name
/// and the one `nested_rules_file` generates. The `let` row needs no trailing operator, because a `let`
/// value is a query. Render the row, do not paraphrase it.
///
/// (Some rows are coarse ladders -- 2000/4000/8000 -- and the exact threshold does not matter for a bound
/// an order of magnitude or more below it. The query-filter rows are bisected rung by rung instead, because
/// theirs is the **nearest** abort to 128 of all ten and so the one the bound has to clear. Two
/// caveats. The boundary is one rung wide -- **1112 parses, 1113 is the unrepeatable rung, 1114 always
/// aborts**. Repeated runs at 1113 split between parsing and aborting. That is stack-start jitter, from
/// environment size and ASLR, and it is *not* affected by how stdout is handled, which was checked
/// over twelve depths with the output discarded and piped and agreed at every one. So do not read a
/// single run at the boundary as the boundary -- three of the values this line has carried came from
/// doing exactly that.
///
/// And the number is a property of the build it was measured on. The two filter rows carry the boundary
/// of the parser as it is, the one that parses a clause's query once: 1112 parses, 1114 always aborts.
/// The build before that fix, which re-parsed the query once per reading of it and so cost time
/// exponential in the depth, aborted seven levels shallower -- 1105 parses, 1106 is its jittery rung, 1107
/// always aborts -- and that figure is retired from the table because the shipped parser is not that
/// build. Parse time and stack are different quantities: the linear time is what
/// `nested_query_filters_cost_time_linear_in_the_depth` pins, while the depth here is set by what a filter
/// level costs in stack, which the same fix also moved. A parser that spent more stack per level would
/// abort shallower, one that spent less would get deeper, and either way this figure would need
/// re-measuring. It is recorded because that movement is the point -- a bound justified by "deeper files
/// abort anyway" would have to be re-derived every time the parser changes, and this one is not: see the
/// argument for 128 at the end.) The ten spellings share no single function, which is why the count is
/// kept per open construct in a thread-local rather than passed down
/// as a parameter. Six functions open a level, one per construct that can contain another:
///
/// ```text
/// block                     every `{ ... }` body, so blocks and `when` blocks and type blocks
/// parse_list, parse_map     a list or map literal, which no block passes through
/// predicate_filter_clauses  a query filter, reached from a clause and from an assignment alike
/// map_keys_match            a key filter, whose right-hand side is a query or a call
/// call_expr                 a function call, in a `let`, as a rule argument or as a right-hand side
/// ```
///
/// That set is chosen to be complete rather than to be a list of shapes someone thought to try: every
/// construct that can contain another passes through one of the six, so nothing nests without incrementing
/// the counter. That is a claim about these six call sites against the grammar, and it is checkable by
/// reading them; what pins it from outside is that the paired test drives all six, one per construct. The
/// last three are needed as well as the first three because the first bound covered blocks, lists and maps
/// only, and a query filter, a key filter and a function call each still recursed with nothing counting
/// the levels -- measured aborting at 1114, 2000 and 3000 respectively, which is what the six filter,
/// key-filter and function-call rows above are spellings of.
///
/// Deliberately no count of the functions involved. This file is built from higher-order `nom` combinators,
/// and whether a parser handed to `block(clause)` or to `when_block`'s second position belongs to the
/// caller, to the callee, or to neither changes the size of every component in the call graph: four
/// defensible models of this one file gave 8, 22, 23 and 25 for the component that survives removing the
/// first three, and a count that names no model does not reproduce when somebody else recomputes it. What is
/// model-independent is the delta: `clause_tail_with_map`
/// and `access_clause_or_block` joined the cyclic core when a clause's query started being parsed once
/// rather than once per reading of it, and every model agrees on those two. Do not put a number back here
/// without also saying how arguments to higher-order combinators are attributed.
///
/// Threading a depth argument instead would have changed the signature of every function on all of those
/// paths -- `clause`, `access`, `cnf_clauses`, `disjunction_clauses`, `parse_value`, `let_value` and
/// everything between -- and of the `pub(crate)` ones the tests call directly, to carry one integer.
///
/// A query filter is bounded here as a depth, not as a cost. Its parse cost is linear in the depth:
/// `nested_query_filters_cost_time_linear_in_the_depth` in `parser_tests.rs` pins a deep-to-shallow ratio
/// under 50 where a parse that doubled per level would read 256, and its doc measures about 112 us against
/// 151 us per parse. So a filter never "becomes unusable before it gets deep enough to abort": the depth
/// at which an unbounded descent overflows the stack is reachable in ordinary time, which is why the bound
/// is needed on this path. It fires during the descent: the refusal is a `Failure`, which nom propagates
/// out of `alt`, `opt` and `fold_many1` without retrying, so a 2000-deep filter is refused in 0.01 seconds.
/// The deepest `[` nesting in either corpus is 3.
///
/// 128 is the value the data loader already enforces on the other kind of input this tool reads
/// (`libyaml::loader::MAX_NESTING_DEPTH`), and there is no reason for the two answers to "how deeply may
/// input nest" to differ. It is far above anything real: over both corpora -- every `.guard` and
/// `.ruleset` in this repository and in the rules registry snapshot -- the deepest is **7** levels, and
/// nothing reaches 8. Two files tie at 7: `guard-examples/cross-account/sns-cross-account.guard` and the
/// registry's `cloudfront_origin_access_identity_enabled.guard`. So the bound clears the whole corpus by
/// more than an order of magnitude rather than merely clearing its maximum, and that is the form of the
/// claim worth keeping: an example file twice as deep as today's deepest would still not approach 128. And
/// it is below every abort above, the nearest of which is 1114.
///
/// Deliberately no file counts here, and no per-level histogram. Re-derive instead: set this constant to
/// N, rebuild, and parse every file, taking a file's level to be the smallest N that accepts it; N = 8
/// admitting nothing further is the check that the maximum has been found. Two cautions, both learned by
/// getting this wrong. A few fixtures are deliberately unparsable and `parse-tree --rules` refuses them at
/// every N -- list them by taking the files no N accepts -- so bucket a file only once some N has accepted
/// it, because one that trips the depth bound at N = 1 and then fails for syntax will otherwise land in the
/// N = 2 bucket and inflate it. And a count of the files in this repository does not survive being written
/// down inside it: adding a fixture is the most ordinary change there is and nothing connects the two, so
/// each of the last revisions of this paragraph carried a total that a later commit in the same pull request
/// invalidated.
///
/// The argument for 128 is that no real file is near it, and deliberately not that files past it would
/// have been unusable anyway. That second argument is the kind that goes stale as the parser gets faster,
/// and it has: a query filter parses in time linear in its depth
/// (`nested_query_filters_cost_time_linear_in_the_depth` in `parser_tests.rs` pins it), so on a
/// build without the nesting bound a 1000-level filter parses in 1.97 seconds, where a parse that
/// doubled per level does not finish in 40; with the bound, the same file is refused in about 0.01
/// seconds. So a depth this bound refuses is not a depth nothing could evaluate -- it is a depth
/// nothing anyone writes
/// reaches, which is the claim the corpus supports and the one that stays true however fast the parser
/// gets.
const MAX_NESTING_DEPTH: usize = 128;

thread_local! {
    /// How many nesting constructs are open at this point in the parse, on this thread.
    ///
    /// Thread-local so the bound does not depend on which thread is parsing, and specifically not on
    /// that thread's stack size: `cargo test` parses on libtest's threads rather than on `main`, and a
    /// limit derived from the stack would then admit a different set of files under test than in the
    /// binary. A fixed count admits the same files everywhere.
    ///
    /// What that buys is a consistent *count*, and it is worth being precise that the abort the count
    /// exists to prevent is not thread-independent at all -- and not profile-independent either. Every
    /// threshold on [`MAX_NESTING_DEPTH`] is the CLI's `main`, which gets 8 MB here; a Rust thread gets
    /// 2 MB by default, so libtest's ceiling is roughly a quarter of it. **Every number in this comment
    /// is an optimized build.** Measured by raising this bound to 100_000 in a throwaway build and
    /// laddering each shape on a libtest thread, three runs per rung:
    ///
    /// ```text
    /// query filter    290 ok, 291 aborts     <- binding, and the same shape that is nearest on `main`
    /// key filter      315 ok, 317 aborts
    /// block clause    beyond 360
    /// function call   beyond 360
    /// ```
    ///
    /// The query filter is the binding shape on both stacks, which is worth stating because it is not the
    /// one a reader would guess: a key filter reaches `access` through the same `predicate_or_index`, and
    /// costs *less* stack per level. A ladder too coarse to separate them cannot tell which is binding:
    /// 300 ok, 350 aborts brackets 291 and 317 both.
    ///
    /// **The guard on that path costs 13 of those levels, and the 291 above is the number with the cost
    /// already in it.** Measured on one tree, three variants differing by one line, first depth that always
    /// aborts: the guard as written, **291**; called but not held live across the recursive descent,
    /// **292**; removed entirely, **304**, with 302 still passing. So 304 - 291 = 13, of which holding the
    /// value is 1 and the call is the other 12 -- `enter` takes a `Span` and a `&str` and returns
    /// `Result<NestingGuard, nom::Err<ParserError>>`, and that return slot is per-frame on every level of
    /// the descent, whether or not the bound ever fires. Worth writing down for two reasons. A reader
    /// measuring this path on a build without the guard gets 304, not 291, and would otherwise think one of
    /// the two numbers wrong; that is exactly the disagreement that produced this paragraph, and it took
    /// comparing ceilings to ceilings in one unit to settle it. And the headroom figure below is the honest
    /// one, because it is computed from the guarded build rather than from an unguarded ceiling the shipped
    /// parser never has.
    ///
    /// At 128 that leaves the tests about 2.3x of headroom (290/128) rather than the far larger margin the
    /// CLI's own figures imply, where the nearest abort is 1114 -- **optimized**. (Stated as its input
    /// rather than as a ratio on purpose. A ratio computed from an abort depth and written down once
    /// goes stale as soon as the depth is re-measured, because a re-measurement corrects the depth
    /// where it is stated and leaves every value derived from it as it was; so the table's figure,
    /// 1114, is one of the measured ones (the shipped build's), the input is stated here, and the reader
    /// derives the ratio from it.) Unoptimized it is not headroom at all. The same query-filter ladder
    /// against a 2 MB stack on this tree gives **67 ok, 68 aborts**, three runs per rung, so a debug build
    /// tops out at about half the bound instead of 2.3x above it: a level costs about 28 KB unoptimized
    /// against about 7 KB optimized, and 128 filter levels need 3648 KB against 927 KB. That is why plain
    /// `cargo test` -- the command `CONTRIBUTING.md` asks contributors to run, and the one
    /// `.github/workflows/pr.yml` runs on all three platforms -- aborted on fifteen of the at-the-limit
    /// cases while `cargo test --release` passed all of them. Those cases now run on a thread sized for the
    /// bound (`on_a_stack_that_reaches_the_bound` in `parser_tests.rs`) rather than on libtest's default,
    /// so what they assert no longer depends on the profile.
    ///
    /// None of that moves the bound, and it is worth saying why rather than leaving the release number to
    /// carry the argument alone. 128 rests on the corpus -- real files run to single digits, 7 levels at the
    /// deepest measured -- and not on stack headroom, and nothing can recurse past it in either profile. The
    /// margin is an order of magnitude on purpose, so that a deeper example file moves the measured maximum
    /// without touching the argument. What the debug figure costs is
    /// the *claim*: "safe with 2.3x to spare" cannot be stated unconditionally, and anyone raising
    /// [`MAX_NESTING_DEPTH`] has to say which profile they are raising it for. Past ~290 optimized or ~67
    /// unoptimized the failure mode is not a failing assertion: the test binary aborts with "fatal runtime
    /// error: stack overflow", taking every other test in that target with it, and naming a thread that --
    /// because several of them overflow at once -- can come out spliced from several test names, or empty.
    static NESTING_DEPTH: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// One nesting construct held open, closed when it goes out of scope.
///
/// The count is restored by `Drop` rather than by the parser, which is what makes it correct under
/// `nom`'s backtracking: an `alt` arm that opens a block and then fails returns `Err` and unwinds the
/// scope, dropping the guard, so a failed attempt leaves the count where it found it. Every increment
/// creates exactly one guard, so there is no path that opens a level without a matching close, and no
/// need to reset the count between files.
struct NestingGuard;

impl NestingGuard {
    /// Opens one level, or refuses the file if that would pass [`MAX_NESTING_DEPTH`].
    ///
    /// A `Failure` rather than an `Error`, so it escapes the `alt`s and `opt`s it sits inside instead of
    /// being retried as a different construct: the file is too deep whichever reading is attempted, and
    /// a recoverable error here would surface as whatever the last alternative had to say about the
    /// position. The two other checks in [`block`] that reject a file outright do the same.
    fn enter<'a>(
        input: Span<'a>,
        construct: &str,
    ) -> Result<NestingGuard, nom::Err<ParserError<'a>>> {
        let level = NESTING_DEPTH.with(|open| open.get()) + 1;
        if level > MAX_NESTING_DEPTH {
            let (line, column) = position_of(&input);
            return Err(nom::Err::Failure(ParserError {
                span: input,
                kind: ErrorKind::TooLarge,
                context: format!(
                    "cfn-guard reads rules files nested at most {MAX_NESTING_DEPTH} levels deep, and \
                     this file goes deeper: the {construct} opened at line {} column {} is at level \
                     {level}. Real rules files nest a handful of levels; nothing in AWS's own rules \
                     registry comes close to this.",
                    line, column,
                ),
            }));
        }

        NESTING_DEPTH.with(|open| open.set(level));
        Ok(NestingGuard)
    }
}

impl Drop for NestingGuard {
    fn drop(&mut self) {
        NESTING_DEPTH.with(|open| open.set(open.get() - 1));
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                         HELPER METHODS                                                         //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// A comment, ending at the end of its line -- at `\n`, or at the `\r` of a CRLF pair.
///
/// `multispace1`, which `white_space_or_comment` reaches for the other half of its alternation, accepts
/// `" \t\r\n"`, so a lone `\r` is a line ending as far as every whitespace position is concerned. This search
/// stopped at `\n` alone, so in a file whose lines end with a bare CR a comment ran to the end of the file:
/// the `}` closing the block the comment sat in was consumed as comment text, and the file was rejected for
/// having no closing brace. Ten of thirteen constructs parsed in such a file and this was one of the three
/// that did not, which is the worst shape for it to be in -- whether the file is readable depended on whether
/// it happened to contain a comment.
///
/// A bare CR ends a line everywhere in this parser, not only here: `extract_message` takes either ending
/// and `position_of` counts either, and `rewriting_line_endings_does_not_change_how_a_rules_file_parses`
/// is what keeps that true. The invariant is worth stating as a whole because a single site that breaks
/// it is hard to see from the others: an `extract_message` that split on `\n` alone would read a bare-CR
/// file as one line and delete a clause, with every reported line and column collapsing to line 1, while
/// every other position in the parser went on treating the CR as a line ending.
///
/// The `\r` arm is load-bearing twice over: it ends a comment in a bare-CR file, and it stops the `\r` of a
/// CRLF pair from being taken as comment text, which would leave a trailing CR on every comment in a file
/// saved by a Windows editor. No rules file in this repository or in the AWS rule registry contains a CR of
/// either kind.
pub(in crate::rules) fn comment2(input: Span) -> IResult<Span, Span> {
    delimited(
        char('#'),
        take_till(|c| c == '\n' || c == '\r'),
        multispace0,
    )(input)
}
//
// This function extracts either white-space-CRLF or a comment
// and discards them
//
// (LWSP / comment)
//
// Expected error codes: (remember alt returns the error from the last one)
//    nom::error::ErrorKind::Char => if the comment does not start with '#'
//
pub(in crate::rules) fn white_space_or_comment(input: Span) -> IResult<Span, ()> {
    value((), alt((multispace1, comment2)))(input)
}

//
// This provides extract for 1*(LWSP / comment). It does not indicate
// failure when this isn't the case. Consumers of this combinator must use
// cut or handle it as a failure if that is the right outcome
//
pub(in crate::rules) fn one_or_more_ws_or_comment(input: Span) -> IResult<Span, ()> {
    value((), many1(white_space_or_comment))(input)
}

//
// This provides extract for *(LWSP / comment), same as above but this one never
// errors out
//
pub(in crate::rules) fn zero_or_more_ws_or_comment(input: Span) -> IResult<Span, ()> {
    value((), many0(white_space_or_comment))(input)
}

pub(in crate::rules) fn white_space(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    move |input: Span| preceded(zero_or_more_ws_or_comment, char(ch))(input)
}

pub(in crate::rules) fn preceded_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn separated_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

pub(in crate::rules) fn followed_by(ch: char) -> impl Fn(Span) -> IResult<Span, char> {
    white_space(ch)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                          Value Type Parsing Routines                                           //
//                                                                                                //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

/// A numeric literal must not run straight into an identifier.
///
/// Without this, a malformed number does not fail: it splits. `Properties.Size == 1e5` parsed as the
/// integer `1` followed by `e5`, and a bare identifier is a valid clause -- a reference to a rule by
/// that name. So the clause became `Size == 1` *and* a reference to a rule called `e5`. If no such
/// rule exists the run dies with "Rule e5 by that name does not exist", which at least says
/// something; if one does exist, the file evaluates cleanly and checks `== 1` where the author wrote
/// `== 100000`. Measured on v3.2.0: a template with `Size: 1` reports PASS at exit 0 against a rule
/// demanding 100000.
///
/// Whitespace still separates clauses, so `Size == 1 other_rule` is unaffected. What is rejected is a
/// digit running into a letter with nothing between them, which is never two clauses.
fn reject_trailing_identifier<'a>(
    remaining: Span<'a>,
    literal: Span<'a>,
) -> IResult<'a, Span<'a>, ()> {
    match remaining.fragment().chars().next() {
        Some(ch) if ch.is_alphanumeric() || ch == '_' => Err(nom::Err::Error(ParserError {
            context: String::from(
                "a number cannot be followed directly by a letter, digit or underscore",
            ),
            kind: ErrorKind::Digit,
            span: literal,
        })),
        _ => Ok((remaining, ())),
    }
}

/// A keyword, which may not run straight into an identifier.
///
/// `tag` matches a prefix, so `tag("true")` matches the first four characters of `trueFlag` and leaves
/// `Flag` behind. A bare identifier is a valid clause -- a reference to a rule by that name -- so
/// `Public == falseFlag` became `Public == false` AND a reference to a rule called `Flag`, and with such
/// a rule present it reported PASS where the author asked whether one property equalled another.
///
/// Rejecting the trailing identifier makes the keyword parser fail, and the alternation then falls
/// through to `property_name`, which is the reading the author wrote: `falseFlag` is a property.
/// `this.foo`, `keys ==` and `EXISTS` at end of line are unaffected, because none of them is followed by
/// an identifier character.
fn keyword<'a>(word: &'static str) -> impl Fn(Span<'a>) -> IResult<'a, Span<'a>, ()> {
    move |input: Span<'a>| {
        let (remaining, matched) = tag(word)(input)?;
        let (remaining, _) = reject_trailing_identifier(remaining, matched)?;
        Ok((remaining, ()))
    }
}

pub(in crate::rules) fn parse_int_value(input: Span) -> IResult<Span, Value> {
    // Sign and digits together, because negating afterwards caps the magnitude at `i64::MAX` and
    // `i64::MIN` is one larger: that order rejects `-9223372036854775808` while accepting
    // `-9223372036854775807` and `9223372036854775807`, a single expressible value refused. Loud, so
    // never a wrong verdict, and one fewer thing an author has to discover.
    let (remaining, digits) = recognize(preceded(opt(tag("-")), digit1))(input)?;
    let (remaining, _) = reject_trailing_identifier(remaining, input)?;

    // `Failure`, not `Error`, for the reason `parse_float` gives for its range check. `digit1` has
    // matched, so this text is an integer literal and nothing else in the alternation is going to read
    // it; a recoverable error here sent `alt` on to the other value productions, and the author was
    // then told whatever the enclosing context had to say -- the generic "expecting either a property
    // access ... or value" in a clause, and nothing at all in a `let`, where the context was empty.
    // `18446744073709551615` is a value a template can carry and an author can copy into a rule, and it
    // was refused without a word about the range.
    match digits.fragment().parse::<i64>() {
        Ok(value) => Ok((remaining, Value::Int(value))),
        Err(_) => Err(nom::Err::Failure(ParserError {
            context: format!(
                "Integer literal is out of range for a 64 bit integer: it has to be between {} and {}",
                i64::MIN,
                i64::MAX
            ),
            kind: ErrorKind::Digit,
            span: input,
        })),
    }
}

/// Walks a delimited literal and returns its body along with the number of bytes it occupies, closing
/// delimiter included.
///
/// The question a scanner has to answer at every delimiter is whether that delimiter is escaped, and the
/// last byte of the text in front of it cannot answer it: `\` and `\\` both end in a backslash and mean
/// opposite things there. Both `parse_string_inner` and `parse_regex_inner` decided from that last byte,
/// so they got `\\` backwards -- they read the second backslash as escaping the delimiter, pushed the
/// delimiter into the value, and carried on reading from after it. The literal then ended at the next
/// matching character anywhere in the file, which for a rules file means an apostrophe in a comment or a
/// slash in a URL. Everything between was absorbed into a value, so the clauses and rules written there
/// were not evaluated, not reported, and the run exited 0.
///
/// Walking forward settles it: a backslash consumes the character after it whichever character that is,
/// so a delimiter inside such a pair can never close the literal and one outside every pair always does.
///
/// `resolve` is handed the character a backslash consumed and appends what the pair contributes to the
/// body. That is the whole of the escape vocabulary, and it is where strings and regular expressions
/// differ.
///
/// `None` means the literal is not terminated -- the text ran to the end of its line, or to the end of
/// input, with no unescaped delimiter. A backslash immediately before a line ending is the same answer,
/// because there is no character on that line for it to escape. Stopping at the line ending is what
/// keeps one missing delimiter from reaching the rest of the file, and it is the only reason a runaway
/// literal is now loud rather than silent: a literal free to cross lines has every following clause
/// available to swallow.
fn scan_escaped_literal(
    input: Span,
    delimiter: char,
    mut resolve: impl FnMut(char, &mut String),
) -> Option<(usize, String)> {
    let mut body = String::new();
    let mut chars = input.fragment().char_indices();
    while let Some((at, c)) = chars.next() {
        match c {
            '\\' => match chars.next() {
                Some((_, escaped)) if escaped != '\n' && escaped != '\r' => {
                    resolve(escaped, &mut body)
                }
                _ => return None,
            },
            '\n' | '\r' => return None,
            _ if c == delimiter => return Some((at + c.len_utf8(), body)),
            _ => body.push(c),
        }
    }
    None
}

/// A string literal understands two escapes: `\\` for a backslash, and a backslash before the quote that
/// opened the literal for that quote. A backslash before anything else is not an escape and stays in the
/// value, which is what lets a regular expression written as a string -- `"^arn:(\w+):(\d+)$"`, the shape
/// of all three such literals in this repository -- keep its own escapes without doubling them.
///
/// `\\` is the addition. With the quote as the only escape, a backslash's meaning depended on what came
/// after it: `"a\\b"` was two literal backslashes, while those same two characters in front of the
/// closing quote were one backslash plus an escaped quote. So no spelling produced a string ending in a
/// backslash. `"x\\"`, `'C:\'`, `"C:\"` and `"x\\\\"` were all rejected, and the diagnostic named the
/// right-hand side rather than the quote, which is the least useful place to look. Resolving `\\` here
/// makes `'x\\'` mean `x\`.
///
/// It also changes `"a\\b"` from two backslashes to one. That is deliberate and it is user-visible. It is
/// the same trade every language with a backslash escape has made, and it is what makes a backslash's
/// meaning independent of its position. No rules file in this repository or in the AWS rule registry
/// writes `\\` inside a string literal, and none writes a backslash before a quote, so no existing file
/// changes meaning.
fn parse_string_inner(ch: char) -> impl Fn(Span) -> IResult<Span, Value> {
    move |input: Span| {
        let (input, _begin) = char(ch)(input)?;
        match scan_escaped_literal(input, ch, |escaped, body| match escaped {
            '\\' => body.push('\\'),
            c if c == ch => body.push(ch),
            c => {
                body.push('\\');
                body.push(c);
            }
        }) {
            Some((consumed, value)) => Ok((input.take_split(consumed).0, Value::String(value))),
            // `Failure`, because `cut(char(ch))` already made an unterminated string one and nothing
            // else in the value alternation starts with a quote. Falling through could only produce some
            // later parser's complaint about text that is plainly a string, which is what the old
            // diagnostic did.
            None => Err(nom::Err::Failure(ParserError {
                context: format!(
                    "String literal is not terminated: no closing {ch} before the end of the line. A backslash escapes the character after it, so write \\\\ for a literal backslash"
                ),
                kind: ErrorKind::Char,
                span: input,
            })),
        }
    }
}

pub(crate) fn parse_string(input: Span) -> IResult<Span, Value> {
    alt((parse_string_inner('\''), parse_string_inner('\"')))(input)
    //    map(
    //        alt((
    //            delimited(
    //                char('"'),
    //                take_while(|c| c != '"'),
    //                char('"')),
    //            delimited(
    //                char('\''),
    //                take_while(|c| c != '\''),
    //                char('\'')),
    //        )),
    //        |s: Span| Value::String((*s.fragment()).to_string()),
    //    )(input)
}

/// `true`, `True` and `TRUE`, and the three matching spellings of false.
///
/// `TRUE` was missing, and the cost was not a parse error. It fell past every value parser into the
/// property-access branch, so `when Properties.Audited == TRUE { ... }` compared a property against
/// another property named `TRUE`, which no document has. The gate never fired, the body never ran, and
/// a rule written to reject public buckets reported them clean at exit 0. Changing one character to
/// `True` made the same file exit 19.
///
/// Nothing chose lower-plus-Title here and lower-plus-UPPER for null; that is two people adding one
/// spelling each. All three are standard, and a gate that can never fire is indistinguishable in the
/// output from a gate that correctly did not apply, so there was no signal to notice it by.
fn parse_bool(input: Span) -> IResult<Span, Value> {
    let true_parser = value(
        Value::Bool(true),
        alt((keyword("true"), keyword("True"), keyword("TRUE"))),
    );
    let false_parser = value(
        Value::Bool(false),
        alt((keyword("false"), keyword("False"), keyword("FALSE"))),
    );
    alt((true_parser, false_parser))(input)
}

/// Decides whether the text is float-shaped, then lets `double` do the parsing.
///
/// The shape test is what makes a bare integer fall through to `parse_int_value`, so it has to accept
/// exactly what a float can look like. It accepted less than that:
///
///   - no leading sign, so `-1.5` was not a float. `parse_int_value` then took the `-1` and left
///     `.5` behind, and the clause failed to parse. Negative thresholds could not be written at all.
///   - a mandatory exponent sign, so `1e5` was not a float either, and that one did not fail loudly.
///     See `reject_trailing_identifier` for what it did instead.
///
/// `double` already handles the sign and the exponent; only this gate was narrower than the thing it
/// was gating.
fn parse_float(input: Span) -> IResult<Span, Value> {
    let signed = opt(char('-'))(input)?;
    let whole = digit1(signed.0)?;
    let fraction = opt(preceded(char('.'), digit1))(whole.0)?;
    let exponent = opt(tuple((one_of("eE"), opt(one_of("+-")), digit1)))(fraction.0)?;
    if (fraction.1).is_some() || (exponent.1).is_some() {
        let r = double(input)?;

        // `double` never fails on an exponent it cannot represent: it saturates to an infinity, or
        // rounds to zero. Either way the clause reads as one bound and means another. `Size < 1e999`
        // cannot fail for any input and `Size > 1e999` cannot pass for any input -- the comparison
        // even reports `ComparedWith = inf` -- and `Size == 1e-999` is satisfied by a `Size` of 0,
        // because the literal rounded to zero on the way in.
        //
        // Underflow is only a problem when the author wrote a nonzero number, so the mantissa is what
        // decides it: `0.0e5` is zero and means zero, while `1e-999` is not zero and does not.
        //
        // The document side does NOT draw this line, and the difference is deliberate rather than an
        // oversight. A rule is authored, so refusing it tells the author something they can act on. A
        // document is data, and rejecting an entire template over one field is out of proportion --
        // there, `loader.rs` retypes the scalar to a string, which leaves every comparison against it
        // incomparable and therefore failing closed, with the reporter naming the mismatch.
        let consumed = input.fragment().len() - r.0.fragment().len();
        let mantissa = input.fragment()[..consumed]
            .split(|c| c == 'e' || c == 'E')
            .next()
            .unwrap_or_default();
        let rounded_to_zero =
            r.1 == 0.0 && mantissa.chars().any(|c| c.is_ascii_digit() && c != '0');

        // `Failure`, not `Error`. A recoverable error sends `alt` back to try the other value
        // productions, and `parse_int_value` then matches the leading digits and leaves the rest, so
        // the reported problem was a stray fragment rather than the literal: `1.5e999` blamed
        // `.5e999` with an empty context, and this message never reached the author at all. Same
        // reasoning as `parse_range` below, which is `Failure` for the same reason.
        if !r.1.is_finite() || rounded_to_zero {
            return Err(nom::Err::Failure(ParserError {
                context: match r.1.is_finite() {
                    true => "Float literal is out of range for a 64 bit float: it rounds to zero"
                        .to_string(),
                    false => {
                        "Float literal is out of range for a 64 bit float: it saturates to an infinity"
                            .to_string()
                    }
                },
                kind: ErrorKind::Float,
                span: input,
            }));
        }
        let (remaining, _) = reject_trailing_identifier(r.0, input)?;
        return Ok((remaining, Value::Float(r.1)));
    }
    Err(nom::Err::Error(ParserError {
        context: "Could not parse floating number".to_string(),
        kind: ErrorKind::Float,
        span: input,
    }))
}

/// A regular expression understands one escape: a backslash before the `/` delimiter, which stands for a
/// plain `/`, since `fancy_regex` does not need that character escaped. A backslash before anything else
/// is left exactly as written, backslash included, because the body is handed to a regex engine that has
/// an escape layer of its own -- the `\d`, `\.`, `\-` and `\:` in the AWS rule registry have to arrive
/// intact.
///
/// `\\` is left alone too, and reaches the engine as the two characters that mean one literal backslash
/// there. The pair closes itself, so a `/` after it ends the regex instead of being read as one more
/// escaped delimiter: `/^x\\/` ends at its own closing slash.
///
/// The same reading makes `/a\//` and `/\//` parse. They were rejected -- `is_not("/")` needed at least
/// one character and after the escape the cursor sat on the closing delimiter with none left -- so an
/// escaped slash was writable everywhere in a regex except immediately before its end.
///
/// One construct in the corpus depended on the old misreading: `[A-Za-z0-9\\/+=]`, in this repository's
/// `advanced_regex_negative_lookbehind_rule.guard` and a copy of it under `guard/ts-lib`, reached the
/// engine as `[A-Za-z0-9\/+=]`. Under a scan that walks, the `\\` closes and the `/` behind it ends the
/// regex early, which leaves an unterminated character class. That file is written `\/` now, which is the
/// spelling that means what it always meant. There is no reading in which `\\/` both terminates in
/// `/^x\\/` and does not terminate there -- the fixture and the swallow are one construct.
///
/// Both failures are `Failure`, not `Error`, for the reason `parse_float` gives above: a recoverable error
/// sends `alt` back to the other value productions and the message never reaches the author. Neither of
/// these did. `Hash == /a(/` reported the generic `expecting either a property access ... or value like
/// ...` and the engine's `Opening parenthesis without closing parenthesis` appeared nowhere in the output,
/// and `Hash == /abc` likewise said nothing about a missing delimiter. Both were formatted and discarded.
///
/// Nothing is given up by refusing to backtrack here. `parse_regex` is the last arm of
/// `parse_scalar_value`, so no other value production was going to be tried, and none of them could match
/// anyway: this function is only reached after `char('/')`, and every other production in the grammar
/// starts a value with a quote, a digit, a sign, a keyword, `[`, or `{`, while a property access is
/// alphanumeric or quoted. A literal beginning with `/` is a regular expression or it is nothing, so the
/// recoverable error bought a worse diagnostic and no second chance.
fn parse_regex_inner(input: Span) -> IResult<Span, Value> {
    let (consumed, regex) =
        match scan_escaped_literal(input, '/', |escaped, body| match escaped {
            '/' => body.push('/'),
            c => {
                body.push('\\');
                body.push(c);
            }
        }) {
            Some(found) => found,
            None => return Err(nom::Err::Failure(ParserError {
                context:
                    "Could not parse regular expression: no closing / before the end of the line"
                        .to_string(),
                kind: ErrorKind::RegexpMatch,
                span: input,
            })),
        };

    match Regex::try_from(regex.as_str()) {
        Ok(_) => Ok((input.take_split(consumed).0, Value::Regex(regex))),
        Err(e) => Err(nom::Err::Failure(ParserError {
            context: format!("Could not parse regular expression: {}", e),
            kind: ErrorKind::RegexpMatch,
            span: input,
        })),
    }
}

fn parse_regex(input: Span) -> IResult<Span, Value> {
    // `preceded`, not `delimited`: the scan consumes the closing delimiter itself, because it is the
    // thing that decided which delimiter closes the literal.
    preceded(char('/'), parse_regex_inner)(input)
}

fn parse_char(input: Span) -> IResult<Span, Value> {
    map(anychar, Value::Char)(input)
}

fn range_value(input: Span) -> IResult<Span, Value> {
    delimited(
        space0,
        alt((parse_float, parse_int_value, parse_char)),
        space0,
    )(input)
}

/// Does the range admit any value at all?
///
/// A lower bound below the upper admits the values between them, whatever the two ends are. Equal
/// bounds admit exactly that one value, and only when both ends are closed: `r[15,15]` is 15 and
/// nothing else, while `r(15,15)`, `r[15,15)` and `r(15,15]` are empty. A lower bound above the
/// upper is empty for every spelling.
///
/// Bounds that do not order against each other answer `false` and are therefore refused. No such
/// bound reaches here today, because `parse_float` rejects the non-finite literals first, so this
/// is the safe direction rather than a reachable case.
fn range_admits_a_value<T: PartialOrd>(lower: &T, upper: &T, inclusive: u8) -> bool {
    const BOTH_CLOSED: u8 = LOWER_INCLUSIVE | UPPER_INCLUSIVE;
    if lower < upper {
        return true;
    }
    lower == upper && inclusive & BOTH_CLOSED == BOTH_CLOSED
}

/// Refuse a range that no value can satisfy, naming both bounds.
///
/// `Failure`, not `Error`, for the reason given on `parse_float` above: a recoverable error sends
/// `alt` back to the other value productions, and the author is told about a stray fragment instead
/// of about the range they wrote.
///
/// The bounds are named through `Debug` rather than `Display`, so that a float keeps its point and a
/// char is quoted. `Display` prints the `2.0` of `r[2.0,1.0]` as `2`, which does not match what the
/// author wrote.
fn reject_empty_range<'a, T: PartialOrd + Debug>(
    lower: &T,
    upper: &T,
    inclusive: u8,
    input: Span<'a>,
) -> Result<(), nom::Err<ParserError<'a>>> {
    if range_admits_a_value(lower, upper, inclusive) {
        return Ok(());
    }
    let context = match lower == upper {
        true => format!(
            "Range literal is empty: both bounds are {lower:?} and at least one end is exclusive, so no value can satisfy it"
        ),
        false => format!(
            "Range literal is empty: the lower bound {lower:?} is above the upper bound {upper:?}, so no value can satisfy it"
        ),
    };
    Err(nom::Err::Failure(ParserError {
        context,
        kind: ErrorKind::IsNot,
        span: input,
    }))
}

/// Widen an integer bound so it can sit alongside a float bound in one `RangeType<f64>`.
///
/// `RangeType` holds a single type, so a range mixing the two kinds has to carry both bounds as
/// floats, and the integer is the one that converts. `bound as f64` on its own is the conversion
/// `compare_int_to_float` in `path_value.rs` refuses to make: above 2^53 an `i64` is not exactly
/// representable, so the cast moves the bound, and on a range check a moved bound quietly admits or
/// excludes a value at the edge. A bound that cannot be widened without moving is refused instead,
/// which is what the surrounding parser already does with a number it cannot represent.
fn widen_bound_to_float(bound: i64, input: Span<'_>) -> Result<f64, nom::Err<ParserError<'_>>> {
    // 2^63. `i64::MAX as f64` rounds *up* to this value and casting it back saturates to
    // `i64::MAX`, so a bare round-trip would report a bound it had moved as exact. Bound on 2^63
    // itself, for the reason `compare_int_to_float` gives.
    const TWO_POW_63: f64 = 9_223_372_036_854_775_808.0;
    let widened = bound as f64;
    if (-TWO_POW_63..TWO_POW_63).contains(&widened) && widened as i64 == bound {
        return Ok(widened);
    }
    Err(nom::Err::Failure(ParserError {
        context: format!(
            "Range bound {bound} cannot be paired with a float bound: it does not fit a 64 bit float exactly, and widening it would move the bound"
        ),
        kind: ErrorKind::IsNot,
        span: input,
    }))
}

/// The four range forms, each over a lower and an upper bound.
///
/// Nothing compared the two bounds, so a transposed pair parsed and became a clause that no
/// document can move. `Resources.SG.Properties.Size not in r[20,10]` exits 0 against every
/// template, and the entire output at the default summary level is a two-line PASS banner: no
/// clause, no range, nothing to notice. Turned around, `in r[20,10]` exits 19 against every
/// template just as vacuously. Floats and chars transpose the same way, `r[2.0,1.0]` and `r[z,a]`,
/// and `r(15,15)` reaches the same emptiness through equal bounds rather than through a swap.
///
/// The argument for refusing this rather than tolerating it is the one already made on
/// `parse_float` above, where a non-finite literal is rejected because `Size < 1e999` cannot fail
/// for any input and `Size > 1e999` cannot pass for any input. An empty range has that property,
/// reached by a transposition typo instead of by an exponent. `docs/CLAUSES.md:189-192` defines all
/// four forms in terms of a `<lower_limit>` and an `<upper_limit>` with the inequalities spelled
/// out, so a range whose lower bound is above its upper is not one of the documented forms.
///
/// Equal bounds are treated on the same measure and split: `r[15,15]` admits exactly 15, which is a
/// usable thing to write, and it is kept. The three spellings that put an open end on equal bounds
/// admit nothing, so they go with the reversed ones. That line is drawn on purpose in
/// `range_admits_a_value` rather than falling out of whichever comparison happened to be written.
///
/// The bound kinds pair off separately from that. A range mixing one integer bound and one float
/// bound is accepted, and both bounds widen to float when exactly one of them is a float.
/// `docs/CLAUSES.md:201` promises that the two kinds "compare against each other as numbers. That
/// includes range membership", and `path_value.rs` carries `int_within_float_range` and
/// `float_within_int_range` to do exactly that. Refusing the mixed range here would leave
/// `Size in r[1,2]` holding for a `Size` of `1.5` while `Size in r[0,20.5]` does not parse at all:
/// a gate narrower than the thing it gates, the same shape of defect as the float shape test above.
fn parse_range(input: Span) -> IResult<Span, Value> {
    let parsed = preceded(
        char('r'),
        tuple((
            one_of("(["),
            separated_pair(range_value, char(','), range_value),
            one_of(")]"),
        )),
    )(input)?;
    let (open, (start, end), close) = parsed.1;
    let mut inclusive: u8 = if open == '[' { LOWER_INCLUSIVE } else { 0u8 };
    inclusive |= if close == ']' { UPPER_INCLUSIVE } else { 0u8 };
    let val = match (start, end) {
        (Value::Int(s), Value::Int(e)) => {
            reject_empty_range(&s, &e, inclusive, input)?;
            Value::RangeInt(RangeType {
                upper: e,
                lower: s,
                inclusive,
            })
        }

        (Value::Float(s), Value::Float(e)) => {
            reject_empty_range(&s, &e, inclusive, input)?;
            Value::RangeFloat(RangeType {
                upper: e,
                lower: s,
                inclusive,
            })
        }

        (Value::Char(s), Value::Char(e)) => {
            reject_empty_range(&s, &e, inclusive, input)?;
            Value::RangeChar(RangeType {
                upper: e,
                lower: s,
                inclusive,
            })
        }

        // One integer bound and one float bound, widened to the float range the evaluator already
        // knows how to check a value of either kind against.
        (Value::Int(s), Value::Float(e)) => {
            let s = widen_bound_to_float(s, input)?;
            reject_empty_range(&s, &e, inclusive, input)?;
            Value::RangeFloat(RangeType {
                upper: e,
                lower: s,
                inclusive,
            })
        }

        (Value::Float(s), Value::Int(e)) => {
            let e = widen_bound_to_float(e, input)?;
            reject_empty_range(&s, &e, inclusive, input)?;
            Value::RangeFloat(RangeType {
                upper: e,
                lower: s,
                inclusive,
            })
        }

        // What is left is a bound pairing that is not two numbers, `r[0,z]` or `r[a,2.5]`, which no
        // comparison decides.
        //
        // The span is `input`, not `parsed.0`. `parsed.0` is what follows the range, so spanning it
        // would put the caret one column past the closing bracket and quote the lines after the
        // offending literal instead of the literal: `let bounds = r[0,z]` puts the literal at column
        // 16 and its `]` at column 21, and would be reported at column 22 with an empty fragment.
        // `parse_float` above spans `input` for its equivalent failure.
        _ => {
            return Err(nom::Err::Failure(ParserError {
                span: input,
                kind: ErrorKind::IsNot,
                context: "Could not parse range: the bounds are not both numbers".to_string(),
            }))
        }
    };
    Ok((parsed.0, val))
}

//
// Adding the parser to return scalar values
//
fn parse_scalar_value(input: Span) -> IResult<Span, Value> {
    //
    // IMP: order does matter
    // parse_float is before parse_int. the later can parse only the whole part of the float
    // to match.
    alt((
        parse_string,
        parse_float,
        parse_int_value,
        parse_bool,
        parse_regex,
    ))(input)
}

///
/// List Values
///

fn parse_list(input: Span) -> IResult<Span, Value> {
    let (input, _open) = preceded_by('[')(input)?;
    let _nesting = NestingGuard::enter(input, "list")?;
    let (input, values) = separated_list0(separated_by(','), parse_value)(input)?;
    let (input, _close) = followed_by(']')(input)?;
    Ok((input, Value::List(values)))
}

fn key_part(input: Span) -> IResult<Span, String> {
    alt((
        map(
            take_while1(|c: char| c.is_alphanumeric() || c == '-' || c == '_'),
            |s: Span| (*s.fragment()).to_string(),
        ),
        map(parse_string, |v| {
            if let Value::String(s) = v {
                s
            } else {
                unreachable!()
            }
        }),
    ))(input)
}

fn key_value(input: Span) -> IResult<Span, (String, Value)> {
    separated_pair(
        preceded(zero_or_more_ws_or_comment, key_part),
        followed_by(':'),
        parse_value,
    )(input)
}

/// A map literal, which refuses a key it holds twice.
///
/// The pairs were collected straight into an `IndexMap`, so a repeated key kept the *last* value silently
/// and the entry order decided the verdict. Against a template holding `Encrypted: false`:
///
/// ```text
/// Resources.One.Properties == { "Encrypted": true, "Encrypted": false }   ->  exit 0   PASS
/// Resources.One.Properties == { "Encrypted": false, "Encrypted": true }   ->  exit 19  FAIL
/// ```
///
/// Two spellings of one key collide the same way, since `key_part` reads `"Encrypted"` and `Encrypted` to the
/// same `String`, and the author of such a file has no way to see which entry won.
///
/// This was the last duplicate-name class on the rules side that was resolved by guessing. `block` refuses a
/// variable declared twice in a scope, `rules_file` refuses a duplicated rule name and a duplicated file-level
/// variable, and `parameter_names` refuses a repeated parameter, each with the same reasoning: a rules file is
/// authored, so an ambiguous one is a mistake to report rather than an input to accommodate. Refusing a file
/// that would otherwise parse is a breaking change, and it is the same breaking change those three make.
///
/// The document side is deliberately not this: a repeated key in a *template* warns and evaluates the last
/// value, because a template is often not the reader's to edit. That is still true, and it is what every
/// user-reachable path does -- measured rather than reasoned, on a template holding `Encrypted` twice:
///
/// ```text
/// validate -d <template>          exit 19   Warning: duplicate key /Resources/One/Properties/Encrypted,
///                                           first at L:5,C:7 and again at L:6,C:7. The last value is
///                                           the one evaluated.
/// validate -i <parameters>        exit 0    the same warning, for the input-parameters file
/// test -d <suite>                 exit 0    the same warning, naming the test file, on stderr; the
///                                           last value is the one the case is evaluated against
/// run_checks (guard-ffi, Lambda)            last value wins, silently: the entry point converts
///                                           through `TryFrom<MarkedValue>`, which drops the duplicate
///                                           list, and has no channel to report one on (read from
///                                           `commands::helper`, not measured through the FFI)
/// rules file with `{ a: 1, a: 2 }` exit 5   refused, which is this function
/// ```
///
/// "Documents are loaded through `libyaml` and `serde`, never through this grammar" is false as an
/// absolute and would be the wrong reason for a right conclusion. A document *can* be read by this grammar:
/// `TryFrom<&str> for PathAwareValue` in `path_value.rs` routes through `Value::try_from` to `parse_value`
/// and so to here, and a template fixture in `eval_tests.rs` reaches this grammar and is held to the same
/// one-spelling-per-key rule, which is the same fact seen from the test side.
///
/// The conclusion survives on a narrower fact: that constructor is `pub(crate)`, `path_value` is a
/// `pub(crate) mod`, and every caller of it is an in-crate test. Every production caller takes another
/// route -- `try_from_marked` for `validate -d` and for the `test` command's `input:` (through
/// `commands::test::convert_input`), and `TryFrom<MarkedValue>` for `validate_and_return_json`, all of
/// them fed by the libyaml loader. So no
/// document a user can supply is refused here, and the authored-file argument above is not being stretched
/// to cover templates. Widening that constructor's visibility, or calling it on document text from
/// production code, would stretch it -- and would turn a warning into a refusal for a file the reader may
/// not be able to edit, which is a materially worse breaking change than refusing a rules file.
///
/// The warning half is pinned by `a_duplicate_name_resolves_last_wins_and_warns_wherever_it_arrived_from`
/// in `libyaml/loader_tests.rs`, which asserts last-wins and the reported duplicate through
/// `try_from_marked`. The visibility half is not pinned by a test and cannot usefully be: it is the
/// `pub(crate)` on `path_value`, and the thing to re-check before widening it is this paragraph.
///
/// Lists are left alone. A repeated value in a list literal is legitimate -- `in [1, 1, 2]` is a set of
/// candidates and a repeat there means nothing -- so a check written over values rather than over keys would
/// reject working files.
fn parse_map(input: Span) -> IResult<Span, Value> {
    // `input` is left pointing at the opening `{` and the advanced spans get their own names, which is
    // what `parameter_names` does and what the refusal below needs. Shadowing `input` per step is the
    // ordinary shape in this file, and here it put the reported position *past the closing brace*: the
    // span in hand after `followed_by('}')` is the text after the map, so `let m = { "a": 1, "a": 2 }`
    // -- 26 characters -- reported line 1 column 27, one past the end of the line, and
    // `inner({ "a": 1, "a": 2 })` reported the column of the `)`. Both point at something that is not
    // the construct and, in the `let` case, at a column the line does not have.
    //
    // Only the `let` and parameterized-call paths showed it. On a clause right-hand side a context
    // wrapper supplies its own span and reports the column just before the literal, so the position
    // looked near enough there to pass a reading.
    let (after_open, _open) = char('{')(input)?;
    let _nesting = NestingGuard::enter(after_open, "map")?;
    let (after_pairs, pairs) = separated_list0(separated_by(','), key_value)(after_open)?;
    let (after_close, _close) = followed_by('}')(after_pairs)?;

    let mut map = IndexMap::with_capacity(pairs.len());
    for (key, value) in pairs {
        if map.insert(key.clone(), value).is_some() {
            return Err(nom::Err::Failure(ParserError {
                span: input,
                kind: ErrorKind::Tag,
                context: format!(
                    "Key {} appears more than once in the same map literal. The later value replaced \
                     the earlier one, so reordering two entries with the same name changed the \
                     verdict, and the file is rejected rather than guessed at.",
                    key
                ),
            }));
        }
    }

    Ok((after_close, Value::Map(map)))
}

/// `null`, `NULL` and `Null`. See `parse_bool` for why the missing spelling mattered.
fn parse_null(input: Span) -> IResult<Span, Value> {
    value(
        Value::Null,
        alt((keyword("null"), keyword("NULL"), keyword("Null"))),
    )(input)
}

pub(crate) fn parse_value(input: Span) -> IResult<Span, Value> {
    preceded(
        zero_or_more_ws_or_comment,
        alt((
            parse_null,
            parse_scalar_value,
            parse_range,
            parse_list,
            parse_map,
        )),
    )(input)
}

////////////////////////////////////////////////////////////////////////////////////////////////////
//                                                                                                //
//                                                                                                //
//                          Expressions Parsing Routines                                          //
//                                                                                                //
//                                                                                                //
////////////////////////////////////////////////////////////////////////////////////////////////////

///
/// Parser Grammar for the CFN Guard rule syntax. Any enhancements to the grammar
/// **MUST** be reflected in this doc section.
///
/// Sample rule language example is as show below
///
/// ```pre
/// let global := [10, 20]                              # common vars for all rules
///
///  rule example_rule {
///    let ec2_instance_types := [/^t*/, /^m*/]   # var regex either t or m family
///
///     dependent_rule                              # named rule reference
///
///    # IN (disjunction, one of them)
///    AWS::EC2::Instance InstanceType IN %ec2_instance_types
///
///    AWS::EC2::Instance {                          # Either an EBS volume
///        let volumes := block_device_mappings      # var local, snake case allowed.
///        when %volumes.Ebs exists {                     # Ebs is setup
///          %volumes.device_name == /^\/dev\/ebs-/      # must have ebs in the name
///          %volumes.Ebs.encrypted == true              # Ebs volume must be encrypted
///          %volumes.Ebs.delete_on_termination == true  # Ebs volume must have delete protection
///        }
///    } or
///    AWS::EC2::Instance {                   # OR a regular volume (disjunction)
///        block_device_mappings.*.device_name == /^\/dev\/sdc-\d/ # all other local must have sdc
///    }
///  }
///
///  rule dependent_rule { ... }
/// ```
///
///  The grammar for the language in ABNF form
///
///
///
///  ```ABNF
///
///  or_term                    = "or" / "OR" / "|OR|"
///
///  var_name                   = 1*CHAR [ 1*(CHAR/ALPHA/_) ]
///  var_name_access            = "%" var_name
///
///  dotted_access              = "." (var_name / var_name_access / "*")
///
///  property_access            = var_name [ dotted_access ]
///  variable_access            = var_name_access [ dotted_access ]
///
///  access                     = variable_access /
///                               property_access
///
///  not_keyword                = "NOT" 1*SP / "not" 1*SP / "!"
///  basic_cmp                  = "==" / ">=" / "<=" / ">" / "<"
///  other_operators            = "IN" / "EXISTS" / "EMPTY"
///  not_other_operators        = not_keyword other_operators
///  not_cmp                    = "!=" / not_other_operators
///
///  cmp                        = basic_cmp / other_operators / not_cmp
///
///  Two productions came out of this grammar rather than into the parser, because neither was ever
///  accepted and this block is normative: `NOT_IN` as a spelling of `not in`, and `KEYS` as a
///  clause-level operator. `Resources.X NOT_IN ["a","b"]` and `Resources.X KEYS == /^a/` are both
///  rejected -- `not in` is the spelling that works, and `keys ==` is valid only inside a filter, where
///  `map_keys_match` handles it. Nothing in `docs/` or the README claims either form, so the grammar was
///  the only thing saying they existed.
///
///  The space after a negation is the line worth reading twice. Were `not_keyword` the three spellings
///  alone, with `not_other_operators` requiring `1*SP` after any of them, the grammar would admit
///  `not empty` and `! empty` and not admit `!empty`. `!empty` is the only spelling that exists: 82
///  occurrences across the 95 rules files here, every example in `docs/CLAUSES.md` and
///  `docs/COMPLEX_COMPOSITION.md`, and no occurrence of
///  `! ` before an operator anywhere. So the space belongs to the word spellings, where it is what keeps
///  `notempty` from reading as a negated `empty`, and `!` needs none because a punctuation mark cannot run
///  into an identifier. `A ! exists` is rejected.
///
///  `type_block` says `1*SP` between the type name and what follows it, not `*SP`. The parser requires one
///  space there, for the block and the clause form together -- they share a single requirement, before the
///  optional `when` -- so `AWS::S3::Bucket{` is rejected. Nothing in the corpus or in `docs/` writes it that
///  way, and the zero-space *clause* form is unwritable anyway, because `type_name` is greedy over
///  alphanumerics and would absorb the property.
///
///  clause                     = access 1*(LWSP/comment) cmp 1*(LWSP/comment) [(access/value)]
///  rule_clause                = rule_name / not_keyword rule_name / clause
///  rule_disjunction_clauses   = rule_clause 1*(or_term 1*(LWSP/comment) rule_clause)
///  rule_conjunction_clauses   = rule_clause 1*( (LSWP/comment) rule_clause )
///
///  type_clause                = type_name 1*SP clause
///  type_block                 = type_name 1*SP [when] "{" *(LWSP/comment) 1*clause "}"
///
///  type_expr                  = type_clause / type_block
///
///  disjunctions_type_expr     = type_expr 1*(or_term 1*(LWSP/comment) type_expr)
///
///  primitives                 = string / integer / float / regex
///  list_type                  = "[" *(LWSP/comment) *value *(LWSP/comment) "]"
///  map_type                   = "{" key_part *(LWSP/comment) ":" *(LWSP/comment) value
///                                   *(LWSP/comment) "}"
///  key_part                   = string / var_name
///  value                      = primitives / map_type / list_type
///
///  ; This said `<any char not DQUOTE>` for a string and gave the escape to the regex alone. Both have
///  ; had one all along, and the disagreement is what let two defects sit here: see
///  ; `scan_escaped_literal`. A backslash consumes the character after it, so an escaped delimiter never
///  ; closes the literal. In a string `\\` resolves to one backslash, and a backslash before the quote
///  ; that opened the literal resolves to that quote; every other backslash stays in the value together
///  ; with the character it escaped. In a regex only `\/` resolves, to `/`, and every other backslash
///  ; reaches the regex engine as written. Neither literal may cross a line ending.
///  string                     = DQUOTE *( <any char not DQUOTE, \, LF or CR> / escape ) DQUOTE /
///                               "'" *( <any char not ', \, LF or CR> / escape ) "'"
///  regex                      = "/" *( <any char not /, \, LF or CR> / escape ) "/"
///  escape                     = "\" <any char not LF or CR>
///
///  comment                    =  "#" *CHAR (LF/CR)
///  assignment                 = "let" one_or_more_ws  var_name zero_or_more_ws
///                                     ("=" / ":=") zero_or_more_ws (access/value)
///
///  when_type                  = when 1*( (LWSP/comment) clause (LWSP/comment) )
///  when_rule                  = when 1*( (LWSP/comment) rule_clause (LWSP/comment) )
///
///  ; Parameterized rules were absent from this block entirely, in both the definition and the call
///  ; form, so it could not be cited either way about them -- which is what let `when` on one go
///  ; missing without contradicting anything written down. `named_rule`'s own `when` was missing too,
///  ; and the parser has accepted it all along.
///  ;
///  ; The empty parameter list is `1*` on purpose and the empty argument list is not. A rule that takes
///  ; no parameters is a `named_rule`; a call with no arguments is accepted by the parser and then
///  ; rejected by `rules_file`, which reads every call against the definition it names.
///  rule_body                  = "{"
///                                   assignment 1*(LWPS/comment)   /
///                                   (type_expr 1*(LWPS/comment))  /
///                                   (disjunctions_type_expr) *(LWSP/comment) "}"
///  named_rule                 = "rule" 1*SP var_name [(LWSP/comment) when_rule] rule_body
///  parameter_list             = "(" *WSP var_name *WSP *("," *WSP var_name *WSP) ")"
///  parameterized_rule         = "rule" 1*SP var_name parameter_list
///                                   [(LWSP/comment) when_rule] rule_body
///  ;
///  ; `argument` is spelled as `assignment`'s right-hand side is, and omits a function call for the
///  ; same reason that one does: this block has never modelled function calls or custom messages,
///  ; and `json_parse(%x)` is as legal an argument here as it is there.
///  argument                   = access / value
///  parameterized_rule_call    = [not_keyword] var_name "(" [ *WSP argument *WSP
///                                   *("," *WSP argument *WSP) ] ")"
///
///  expressions                = 1*( (assignment / named_rule / parameterized_rule / type_expr / disjunctions_type_expr / comment) (LWPS/comment) )
///  ```
///
///

//
// ABNF     =  1*CHAR [ 1*(CHAR / _) ]
//
// All names start with an alphabet and then can have _ intermixed with it. This
// combinator does not fail, it the responsibility of the consumer to fail based on
// the error
//
// Expected error codes:
//    nom::error::ErrorKind::Alpha => if the input does not start with a char
//
pub(crate) fn var_name(input: Span) -> IResult<Span, String> {
    let (remainder, first_part) = alpha1(input)?;
    let (remainder, next_part) = take_while(|c: char| c.is_alphanumeric() || c == '_')(remainder)?;
    let mut var_name = (*first_part.fragment()).to_string();
    var_name.push_str(next_part.fragment());
    Ok((remainder, var_name))
}

//
//  var_name_access            = "%" var_name
//
//  This combinator does not fail, it is the responsibility of the consumer to fail based
//  on the error.
//
//  Expected error types:
//     nom::error::ErrorKind::Char => if if does not start with '%'
//
//  see var_name for other error codes
//
pub(crate) fn var_name_access(input: Span) -> IResult<Span, String> {
    preceded(char('%'), var_name)(input)
}

//
// Comparison operators
//
fn in_keyword(input: Span) -> IResult<Span, CmpOperator> {
    value(CmpOperator::In, alt((keyword("in"), keyword("IN"))))(input)
}

fn not(input: Span) -> IResult<Span, ()> {
    match alt((preceded(tag("not"), space1), preceded(tag("NOT"), space1)))(input) {
        Ok((remainder, _not)) => Ok((remainder, ())),

        Err(nom::Err::Error(_)) => {
            let (input, _bang_char) = char('!')(input)?;
            Ok((input, ()))
        }

        Err(e) => Err(e),
    }
}

fn eq(input: Span) -> IResult<Span, (CmpOperator, bool)> {
    alt((
        value((CmpOperator::Eq, false), tag("==")),
        value((CmpOperator::Eq, true), tag("!=")),
    ))(input)
}

fn keys(input: Span) -> IResult<Span, ()> {
    value((), alt((keyword("KEYS"), keyword("keys"))))(input)
}

fn exists(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::Exists,
        alt((keyword("EXISTS"), keyword("exists"))),
    )(input)
}

fn empty(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::Empty,
        alt((keyword("EMPTY"), keyword("empty"))),
    )(input)
}

fn other_operations(input: Span) -> IResult<Span, (CmpOperator, bool)> {
    let (input, not) = opt(not)(input)?;
    let (input, operation) = alt((in_keyword, exists, empty, is_type_operations))(input)?;
    Ok((input, (operation, not.is_some())))
}

fn is_list(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsList,
        alt((keyword("IS_LIST"), keyword("is_list"))),
    )(input)
}

fn is_struct(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsMap,
        alt((keyword("IS_STRUCT"), keyword("is_struct"))),
    )(input)
}

fn is_string(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsString,
        alt((keyword("IS_STRING"), keyword("is_string"))),
    )(input)
}

fn is_bool(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsBool,
        alt((keyword("IS_BOOL"), keyword("is_bool"))),
    )(input)
}

fn is_int(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsInt,
        alt((keyword("IS_INT"), keyword("is_int"))),
    )(input)
}

fn is_float(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsFloat,
        alt((keyword("IS_FLOAT"), keyword("is_float"))),
    )(input)
}

fn is_null(input: Span) -> IResult<Span, CmpOperator> {
    value(
        CmpOperator::IsNull,
        alt((keyword("IS_NULL"), keyword("is_null"))),
    )(input)
}

/// The type operators, and `in`, go through `keyword` for the reason `true`/`false`/`null` do.
///
/// `tag("IS_INT")` matches the first six characters of `IS_INTEGER` and leaves `EGER` behind, and a bare
/// identifier is a valid clause -- a reference to a rule of that name. So `Size IS_INTEGER` parsed as
/// `Size IS_INT` *and* a reference to a rule called `EGER`: loud when no such rule exists, and silently
/// PASS at exit 0 when one does. Same shape as the `falseFlag` case these helpers were written for; the
/// guard had simply not been applied to this group or to `in`.
fn is_type_operations(input: Span) -> IResult<Span, CmpOperator> {
    alt((
        is_string, is_list, is_struct, is_bool, is_int, is_null, is_float,
    ))(input)
}

pub(crate) fn value_cmp(input: Span) -> IResult<Span, (CmpOperator, bool)> {
    //
    // This is really crappy as the earlier version used << for custom message
    // delimiter. '<' can be interpreted as Lt comparator.
    // TODO revisit the custom message delimiter
    //
    let (input, is_custom_message_start) = peek(opt(value(true, tag("<<"))))(input)?;
    if is_custom_message_start.is_some() {
        return Err(nom::Err::Error(ParserError {
            span: input,
            context: "Custom message tag detected".to_string(),
            kind: ErrorKind::Tag,
        }));
    }

    alt((
        //
        // Basic cmp checks. Order does matter, you always go from more specific to less
        // specific. '>=' before '>' to ensure that we do not compare '>' first and conclude
        //
        eq,
        value((CmpOperator::Ge, false), tag(">=")),
        value((CmpOperator::Le, false), tag("<=")),
        value((CmpOperator::Gt, false), char('>')),
        value((CmpOperator::Lt, false), char('<')),
        //
        // Other operations
        //
        // keys_keyword,
        other_operations,
    ))(input)
}

/// The message text between `<<` and `>>`.
///
/// The contract, stated here once; every other mention of it points here. The commit body carries the
/// history of the earlier terminators and the corpus census behind these rules.
///
/// - Inline form: a `>>` on the opening line closes the message there.
/// - Block form: the message ends at the first later line that starts with `>>` after its indentation. In
///   both forms the rest of that line is the grammar's, read as it would be anywhere else: a comment, `}`,
///   `]`, `{`, `or`, a clause, or a rule reference such as `>> other`.
/// - A `<<` before the closing tag, in either form, is refused: a body may not hold `<<`, because a `<<`
///   there is how a forgotten tag swallows the next clause (that clause's own `>>` would close this
///   message). This costs a body quoting `cat <<EOF` or a `<<placeholder>>`; `docs/KNOWN_ISSUES.md` lists
///   both.
/// - A block message whose terminator lies past a rule header line (`rule name {` or `rule name when ...`)
///   is refused: a body may not hold a rule header, so that terminator belongs to a later rule and this
///   message is missing its own.
/// - A body line that ends in `>>` after other text, or in `>>` and a comment, is text while the scan can
///   still find a terminator (`Expected: List<List<String>>` is a body line). It is named only when the
///   scan fails anyway, at a `<<` line or with no terminator, as the line probably meant to close the
///   message. A `>>` in the middle of a line is text.
/// - Every refusal leads with the line and column where the message opened. With no terminator, the error
///   names the first body line ending in `>>` and the first `}` or rule header line the scan passed, when
///   there are such lines, as the two readings of where the message was meant to end: neither "the `>>`
///   must start its line" nor "close the message before the `}`" is ever the only advice.
///
/// "Line" means what it means everywhere else in this parser: a line ends at `\n` or at a bare `\r`.
/// `a_closing_tag_with_trailing_text_ends_the_message` and `a_message_body_holds_neither_tag` pin the trees
/// and the refusals, `a_stray_closing_tag_does_not_close_a_message` the two readings, and the `validate`
/// tests over `resources/validate/message-closing-tag` the verdicts.
fn extract_message(input: Span) -> IResult<Span, &str> {
    let fragment = input.fragment();
    let next_line_break = |from: usize| fragment[from..].find(|c: char| c == '\n' || c == '\r');
    let opening_line_end = next_line_break(0).unwrap_or(fragment.len());

    let refuse = |at: usize, context: String| {
        nom::Err::Failure(ParserError {
            span: input.take_split(at).0,
            kind: ErrorKind::Tag,
            context,
        })
    };
    // Where this message opened, for every error that says a message is unterminated. Computed inside the
    // closure, so a parse that succeeds never pays for it: the position is a walk over the line's
    // characters, and a file has one message per clause. `input` starts right after the `<<`, so the tag
    // itself sits two columns earlier.
    let unclosed = |detail: String| {
        let (open_line, open_column) = position_of(&input);
        let open_column = open_column.saturating_sub(2).max(1);
        refuse(
            0,
            format!(
                "Message opened at line {} column {} is not closed. Unable to find a closing >> tag for \
                 message: {}",
                open_line, open_column, detail
            ),
        )
    };
    // The line number of a later offset in this message, for the lines an error names.
    let line_of = |offset: usize| position_of(&input.take_split(offset).0).0;
    // A `<<` before the closing tag is a forgotten tag (contract above). When the scan passed a body line
    // that ends in `>>` on the way, that line is named too, as the line probably meant to close the message.
    let forgotten_tag = |line: &str, tag_shaped: Option<(usize, &str)>| {
        let mut detail = format!(
            "a << appears before the next closing >>, on the line `{}`. A message body may not contain \
             <<; if that << opens a later clause's message, this message's own closing >> tag is missing",
            line.trim()
        );
        if let Some((start, shaped)) = tag_shaped {
            detail.push_str(&format!(
                ". The earlier line `{}` (line {}) ends in >> after other text; if it was meant to close \
                 this message, the closing >> tag must start its line",
                shaped.trim(),
                line_of(start)
            ));
        }
        unclosed(detail)
    };

    // Nothing here looks past the closing tag: the rest of its line is the grammar's (contract above).
    let close_at = |closing_tag: usize, tag_shaped: Option<(usize, &str)>| {
        if fragment[..closing_tag].contains("<<") {
            return Err(forgotten_tag(&fragment[..opening_line_end], tag_shaped));
        }
        let split = input.take_split(closing_tag);
        Ok((split.0, *split.1.fragment()))
    };

    // Inline form: both tags on the opening line.
    if let Some(closing_tag) = fragment[..opening_line_end].find(">>") {
        return close_at(closing_tag, None);
    }

    // Block form (contract above). The scan remembers, without acting on them, the first body line that
    // ends in `>>` (with or without a trailing comment: `>>`, blanks, `#`, so `see issue #42` stays text),
    // the first line that looks like file structure (`}` or a rule header), and the first rule header; the
    // first two are named only when the scan fails, the third refuses a terminator found past it.
    let ends_in_tag = |body: &str| {
        let text = body.trim_end();
        text.ends_with(">>")
            || text.match_indices('#').any(|(hash, _)| {
                let before = &text[..hash];
                before.ends_with(char::is_whitespace) && before.trim_end().ends_with(">>")
            })
    };
    let mut cursor = opening_line_end;
    let mut terminator = None;
    let mut tag_shaped: Option<(usize, &str)> = None;
    let mut structure_passed: Option<(usize, &str)> = None;
    let mut rule_header_passed: Option<(usize, &str)> = None;
    while cursor < fragment.len() {
        let line_start = cursor + 1;
        let line_end =
            next_line_break(line_start).map_or(fragment.len(), |offset| line_start + offset);
        let line = &fragment[line_start..line_end];
        let body = line.trim_start();
        if body.starts_with(">>") {
            terminator = Some(line_start + (line.len() - body.len()));
            break;
        }
        if line.contains("<<") {
            return Err(forgotten_tag(line, tag_shaped));
        }
        if tag_shaped.is_none() && ends_in_tag(body) {
            tag_shaped = Some((line_start, line));
        }
        let header = looks_like_rule_header(body);
        if structure_passed.is_none() && (body.starts_with('}') || header) {
            structure_passed = Some((line_start, line));
        }
        if rule_header_passed.is_none() && header {
            rule_header_passed = Some((line_start, line));
        }
        cursor = line_end;
    }
    let Some(closing_tag) = terminator else {
        // Structure the scan passed is a second reading only when it came before the line ending in `>>`:
        // a `}` after that line is the enclosing block's own brace, which every message ends before.
        let before_tag =
            |(at, _): &(usize, &str)| tag_shaped.map_or(true, |(shaped_at, _)| *at < shaped_at);
        let structure_before_tag = structure_passed.filter(before_tag);
        let mut detail = String::from("no later line starts with >>");
        // A rule header before the line ending in `>>` leaves one reading: a message never runs across a
        // rule header, so moving that `>>` onto its own line would only be refused by the check below.
        if let Some((header_at, header)) = rule_header_passed.filter(before_tag) {
            let (open_line, _) = position_of(&input);
            detail.push_str(&format!(
                ", and the scan passed the rule header `{}` at line {} on the way: the message opened at \
                 line {} is missing its closing >> tag before that line",
                header.trim(),
                line_of(header_at),
                open_line
            ));
            return Err(unclosed(detail));
        }
        match (tag_shaped, structure_before_tag) {
            (None, None) => {}
            (Some((shaped_at, shaped)), None) => detail.push_str(&format!(
                ". The line `{}` (line {}) ends in >> after other text. A closing >> tag must start its \
                 line, or the message must not end a line with >>",
                shaped.trim(),
                line_of(shaped_at)
            )),
            (None, Some((structure_at, structure))) => detail.push_str(&format!(
                ", and the scan passed `{}` at line {} on the way: the message is probably missing its \
                 closing >> tag before that line",
                structure.trim(),
                line_of(structure_at)
            )),
            (Some((shaped_at, shaped)), Some((structure_at, structure))) => {
                let (open_line, _) = position_of(&input);
                detail.push_str(&format!(
                    ". Two readings: the message opened at line {} is missing its closing >> tag before \
                     `{}` at line {}; or it runs to line {}, where the line `{}` ends in >> after other \
                     text and the closing >> tag there must start its line",
                    open_line,
                    structure.trim(),
                    line_of(structure_at),
                    line_of(shaped_at),
                    shaped.trim()
                ));
            }
        }
        return Err(unclosed(detail));
    };
    if let Some((header_at, header)) = rule_header_passed {
        return Err(unclosed(format!(
            "the next line starting with >> is line {}, but the scan passed the rule header `{}` at line \
             {} on the way. A message body may not hold a rule header, so that >> belongs to a later rule \
             and this message is missing its own closing >> tag; close it before line {} with a >> that \
             starts its line",
            line_of(closing_tag),
            header.trim(),
            line_of(header_at),
            line_of(header_at)
        )));
    }

    close_at(closing_tag, tag_shaped)
}

/// Whether a body line reads as a rule header: `rule`, blanks, a name, then the end of the line, `#`, `(`
/// (a parameter list), `{`, or the whole word `when`. A name alone covers the two-line header the docs
/// write (`rule name` with `when ...` or `{` on the next line). Prose such as "rule of thumb: ..." or
/// "rule X whenever ..." is not one.
fn looks_like_rule_header(body: &str) -> bool {
    let Some(after_keyword) = body.strip_prefix("rule") else {
        return false;
    };
    let rest = after_keyword.trim_start_matches([' ', '\t']);
    if rest.len() == after_keyword.len() {
        return false;
    }
    let name_end = rest
        .find(|c: char| !(c.is_alphanumeric() || c == '_'))
        .unwrap_or(rest.len());
    if name_end == 0 {
        return false;
    }
    let after_name = rest[name_end..].trim();
    let whole_word_when = after_name.strip_prefix("when").is_some_and(|tail| {
        tail.chars()
            .next()
            .map_or(true, |c| !(c.is_alphanumeric() || c == '_'))
    });
    after_name.is_empty()
        || after_name.starts_with('#')
        || after_name.starts_with('(')
        || after_name.starts_with('{')
        || whole_word_when
}

fn custom_message(input: Span) -> IResult<Span, &str> {
    delimited(tag("<<"), extract_message, tag(">>"))(input)
}

pub(crate) fn does_comparator_have_rhs(op: &CmpOperator) -> bool {
    !op.is_unary()
}

fn variable_capture_in_map_or_index(input: Span) -> IResult<Span, String> {
    let (input, var) = preceded(zero_or_more_ws_or_comment, var_name)(input)?;
    let (input, _pipe) = preceded(space0, char('|'))(input)?;
    Ok((input, var))
}

fn predicate_filter_clauses(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;

    // Held for the rest of this function, so the level is open for exactly as long as the filter is.
    // Safe to open as soon as the `[` is consumed because this is the last branch of
    // `predicate_or_index`: nothing else is tried at this position afterwards, so a level opened here
    // is never open while a sibling reading is being attempted. `map_keys_match` cannot say the same
    // and does not open here; see the guard there.
    let _nesting = NestingGuard::enter(input, "filter")?;

    let (input, var) = opt(variable_capture_in_map_or_index)(input)?;
    let (input, filters) = cnf_clauses(input, clause)?;
    // A trailing `or` lands here: `separated_list1` backtracks a separator whose following clause
    // fails, `cnf_clauses` returns what it has, and the `]` is not next. The bare `cut` refused that
    // with nom's empty context, `when handling , fragment or ] EXISTS`; the context names what the
    // filter was ready to read instead. The `context` re-points the error at the input it is given,
    // and that is already the offending token here: `cnf_clauses` hands back its input with the
    // trailing whitespace and comments consumed, so the skip inside `close_array` has nothing left
    // to cross. The block closer below is the one that had to move its skip out of the `context`.
    let (input, _close) = context(
        "expecting a clause, `or`, or the closing `]` of the filter; an `or` needs a clause on both sides",
        cut(close_array),
    )(input)?;
    Ok((input, QueryPart::Filter(var, filters)))
}

fn dotted_property(input: Span) -> IResult<Span, QueryPart> {
    preceded(
        zero_or_more_ws_or_comment,
        preceded(
            char('.'),
            alt((
                map(parse_int_value, |idx| {
                    let idx = match idx {
                        Value::Int(i) => i,
                        _ => unreachable!(),
                    };
                    QueryPart::Index(idx)
                }),
                map(property_name, QueryPart::Key),
                map(var_name_access, QueryPart::Variable),
                value(QueryPart::AllValues(None), char('*')),
            )), // end alt
        ), // end preceded for char '.'
    )(input)
}

fn open_array(input: Span) -> IResult<Span, ()> {
    value((), preceded(zero_or_more_ws_or_comment, char('[')))(input)
}

fn close_array(input: Span) -> IResult<Span, ()> {
    value((), preceded(zero_or_more_ws_or_comment, char(']')))(input)
}

fn all_indices(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    let (input, query_part) = alt((
        value(
            QueryPart::AllIndices(None),
            preceded(zero_or_more_ws_or_comment, char('*')),
        ),
        // Whitespace-tolerant like the `*` branch above, and it was not. Without the `preceded`, a leading
        // space made this branch fail, `array_index` fail after it, and `map_key_lookup` -- which does skip
        // whitespace -- catch the same identifier and return `AllValues(Some(name))` instead. So `[x]` and
        // `[x ]` were one query part while `[ x]` and `[ x ]` were another.
        //
        // Two spaces were the whole difference between a working rule and an unevaluatable one, because the
        // `%var` map-key interpolation arm in `eval_context.rs` accepts `AllIndices`, `Key` and `Index` after
        // an interpolated variable and not `AllValues`: `Tags.%k[x] == "prod"` passed at exit 0 while
        // `Tags.%k[ x ] == "prod"` bailed at exit 19 with "This type of query R based variable interpolation
        // is not supported".
        map(preceded(zero_or_more_ws_or_comment, var_name), |name| {
            QueryPart::AllIndices(Some(name))
        }),
    ))(input)?;
    let (input, _close) = close_array(input)?;
    Ok((input, query_part))
}

fn array_index(input: Span) -> IResult<Span, QueryPart> {
    map(
        delimited(
            open_array,
            // Whitespace-tolerant like every other bracket form, and it was not. `open_array` and
            // `close_array` each skip whitespace, so a trailing space was fine and a leading one was not:
            // `Names[0 ]` parsed and `Names[ 0]` did not, because the space reached `parse_int_value`, whose
            // `digit1` cannot begin on one. The numeric index was the only bracket form with the omission --
            // `[*]`, `[x]` and a filter all accepted the space.
            //
            // Nothing else in `predicate_or_index` reads a bare integer, so the query fell through to
            // `predicate_filter_clauses` and the whole file was rejected with "There were no clauses
            // present". Loud rather than misread, but `Names[ 0 ]` is an ordinary way to write it, and it
            // took `Tags[ 0 ].Key` and an index inside a filter down with it.
            //
            // The `cut` below keeps its scope: a filter whose first token is an integer is not a clause in
            // any spelling, `[0 == 1]` included, so accepting the space cannot commit to this branch for
            // input another branch would have read.
            preceded(zero_or_more_ws_or_comment, parse_int_value),
            cut(close_array),
        ),
        |idx| {
            let idx = match idx {
                Value::Int(i) => i,
                _ => unreachable!(),
            };
            QueryPart::Index(idx)
        },
    )(input)
}

/// A quoted key inside brackets: `Resources["MyBucket"]` is `Key("MyBucket")`.
///
/// This had a second branch, `[ ws* var_name ws* ]` mapped to `AllValues(Some(name))`, and it is deleted
/// rather than kept, because after `all_indices`' named branch became whitespace-tolerant it accepted
/// exactly the same language -- `close_array` skips the trailing whitespace in both -- and `all_indices`
/// comes first in `predicate_or_index`. Nothing an author can write reached it. Measured across sixteen
/// spellings including tabs, newlines and comments inside the brackets, no query part came back as
/// `AllValues(Some(_))`; `no_query_spelling_produces_a_named_all_values` is that measurement, kept as the
/// pin.
///
/// The two branches were never distinguishable by language. Before the tolerance they were separated only
/// by whether a space happened to precede the identifier, which made `[x]` an `AllIndices` and `[ x ]` an
/// `AllValues` -- the accident that broke `Tags.%k[ x ]`. So one of the two had to go, and `AllIndices` is
/// the one to keep: it is what the interpolated-key arm of `query_retrieval_with_converter` accepts, and
/// the evaluator treats a named `AllIndices` and a named `AllValues` identically anyway (list ->
/// `accumulate`, map -> `accumulate_map` with the key captured, scalar -> pass through).
///
/// The alternative -- reordering `predicate_or_index` to put this branch first -- only moves the deadness
/// onto `all_indices`' named branch and turns every `[x]` into an `AllValues`, which reopens the
/// interpolated-key failure it would then have to widen that arm to absorb.
///
/// `AllValues` therefore only ever carries `None`, and the `Some` handling that fed it is gone from
/// `eval_context::query_retrieval_with_converter` and `exprs::collect_query_capture_names`. Making it
/// nameable again means restoring all three, and the suite says so rather than this comment: putting this
/// branch back while leaving the two consumers deleted turns `test_variable_capture_syntax` and
/// `a_bare_name_capture_does_not_leak_across_iterations_of_a_block` red alongside the pin, because the
/// name parses and then captures nothing.
fn map_key_lookup(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    // The same omission as `array_index` above, and the last bracket form carrying it. A quoted key
    // names a property a bare identifier cannot spell -- `Resources["MyBucket"]` is `Key("MyBucket")`
    // -- and `Resources[ "MyBucket" ]` was rejected, while `Resources["MyBucket" ]` parsed, because
    // `open_array` and `close_array` skipped whitespace and `parse_string` did not.
    //
    // Widening this branch is not the same question as widening the index, because a string literal
    // opens a clause as readily as it names a key: `[ "AWS::CloudFormation::Authentication" exists ]`
    // is a filter, and one in the AWS rule registry. What keeps the two apart is `close_array` below
    // carrying no `cut`. Consuming the string and then not finding `]` is a recoverable error, so a
    // clause backtracks out of here with the string unconsumed and `predicate_filter_clauses` reads
    // it. The token after the string decides, and the spelling with spaces reaches that decision as the
    // spelling without does.
    let (input, query_part) = map(preceded(zero_or_more_ws_or_comment, parse_string), |idx| {
        let idx = match idx {
            Value::String(i) => i,
            _ => unreachable!(),
        };
        QueryPart::Key(idx)
    })(input)?;
    let (input, _close) = close_array(input)?;
    Ok((input, query_part))
}

fn map_keys_match(input: Span) -> IResult<Span, QueryPart> {
    let (input, _open) = open_array(input)?;
    let (input, var) = opt(variable_capture_in_map_or_index)(input)?;
    let (input, _) = zero_or_more_ws_or_comment(input)?;
    // The filter's site is its `keys` keyword, the one token every key filter has.
    let location = file_location_of(&input);
    let (input, _keys) = keys(input)?;
    // The four comparators a key filter accepts. `MapKeyComparator` exists so this list and the
    // evaluator cannot disagree: anything absent here is unrepresentable downstream rather than an
    // unreachable match arm.
    //
    // Not `cut`, and that is the fix. `keys` is only reserved for these four comparators, so a filter over a
    // *property* named `keys` -- `[ keys EXISTS ]` -- is a different clause and the next branch of
    // `predicate_or_index` parses it. Committing here stopped that branch from ever running, and the proof
    // that nothing ambiguous forced the rejection is positional: `[ Size EXISTS keys EXISTS ]` was accepted,
    // so the identical clause parsed one slot later. `[ keys EXISTS ]`, `[ keys EMPTY ]`, `[ keys IS_LIST ]`
    // and `[ keys >= 1 ]` were all rejected in first position alone.
    //
    // The `cut`s below stay: once a key-filter comparator has been seen, this is a key filter and a missing
    // right-hand side or closing bracket is an error rather than another reading.
    let (input, cmp) = preceded(
        zero_or_more_ws_or_comment,
        alt((
            value(MapKeyComparator::Eq, tag("==")),
            value(MapKeyComparator::NotEq, tag("!=")),
            value(MapKeyComparator::In, in_keyword),
            map(tuple((not, in_keyword)), |_m| MapKeyComparator::NotIn),
        )),
    )(input)?;
    // Value, then function call, then access -- the order and the set that `clause_tail_with_map` and `let_value`
    // use. The function call was missing here, and it is the one right-hand side of the three that changed
    // what a clause means rather than rejecting it. `access` matched the function's name as a query and left
    // `(...)` behind, `close_array` carries no `cut` so that failed recoverably, and
    // `predicate_filter_clauses` -- the next branch of `predicate_or_index` -- then read the same text as an
    // ordinary filter over a property named `keys`. So `Tags[ keys == to_lower("ALPHA") ]` asked whether a
    // child property called `keys` equalled `alpha`, where the two spellings beside it asked what the author
    // wrote. Against a document holding one entry keyed `alpha` whose `keys` child is `zulu`, the literal and
    // the variable spellings pass at exit 0 and the function spelling failed at exit 19, blaming a value it
    // named as `[null]`.
    //
    // Nothing downstream forced the narrower set: `MapKeyFilterClause::compare_with` is a `LetValue`, and the
    // arm that resolves a `LetValue::FunctionCall` for a key filter is already there in
    // `eval_context::query_retrieval_with_converter` -- it was unreachable because the parser could not build
    // one.
    // Held for the rest of this function, which is the right-hand side -- the only part of a key filter
    // that recurses, through `access` and `function_expr` below. Opened here rather than at the `[`
    // above on purpose: this branch is tried *before* `predicate_filter_clauses`, and a filter over a
    // property named `keys` backtracks out of it (see the comment on the comparator above). A level held
    // during that failed attempt would count against the ordinary filter that reads the same text next,
    // so a file legally 128 filters deep would be refused at 128 rather than at 129. By here the
    // comparator has matched and this is a key filter in any reading.
    let _nesting = NestingGuard::enter(input, "key filter")?;

    let (input, with) = cut(preceded(
        zero_or_more_ws_or_comment,
        alt((
            map(parse_value, |value| {
                LetValue::Value(PathAwareValue::try_from(value).unwrap())
            }),
            map(
                preceded(zero_or_more_ws_or_comment, function_expr),
                LetValue::FunctionCall,
            ),
            map(
                preceded(zero_or_more_ws_or_comment, access),
                LetValue::AccessClause,
            ),
        )),
    ))(input)?;
    let (input, _close) = close_array(input)?;
    Ok((
        input,
        QueryPart::MapKeyFilter(
            var,
            MapKeyFilterClause {
                comparator: cmp,
                compare_with: with,
                location,
            },
        ),
    ))
}

/// The bracket forms, as an ordered alternation. Order is meaning here, so the languages are written down.
///
/// Shadowing is a class rather than an incident in an `alt`: an earlier branch that accepts a later
/// branch's input makes the later one dead, silently and for every input. `map_key_lookup`'s named branch
/// died that way and went unnoticed until the branches' languages were written out, so the five languages after this change are:
///
/// | branch                     | language                                    | yields                     |
/// |----------------------------|---------------------------------------------|----------------------------|
/// | `all_indices`              | `[ ws* ('*' \| var_name) ws* ]`             | `AllIndices(None \| Some)` |
/// | `array_index`              | `[ ws* ('-'? digit+) ws* ]`                 | `Index`                    |
/// | `map_key_lookup`           | `[ ws* string ws* ]`                        | `Key`                      |
/// | `map_keys_match`           | `[ ws* (var '\|')? ws* keys cmp rhs ws* ]`  | `MapKeyFilter`             |
/// | `predicate_filter_clauses` | `[ ws* (var '\|')? clause+ ws* ]`           | `Filter`                   |
///
/// No pair shadows. The first three are disjoint on their first non-whitespace character, because
/// `var_name` is `alpha1` followed by alphanumerics and underscores: it cannot begin on `*`, on a digit,
/// on `-`, or on a quote. The last two overlap the first three on their opening token and are reached by
/// backtracking rather than by being distinguishable up front -- `[ keys == x ]` and `[ x | Type == 'a' ]`
/// both start down `all_indices`, which fails at its `close_array` and gives the input back. That is why
/// `all_indices`, `map_key_lookup` and `map_keys_match` carry no `cut` on their closing bracket, and
/// changing any of them to carry one would kill the branch below it.
///
/// Two narrownesses here are load-bearing and are left alone:
///
/// - `array_index`'s `cut(close_array)`. A filter whose first token is a bare integer is not a clause in
///   any spelling, `[0 == 1]` included, so committing once the digits are read costs nothing and gives a
///   pointed error instead of "There were no clauses present".
/// - `map_key_lookup` reading only a string. Widening it back to a bare identifier is what created the
///   shadowing this change removed; see the note on that function.
fn predicate_or_index(input: Span) -> IResult<Span, QueryPart> {
    alt((
        all_indices,
        array_index,
        map_key_lookup,
        map_keys_match,
        predicate_filter_clauses,
    ))(input)
}

//
//  dotted_access              = "." (var_name / "*")
//
// This combinator does not fail. It is the responsibility of the consumer to fail based
// on error.
//
// Expected error types:
//    nom::error::ErrorKind::Char => if the start is not '.'
//
// see var_name, var_name_access for other error codes
//
fn dotted_access(input: Span) -> IResult<Span, Vec<QueryPart>> {
    fold_many1(
        alt((dotted_property, predicate_or_index)),
        Vec::new,
        |mut acc: Vec<QueryPart>, part| {
            acc.push(part);
            acc
        },
    )(input)
}

fn property_name(input: Span) -> IResult<Span, String> {
    alt((
        var_name,
        map(parse_string, |v| match v {
            Value::String(value) => value,
            _ => unreachable!(),
        }),
    ))(input)
}

fn some_keyword(input: Span) -> IResult<Span, bool> {
    value(
        true,
        delimited(
            zero_or_more_ws_or_comment,
            alt((tag("SOME"), tag("some"))),
            one_or_more_ws_or_comment,
        ),
    )(input)
}

/// `this`, with the word boundary `some_keyword` has and this one did not.
///
/// `this_keyword` is the first branch of `access`, so it beat `property_name`: a property named
/// `thisThing` could not be written at all on the left of a clause, and on the right it split into
/// `this` plus a reference to a rule named `Thing`. `something == 1` has always parsed, because
/// `some_keyword` requires trailing whitespace; the asymmetry was an omission, not a policy.
fn this_keyword(input: Span) -> IResult<Span, QueryPart> {
    preceded(
        zero_or_more_ws_or_comment,
        alt((
            value(QueryPart::This, keyword("this")),
            value(QueryPart::This, keyword("THIS")),
        )),
    )(input)
}

//
//   access     =   (var_name / var_name_access) [dotted_access]
//
pub(crate) fn access(input: Span) -> IResult<Span, AccessQuery> {
    access_query(input, true)
}

/// `access` with `some` read as a property name rather than as the modifier.
///
/// `some` is a legal property name, and `opt(some_keyword)` commits: once the modifier has matched, the
/// remainder is parsed as though it were meant, and whatever fails afterwards fails for the whole clause.
/// So `some == "bar"` failed inside `access` -- an operator cannot begin a query -- and `some exists` failed
/// one step later in `clause_tail_with_map`, where `exists` had already been taken as the query and no comparator
/// was left. Neither is ambiguous: the modifier reading of both is a `some` with no clause after it.
/// `someProperty` and `some.foo` were never affected, because `some_keyword` requires a space after the word.
///
/// This differs from `access` only when `some` or `SOME` is followed by whitespace, which is the only input
/// `opt(some_keyword)` consumes anything on. Everywhere else the two are the same parser, so a clause parser
/// built on this one can be tried after the ordinary one without widening the alternation for any other input.
fn access_without_some_modifier(input: Span) -> IResult<Span, AccessQuery> {
    access_query(input, false)
}

fn access_query(input: Span, some_modifier: bool) -> IResult<Span, AccessQuery> {
    let (input, any) = match some_modifier {
        true => opt(some_keyword)(input)?,
        false => (input, None),
    };
    let match_all = any.is_none();
    map(
        tuple((
            alt((
                this_keyword,
                // A `%name` is the only text that becomes a variable; a quoted `"%name"` is a key.
                map(var_name_access, QueryPart::Variable),
                map(property_name, QueryPart::Key),
            )),
            opt(dotted_access),
        )),
        move |(first, remainder)| {
            let query_parts = match remainder {
                Some(mut parts) => {
                    parts.insert(0, first.clone());
                    if first.is_variable() {
                        // Slot 1 of a variable-rooted query is a reserved no-op, and this reserves it.
                        // `query_retrieval_with_converter`'s root-variable arm needs a part there that is
                        // not the author's. A binding whose own query projected -- `let buckets =
                        // Resources.*[ .. ]` -- has already handed back the individuals, so the arm
                        // consumes the reserved slot instead of enumerating them a second time. Leave the
                        // slot out and the only thing left for it to consume is the author's first written
                        // part, which is the mistake this branch made with `[ name ]` and records below.
                        //
                        // Reserving the slot does not make slot 1 unreachable, because that arm decides
                        // rather than skips: it consumes the slot only when the enumeration the slot stands
                        // for happens somewhere else -- `query_projects` says the binding produced the
                        // members, or the part right after the slot is an expansion standing in for the
                        // slot's own -- and otherwise resumes *at* the slot and runs what is there.
                        //
                        // `expansion_at` alone is not that second condition, and reading it as though it
                        // were is what this paragraph got wrong before. A bare `[*]` at that position is
                        // the author's own second wildcard rather than a restatement of the slot -- it is
                        // there precisely because the branch below declined to insert in front of one --
                        // so the arm excludes `AllIndices(None)` and lets `%v[*][*]` run both of its
                        // wildcards, which is what `Cfg.Groups[*][*]` does. The accounting for that
                        // choice lives on the arm and is not duplicated here.
                        //
                        // A bare `[*]` is the one thing allowed to occupy the slot instead, because it is
                        // the same no-op. `%r[*].Type` and `%r.Type` are the same query, and injecting a
                        // second `AllIndices(None)` in front of the author's would leave one of the two
                        // unskipped: it would hand the whole map through to `Type` and not find it.
                        //
                        // The condition was `AllIndices(_)`, which also matched a *named* index. A named
                        // index is a key capture -- real work rather than a no-op -- so it took the
                        // reserved slot and the root arm ate it. `%r[ name ].Type` then looked `Type` up
                        // inside the variable's own value instead of inside each of its members:
                        // `%r[ name ].Type in [..]` went from exit 0 PASS to exit 19 "Could not find key
                        // Type inside struct at path /Resources", and the same query as a `when` gate went
                        // from exit 19 with a full ComparisonError to exit 0 with nothing on either
                        // channel -- a rule with a violation to report passing silently, which is the
                        // direction that made this urgent.
                        //
                        // That is the Map-valued case. A LIST-valued binding moved as well, and the
                        // paragraph above would not tell you so. Where a map binding lost the descent
                        // into its members, a list binding changed from meaning "the whole list" to
                        // meaning "its elements". Measured with two release binaries built at this tip,
                        // over `Items: [{V: 1}, {V: 2}]` and `let l = Cfg.Items`: `%l[ n ] IS_STRUCT`
                        // was exit 19 before, naming the list itself -- "Property [/Cfg/Items] ...
                        // needed value at [[{"V":1},{"V":2}]] was not a struct" -- and is exit 0 after,
                        // because each member is a struct. FAIL to PASS, the opposite direction from
                        // the map case. The fix moves verdicts both ways, so neither direction is the
                        // safe one to assume when reading a rule that this changed.
                        //
                        // In every case measured the new answer is the one the literal-rooted spelling
                        // already gave, which is why the old answer was the wrong one rather than
                        // merely the other one. `Cfg.Items[ n ] IS_STRUCT` is exit 0 on both binaries,
                        // because a literal root never took this path, so the fix brings `%l` into
                        // agreement with `Cfg.Items` instead of inventing a third behavior.
                        // `%l[ n ].V == 1` is exit 19 on both binaries but for different reasons:
                        // before, a retrieval error, "Attempting to retrieve from key V but type is not
                        // an struct type at path /Cfg/Items ... Type = array"; after, a real comparison
                        // failure against the member whose `V` is 2, which is exactly what
                        // `Cfg.Items[ n ].V == 1` reports. An exit code that does not move can still be
                        // a different answer, so exit codes alone do not measure this.
                        //
                        // `AllIndices(Some(_))` started reaching this position because `all_indices`' named
                        // branch became whitespace-tolerant. That change is right and stays: `[x]` and
                        // `[ x ]` are the same query, and the tolerance is what makes `Tags.%k[ x ]`
                        // resolve at parity with `Tags.%k[x]` one position along, where the interpolated-key
                        // arm accepts `AllIndices` and not `AllValues`. It widened a hole rather than
                        // opening one: `%r[name].Type`, no spaces, always took this path and always failed
                        // the same way, measured at exit 19 both with the tolerance and without it.
                        //
                        // Narrowing the root arm's skip to `AllIndices(None)` instead would work equally
                        // well, and is rejected as a redundant second guard. `access_query` is the only
                        // route in this tree that builds a query rooted at a `%var` -- the two other
                        // `AccessQuery` construction sites, `type_block`'s injected `Resources.*[ .. ]` and
                        // `AccessClause::default`, are both literal-rooted -- so the invariant is total
                        // here, and holding it in one place keeps the test able to fail. If a second
                        // construction route is ever added, that arm is the second place to narrow.
                        //
                        // Which of the two happened is recorded rather than left to be re-derived. The
                        // inserted slot is byte-identical to the author's own `[*]`, so once the insert
                        // was made the AST no longer said whether one had happened, and the root arm read
                        // it off slot 2's shape instead: a bare `[*]` there could only come from the
                        // author having written one at slot 1 too, since the insert would not have fired
                        // in front of it. Sound in one direction only, and four spellings parse to the
                        // same parts through the gap -- `%v[*].*` with `%v.*`, `%v[*][ n ]` with
                        // `%v[ n ]`, and `%v[0]` and `%v[-1]` each with their `[*]`-prefixed twin. See
                        // `QueryPart::AuthoredIndices` for what each pair costs.
                        //
                        // The author's `[*]` carries the mark rather than the inserted slot, because the
                        // inserted slot is in every `%v.X` query and so in `parse-tree` output and in
                        // every verbose report's rendered `Context=`. Marking it there would move those
                        // goldens; marking the rarer half of the same bit moves none.
                        match parts.get(1) {
                            Some(QueryPart::AllIndices(None)) => {
                                parts[1] = QueryPart::AuthoredIndices;
                            }
                            _ => {
                                parts.insert(1, QueryPart::AllIndices(None));
                            }
                        }
                    }
                    parts
                }

                None => {
                    vec![first]
                }
            };
            AccessQuery {
                query: query_parts,
                match_all,
            }
        },
    )(input)
}

fn clause_with_map<'loc, A, M, T: 'loc>(
    input: Span<'loc>,
    mut access: A,
    mapper: M,
) -> IResult<Span<'loc>, T>
where
    A: FnMut(Span<'loc>) -> IResult<Span<'loc>, AccessQuery<'loc>>,
    M: FnMut(GuardAccessClause<'loc>) -> T + 'loc,
{
    let location = file_location_of(&input);

    let (rest, not) = preceded(zero_or_more_ws_or_comment, opt(not))(input)?;
    let (rest, query) = access(rest)?;
    clause_tail_with_map(rest, location, not.is_some(), query, access, mapper)
}

/// A comparison clause, continued from a query already parsed.
///
/// Split out of `clause_with_map` so `access_clause_or_block` can offer one parse of a query to this
/// reading and to the block reading, rather than each parsing the same text for itself.
fn clause_tail_with_map<'loc, A, M, T: 'loc>(
    input: Span<'loc>,
    location: FileLocation<'loc>,
    negation: bool,
    query: AccessQuery<'loc>,
    access: A,
    mut mapper: M,
) -> IResult<'loc, Span<'loc>, T>
where
    A: FnMut(Span<'loc>) -> IResult<Span<'loc>, AccessQuery<'loc>>,
    M: FnMut(GuardAccessClause<'loc>) -> T + 'loc,
{
    let (rest, cmp) = preceded(
        context("expecting one or more WS or comment blocks", zero_or_more_ws_or_comment),
        // error if there is no value_cmp, has to exist
        context("expecting comparison binary operators like >, <= or unary operators KEYS, EXISTS, EMPTY or NOT",
                value_cmp)
    )(input)?;

    if !does_comparator_have_rhs(&cmp.0) {
        let (rest, custom_message) = map(
            preceded(zero_or_more_ws_or_comment, opt(custom_message)),
            |msg| msg.map(String::from),
        )(rest)?;
        Ok((
            rest,
            mapper(GuardAccessClause {
                access_clause: AccessClause {
                    query,
                    comparator: cmp,
                    compare_with: None,
                    custom_message,
                    location,
                },
                negation,
            }),
        ))
    } else {
        let (rest, (compare_with, custom_message)) =
            context("expecting either a property access \"engine.core\" or value like \"string\" or [\"this\", \"that\"]",
                    cut(alt((
                        //
                        // Order does matter here as true/false and other values can be interpreted as access
                        //
                        map(tuple((
                            parse_value, preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            move |(rhs, msg)| {
                                (Some(LetValue::Value(PathAwareValue::try_from(rhs).unwrap())), msg.map(String::from).or(None))
                            }),
                       map(tuple((
                            preceded(zero_or_more_ws_or_comment, function_expr),
                            preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            |(rhs, msg)| {
                                (Some(LetValue::FunctionCall(rhs)), msg.map(String::from).or(None))
                            }),
                        map(tuple((
                            preceded(zero_or_more_ws_or_comment, access),
                            preceded(zero_or_more_ws_or_comment, opt(custom_message)))),
                            |(rhs, msg)| {
                                (Some(LetValue::AccessClause(rhs)), msg.map(String::from).or(None))
                            }),

                    ))))(rest)?;
        Ok((
            rest,
            mapper(GuardAccessClause {
                access_clause: AccessClause {
                    query,
                    comparator: cmp,
                    compare_with,
                    custom_message,
                    location,
                },
                negation,
            }),
        ))
    }
}

fn clause_with<A>(input: Span, access: A) -> IResult<Span, GuardClause>
where
    A: Fn(Span) -> IResult<Span, AccessQuery>,
{
    clause_with_map(input, access, GuardClause::Clause)
}

pub(crate) fn block_clause(input: Span) -> IResult<Span, GuardClause> {
    let location = file_location_of(&input);

    let (rest, query) = access(input)?;
    block_clause_with_query(rest, location, query)
}

/// A block clause, continued from a query already parsed.
///
/// The counterpart of `clause_tail_with_map`, and split out for the same reason: `access_clause_or_block`
/// parses the query once and offers it to both readings.
fn block_clause_with_query<'loc>(
    input: Span<'loc>,
    location: FileLocation<'loc>,
    query: AccessQuery<'loc>,
) -> IResult<'loc, Span<'loc>, GuardClause<'loc>> {
    let (input, not_empty) = opt(value(
        true,
        preceded(zero_or_more_ws_or_comment, tuple((not, empty))),
    ))(input)?;
    let (input, (assignments, conjunctions)) = block(clause)(input)?;
    Ok((
        input,
        GuardClause::BlockClause(BlockGuardClause {
            query,
            block: Block {
                assignments,
                conjunctions,
            },
            location,
            not_empty: not_empty.map_or(false, std::convert::identity),
        }),
    ))
}

/// A function call, once `call_expr` has agreed that the text is one.
///
/// The two refusals below are `Failure`, not `Error`, for the reason `parse_float` and
/// `parse_regex_inner` give and for the one `parameter_names` gives: a recoverable error sends the
/// enclosing `alt` on to the next value production, and the message never reaches the author. With these
/// two as `Error`, the diagnostic is formatted and discarded in all three cases, and the author reads
/// instead:
///
/// ```text
/// let x = json_parse(a, b)      exit 5, "at line 1 at column 19 ... fragment (a, b)"
/// let x = unknown_function(a)   exit 5, "at line 1 at column 25 ... fragment (a)"
/// X == json_parse(a, b)         exit 5, a fragment rather than the counts
/// ```
///
/// In each one the next production is `access`, which reads the name as a bare property, leaves the
/// argument list unconsumed, and hands `all_consuming` a stray `(` to complain about. `LetExpr::try_from`
/// went further and returned `Ok`, with an `AccessClause` over the name and the arguments dropped.
///
/// Backtracking past these two points is impossible, which is what makes the commitment safe. Both are
/// reached only after `call_expr` has consumed a name, a `(`, an argument list and the matching `)`, so
/// the text is `name(...)` in any reading -- and `name(` is a function call or nothing. Only two
/// productions in this file read a `(` at all: `call_expr` here, and `parameter_names`, which reads a
/// rule *definition*'s parameter list. No query production reads one, so `access` cannot be the correct
/// reading of this text. A parameterized rule *call* does not come through here either; it is parsed by
/// `parameterized_rule_call_clause`, which calls `call_expr` directly.
///
/// What stays recoverable is the question `call_expr` answers: whether this is a call at all. Its
/// failure on a missing `(` still propagates as an `Error`, because that is the signal every `alt` above
/// needs in order to try `access` on an ordinary property access. The split is the one `parse_float`
/// draws -- its float-shape test is still an `Error` so a bare integer can fall through, and only its
/// out-of-range checks are `Failure`. An `Error` here means "this production does not apply"; a
/// `Failure` means "it applies and the input is wrong".
fn function_expr(input: Span) -> IResult<Span, FunctionExpr> {
    let location = file_location_of(&input);

    // Held because `input` is about to be shadowed by the span *after* the call, and both refusals
    // below want to point at the call itself. Reporting the position after it puts the caret past the
    // closing parenthesis -- on `let x = json_parse(a, b)` that is column 25, the end of the line,
    // rather than column 9 where `json_parse` starts. `block` has the same note about a refusal landing
    // past the construct it is about.
    let at_call = input;
    let (input, (name, parameters)) = call_expr(input)?;

    let name = FunctionName::try_from(name.as_str()).map_err(|e| {
        nom::Err::Failure(ParserError {
            // The payload rather than `e.to_string()`. `FunctionName::try_from` returns
            // `Error::ParseError`, whose `Display` wraps its text in "Parser Error when parsing `..`",
            // and this context is wrapped that same way again on the way out, so the rendered message
            // said it twice around one sentence. Invisible while the error was being discarded.
            context: match e {
                Error::ParseError(message) => message,
                other => other.to_string(),
            },
            span: at_call,
            kind: ErrorKind::AlphaNumeric,
        })
    })?;

    if parameters.len() != name.get_expected_number_of_args() {
        return Err(nom::Err::Failure(ParserError {
            context: format!(
                "function: {name} requires: {} parameters to be passed, but received: {}",
                name.get_expected_number_of_args(),
                parameters.len()
            ),
            span: at_call,
            kind: ErrorKind::AlphaNumeric,
        }));
    }

    Ok((
        input,
        FunctionExpr {
            location,
            name,
            parameters,
        },
    ))
}

pub(crate) fn let_value(input: Span) -> IResult<Span, LetValue> {
    preceded(
        zero_or_more_ws_or_comment,
        alt((
            map(parse_value, |val| {
                LetValue::Value(PathAwareValue::try_from(val).unwrap())
            }),
            map(function_expr, LetValue::FunctionCall),
            map(access, LetValue::AccessClause),
        )),
    )(input)
}

fn call_expr(input: Span) -> IResult<Span, (String, Vec<LetValue>)> {
    // Spelled out rather than as one `tuple((var_name, delimited(..)))` so the level can be opened
    // between the `(` and the arguments. The sequence, and every failure it can return, is the same.
    let (input, name) = var_name(input)?;
    let (input, _open) = char('(')(input)?;

    // Held for the rest of this function, which is the whole argument list, so the level is open for
    // exactly as long as the call is. After the `(` rather than before `var_name`, so a bare name that
    // is not a call -- which is most of what this parser tries this on -- costs nothing.
    let _nesting = NestingGuard::enter(input, "function call")?;

    let (input, parameters) =
        separated_list0(char(','), delimited(multispace0, let_value, multispace0))(input)?;
    let (input, _close) = char(')')(input)?;
    Ok((input, (name, parameters)))
}

pub(crate) fn parameterized_rule_call_clause(
    input: Span,
) -> IResult<Span, ParameterizedNamedRuleClause> {
    let location = file_location_of(&input);

    let (input, not) = opt(not)(input)?;
    let (input, (rule_name, access_clauses)) = call_expr(input)?;
    let (input, custom_message) = opt(preceded(zero_or_more_ws_or_comment, custom_message))(input)?;
    Ok((
        input,
        ParameterizedNamedRuleClause {
            parameters: access_clauses,
            named_rule: GuardNamedRuleClause {
                location,
                custom_message: custom_message.map(|s| s.to_string()),
                negation: not.map_or(false, |_| true),
                dependent_rule: rule_name,
            },
        },
    ))
}

//
//  simple_unary               = "EXISTS" / "EMPTY"
//  keys_unary                 = "KEYS" 1*SP simple_unary
//  keys_not_unary             = "KEYS" 1*SP not_keyword 1*SP unary_operators
//  unary_operators            = simple_unary / keys_unary / not_keyword simple_unary / keys_not_unary
//
//
//  clause                     = access 1*SP unary_operators *(LWSP/comment) custom_message /
//                               access 1*SP binary_operators 1*(LWSP/comment) (access/value) *(LWSP/comment) custom_message
//
// Errors:
//     nom::error::ErrorKind::Alpha, if var_name_access / var_name does not work out
//     nom::error::ErrorKind::Char, if whitespace / comment does not work out for needed spaces
//
// Failures:
//     nom::error::ErrorKind::Char  if access / parse_value does not work out
//
//
fn clause(input: Span) -> IResult<Span, GuardClause> {
    alt((
        when_block(single_clauses, clause, |conds, (assigns, cls)| {
            GuardClause::WhenBlock(
                conds,
                Block {
                    assignments: assigns,
                    conjunctions: cls,
                },
            )
        }),
        // Ahead of `access_clause_or_block`. The two are disjoint: this one needs a `(` immediately after
        // the name, and the block reading needs a `{` at the position where the query stopped, which for
        // a name is that same `(`.
        map(
            parameterized_rule_call_clause,
            GuardClause::ParameterizedNamedRule,
        ),
        access_clause_or_block,
        // Last, and only reached when the reading above failed. `some` is a property name as well as the
        // modifier, and `access` commits to the modifier as soon as it sees the word and a space, so
        // `some == "bar"` and `some exists` -- clauses about a property named `some` -- could not be written.
        // See `access_without_some_modifier`.
        //
        // This arm cannot take input `rule_clause` was reading, which is what the enclosing alternations try
        // after this one: it succeeds only where a comparator follows the name, and `rule_clause` reads a bare
        // name only when a newline, a comment, `{`, `}` or `or` follows it.
        |i| clause_with(i, access_without_some_modifier),
    ))(input)
}

/// The two readings of a clause that open with a query, over one parse of it.
///
/// A block clause and a comparison clause both begin with an `access`, and as separate arms of the
/// alternation above each got its own attempt: the block reading parsed the entire query, found no `{`
/// where `block` needs one, returned a recoverable error, and the comparison arm parsed the identical
/// text again. A filter inside a query is a `clause`, so the two attempts double at every level of
/// nesting, and the cost of `rule a { q[ q[ .. ] exists ] exists }` was 2^depth: measured at 2.00x per
/// level over nine consecutive levels, thirty seconds at depth twenty for a 262-byte file, about nine
/// hours at depth thirty. Every depth parsed correctly and exited 0, so nothing was ever reported --
/// a caller with a timeout saw a timeout and one without saw nothing.
///
/// The block reading is still tried first, and has to be. Both readings succeed on
/// `foo not empty { .. }`, because `empty` is a unary comparator and the comparison reading takes
/// `foo not empty` and leaves the block unread; the block arm came earlier and won.
///
/// The sharing is conditional because the two readings do not open at the same position in general.
/// The comparison reading skips whitespace and takes a negation before the query, and the block reading
/// does neither -- it reads `not`, `NOT` or `!` as the start of a property name instead, which is why
/// `not { a == 1 }` is a block clause over a property called `not` and `not foo { a == 1 }` is not a
/// block clause at all. So one parse serves both exactly when that prefix consumed nothing, and
/// otherwise the two readings are tried in turn as before. That fallback cannot be the exponential case:
/// after a negation the block reading needs the filter to hang off the negation word itself and the
/// comparison reading needs a name in its place, so at most one of the two descends.
fn access_clause_or_block(input: Span) -> IResult<Span, GuardClause> {
    let location = file_location_of(&input);

    // A negation consumes at least one character, so an unmoved offset means the prefix took neither a
    // negation nor any whitespace, which is exactly when the two readings open on the same span.
    let (after_prefix, _) = preceded(zero_or_more_ws_or_comment, opt(not))(input)?;
    if after_prefix.location_offset() == input.location_offset() {
        let (rest, query) = access(input)?;
        match block_clause_with_query(rest, location.clone(), query.clone()) {
            Err(nom::Err::Error(_)) => {}
            result => return result,
        }

        return clause_tail_with_map(rest, location, false, query, access, GuardClause::Clause);
    }

    match block_clause(input) {
        Err(nom::Err::Error(_)) => clause_with(input, access),
        result => result,
    }
}

fn single_clause(input: Span) -> IResult<Span, WhenGuardClause> {
    match clause_with_map(input, access, WhenGuardClause::Clause) {
        // The same fallback as the last arm of `clause`, for a condition in a `when`. Only on a recoverable
        // error: a Failure means something further in committed, and retrying would report the wrong thing.
        Err(nom::Err::Error(_)) => {
            clause_with_map(input, access_without_some_modifier, WhenGuardClause::Clause)
        }
        result => result,
    }
}

//
//  rule_clause   =   (var_name (LWSP/comment)) /
//                    (var_name [1*SP << anychar >>] (LWSP/comment)
//
//
//  rule_clause get to be the most pesky of them all. It has the least
//  form and thereby can interpret partials of other forms as a rule_clause
//  To ensure we don't do that we need to peek ahead after a rule name
//  parsing to see which of these forms is present for the rule clause
//  to succeed
//
//      rule_name[ \t]*(\n / \r\n / \r)
//      rule_name[ \t\n]+or[ \t\n]+
//      rule_name(#[^\n\r]+)
//
//      rule_name\s+<<msg>>[ \t\n]+or[ \t\n]+
//
//
//

/// The line endings `rule_clause` peeks for, which has to be the set the rest of the parser accepts.
///
/// A bare `\r` was missing. `zero_or_more_ws_or_comment` reaches `multispace1`, which accepts `" \t\r\n"`, so a
/// lone CR is whitespace at every other position in this parser -- but a rule reference is read by peeking for
/// one of a fixed set of following tokens, and anything outside that set falls to the `cut` on
/// `custom_message`, whose Failure escapes the alternation. So in a file whose lines end with a bare CR, a
/// comparison clause parsed and a rule reference on its own line did not, and the second term of a disjunction
/// did not either. Measured across thirteen constructs in one such file, ten parsed and three did not, which
/// makes readability depend on which construct happens to sit at the boundary. A uniform rejection would at
/// least be predictable; this was not.
///
/// Longest first, so `\r\n` is never read as a bare `\r` with a stray `\n` after it. CRLF was already handled
/// and is unaffected.
fn newline(input: Span) -> IResult<Span, Span> {
    alt((tag("\r\n"), tag("\n"), tag("\r")))(input)
}

fn rule_clause(input: Span) -> IResult<Span, GuardClause> {
    let location = file_location_of(&input);

    let (remaining, not) = opt(not)(input)?;
    let (remaining, ct_type) = var_name(remaining)?;

    // A dangling operator is a syntax error, not a reference to a rule with the operator's name.
    //
    // `separated_list1` backtracks a separator whose following element fails, so `Resources exists or`
    // leaves the literal `or` sitting where `disjunction_clauses` next expects an element. `or` is a
    // valid `var_name`, and what follows it there is a newline or a `}` -- both in the peek set below --
    // so the reference reading was accepted. `rule r { Resources exists or }` parsed into two
    // conjunctions whose second was `NamedRule("or")`, and the run then said two contradictory things
    // about a name the author never wrote: stdout reported "dependent rule [or] did not PASS" while
    // stderr said `Rule or by that name does not exist, Rule Names = ["r"]`. A `when` list did the same
    // -- `rule main when a or { .. }` reported the identical pair.
    //
    // Refused here rather than through `CallSiteMismatch`, which is the post-parse check that reads a
    // call site against the definition it names. Neither half of that describes this input: there is no
    // argument list to disagree about, and no definition of `or` to disagree with. Reaching for
    // `MissingArguments` would also mean accepting the wrong tree first and diagnosing it afterwards,
    // where the parser has the operator's own span in hand -- and that variant's doc comment argues
    // against exactly this kind of reuse, on the ground that a message which misdescribes the input is
    // the defect it was added to remove.
    //
    // Only the two spellings `or_term` accepts through `var_name`. `|OR|` cannot reach here, since a
    // `var_name` starts with `alpha1`, and `Or` or `oR` are ordinary names that no separator would have
    // consumed, so refusing them would take away a rule name over a resemblance.
    //
    // Left alone deliberately: `rule or { .. }` still parses, and a rule so named is still evaluated and
    // reported. Only the by-name reference is refused, which is the one position where the name cannot
    // be told apart from the operator. Without this refusal, a file that declares `rule or` and
    // references it runs at exit 0, so a real if absurd capability is being narrowed; refusing the
    // definition as well would be a second behavior change with no defect driving it.
    // `a_dangling_or_is_a_syntax_error` pins both halves so a later widening is a decision rather than a
    // drift.
    if ct_type == "or" || ct_type == "OR" {
        return Err(nom::Err::Failure(ParserError {
            context: format!(
                "`{ct_type}` is the disjunction operator, not a rule name. A clause is required on \
                 both sides of `{ct_type}`: write the missing clause, or delete the `{ct_type}`."
            ),
            span: input,
            kind: ErrorKind::Tag,
        }));
    }

    //
    // we peek to preserve the input, if it is or, space+newline or comment
    // we return
    //
    // `}` is in the set, and it was not. Anything not peeked here falls to the `cut(custom_message)`
    // below, whose Failure escapes the enclosing alternation -- so `rule b { a }` was rejected with an
    // error naming `}` rather than the reference, while the same rule written over three lines parsed.
    // Every other clause form works inline, which made this specific to rule references.
    let do_return = remaining.is_empty()
        || matches!(
            peek(alt((
                preceded(space0, value((), newline)),
                preceded(space0, value((), comment2)),
                preceded(space0, value((), char('{'))),
                preceded(space0, value((), char('}'))),
                value((), or_join),
            )))(remaining),
            Ok((_same, _ignored))
        );

    if do_return {
        return Ok((
            remaining,
            GuardClause::NamedRule(GuardNamedRuleClause {
                dependent_rule: ct_type,
                location,
                negation: not.is_some(),
                custom_message: None,
            }),
        ));
    }

    //
    // Else it must have a custom message
    //
    // Said in words before the `cut`, because the `cut` alone said nothing. `tag("<<")` fails with
    // nom's empty context, and the `Failure` escapes every alternation above with that field still
    // blank, so `rule b { a extra }` was refused as `when handling , fragment extra }`: the right
    // verdict, with the one field an author reads first left empty.
    //
    // What follows the identifier decides which words. This production is the last one tried, so
    // the text in hand is not always a rule reference with something stray after it: `a.b` or `a[0]`
    // with no comparator is a clause that `clause` gave up on, and `let x = 1` in a `when` list is an
    // assignment where a condition belongs. Calling either "the rule reference `a`" misdescribes the
    // input in the same way the old `Rule or by that name does not exist` did. The characters `.`,
    // `[`, `=`, `!`, `<` and `>` cannot follow a rule reference, so they select the clause wording;
    // `let` selects its own; anything else really is a stray token after a reference, and the peek
    // set above is what the parser was ready to read there.
    //
    // One more shape has its own words, and they come first: a body line that starts with `>>`
    // (`>> append to the runbook`) ends up here, since `append` is read as a reference and `to the
    // runbook` is nothing a reference may be followed by. The text after a block message's `>>` is
    // the grammar's (see `extract_message`); when prose follows the word and a block terminator
    // precedes it, the refusal carries the hint that says so. A typo such as `>> Encrypted = true`,
    // where `var_name` stopped on `.`, `[` or an operator, keeps the clause wording. The line index is
    // read for the wording only; acceptance is decided above.
    let prose_follows = {
        let rest = remaining.fragment();
        let words = rest.trim_start_matches([' ', '\t']);
        words.len() < rest.len() && words.starts_with(|c: char| c.is_alphabetic())
    };
    let (remaining, _) = space0(remaining)?;
    if !remaining.fragment().starts_with("<<") {
        let next = remaining.fragment().chars().next();
        let context = match next {
            _ if prose_follows && block_terminator_precedes(&input) => String::from(
                "a body line may not start with >>. If this text belongs to the message, \
                 move it before the >>",
            ),
            Some(ch @ ('.' | '[' | '=' | '!' | '<' | '>')) => format!(
                "`{ct_type}` is followed by `{ch}`, which cannot follow a rule reference, so this is \
                 read as a clause: expecting a property access and then comparison binary operators \
                 like >, <= or unary operators KEYS, EXISTS, EMPTY or NOT, with a value after a \
                 binary operator"
            ),
            _ if ct_type == "let" => String::from(
                "`let` begins an assignment, not a clause or a rule reference: an assignment reads \
                 `let <name> = <value>`, and is not allowed in a `when` condition",
            ),
            _ => format!(
                "expecting `or`, a custom message `<< ... >>`, a comment, the end of the line, or a \
                 `{{` or `}}` after the rule reference `{ct_type}`"
            ),
        };
        return Err(nom::Err::Failure(ParserError {
            context,
            span: remaining,
            kind: ErrorKind::Tag,
        }));
    }
    let (remaining, message) = cut(custom_message)(remaining)?;
    Ok((
        remaining,
        GuardClause::NamedRule(GuardNamedRuleClause {
            dependent_rule: ct_type,
            location,
            negation: not.is_some(),
            custom_message: Some(message.to_string()),
        }),
    ))
}

//
// clauses
//
/// Reads a newline-separated list of `or`-joined clause groups, one conjunction per line.
///
/// Took two more parameters than it used, and both lied rather than merely going unread. A mapper
/// `M: FnMut(Vec<E>) -> T` was never called -- and could not have mattered, since `T` appears nowhere in
/// the return type -- and all three call sites passed `std::convert::identity` for it. A `non_empty: bool`
/// was never forwarded either: the call to `disjunction_clauses` below has always hard-coded `true`,
/// while `single_clauses` and `clauses` passed `false` and read as asking for the opposite.
///
/// Removed rather than honored, because the value those two callers asked for cannot be honored. `false`
/// selects `separated_list0`, and nom 7.1.3 returns `Ok((i, vec![]))` from it with the input unconsumed
/// when the first element fails (`multi/mod.rs:241-242`; the lockfile pins that version). The loop below
/// would then set `rest` to the span it already held, push an empty `Disjunctions`, and never terminate.
/// So the parameter was not an unused option, it was an option with one legal value.
///
/// Nothing is given up by fixing the value, and two things already said so. An empty conjunction list is
/// refused unconditionally a few lines down, so it was never a reachable outcome under any argument. And
/// `when_conditions` carries a comment stating that "`single_clauses` raises its own Failure for an empty
/// condition list in any case, which is where those spellings are actually rejected" -- the `false`-passing
/// caller was documented as depending on the `true` behavior.
#[allow(clippy::redundant_closure)]
fn cnf_clauses<'loc, E, F>(input: Span<'loc>, mut f: F) -> IResult<Span<'loc>, Conjunctions<E>>
where
    F: FnMut(Span<'loc>) -> IResult<Span<'loc>, E>,
    E: Clone + 'loc,
{
    let mut conjunctions = Conjunctions::new();
    let mut rest = input;
    loop {
        match disjunction_clauses(rest, |i: Span| f(i)) {
            Err(nom::Err::Error(_)) => {
                if conjunctions.is_empty() {
                    let (line, column) = position_of(&input);
                    return Err(nom::Err::Failure(ParserError {
                        span: input,
                        context: format!(
                            "There were no clauses present {}#{}@{}",
                            input.extra, line, column
                        ),
                        kind: ErrorKind::Many1,
                    }));
                }
                return Ok((rest, conjunctions));
            }

            Ok((left, disjunctions)) => {
                rest = left;
                conjunctions.push(disjunctions);
            }

            Err(e) => return Err(e),
        }
    }
}

/// Reads one conjunction: a clause, or several joined by `or`.
///
/// Had a `non_empty: bool` selecting `separated_list1` over `separated_list0`, and all four call sites
/// passed `true`, so the `separated_list0` arm was unreachable. Removed with the arm, for the reason
/// given on `cnf_clauses`: `separated_list0` succeeds without consuming input when the first element
/// fails, which every caller here reaches from a loop that would then not terminate. Keeping the
/// parameter after `cnf_clauses` stopped offering it would have left the same lie one level down.
#[allow(clippy::redundant_closure)]
fn disjunction_clauses<'loc, E, F>(
    input: Span<'loc>,
    mut parser: F,
) -> IResult<Span<'loc>, Disjunctions<E>>
where
    F: FnMut(Span<'loc>) -> IResult<Span<'loc>, E>,
    E: Clone + 'loc,
{
    separated_list1(
        or_join,
        preceded(zero_or_more_ws_or_comment, |i: Span<'loc>| parser(i)),
    )(input)
}

fn single_clauses(input: Span) -> IResult<Span, Conjunctions<WhenGuardClause>> {
    cnf_clauses(
        input,
        //
        // Order does matter here. Both rule_clause and access clause have the same syntax
        // for the first part e.g
        //
        // s3_encrypted_bucket  or configuration.containers.*.port == 80
        //
        // the first part is a rule clause and the second part is access clause. Consider
        // this example
        //
        // s3_encrypted_bucket or bucket_encryption EXISTS
        //
        // The first part if rule clause and second part is access. if we use the rule_clause
        // to be first it would interpret bucket_encryption as the rule_clause. Now to prevent that
        // we are using the alt form to first parse to see if it is clause and then try rules_clause
        //
        alt((
            single_clause,
            map(
                parameterized_rule_call_clause,
                WhenGuardClause::ParameterizedNamedRule,
            ),
            map(rule_clause, |g| match g {
                GuardClause::NamedRule(nr) => WhenGuardClause::NamedRule(nr),
                _ => unreachable!(),
            }),
        )),
    )
}

#[allow(dead_code)] // TODO: investigate why this is unused
fn clauses(input: Span) -> IResult<Span, Conjunctions<GuardClause>> {
    cnf_clauses(
        input,
        //
        // Order does matter here. Both rule_clause and access clause have the same syntax
        // for the first part e.g
        //
        // s3_encrypted_bucket  or configuration.containers.*.port == 80
        //
        // the first part is a rule clause and the second part is access clause. Consider
        // this example
        //
        // s3_encrypted_bucket or bucket_encryption EXISTS
        //
        // The first part if rule clause and second part is access. if we use the rule_clause
        // to be first it would interpret bucket_encryption as the rule_clause. Now to prevent that
        // we are using the alt form to first parse to see if it is clause and then try rules_clause
        //
        alt((clause, rule_clause)),
    )
}

fn let_assignment_expr(input: Span) -> IResult<Span, String> {
    let (input, _let_keyword) = tag("let")(input)?;
    //
    // if we have a pattern like "letproperty" that can be an access keyword
    // then there is no space in between. This will error out.
    //
    let (at_name, _space) = one_or_more_ws_or_comment(input)?;
    let (after_name, assigned) = var_name(at_name)?;

    // The assignment sign is what identifies an assignment, so that is where the commitment belongs. It was a
    // `cut`, and `let` is a legal property name: `let EXISTS` is a clause about that property, but `var_name`
    // above reads the `EXISTS` as the variable being assigned, and the `cut` then made the missing sign a
    // Failure that escaped the alternation instead of letting `clause` read the line. Every unary comparator
    // was affected and no binary one was, because `let == "bar"` fails at `var_name`, which was already
    // recoverable.
    //
    // What distinguishes the two readings is the name: `let` and a space followed by a comparator is the whole
    // of the clause, and followed by anything else it is an assignment that has lost its sign. So only the
    // first falls through, and `let x` still says what is wrong with it -- which it could not do by falling
    // through, because the alternation's last error would name the line rather than the missing sign.
    //
    // Unlike `rule`, the name here cannot be separated from the construct by looking at what follows it, so
    // the test is on the name itself.
    match preceded(zero_or_more_ws_or_comment, alt((tag("="), tag(":="))))(after_name) {
        Ok((input, _sign)) => Ok((input, assigned)),

        Err(nom::Err::Error(recoverable)) => match peek(value_cmp)(at_name) {
            Ok(_) => Err(nom::Err::Error(recoverable)),
            Err(_) => Err(nom::Err::Failure(ParserError {
                context: format!(
                    "Expected = or := after let {}, as in \"let {} = 10\".",
                    assigned, assigned
                ),
                kind: ErrorKind::Tag,
                span: after_name,
            })),
        },

        Err(e) => Err(e),
    }
}

fn assignment(input: Span) -> IResult<Span, LetExpr> {
    let (input, var_name) = let_assignment_expr(input)?;

    match parse_value(input) {
        Ok((input, value)) => Ok((
            input,
            LetExpr {
                var: var_name,
                value: LetValue::Value(PathAwareValue::try_from(value).unwrap()),
            },
        )),

        Err(nom::Err::Error(_)) => {
            //
            // if we did not succeed in parsing a value object, then
            // if must be an access pattern, or function call  else it is a failure
            match preceded(zero_or_more_ws_or_comment, function_expr)(input) {
                Ok((input, function)) => Ok((
                    input,
                    LetExpr {
                        var: var_name,
                        value: LetValue::FunctionCall(function),
                    },
                )),

                // Fall through to an access only on a *recoverable* error, which is the same rule
                // `single_clause` follows: a `Failure` means something inside the call committed, and
                // reading the same text as a property access instead reports whatever that fails on.
                // The depth bound is one such commitment, and it shows: falling through on a `Failure` too,
                // `let x = to_upper(to_upper( ... ))` past the bound is refused -- correctly, at 5 -- with a
                // `ParserError` whose context is the empty string, because the message that named the depth
                // is thrown away here and `access` fails on the `(` with nothing to say. A `cut` around
                // this call cannot prevent that: it turns a recoverable error into a `Failure`, the arm
                // below then catches it, and no outcome changes at all.
                Err(nom::Err::Error(_)) => {
                    let (input, access) = cut(preceded(zero_or_more_ws_or_comment, access))(input)?;

                    Ok((
                        input,
                        LetExpr {
                            var: var_name,
                            value: LetValue::AccessClause(access),
                        },
                    ))
                }

                Err(e) => Err(e),
            }
        }

        Err(e) => Err(e),
    }
}

//
// when keyword
//
/// The first variable name assigned twice in a list of assignments, if any.
///
/// Order of declaration is what an author would expect to decide the winner, and it is not what does; see
/// the call sites for the measurement. Returning the name rather than a bool so the diagnostic can say
/// which one.
fn first_duplicate_assignment(assignments: &[LetExpr<'_>]) -> Option<String> {
    let mut seen = std::collections::HashSet::new();
    assignments
        .iter()
        .find(|assignment| !seen.insert(assignment.var.as_str()))
        .map(|assignment| assignment.var.clone())
}

/// The diagnostic for a cycle among `let` right-hand sides, shared by the two scopes that look for
/// one so they cannot drift apart.
///
/// The chain is spelled out because the name alone does not say what to change in a longer ring: with
/// `let a = %b` and `let b = %a`, either declaration is the one to edit and the author has to see
/// both to pick. No scope phrase, unlike the duplicate-assignment messages -- a duplicate is only a
/// problem relative to a scope, while a cycle is unresolvable wherever it sits, and the block-level
/// site carries a span that says where.
///
/// That last clause was false when it was written and is true now. The block-level site reported the
/// span left after the whole body was consumed, which lands on the closing brace of the enclosing
/// block rather than on the scope holding the ring; it now reports the block's opening brace. The
/// file-level site still carries no position at all, which is a separate gap and not this one.
fn let_cycle_message(cycle: &[&str]) -> String {
    if let [only] = cycle {
        return format!(
            "Variable {} is defined in terms of itself. Resolving it recurses until the stack is \
             exhausted, so the file is rejected rather than run.",
            only
        );
    }

    format!(
        "Variables {} are defined in terms of each other. Resolving any of them recurses until the \
         stack is exhausted, so the file is rejected rather than run.",
        cycle
            .iter()
            .chain(cycle.first())
            .copied()
            .collect::<Vec<&str>>()
            .join(" -> ")
    )
}

/// The diagnostic for a cycle among rule references, the sibling of [`let_cycle_message`].
///
/// Worded to match it, because the two say the same thing about two namespaces and an author who has
/// seen one should recognise the other. The ring is spelled out for the reason given there: with
/// `rule a { b }` and `rule b { a }`, either definition is the one to edit and the author has to see
/// both to pick.
fn rule_cycle_message(cycle: &[&str]) -> String {
    if let [only] = cycle {
        return format!(
            "Rule {} references itself. Evaluating it recurses until the stack is exhausted, so the \
             file is rejected rather than run.",
            only
        );
    }

    format!(
        "Rules {} reference each other. Evaluating any of them recurses until the stack is exhausted, \
         so the file is rejected rather than run.",
        cycle
            .iter()
            .chain(cycle.first())
            .copied()
            .collect::<Vec<&str>>()
            .join(" -> ")
    )
}

/// The diagnostic for a call site that does not agree with the definition it names.
///
/// Both arms name the rule and both counts, because the exit code was carrying the whole message
/// before: an arity mismatch reached `main` as `Error::IncompatibleError` and exited -1, which says
/// cfn-guard broke rather than naming a rule to edit.
///
/// The `NotParameterized` arm exists because the old message contradicted itself. `check()` against
/// `rule check { ... }` reported `Parameterized Rule with name check was not found, candidate []`
/// three lines under a report listing `check PASS` -- the lookup consulted the parameterized-rule
/// table only, and its empty candidate list was the tell. `check` was never missing.
///
/// `MissingArguments` is that arm's mirror and exists for the same reason. `check` against
/// `rule check(t) { ... }` wrote "Check was not compliant as dependent rule \[check\] did not PASS" to
/// stdout and "Rule check by that name does not exist, Rule Names = [\"main\"]" to stderr, so one report
/// said the rule ran and did not pass, and said it does not exist. The two arms carry separate messages
/// because they ask for opposite edits: drop the parentheses, or add them.
fn call_site_mismatch_message(mismatch: &CallSiteMismatch<'_>) -> String {
    match mismatch {
        CallSiteMismatch::Arity {
            rule_name,
            expected,
            got,
        } => format!(
            "Rule {name} is declared with {expected} {expected_noun}, and a call passes it {got} \
             {got_noun}. The counts have to match, or a reference to a parameter inside {name} cannot \
             say which argument it means.",
            name = rule_name,
            expected = expected,
            expected_noun = plural(*expected, "parameter"),
            got = got,
            got_noun = plural(*got, "argument"),
        ),

        CallSiteMismatch::NotParameterized { rule_name } => format!(
            "Rule {name} is declared without a parameter list, so it cannot be called as \
             {name}(...). Write {name} on its own to reference it. Parentheses name a parameterized \
             rule, and there is no parameterized rule called {name} in this file.",
            name = rule_name,
        ),

        CallSiteMismatch::MissingArguments {
            rule_name,
            expected,
        } => format!(
            "Rule {name} is declared with {expected} {expected_noun}, so it cannot be referenced as a \
             bare {name}. Write {name}(...) passing {expected} {got_noun}. A bare name references a rule \
             declared without a parameter list, and the only {name} in this file has one.",
            name = rule_name,
            expected = expected,
            expected_noun = plural(*expected, "parameter"),
            got_noun = plural(*expected, "argument"),
        ),

        // `let` rather than a comparison, because a comparison with the call on its left is not
        // available: `count(%x) == 1` is read as this same rule call followed by a stray `== 1`. A
        // function call is accepted wherever `let_value` is read -- a `let` right-hand side, a
        // comparison's right side, a key filter's right side, a call argument -- but never as a clause
        // or as the left side of one. The advice names the spelling that puts a verdict on its result.
        CallSiteMismatch::BuiltinFunction { name } => format!(
            "{name} is a built-in function, not a rule, so {name}(...) cannot stand on its own as a \
             clause: a function call has no verdict. Assign its result and write a clause over the \
             variable, as in `let n = {name}(...)` followed by `%n == 1`. Parentheses after a bare \
             name call a parameterized rule, and there is no parameterized rule called {name} in this \
             file.",
            name = name,
        ),
    }
}

fn plural(count: usize, noun: &str) -> String {
    match count {
        1 => noun.to_string(),
        _ => format!("{}s", noun),
    }
}

/// The `when` keyword, and it has to be a keyword rather than a tag because what follows it is `cut`.
///
/// `tag("when")` matched the first four characters of `whenever`, the whitespace `when_conditions` requires
/// then failed, and the `cut` inside it turned that recoverable Error into a Failure -- which escapes both
/// the `opt(when_conditions(..))` around it and the `alt` in `rules_file` that would otherwise have read the
/// line as an ordinary clause. So any clause whose first identifier began with `when` or `WHEN` was an
/// unrecoverable parse failure: `whenCreated EXISTS` was rejected at the `C`, while `createdWhen EXISTS` and
/// `WhenCreated EXISTS` were fine, because only the exact-case prefixes reach the tag.
///
/// The tell-tale was that `rule whenever { ... }` *defined* fine and a `whenever` reference did not -- a rule
/// you could declare and never call. `some`, `let` and `rule` were already safe from this, not by design but
/// because their own whitespace requirement yields a recoverable Error with no cut behind it.
fn when(input: Span) -> IResult<Span, ()> {
    value((), alt((keyword("when"), keyword("WHEN"))))(input)
}

#[allow(clippy::redundant_closure)]
fn when_conditions<'loc, P>(
    mut condition_parser: P,
) -> impl FnMut(Span<'loc>) -> IResult<Span<'loc>, Conjunctions<WhenGuardClause<'loc>>>
where
    P: FnMut(Span<'loc>) -> IResult<Span<'loc>, Conjunctions<WhenGuardClause<'loc>>>,
{
    move |input: Span| {
        //
        // see if there is a "when" keyword
        //
        let (input, _when_keyword) = preceded(zero_or_more_ws_or_comment, when)(input)?;

        // The space is required, and it is required *outside* the `cut`. That is the fix. `keyword("when")`
        // rejects a trailing identifier character, so `whenCreated` no longer reaches here, but a trailing
        // `.`, `[` or operator character is not an identifier character and still does: `when.foo == "bar"`
        // matched the keyword, failed this requirement, and the `cut` turned that into a Failure that
        // escaped both the `opt(when_conditions(..))` around it and the `alt` that would have read the line
        // as a clause about a property named `when`. So half of the `whenever` defect was still live, in the
        // half of the spellings `keyword` cannot see.
        //
        // A `when` block cannot be spelled without this space, so `when.`, `when[` and `when(` have exactly
        // one reading each and letting them fall through admits nothing new. `some_keyword` and
        // `let_assignment_expr` already require their space this way.
        let (input, _space) = one_or_more_ws_or_comment(input)?;

        //
        // If there is "when" then parse conditions. It is an error not to have
        // clauses following it
        //
        // The conditions stay committed. Once the space is there the line is no longer decidable from the
        // `when` alone -- `when` on its own line is a reference to a rule of that name, `when == "bar"` is a
        // clause, and `when { ... }` is a block clause over a property named `when` -- so falling through
        // would turn a `when` block missing its conditions into a silently different rule rather than an
        // error. `single_clauses` raises its own Failure for an empty condition list in any case, which is
        // where those spellings are actually rejected; quoting the key reaches all three of them.
        cut(|s| condition_parser(s))(input)
    }
}

#[allow(clippy::redundant_closure)]
fn block<'loc, T, P>(
    mut clause_parser: P,
) -> impl FnMut(Span<'loc>) -> IResult<Span<'loc>, (Vec<LetExpr<'loc>>, Conjunctions<T>)>
where
    P: FnMut(Span<'loc>) -> IResult<Span<'loc>, T>,
    T: Clone + 'loc,
{
    move |input: Span| {
        // `at_brace` is held on the opening `{` and the advanced spans get their own names, which is
        // what `parse_map` does and what the two refusals below need. Shadowing `input` per step is
        // the ordinary shape in this file, and here it put both reported positions *past the whole
        // block body*: the span in hand after `fold_many1` is the text after the last clause, which
        // lands on the closing brace of the enclosing block. Measured, on a duplicate `let v` at
        // line 3 column 5 of a four-line rule body, the refusal reported line 5 column 1 -- the
        // rule's own `}` -- and on the same duplicate inside a `when` block at line 4 column 9 it
        // reported line 6 column 5, that block's `}`. A reader is sent to a brace they did not write
        // wrong.
        //
        // The brace rather than the offending statement, and that is a deliberate stop short of
        // perfect. `LetExpr` carries no location, so naming the declaration itself would mean
        // teaching the fold below to accumulate spans -- a wider change than a locator repair. The
        // opening brace is the scope the message is about ("in the same scope"), it is a construct
        // the author wrote, and it is the same choice `parse_map` made for the same reason.
        let (at_brace, _leading) = zero_or_more_ws_or_comment(input)?;
        let (after_open, _start_block) = char('{')(at_brace)?;

        // Held for the rest of this function, which is the whole of the block's body, so the level is
        // open for exactly as long as the block is. `_nesting` rather than `_`, which would drop it
        // here and count nothing.
        let _nesting = NestingGuard::enter(after_open, "block")?;

        let mut conjunctions: Conjunctions<T> = Conjunctions::new();
        let (after_body, results) = fold_many1(
            alt((
                map(preceded(zero_or_more_ws_or_comment, assignment), |s| {
                    (Some(s), None)
                }),
                map(
                    |i: Span<'loc>| disjunction_clauses(i, |i| clause_parser(i)),
                    |c: Disjunctions<T>| (None, Some(c)),
                ),
            )),
            Vec::new,
            |mut acc, pair| {
                acc.push(pair);
                acc
            },
        )(after_open)?;

        let mut assignments = vec![];
        for each in results {
            match each {
                (Some(let_expr), None) => {
                    assignments.push(let_expr);
                }
                (None, Some(v)) => conjunctions.push(v),
                (_, _) => unreachable!(),
            }
        }

        // The same argument as the duplicate rule-name check, and a worse case than it. A name declared
        // twice in one scope was accepted, and `%name` then resolved to one of the two by a rule the author
        // cannot see: `extract_variables` files literals, queries and function calls into three separate
        // maps, each `insert` overwriting silently, and `resolve_variable` consults them in a fixed order.
        // So the winner is decided by *kind precedence*, not by which declaration came first.
        //
        // With `Size: 1` in the template and both declarations in one scope:
        //
        //     let v = 1     then  let v = 999   ->  exit 19
        //     let v = 999   then  let v = 1     ->  exit 0
        //
        // and when the two are of different kinds, reordering them changes nothing at all -- the query wins
        // over the literal wherever it sits. Unlike the rule-name case, which could not move the exit code,
        // this one flips the verdict.
        //
        // Every nested scope reaches this function, so one check here covers rule bodies and blocks inside
        // them; file-level declarations are checked where they are collected in `rules_file`.
        if let Some(duplicate) = first_duplicate_assignment(&assignments) {
            return Err(nom::Err::Failure(ParserError {
                span: at_brace,
                kind: ErrorKind::Tag,
                context: format!(
                    "Variable {} is assigned more than once in the same scope. Which assignment wins \
                     depends on the kind of each value rather than on their order, so the file is \
                     rejected rather than guessed at.",
                    duplicate
                ),
            }));
        }

        // The same argument again, and a worse symptom than either duplicate case. A right-hand side
        // that reads a name this scope declares recurses with nothing to stop it, and the process
        // aborts on a stack overflow at exit 134 with a core dump -- outside the documented exit codes,
        // so a caller checking for 0, 5 or 19 gets neither a pass nor a failure it can report. Both
        // scopes reach it: `rule r { let a = %a ... }` and the file-level `let a = %a` took the same
        // route through two copies of `resolve_variable`.
        //
        // A cycle check rather than a recursion depth limit, because the cycle is decidable from the
        // text. This rejects exactly the files that cannot resolve and names the ring, where a depth
        // limit would turn the crash into an arbitrary failure at an arbitrary depth and would still
        // reject a legal chain that happened to be longer than the limit.
        // Same span, same reason as the duplicate check above. This site had the identical defect and
        // is fixed with it rather than left for later: the two are one expression apart, share the
        // one shadowed span, and `let_cycle_message`'s own comment asserted that "the block-level
        // site carries a span that says where", which was false by the same measurement.
        if let Some(cycle) = first_let_cycle(&assignments) {
            return Err(nom::Err::Failure(ParserError {
                span: at_brace,
                kind: ErrorKind::Tag,
                context: let_cycle_message(&cycle),
            }));
        }

        // Same refusal as the filter's closing `]`, same reason for the words: a body that ends on a
        // trailing `or` reaches this `cut` with the `or` still unread, and the bare `cut` reported it
        // as `when handling , fragment or }`. The context lists what a body may continue with. The
        // whitespace-and-comment skip stays outside the `context` for the reason given at the filter:
        // with comment lines between the last clause and the bad token, a context around the skip
        // reported the line of the last clause, measured as line 5 for a token on line 8.
        let (after_close, _end_block) = preceded(
            zero_or_more_ws_or_comment,
            context(
                "expecting a clause, a `let` assignment, or the closing `}` of the block; an `or` needs a clause on both sides",
                cut(char('}')),
            ),
        )(after_body)?;

        Ok((after_close, (assignments, conjunctions)))
    }
}

pub(crate) fn type_name(input: Span) -> IResult<Span, TypeName> {
    match tuple((
        terminated(var_name, tag("::")),
        terminated(var_name, tag("::")),
        var_name,
    ))(input)
    {
        Ok((remaining, parts)) => {
            // A CloudFormation module's type is its three parts plus this suffix, and that whole string
            // is what the template's `Type` field carries. Read here so that `type_block` can ask for the
            // space that has to follow the name, and kept in the name because `type_block` compares the
            // name against `Type` with `==`. Consumed and dropped, a block written
            // `My::Org::Mod::MODULE { .. }` would look for `My::Org::Mod`: no module resource would match
            // and the rule would SKIP at exit 0, while a resource of the bare type would be selected.
            let (remaining, module) = opt(tag("::MODULE"))(remaining)?;
            Ok((
                remaining,
                TypeName {
                    type_name: format!(
                        "{}::{}::{}{}",
                        parts.0,
                        parts.1,
                        parts.2,
                        module.map_or("", |suffix| *suffix.fragment())
                    ),
                },
            ))
        }
        Err(nom::Err::Error(_e)) => {
            // custom resource might only have one separator
            let (remaining, parts) = tuple((terminated(var_name, tag("::")), var_name))(input)?;
            Ok((
                remaining,
                TypeName {
                    type_name: format!("{}::{}", parts.0, parts.1),
                },
            ))
        }
        Err(e) => Err(e),
    }
}
//
// Type block
//
fn type_block(input: Span) -> IResult<Span, TypeBlock> {
    //
    // Start must be a type name like "AWS::SQS::Queue"
    //
    let location = file_location_of(&input);
    let (input, name) = type_name(input)?;

    //
    // There has to be a space following type name, else it is a failure
    //
    let (input, _space) = cut(one_or_more_ws_or_comment)(input)?;

    let (input, when_conditions) = opt(when_conditions(single_clauses))(input)?;

    let (input, (assignments, clauses)) = if when_conditions.is_some() {
        cut(block(clause))(input)?
    } else {
        match block(clause)(input) {
            Ok((input, result)) => (input, result),
            Err(nom::Err::Error(_)) => {
                let (input, conjs) = cut(preceded(
                    zero_or_more_ws_or_comment,
                    map(clause, |s| vec![s]),
                ))(input)?;
                (input, (Vec::new(), vec![conjs]))
            }
            Err(e) => return Err(e),
        }
    };

    Ok((
        input,
        TypeBlock {
            conditions: when_conditions,
            type_name: name.type_name.to_string(),
            block: Block {
                assignments,
                conjunctions: clauses,
            },
            query: vec![
                QueryPart::Key("Resources".to_string()),
                QueryPart::AllValues(None),
                QueryPart::Filter(
                    None,
                    Conjunctions::from([Disjunctions::from([GuardClause::Clause(
                        GuardAccessClause {
                            negation: false,
                            access_clause: AccessClause {
                                query: AccessQuery {
                                    query: vec![QueryPart::Key("Type".to_string())],
                                    match_all: true,
                                },
                                custom_message: None,
                                location,
                                compare_with: Some(LetValue::Value(PathAwareValue::String((
                                    Path::root(),
                                    name.type_name,
                                )))),
                                comparator: (CmpOperator::Eq, false),
                            },
                        },
                    )])]),
                ),
            ],
        },
    ))
}

#[allow(clippy::redundant_closure)]
fn when_block<'loc, C, B, M, T, R>(
    mut conditions: C,
    mut block_fn: B,
    mut mapper: M,
) -> impl FnMut(Span<'loc>) -> IResult<Span<'loc>, R>
where
    C: FnMut(Span<'loc>) -> IResult<Span, Conjunctions<WhenGuardClause<'loc>>>,
    B: FnMut(Span<'loc>) -> IResult<Span<'loc>, T>,
    T: Clone + 'loc,
    R: 'loc,
    M: FnMut(Conjunctions<WhenGuardClause<'loc>>, (Vec<LetExpr<'loc>>, Conjunctions<T>)) -> R,
{
    move |input: Span| {
        map(
            preceded(
                zero_or_more_ws_or_comment,
                pair(when_conditions(|p| conditions(p)), block(|p| block_fn(p))),
            ),
            |(w, b)| mapper(w, b),
        )(input)
    }
}

fn rule_block_clause(input: Span) -> IResult<Span, RuleClause> {
    alt((
        map(
            preceded(zero_or_more_ws_or_comment, type_block),
            RuleClause::TypeBlock,
        ),
        map(
            preceded(
                zero_or_more_ws_or_comment,
                pair(
                    when_conditions(single_clauses),
                    block(alt((clause, rule_clause))),
                ),
            ),
            |(conditions, block)| {
                RuleClause::WhenBlock(
                    conditions,
                    Block {
                        assignments: block.0,
                        conjunctions: block.1,
                    },
                )
            },
        ),
        map(
            preceded(zero_or_more_ws_or_comment, alt((clause, rule_clause))),
            RuleClause::Clause,
        ),
    ))(input)
}

/// The name in a rule definition, deciding on the way whether the line is a definition at all.
///
/// `rule` is a legal property name, so `rule == "bar"` at file level is a clause about that property and has
/// to reach `default_clauses`. `cut(var_name)` stopped it: `var_name` failed on the `==` and the `cut` made
/// that a Failure, which escaped `rules_file`'s alternation before the arm that reads clauses ever ran. The
/// identical clause parses inside a rule body, where a rule definition is not one of the alternatives -- which
/// is what shows the rejection was the commitment and not the grammar.
///
/// What can follow `rule` and a space in a clause is a comparator, or more of the query: `dotted_property`
/// and `predicate_or_index` both skip leading whitespace, so `rule .foo == 1` and `rule ["foo"] == 1` are
/// clauses in the same way `wibble .foo == 1` is. Neither can begin a rule name, which is `alpha1` followed by
/// alphanumerics, so falling through on them cannot cost a definition.
///
/// Anything else is a definition whose name is malformed, and saying so here beats letting the alternation
/// fail: its last error names the start of the line with no context at all, while `rule 1foo {` has one
/// obvious thing wrong with it.
fn rule_definition_name(input: Span) -> IResult<Span, String> {
    match var_name(input) {
        Ok(parsed) => Ok(parsed),

        Err(nom::Err::Error(recoverable)) => match peek(alt((
            value((), value_cmp),
            value((), dotted_access),
        )))(input)
        {
            Ok(_) => Err(nom::Err::Error(recoverable)),
            Err(_) => Err(nom::Err::Failure(ParserError {
                context: String::from(
                    "Expected a name for this rule, as in \"rule my_rule { ... }\". A clause about a \
                     property named rule needs the name in quotes, as \"rule\".",
                ),
                kind: ErrorKind::Alpha,
                span: input,
            })),
        },

        Err(e) => Err(e),
    }
}

//
// rule block
//
fn rule_block(input: Span) -> IResult<Span, Rule> {
    //
    // rule is followed by space
    //
    let (input, _rule_keyword) = preceded(zero_or_more_ws_or_comment, tag("rule"))(input)?;
    let (input, _space) = one_or_more_ws_or_comment(input)?;

    // The name is what identifies a definition, so that is where the commitment belongs; see
    // `rule_definition_name`. `cut(block(..))` below still reports a missing or misplaced brace against the
    // rule, and `rule <name>` with neither `(`, `when` nor `{` after it is still an error.
    let (input, rule_name) = rule_definition_name(input)?;
    let (input, conditions) = opt(when_conditions(single_clauses))(input)?;
    let (input, (assignments, conjunctions)) = cut(block(rule_block_clause))(input)?;

    Ok((
        input,
        Rule {
            rule_name,
            conditions,
            block: Block {
                assignments,
                conjunctions,
            },
        },
    ))
}

//
// parameter names
//
/// The parameter list of a parameterized rule, rejecting an empty list and a name that appears twice.
///
/// Collecting straight into the `IndexSet` dropped the duplicate silently, so `rule r(a, a)` became a
/// one-parameter rule. Nothing complained at the definition; the arity check then failed at every
/// *call*, blaming the caller for passing two arguments to a rule written to take two -- `Arity
/// mismatch for called parameter rule r, expected 1, got 2` -- and the run ended at 255, an internal
/// failure, for a rule-authoring mistake the parser was holding in its hand.
///
/// The empty list is rejected on purpose rather than admitted for symmetry with the call form, which
/// accepts `r()` because `call_expr` uses `separated_list0`. A rule with no parameters already has a
/// spelling -- `rule r { ... }` -- and a second one would not mean the same thing: a rule in
/// `guard_rules` gets a verdict of its own in every report, while a parameterized rule is only
/// evaluated where a clause invokes it, which is the asymmetry
/// `commands/reporters/test/mod.rs` has to explain to anyone whose test expectation names one. So
/// `rule r()` would be a way to write a rule that silently never reports, for no gain over the form
/// that does. What it needed was a message saying which spelling to use, and that is what this is:
/// `separated_list1` already rejected it, but only by failing inside `var_name` on the `)`, which
/// reported a nameless parse error whose "fragment" was the whole remainder of the file.
///
/// `Failure` rather than `Error` in both cases because `(` and a name list have already been
/// consumed here -- a recoverable error would send `alt` back to try the non-parameterized rule form
/// and report something unrelated about the line.
fn parameter_names(input: Span) -> IResult<Span, indexmap::IndexSet<String>> {
    let (after_open, _open) = char('(')(input)?;
    let (after_open, empty) = opt(peek(preceded(multispace0, char(')'))))(after_open)?;
    if empty.is_some() {
        return Err(nom::Err::Failure(ParserError {
            context: String::from(
                "A parameterized rule needs at least one parameter. Write the rule without a \
                 parameter list, as \"rule my_rule { ... }\", for one that takes none.",
            ),
            kind: ErrorKind::SeparatedList,
            span: input,
        }));
    }

    let (remaining, names) = terminated(
        separated_list1(
            char(','),
            cut(delimited(multispace0, var_name, multispace0)),
        ),
        cut(char(')')),
    )(after_open)?;

    let unique = names
        .iter()
        .cloned()
        .collect::<indexmap::IndexSet<String>>();
    if unique.len() != names.len() {
        let repeated = names
            .iter()
            .enumerate()
            .find(|(at, name)| names[..*at].contains(name))
            .map(|(_, name)| name.as_str())
            .unwrap_or("");
        return Err(nom::Err::Failure(ParserError {
            context: format!(
                "Parameter {} is declared more than once. Each parameter needs its own name, or a \
                 reference to it cannot say which argument it means.",
                repeated
            ),
            kind: ErrorKind::SeparatedList,
            span: input,
        }));
    }

    Ok((remaining, unique))
}

//
// Parameterized Rule
//
fn parameterized_rule_block(input: Span) -> IResult<Span, ParameterizedRule> {
    //
    // rule is followed by space
    //
    let (input, _rule_keyword) = delimited(
        zero_or_more_ws_or_comment,
        tag("rule"),
        one_or_more_ws_or_comment,
    )(input)?;

    // See `rule_definition_name`. This arm is tried before `rule_block`, so the Failure escaped from here
    // first and both sites needed the same treatment.
    let (input, rule_name) = rule_definition_name(input)?;
    let (input, parameter_names) = parameter_names(input)?;

    // The same step `rule_block` takes, in the same position relative to the block. It was missing
    // here and `conditions` was hardcoded to `None`, so `rule check(t) when ... { ... }` did not parse
    // -- and not by a refusal: the `cut` on the block reported a brace problem at the column where
    // `when` begins, with an empty "when handling" field and the rest of the file as its fragment, so
    // nothing said the construct was unavailable or what to write instead.
    //
    // Nothing downstream needed changing. `eval_parameterized_rule_call` evaluates the body through
    // `eval_rule`, which is the function that reads `rule.conditions`, so a parameterized rule whose
    // condition does not match returns SKIP exactly as a plain one does -- and the SKIP arm of
    // `eval_parameterized_rule_call` then treats it as the plain spelling's reference is treated.
    // `first_name_assigned_and_captured` already walks `parameterized_rules` and reads their
    // conditions, so the assigned-and-captured check covers them without a change.
    let (input, conditions) = opt(when_conditions(single_clauses))(input)?;
    let (input, (assignments, conjunctions)) = cut(block(rule_block_clause))(input)?;

    Ok((
        input,
        ParameterizedRule {
            parameter_names,
            rule: Rule {
                rule_name,
                block: Block {
                    assignments,
                    conjunctions,
                },
                conditions,
            },
        },
    ))
}

fn default_clauses(input: Span) -> IResult<Span, Disjunctions<GuardClause>> {
    let (input, disjunctions) = disjunction_clauses(input, clause)?;
    Ok((input, disjunctions))
}

fn type_block_clauses(input: Span) -> IResult<Span, Disjunctions<TypeBlock>> {
    let (input, disjunctions) = disjunction_clauses(input, type_block)?;
    Ok((input, disjunctions))
}

#[allow(clippy::redundant_closure)]
fn remove_whitespace_comments<'loc, P, R>(
    mut parser: P,
) -> impl FnMut(Span<'loc>) -> IResult<Span<'loc>, R>
where
    P: FnMut(Span<'loc>) -> IResult<Span<'loc>, R>,
{
    move |input: Span| {
        delimited(
            zero_or_more_ws_or_comment,
            |s| parser(s),
            zero_or_more_ws_or_comment,
        )(input)
    }
}

#[derive(Clone, PartialEq, Debug)]
enum Exprs<'loc> {
    Assignment(LetExpr<'loc>),
    DefaultTypeBlock(Disjunctions<TypeBlock<'loc>>),
    DefaultWhenBlock(WhenConditions<'loc>, Block<'loc, GuardClause<'loc>>),
    DefaultClause(Disjunctions<GuardClause<'loc>>),
    Rule(Rule<'loc>),
    ParameterizedRule(ParameterizedRule<'loc>),
}

pub(crate) fn get_rule_name<'b>(rule_file_name: &str, rule_name: &'b str) -> &'b str {
    let prefix = format!("{file_name}/", file_name = rule_file_name);
    if rule_name.starts_with(&prefix) {
        &rule_name[prefix.len()..]
    } else {
        rule_name
    }
}

//
// Rules File
//
pub(crate) fn rules_file(input: Span) -> Result<Option<RulesFile>, Error> {
    // Every position reported while parsing this file is measured against the file, not against `\n`.
    //
    // Three separate things in this parser count lines, and they did not agree. `multispace1`, `comment2`
    // and `newline` treat a lone `\r` as a line ending. `extract_message` split on `\n`, which is the
    // clause-deleting defect fixed there. And every line and column reported comes from `nom_locate`,
    // which counts `\n` alone -- so a file whose lines end in a bare `\r` parsed correctly and then
    // described itself wrongly, reporting an error on line 6 as line 1 column 119. `SourceScope` is what
    // makes the third one agree with the first two; `position_of` is where all ten reporting sites ask.
    //
    // Held for the whole function rather than for the parse, because the `?` below renders a
    // `ParserError` into its message through `From`, and that runs before this guard drops.
    //
    // A bare CR is a supported line ending here, deliberately and by test:
    // `a_bare_carriage_return_ends_a_line_like_the_other_two_spellings` compares 9 constructs across all
    // three spellings, and `a_cr_only_rules_file_still_enforces_its_rules` runs one end to end. Refusing
    // such a file would have been the smaller change -- one check here, and every `\n` assumption in the
    // file becomes sound by construction -- and it was rejected because those two tests say the support
    // is intended, not incidental.
    //
    // One site outside this function still counts `\n` alone, named so that it is not read as covered:
    // the single-line reporters flatten a message with `replace('\n', ";")`, which leaves the `\r` of a
    // CRLF message body in the output. That is the reporting side rather than the parser, and that one
    // flattening cannot change a verdict.
    //
    // Read that as a claim about that one site and not about the reporting side generally, because a
    // reporter defect can absolutely change what a caller sees: `emit_messages` in
    // `reporters/validate/common.rs` accepts a whitespace-only `<< >>` message, pinned by
    // `emit_messages_tests`, and an `emit_messages` that panicked on it would turn a violation reported
    // at exit 19 into an abort at 101. A reader who trusted the wider claim would not look there.
    //
    // `ReadCursor` in `utils/mod.rs` was a second site that counted `\n` alone and no longer is. It now
    // recognizes all five breaks libyaml does -- CR, LF, NEL, LS and PS -- so a data file spelled with
    // any of them renders a `Code:` excerpt whose line numbers match the `L:` reported beside it.
    //
    // A UTF-8 byte order mark ahead of the first character is not part of the file. Editors on Windows
    // write one, nothing renders it, and no production here accepts it -- `multispace1` does not count
    // U+FEFF as whitespace and every top-level construct opens with a keyword or a name -- so such a file
    // failed at line 1 column 1 with an empty `when handling` and a fragment that printed as the valid
    // text it visibly was. Stripped here rather than at each reader so every route that parses rules
    // gets the same answer: `validate`, `test`, `parse-tree`, the library's `TryFrom<&str>`.
    //
    // A fresh span rather than a `take(3)`, so positions are measured from the first visible character,
    // which is where an editor puts column 1. Only at offset 0: the fresh span starts there, so a span
    // that was already advanced would be rebased past the positions `SourceScope` measures against. A
    // mark anywhere else in the file stays the parse error it was; `ParserError`'s `Display` names it
    // there.
    let input = match input.fragment().strip_prefix('\u{feff}') {
        Some(rest) if input.location_offset() == 0 => Span::new_extra(rest, input.extra),
        _ => input,
    };
    let _source = SourceScope::enter(&input);

    let input = match zero_or_more_ws_or_comment(input) {
        Ok(input) => {
            if input.0.is_empty() {
                return Ok(None);
            }

            input.0
        }
        Err(_) => input,
    };

    // Text that no top-level production reads is refused in words rather than through
    // `all_consuming`, whose `Eof` error carries nom's empty context: a stray `}` after the last rule
    // was refused as `when handling , fragment }`. Two ways to arrive here, one message. `fold_many1`
    // stops when an iteration fails recoverably, which leaves the unread text as the remainder; and
    // when the very first expression fails that way it returns a `Many1` error with the same empty
    // context, at the same position. Wrapping the whole fold in `context(..)` would instead prefix
    // every refusal inside every rule with this text, so the check is made here, on the two outcomes
    // that mean "nothing reads this".
    let unread_at_top_level = |span: Span<'_>| {
        Error::from(nom::Err::Failure(ParserError {
            context: "expecting a rule, a `let` assignment, a type block, a `when` block, a clause, or the end of the file"
                .to_string(),
            kind: ErrorKind::Eof,
            span,
        }))
    };
    let folded = fold_many1(
        remove_whitespace_comments(alt((
            map(assignment, Exprs::Assignment),
            map(parameterized_rule_block, Exprs::ParameterizedRule),
            map(rule_block, Exprs::Rule),
            map(type_block_clauses, Exprs::DefaultTypeBlock),
            when_block(single_clauses, alt((clause, rule_clause)), |c, b| {
                Exprs::DefaultWhenBlock(
                    c,
                    Block {
                        assignments: b.0,
                        conjunctions: b.1,
                    },
                )
            }),
            map(default_clauses, Exprs::DefaultClause),
        ))),
        Vec::new,
        |mut acc, expr| {
            acc.push(expr);
            acc
        },
    )(input);
    let exprs = match folded {
        Ok((rest, exprs)) if rest.fragment().is_empty() => exprs,
        Ok((rest, _)) => return Err(unread_at_top_level(rest)),
        Err(nom::Err::Error(e)) => return Err(unread_at_top_level(e.span)),
        Err(e) => return Err(e.into()),
    };

    let mut global_assignments = Vec::with_capacity(exprs.len());
    let mut default_rule_clauses = Vec::with_capacity(exprs.len());
    let mut named_rules = Vec::with_capacity(exprs.len());
    let mut parameterized_rules = Vec::with_capacity(exprs.len());

    for each in exprs {
        match each {
            Exprs::Rule(r) => named_rules.push(r),
            Exprs::ParameterizedRule(p) => parameterized_rules.push(p),
            Exprs::Assignment(l) => global_assignments.push(l),
            Exprs::DefaultClause(clause_disjunctions) => default_rule_clauses.push(
                clause_disjunctions
                    .into_iter()
                    .map(RuleClause::Clause)
                    .collect(),
            ),
            Exprs::DefaultTypeBlock(disjunctions) => default_rule_clauses.push(
                disjunctions
                    .into_iter()
                    .map(RuleClause::TypeBlock)
                    .collect(),
            ),
            Exprs::DefaultWhenBlock(w, b) => {
                default_rule_clauses.push(vec![RuleClause::WhenBlock(w, b)])
            }
        }
    }

    if !default_rule_clauses.is_empty() {
        // `<file name>/default` when the span carries a file name, and a plain `default` when it does
        // not. The plain name is the one callers of the public `run_checks` entry point read back in a
        // report and key on when they pass no rules file name, so it stays byte for byte what it was.
        //
        // Kept at the price of an ambiguity, named here rather than fixed. `default` is a legal rule
        // name, so with no file name an author's own `rule default { .. }` beside top-level clauses is
        // two rules called `default`, and the duplicate check below refuses the file; under a file name
        // the same bytes are `<name>/default` and `default`, which evaluate. The commands all pass a
        // file name (`parse-tree` included, since it started passing its `--rules` path), so the
        // collision is reachable only through `TryFrom<&str>` and a `run_checks` caller that names
        // nothing. Spelling the nameless case `/default` -- a name no `var_name` can collide with --
        // was tried and rejected: it moved the report those callers key on.
        let default_rule_name: String = if input.extra.to_string().trim().is_empty() {
            DEFAULT_RULE_NAME.to_string()
        } else {
            format!(
                "{rule_file_name}/{rule_name}",
                rule_file_name = input.extra,
                rule_name = DEFAULT_RULE_NAME
            )
        };

        let default_rule = Rule {
            conditions: None,
            rule_name: default_rule_name,
            block: Block {
                assignments: vec![],
                conjunctions: default_rule_clauses,
            },
        };
        named_rules.insert(0, default_rule);
    }

    // A rule name is what a reference resolves through, so defining one twice makes every reference
    // to it ambiguous -- and the file was accepted, with the reference binding to whichever
    // definition came first. That is a verdict difference, not a stylistic one. Two definitions of
    // `dup`, one holding and one not, and a `rule user when dup { ... }`:
    //
    //     order in the file            user
    //     holding definition first     PASS
    //     failing definition first     SKIP
    //
    // Both definitions still run and report, so the file exits 19 either way and the exit code
    // cannot see it. The guarded rule silently changed from enforced to not-applicable on a
    // reordering that no author would expect to matter.
    //
    // Parameterized rules share the namespace, so they are checked together: `rule r` and
    // `rule r(x)` collide for the same reason.
    // File-level declarations, for the same reason and with the same consequence as the block-level check
    // in `block`. Checked here because these are collected here and never pass through that function.
    if let Some(duplicate) = first_duplicate_assignment(&global_assignments) {
        return Err(Error::ParseError(format!(
            "Variable {} is assigned more than once at the file level. Which assignment wins depends on \
             the kind of each value rather than on their order, so the file is rejected rather than \
             guessed at.",
            duplicate
        )));
    }

    // File-level cycles, for the reason given at the block-level check in `block`.
    if let Some(cycle) = first_let_cycle(&global_assignments) {
        return Err(Error::ParseError(let_cycle_message(&cycle)));
    }

    let mut seen = std::collections::HashSet::new();
    for name in named_rules.iter().map(|r| r.rule_name.as_str()).chain(
        parameterized_rules
            .iter()
            .map(|p| p.rule.rule_name.as_str()),
    ) {
        if !seen.insert(name) {
            return Err(Error::ParseError(format!(
                "Rule {} is defined more than once. A reference to it would resolve to whichever \
                 definition came first, so the file is rejected rather than guessed at.",
                name
            )));
        }
    }

    let rules_file = RulesFile {
        assignments: global_assignments,
        guard_rules: named_rules,
        parameterized_rules,
    };

    // The same argument as the duplicate-assignment checks above, over the one namespace those two do
    // not compare against. They match assignment names to each other; a filter's capture name is a
    // variable defined in that scope as well -- it is read back as `%name` like any other -- and a name
    // that is both resolves by kind precedence in exactly the way the check above refuses to guess at.
    //
    // Checked here rather than in `block`, because the scopes have to be enumerated one at a time and
    // that function is generic over its clause type, which leaves it unable to walk them.
    if let Some((name, scope)) = first_name_assigned_and_captured(&rules_file) {
        return Err(Error::ParseError(format!(
            "Variable {name} is both assigned and declared as a filter capture {scope}. Which one \
             {name} resolves to depends on the kind of the assigned value rather than on their order, \
             so the file is rejected rather than guessed at. Rename one of them.",
            name = name,
            scope = scope
        )));
    }

    // The same namespace once more, for the one binding the check above does not see: a parameterized
    // rule's parameter, assigned at every call rather than by a `let`. A filter capture in the rule's
    // own `when` condition under a parameter's name is read as the parameter wherever the rule reads
    // `%name`, so the capture does nothing and the author is told rather than left with it.
    if let Some((name, rule)) = first_parameter_captured_in_conditions(&rules_file) {
        return Err(Error::ParseError(format!(
            "Parameter {name} of rule {rule} is also declared as a filter capture in the rule's when \
             condition. Every read of %{name} in the rule is the parameter, so the capture can never be \
             read, and the file is rejected rather than left with a binding that does nothing. Rename \
             the capture.",
            name = name,
            rule = rule
        )));
    }

    // The other half of the crash the `let` cycle check above catches, and the half that needs no `let`
    // in the file at all. `rule loop { loop }` and `rule loop(n) { loop(%n) }` both exhausted the stack
    // and aborted at 134, outside the documented exit codes entirely, so a caller checking for 0, 5 or
    // 19 got neither a pass nor a failure it could report -- and the abort happens before any finding
    // is written, so a file with one accidental cycle said nothing about the other rules in it either.
    //
    // Checked here rather than in `block`, because a rule reference resolves against the whole file's
    // rule namespace and no smaller scope holds enough to decide it. Checked over `rules_file` rather
    // than over the two rule lists so a cycle can close through either spelling, or one of each; see
    // `first_rule_reference_cycle` for why one graph rather than a guard in each evaluation path.
    //
    // After the duplicate-name check above on purpose: that check is what makes a rule name unique, and
    // this one keys a graph by it.
    if let Some(cycle) = first_rule_reference_cycle(&rules_file) {
        return Err(Error::ParseError(rule_cycle_message(&cycle)));
    }

    // A call site read against the definition it names, which is the last thing in this file decidable
    // from the text that was being left to evaluation. `eval_parameterized_rule_call` reached the same
    // conclusion about the argument count and returned `Error::IncompatibleError`, and what happened
    // next depended on where the call sat. From a rule body the error escaped to `main`, which exited
    // -1 -- `INTERNAL_FAILURE` in `guard/tests/utils.rs` -- for an authoring mistake, after stdout had
    // already listed the calling rule under "FAILED rules", while an unknown rule name on the same code
    // path exited 5. From a `when` condition or a filter predicate the role split, which then admitted
    // `IncompatibleError`, held the error as a clause verdict: exit 19, the rule under "Could not be
    // evaluated", nothing on stderr. Today that arm, reachable only by a `RulesFile` assembled without
    // this parser, raises `InternalError::UncheckedParserInvariant` and exits -1 from every position, while
    // `IncompatibleError` itself is classified by `Error::is_rules_file_mistake` at exit 5. This
    // comment is the one account of that history; `first_call_site_mismatch` and
    // `a_parameterized_call_must_match_the_rule_it_names` point here. `parameter_names` says the same
    // thing about the duplicate-parameter case it rejects: the mistake was one "the parser was holding
    // in its hand".
    //
    // Two things beyond the exit code come with answering it here. A call site nothing evaluates is
    // now checked, where before `rule MAIN { check(1, 2) }` only reported because something evaluated
    // `MAIN`. And the report no longer contradicts itself: the runtime error wrote `Status = FAIL` and
    // the calling rule under "FAILED rules" to stdout, then said on stderr that cfn-guard had broken.
    if let Some(mismatch) = first_call_site_mismatch(&rules_file) {
        return Err(Error::ParseError(call_site_mismatch_message(&mismatch)));
    }

    Ok(Some(rules_file))
}

//
//  ABNF        = "or" / "OR" / "|OR|"
//
fn or_term(input: Span) -> IResult<Span, Span> {
    alt((tag("or"), tag("OR"), tag("|OR|")))(input)
}

fn or_join(input: Span) -> IResult<Span, Span> {
    delimited(
        zero_or_more_ws_or_comment,
        or_term,
        one_or_more_ws_or_comment,
    )(input)
}

impl<'a> TryFrom<&'a str> for AccessQuery<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        let access = access(span)?.1;
        Ok(access)
    }
}

impl<'a> TryFrom<&'a str> for LetExpr<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        let assign = assignment(span)?.1;
        Ok(assign)
    }
}

impl<'a> TryFrom<&'a str> for GuardClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(clause(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for TypeBlock<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(preceded(zero_or_more_ws_or_comment, type_block)(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for Rule<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(rule_block(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for ParameterizedRule<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(parameterized_rule_block(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for ParameterizedNamedRuleClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(parameterized_rule_call_clause(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for FunctionExpr<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(function_expr(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for RuleClause<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        Ok(preceded(zero_or_more_ws_or_comment, rule_block_clause)(span)?.1)
    }
}

impl<'a> TryFrom<&'a str> for RulesFile<'a> {
    type Error = Error;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let span = from_str2(value);
        // `rules_file` answers an empty file, or one that is all whitespace and comments, with `None`,
        // and the commands read that as "nothing to check". This conversion has to produce a
        // `RulesFile`, so for it the same input is an error rather than a `None` to unwrap: the unwrap
        // panicked on `""` and on a comment-only text with `called Option::unwrap() on a None value`.
        match rules_file(span)? {
            Some(rules) => Ok(rules),
            None => Err(Error::ParseError(
                "Rules file has no rules: it is empty, or holds only whitespace and comments"
                    .to_string(),
            )),
        }
    }
}

#[derive(Ord, Eq, PartialEq, PartialOrd, Debug, Clone, Hash)]
pub(crate) struct TypeName {
    pub type_name: String,
}
impl Display for TypeName {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "{}", self.type_name.to_lowercase().replace("::", "_"))
    }
}

#[cfg(test)]
#[path = "parser_tests.rs"]
mod parser_tests;

#[cfg(test)]
#[path = "parser_regression_repros.rs"]
mod parser_regression_repros;
