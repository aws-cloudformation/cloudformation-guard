use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::string::FromUtf8Error;
use thiserror::Error;
use wasm_bindgen::JsValue;

use crate::rules::parser::{ParserError, Span};
use crate::rules::QueryResult;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    #[error("Error parsing incoming JSON context {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Error parsing incoming YAML context {0}")]
    YamlError(#[from] serde_yaml::Error),
    #[error("Formatting error when writing {0}")]
    FormatError(#[from] std::fmt::Error),
    #[error("I/O error when reading {0}")]
    IoError(#[from] std::io::Error),
    #[error("Parser Error when parsing `{0}`")]
    ParseError(String),
    #[error("Regex expression parse error for rules file {0}")]
    RegexError(#[from] Box<fancy_regex::Error>),
    #[error(
        "Could not evaluate clause for a rule with missing property for incoming context `{0}`"
    )]
    MissingProperty(String),
    #[error("There was no variable or value object to resolve. Error = `{0}`")]
    MissingValue(String),
    #[error("Could not retrieve data from incoming context. Error = `{0}`")]
    RetrievalError(String),
    #[error("Variable assignment could not be resolved in rule file or incoming context `{0}`")]
    MissingVariable(String),
    #[error("Conflicting rule or variable assignments inside the same scope `{0}`")]
    MultipleValues(String),
    #[error("Types or variable assignments have incompatible types to retrieve `{0}`")]
    IncompatibleRetrievalError(String),
    #[error("Types or variable assignments are incompatible `{0}`")]
    IncompatibleError(String),
    /// A comparison that had no answer, as opposed to operands that could not be compared.
    ///
    /// Classified with `Unevaluatable` by `is_unevaluatable`: a clause verdict, failed closed as an
    /// assertion, carried as a gate, held in an `or` for a sibling that can decide. It is kept apart
    /// from `Unevaluatable` for its message alone, and apart from `IncompatibleError`, which
    /// `is_unevaluatable` does not admit and which `is_rules_file_mistake` classifies as the rules
    /// file's at exit 5; what that variant also adds is the claim "Types or variable assignments are
    /// incompatible", and that is false of a comparison the engine abandoned part way: `fancy_regex`
    /// exhausting its backtracking budget refuses a `String` against a `Regex`, a pair `compare_eq` has
    /// an arm for and did run.
    /// Raised there, it would put the false claim inside both frames that print the reason -- a rule frame
    /// reading "not applicable: Types or variable assignments are incompatible `The regular expression
    /// could not be evaluated ...`", and a filter frame wrapping the same sentence in "due to retrieval
    /// error ... when handling clause, bailing".
    ///
    /// Renders as the reason alone, with no framing of its own, because each of those two sites already
    /// supplies its own and a second one reads as two errors stacked.
    #[error("{0}")]
    UndecidableComparison(String),
    #[error("Comparing incoming context with literals or dynamic results wasn't possible `{0}`")]
    NotComparable(String),
    /// A clause that has no answer on this data. Raised at these sites, each through
    /// `Error::unanswerable` or `Error::unanswerable_from` unless said otherwise, and only for a value
    /// the template supplied: `EMPTY` against a type that cannot be empty (`eval::element_empty_operation`,
    /// one site); a `%var` used as a key whose values are not strings (two arms of
    /// `eval_context::query_retrieval_with_converter`, one for a single value and one for a list of
    /// keys); a filter after a key or after `this` that holds a non-null scalar, which has no entries to
    /// select among, with or without a capture (the scalar arm of `eval_context::apply_filter_noting`,
    /// one site); a filter over one map, named by `this` or by a key, that selected nothing while its
    /// predicate names a key of the map itself, which is a question about the map the filter never asked
    /// (`eval_context::filter_over_a_member_map_refusal`, two sites: returned by `filter_over_a_named_map`
    /// once `apply_filter_noting` reports that the filter kept no entry, reached from the `this` arm,
    /// the key and variable arm, and `continue_from_key_selection` of
    /// `query_retrieval_with_converter`; and by the reader-slot arm of `query_retrieval_with_converter`,
    /// for `%m[ f ]` over a map whose entries are all non-null scalars when the predicate names a key
    /// the map itself holds); a filter over one map, named by `this` or by a key, whose predicate names
    /// no key of the map and which passed a non-null scalar entry over under a predicate that holds on
    /// the map read as one object, and kept nothing or kept a map-valued entry in the map's place, or
    /// which handed its scalars to the predicate for a `this` clause and kept one by an absence clause
    /// alone (`eval_context::filter_passing_over_scalars_refusal`, three sites, all in
    /// `filter_over_a_named_map` after the own-key reading above: the none-kept branch, the kept-member
    /// branch and the scalar-kept-by-absence branch, reached from the same three arms as the own-key
    /// refusal); a filter after the author's `[*]` over a map that mixes
    /// map-valued entries with a scalar while the predicate names a key those entries hold, and a filter
    /// after `[*]` or `.*` over a map whose own key the predicate names while none of its map-valued
    /// entries holds it (`eval_context::refuse_a_filter_over_a_one_object_shaped_map`, one site, reached
    /// from the `AllIndices` arm of `query_retrieval_with_converter` and, for the own-key case, from the
    /// `AllValues` arm through `refuse_a_filter_after_the_dot_wildcard`); a filter after `.*` over a map
    /// whose entries are all non-null scalars (`eval_context::refuse_a_filter_after_the_dot_wildcard`,
    /// one site, the `AllValues` arm); a filter after the author's `[*]` that read a map as one object,
    /// compares against keys the object does not hold, kept nothing, and is followed by a query part
    /// (`eval_context::refuse_a_filter_over_one_object_lacking_the_predicates_keys`, one site, the
    /// `AllIndices` arm; inside a filter predicate's query all three wildcard sites leave the undecidable
    /// result for the map under test instead, on which the enclosing clause fails closed); the same
    /// refusal for a read of that filter's empty selection made later (`eval_context::LacksKeysNote::
    /// refuse_read`, one site, reached from the variable arm of `query_retrieval_with_converter` for a
    /// binding read or a parameterized rule's parameter, and from `read_from_the_empty_selection` for a
    /// clause of a block body run over the empty selection, which the block clause in `eval` records as
    /// the body's refusal when a gate hands it up; inside a filter predicate's query it leaves the
    /// undecidable marker for the object instead); a
    /// capture declared after `this` over a map with entries, or after an index, an earlier filter or a
    /// map-key filter over any value that is not a list (`eval_context::capture_not_bound_here`, one
    /// call site, inside `refuse_unbound_capture`, which the `this` arm of `apply_filter_noting` and
    /// `filter_tests_one_value` both reach, because a list at any of those positions binds the capture
    /// and the template decides which value sits there; the same capture over a scalar after `this` is
    /// refused with the filter by the scalar arm above, which announces it through the same
    /// `announce_unbound_capture`; inside a filter predicate's query `refuse_unbound_capture` leaves an
    /// undecidable result for the entry under test instead); a function argument that is not what the
    /// function needs (`eval_context::exactly_one`, the refusal every function shares for an argument
    /// that resolved to none or several values, plus two sites each in `RegexReplaceFunction::call` and
    /// `substring_bounds` and one in `JoinFunction::call`); `parse_float`,
    /// `parse_int`, `parse_bool` and `parse_char` on a value they cannot convert (`functions::converters`,
    /// ten sites: a string, a character or a non-finite float into a float or an integer, a float that
    /// does not fit an integer, a string into a boolean, an integer out of 0-9 or an unrepresentable
    /// digit into a character, a string longer than one character into a character); `parse_epoch` on a
    /// string that is not a date (`functions::date_time`, one site); and in `functions::strings`,
    /// `json_parse` on a string that is not a document and on a document whose keys it cannot read (two
    /// sites), `regex_replace` on a pattern that does not compile, classified on the pattern's
    /// provenance, and on a match that spends the backtracking budget, classified on the input's (two
    /// sites), and `join` over a value that is not a string (one site; `join` over an unresolved path
    /// raises `Unevaluatable` directly). `eval::is_unevaluatable` matches this variant and
    /// `UndecidableComparison`, the variant for a comparison the regex engine abandoned part
    /// way, and nothing else. A refusal, the evaluator's own sentence about a read it would not make,
    /// is this variant too, with nothing on the error to say so: the shape of this public enum is kept
    /// as it is, and the kind travels out of band, as the exact texts the refusal producers registered
    /// through `eval_context::refuse` for the evaluation under way, which `eval_context::is_refusal` reads
    /// where an error is written into a record, so the reporters can print a refusal whole where they
    /// cut a sentence that may carry a value.
    ///
    /// Classified where it is raised, so that the evaluator can match the variant: an unevaluatable
    /// clause is a verdict about that clause (an assertion fails closed, a gate fails its rule closed,
    /// and in an `or` a sibling that can decide does), where every other error is a failure of the
    /// machinery or a mistake in the rules file and stops the run. The message names the operation
    /// and the path, which is what the reporters print.
    ///
    /// Raised only for a value the template supplied. The same operation on a value written in the
    /// rules file (`let b = true` with `!EMPTY`, `parse_int("abc")`, `let sizes = [1, 2]` used as a
    /// key) is a mistake in the rules file and is `IncompatibleError`; `Error::unanswerable` makes
    /// that choice from the input's provenance so every raise site answers it the same way.
    #[error("Clause could not be evaluated against the incoming context `{0}`")]
    Unevaluatable(String),
    #[error("Could not convert in JSON value object {0}")]
    ConversionError(#[from] Infallible),
    #[error("The path `{0}` does not exist")]
    FileNotFoundError(String),
    /// The YAML stream parsed cleanly but held no document -- a file of nothing but comments, for
    /// one. Distinct from `ParseError` so that the caller, which is the only place that knows the
    /// file's name, can report it the same way it reports a file with no bytes in it.
    #[error("no YAML document was found in the data")]
    MissingDocument,
    /// A document the loader read successfully and refuses to model, because it uses a construct
    /// cfn-guard has no representation for.
    ///
    /// Distinct from `ParseError` because the two mean different things to a caller. `ParseError` is
    /// libyaml's own failure, malformed text, saying what the parser expected and where it stopped;
    /// `validate::build_data_file` reports it under the file's name, and adds the file's first
    /// hundred bytes only when the message is the bare "error parsing file", the fallback for a
    /// failure libyaml records without describing. This variant is a document that parses and holds
    /// a construct the loader will not model, reported under the file's name with no excerpt, and
    /// the library's callers see the two as different codes. For the same reason it is also how
    /// `values::read_from` reports valid JSON that libyaml refuses, naming the limit hit: the text
    /// parses as JSON, and what it holds is a construct cfn-guard will not model. Text that is not
    /// JSON either is a `ParseError`.
    #[error("{0}")]
    UnsupportedDocument(String),
    #[error(transparent)]
    Errors(#[from] Errors),
    #[error("{0}")]
    IllegalArguments(String),
    #[error("Error occurred while attempting to write junit report")]
    XMLError(#[from] quick_xml::Error),
    #[error("{0}")]
    InternalError(#[from] InternalError),
}

impl Error {
    /// Whether this is a mistake in the rules file -- a name it uses but never declares, or an
    /// operation it writes against a value it also writes -- rather than a failure of cfn-guard.
    ///
    /// It exists to pick an exit code. `ERROR_STATUS_CODE` (5) is what this repository assigns to "the
    /// ruleset is broken", and `-1` -- which the table at `guard/tests/utils.rs` names
    /// `INTERNAL_FAILURE` -- is what it assigns to the tool itself breaking. Returning `Err` out of a
    /// command reaches `main`'s catch-all and therefore reports the second, which tells an author
    /// their file is fine and cfn-guard is not.
    ///
    /// Both variants are produced only where a name has no declaration behind it. `MissingValue`
    /// covers a variable with no `let` (`rules/eval_context.rs`, "the end of the chain, and the only
    /// place the unresolved-variable error is produced"), a rule that does not exist, and a
    /// parameterized rule that does not exist. `MissingVariable` is the same condition on the older
    /// evaluation path in `rules/evaluate.rs`.
    ///
    /// `IncompatibleError` is the rules-file half of `Error::unanswerable`: an operation on a value the
    /// rules file wrote, which can never succeed whatever the template holds (`let numeric = 5` with
    /// `%numeric empty`, `parse_int("abc")`, `json_parse("{bad")`, a `let` of integers used as a key),
    /// and a query shape interpolation does not support (`Resources.%names.*`). Every raise site of the
    /// variant is a fact about the rules file. The two invariants the parser keeps and the evaluator
    /// still checks, a parameterized call's arity and a binary clause's right-hand side, are reachable
    /// only from a `RulesFile` assembled without the parser, and are `InternalError`
    /// (`UncheckedParserInvariant`, one variant for both): a fault of cfn-guard's own, not a mistake in
    /// the file, so they exit as an internal failure rather than as "your ruleset is broken". The
    /// template's
    /// half, `Unevaluatable`, is a verdict the evaluator reaches, never an error a command classifies.
    ///
    /// Deliberately narrow, and `ParseError` is deliberately absent even though a syntax error is
    /// equally the author's mistake: `ParseError` is also how an empty or unparsable *data* file is
    /// reported (`validate::data_file_is_empty`), and that path exits `-1` today with a test pinning
    /// both the code and the message. `parse_tree` classifies its own parse error at the single call
    /// site where a parse error is the only thing that can come back.
    pub(crate) fn is_rules_file_mistake(&self) -> bool {
        matches!(
            self,
            Error::MissingValue(_) | Error::MissingVariable(_) | Error::IncompatibleError(_)
        )
    }

    /// The same error again: every variant rebuilt with its own payload, so the error a file-level
    /// assignment raised the first time it was forced is the error every later read of the name raises,
    /// variant and text alike (`Scope::failed_assignments`). The payloads that are not `Clone` are
    /// rebuilt from what they print: a JSON or YAML error as a custom error with the same message, an
    /// I/O error with its kind and message.
    pub(crate) fn repeated(&self) -> Error {
        match self {
            Error::JsonError(e) => {
                Error::JsonError(<serde_json::Error as serde::de::Error>::custom(e))
            }
            Error::YamlError(e) => {
                Error::YamlError(<serde_yaml::Error as serde::de::Error>::custom(e))
            }
            Error::FormatError(_) => Error::FormatError(std::fmt::Error),
            Error::IoError(e) => Error::IoError(std::io::Error::new(e.kind(), e.to_string())),
            Error::ParseError(s) => Error::ParseError(s.clone()),
            Error::RegexError(e) => Error::RegexError(e.clone()),
            Error::MissingProperty(s) => Error::MissingProperty(s.clone()),
            Error::MissingValue(s) => Error::MissingValue(s.clone()),
            Error::RetrievalError(s) => Error::RetrievalError(s.clone()),
            Error::MissingVariable(s) => Error::MissingVariable(s.clone()),
            Error::MultipleValues(s) => Error::MultipleValues(s.clone()),
            Error::IncompatibleRetrievalError(s) => Error::IncompatibleRetrievalError(s.clone()),
            Error::IncompatibleError(s) => Error::IncompatibleError(s.clone()),
            Error::UndecidableComparison(s) => Error::UndecidableComparison(s.clone()),
            Error::NotComparable(s) => Error::NotComparable(s.clone()),
            Error::Unevaluatable(s) => Error::Unevaluatable(s.clone()),
            Error::ConversionError(never) => match *never {},
            Error::FileNotFoundError(s) => Error::FileNotFoundError(s.clone()),
            Error::MissingDocument => Error::MissingDocument,
            Error::UnsupportedDocument(s) => Error::UnsupportedDocument(s.clone()),
            Error::Errors(errors) => {
                Error::Errors(Errors(errors.0.iter().map(Error::repeated).collect()))
            }
            Error::IllegalArguments(s) => Error::IllegalArguments(s.clone()),
            Error::XMLError(e) => Error::XMLError(e.clone()),
            Error::InternalError(e) => Error::InternalError(e.repeated()),
        }
    }

    /// The error for an operation the given input cannot support, classified by where the input came
    /// from.
    ///
    /// A `QueryResult::Literal` was written in the rules file, so the operation can never succeed on
    /// it and the mistake is the author's: `IncompatibleError`, which stops the run. A `Resolved` value
    /// came from the template, so the clause has no answer on this data and only on this data:
    /// `Unevaluatable`, which the evaluator fails closed and which a sibling in an `or` may decide. An
    /// `UnResolved` input is a path the template did not have, a fact about the data as well.
    ///
    /// Provenance travels, per value and per function call, not per character. A literal stays a
    /// literal through a `let` (`let b = true`), through a parameterized call's argument (`p(true)`
    /// binds `%n` to a literal inside `p`), and through a function: `resolve_function` wraps a result
    /// as a literal if and only if every input it read was one. The limit of that rule is a function
    /// with one template input among literals: its whole result is a template value, so
    /// `parse_int(%s)` after `let s = regex_replace("ABC", Resources.Vol.Type, "")` is held even though
    /// the characters it cannot convert came from the literal. So `parse_int(%s)` after
    /// `let s = to_lower("ABC")` is still the author's mistake, while the
    /// same chain over `to_lower(Resources.X.Type)` is resolved data all the way down.
    pub(crate) fn unanswerable(input: &QueryResult, message: String) -> Error {
        Error::unanswerable_from(matches!(input, QueryResult::Literal(_)), message)
    }

    /// `unanswerable` for a site that has already consumed the `QueryResult` and kept only whether it
    /// was a literal.
    pub(crate) fn unanswerable_from(from_rules_file: bool, message: String) -> Error {
        match from_rules_file {
            true => Error::IncompatibleError(message),
            false => Error::Unevaluatable(message),
        }
    }
}

#[derive(Debug, Error)]
pub enum InternalError {
    #[error("non string type detected for key in a map at {0}, cfn-guard only supports keys that are string types")]
    InvalidKeyType(String),
    #[error("internal error {0}")]
    UnresolvedKeyForReporter(String),
    #[error("{0}")]
    FromUtf8Error(#[from] FromUtf8Error),
    #[error("{0}")]
    IncompatibleWriterError(String),
    #[error("{0}")]
    UnsupportedBufferError(String),
    /// A writer accessor asked to read back a buffer that is a process stream (stdout or stderr),
    /// which cannot be read back: `err_to_stripped`, `into_string` and `into_stripped_parts` in
    /// `utils::writer` have always refused a stream with this variant, naming the method and the
    /// buffer. Nothing in the evaluator raises it.
    #[error("{0}")]
    UnsupportedOperationError(String),
    /// The recorder was asked to end a record whose context does not match the one last started, or
    /// one that was never started. Always a defect in the evaluator's own bookkeeping, never a fact
    /// about the data or the rules file, so it stops the run as an `InternalError`, which no command
    /// classifies: raised as `IncompatibleError` it would be classified by `is_rules_file_mistake` and
    /// exit 5, blaming the rules file for a fault in the tool.
    #[error("internal error {0}")]
    EventRecordMismatch(String),
    /// An invariant the parser keeps reached evaluation unchecked: a parameterized-rule call whose
    /// argument count does not match the rule's parameter list, or a binary clause with no right-hand
    /// side.
    ///
    /// The parser compares every call site against the definition it names and refuses the file at
    /// exit 5, and never produces a clause whose comparator takes a right-hand side without one, so no
    /// rules file it accepted can reach either check; only a `RulesFile` assembled without the parser
    /// can. That makes each a broken invariant of cfn-guard's own, not a statement about the file, and
    /// an `InternalError` for the same reason `EventRecordMismatch` is: raised as `IncompatibleError`
    /// it would be classified by `is_rules_file_mistake` and exit 5, blaming the rules file for a fault
    /// in the tool. One variant for every such invariant, because the variant carries the
    /// classification and nothing else: whichever invariant broke, the answer is the same internal
    /// failure. The message says which one fired, naming the rule and both counts or naming the
    /// clause, and a test that cares which case it reached reads the message. Pinned by
    /// `an_unchecked_call_site_arity_mismatch_is_an_internal_error` and
    /// `a_binary_clause_with_no_right_hand_side_is_an_internal_error`, each on the variant and its
    /// message.
    #[error("{0}")]
    UncheckedParserInvariant(String),
}

impl InternalError {
    /// The same error again, for `Error::repeated`.
    pub(crate) fn repeated(&self) -> InternalError {
        match self {
            InternalError::InvalidKeyType(s) => InternalError::InvalidKeyType(s.clone()),
            InternalError::UnresolvedKeyForReporter(s) => {
                InternalError::UnresolvedKeyForReporter(s.clone())
            }
            InternalError::FromUtf8Error(e) => InternalError::FromUtf8Error(e.clone()),
            InternalError::IncompatibleWriterError(s) => {
                InternalError::IncompatibleWriterError(s.clone())
            }
            InternalError::UnsupportedBufferError(s) => {
                InternalError::UnsupportedBufferError(s.clone())
            }
            InternalError::UnsupportedOperationError(s) => {
                InternalError::UnsupportedOperationError(s.clone())
            }
            InternalError::EventRecordMismatch(s) => InternalError::EventRecordMismatch(s.clone()),
            InternalError::UncheckedParserInvariant(s) => {
                InternalError::UncheckedParserInvariant(s.clone())
            }
        }
    }
}

#[derive(Debug, Error)]
pub struct Errors(pub Vec<Error>);

impl std::fmt::Display for Errors {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let vec = self
            .0
            .iter()
            .map(|e| format!("{e:#?}"))
            .collect::<Vec<String>>();

        let formatted = format!("{:?}", &vec);
        write!(f, "{}", formatted)
    }
}

/// For `nom`'s own error type, which nothing in this crate produces.
///
/// The parser's `IResult` carries `ParserError`, so the impl below is the one every `?` in the grammar
/// reaches; this one has no producer anywhere in the tree. It is not flagged as dead, because an impl of
/// a foreign trait never is, and it cannot be reached from outside either, since `Span` is `pub(crate)`.
///
/// It counts positions through `position_of` regardless. It is the eleventh site of the bare-CR position
/// defect and the only one that was unreachable, and an unreachable copy of a defect is how the defect
/// comes back: whoever makes this reachable will not be thinking about line endings.
impl<'a> From<nom::Err<(Span<'a>, nom::error::ErrorKind)>> for Error {
    fn from(err: nom::Err<(Span<'a>, nom::error::ErrorKind)>) -> Self {
        let msg = match err {
            nom::Err::Incomplete(_) => "More bytes required for parsing".to_string(),
            nom::Err::Failure((s, _k)) | nom::Err::Error((s, _k)) => {
                let span = s as Span;
                let (line, column) = crate::rules::parser::position_of(&span);
                format!(
                    "Error parsing file {} at line {} at column {}, remaining {}",
                    span.extra,
                    line,
                    column,
                    *span.fragment()
                )
            }
        };
        Error::ParseError(msg)
    }
}

impl<'a> From<nom::Err<ParserError<'a>>> for Error {
    fn from(err: nom::Err<ParserError<'a>>) -> Self {
        let msg = match err {
            nom::Err::Failure(e) | nom::Err::Error(e) => format!("Parsing Error {e}"),
            nom::Err::Incomplete(_) => "More bytes required for parsing".to_string(),
        };
        Error::ParseError(msg)
    }
}

impl From<JsValue> for Error {
    fn from(err: JsValue) -> Self {
        err.into()
    }
}
