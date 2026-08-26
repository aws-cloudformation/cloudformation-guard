use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use std::string::FromUtf8Error;
use thiserror::Error;
use wasm_bindgen::JsValue;

use crate::rules::parser::{ParserError, Span};

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
    #[error("Comparing incoming context with literals or dynamic results wasn't possible `{0}`")]
    NotComparable(String),
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
    /// Distinct from `ParseError` because of what the caller does with each. `ParseError` is also
    /// how libyaml's own failures arrive, and those carry the fixed string "error parsing file",
    /// so `validate::build_data_file` replaces the message with the first hundred bytes of the file
    /// to give the reader something to go on. That substitution is right for a message that says
    /// nothing and wrong for one that names the construct and its position, so the two need to be
    /// tellable apart.
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
    /// Whether this is a name a rules file uses but never declares -- the author's mistake, rather
    /// than a failure of cfn-guard.
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
    /// Deliberately narrow, and `ParseError` is deliberately absent even though a syntax error is
    /// equally the author's mistake: `ParseError` is also how an empty or unparsable *data* file is
    /// reported (`validate::data_file_is_empty`), and that path exits `-1` today with a test pinning
    /// both the code and the message. `parse_tree` classifies its own parse error at the single call
    /// site where a parse error is the only thing that can come back.
    pub(crate) fn is_undeclared_name(&self) -> bool {
        matches!(self, Error::MissingValue(_) | Error::MissingVariable(_))
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
    #[error("{0}")]
    UnsupportedOperationError(String),
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

impl<'a> From<nom::Err<(Span<'a>, nom::error::ErrorKind)>> for Error {
    fn from(err: nom::Err<(Span<'a>, nom::error::ErrorKind)>) -> Self {
        let msg = match err {
            nom::Err::Incomplete(_) => "More bytes required for parsing".to_string(),
            nom::Err::Failure((s, _k)) | nom::Err::Error((s, _k)) => {
                let span = s as Span;
                format!(
                    "Error parsing file {} at line {} at column {}, remaining {}",
                    span.extra,
                    span.location_line(),
                    span.get_utf8_column(),
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
