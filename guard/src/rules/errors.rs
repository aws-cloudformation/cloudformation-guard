use std::convert::Infallible;
use std::fmt::{Debug, Formatter};
use thiserror::Error;

use crate::rules::parser::{ParserError, Span};

#[derive(Debug, Error)]
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
    RegexError(#[from] fancy_regex::Error),
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
    #[error(transparent)]
    Errors(#[from] Errors),
    #[error("{0}")]
    IllegalArguments(String),
}

#[derive(Debug, Error)]
pub struct Errors(pub Vec<Error>);

impl std::fmt::Display for Errors {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        let vec = self
            .0
            .iter()
            .map(|e| format!("{e:#?}"))
            .collect::<Vec<String>>();

        format!("{:?}", &vec);

        Ok(())
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
