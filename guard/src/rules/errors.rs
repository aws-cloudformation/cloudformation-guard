use std::convert::Infallible;
use std::fmt::Display;
use std::fmt::Formatter;

use nom;
use serde_json;

#[derive(Debug)]
pub struct Error(pub ErrorKind);

impl Error {
    pub fn new(kind: ErrorKind) -> Error {
        Error(kind)
    }
}

fn error_kind_msg(kind: &ErrorKind) -> String {
    match kind {
        ErrorKind::JsonError(err) => {
            format!("Error parsing incoming JSON context {}", err)
        }

        ErrorKind::YamlError(err) => {
            format!("Error parsing incoming YAML context {}", err)
        }

        ErrorKind::FormatError(fmt) => {
            format!("Formatting error when writing {}", fmt)
        }

        ErrorKind::IoError(io) => {
            format!("I/O error when reading {}", io)
        }

        ErrorKind::ParseError(err) => {
            format!("Parser Error when parsing {}", err)
        }

        ErrorKind::RegexError(err) => {
            format!("Regex expression parse error for rules file {}", err)
        }

        ErrorKind::MissingProperty(err) => {
            format!("Could not evaluate clause for a rule with missing property for incoming context {}", err)
        }

        ErrorKind::MissingVariable(err) => {
            format!(
                "Variable assignment could not be resolved in rule file or incoming context {}",
                err
            )
        }

        ErrorKind::MultipleValues(err) => {
            format!(
                "Conflicting rule or variable assignments inside the same scope {}",
                err
            )
        }

        ErrorKind::IncompatibleRetrievalError(err) => {
            format!(
                "Types or variable assignments have incompatible types to retrieve {}",
                err
            )
        }

        ErrorKind::IncompatibleError(err) => {
            format!("Types or variable assignments are incompatible {}", err)
        }

        ErrorKind::NotComparable(err) => {
            format!(
                "Comparing incoming context with literals or dynamic results wasn't possible {}",
                err
            )
        }

        ErrorKind::ConversionError(_ignore) => {
            format!("Could not convert in JSON value object")
        }

        ErrorKind::Errors(all) => {
            let vec = all
                .iter()
                .map(|e| error_kind_msg(e))
                .collect::<Vec<String>>();
            format!("{:?}", &vec)
        }

        ErrorKind::RetrievalError(err) => {
            format!(
                "Could not retrieve data from incoming context. Error = {}",
                err
            )
        }

        ErrorKind::MissingValue(err) => {
            format!(
                "There was no variable or value object to resolve. Error = {}",
                err
            )
        }
    }
}

fn error_kind_fmt(kind: &ErrorKind, f: &mut Formatter<'_>) -> std::fmt::Result {
    writeln!(f, "{}", error_kind_msg(kind))
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        error_kind_fmt(&self.0, f)
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    JsonError(serde_json::Error),
    YamlError(serde_yaml::Error),
    FormatError(std::fmt::Error),
    IoError(std::io::Error),
    ParseError(String),
    RegexError(regex::Error),
    MissingProperty(String),
    MissingValue(String),
    RetrievalError(String),
    MissingVariable(String),
    MultipleValues(String),
    IncompatibleRetrievalError(String),
    IncompatibleError(String),
    NotComparable(String),
    ConversionError(std::convert::Infallible),
    Errors(Vec<ErrorKind>),
}

impl From<std::fmt::Error> for Error {
    fn from(e: std::fmt::Error) -> Self {
        Error::new(ErrorKind::FormatError(e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error(ErrorKind::JsonError(err))
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(err: serde_yaml::Error) -> Self {
        Error(ErrorKind::YamlError(err))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::new(ErrorKind::IoError(err))
    }
}

impl From<regex::Error> for Error {
    fn from(err: regex::Error) -> Self {
        Error(ErrorKind::RegexError(err))
    }
}

impl From<std::convert::Infallible> for Error {
    fn from(err: Infallible) -> Self {
        Error(ErrorKind::ConversionError(err))
    }
}

use crate::rules::parser::{ParserError, Span};

impl<'a> From<nom::Err<(Span<'a>, nom::error::ErrorKind)>> for Error {
    fn from(err: nom::Err<(Span<'a>, nom::error::ErrorKind)>) -> Self {
        let msg = match err {
            nom::Err::Incomplete(_) => format!("More bytes required for parsing"),
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
        Error(ErrorKind::ParseError(msg))
    }
}

impl<'a> From<nom::Err<ParserError<'a>>> for Error {
    fn from(err: nom::Err<ParserError<'a>>) -> Self {
        let msg = match err {
            nom::Err::Failure(e) | nom::Err::Error(e) => format!("Parsing Error {}", e),
            nom::Err::Incomplete(_) => format!("More bytes required for parsing"),
        };
        Error(ErrorKind::ParseError(msg))
    }
}
