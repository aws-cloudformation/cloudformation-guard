use serde_json;
use nom;

use crate::rules::parser::Span;
use std::convert::Infallible;
use std::fmt::Formatter;
use std::fmt::Display;

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
        },

        ErrorKind::IoError(io) => {
            format!("I/O error when reading {}", io)
        },

        ErrorKind::ParseError(err) => {
            format!("Parser Error when parsing rules file {}", err)
        },

        ErrorKind::RegexError(err) => {
            format!("Regex expression parse error for rules file {}", err)
        },

        ErrorKind::MissingProperty(err) => {
            format!("Could not evaluate clause for a rule with missing property for incoming context {}", err)
        },

        ErrorKind::MissingVariable(err) => {
            format!("Variable assignment could not be resolved in rule file or incoming context {}", err)
        },

        ErrorKind::MultipleValues(err) => {
            format!("Conflicting rule or variable assignments inside the same scope {}", err)
        },

        ErrorKind::IncompatibleError(err) => {
            format!("Types or variable assignments do not match {}", err)
        },

        ErrorKind::NotComparable(err) => {
            format!("Comparing incoming context with literals or dynamic results wasn't possible {}", err)
        },

        ErrorKind::ConversionError(_ignore) => {
            format!("Could not convert in JSON value object")
        },

        ErrorKind::Errors(all) => {
            let vec = all.iter().map(|e| error_kind_msg(e) ).collect::<Vec<String>>();
            format!("{:?}", &vec)
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
    IoError(std::io::Error),
    ParseError(String),
    RegexError(regex::Error),
    MissingProperty(String),
    MissingVariable(String),
    MultipleValues(String),
    IncompatibleError(String),
    NotComparable(String),
    ConversionError(std::convert::Infallible),
    Errors(Vec<ErrorKind>)
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error(ErrorKind::JsonError(err))
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

impl <'a> From<nom::Err<(Span<'a>, nom::error::ErrorKind)>> for Error {
    fn from(err: nom::Err<(Span<'a>, nom::error::ErrorKind)>) -> Self {
        let msg = match err {
            nom::Err::Incomplete(_) => format!("More bytes required for parsing"),
            nom::Err::Failure((s, _k)) | nom::Err::Error((s, _k)) => {
                let span = s as Span;
                format!("Error parsing file {} at line {} at column {}, remaining {}",
                        span.extra, span.location_line(), span.get_utf8_column(), *span.fragment())
            }
        };
        Error(ErrorKind::ParseError(msg))
    }
}
