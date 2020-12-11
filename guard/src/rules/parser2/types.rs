use std::fmt::Formatter;

use nom::error::{ErrorKind, ParseError};
use nom_locate::LocatedSpan;

pub(crate) type Span2<'a> = LocatedSpan<&'a str, &'a str>;

pub(crate) fn from_str2(in_str: &str) -> Span2 {
    Span2::new_extra(in_str, "")
}

#[derive(Clone, PartialEq, Debug)]
pub(crate) struct ParserError<'a> {
    pub(crate) context: String,
    pub(crate) span: Span2<'a>,
    pub(crate) kind: nom::error::ErrorKind,
}

pub(crate) type IResult<'a, I, O> = nom::IResult<I, O, ParserError<'a>>;

