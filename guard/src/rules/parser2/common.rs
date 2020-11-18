use nom::branch::alt;
use nom::bytes::complete::{tag, take_till};
use nom::character::complete::{char, multispace0, multispace1, space0};
use nom::combinator::{map, value};
use nom::error::context;
use nom::multi::{many0, many1};
use nom::sequence::{delimited, preceded, tuple};

use super::*;

impl<'a> ParserError<'a> {
    pub(crate) fn context(&self) -> &str {
        &self.context
    }

    pub(crate) fn span(&self) -> &Span2<'a> {
        &self.span
    }

    pub(crate) fn kind(&self) -> nom::error::ErrorKind {
        self.kind
    }
}

impl<'a> ParseError<Span2<'a>> for ParserError<'a> {
    fn from_error_kind(input: Span2<'a>, kind: ErrorKind) -> Self {
        ParserError {
            context: "".to_string(),
            span: input,
            kind,
        }
    }

    fn append(_input: Span2<'a>, kind: ErrorKind, other: Self) -> Self {
        other
    }

    fn add_context(input: Span2<'a>, ctx: &'static str, other: Self) -> Self {
        let context = if other.context.is_empty() {
            format!("{}", ctx)
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

impl<'a> std::fmt::Display for ParserError<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let message = format!(
            "Error parsing file {} at line {} at column {}, when handling {}",
            self.span.extra, self.span.location_line(), self.span.get_utf8_column(),
            self.context);
        f.write_str(&message);
        Ok(())
    }
}



pub(super) fn comment2(input: Span2) -> IResult<Span2, Span2> {
    delimited(char('#'), take_till(|c| c == '\n'), char('\n'))(input)
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
pub(super) fn white_space_or_comment(input: Span2) -> IResult<Span2, ()> {
    context("comment_whitespace",
            value((), alt((
                multispace1,
                comment2
            ))))(input)
}

//
// This provides extract for 1*(LWSP / commment). It does not indicate
// failure when this isn't the case. Consumers of this combinator must use
// cut or handle it as a failure if that is the right outcome
//
pub(super) fn one_or_more_ws_or_comment(input: Span2) -> IResult<Span2, ()> {
    context("one_or_more",
            value((), many1(white_space_or_comment)))(input)
}

//
// This provides extract for *(LWSP / comment), same as above but this one never
// errors out
//
pub(super) fn zero_or_more_ws_or_comment(input: Span2) -> IResult<Span2, ()> {
    context("zero_or_more",
            value((), many0(white_space_or_comment)))(input)
}

pub(super) fn white_space(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    move |input: Span2| preceded(multispace0, char(ch))(input)
}


pub(super) fn followed_by(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    white_space(ch)
}

pub(super) fn white_space_only(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    move |input: Span2| preceded(space0, char(ch))(input)
}

pub(super) fn white_space_tag(t: &str) -> impl Fn(Span2) -> IResult<Span2, &str> {
    let copy = String::from(t);
    move |input: Span2| {
        map(preceded(multispace0, tag(copy.as_str())), |s: Span2| {
            *s.fragment()
        })(input)
    }
}

pub(super) fn white_space_only_tag(tag_: &str) -> impl Fn(Span2) -> IResult<Span2, Span2> {
    let copy = String::from(tag_);
    move |input: Span2| preceded(space0, tag(copy.as_str()))(input)
}

pub(super) fn preceded_by(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    white_space(ch)
}

pub(super) fn preceded_by_space_only(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    white_space_only(ch)
}

pub(super) fn followed_by_space_only(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    white_space(ch)
}

pub(super) fn separated_by(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    white_space(ch)
}

pub(super) fn separated_by_space_only(ch: char) -> impl Fn(Span2) -> IResult<Span2, char> {
    white_space_only(ch)
}

pub(super) fn preceded_by_tag(tag: &str) -> impl Fn(Span2) -> IResult<Span2, &str> {
    white_space_tag(tag)
}

pub(super) fn followed_by_tag(tag: &str) -> impl Fn(Span2) -> IResult<Span2, &str> {
    white_space_tag(tag)
}

pub(super) fn separated_by_tag(tag: &str) -> impl Fn(Span2) -> IResult<Span2, &str> {
    white_space_tag(tag)
}

