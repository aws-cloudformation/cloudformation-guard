use crate::rules::{
    errors::Error,
    libyaml::{
        event::{convert_event, Event},
        util::system_mark_to_location,
        util::Owned,
    },
    path_value::Location,
    Result,
};

use std::{borrow::Cow, mem::MaybeUninit, ptr::addr_of_mut};

use unsafe_libyaml as sys;

pub(crate) struct Parser<'input> {
    pin: Owned<ParserPinned<'input>>,
}

struct ParserPinned<'input> {
    sys: sys::yaml_parser_t,
    input: Cow<'input, [u8]>,
}

/// The UTF-8 encoding of U+FEFF, the byte order mark some editors write at the start of a file.
const UTF8_BOM: &[u8] = &[0xEF, 0xBB, 0xBF];

impl<'input> Parser<'input> {
    pub fn new(input: Cow<'input, [u8]>) -> Parser<'input> {
        let input = without_bom(input);
        let owned = Owned::<ParserPinned>::new_uninit();
        let pin = unsafe {
            let parser = addr_of_mut!((*owned.ptr).sys);
            if sys::yaml_parser_initialize(parser).fail {
                panic!(
                    "malloc error: {}",
                    Error::ParseError("error parsing file".to_string())
                );
            }
            sys::yaml_parser_set_encoding(parser, sys::YAML_UTF8_ENCODING);
            sys::yaml_parser_set_input_string(parser, input.as_ptr(), input.len() as u64);
            addr_of_mut!((*owned.ptr).input).write(input);
            Owned::assume_init(owned)
        };
        Parser { pin }
    }

    pub fn next(&mut self) -> Result<(Event<'input>, Location)> {
        let mut event = MaybeUninit::<sys::yaml_event_t>::uninit();
        unsafe {
            let parser = addr_of_mut!((*self.pin.ptr).sys);
            if (&(*parser)).error != sys::YAML_NO_ERROR {
                return Err(parse_failure(&*parser, &(*self.pin.ptr).input));
            }
            let event = event.as_mut_ptr();
            if sys::yaml_parser_parse(parser, event).fail {
                return Err(parse_failure(&*parser, &(*self.pin.ptr).input));
            }
            let ret = convert_event(&*event, &(*self.pin.ptr).input);
            let location = system_mark_to_location((*event).start_mark);

            // The delete has to happen before the conversion result is propagated, or an
            // unconvertible event would leak the libyaml allocation on its way out.
            sys::yaml_event_delete(event);
            Ok((ret?, location))
        }
    }
}

/// The input without a leading byte order mark, which is not part of the document.
///
/// The encoding is preset to UTF-8 before libyaml reads anything, and that skips libyaml's own
/// reader-level handling of the mark. The scanner then met it as the first character of line 1 and
/// counted it as a column, so every position on line 1 came out one column to the right of where
/// the text sits, and a file saved with a mark reported `C:2` for a key the `Code:` excerpt beside
/// it showed at column 1. Dropping the mark here, before the bytes reach libyaml, is what makes a
/// file with the mark report the same positions as the same file without it. The document readers
/// in `rules::values` strip the mark once more before either reader runs, so on those routes this
/// finds nothing to drop; it covers the callers that hand bytes to the parser directly.
///
/// A borrowed input stays borrowed; only an owned input that carries the mark is touched.
fn without_bom(input: Cow<'_, [u8]>) -> Cow<'_, [u8]> {
    match input {
        Cow::Borrowed(bytes) => Cow::Borrowed(bytes.strip_prefix(UTF8_BOM).unwrap_or(bytes)),
        Cow::Owned(mut bytes) => {
            if bytes.starts_with(UTF8_BOM) {
                bytes.drain(..UTF8_BOM.len());
            }
            Cow::Owned(bytes)
        }
    }
}

/// libyaml's failure as a `ParseError` that says what the parser could not read and where.
///
/// libyaml records a failure in the parser's fields: `problem`, its text ("did not find expected ','
/// or ']'"), where it stopped, and, for some failures, `context` with `context_mark`, the construct it
/// was inside when it stopped ("while parsing a flow sequence"). All of it reaches every caller --
/// `validate`, the `test` command and the library entry point behind the FFI and the Lambda -- with
/// the position rendered as the loader renders every other position, so it reads `L:2,C:3` like a
/// refusal's. "error parsing file" alone is the fallback for a failure libyaml records without
/// describing.
///
/// Where the parser stopped is in `problem_mark` for a scanner or parser failure, and nowhere for a
/// reader failure: libyaml's reader decodes the input ahead of the scanner and, on a byte sequence
/// that is not UTF-8 or a character YAML does not allow (a raw control character, say), records the
/// byte offset of the character in `problem_offset` and the character itself in `problem_value`,
/// leaving `problem_mark` at the zero the parser was initialized with. Rendering that mark would place
/// every such failure at `L:1,C:1`, so a reader failure's position is computed from the offset over
/// the input instead, counting the line breaks the way the loader does, and the character is named
/// as `#x1B`.
///
/// # Safety
///
/// `parser` must be a parser `yaml_parser_initialize` succeeded on and that has not been deleted, and
/// `input` the text it was given; the two C strings are read only while it is alive.
unsafe fn parse_failure(parser: &sys::yaml_parser_t, input: &[u8]) -> Error {
    // unsafe-libyaml declares `problem` and `context` as `*const libc::c_char` with its own
    // `libc::c_char`, which is `i8` on every target (its lib.rs: `i8 as c_char`), while
    // `std::ffi::c_char` is `u8` on aarch64, arm, riscv, s390x and powerpc Linux. The parameter is
    // the field's type and the cast is what makes the read build on those targets.
    let text_of = |ptr: *const i8| -> Option<String> {
        if ptr.is_null() {
            return None;
        }
        let text = std::ffi::CStr::from_ptr(ptr.cast())
            .to_string_lossy()
            .into_owned();
        (!text.is_empty()).then_some(text)
    };
    let Some(problem) = text_of(parser.problem) else {
        return Error::ParseError("error parsing file".to_string());
    };
    let mut message = format!("error parsing file: {problem}");
    if parser.error == sys::YAML_READER_ERROR {
        // `problem_value` is -1 when the reader has no character to name, as for a truncated
        // multi-byte sequence at the end of the input.
        if parser.problem_value >= 0 {
            message.push_str(&format!(" (#x{:X})", parser.problem_value));
        }
        message.push_str(&format!(
            " at {}",
            location_of_offset(input, parser.problem_offset as usize)
        ));
        return Error::ParseError(message);
    }
    message.push_str(&format!(
        " at {}",
        system_mark_to_location(parser.problem_mark)
    ));
    if let Some(context) = text_of(parser.context) {
        message.push_str(&format!(
            ", {context} that starts at {}",
            system_mark_to_location(parser.context_mark)
        ));
    }
    Error::ParseError(message)
}

/// The line and column of the character that starts at byte `offset` of `input`, numbered as libyaml
/// numbers its marks: lines from 1, columns from 1 in characters, with CR, LF, CRLF, NEL, LS and PS
/// each ending a line, which is the one definition of a line break the loader and its JSON rewriter
/// share ([`crate::utils::break_width`]). An offset past the end of the input is the position just
/// after its last character.
fn location_of_offset(input: &[u8], offset: usize) -> Location {
    let end = offset.min(input.len());
    let mut location = Location { line: 1, col: 1 };
    let mut at = 0;
    while at < end {
        if let Some(width) = crate::utils::break_width(input, at) {
            location.line += 1;
            location.col = 1;
            at += width;
            continue;
        }
        // One column per character: a UTF-8 continuation byte (10xxxxxx) is not a new one.
        if input[at] & 0xC0 != 0x80 {
            location.col += 1;
        }
        at += 1;
    }
    location
}

impl<'input> Drop for ParserPinned<'input> {
    fn drop(&mut self) {
        unsafe { sys::yaml_parser_delete(&mut self.sys) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    /// The column counts characters, not bytes, and the line is counted from one.
    #[test]
    fn an_offset_is_placed_by_character() {
        // Two lines; the second holds a two-byte character before the offset.
        let input = "ab\n\u{e9}cd".as_bytes();
        let offset_of_d = input.len() - 1;

        assert_eq!(
            Location { line: 2, col: 3 },
            location_of_offset(input, offset_of_d)
        );
    }

    /// A bare CR ends a line, and CRLF is one line ending, not two, as both are for libyaml and
    /// for the excerpt's cursor. The inputs mix the two so that a body counting `\n` alone fails
    /// the first (it places that offset on line 2) and a body counting CR and LF separately fails
    /// the second (it places that offset on line 5).
    #[test]
    fn a_bare_cr_ends_a_line_and_a_crlf_ends_one() {
        assert_eq!(
            Location { line: 3, col: 1 },
            location_of_offset(b"a\rb\nc", 4)
        );
        assert_eq!(
            Location { line: 4, col: 1 },
            location_of_offset(b"a\rb\nc\r\nd", 7)
        );
    }
}
