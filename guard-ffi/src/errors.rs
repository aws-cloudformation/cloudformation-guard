use cfn_guard::Error;
use ffi_support::{ErrorCode, ExternError};
use std::fmt::{Display, Formatter};

/// Anything this boundary reports to a C caller.
///
/// Two kinds, kept apart because they are not the same thing: an error `cfn_guard` produced, and an
/// argument the caller got wrong before `cfn_guard` was reached. `Input` used not to exist -- an
/// unreadable pointer panicked inside the conversion, was caught by the `catch_unwind` in
/// `ffi_support::call_with_result`, and reached the caller as `ErrorCode::PANIC`, which is -1.
pub enum FfiError {
    Guard(Error),
    Input(InvalidInput),
}

/// A `content` or `file_name` pointer that could not be read as a Rust string, and why.
///
/// `whose` and `field` name it -- `data.content`, `rules.file_name` -- because the code alone does
/// not say which of the four pointers was wrong, and a caller with two inputs cannot tell from a
/// bare code which one to look at.
#[derive(Debug, Eq, PartialEq)]
pub struct InvalidInput {
    pub whose: &'static str,
    pub field: &'static str,
    pub cause: InvalidInputCause,
}

#[derive(Debug, Eq, PartialEq)]
pub enum InvalidInputCause {
    Null,
    NotUtf8,
}

impl Display for InvalidInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let InvalidInput {
            whose,
            field,
            cause,
        } = self;

        match cause {
            InvalidInputCause::Null => write!(f, "{whose}.{field} was a null pointer"),
            InvalidInputCause::NotUtf8 => write!(f, "{whose}.{field} did not hold valid UTF-8"),
        }
    }
}

impl Display for FfiError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            FfiError::Guard(error) => write!(f, "{error}"),
            FfiError::Input(input) => write!(f, "{input}"),
        }
    }
}

impl From<Error> for FfiError {
    fn from(e: Error) -> Self {
        FfiError::Guard(e)
    }
}

impl From<InvalidInput> for FfiError {
    fn from(e: InvalidInput) -> Self {
        FfiError::Input(e)
    }
}

fn get_code(e: &FfiError) -> ErrorCode {
    let code = match e {
        FfiError::Guard(e) => match e {
            Error::JsonError(_err) => 1,
            Error::YamlError(_err) => 2,
            Error::FormatError(_fmt) => 3,
            Error::IoError(_io) => 4,
            Error::ParseError(_err) => 5,
            Error::RegexError(_err) => 6,
            Error::MissingProperty(_err) => 7,
            Error::MissingVariable(_err) => 8,
            Error::MultipleValues(_err) => 9,
            Error::IncompatibleRetrievalError(_err) => 10,
            Error::IncompatibleError(_err) => 11,
            Error::NotComparable(_err) => 12,
            Error::ConversionError(_ignore) => 13,
            Error::Errors(_all) => 14,
            Error::RetrievalError(_err) => 15,
            Error::MissingValue(_err) => 16,
            Error::FileNotFoundError(_) => 17,
            Error::IllegalArguments(_) => 18,
            //NOTE: skipping 19 since we already use that for something and dont want to confuse users
            //that use both the regular cli, and the ffi
            Error::XMLError(_) => 20,
            Error::MissingDocument => 21,
            // This answered `unreachable!()`. Nothing routes an `InternalError` here as the code stands,
            // because `validate_and_return_json` maps every conversion failure to `ParseError` before
            // returning, but `Error` and `run_checks` are both public, so the reachability of one
            // variant is not something this table should rest on. A panic here is caught by the
            // `catch_unwind` in `ffi_support::call_with_result` and reported as `ErrorCode::PANIC`, which
            // is -1, so the cost was not an abort: it was the cause being replaced by the panic raised
            // while reporting it.
            Error::InternalError(_) => 22,
            // 25, not 23. The two codes after 22 belong to the invalid-input causes below,
            // and they are named in `cfn_guard.h`, in `lib.rs`'s header comment and in
            // `errors_tests.rs`, so moving them to keep this block contiguous would mean
            // four edits to spare one gap. The gap is here instead.
            Error::UnsupportedDocument(_) => 25,
            // Its own code rather than folded into 11. Both mean the clause could not be evaluated, and
            // the evaluator classifies them together for that reason, but a caller switching on the code
            // is asking what to do about it: operands of kinds that cannot be compared are a rules-file
            // or template problem to correct, while a comparison the engine abandoned is a pattern to
            // simplify or an input to shorten. Reusing 11 would tell such a caller the first when it is
            // the second, and the codes are cheap.
            Error::UndecidableComparison(_) => 26,
        },
        // Deliberately their own codes rather than folded into `IllegalArguments`, which is a guard
        // error about the contents of a rules file: a caller looking at a bad pointer and a caller
        // looking at a bad rule need to be able to tell those apart. And deliberately two codes
        // rather than one, because the two causes were indistinguishable before -- `FfiStr::as_str`
        // panics with "Unexpected null string pointer passed to rust" for invalid UTF-8 as well as
        // for a null pointer, sending the real cause to `log::error!`, which a C caller has no Rust
        // logger to receive.
        FfiError::Input(InvalidInput {
            cause: InvalidInputCause::Null,
            ..
        }) => 23,
        FfiError::Input(InvalidInput {
            cause: InvalidInputCause::NotUtf8,
            ..
        }) => 24,
    };
    ErrorCode::new(code)
}

impl From<FfiError> for ExternError {
    fn from(e: FfiError) -> ExternError {
        ExternError::new_error(get_code(&e), e.to_string())
    }
}

#[cfg(test)]
#[path = "errors_tests.rs"]
mod errors_tests;
