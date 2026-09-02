use cfn_guard::Error;
use ffi_support::{ErrorCode, ExternError};

pub struct FfiError(pub Error);

impl From<Error> for FfiError {
    fn from(e: Error) -> Self {
        FfiError(e)
    }
}

fn get_code(e: &Error) -> ErrorCode {
    let code = match &e {
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
    };
    ErrorCode::new(code)
}

impl From<FfiError> for ExternError {
    fn from(e: FfiError) -> ExternError {
        ExternError::new_error(get_code(&e.0), e.0.to_string())
    }
}

#[cfg(test)]
#[path = "errors_tests.rs"]
mod errors_tests;
