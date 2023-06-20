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
        Error::InternalError(_) => unreachable!(),
    };
    ErrorCode::new(code)
}

impl From<FfiError> for ExternError {
    fn from(e: FfiError) -> ExternError {
        ExternError::new_error(get_code(&e.0), e.0.to_string())
    }
}
