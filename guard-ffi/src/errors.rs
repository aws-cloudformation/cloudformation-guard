use ffi_support::{ExternError, ErrorCode};
use cfn_guard::{Error, ErrorKind};

pub struct FfiError(pub Error);

impl From<Error> for FfiError {
    fn from(e : Error) -> Self {
        FfiError(e)
    }
}

fn get_code(e : &Error) -> ErrorCode {
    let code = match &e.0 {
        ErrorKind::JsonError(_err) => 1,
        ErrorKind::YamlError(_err) => 2,
        ErrorKind::FormatError(_fmt) => 3,
        ErrorKind::IoError(_io) => 4,
        ErrorKind::ParseError(_err) => 5,
        ErrorKind::RegexError(_err) => 6,
        ErrorKind::MissingProperty(_err) => 7,
        ErrorKind::MissingVariable(_err) => 8,
        ErrorKind::MultipleValues(_err) => 9,
        ErrorKind::IncompatibleRetrievalError(_err) => 10,
        ErrorKind::IncompatibleError(_err) => 11,
        ErrorKind::NotComparable(_err) => 12,
        ErrorKind::ConversionError(_ignore) => 13,
        ErrorKind::Errors(_all) => 14,
        ErrorKind::RetrievalError(_err) => 15,
        ErrorKind::MissingValue(_err) => 16,
        ErrorKind::FileNotFoundError(_) => 17,
    };
    ErrorCode::new(code)
}

impl From<FfiError> for ExternError {
    fn from(e: FfiError) -> ExternError {
        ExternError::new_error(get_code(&e.0), e.0.to_string())
    }
}
