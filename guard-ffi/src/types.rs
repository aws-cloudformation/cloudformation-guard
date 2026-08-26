use crate::errors::{InvalidInput, InvalidInputCause};
use cfn_guard::ValidateInput;
use ffi_support::FfiStr;

#[repr(C)]
pub struct FfiValidateInput<'a> {
    pub data: FfiStr<'a>,
    pub file_name: FfiStr<'a>,
}

impl<'a> FfiValidateInput<'a> {
    /// The two pointers as Rust strings, or which one could not be read and why.
    ///
    /// This was `impl From<FfiValidateInput<'a>> for ValidateInput<'a>`, built on
    /// `impl From<FfiStr<'a>> for &'a str`, which is `FfiStr::as_str` -- and that is
    /// `as_opt_str().expect("Unexpected null string pointer passed to rust")`. So a null pointer
    /// panicked, and so did invalid UTF-8, with the *null* message: `as_opt_str` sends the real
    /// cause to `log::error!` and answers `None`, and a C caller has no Rust logger installed to
    /// receive it.
    ///
    /// The panic was caught by the `catch_unwind` inside `ffi_support::call_with_result`, so nothing
    /// unwound across the boundary, but what the caller observed was `ErrorCode::PANIC` -- which is
    /// -1, a value the header does not mention and `get_code` never produces -- reached by an
    /// ordinary caller mistake rather than by an internal fault. Measured across the boundary
    /// against the built dylib: all four null pointers and a non-UTF-8 `content` gave code -1 with
    /// "Unexpected null string pointer passed to rust", and each printed a Rust panic to stderr.
    ///
    /// `whose` is `"data"` or `"rules"`, so the reported field reads `data.content`.
    pub fn read(self, whose: &'static str) -> Result<ValidateInput<'a>, InvalidInput> {
        let FfiValidateInput { data, file_name } = self;

        Ok(ValidateInput {
            content: read_str(data, whose, "content")?,
            file_name: read_str(file_name, whose, "file_name")?,
        })
    }
}

/// One pointer as a `&str`, or why it could not be read.
///
/// `as_opt_str` borrows and answers `None` for a null pointer and for invalid UTF-8 alike;
/// `into_opt_string` consumes and answers `None` only for a null pointer, because it replaces
/// invalid UTF-8 with the replacement character instead. Asking both distinguishes the two causes
/// without dereferencing the pointer here, which is the whole reason `FfiStr` is in the signature.
fn read_str<'a>(
    value: FfiStr<'a>,
    whose: &'static str,
    field: &'static str,
) -> Result<&'a str, InvalidInput> {
    if let Some(readable) = value.as_opt_str() {
        return Ok(readable);
    }

    Err(InvalidInput {
        whose,
        field,
        cause: match value.into_opt_string() {
            None => InvalidInputCause::Null,
            Some(..) => InvalidInputCause::NotUtf8,
        },
    })
}

#[cfg(test)]
#[path = "types_tests.rs"]
mod types_tests;
