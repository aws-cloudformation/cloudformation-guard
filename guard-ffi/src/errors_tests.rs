use cfn_guard::{run_checks, Error, InternalError, ValidateInput};
use ffi_support::ExternError;

use super::*;

/// Reads back the message an `ExternError` carries. The pointer is owned by a `CString` the
/// `ExternError` leaked for the C caller to free, so it outlives this borrow; a test leaking it is
/// the whole cost of not calling the destructor here.
fn message_of(error: &ExternError) -> String {
    unsafe {
        std::ffi::CStr::from_ptr(error.get_raw_message())
            .to_string_lossy()
            .into_owned()
    }
}

/// `get_code` answered `Error::InternalError` with `unreachable!()`, in a table every error crossing
/// the FFI boundary is fed through. The conversion runs inside the `catch_unwind` in
/// `ffi_support::call_with_result`, so the abort was contained rather than fatal, but what a C caller
/// then observed was a null return and `ErrorCode::PANIC`, which is -1, carrying "internal error:
/// entered unreachable code". The cause was replaced by the panic that reporting it caused, so the
/// message naming the offending key was lost.
///
/// `catch_unwind` here is deliberate, for the same reason as in the libyaml loader tests: a test
/// that only asserted on the returned code would not have failed before this change, because the
/// conversion never returned a code to assert on. The assertion would have been unreachable rather
/// than false.
#[test]
fn an_internal_error_converts_to_a_code_rather_than_panicking() {
    let cases = [
        Error::InternalError(InternalError::InvalidKeyType(String::from("L:1,C:0"))),
        Error::InternalError(InternalError::UnresolvedKeyForReporter(String::from(
            "Resources",
        ))),
    ];

    for error in cases {
        let rendered = error.to_string();
        // `Error` boxes a `dyn Error`, so it is not `UnwindSafe`. Asserting it is, is sound here:
        // nothing is read back out of the closure's captures after a panic, only the returned value.
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            ExternError::from(FfiError(error))
        }));

        let converted = match outcome {
            Ok(converted) => converted,
            Err(..) => panic!(
                "converting `{}` panicked instead of giving a code",
                rendered
            ),
        };

        assert_eq!(
            22,
            converted.get_code().code(),
            "`{}` did not convert to the internal-error code",
            rendered
        );
        // The code alone does not say which key or which reporter, so the message has to survive.
        assert_eq!(rendered, message_of(&converted));
    }
}

/// The control, and the reason the case above constructs the error rather than provoking it through
/// the entry point. A data file with a non-string key is the input that produces
/// `InternalError::InvalidKeyType`, but it does not reach this table: `validate_and_return_json`,
/// which is what `cfn_guard_run_checks` calls, parses with serde rather than the libyaml loader and
/// maps every conversion failure to `Error::ParseError` before returning. All four key shapes come
/// back as a parse error and none of them panics.
///
/// So the table is fed by `Error`'s public surface rather than by this route as the code stands. It
/// is still wrong for it to abort: `Error` is public, `run_checks` is public, and a table that is
/// total for every variant does not depend on an unreachability argument that the next commit to
/// either of those can invalidate.
#[test]
fn a_non_string_key_reaches_the_entry_point_as_a_parse_error() {
    let rules = "rule r { Resources.B.Properties.Encrypted == true }";

    for data in ["1: foo\n", "true: foo\n", "~: foo\n", "[1, 2]: foo\n"] {
        let outcome = std::panic::catch_unwind(|| {
            run_checks(
                ValidateInput {
                    content: data,
                    file_name: "d.yaml",
                },
                ValidateInput {
                    content: rules,
                    file_name: "r.guard",
                },
                false,
            )
        });

        let returned = match outcome {
            Ok(returned) => returned,
            Err(..) => panic!("run_checks panicked on the key in {:?}", data),
        };

        assert!(
            matches!(returned, Err(Error::ParseError(..))),
            "the key in {:?} gave {:?}, not a parse error",
            data,
            returned
        );
    }
}
