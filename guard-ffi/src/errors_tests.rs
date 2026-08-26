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
            ExternError::from(FfiError::Guard(error))
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

/// An unreadable input pointer reports a code of its own rather than the -1 a caught panic produced.
///
/// -1 is `ErrorCode::PANIC`. Nothing documents it -- neither the doc comment on
/// `cfn_guard_run_checks` nor the header -- and `get_code` cannot produce it, yet it was what an
/// ordinary caller mistake reached. Measured across the boundary before this change: all four null
/// pointers, and a `content` holding invalid UTF-8, gave -1.
#[test]
fn an_unreadable_input_pointer_converts_to_its_own_code() {
    let cases = [
        (
            InvalidInputCause::Null,
            23,
            "data.content was a null pointer",
        ),
        (
            InvalidInputCause::NotUtf8,
            24,
            "data.content did not hold valid UTF-8",
        ),
    ];

    for (cause, expected_code, expected_message) in cases {
        let converted = ExternError::from(FfiError::Input(InvalidInput {
            whose: "data",
            field: "content",
            cause,
        }));

        assert_eq!(expected_code, converted.get_code().code());
        // The code does not say which of the four pointers was wrong, so the message has to.
        assert_eq!(expected_message, message_of(&converted));
    }
}

/// The two causes are told apart, which they were not before: `FfiStr::as_str` panics with
/// "Unexpected null string pointer passed to rust" for invalid UTF-8 as well, sending the real cause
/// to `log::error!` -- which a C caller has no Rust logger to receive.
#[test]
fn a_null_pointer_and_invalid_utf8_do_not_report_the_same_thing() {
    let null = ExternError::from(FfiError::Input(InvalidInput {
        whose: "rules",
        field: "file_name",
        cause: InvalidInputCause::Null,
    }));
    let not_utf8 = ExternError::from(FfiError::Input(InvalidInput {
        whose: "rules",
        field: "file_name",
        cause: InvalidInputCause::NotUtf8,
    }));

    assert_ne!(null.get_code().code(), not_utf8.get_code().code());
    assert_ne!(message_of(&null), message_of(&not_utf8));
}

/// Every code `get_code` produces is distinct, is usable as an error, and is not 19.
///
/// The table has no `_ =>` arm, so the compiler makes it total over `Error` -- that is what keeps it
/// complete. What the compiler cannot check is that two arms do not answer the same number, and
/// adding the two input codes is exactly the change that could collide.
///
/// Five `Error` variants are absent, because guard-ffi depends on `cfn-guard` and `ffi-support` and
/// nothing else, so their payloads cannot be built here: `JsonError` (1), `YamlError` (2),
/// `RegexError` (6), `Errors` (14) and `XMLError` (20). `ConversionError` (13) is absent for a
/// stronger reason -- its payload is `Infallible`, so no value of it exists and the arm is
/// unreachable by construction. None of those five numbers appears below, so the arms covered here
/// are distinct from them too.
#[test]
fn every_error_code_is_distinct_and_usable() {
    let errors = vec![
        FfiError::Guard(Error::FormatError(std::fmt::Error)),
        FfiError::Guard(Error::IoError(std::io::Error::new(
            std::io::ErrorKind::Other,
            "io",
        ))),
        FfiError::Guard(Error::ParseError(String::from("x"))),
        FfiError::Guard(Error::MissingProperty(String::from("x"))),
        FfiError::Guard(Error::MissingVariable(String::from("x"))),
        FfiError::Guard(Error::MultipleValues(String::from("x"))),
        FfiError::Guard(Error::IncompatibleRetrievalError(String::from("x"))),
        FfiError::Guard(Error::IncompatibleError(String::from("x"))),
        FfiError::Guard(Error::NotComparable(String::from("x"))),
        FfiError::Guard(Error::RetrievalError(String::from("x"))),
        FfiError::Guard(Error::MissingValue(String::from("x"))),
        FfiError::Guard(Error::FileNotFoundError(String::from("x"))),
        FfiError::Guard(Error::IllegalArguments(String::from("x"))),
        FfiError::Guard(Error::MissingDocument),
        FfiError::Guard(Error::InternalError(InternalError::InvalidKeyType(
            String::from("x"),
        ))),
        FfiError::Input(InvalidInput {
            whose: "data",
            field: "content",
            cause: InvalidInputCause::Null,
        }),
        FfiError::Input(InvalidInput {
            whose: "data",
            field: "content",
            cause: InvalidInputCause::NotUtf8,
        }),
    ];

    let expected = errors.len();
    let mut codes = vec![];

    for error in errors {
        let rendered = error.to_string();
        let code = ExternError::from(error).get_code().code();

        // 0 is what `ExternError::success()` carries, so an error reporting it would read as a
        // successful run with a null result. -1 is `ErrorCode::PANIC`. 19 is the CLI's
        // validation-failure exit code, deliberately skipped so the two cannot be confused.
        assert!(code > 0, "`{}` reported code {}", rendered, code);
        assert_ne!(19, code, "`{}` reported the CLI's failure code", rendered);

        codes.push(code);
    }

    codes.sort_unstable();
    codes.dedup();
    assert_eq!(
        expected,
        codes.len(),
        "two errors share a code: {:?}",
        codes
    );
}
