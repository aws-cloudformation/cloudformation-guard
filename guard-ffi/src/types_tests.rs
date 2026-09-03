use super::*;
use crate::errors::InvalidInputCause;
use std::ffi::CString;

/// An `FfiStr` over `bytes`, which must end in a NUL.
///
/// # Safety
///
/// The returned `FfiStr` borrows `bytes`, and the lifetime is inferred rather than tied to it, so it
/// must not outlive the slice. Every caller below keeps the slice alive for the whole test.
unsafe fn ffi_str(bytes: &[u8]) -> FfiStr<'_> {
    assert_eq!(
        Some(&0u8),
        bytes.last(),
        "the fixture must be NUL-terminated"
    );

    FfiStr::from_raw(bytes.as_ptr() as *const std::os::raw::c_char)
}

fn null_str<'a>() -> FfiStr<'a> {
    unsafe { FfiStr::from_raw(std::ptr::null()) }
}

/// The path that used to work, and still has to: both pointers readable, both strings handed through
/// unchanged.
#[test]
fn readable_pointers_come_through_unchanged() {
    let content = CString::new("foo:\n  bar: true").unwrap();
    let file_name = CString::new("data.yaml").unwrap();

    let input = FfiValidateInput {
        data: FfiStr::from_cstr(&content),
        file_name: FfiStr::from_cstr(&file_name),
    };

    let read = input.read("data").expect("readable pointers were refused");

    assert_eq!("foo:\n  bar: true", read.content);
    assert_eq!("data.yaml", read.file_name);
}

/// A null pointer is reported, not panicked on. `read` used to be `From<FfiValidateInput>`, built on
/// `From<FfiStr> for &str`, which is `as_str()`, which is
/// `as_opt_str().expect("Unexpected null string pointer passed to rust")`.
///
/// Either field, because the conversion read both and either one could be the null.
#[test]
fn a_null_pointer_is_reported_rather_than_panicked_on() {
    let readable = CString::new("x").unwrap();

    let content_is_null = FfiValidateInput {
        data: null_str(),
        file_name: FfiStr::from_cstr(&readable),
    };
    let name_is_null = FfiValidateInput {
        data: FfiStr::from_cstr(&readable),
        file_name: null_str(),
    };

    for (input, expected_field) in [(content_is_null, "content"), (name_is_null, "file_name")] {
        // `catch_unwind` on purpose: before this change the assertion below was unreachable rather
        // than false, because the conversion never returned anything to assert on.
        let outcome =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || input.read("rules")));

        let returned = match outcome {
            Ok(returned) => returned,
            Err(..) => panic!("reading a null {} panicked", expected_field),
        };

        assert_eq!(
            Err(InvalidInput {
                whose: "rules",
                field: expected_field,
                cause: InvalidInputCause::Null,
            }),
            returned.map(|input| input.content)
        );
    }
}

/// Invalid UTF-8 is reported as invalid UTF-8. It used to panic with the *null pointer* message: the
/// real cause went to `log::error!`, which a C caller has no Rust logger to receive, so a caller
/// debugging an incorrectly encoded template was told their pointer was null.
#[test]
fn invalid_utf8_is_reported_as_invalid_utf8_and_not_as_a_null_pointer() {
    // 0xff is not a valid UTF-8 lead byte in any position.
    let not_utf8 = [b'f', b'o', b'o', 0xff, 0x00];
    let readable = CString::new("data.yaml").unwrap();

    let input = FfiValidateInput {
        data: unsafe { ffi_str(&not_utf8) },
        file_name: FfiStr::from_cstr(&readable),
    };

    let outcome =
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || input.read("data")));

    let returned = match outcome {
        Ok(returned) => returned,
        Err(..) => panic!("reading a non-UTF-8 content panicked"),
    };

    assert_eq!(
        Err(InvalidInput {
            whose: "data",
            field: "content",
            cause: InvalidInputCause::NotUtf8,
        }),
        returned.map(|input| input.content)
    );
}

/// The empty string is readable, and is not a null pointer. It is the value most likely to be
/// mistaken for one, since a C caller reaching for "no content" may pass either.
#[test]
fn the_empty_string_is_read_rather_than_refused() {
    let empty = CString::new("").unwrap();
    let file_name = CString::new("data.yaml").unwrap();

    let input = FfiValidateInput {
        data: FfiStr::from_cstr(&empty),
        file_name: FfiStr::from_cstr(&file_name),
    };

    assert_eq!(
        "",
        input
            .read("data")
            .expect("the empty string was refused")
            .content
    );
}
