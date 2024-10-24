#![no_main]

use cfn_guard::{run_checks, ValidateInput};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        let _ = run_checks(
            ValidateInput {
                content: s,
                file_name: "tmpl",
            },
            ValidateInput {
                content: "let ec2 = []",
                file_name: "rule",
            },
            false,
        );
    }
});
