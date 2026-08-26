use cfn_guard::run_checks;
use ffi_support::ExternError;
use std::os::raw::c_char;

mod errors;
mod types;

use errors::FfiError;
use types::FfiValidateInput;

/**
 * C prototype for this function:
 * typedef struct {
 *   int32_t code;
 *   char *message;
 * } extern_err_t;
 *
 * typedef struct {
 *   char *content;
 *   char *file_name;
 * } validate_input_t;
 *
 * char* cfn_guard_run_checks(validate_input_t data, validate_input_t rules, bool verbose, extern_err_t * err);
 * void cfn_guard_free_string(char *);
 *
 * if an error is returned, it will be populated in `err`. `cfn_guard_free_string` must be called
 * for the `message` field in `err`.
 *
 * if `err.code` == 0, then the result will be a json string. This `*char` must be passed to
 * `cfn_guard_free_string` to return the memory allocated by rust. A validation failure is not an
 * error: it comes back as code 0 with the failure described inside that json.
 *
 * every pointer in `data` and `rules` must be non-null and must hold valid UTF-8. `err.code` is 23
 * for a null one and 24 for one that is not UTF-8, and `err.message` names the field. Both used to
 * panic inside the conversion -- with the null message either way -- and the caught panic reached
 * the caller as -1, which nothing documents. Every other non-zero code comes from `get_code` in
 * errors.rs and is in 1..=24, skipping 19 so it cannot be confused with the CLI's
 * validation-failure exit code.
 */
#[no_mangle]
pub extern "C" fn cfn_guard_run_checks<'a>(
    data: FfiValidateInput<'a>,
    rules: FfiValidateInput<'a>,
    verbose: c_char,
    err: &mut ExternError,
) -> *mut c_char {
    ffi_support::call_with_result(err, || {
        // Read both pointers before calling into guard. `data.into()` and `rules.into()` used to do
        // this as argument expressions, which meant an unreadable pointer panicked here rather than
        // returning a code.
        let data = data.read("data")?;
        let rules = rules.read("rules")?;

        run_checks(data, rules, verbose == 1).map_err(FfiError::Guard)
    })
}

ffi_support::define_string_destructor!(cfn_guard_free_string);
