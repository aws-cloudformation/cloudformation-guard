//! Helpers shared by the crate's unit tests. Compiled only into the lib test binary.

use std::sync::{Mutex, MutexGuard};

/// Serializes the tests that force the `colored` override on.
///
/// `colored::control::set_override` sets one flag for the whole process, and the harness runs tests
/// on parallel threads, so a test that forces color on would otherwise be forcing it on for
/// whichever sibling is writing a report at the same moment. Every test that forces color holds
/// this lock through a [`ForcedColor`], so two forced windows never overlap and the flag is back to
/// the environment's answer before the next one opens.
///
/// It is a crate-level helper rather than a private static of one test module so that a test in
/// any module can take it. Today the only callers are the entry-point tests in `lib.rs`: every other
/// unit test that reads a report rendered through `colored` reads it through
/// `strip_escape_sequences`, and the remaining reporter tests compare text that `colored` never
/// touches. The code excerpt tests in the CFN reporter do not render through `colored` at all: the
/// excerpt writer takes whether to colour as a parameter (`emit_code`), so they pass it and depend on
/// no flag. A new test that forces color,
/// or that asserts on text with its escapes kept, takes a [`ForcedColor`] too. A test that wants
/// plain text with color OFF and no strip has no guard today: it would need forcers kept out while
/// it runs, which this `Mutex` cannot express without also turning color on. If one is ever written,
/// this becomes an `RwLock` with the forcers on the write side and such readers on the read side.
static COLOR_OVERRIDE: Mutex<()> = Mutex::new(());

/// Color forced on for as long as this is alive, under [`COLOR_OVERRIDE`].
///
/// Dropping it lets the environment decide again, which is the state every test starts from
/// (`colored` keeps no record of an earlier override to put back). The reset lives in `drop` so that
/// a test body that panics also puts the flag back; a bare `unset_override` written after the
/// assertions would be skipped by the panic and leave color forced on for every test that runs after
/// it.
pub(crate) struct ForcedColor {
    /// Held, never read: releasing it is what the drop is for.
    _lock: MutexGuard<'static, ()>,
}

impl ForcedColor {
    /// Takes the lock, then forces color on.
    ///
    /// A test that failed while holding the lock leaves it poisoned; the state it guards was reset by
    /// that guard's drop during unwinding, so the lock is taken anyway rather than failing this test
    /// for the earlier one's reason.
    pub(crate) fn new() -> Self {
        let lock = COLOR_OVERRIDE
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        colored::control::set_override(true);
        ForcedColor { _lock: lock }
    }
}

impl Drop for ForcedColor {
    fn drop(&mut self) {
        // Runs before the field's `MutexGuard` is dropped, so the flag is back to the environment's
        // answer before the next holder can take the lock.
        colored::control::unset_override();
    }
}
