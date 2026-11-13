pub use guard_lang::*;

/// The rulegen round-trip model reads templates the way `rulegen` reads them, through the one loader
/// `validate` reads with, reached here through `guard_lang::values::read_from`. It exercises the
/// `rulegen` command, which lives in this crate, so the test lives here rather than in `guard-lang`.
/// `allow(deprecated)`: the command structs it builds carry deprecated fields, as the old module
/// carried the allowance for the whole `rules` tree.
#[cfg(test)]
#[allow(deprecated)]
mod rulegen_round_trip_tests;
