pub mod reader;

/// The text helpers the evaluator's notices and the reporters share moved with the evaluator into
/// `guard-lang` (`guard_lang::utils`); this module keeps their old paths working for this crate and
/// its integration tests.
pub mod writer {
    pub use guard_lang::utils::writer::*;
}

pub(crate) use guard_lang::utils::ReadCursor;
