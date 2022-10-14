// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/* require return types marked as must_use to be used (such as Result types) */
#![deny(unused_must_use)]

mod rules;
pub mod commands;
pub mod command;
mod migrate;
mod utils;

pub use crate::rules::errors::{Error, ErrorKind};
pub use crate::commands::helper::{validate_and_return_json as run_checks, ValidateInput};
