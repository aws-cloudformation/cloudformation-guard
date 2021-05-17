// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;

use cfn_guard;
use lambda_runtime::{error::HandlerError, lambda, Context};
use log::{self, info};
use serde_derive::{Deserialize, Serialize};
use simple_logger;

#[derive(Deserialize, Debug)]
struct CustomEvent {
    #[serde(rename = "data")]
    data: String,
    #[serde(rename = "rules")]
    rules: String,
}

#[derive(Serialize)]
struct CustomOutput {
    message: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(call_cfn_guard);

    Ok(())
}

fn call_cfn_guard(e: CustomEvent, _c: Context) -> Result<CustomOutput, HandlerError> {
    info!("Template is [{}]", &e.data);
    info!("Rule Set is [{}]", &e.rules);
    let result = match cfn_guard::run_checks(&e.data, &e.rules)
    {
        Ok(t) => t,
        Err(e) => (e.to_string()),
    };

    Ok(CustomOutput {
        message: result,
    })
}
