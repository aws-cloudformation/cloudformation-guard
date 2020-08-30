// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use std::error::Error;
use cfn_guard_rulegen;
use lambda_runtime::{error::HandlerError, lambda, Context};
use log::{self, info};
use serde_derive::{Deserialize, Serialize};
use simple_logger;

#[derive(Deserialize, Debug)]
struct CustomEvent {
    #[serde(rename = "template")]
    template: String
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(my_handler);

    Ok(())
}

#[derive(Serialize)]
struct CustomOutput {
    message: Vec<String>
}


fn my_handler(e: CustomEvent, _c: Context) -> Result<CustomOutput, HandlerError> {

    info!("Template is [{}]", &e.template);
    let result = cfn_guard_rulegen::run_gen(&e.template);

    Ok(CustomOutput {
        message: result
    })
}
