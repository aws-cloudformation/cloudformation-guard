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
    #[serde(rename = "template")]
    template: String,
    #[serde(rename = "ruleSet")]
    rule_set: String,
    #[serde(rename = "strictChecks")]
    strict_checks: bool,
}

#[derive(Serialize)]
struct CustomOutput {
    message: Vec<String>,
    #[serde(rename = "exitStatus")]
    exit_status: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_level(log::Level::Info)?;
    lambda!(my_handler);

    Ok(())
}

fn my_handler(e: CustomEvent, _c: Context) -> Result<CustomOutput, HandlerError> {
    //dbg!(&e);
    info!("Template is [{}]", &e.template);
    info!("Rule Set is [{}]", &e.rule_set);
    let (result, exit_code) = match cfn_guard::run_check(&e.template, &e.rule_set, e.strict_checks)
    {
        Ok(t) => t,
        Err(e) => (vec![e], 1),
    };

    let exit_status = match exit_code {
        0 => "PASS",
        1 => "ERR",
        2 | _ => "FAIL",
    };

    Ok(CustomOutput {
        message: result,
        exit_status: String::from(exit_status),
    })
}
