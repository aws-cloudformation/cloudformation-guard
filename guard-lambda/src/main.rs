// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cfn_guard;
use lambda_runtime::{handler_fn, Context, Error};
use log::{self, LevelFilter, info};
use serde_derive::{Deserialize, Serialize};
use simple_logger::SimpleLogger;

#[derive(Deserialize, Debug)]
struct CustomEvent {
    #[serde(rename = "data")]
    data: String,
    #[serde(rename = "rules")]
    rules: Vec<String>,
}

#[derive(Serialize)]
struct CustomOutput {
    message: Vec<serde_json::Value>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {

    SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();
    let func = handler_fn(call_cfn_guard);
    lambda_runtime::run(func).await?;
    Ok(())
}

pub(crate) async fn call_cfn_guard(e: CustomEvent, _c: Context) -> Result<CustomOutput, Error> {
    info!("Template is: [{}]", &e.data);
    info!("Rule Set is: [{:?}]", &e.rules);
    let mut results_vec = Vec::new();
    for rule in e.rules.iter() {
        let result = match cfn_guard::run_checks(&e.data, &rule) {
            Ok(t) => t,
            Err(e) => (e.to_string()),
        };
        let json_value: serde_json::Value = serde_json::from_str(&result)?;
        results_vec.push(json_value)
    }
    Ok(CustomOutput {
        message: results_vec,
    })
}