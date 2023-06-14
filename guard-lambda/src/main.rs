// Copyright Amazon Web Services, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cfn_guard::{run_checks, ValidateInput};
use lambda_runtime::{handler_fn, Context, Error};
use log::{self, info, LevelFilter};
use serde_derive::{Deserialize, Serialize};
use simple_logger::SimpleLogger;

fn default_as_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CustomEvent {
    #[serde(rename = "data")]
    pub data: String,
    #[serde(rename = "rules")]
    pub rules: Vec<String>,
    #[serde(rename = "verbose", default = "default_as_true")] // for backward compatibility
    pub verbose: bool,
}

#[derive(Serialize)]
pub struct CustomOutput {
    pub message: Vec<serde_json::Value>,
}

#[tokio::main]
#[allow(dead_code)]
async fn main() -> Result<(), Error> {
    SimpleLogger::new()
        .with_level(LevelFilter::Info)
        .init()
        .unwrap();
    let func = handler_fn(call_cfn_guard);
    lambda_runtime::run(func).await?;
    Ok(())
}

pub async fn call_cfn_guard(e: CustomEvent, _c: Context) -> Result<CustomOutput, Error> {
    info!("Template is: [{}]", &e.data);
    info!("Rules are: [{:?}]", &e.rules);
    let mut results_vec = Vec::new();
    for rule in e.rules.iter() {
        let result = match run_checks(
            ValidateInput {
                content: &e.data,
                file_name: "lambda-payload",
            },
            ValidateInput {
                content: rule,
                file_name: "lambda-rule",
            },
            e.verbose,
        ) {
            Ok(t) => t,
            Err(e) => e.to_string(),
        };
        let json_value: serde_json::Value = serde_json::from_str(&result)?;
        results_vec.push(json_value)
    }
    Ok(CustomOutput {
        message: results_vec,
    })
}

impl std::fmt::Display for CustomEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        write!(f, "{}", serde_json::to_string_pretty(&self).unwrap())?;
        Ok(())
    }
}

impl std::fmt::Display for CustomOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        for message in &self.message {
            write!(
                f,
                "{}",
                match serde_json::to_string_pretty(message) {
                    Ok(message) => message,
                    Err(_) => unreachable!(),
                }
            )?;
        }
        Ok(())
    }
}
