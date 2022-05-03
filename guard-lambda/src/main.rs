// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use cfn_guard;
use lambda_runtime::{handler_fn, Context, Error};
use log::{self, LevelFilter, info, error};
use serde_derive::{Deserialize, Serialize};
use simple_logger::SimpleLogger;

fn default_as_true() -> bool {
    true
}

fn default_as_empty() -> String {
    "".to_string()
}

#[derive(Deserialize, Debug)]
struct CustomEvent {
    #[serde(rename = "data")]
    data: String,
    #[serde(rename = "rules")]
    rules: Vec<String>,
    #[serde(rename = "verbose", default="default_as_true")] // for backward compatibility
    verbose: bool,
    #[serde(rename = "s3_output_bucket", default="default_as_empty")]
    s3_output_bucket: String,
}

#[derive(Serialize)]
struct CustomOutput {
    message: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct FailureResponse {
    pub body: String, 
}

#[derive(Debug, Serialize)]
struct SuccessMessage{
    pub message: String, 
}

// Implement Display for the Failure response so that we can then implement Error.
impl std::fmt::Display for FailureResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.body)
    }
}   

// Implement Error for the FailureResponse so that we can `?` (try) the Response 
// returned by `lambda_runtime::run(func).await` in `fn main`. 
impl std::error::Error for FailureResponse {}

#[tokio::main]
async fn main() -> Result<(), Error> {

    SimpleLogger::new().with_level(LevelFilter::Info).init().unwrap();
    let func = handler_fn(call_cfn_guard);
    lambda_runtime::run(func).await?;
    Ok(())
}

pub async fn upload_object_to_s3(client: &aws_sdk_s3::Client, bucket_name: &str, key: &str, b: &str) -> Result<(), Error> {
    //let body = ByteStream::from_static(b.as_bytes()).await;
    client
        .put_object()
        .bucket(bucket_name)
        .key(key)
        .body(b.as_bytes().to_owned().into())
        .content_type("text/plain")
        .send()
        .await
        .map_err(|err| {
            // In case of failure, log a detailed error to CloudWatch.
            error!(
                "failed to upload file '{}' to S3 with error: {}",
                &key, err
            );
            // The sender of the request receives this message in response.
            FailureResponse {
                body: "The lambda encountered an error and your message was not saved".to_owned(),
            }
        })?;
    
    let s3_location = format!("s3://{}/{}", bucket_name, key);
    info!("Successfully stored the scan results in S3 with the name '{}'", &s3_location);

    Ok(())
}

pub(crate) async fn call_cfn_guard(e: CustomEvent, _c: Context) -> Result<CustomOutput, Error> {
    info!("Template is: [{}]", &e.data);
    info!("Rules are: [{:?}]", &e.rules);
    let mut results_vec = Vec::new();
    for rule in e.rules.iter() {
        let result = match cfn_guard::run_checks(&e.data, &rule, e.verbose) {
            Ok(t) => t,
            Err(e) => (e.to_string()),
        };
        let json_value: serde_json::Value = serde_json::from_str(&result)?;
        results_vec.push(json_value)
    }

    //let response: CustomOutput;
    let mut response = Vec::new();

    if e.s3_output_bucket.is_empty() {
        response = results_vec;
    }else {
        // No extra configuration is needed as long as your Lambda has 
        // the necessary permissions attached to its role.
        let config = aws_config::from_env().load().await;

        // Create an S3 client
        let client = aws_sdk_s3::Client::new(&config);

        // Generate a filename based on when the request was received.
        let filename = format!("{}.json", time::OffsetDateTime::now_utc().unix_timestamp());
        let body = serde_json::to_string(&results_vec)?;
        
        upload_object_to_s3(
            &client,
            &e.s3_output_bucket, 
            &filename, 
            &body
        ).await?;

        let j = serde_json::json!({
            "message": format!("Successfully stored the scan results in S3 with the name '{}'", &filename)
        });
        let json_value: serde_json::Value = serde_json::from_value(j)?;
        response.push(json_value);
    }

    Ok(CustomOutput {
        message: response,
    })
}