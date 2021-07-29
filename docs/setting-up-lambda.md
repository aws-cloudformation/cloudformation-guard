# Installing Guard as an AWS Lambda function<a name="setting-up-lambda"></a>

You can install AWS CloudFormation Guard through Cargo, the Rust package manager\. *Guard as an AWS Lambda* function \(`cfn-guard-lambda`\) is a lightweight wrapper around Guard \(cfn\-guard\) that can be used as a Lambda function\.

## Install Guard as a Lambda<a name="w15aac10c16b5"></a>

### Prerequisites<a name="guard-as-lambda-prerequisites"></a>

Before you can install Guard as a Lambda function, you must fulfill the following prerequisites:
+ AWS Command Line Interface \(AWS CLI\) configured with permissions to deploy and invoke Lambda functions\. For more information, see [Configuring the AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html)\.
+ An AWS Lambda execution role in AWS Identity and Access Management \(IAM\)\. For more information, see [AWS Lambda execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)\.
+ In CentOS/RHEL environments, add the `musl-libc` package repository to your yum config\. For more information, see [ngompa/musl\-libc](https://copr.fedorainfracloud.org/coprs/ngompa/musl-libc/)\.

## To install the Rust package manager<a name="install-rust-and-cargo"></a>

Cargo is the Rust package manager\. Complete the following steps to install Rust which includes Cargo\.

1. Run the following command from a terminal, and then follow the onscreen instructions to install Rust\.

   ```
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   ```

   1. \(Optional\) For Ubuntu environments, run the following command\.

     ```
     sudo apt-get update; sudo apt install build-essential
     ```

1. Configure your `PATH` environment variable, and run the following command\.

   ```
   source $HOME/.cargo/env
   ```

## To install Guard as a Lambda function \(Linux, macOS, or Unix\)<a name="to-isntall-guard-as-a-lambda"></a>

1. From your command terminal, run the following command\.

   ```
   cargo install cfn-guard-lambda
   ```

   1. \(Optional\) To confirm the installation of Guard as a Lambda function, run the following command\.

     ```
     cfn-guard-lambda --version
     ```

     The command returns the following output\.

     ```
     cfn-guard-lambda 2.0
     ```

1. To install `musl` support, run the following command\.

   ```
   rustup target add x86_64-unknown-linux-musl
   ```

1. Build with `musl`, and then run the following command in your terminal\.

   ```
   cargo build --release --target x86_64-unknown-linux-musl
   ```

   For a [custom runtime](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html), AWS Lambda requires an executable with the name `bootstrap` in the deployment package \.zip file\. Rename the generated `cfn-lambda` executable to `bootstrap` and then add it to the \.zip archive\.

   1. For macOS environments, create your cargo configuration file in the root of the Rust project or in `~/.cargo/config`\.

     ```
     [target.x86_64-unknown-linux-musl]
     linker = "x86_64-linux-musl-gcc"
     ```

1. Change to the `cfn-guard-lambda` root directory\.

   ```
   cd ~/.cargo/bin/cfn-guard-lambda
   ```

1. Run the following command in your terminal\.

   ```
   cp ./../target/x86_64-unknown-linux-musl/release/cfn-guard-lambda ./bootstrap && zip lambda.zip bootstrap && rm bootstrap
   ```

1. Run the following command to submit `cfn-guard`as a Lambda function to your account\.

   ```
   aws lambda create-function --function-name cfnGuard \
    --handler guard.handler \
    --zip-file fileb://./lambda.zip \
    --runtime provided \
    --role arn:aws:iam::444455556666:role/your_lambda_execution_role \ 
    --environment Variables={RUST_BACKTRACE=1} \
    --tracing-config Mode=Active
   ```

## To build and run Guard as a Lambda function<a name="build-and-run-lambda"></a>

To invoke the submitted `cfn-guard-lambda` as a Lambda function, run the following command\.

```
aws lambda invoke --function-name rustTest \
  --payload '{"data": "input data", "rules" : "input rules"}' \
  output.json
```

## To call the Lambda function request structure<a name="calling-the-lambda-function"></a>

Requests to `cfn-guard-lambda` require the following fields:
+ `data` – The string version of the YAML or JSON template
+ `rules` – The string version of the rule set file