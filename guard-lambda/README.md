# AWS CloudFormation Guard as a Lambda

The Lambda version of the tool is a lightweight wrapper around the core [cfn-guard](../guard) code that can simply be invoked as a Lambda.

## Table of Contents

* [Installation](#installation)
* [Build and run post-install](#to-build-and-run-post-install)
* [Calling the Lambda Function](#calling-the-lambda-function)
* [FAQs](#faqs)

## Installation

### Dependencies

* AWS CLI [configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) with permissions to deploy and invoke Lambdas
* An [AWS Lambda Execution Role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) in IAM
* [Rust](https://rustup.rs/) (See the installation instructions in the [top-level README](../README.md#install-rust))
* If building on a Mac, you'll need [Homebrew](https://brew.sh/).
* If building on Ubuntu, you'll need to run `sudo apt-get update; sudo apt install build-essential` if you haven't already
* If building on CentOS/RHEL you'll need to add the `musl-libc` package repository to your yum config (see https://copr.fedorainfracloud.org/coprs/ngompa/musl-libc/)

### Mac/Ubuntu

1. Install and configure the [dependencies](#dependencies).
1. If you're on a Mac, add the following to `~/.cargo/config`:
    ```
    [target.x86_64-unknown-linux-musl]
    linker = "x86_64-linux-musl-gcc"
    ```
1. Ensure you're in the `cfn-guard-lambda` directory
1. Run `cargo build --release --target x86_64-unknown-linux-musl`. For [a custom runtime](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html), AWS Lambda looks for an executable called `bootstrap` in the deployment package zip. Rename the generated `cfn-lambda` executable to `bootstrap` and add it to a zip archive.
1. Run `cp ./../target/x86_64-unknown-linux-musl/release/cfn-guard-lambda ./bootstrap && zip lambda.zip bootstrap && rm bootstrap`.
1. Run the following command to submit cfn-guard as a AWS Lambda to your account:

```bash
aws lambda create-function --function-name cfnGuard \
 --handler guard.handler \
 --zip-file fileb://./lambda.zip \
 --runtime provided \
 --role arn:aws:iam::XXXXXXXXXXXXX:role/your_lambda_execution_role \
 --environment Variables={RUST_BACKTRACE=1} \
 --tracing-config Mode=Active
```

## To build and run post-install

To invoke the submitted cfn-guard as a Lambda function run:

```bash
aws lambda invoke --function-name rustTest \
  --payload '{"data": "<input data>", "rules" : "<input rules>"}' \
  output.json
```

## Calling the Lambda Function

### Request Structure

Requests to `cfn-guard-lambda` require the two following fields:
* `data` - The string version of the YAML or JSON template
* `rules` - The string version of the rule set file


## FAQs

**Q: How do I troubleshoot a lambda call returning an opaque error message like:**

    ```bash
    {"errorType": "Runtime.ExitError", "errorMessage": "RequestId: 1c0c0620-0f83-40bc-8eca-3cf2cf24820f Error: Runtime exited with error: exit status 101"}
    ```

> Run the same rule set and template locally with `cfn-guard` to get a better message:

    ```bash
    Parsing error handling template file, Error = while parsing a flow mapping, did not find expected ',' or '}' at line 21 column 1
    ```

> `cfn-guard-lambda` is just a wrapper for the `cfn-guard` code and each can be used to test the other.
