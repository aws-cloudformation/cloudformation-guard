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

> :warning: **If you are sending lambda output to an S3 bucket**: you will need to add necesary permissions, that allows lambda fucntion to write into S3. (https://aws.amazon.com/blogs/security/writing-iam-policies-how-to-grant-access-to-an-amazon-s3-bucket/)

### Mac/Ubuntu

1. Install and configure the [dependencies](#dependencies).
1. Run `rustup target add x86_64-unknown-linux-musl`.
1. If you're on a Mac, add the following to `~/.cargo/config`:
    ```
    [target.x86_64-unknown-linux-musl]
    linker = "x86_64-linux-musl-gcc"
    ```
1. Ensure you're in the `guard-lambda` directory
1. Run `cargo build --release --target x86_64-unknown-linux-musl`. For [a custom runtime](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html), AWS Lambda looks for an executable called `bootstrap` in the deployment package zip. Rename the generated `cfn-lambda` executable to `bootstrap` and add it to a zip archive.
1. Run `cp ./../target/x86_64-unknown-linux-musl/release/cfn-guard-lambda ./bootstrap && zip lambda.zip bootstrap && rm bootstrap`.
1. Run the following command to submit cfn-guard as a AWS Lambda to your account:

```bash
aws lambda create-function --function-name cfnGuardLambda \
 --handler guard.handler \
 --zip-file fileb://./lambda.zip \
 --runtime provided \
 --role arn:aws:iam::XXXXXXXXXXXXX:role/your_lambda_execution_role \
 --environment Variables={RUST_BACKTRACE=1} \
 --tracing-config Mode=Active
```

## Calling the AWS Lambda Function

## Payload Structure

The payload JSON to `cfn-guard-lambda` requires the following two fields:
* `data` - String version of the YAML or JSON structured data
* `rules` - List of string version of rules files that you want to run your YAML or JSON structured data against.

## Invoking `cfn-guard-lambda`

To invoke the submitted cfn-guard as a AWS Lambda function run:

```bash
aws lambda invoke --function-name cfnGuardLambda \
  --payload "{"data": "<input data>", "rules" : ["<input rules 1>", "<input rules 2>", ...]}" \
  output.json
```
The above works for AWS CLI version 1. If you are planning to use the AWS CLI version 2 please refer to the [Migrating from AWS CLI version 1 to version 2 document](https://docs.aws.amazon.com/cli/latest/userguide/cliv2-migration.html#cliv2-migration-binaryparam) for changes required to the above command.

### Example

```bash
aws lambda invoke --function-name cfnGuard --payload '{"data": "{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}}}", "rules" : [ "Resources.*[ Type == /EC2::Volume/ ].Properties.Encrypted == false" ]}' output.json
```

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
