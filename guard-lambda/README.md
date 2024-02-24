# AWS CloudFormation Guard as a Lambda

The Lambda version of the tool is a lightweight wrapper around the core [cfn-guard](../guard) code that can simply be invoked as a Lambda. We currently support 2 methods for deploying the Lambda.

## Table of Contents

* [Method 1: Installation using AWS CLI](#method-1-installation-using-aws-cli)
* [Method 2: Installation using SAM CLI](#method-2-installation-using-sam-cli)
* [Calling the AWS Lambda Function](#calling-the-aws-lambda-function)
* [FAQs](#faqs)

## Method 1: Installation using AWS CLI

### Dependencies

* AWS CLI [configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) with permissions to deploy and invoke Lambdas
* [Rust](https://rustup.rs/) (See the installation instructions in the [top-level README](../README.md#install-rust))
* If building on a Mac, you'll need [Homebrew](https://brew.sh/).
* If building on Ubuntu, you'll need to run `sudo apt-get update; sudo apt install build-essential` if you haven't already
* If building on CentOS/RHEL you'll need to add the `musl-libc` package repository to your yum config (see https://copr.fedorainfracloud.org/coprs/ngompa/musl-libc/)

### Mac/Ubuntu

1. Install and configure the [dependencies](#dependencies).
2. Run `rustup target add x86_64-unknown-linux-musl`.
3. If you're on a Mac, add the following to `~/.cargo/config`:
    ```
    [target.x86_64-unknown-linux-musl]
    linker = "x86_64-linux-musl-gcc"
    ```
4. Ensure you're in the `guard-lambda` directory.
5. Run `cargo build --release --target x86_64-unknown-linux-musl`. For [a custom runtime](https://docs.aws.amazon.com/lambda/latest/dg/runtimes-custom.html), AWS Lambda looks for an executable called `bootstrap` in the deployment package zip. Rename the generated `cfn-lambda` executable to `bootstrap` and add it to a zip archive.
6. Run `cp ./../target/x86_64-unknown-linux-musl/release/cfn-guard-lambda ./bootstrap && zip lambda.zip bootstrap && rm bootstrap`.
7. Initialize the following shell variables with values corresponding to your account:
   ```bash
   LAMBDA_FUNCTION_NAME=CloudFormationGuardLambda
   AWS_ACCOUNT_ID=111111111111
   REGION=us-east-1
   ROLE_NAME="${LAMBDA_FUNCTION_NAME}Role"
   ```
8. Create [an execution role for Lambda function]((https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)). Refer the linked documentation for updated instructions. Alternatively, use the following command:
   ```bash
   aws iam create-role \
      --role-name $ROLE_NAME \
      --assume-role-policy-document '{"Version": "2012-10-17","Statement": [{ "Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]}'
   
   aws iam attach-role-policy \
      --role-name $ROLE_NAME \
      --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
   ```
9. Run the following command to submit `cfn-guard` as an AWS Lambda function to your account:
   ```bash
    aws lambda create-function \
    --function-name $LAMBDA_FUNCTION_NAME \
    --handler guard.handler \
    --zip-file fileb://./lambda.zip \
    --runtime provided \
    --role "arn:aws:iam::${AWS_ACCOUNT_ID}:role/${ROLE_NAME}" \
    --environment Variables={RUST_BACKTRACE=1} \
    --tracing-config Mode=Active \
    --region $REGION
   ```

## Method 2: Installation using SAM CLI

### Dependencies

* [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-getting-started.html) installed
* AWS CLI [installed](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) and [configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) with permissions to deploy via CloudFormation. SAM CLI will internally use the credentials you setup AWS CLI with. You may use the following IAM policy as a reference for least privileged access.

  <details>
    <summary>
      IAM Policy for SAM CLI User
    </summary>

    ```js
    {
        "Version": "2012-10-17",
        "Statement":
        [
            {
                "Effect": "Allow",
                "Action":
                [
                    "cloudformation:CreateChangeSet",
                    "cloudformation:CreateStack",
                    "cloudformation:DeleteChangeSet",
                    "cloudformation:DeleteStack",
                    "cloudformation:DescribeChangeSet",
                    "cloudformation:DescribeStackEvents",
                    "cloudformation:DescribeStackResource",
                    "cloudformation:DescribeStackResources",
                    "cloudformation:DescribeStacks",
                    "cloudformation:ExecuteChangeSet",
                    "cloudformation:GetTemplate",
                    "cloudformation:GetTemplateSummary",
                    "cloudformation:ListStackResources",
                    "cloudformation:SetStackPolicy",
                    "cloudformation:UpdateStack",
                    "cloudformation:UpdateTerminationProtection",
                    "iam:AttachRolePolicy",
                    "iam:CreateRole",
                    "iam:DeleteRole",
                    "iam:DetachRolePolicy",
                    "iam:GetRole",
                    "iam:PassRole",
                    "lambda:CreateFunction",
                    "lambda:DeleteFunction",
                    "lambda:GetFunction",
                    "lambda:TagResource",
                    "s3:GetObject",
                    "s3:PutObject"
                ],
                "Resource": "*"
            }
        ]
    }
    ```
  </details>


* [Docker](https://docs.docker.com/get-docker/) installed

### Building and deploying

#### Guided

1. Make sure docker is running
2. Navigate to `guard-lambda` directory and run `sam build --use-container` to build the code for the Lambda function
3. Run `sam deploy --guided` and complete the interactive workflow. This workflow will create a CloudFormation changeset and deploy it
4. Once it succeeds, the name of the function will be shown in the `CloudFormationGuardLambdaFunctionName` output
5. For subsequent updates, build the code again (step 2) and run `sam deploy` (without `--guided`)

#### CI/CD

This approach does not require user input and can be used in CI/CD pipelines:

1. Make sure docker is running
2. Navigate to `guard-lambda` directory and run `sam build --use-container` to build the code for the Lambda function
3. Run `sam package --s3-bucket <your-bucket-name>` this will create a `.zip` package with the code and dependencies and upload to S3
4. Run `sam deploy --s3-bucket <your-bucket-name> --stack-name <your-stack-name` this will deploy the application to CloudFormation
5. Once it succeeds, the name of the function will be shown in the `CloudFormationGuardLambdaFunctionName` output. To retrieve this programmatically, run ` sam list stack-outputs --output json`. If `jq` is available, you can retrieve the value by running `sam list stack-outputs --output json | jq -r .[0].OutputValue`

See [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-package.html) for all `sam package` options
see [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/sam-cli-command-reference-sam-deploy.html) for all sam deploy options

Alternatively, you can build a `somconfig.toml` in your directory and specify any and all CLI options in [toml](https://toml.io/en/) format. AWS Documentation [here](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-config.html).

#### Specifying Stack Parameters

To specify a stack parameter, add  `--parameter-overrides` option to the `sam deploy` command. For example, to specify the `FunctionName`, run the following command:

```bash
sam deploy \
  --s3-bucket <your-bucket-name> \
  --stack-name <your-stack-name> \
  --parameter-overrides FunctionName=MyCfnGuardLambda
```

or in your `samconfig.toml`:

```toml
[default.global.parameters]
s3_bucket = "<your-bucket-name>"
stack_name = "<your-stack-name>"
parameter_overrides = "FunctionName=MyCfnGuardLambda"
```

Note: multiple parameters are separated by spaces: `Param1=Value1 Param2=Value2`

## Calling the AWS Lambda Function

## Payload Structure

The payload JSON to `cfn-guard-lambda` requires the following two fields:
* `data` - (_Mandatory_, string) Infrastructure as code template data in YAML or JSON structure.
* `rules` - (_Mandatory_, list of strings) List of rules that you want to run your YAML or JSON structured data against.
* `verbose` - (_Optional_, boolean) A flag when set to `false` makes Lambda emit a shorter version of the output. This is set to `true` by default for backward compatibility.

## Invoking `cfn-guard-lambda`

Initialize the variable `LAMBDA_FUNCTION_NAME` to the name of the deployed AWS Lambda Function, and invoke it using the following syntax:

```bash
aws lambda invoke \
--function-name $LAMBDA_FUNCTION_NAME \
--cli-binary-format raw-in-base64-out \
--payload "{"data": "<input data>", "rules" : ["<input rules 1>", "<input rules 2>", ...], "verbose": <true|false>}" \
output.json
```

**Note:** `--cli-binary-format` option is only required to override the default configuration setting to perform the parsing of
JSON input. If the command doesn't work with this option, try running it without this configuration override. Your current
AWS CLI version may have this configuration set to the required value.

### Example

```bash
aws lambda invoke \
--function-name $LAMBDA_FUNCTION_NAME \
--cli-binary-format raw-in-base64-out \
--payload '{"data":"{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":true,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":true,\"AvailabilityZone\":\"us-west-2c\"}}}}","rules":["let ec2_volumes = Resources.*[ Type == /EC2::Volume/ ]\nrule EC2_ENCRYPTION_BY_DEFAULT when %ec2_volumes !empty {\n    %ec2_volumes.Properties.Encrypted == true \n      <<\n            Violation: All EBS Volumes should be encrypted \n            Fix: Set Encrypted property to true\n       >>\n}"],"verbose":false}' \
output.json
```

**Note:** `--cli-binary-format` option is only required to override the default configuration setting to perform the parsing of
JSON input. If the command doesn't work with this option, try running it without this configuration override. Your current
AWS CLI version may have this configuration set to the required value.

## FAQs

**Q: How do I troubleshoot a lambda call returning an opaque error message like:**

```bash
{"errorType": "Runtime.ExitError", "errorMessage": "RequestId: 1c0c0620-0f83-40bc-8eca-3cf2cf24820f Error: Runtime exited with error: exit status 101"}
 ```
**A:** Run the same rule set and template locally with `cfn-guard` to get a better message, such as:

```bash
Parsing error handling template file, Error = while parsing a flow mapping, did not find expected ',' or '}' at line 21 column 1
```

`cfn-guard-lambda` is just a wrapper for the `cfn-guard` code and each can be used to test the other.
