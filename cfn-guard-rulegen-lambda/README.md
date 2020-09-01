# [PREVIEW] CloudFormation Guard Rulegen as a Lambda
## Table of Contents
* [Installation](#installation)
* [Build and run post-install](#to-build-and-run-post-install)
* [Calling the Lambda Function](#calling-the-lambda-function)
* [FAQ](#faq)

## Installation
### Dependencies
* AWS CLI [configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) with permissions to deploy and invoke Lambdas
* An [AWS Lambda Execution Role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) in IAM
* A shell environment variable called `CFN_GUARD_LAMBDA_ROLE_ARN` set to the ARN of that role
* [Rust](https://rustup.rs/) (See the installation instructions in the [top-level README](../README.md#install-rust))
* If building on a Mac, you'll need [Homebrew](https://brew.sh/).  
* If building on Ubuntu, you'll need to run `sudo apt-get update; sudo apt install build-essential` if you haven't already
* If leveraging, cloud infrastructure in code and provisioning it through AWS CloudFormation, you'll need to install or update the [AWS CDK CLI] from npm (requires [Node.js ≥ 10.13.0](https://nodejs.org/download/release/latest-v10.x/)): `npm i -g aws-cdk`

### Mac/Ubuntu
1. Install and configure the [dependencies](#dependencies).
1. If you're on a Mac, add the following to `~/.cargo/config`:
    ```
    [target.x86_64-unknown-linux-musl]
    linker = "x86_64-linux-musl-gcc"
    ```
1. Ensure you're in the `cfn-guard-rulegen-lambda` directory
1. Run `make pre-reqs`.
1. Run `make install`. Or to use the Cloud Development Kit (CDK) to deploy, run `make install-cdk` instead

## To build and run post-install

To build, deploy and test the function after you edit its source code, run `make test`.

To merely invoke the function, run `make invoke`.  The variables in the Makefile used to make the calls can be manipulated to provide different payloads.


This project is licensed under the Apache-2.0 License.

We will be working to improve the quality of lambda messages, but as a general rule, `cfn-guard-rulegen-lambda` is just a wrapper for the `cfn-guard-rulegen` code and each can be used to test the other.

## Calling the Lambda Function
### Request Structure
Requests to `cfn-guard-rulegen-lambda` require the following field:
* `template` - The string version of the YAML or JSON CloudFormation Template

#### Example
There are example payloads in the [Makefile](Makefile).  Here's one we use to test a rule set that should not pass:

```
request_payload = '{ "template": "{\n    \"Resources\": {\n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}"}'
 
 #======================================================================
 # Request Payload
 #======================================================================
 # Template
 # {"Resources": {
 #  "NewVolume" : {
 #    "Type" : "AWS::EC2::Volume",
 #    "Properties" : {
 #    "Size" : 100,
 #    "Encrypted": true,
 #    "AvailabilityZone" : "us-east-1b"
 #    }
 #  },
 #  "NewVolume2" : {
 #    "Type" : "AWS::EC2::Volume",
 #    "Properties" : {
 #      "Size" : 99,
 #      "Encrypted": true,
 #      "AvailabilityZone" : "us-east-1b"
 #    }
 #  }
 #}
 #======================================================================
```
## FAQ

* **Q: How do I troubleshoot a lambda call returning an opaque error message like:**
	
	```
	{"errorType": "Runtime.ExitError", "errorMessage": "RequestId: 1c0c0620-0f83-40bc-8eca-3cf2cf24820f Error: Runtime exited with error: exit status 101"}
	```

* **A: Run the same template locally with `cfn-guard-rulegen` to get a better message:**

	```
	thread 'main' panicked at 'Bad Rule Operator: REQUIRE', src/rule_proc.rs:344:2
	```
	
	We will be working to improve the quality of lambda messages, but as a general rule, `cfn-guard-rulegen-lambda` is just a wrapper for the `cfn-guard-rulegen` code and each can be used to test the other.
