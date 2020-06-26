# [PREVIEW] CloudFormation Guard Rulegen as a Lambda

## Dependencies
* AWS CLI [configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) with permissions to deploy and invoke Lambdas
* An [AWS Lambda Execution Role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) in IAM
* A shell environment variable called `CFN_GUARD_LAMBDA_ROLE_ARN` set to the ARN of that role
* [Rust](https://rustup.rs/)

## To install CloudFormation Guard Rulegen Lambda the first time

1. Clone the cloudformation-guard repo.

1. Ensure `cfn-guard-rulegen` directory is co-located with this folder as CloudFormation Guard Rulegen Lambda depends on the source in that folder.

1.  If you're on a Mac, add the following to `~/.cargo/config`:

```
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
```

1. Run `make pre-reqs`.

1. Run `make install`.

## To build and run post-install

To build, deploy and test the function after you edit its source code, run `make test`.

To merely invoke the function, run `make invoke`.  The variables in the Makefile used to make the calls can be manipulated to provide different payloads.


This project is licensed under the Apache-2.0 License.

We will be working to improve the quality of lambda messages, but as a general rule, `cfn-guard-rulegen-lambda` is just a wrapper for the `cfn-guard-rulegen` code and each can be used to test the other.
