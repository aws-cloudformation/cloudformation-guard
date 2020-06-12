# [PREVIEW] CloudFormation Guard as a Lambda

The Lambda version of the tool is a lightweight wrapper around the core [cfn-guard](../cfn-guard) code that can simply be invoked as a Lambda.

The primary interface for building and deploying the tool is the [Makefile](Makefile).  Examples for the payload it expects can be found there.

## Dependencies
* AWS CLI [configured](https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html) with permissions to deploy and invoke Lambdas
* An [AWS Lambda Execution Role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html) in IAM
* A shell environment variable called `CFN_GUARD_LAMBDA_ROLE_ARN` set to the ARN of that role
* [Rust](https://rustup.rs/) (See the installation instructions in the [top-level README](../README.md#install-rust))
* If building on a Mac, you'll need [Homebrew](https://brew.sh/).  
* If building on Ubuntu, you'll need to run `sudo apt-get update; sudo apt install build-essential` if you haven't already

## To install CloudFormation Guard Lambda the first time

If you're on a Mac, add the following to `~/.cargo/config`:

```
[target.x86_64-unknown-linux-musl]
linker = "x86_64-linux-musl-gcc"
```
1. Ensure you're in the `cfn-guard-lambda` directory
1. Run `make pre-reqs`.
1. Run `make install`.

## To build and run post-install

To build, deploy and test the function after you edit its source code, run `make test`.

To merely invoke the function, run `make invoke`.  The variables in the Makefile used to make the calls can be manipulated to provide different payloads.

In either case, the Lambda Function will be invoked multiple times.  Once each for testing `FAIL`, `PASS` and `ERR` exits:

```
$> make test
This is a Darwin machine...
env PKG_CONFIG_ALLOW_CROSS=1 cargo build --release --target x86_64-unknown-linux-musl
    Finished release [optimized] target(s) in 0.16s
cp target/x86_64-unknown-linux-musl/release/cfn-guard-lambda ./bootstrap
chmod +x bootstrap
zip lambda.zip bootstrap
  adding: bootstrap (deflated 67%)
aws lambda update-function-code --function-name cfn-guard-lambda --zip-file fileb://./lambda.zip
{
    "FunctionName": "cfn-guard-lambda",
    "FunctionArn": "arn:aws:lambda:us-east-1:XXXXXX:function:cfn-guard-lambda",
    "Runtime": "provided",
    "Role": "arn:aws:iam::XXXXXX:role/no_perm_lambda_execution",
    "Handler": "doesnt.matter",
    "CodeSize": 2559030,
    "Description": "",
    "Timeout": 3,
    "MemorySize": 128,
    "LastModified": "2020-06-15T16:29:06.473+0000",
    "CodeSha256": "LaO7ei8FE+M5PD0Y+CyBFtSQ9s0An4Xy1uY/Q+u+Rwc=",
    "Version": "$LATEST",
    "Environment": {
        "Variables": {
            "RUST_BACKTRACE": "1"
        }
    },
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "20ff5af0-dbff-4142-b61b-a6770b8ca268",
    "State": "Active",
    "LastUpdateStatus": "Successful"
}
aws lambda invoke --function-name cfn-guard-lambda --payload '{ "template": "{\n    \"Resources\": {\n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}", "ruleSet": "let require_encryption = true\nlet disallowed_azs = [us-east-1a,us-east-1b,us-east-1c]\n\nAWS::EC2::Volume AvailabilityZone NOT_IN %disallowed_azs\nAWS::EC2::Volume Encrypted != %require_encryption\nAWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99\nAWS::IAM::Role AssumeRolePolicyDocument.Version == 2012-10-18\nAWS::EC2::Volume Lorem == true\nAWS::EC2::Volume Encrypted == %ipsum\nAWS::EC2::Volume AvailabilityZone != /us-east-.*/", "strict_checks": true}' output.json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
cat output.json | jq '.'
{
  "message": [
    "[NewVolume2] failed because [AvailabilityZone] is [us-east-1b] and the pattern [us-east-.*] is not permitted",
    "[NewVolume2] failed because [Encrypted] is [true] and that value is not permitted",
    "[NewVolume2] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]",
    "[NewVolume2] failed because it does not contain the required property of [Lorem]",
    "[NewVolume2] failed because there is no value defined for [%ipsum] to check [Encrypted] against",
    "[NewVolume] failed because [AvailabilityZone] is [us-east-1b] and the pattern [us-east-.*] is not permitted",
    "[NewVolume] failed because [Encrypted] is [true] and that value is not permitted",
    "[NewVolume] failed because [Size] is [100] and the permitted value is [101]",
    "[NewVolume] failed because [Size] is [100] and the permitted value is [99]",
    "[NewVolume] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]",
    "[NewVolume] failed because it does not contain the required property of [Lorem]",
    "[NewVolume] failed because there is no value defined for [%ipsum] to check [Encrypted] against"
  ],
  "exit_status": "FAIL"
}
aws lambda invoke --function-name cfn-guard-lambda --payload '{ "template": "{\n    \"Resources\": {\n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}", "ruleSet": "let require_encryption = true", "strict_checks": true}' output.json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
cat output.json | jq '.'
{
  "message": [],
  "exit_status": "PASS"
}
aws lambda invoke --function-name cfn-guard-lambda --payload '{ "template": "{\n    \"Resources\": \n        \"NewVolume\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 100,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        },\n        \"NewVolume2\" : {\n            \"Type\" : \"AWS::EC2::Volume\",\n            \"Properties\" : {\n                \"Size\" : 99,\n                \"Encrypted\": true,\n                \"AvailabilityZone\" : \"us-east-1b\"\n            }\n        } }\n}", "ruleSet": "let require_encryption = true", "strict_checks": true}' output.json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
cat output.json | jq '.'
{
  "message": [
    "ERROR:  Template file format was unreadable as json or yaml: while parsing a flow mapping, did not find expected ',' or '}' at line 3 column 21"
  ],
  "exit_status": "ERR"
}
```

## FAQ

* **Q: How do I troubleshoot a lambda call returning an opaque error message like:**
	
	```
	{"errorType": "Runtime.ExitError", "errorMessage": "RequestId: 1c0c0620-0f83-40bc-8eca-3cf2cf24820f Error: Runtime exited with error: exit status 101"}
	```

* **A: Run the same rule set and template locally with `cfn-guard` to get a better message:**

	```
	thread 'main' panicked at 'Bad Rule Operator: REQUIRE', src/rule_proc.rs:344:2
	```
	
	We will be working to improve the quality of lambda messages, but as a general rule, `cfn-guard-lambda` is just a wrapper for the `cfn-guard` code and each can be used to test the other.

