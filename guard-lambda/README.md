# AWS CloudFormation Guard as a Lambda

The Lambda version of the tool is a lightweight wrapper around the core [cfn-guard](../guard) code that can simply be invoked as a Lambda.

## Table of Contents

* [Installation](#installation)
* [FAQs](#faqs)

## Installation

For information about installing Guard as an AWS Lambda function, building and running Guard as a Lambda function, and calling the Lambda function request structure, see [Install Guard as an AWS Lambda function](docs/setting-up-lambda.md).

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
