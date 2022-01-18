# AWS CloudFormation Guard User Guide

-----
*****Copyright &copy; Amazon Web Services, Inc. and/or its affiliates. All rights reserved.*****

-----
Amazon's trademarks and trade dress may not be used in 
     connection with any product or service that is not Amazon's, 
     in any manner that is likely to cause confusion among customers, 
     or in any manner that disparages or discredits Amazon. All other 
     trademarks not owned by Amazon are the property of their respective
     owners, who may or may not be affiliated with, connected to, or 
     sponsored by Amazon.

-----
## Contents
+ [What is AWS CloudFormation Guard?](what-is-guard.md)
+ [Setting up AWS CloudFormation Guard](setting-up.md)
   + [Installing AWS CloudFormation Guard](installing-cfn-guard-cli.md)
      + [Installing Guard (Linux, macOS, or Unix)](setting-up-linux.md)
      + [Installing Guard (Windows)](setting-up-windows.md)
   + [Installing Guard as an AWS Lambda function](setting-up-lambda.md)
+ [Getting started with AWS CloudFormation Guard](getting-started.md)
   + [Migrating Guard 1.0 rules to Guard 2.0](migrate-rules.md)
   + [Writing AWS CloudFormation Guard rules](writing-rules.md)
      + [Defining queries and filtering](query-and-filtering.md)
      + [Assigning and referencing variables in AWS CloudFormation Guard rules](variables.md)
      + [Composing named-rule blocks in AWS CloudFormation Guard](named-rule-block-composition.md)
      + [Writing clauses to perform context-aware evaluations](context-aware-evaluations.md)
   + [Testing AWS CloudFormation Guard rules](testing-rules.md)
   + [Validating input data against AWS CloudFormation Guard rules](validating-rules.md)
+ [Troubleshooting AWS CloudFormation Guard](troubleshooting.md)
+ [AWS CloudFormation Guard CLI command reference](cfn-guard-command-reference.md)
   + [Global parameters](cfn-guard-global-parameters.md)
   + [migrate](cfn-guard-migrate.md)
   + [parse-tree](cfn-guard-parse-tree.md)
   + [rulegen](cfn-guard-rulegen.md)
   + [test](cfn-guard-test.md)
   + [validate](cfn-guard-validate.md)
+ [Security in AWS CloudFormation Guard](security.md)
+ [Document history](doc-history.md)
+ [AWS glossary](glossary.md)