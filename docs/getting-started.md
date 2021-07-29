# Getting started with AWS CloudFormation Guard<a name="getting-started"></a>

This section demonstrates how you can complete the core Guard tasks of writing, testing, and validating rules against JSON\- or YAML\-formatted structured data\. In addition, it contains detailed walkthroughs that demonstrate writing rules that respond to specific use cases\.

**Topics**
+ [Prerequisites](#getting-started-prerequisites)
+ [Overview of using Guard rules](#getting-started-overview)
+ [Writing AWS CloudFormation Guard rules](writing-rules.md)
+ [Testing AWS CloudFormation Guard rules](testing-rules.md)
+ [Validating input data against AWS CloudFormation Guard rules](validating-rules.md)

## Prerequisites<a name="getting-started-prerequisites"></a>

Before you can write policy rules using the Guard domain\-specific language \(DSL\), you must install the Guard command line interface \(CLI\)\. For more information, see [Setting up Guard](setting-up.md)\.

## Overview of using Guard rules<a name="getting-started-overview"></a>

When using Guard, you typically perform the following steps:

1. Write JSON\- or YAML\-formatted structured data to validate\.

1. Write Guard policy rules\. For more information, see [Writing Guard rules](writing-rules.md)\.

1. Verify that your rules work as intended by using the Guard `test` command\. For more information about unit testing, see [Testing Guard rules](testing-rules.md)\.

1. Use the Guard `validate` command to validate your JSON\- or YAML\-formatted structured data against your rules\. For more information, see [Validating input data against Guard rules](validating-rules.md)\.