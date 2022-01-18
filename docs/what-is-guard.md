# What is AWS CloudFormation Guard?<a name="what-is-guard"></a>

AWS CloudFormation Guard is a policy\-as\-code evaluation tool that is open source and useful for general purposes\. The Guard command line interface \(CLI\) provides you with a declarative domain\-specific language \(DSL\) that you can use to express policy as code\. In addition, you can use CLI commands to validate JSON\- or YAML\-formatted structured data against those rules\. Guard also provides a built\-in unit testing framework to verify that your rules work as intended\.

Guard doesn't validate CloudFormation templates for valid syntax or allowed property values\. You can use the [cfn\-lint](https://github.com/aws-cloudformation/cfn-python-lint) tool to perform a thorough inspection of template structure\.

**Note**  
Guard 2\.0\.3 is the latest version, released in June 2021\. We recommend that you migrate your rules to this version because it has many significant enhancements\. Guard 2\.0 is backward incompatible with Guard 1\.0 rules\. Using Guard 2\.0 together with Guard 1\.0 rules and vice versa can result in breaking changes\. For information about enhancements and migrating your Guard rules, see [Migrating Guard 1\.0 rules to Guard 2\.0](migrate-rules.md)\.

**Topics**
+ [Are you a first\-time Guard user?](#first-time-user)
+ [Features of Guard](#cfn-guard-feature-overview)
+ [Accessing Guard](#acessing-cfn-guard)
+ [Best practices](#best-practices)

## Are you a first\-time Guard user?<a name="first-time-user"></a>

If you're a first\-time user of Guard, we recommend that you begin by reading the following sections:
+  [Setting up Guard](setting-up.md) – This section describes how to install Guard\. With Guard, you can write policy rules using the Guard DSL and validate your JSON\- or YAML\-formatted structured data against those rules\.
+  [Writing Guard rules](writing-rules.md) – This section provides detailed walkthroughs for writing policy rules\.
+  [Testing Guard rules](testing-rules.md) – This section provides a detailed walkthrough for testing your rules to verify that they work as intended, and validating your JSON\- or YAML\-formatted structured data against your rules\. 
+  [Validating input data against Guard rules](validating-rules.md) – This section provides a detailed walkthrough for validating your JSON\- or YAML\-formatted structured data against your rules\. 
+  [Guard CLI reference](cfn-guard-command-reference.md) – This section describes the commands that are available in the Guard CLI\. 

## Features of Guard<a name="cfn-guard-feature-overview"></a>

Using Guard, you can write policy rules to validate any JSON\- or YAML\-formatted structured data against, including but not limited to AWS CloudFormation templates\. Guard supports the entire spectrum of end\-to\-end evaluation of policy checks\. Rules are useful in the following business domains:
+ **Preventative governance and compliance \(shift\-left testing\)** – Validate infrastructure as code \(IaC\) or infrastructure and service compositions against policy rules that represent your organizational best practices for security and compliance\. For example, you can validate CloudFormation templates, CloudFormation change sets, JSON\-based Terraform configuration files, or Kubernetes configurations\.
+ **Detective governance and compliance** – Validate conformity of Configuration Management Database \(CMDB\) resources such as AWS Config\-based configuration items \(CIs\)\. For example, developers can use Guard policies against AWS Config CIs to continuously monitor the state of deployed AWS and non\-AWS resources, detect violations from policies, and start remediation\.
+ **Deployment safety** – Ensure that changes are safe before deployment\. For example, validate CloudFormation change sets against policy rules to prevent changes that result in resource replacement, such as renaming an Amazon DynamoDB table\.

## Accessing Guard<a name="acessing-cfn-guard"></a>

To access the Guard DSL and commands, you must install the Guard CLI\. For information about installing the Guard CLI, see [Setting up Guard](setting-up.md)\.

## Best practices<a name="best-practices"></a>

When you use Guard 2\.0, be aware of the following best practices:
+ [Migrate Guard 1\.0 rules to Guard 2\.0](migrate-rules.md)\.
+ Write simple rules, and use named rules to reference them in other rules\. Complex rules can be difficult to maintain and test\.