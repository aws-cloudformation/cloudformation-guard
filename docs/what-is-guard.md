# What is AWS CloudFormation Guard?<a name="what-is-guard"></a>

AWS CloudFormation Guard is a policy\-as\-code evaluation tool that is open source and useful for general purposes\. The Guard command line interface \(CLI\) provides you with a declarative domain\-specific language \(DSL\) that you can use to express policy as code\. In addition, you can use CLI commands to validate JSON\- or YAML\-formatted structured data against those rules\. Guard also provides a built\-in unit testing framework to verify that your rules work as intended\.

**Note**  
Guard 2\.0\.3 is the latest version, released in June 2021\. We recommend that you migrate your rules to this version because it has many significant enhancements\. Guard 2\.0 is backward incompatible with Guard 1\.0 rules\. Using Guard 2\.0 together with Guard 1\.0 can result in breaking changes\. For information about enhancements and migrating your Guard rules, see [Migrating Guard 1\.0 rules to Guard 2\.0](#migrate-rules)\.

**Topics**
+ [Are you a first\-time Guard user?](#first-time-user)
+ [Features of Guard](#servicename-feature-overview)
+ [Accessing Guard](#acessing-servicename)
+ [Best practices](#best-practices)
+ [Considerations when using Guard](#considerations)
+ [Migrating Guard 1\.0 rules to Guard 2\.0](#migrate-rules)

## Are you a first\-time Guard user?<a name="first-time-user"></a>

If you're a first\-time user of Guard, we recommend that you begin by reading the following sections:
+  [Setting up Guard](setting-up.md) – This section describes how to install Guard\. With Guard, you can write policy rules using the Guard DSL and validate your JSON\- or YAML\-formatted structured data against those rules\.
+  [Writing Guard rules](writing-rules.md) – This section provides detailed walkthroughs for writing policy rules\.
+  [Testing Guard rules](testing-rules.md) – This section provides a detailed walkthrough for testing your rules to verify that they work as intended, and validating your JSON\- or YAML\-formatted structured data against your rules\. 
+  [Validating input data against Guard rules](validating-rules.md) – This section provides a detailed walkthrough for validating your JSON\- or YAML\-formatted structured data against your rules\. 
+  [Guard CLI reference](cfn-guard-command-reference.md) – This section describes the commands that are available in the Guard CLI\. 

## Features of Guard<a name="servicename-feature-overview"></a>

Using Guard, you can write policy rules to validate any JSON\- or YAML\-formatted structured data against, including but not limited to AWS CloudFormation templates\. Guard supports the entire spectrum of end\-to\-end evaluation of policy checks\. Rules are useful in the following business domains:
+ **Preventative governance and compliance \(shift\-left testing\)** – Validate infrastructure as code \(IaC\) or infrastructure and service compositions against policy rules that represent your organizational best practices for security and compliance\. For example, you can validate CloudFormation templates, CloudFormation change sets, JSON\-based Terraform configuration files, or Kubernetes configurations\.
+ **Detective governance and compliance** – Validate conformity of Configuration Management Database \(CMDB\) resources such as AWS Config\-based configuration items \(CIs\)\. For example, developers can use Guard policies against AWS Config CIs to continuously monitor the state of deployed AWS and non\-AWS resources, detect violations from policies, and start remediation\.
+ **Deployment safety** – Ensure that changes are safe before deployment\. For example, validate CloudFormation change sets against policy rules to prevent changes that result in resource replacement, such as renaming an Amazon DynamoDB table\.

## Accessing Guard<a name="acessing-servicename"></a>

To access the Guard DSL and commands, you must install the Guard CLI\. For information about installing the Guard CLI, see [Setting up Guard](setting-up.md)\.

## Best practices<a name="best-practices"></a>

When you use Guard 2\.0, be aware of the following best practices:
+ Write rules in Guard 2\.0 syntax, and [migrate rules written in Guard 1\.0 syntax to Guard 2\.0](#migrate-rules)\.
+ Write simple rules, and use named rules to reference them in other rules\. Complex rules can be difficult to maintain and test\.

## Considerations when using Guard<a name="considerations"></a>

When you use Guard 2\.0, here are some considerations to keep in mind:
+ Guard doesn't validate CloudFormation templates for valid syntax or allowed property values\. You can use the [cfn\-lint](https://github.com/aws-cloudformation/cfn-python-lint) tool to perform a thorough inspection of template structure\.
+ Your unit test file must have one of the following extensions: `.json`, `.JSON`, `.jsn`, `.yaml`, `.YAML`, or `.yml`\. For more information about unit testing for Guard rules, see [Testing Guard rules](testing-rules.md)\.

## Migrating Guard 1\.0 rules to Guard 2\.0<a name="migrate-rules"></a>

If you have written rules using Guard 1\.0 syntax, we recommend that you migrate them to Guard 2\.0 syntax\. Migrating involves updating the Guard CLI but doesn't require any changes to your rules files themselves\.

### Enhancements in Guard 2\.0<a name="migrate-rules-enhancements"></a>

The enhancements that are available in Guard 2\.0 do the following:
+ Makes Guard general purpose by providing the ability to validate any JSON\- and YAML\-formatted structured data, against policy rules\. You're no longer limited to using only AWS CloudFormation templates,
+ Adds the Guard [migrate](cfn-guard-migrate.md) CLI command so that you can migrate your Guard 1\.0 rules to Guard 2\.0 syntax\.
+ Adds the Guard [parse\-tree](cfn-guard-parse-tree.md) CLI command so that you can generate a parse tree for the rules defined in a Guard rules file\.
+ Adds the ability to validate additional CloudFormation template sections\. Using Guard 1\.0, you can write rules that validate the `Resources` section of your CloudFormation templates\. Using Guard 2\.0, you can write rules that validate *all* sections of your CloudFormation templates, including the `Description` and `Parameters` sections\.
+ Adds filtering capability so that you can select and further refine your selection of target resources or values against which to evaluate clauses\.
+ Introduces the *query block* feature that you can use to write rules that are more concise than those available with Guard 1\.0\. Using the query block feature, you can group relevant resource type properties together\. For more information about query blocks, see [Query blocks](writing-rules.md#query-blocks)\.
+ Introduces the *named rule* feature, which you can use to assign a name to a set of rules\. Then, you can reference these modular validation blocks, called *named\-rule blocks*, in other rules\. Named\-rule blocks promote reuse, improve composition, and remove verbosity and repetition\. For more information about named\-rule blocks, see [Named\-rule blocks](writing-rules.md#named-rule-blocks)\.
+ Provides the ability to write unit tests and then verify that your rules work as expected using the Guard [Testing Guard rules](testing-rules.md) CLI command\.

### Migrate a Guard rule<a name="migrate-rules-how-to"></a>

Migrating a Guard 1\.0 rule to Guard 2\.0 is straightforward, as shown in the following procedure and examples\.
+ Run the `migrate` command\. 

  In the following example, for the `--rules` parameter, we specify the name of a Guard 1\.0 rules file as `rules.guard`\. For the `--output` parameter, we specify the file name `migrated_rules.guard`\. Guard creates `migrated_rules.guard` and then writes the migrated rules to this file\.

  ```
  cfn-guard migrate 
   --output migrated_rules.guard
   --rules rules.guard
  ```

  The following are the contents of the `rules.guard` file, which is written in Guard 1\.0 syntax\.

  ```
  let encryption_flag = true
       
  AWS::EC2::Volume Encrypted == %encryption_flag
  AWS::EC2::Volume Size <= 100
  ```

  After we run `migrate` on the `rules.guard` file, `migrated_rules.guard` contains the following rules, which are written in Guard 2\.0 syntax\.

  ```
  rule migrated_rules {
      let aws_ec2_volume = Resources.*[ Type == "AWS::EC2::Volume" ]
   
      let encryption_flag = true
   
      %aws_ec2_volume.Properties.Encrypted == %encryption_flag
      %aws_ec2_volume.Properties.Size <= 100
  }
  ```