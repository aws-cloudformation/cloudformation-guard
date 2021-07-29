# Validating input data against AWS CloudFormation Guard rules<a name="validating-rules"></a>

You can use the AWS CloudFormation Guard `validate` command to validate data against Guard rules\. For more information about the `validate` command, including its parameters and options, see [validate](cfn-guard-validate.md)\.

## Prerequisites<a name="validating-rules-prerequisites"></a>
+ Write Guard rules to validate your input data against\. For more information, see [Writing Guard rules](writing-rules.md)\.
+ Test your rules to ensure that they work as intended\. For more information, see [Testing Guard rules](testing-rules.md)\.

## Using the `validate` command<a name="validating-rules-walkthrough"></a>

To validate your input data, such as an AWS CloudFormation template, against your Guard rules, run the Guard `validate` command\. For the `--rules` parameter, specify the name of a rules file\. For the `--data` parameter, specify the name of the input data file\.

```
cfn-guard validate \
  --rules rules.guard \
  --data template.json
```

If Guard successfully validates the templates, the `validate` command returns an exit status of `0` \(`$?` in bash\)\. If Guard identifies a rule violation, the `validate` command returns a status report of the rules that failed\. Use the verbose flag \(`-v`\) to see the detailed evaluation tree that shows how Guard evaluated each rule\.

```
Summary Report Overall File Status = PASS
PASS/SKIP rules
default PASS
```

## Validating multiple rules against multiple data files<a name="validating-rules-overview"></a>

To help maintain rules, you can write rules into multiple files and organize the rules as you want\. Then, you can validate multiple rule files against a data file or multiple data files\. The `validate` command can take a directory of files for the `--data` and `--rules` options\. For example, you can run the following command where `/path/to/dataDirectory` contains one or more data files and `/path/to/ruleDirectory` contains one or more rules files\.

```
cfn-guard validate --data /path/to/dataDirectory --rules /path/to/ruleDirectory
```

You can write rules to check whether various resources defined in multiple CloudFormation templates have the appropriate property assignments to guarantee encryption at rest\. For search and maintenance ease, you can have rules for checking encryption at rest in each resource in separate files, called `s3_bucket_encryption.guard`, `ec2_volume_encryption.guard`, and `rds_dbinstance_encrytion.guard` in a directory with the path `~/GuardRules/encryption_at_rest`\. The CloudFormation templates that you need to validate are in a directory with the path `~/CloudFormation/templates`\. In this case, run the `validate` command as follows\.

```
cfn-guard validate --data ~/CloudFormation/templates --rules ~/GuardRules/encryption_at_rest
```