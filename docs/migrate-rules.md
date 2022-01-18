# Migrating Guard 1\.0 rules to Guard 2\.0<a name="migrate-rules"></a>

If you have written rules using Guard 1\.0 syntax, we recommend that you migrate them to Guard 2\.0 syntax\. Guard 2\.0 is backward incompatible with Guard 1\.0 rules\. Migrating involves updating the Guard CLI but doesn't require any changes to your rules files themselves\.

## Enhancements in Guard 2\.0<a name="migrate-rules-enhancements"></a>

The enhancements that are available in Guard 2\.0 do the following:
+ Makes Guard general purpose by providing the ability to validate any JSON\- and YAML\-formatted structured data, against policy rules\. You're no longer limited to using only AWS CloudFormation templates\.
+ Adds the Guard [migrate](cfn-guard-migrate.md) CLI command so that you can migrate your Guard 1\.0 rules to Guard 2\.0 syntax\.
+ Adds the Guard [parse\-tree](cfn-guard-parse-tree.md) CLI command so that you can generate a parse tree for the rules defined in a Guard rules file\.
+ Adds the ability to validate additional CloudFormation template sections\. Using Guard 1\.0, you can write rules that validate the `Resources` section of your CloudFormation templates\. Using Guard 2\.0, you can write rules that validate *all* sections of your CloudFormation templates, including the `Description` and `Parameters` sections\.
+ Adds filtering capability so that you can select and further refine your selection of target resources or values against which to evaluate clauses\.
+ Introduces the *query block* feature that you can use to write rules that are more concise than those available with Guard 1\.0\. Using the query block feature, you can group relevant resource type properties together\. For more information about query blocks, see [Query blocks](writing-rules.md#query-blocks)\.
+ Introduces the *named rule* feature, which you can use to assign a name to a set of rules\. Then, you can reference these modular validation blocks, called *named\-rule blocks*, in other rules\. Named\-rule blocks promote reuse, improve composition, and remove verbosity and repetition\. For more information about named\-rule blocks, see [Named\-rule blocks](writing-rules.md#named-rule-blocks)\.
+ Provides the ability to write unit tests and then verify that your rules work as expected using the Guard [Testing Guard rules](testing-rules.md) CLI command\.

## Migrate a Guard rule<a name="migrate-rules-how-to"></a>

To migrate a Guard 1\.0 rule to Guard 2\.0, do the following:
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