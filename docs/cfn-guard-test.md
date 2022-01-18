# test<a name="cfn-guard-test"></a>

Validates an AWS CloudFormation Guard rules file against a Guard unit testing file in JSON or YAML format to determine the success of individual rules\.

## Syntax<a name="cfn-guard-test-synopsis"></a>

```
cfn-guard test 
--rules-file <value>
--test-data <value>
```

## Parameters<a name="cfn-guard-test-flags"></a>

`-h`, `--help`

Prints help information\.

`-m`, `--last-modified`

Sorts by last\-modified times within a directory

`-V`, `--version`

Prints version information\.

`-v`, `--verbose`

Increases the output verbosity\. Can be specified multiple times\.

The verbose output follows the structure of the Guard rules file\. Every block in the rules file is a block in the verbose output\. The top\-most block is each rule\. If there are `when` conditions against the rule, they appear as a sibling condition block\.

## Options<a name="cfn-guard-test-options"></a>

`-r`, `--rules-file`

Provides the name of a rules file\.

`-t`, `--test-data`

Provides the name of a file or directory for data files in either JSON or YAML format\.

## args<a name="cfn-guard-test-args"></a>

<alphabetical>

Sorts alphabetically inside a directory\.

## Examples<a name="cfn-guard-test-examples"></a>

```
cfn-guard test \
--rules rules.guard \
--test-data rules_tests.json
```

## Output<a name="cfn-guard-test-output"></a>

```
PASS|FAIL Expected Rule = rule_name, Status = SKIP|FAIL|PASS, Got Status = SKIP|FAIL|PASS
```

## See also<a name="cfn-guard-test-see-also"></a>

[Testing Guard rules](testing-rules.md)