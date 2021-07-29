# parse\-tree<a name="cfn-guard-parse-tree"></a>

Generates a parse tree for the AWS CloudFormation Guard rules defined in a rules file\.

## Syntax<a name="cfn-guard-parse-tree-synopsis"></a>

```
cfn-guard parse-tree 
--output <value>
--rules <value>
```

## Parameters<a name="cfn-guard-parse-tree-flags"></a>

`-h`, `--help`

Prints help information\.

`-j`, `--print-json`

Prints the output in JSON format\.

`-y`, `--print-yaml`

Prints the output in YAML format\.

`-V`, `--version`

Prints version information\.

## Options<a name="cfn-guard-parse-tree-options"></a>

`-o`, `--output`

Writes the generated tree to an output file\.

`-r`, `--rules`

Provides a rules file\.

## Examples<a name="cfn-guard-parse-tree-examples"></a>

```
cfn-guard parse-tree \
--output output.json \
--rules rules.guard
```