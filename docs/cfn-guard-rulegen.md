# rulegen<a name="cfn-guard-rulegen"></a>

Takes a JSON\- or YAML\-formatted AWS CloudFormation template file and autogenerates a set of AWS CloudFormation Guard rules that match the properties of the template resources\. This command is a useful way to get started with rule writing or to create ready\-to\-use rules from known good templates\.

## Syntax<a name="cfn-guard-rulgen-synopsis"></a>

```
cfn-guard rulegen
--output <value>  
--template <value>
```

## Parameters<a name="cfn-guard-rulegen-flags"></a>

`-h`, `--help`

Prints help information\.

`-V`, `--version`

Prints version information\.

## Options<a name="cfn-guard-rulegen-options"></a>

`-o`, `--output`

Writes the generated rules to an output file\. Given the potential for hundreds or even thousands of rules to emerge, we recommend using this option\.

`-t`, `--template`

Provides the path to a CloudFormation template file in JSON or YAML format\.

## Examples<a name="cfn-guard-rulegen-examples"></a>

```
cfn-guard rulegen \
--output output.json \
--template template.json
```