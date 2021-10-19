# validate<a name="cfn-guard-validate"></a>

Validates data against AWS CloudFormation Guard rules to determine success or failure\.

## Syntax<a name="cfn-guard-validate-synopsis"></a>

```
cfn-guard validate
--data <value>
--output-format <value>
--rules <value>
--show-summary <value>
--type <value>
```

## Parameters<a name="cfn-guard-validate-flags"></a>

`-a`, `--alphabetical`

Validates files in a directory that is ordered alphabetically\.

`-h`, `--help`

Prints help information\.

`-m`, `--last-modified`

Validates files in a directory that is ordered by last\-modified times\.

`-P`, `--payload`

Allows you to provide rules and data in the following JSON format via `stdin`:

```
{"rules":["<rules 1>", "<rules 2>", ...], "data":["<data 1>", "<data 2>", ...]}
```

For example:

```
{"data": ["{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}","{\"Resources\":{\"NewVolume\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":500,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2b\"}},\"NewVolume2\":{\"Type\":\"AWS::EC2::Volume\",\"Properties\":{\"Size\":50,\"Encrypted\":false,\"AvailabilityZone\":\"us-west-2c\"}}},\"Parameters\":{\"InstanceName\":\"TestInstance\"}}"], "rules" : [ "Parameters.InstanceName == \"TestInstance\"","Parameters.InstanceName == \"TestInstance\"" ]}
```

For "rules", specify a string list of rules files\. For "data", specify a string list of data files\.

If you specify the `--payload` flag, don't specify the `--rules` or `--data` options\.

`-p`, `--print-json`

Prints the output in JSON format\.

`-s`, `--show-clause-failures`

Shows clause failure including a summary\.

`-V`, `--version`

Prints version information\.

`-v`, `--verbose`

Increases the output verbosity\. Can be specified multiple times\.

## Options<a name="cfn-guard-validate-options"></a>

`-d`, `--data` \(string\)

Provides the name of a file or directory for data files in either JSON or YAML format\. If you provide a directory, Guard evaluates the specified rules against all data files in the directory\. The directory must contain only data files; it cannot contain both data and rules files\.

If you specify the `--payload` flag, don't specify the `--data` option\.

`-o`, `--output-format` \(string\)

Writes to an output file\.

*Default*: `single-line-summary`

*Allowed values*: `json` \| `yaml` \| `single-line-summary`

`-r`, `--rules` \(string\)

Provides the name of a rules file or a directory of rules files\. If you provide a directory, Guard evaluates all rules in the directory against the specified data\. The directory must contain only rules files; it cannot contain both data and rules files\.

If you specify the `--payload` flag, do not specify the `--rules` option\.

`--show-summary` \(string\)

Specifies the verbosity of the Guard rule evaluation summary\. If you specify `all`, Guard displays the full summary\. If you specify `pass,fail`, Guard only displays summary information for rules that passed or failed\. If you specify `none`, Guard does not display summary information\. By default, `all` is specified\. 

*Allowed values*: `all` \| `pass,fail` \| `none`

`-t`, `--type` \(string\)

Provides the format of your input data\. When you specify the input data type, Guard displays the logical names of CloudFormation template resources in the output\. By default, Guard displays property paths and values, such as `Property [/Resources/vol2/Properties/Encrypted`\.

*Allowed values*: `CFNTemplate`

## Examples<a name="cfn-guard-validate-examples"></a>

```
cfn-guard validate \
--data file_directory_name \
--output-format yaml \
--rules rules.guard \
--show-summary pass,fail \
--type CFNtemplate
```

## Output<a name="cfn-guard-validate-output"></a>

If Guard successfully validates the templates, the `validate` command returns an exit status of `0` \(`$?` in bash\)\. If Guard identifies a rule violation, the `validate` command returns a status report of the rules that failed\. Use the verbose flag \(`-v`\) to see the detailed evaluation tree that shows how Guard evaluated each rule\.

```
Summary Report Overall File Status = PASS
PASS/SKIP rules
default PASS
```

## See also<a name="cfn-guard-validate-see-also"></a>

[Validating input data against Guard rules](validating-rules.md)