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

`-o`, `--output-format` \(string\)

Writes to an output file\.

*Allowed values*: `json` \| `yaml` \| `single-line-summary`

`-r`, `--rules` \(string\)

Provides the name of a rules file or a directory of rules files\. If you provide a directory, Guard evaluates all rules in the directory against the specified data\. The directory must contain only rules files; it cannot contain both data and rules files\.

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