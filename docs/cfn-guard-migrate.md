# migrate<a name="cfn-guard-migrate"></a>

Generates rules in AWS CloudFormation Guard 2\.0 language from rules written using Guard 1\.0 language\.

## Syntax<a name="cfn-guard-migrate-synopsis"></a>

```
cfn-guard migrate
--output <value>
--rules <value>
```

## Parameters<a name="cfn-guard-migrate-flags"></a>

`-h`, `--help`

Prints help information\.

`-V`, `--version`

Prints version information\.

## Options<a name="cfn-guard-migrate-options"></a>

`-o`, `--output`

Writes to an output file\.

`-r`, `--rules`

Provides the name of a rules file\.

## Examples<a name="cfn-guard-migrate-examples"></a>

```
cfn-guard migrate \
--output output.json \
--rules rules.guard
```

## See also<a name="cfn-guard-migrate-see-also"></a>

[Migrating Guard 1\.0 rules to Guard 2\.0](migrate-rules.md)