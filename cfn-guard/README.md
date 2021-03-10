# CFN Guard CLI Tool

[docs](docs/guard.md)


## Commands

### Validate

Main validation command. Used to validate a template/json/yaml file against a guard ruleset. For information on writing rules, refer to the [rule syntax section](docs/language-syntax.md)
```
cfn-guard validate --rules path/to/ruleset.guard --data cloudformation/template.json [--verbose]
```

### Parse tree
Used to parse guard rulesets to see if they are parseable by the tool and their structure. Mostly meant to ensure rules you are crafting have the correct behavior.

```
cfn-guard parse-tree --rules path/to/ruleset.guard --output output-file.json
```


### Rulegen
Used to generate rules from known good templates. Provide a CloudFormation template, and rulegen handles generating a ruleset based on the properties in the template.

```
cfn-guard rulegen --template path/to/template.json --output rules.guard
```

### Migrate
Used to migrate old rulesets to the 2.0 ruleset language. Old rulesets are compatible with the 1.0 version to the tool [here](https://github.com/aws-cloudformation/cloudformation-guard). Rules are validates before writing to ensure anything migrated is actually parseable.

```
cfn-guard migrate --rules old/ruleset.guard --output new-rules.guard
```
