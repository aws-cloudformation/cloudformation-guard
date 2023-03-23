# AWS CloudFormation Guard 2.0's Modes of Operation

AWS CloudFormation Guard is an open-source general-purpose policy-as-code evaluation tool. It provides developers with a simple-to-use, yet powerful and expressive domain-specific language (DSL) to define policies and enables developers to validate JSON- or YAML- formatted structured data with those policies.

As an example of how to use AWS CloudFormation Guard (cfn-guard), given a CloudFormation template (template.json):

```json
{
    "Resources":{
        "NewVolume":{
            "Type":"AWS::EC2::Volume",
            "Properties":{
                "Size":500,
                "Encrypted":false,
                "AvailabilityZone":"us-west-2b"
            }
        },
        "NewVolume2":{
            "Type":"AWS::EC2::Volume",
            "Properties":{
                "Size":100,
                "Encrypted":false,
                "AvailabilityZone":"us-west-2c"
            }
        }
    },
    "Parameters":{
        "InstanceName":"NewInstance"
    }
}
```

And a rules file (rules.guard):

```
# Create a variable named 'aws_ec2_volume_resources' that selects all resources of type "AWS::EC2::Volume"
# in the input resource template
let aws_ec2_volume_resources = Resources.*[ Type == 'AWS::EC2::Volume' ]

# Create a rule named aws_template_parameters for validation in the "Parameters" section of the template
rule aws_template_parameters {
    Parameters.InstanceName == "TestInstance"
}

# Create a rule named aws_ec2_volume that filters on "AWS::EC2::Volume" type being present in the template
rule aws_ec2_volume when %aws_ec2_volume_resources !empty {
    %aws_ec2_volume_resources.Properties.Encrypted == true
    %aws_ec2_volume_resources.Properties.Size IN [50, 500]
    %aws_ec2_volume_resources.Properties.AvailabilityZone IN ["us-west-2c", "us-west-2b"]
}
```

You can check the compliance of template.json with rules.guard:

```bash
$ ./cfn-guard validate --data template.json --rules rules.guard
_Summary Report_ Overall File Status = FAIL
PASS/SKIP rules
FAILED rules
aws_template_parameters FAIL
aws_ec2_volume FAIL
```

We designed `cfn-guard` to be plugged into your build processes.

If CloudFormation Guard validates the templates successfully, it gives you an exit status (`$?` in bash) of `0`. If CloudFormation Guard identifies a rule violation, it gives you a status report of the rules that failed.
Use the verbose flag `-v` to see the detailed evaluation tree that shows how CloudFormation Guard evaluated each rule.

## Modes of Operation

`cfn-guard` has five modes of operation:


### Validate

`validate` (like the example above) validates data against rules.

```bash
cfn-guard-validate
Evaluates rules against the data files to determine success or failure.
You can point rules flag to a rules directory and point data flag to a data directory.
When pointed to a directory it will read all rules in the directory file and evaluate
them against the data files found in the directory. The command can also point to a
single file and it would work as well.
Note - When pointing the command to a directory, the directory may not contain a mix of
rules and data files. The directory being pointed to must contain only data files,
or rules files.

USAGE:
    cfn-guard validate [FLAGS] [OPTIONS] --rules <rules>

FLAGS:
    -a, --alphabetical            Validate files in a directory ordered alphabetically
    -h, --help                    Prints help information
    -m, --last-modified           Validate files in a directory ordered by last modified times
    -p, --print-json              Print output in json format
    -s, --show-clause-failures    Show clause failure along with summary
    -V, --version                 Prints version information
    -v, --verbose                 Verbose logging

OPTIONS:
    -d, --data <data>      Provide a file or dir for data files in JSON or YAML
    -r, --rules <rules>    Provide a rules file or a directory of rules files

```

### Rulegen

`rulegen` takes a JSON- or YAML-formatted CloudFormation template file and autogenerates a set of `cfn-guard` rules that match the properties of its resources. This is a useful way to get started with rule-writing or just create ready-to-use rules from known-good templates.

```bash
cfn-guard-rulegen
Autogenerate rules from an existing JSON- or YAML- formatted data. (Currently works with only CloudFormation templates)

USAGE:
    cfn-guard rulegen [OPTIONS] --template <template>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <output>        Write to output file
    -t, --template <template>    Provide path to a CloudFormation template file in JSON or YAML
```
For example, using the same template (template.json) from the above example:

```bash
$ cfn-guard rulegen --data template.json
let aws_ec2_volume_resources = Resources.*[ Type == 'AWS::EC2::Volume' ]
rule aws_ec2_volume when %aws_ec2_volume_resources !empty {
    %aws_ec2_volume_resources.Properties.Size IN [500, 100]
    %aws_ec2_volume_resources.Properties.AvailabilityZone IN ["us-west-2b", "us-west-2c"]
    %aws_ec2_volume_resources.Properties.Encrypted == false
}
```

Given the potential for hundreds or even thousands of rules to emerge, we recommend using the `--output` flag to write the generated rules to a file:

```
cfn-guard rulegen --data template.json --output rules.guard
```

### Migrate

`migrate` command generates rules in the new AWS Cloudformation Guard 2.0 syntax from rules written using 1.0 language.

```bash
cfn-guard-migrate
Migrates 1.0 rules to 2.0 compatible rules.

USAGE:
    cfn-guard migrate [OPTIONS] --rules <rules>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <output>    Write migrated rules to output file
    -r, --rules <rules>      Provide a rules file
```

For example for rules written in the 1.0 language (example.ruleset) as:

```bash
let encryption_flag = true

AWS::EC2::Volume Encrypted == %encryption_flag
AWS::EC2::Volume Size <= 100
```

The equivalent rules in the 2.0 language can be generated using the migrate command as:

```bash
$ cfn-guard migrate --rules example.ruleset
rule migrated_rules {
    let aws_ec2_volume = Resources.*[ Type == "AWS::EC2::Volume" ]

    let encryption_flag = true

    %aws_ec2_volume.Properties.Encrypted == %encryption_flag
    %aws_ec2_volume.Properties.Size <= 100
}
```

### Parse Tree

`parse-tree` command generates a parse tree for the rules defined in a rules file. Use the `--output` flag to write the generated tree to a file.

```bash
cfn-guard-parse-tree
Prints out the parse tree for the rules defined in the file.

USAGE:
    cfn-guard parse-tree [FLAGS] [OPTIONS]

FLAGS:
    -h, --help          Prints help information
    -j, --print-json    Print output in json format
    -y, --print-yaml    Print output in json format
    -V, --version       Prints version information

OPTIONS:
    -o, --output <output>    Write to output file
    -r, --rules <rules>      Provide a rules file
```

### Test

Use the `test` command to write unit tests in JSON or YAML format for your rules

```bash
cfn-guard-test
Built in unit testing capability to validate a Guard rules file against
unit tests specified in YAML format to determine each individual rule's success
or failure testing.

USAGE:
    cfn-guard test [FLAGS] --rules-file <rules-file> --test-data <test-data> [alphabetical]

FLAGS:
    -h, --help             Prints help information
    -m, --last-modified    Sort by last modified times within a directory
    -V, --version          Prints version information
    -v, --verbose          Verbose logging

OPTIONS:
    -r, --rules-file <rules-file>    Provide a rules file
    -t, --test-data <test-data>      Provide a file or dir for data files in JSON or YAML

ARGS:
    <alphabetical>    Sort alphabetically inside a directory
```

For example, given a rules file (rules.guard) as:

```bash
rule assert_all_resources_have_non_empty_tags {
    when Resources.* !empty {
        Resources.*.Properties.Tags !empty
    }
}
```

You can write a YAML-formatted unit test file (test.yml) as:

```yaml
---
- input:
    Resources: {}
   expectations:
   rules:
     assert_all_resources_have_non_empty_tags: SKIP
- input:
  Resources:
    nonCompliant:
      Type: Consoto::Network::VPC
      Properties: {}
  expectations:
  rules:
    assert_all_resources_have_non_empty_tags: FAIL
```

You can then test your rules file using the `test` command as:

```bash
$ cfn-guard test -r rules.guard -t test.yml
PASS Expected Rule = assert_all_resources_have_non_empty_tags, Status = SKIP, Got Status = SKIP
PASS Expected Rule = assert_all_resources_have_non_empty_tags, Status = FAIL, Got Status = FAIL
