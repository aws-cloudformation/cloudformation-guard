# AWS CloudFormation Guard 2.0's Modes of Operation

AWS CloudFormation Guard is an open-source general-purpose policy-as-code evaluation tool. It provides developers with a simple-to-use, yet powerful and expressive domain-specific language (DSL) to define policies and enables developers to validate JSON- or YAML- formatted structured data with those policies.

As an example of how to use AWS CloudFormation Guard (cfn-guard), given a CloudFormation template (template.json):

```json
{
  "Resources": {
    "NewVolume": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Size": 500,
        "Encrypted": false,
        "AvailabilityZone": "us-west-2b"
      }
    },
    "NewVolume2": {
      "Type": "AWS::EC2::Volume",
      "Properties": {
        "Size": 100,
        "Encrypted": false,
        "AvailabilityZone": "us-west-2c"
      }
    }
  },
  "Parameters": {
    "InstanceName": "NewInstance"
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

````bash
Usage: cfn-guard validate [OPTIONS] <--rules [<rules>...]|--payload>

Options:
  -r, --rules [<rules>...]
          Provide a rules file or a directory of rules files. Supports passing multiple values by using this option repeatedly.
          Example:
           --rules rule1.guard --rules ./rules-dir1 --rules rule2.guard
          For directory arguments such as `rules-dir1` above, scanning is only supported for files with following extensions: .guard, .ruleset
  -d, --data [<data>...]
          Provide a data file or directory of data files in JSON or YAML. Supports passing multiple values by using this option repeatedly.
          Example:
           --data template1.yaml --data ./data-dir1 --data template2.yaml
          For directory arguments such as `data-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template
  -i, --input-parameters [<input-parameters>...]
          Provide a data file or directory of data files in JSON or YAML that specifies any additional parameters to use along with data files to be used as a combined context. All the parameter files passed as input get merged and this combined context is again merged with each file passed as an argument for `data`. Due to this, every file is expected to contain mutually exclusive properties, without any overlap. Supports passing multiple values by using this option repeatedly.
          Example:
           --input-parameters param1.yaml --input-parameters ./param-dir1 --input-parameters param2.yaml
          For directory arguments such as `param-dir1` above, scanning is only supported for files with following extensions: .yaml, .yml, .json, .jsn, .template
  -t, --type <type>
          Specify the type of data file used for improved messaging - ex: CFNTemplate [possible values: CFNTemplate]
  -o, --output-format <output-format>
          Specify the format in which the output should be displayed [default: single-line-summary] [possible values: json, yaml, single-line-summary]
  -E, --previous-engine
          Uses the old engine for evaluation. This parameter will allow customers to evaluate old changes before migrating
  -S, --show-summary <show-summary>
          Controls if the summary table needs to be displayed. --show-summary fail (default) or --show-summary pass,fail (only show rules that did pass/fail) or --show-summary none (to turn it off) or --show-summary all (to show all the rules that pass, fail or skip) [default: fail] [possible values: none, all, pass, fail, skip]
  -s, --show-clause-failures
          Show clause failure along with summary
  -a, --alphabetical
          Validate files in a directory ordered alphabetically
  -m, --last-modified
          Validate files in a directory ordered by last modified times
  -v, --verbose
          Verbose logging
  -p, --print-json
          Print output in json format
  -P, --payload
          Provide rules and data in the following JSON format via STDIN,
          {"rules":["<rules 1>", "<rules 2>", ...], "data":["<data 1>", "<data 2>", ...]}, where,
          - "rules" takes a list of string version of rules files as its value and
          - "data" takes a list of string version of data files as it value.
          When --payload is specified --rules and --data cannot be specified.
  -z, --structured
          Print out a list of structured and valid JSON/YAML. This argument conflicts with the following arguments:
          verbose
           print-json
           previous-engine
           show-summary: all/fail/pass/skip
          output-format: single-line-summary
  -h, --help
          Print help```

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
````

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

Usage: cfn-guard parse-tree [OPTIONS]

Options:
  -r, --rules <rules>    Provide a rules file
  -o, --output <output>  Write to output file
  -p, --print-json       Print output in JSON format. Use -p going forward, as the short flag -j is on deprecation path.
  -y, --print-yaml       Print output in YAML format
  -h, --help             Print help
```

### Test

Use the `test` command to write unit tests in JSON or YAML format for your rules

```bash
cfn-guard-test
Built in unit testing capability to validate a Guard rules file against
unit tests specified in YAML format to determine each individual rule's success
or failure testing.

Usage: cfn-guard test [OPTIONS]

Options:
  -r, --rules-file <rules-file>  Provide a rules file
  -t, --test-data <test-data>    Provide a file or dir for data files in JSON or YAML
  -d, --dir <dir>                Provide the root directory for rules
  -E, --previous-engine          Uses the old engine for evaluation. This parameter will allow customers to evaluate old changes before migrating
  -a, --alphabetical             Sort alphabetically inside a directory
  -m, --last-modified            Sort by last modified times within a directory
  -v, --verbose                  Verbose logging
  -h, --help                     Print help
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
```

### Autocompletions

To setup Autocompletions you will need to follow instructions for the specific shell your are running.

Currently guard only supports autocompletions for zsh, bash, and fish shells. If you would like autocompletions for a specific shell feel free to open up a new github issue.

Autocompletions are only something available for version >= 3.0

#### zsh

```sh
    cfn-guard completions --shell='zsh' > /usr/local/share/zsh/site-functions/_cfn-guard && compinnit
```

#### bash

```bash
    cfn-guard completions --shell='bash' > ~/cfn-guard.bash && source ~/cfn-guard.bash
```

#### fish

```sh
    cfn-guard completions --shell='fish' > ~/cfn-guard.fish
    cd ~
    ./ ./cfn-guard.fish
```

NOTE: for both bash and fish shells you are able to output the completions script to any file in any location you would like, just make sure the file you output it to and the file you source are the same.
For bash shells if you dont want to do this everytime you open up a new terminal, once you have the script you can add source ~/cfn-guard.bash to your .bashrc
