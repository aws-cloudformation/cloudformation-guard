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

For information about using Guard CLI commands, see [Guard CLI command reference](docs/cfn-guard-command-reference.md).)