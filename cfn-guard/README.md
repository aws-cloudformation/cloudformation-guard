# [PREVIEW] AWS CloudFormation Guard
A command line tool for validating AWS CloudFormation resources against policy.

## Table of Contents

* [About](#about)
* [Writing Rules](#writing-rules)
* [Troubleshooting](#troubleshooting)
* [Building And Running](#to-build-and-run)
* [Testing Code Changes](#to-test)

# About
`cfn-guard` is a tool for checking CloudFormation resources for properties using a light-weight, firewall-rule-like syntax.

As an example of how to use it, given a CloudFormation template:

```
 > cat ebs_volume_template.json
{
"Resources": {
    "NewVolume" : {
        "Type" : "AWS::EC2::Volume",
        "Properties" : {
            "Size" : 100,
            "Encrypted": false,
            "AvailabilityZone" : "us-east-1b"
        }
    },
    "NewVolume2" : {
        "Type" : "AWS::EC2::Volume",
        "Properties" : {
            "Size" : 99,
            "Encrypted": true,
            "AvailabilityZone" : "us-east-1b"
        }
    }
  }
}
```

And a Rules file

```
> cat ebs_volume_rule_set
let encryption_flag = true
let disallowed_azs = [us-east-1a,us-east-1b,us-east-1c]

AWS::EC2::Volume AvailabilityZone NOT_IN %disallowed_azs
AWS::EC2::Volume Encrypted != %encryption_flag
AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99 |OR| AWS::EC2::Volume Size >= 101
AWS::IAM::Role AssumeRolePolicyDocument.Version == 2012-10-18
AWS::EC2::Volume AvailabilityZone != /us-east-.*/
```

You can check the compliance of that template with those rules:

```
> cfn-guard check -t ebs_volume_template.json -r ebs_volume_rule_set
"[NewVolume2] failed because [AvailabilityZone] is [us-east-1b] and the pattern [us-east-.*] is not permitted"
"[NewVolume2] failed because [Encrypted] is [true] and that value is not permitted"
"[NewVolume2] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]"
"[NewVolume] failed because [AvailabilityZone] is [us-east-1b] and the pattern [us-east-.*] is not permitted"
"[NewVolume] failed because [Size] is [100] and the permitted value is [101]"
"[NewVolume] failed because [Size] is [100] and the permitted value is [99]"
"[NewVolume] failed because [Size] is [100] and the permitted value is [>= 101]"
"[NewVolume] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]"
Number of failures: 7
```

We designed `cfn-guard` to be plugged into your build processes.  

If CloudFormation Guard validates the CloudFormation templates successfully, it gives you no output and an exit status (`$?` in bash) of `0`. If CloudFormation Guard identifies a rule violation, it gives you a count of the rule violations, an explanation for why the rules failed, and an exit status of `2`.  If there's a runtime error with the rule set or processing, it will exit with a `1`. 

If you want CloudFormation Guard to get the result of the rule check but still get an exit value of `0`, use the `-w` Warn flag.

## Check vs Rulegen

`cfn-guard` has two modes:  

### Check
`check` (like the example above) checks templates against rulesets.
```
cfn-guard-check
Check CloudFormation templates against rules

USAGE:
    cfn-guard check [FLAGS] --rule_set <RULE_SET_FILE> --template <TEMPLATE_FILE>

FLAGS:
    -h, --help             Prints help information
    -s, --strict-checks    Fail resources if they're missing the property that a rule checks
    -v                     Sets the level of verbosity - add v's to increase output
    -V, --version          Prints version information
    -w, --warn_only        Show results but return an exit code of 0 regardless of rule violations

OPTIONS:
    -r, --rule_set <RULE_SET_FILE>    Rules to check the template against
    -t, --template <TEMPLATE_FILE>    CloudFormation Template
```

### Rulegen
`rulegen` takes a CloudFormation template and autogenerates a set of `cfn-guard` rules that match the properties of its resources.  This is a useful way to get started rule-writing or just create ready-to-use rulesets from known-good templates.

``` 
cfn-guard-rulegen
Autogenerate rules from an existing CloudFormation template

USAGE:
    cfn-guard rulegen [FLAGS] <TEMPLATE>

FLAGS:
    -h, --help       Prints help information
    -v               Sets the level of verbosity - add v's to increase output
    -V, --version    Prints version information

ARGS:
    <TEMPLATE>
```
For example:

``` 
> cfn-guard rulegen Examples/ebs-volume-template.json
AWS::EC2::Volume AvailabilityZone == us-west-2b |OR| AWS::EC2::Volume AvailabilityZone == us-west-2c
AWS::EC2::Volume Encrypted == false
AWS::EC2::Volume Size == 50 |OR| AWS::EC2::Volume Size == 500
```

Given the potential for hundreds or even thousands of rules to emerge, we recommend piping the output through `sort` and into a file for editing:

```
cfn-guard rulegen Examples/aws-waf-security-automations.template | sort > ~/waf_rules
```


# Writing Rules

## Basic syntax

We modeled `cfn-guard` rules on firewall rules.  They're easy to write and have a declarative syntax.

The most basic CloudFormation Guard rule has the form:

```
<CloudFormation Resource Type> <Property> <Operator> <Value>
```

The available operators are:

* `==` - Equal
* `!=` - Not Equal
* `<` - Less Than
* `>` - Greater Than
* `<=` - Less Than Or Equal To
* `>=` - Greater Than Or Equal To
* `IN` - In a list of form `[x, y, z]`
* `NOT_IN` - Not in a list of form `[x, y, z]` 

## Checking Resource Properties and Attributes

Properties in a rule can take two forms.  The basic form exists to make writing simple rules very straightforward:

```
AWS::EC2::Volume Encryption == true
```

This simple form makes the assumption that the property you're checking is in the resource's `Properties` section:

```
    "NewVolume" : {
           "Type" : "AWS::EC2::Volume",
           "Properties" : {
               "Size" : 101,
               "Encrypted": true,
               "AvailabilityZone" : "us-west-2b"
           }
       }
```

However, you may also want to write a rule that checks the resource's [Attributes](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-product-attribute-reference.html):

``` 
    "NewVolume" : {
       "Type" : "AWS::EC2::Volume",
       "Properties" : {
          "Size" : "100",
          "Encrypted" : "true",
       },
       "DeletionPolicy" : "Snapshot"
    }
```
In this case, let's say we want to check the `DeletionPolicy` for deployment safety reasons.  We could write a rule that checks attributes at the level above `Properties` by preceding the symbol in the property position with a `.` to indicate that you want to examine a value at the root of the resource:

``` 
AWS::EC2::Volume .DeletionPolicy == Snapshot
```

## Comments

Comments can be added to a rule set via the `#` operator:
```
# This is a comment
```


## Rule Logic

### ANDs and ORs
Each rule in a given rule set is implicitly `AND`'d to every other rule.

You can `OR` rules on a single line to provide alternate acceptable values of arbitrary types using `|OR|`:

``` 
AWS::EBS::Volume Size == 500 |OR| AWS::EBS::Volume AvailabiltyZone == us-east-1b
```

### WHEN checks
At times, you may not want to check every resource of a particular type in a template for the same values.  You can write conditional checks using the `WHEN-CHECK` syntax:

``` 
<CloudFormation Resource Type> WHEN <Property> <Operator> <Value> CHECK <Property> <Operator> <Value>
```
As an example:
``` 
AWS::DynamoDB::Table WHEN Tags.* == /.*PROD.*/ CHECK .DeletionPolicy == Retain
```
The first section (`WHEN Tags.* == /.*PROD.*/`) is the `condition` you want to filter on.  It uses the same property and value syntax and semantics as a basic rule.  

The second section (`CHECK .DeletionPolicy == Retain`) is the `consequent` that the resource must pass for the rule to pass.

If the `condition` matches, the `consequent` is evaluated and the result of that evaluation is added to the overall ruleset results.

Note that `WHEN` checks **can only operate on a single resource type at a time**.  They can also be aggregated using `OR`'s like a regular rule:

``` 
AWS::DynamoDB::Table when Tags == /.*PROD.*/ check .DeletionPolicy == Retain |OR| AWS::DynamoDB::Table WHEN Tags.* == /.*DEV.*/ CHECK .DeletionPolicy == Delete
```

To see a practical example of a conditional rule, look at the `conditional-ddb-template` files in the [Examples](../Examples) directory.

## Checking nested fields
### Using explicit paths
Fields that are nested inside CloudFormation [resource properties](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-template-resource-type-ref.html) can be addressed using a dotted notation:

```
AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Principal.Service.0 == lambda.amazonaws.com
```

Note that the list-index syntax in that rule matches to a CloudFormation template with the following `Resources` section:

```
Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
```
### Using Wildcards
You can also refer to template items, lists and maps as wildcards (`*`).  Wildcards are a preprocessor macro that examines both the rules file and the template to expand the wildcards into lists of rules of the same length as those contained in the template that's being checked.

In other words, given a template of the form:
``` 
Resources:
  LambdaRoleHelper:
    Type: 'AWS::IAM::Role'
    Properties:
      AssumeRolePolicyDocument:
        Statement:
          - Effect: Allow
            Principal:
              Service:
                - lambda.amazonaws.com
          - Effect: Allow
            Principal:
              Service:
                - ec2.amazonaws.com
```
And a rule of the form:
```
AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* == lambda.amazonaws.com
```

CloudFormation Guard will walk the template and internally convert the wildcard rule to:
```
AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Principal.Service.0 == lambda.amazonaws.com |OR| AWS::IAM::Role AssumeRolePolicyDocument.Statement.1.Principal.Service.0 == ec2.amazonaws.com
```
#### Wildcard Semantics
Note carefully the different semantic meanings between the equality (`==`) or in-a-list (`IN`) operators and the inequality (`!=`) or not-in-a-list (`NOT_IN`) ones with wildcards:

```
AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* == lambda.amazonaws.com
```

means **"At least one item that matches those wildcards should match that value"** and is executed as a set of `OR` rules.

```
AWS::IAM::Role AssumeRolePolicyDocument.Statement.*.Principal.Service.* != lambda.amazonaws.com
```

means **"None of the items that those wildcards match should match that value"** and is executed as a set of `AND` rules.

To see how the rule is expanded at runtime, run with the `-v` flag and look for "Applying rule" in the output.

## Regular Expressions

You can also write rules to match against the [Rust Regex syntax](https://docs.rs/regex/1.2.0/regex/#syntax) which matches to the Perl Compatible Regular Expression (PCRE) syntax.

The form is `/<regex pattern>/` so:

``` 
AWS::IAM::Role AssumeRolePolicyDocument.Version == /(\d{5})-(\d{2})-(\d{2})/
AWS::EC2::Volume AvailabilityZone != /us-east-.*/
```

## Variable Syntax

### Assignment
You can declare variables using a `let` syntax:

```
let <VAR NAME> = <list or scalar>
```

For example:

```
let size = 500
# Regular list
let azs = [us-east-1b, us-east-1b]
# JSON list
let tag_vals = ["tests", 1, ["a", "b"], {"Key":"A","Value":"a"},{"Key":"A","Value":{"Ref":"a"}}]
```

And then refer to those variables in rules using `%`:

```
AWS::EBS::Volume Size == %size
```

### JSON lists vs non-JSON lists

#### JSON Lists
Any valid JSON list literal is a valid JSON list. The list:
``` 
let tag_vals = ["tests", 1, ["a", "b"], {"Key":"A","Value":"a"},{"Key":"A","Value":{"Ref":"a"}}]
```
Will flatten out to a list of the following values:
``` 
"tests",
1,
["a, b"],
{"Key":"A","Value":"a"},
{"Key":"A","Value":{"Ref":"a"}}
```
That you can match properties of a template resource against using `IN` or `NOT_IN`.

#### Non-JSON Lists
Any list that's not a json literal is just a comma-separated list of values.

#### Mixing list types
**Lists containing a mix of JSON and non-JSON values are interpreted as non-JSON**

So if
``` 
let tag_vals = ["tests", {"Key":"A","Value":"a"},{"Key":"A","Value":{"Ref":"a"}}]
```
Were written as

``` 
let tag_vals = [tests, {"Key":"A","Value":"a"},{"Key":"A","Value":{"Ref":"a"}}]
```
It would be evaluated as a list of the items:
```
tests,
{"Key":"A",
"Value":"a"},
{"Key":"A",
"Value":{"Ref":"a"}}
```
Which is almost certainly not what you'd want.  

If you see strange behavior in a rule working with a json list, run with `-vv` and you'll see a line like:
``` 
2020-07-01 14:49:18,411 DEBUG [cfn_guard::util] List [tests, {"Key":"A","Value":"a"},{"Key":"A","Value":{"Ref":"a"}}] is not a json list
```
That will give you more information on how `cfn-guard` is processing it.

(See [Troubleshooting](#troubleshooting) for more details on using the different logging levels to see how your template and rule set are being processed.)

### Environment Variables
You can even reference **environment variables** using the Makefile-style notation: `%{Name}`

So you could rewrite the IAM Role rule above as:

```
AWS::IAM::Role AssumeRolePolicyDocument.Statement.0.Principal.Service.0 == %{IAM_PRIN}
```

And then invoke `cfn-guard` from the command line with that variable set:

``` 
IAM_PRIN=lambda.amazonaws.com cfn-guard -t iam_template -r iam_rule_set
```

Note:  All environment variables are available for use at runtime. They don't need to be explicitly set during the `cfn-guard` invocation.

**Environment Variables are not logged to avoid persisting sensitive information.  You should use them to pass sensitive values in to `cfn-guard` instead of the `let` form.**

## Custom Failure Messages

There is an optional field in the rule syntax where you can provide your own custom messages by adding `<<` and the message text to the end of the rule:

    AWS::EC2::Volume Encrypted == %encryption_flag << lorem ipsum

Also, it's important to remember that |OR| constructs are concatenations of discrete rules.  So

    AWS::EC2::Volume Size == 201 |OR| AWS::EC2::Volume Size == 199 << lorem ipsum
   
Would only return a custom message on the SECOND rule, not both.  If you want custom messages for both, you need to add the custom message to both sides of the `|OR|`:

    AWS::EC2::Volume Size == 201 << ipsum lorem |OR| AWS::EC2::Volume Size == 199 << lorem ipsum

Similarly, be careful when adding the same custom message to multiple rules.  It could obscure what the actual failures are.

For example, if you apply the following CloudFormation Guard rule set:

```
let allowed_azs = [us-east-1a,us-east-1b,us-east-1c]

AWS::EC2::Volume AvailabilityZone IN %allowed_azs
AWS::EC2::Volume AvailabilityZone == /.*d/
```

To Examples/ebs_volume_template.json.  `cfn-guard` would return:

```
"[NewVolume2] failed because [AvailabilityZone] is [us-west-2c] and the permitted pattern is [.*d]"
"[NewVolume2] failed because [us-west-2c] is not in [us-east-1a,us-east-1b,us-east-1c] for [AvailabilityZone]"
```

But if both rules have the same custom failure message:

``` 
AWS::EC2::Volume AvailabilityZone IN %allowed_azs << lorem ipsum
AWS::EC2::Volume AvailabilityZone == /.*d/ << lorem ipsum
```

The result looks like an erroneous repeat:
```
 "[NewVolume2] failed because [AvailabilityZone] is [us-west-2c] and lorem ipsum"
 "[NewVolume2] failed because [AvailabilityZone] is [us-west-2c] and lorem ipsum"
```

Custom messages are syntactically valid on both sides of a [WHEN check](README.md#when-checks):

``` 
AWS::DynamoDB::Table WHEN Tags == /.*PROD.*/ << custom conditional message CHECK .DeletionPolicy != Retain << custom consequent message
```

But the `condition`'s custom message is only exposed inline as part of the raw rule included in the error message:

```
[DDBTable] failed because [.DeletionPolicy] is [Retain] and custom consequent message when AWS::DynamoDB::Table Tags == /.*PROD.*/ << custom conditional message
```


## Working with CloudFormation Intrinsic Functions
Because of the way YAML is parsed by serde_yaml, functions like `!GetAtt` are treated as comments and ignored. For example:
``` 
  NewVolume:
    Type: AWS::EC2::Volume
    Properties:
      Size: 512
      AvailabilityZone: !GetAtt [EC2Instance, AvailabilityZone]
```
Checked against the rule:
``` 
AWS::EC2::Volume AvailabilityZone == !GetAtt [EC2Instance, AvailabilityZone]
```
Results in a failure:
``` 
"[NewVolume] failed because [AvailabilityZone] is [["EC2Instance","AvailabilityZone"]] and the permitted value is [!GetAtt [EC2Instance, AvailabilityZone]]"
```
That effect, combined with the parser stripping out whitespace between values means that the rule would need to be written as:
``` 
AWS::EC2::Volume AvailabilityZone == ["EC2Instance","AvailabilityZone"]
```
where the values are quoted and with no space behind the `,` in order to match.

If you see something that should match but doesn't, the failure message (`["EC2Instance","AvailabilityZone"]`) will help you identify why. 

This last part about the stripped whitespace is also true for the JSON version of the `Fn::GetAtt` function:
``` 
{
"Resources": {
    "NewVolume" : {
        "Type" : "AWS::EC2::Volume",
        "Properties" : {
            "Size" : 100,
            "Encrypted": false,
            "AvailabilityZone" : { "Fn::GetAtt" : [ "EC2Instance", "AvailabilityZone" ] }
        }
    },
    "NewVolume2" : {
        "Type" : "AWS::EC2::Volume",
        "Properties" : {
            "Size" : 99,
            "Encrypted": true,
            "AvailabilityZone" : "us-east-1b"
        }
    }
  }
```
Which would fail with a message like:
```
"[NewVolume] failed because [AvailabilityZone] is [{"Fn::GetAtt":["EC2Instance","AvailabilityZone"]}] and the permitted value is [["EC2Instance","AvailabilityZone"]]"
```
In order to handle both cases in both template formats, use an `|OR|` rule like the following (without escaping the quotes and without interstitial whitespace):
``` 
AWS::EC2::Volume AvailabilityZone == ["EC2Instance","AvailabilityZone"] |OR| AWS::EC2::Volume AvailabilityZone == {"Fn::GetAtt":["EC2Instance","AvailabilityZone"]}
```

**When in doubt about how the YAML or JSON will get parsed, use `cfn-guard-rulegen` on the template you're checking.  It outputs in a form that adheres to the same properties of the parsers.**

``` 
⋊> cfn-guard-rulegen guard-test-ec2-dev.yaml
AWS::EC2::Instance SecurityGroups == ["InstanceSecurityGroup"]
AWS::EC2::Instance KeyName == KeyName
AWS::EC2::Volume AvailabilityZone == ["EC2Instance","AvailabilityZone"]
AWS::EC2::Volume Size == 512
AWS::EC2::Instance ImageId == LatestAmiId
AWS::EC2::SecurityGroup GroupDescription == Enable SSH access via custom port 33322
AWS::EC2::SecurityGroup SecurityGroupIngress == [{"CidrIp":"SSHLocation","FromPort":22,"IpProtocol":"tcp","ToPort":22}]
AWS::EC2::Instance InstanceType == t3.medium

⋊> cfn-guard-rulegen ebs_volume_template_example.json
AWS::EC2::Volume Size == 100 |OR| AWS::EC2::Volume Size == 99
AWS::EC2::Volume Encrypted == true |OR| AWS::EC2::Volume Encrypted == false
AWS::EC2::Volume AvailabilityZone == {"Fn::GetAtt":["EC2Instance","AvailabilityZone"]}
```
# Strict Checks
The `--strict-check` flag will cause a resource to fail a check if it does not contain the property the rule is checking.  This is useful to enforce the presence of optional properties like `Encryption == true`.

Strict checks and wildcards need to be carefully thought out before being used together, however.  Wildcards create rules at runtime that map to all of the values that *each* resource of that type has at the position of the wildcard.  That means means that overly broad wildcards will give overly broad failures.

As an example, let's look at the following wildcard scenario:

Here's a template snippet:
``` 
{
    "Resources": {
        "NewVolume" : {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                "AutoEnableIO": true,
                "Size" : 101,
                "Encrypted": true,
                "AvailabilityZone" : "us-west-2b"
            }
        },
        "NewVolume2" : {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                "Size" : 99,
                "Encrypted": true,
                "AvailabilityZone" : "us-west-2c"
            }
        }
    }
}
```
It's perfectly valid semantically (although of dubious practical value) to use a wildcard to ensure that at least one property has a value equal to true:
```
AWS::EC2::Volume * == true
```
As discussed above in the section about wildcards, this translates at runtime to a rule for each property being created and joined by an `|OR|`:
```
> cfn-guard -t ~/scratch-template.yaml -r ~/scratch.ruleset -vvv
...
2020-08-07 17:25:59,000 INFO  [cfn_guard] Applying rule 'CompoundRule(
    CompoundRule {
        compound_type: OR,
        raw_rule: "AWS::EC2::Volume * == true",
        rule_list: [
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "AvailabilityZone",
                    operation: Require,
                    value: "true",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "Size",
                    operation: Require,
                    value: "true",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "Encrypted",
                    operation: Require,
                    value: "true",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "AutoEnableIO",
                    operation: Require,
                    value: "true",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
        ],
    },
)'

```
And the check will pass.

However, if you change your wildcard rule to be a `!=`:
``` 
AWS::EC2::Volume * != false
```

The `OR` rule becomes an `AND` rule:
```
2020-08-07 17:33:20,637 INFO  [cfn_guard] Applying rule 'CompoundRule(
    CompoundRule {
        compound_type: AND,
        raw_rule: "AWS::EC2::Volume * != false",
        rule_list: [
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "AvailabilityZone",
                    operation: RequireNot,
                    value: "false",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "AutoEnableIO",
                    operation: RequireNot,
                    value: "false",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "Size",
                    operation: RequireNot,
                    value: "false",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
            SimpleRule(
                Rule {
                    resource_type: "AWS::EC2::Volume",
                    field: "Encrypted",
                    operation: RequireNot,
                    value: "false",
                    rule_vtype: Value,
                    custom_msg: None,
                },
            ),
        ],
    },
)'
```

And if you run it with `--strict-checks` it'll fail because `NewVolume2` does not contain the `AutoEnableIO` property:

``` 
> cfn-guard -t ~/scratch-template.yaml -r ~/scratch.ruleset --strict-checks
[NewVolume2] failed because it does not contain the required property of [AutoEnableIO]
Number of failures: 1
```
Admittedly, this is a very contrived example, but it's an important to behavior understand.


# Troubleshooting
`cfn-guard` is meant to be used as part of a tool chain.  It does not, for instance, check to see if the CloudFormation template presented to it is valid CloudFormation.  The [cfn-lint](https://github.com/aws-cloudformation/cfn-python-lint) tool already does a deep and thorough inspection of template structure and provides copious feedback to help users write high-quality templates.  

`cfn-guard` also does not put constraints on what types you're checking or the properties those types can be checked for.  That aspect can result in some confusion when you're hand-crafting rules and not getting the results you expected. 

The best way to see how the rule sets are been processed is to take advantage of the different logging levels (eg `-vvv`).  When logging is enabled, you can trace the entire execution and see how `cfn-guard` is working internally.

For instance, here's a simple template:

```
{
    "Resources": {
        "NewVolume" : {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                "Size" : 101,
                "Encrypted": false,
                "AvailabilityZone" : "us-west-2b"
            }
        },
        "NewVolume2" : {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                "Size" : 99,
                "Encrypted": false,
                "AvailabilityZone" : "us-west-2c"
            }
        }
    }
}
```
And a sample rule set:
```
let encryption_flag = true
AWS::EC2::Volume Encrypted == %encryption_flag
```
With the `-vvv` trace logging enabled, you can see how the assignment was parsed:
```
2020-06-27 13:18:00,097 DEBUG [cfn_guard::parser] Parsing 'let encryption_flag = true'
2020-06-27 13:18:00,112 DEBUG [cfn_guard::parser] line_type is Assignment
2020-06-27 13:18:00,122 TRACE [cfn_guard::parser] Parsed assignment's captures are: Captures(
    {
        0: Some(
            "let encryption_flag = true",
        ),
        "var_name": Some(
            "encryption_flag",
        ),
        "operator": Some(
            "=",
        ),
        "var_value": Some(
            "true",
        ),
    },
)
2020-06-27 13:18:00,122 TRACE [cfn_guard::parser] Inserting key: [encryption_flag], value: [true] into variables
```
And the rule:
```
2020-06-27 13:18:00,122 DEBUG [cfn_guard::parser] Parsing 'AWS::EC2::Volume Encrypted == %encryption_flag'
2020-06-27 13:18:00,134 DEBUG [cfn_guard::parser] line_type is Rule
2020-06-27 13:18:00,135 DEBUG [cfn_guard::parser] Line is an 'AND' rule
2020-06-27 13:18:00,135 TRACE [cfn_guard::parser] Entered destructure_rule
2020-06-27 13:18:00,154 TRACE [cfn_guard::parser] Parsed rule's captures are: Captures(
    {
        0: Some(
            "AWS::EC2::Volume Encrypted == %encryption_flag",
        ),
        "resource_type": Some(
            "AWS::EC2::Volume",
        ),
        "resource_property": Some(
            "Encrypted",
        ),
        "operator": Some(
            "==",
        ),
        "rule_value": Some(
            "%encryption_flag",
        ),
    },
)
2020-06-27 13:18:00,155 TRACE [cfn_guard::parser] Destructured rules are: [
    Rule {
        resource_type: "AWS::EC2::Volume",
        field: "Encrypted",
        operation: Require,
        value: "%encryption_flag",
        rule_vtype: Variable,
        custom_msg: None,
    },
]
2020-06-27 13:18:00,155 DEBUG [cfn_guard::parser] Parsed rule is: CompoundRule {
    compound_type: AND,
    rule_list: [
        Rule {
            resource_type: "AWS::EC2::Volume",
            field: "Encrypted",
            operation: Require,
            value: "%encryption_flag",
            rule_vtype: Variable,
            custom_msg: None,
        },
    ],
}
```
Whenever your rules aren't behaving as expected, this is great way to see why.

## Troubleshooting FAQ

**Q: I keep trying to force a failure with a bad rule value and I'm not getting any results**

A: This is almost always due to fact that there's a typo in the property name you're trying to check for in your rule.  Turn on `--strict-checks` and you'll get an error if the names don't match.  This is an easy way to spot typos.


# To Build and Run

## Install Rust
See the instructions in the [top-level README](../README.md#install-rust).
  
## Run the tool
Open whatever shell you prefer (eg, `bash` on Mac/Linux or `cmd.exe` on Windows) and cd into the directory where the source has been downloaded.

### Using Cargo

With cargo, you can run right from the git directory, but it won't be as fast as a compiled build-release.

```
cargo run -- -t <CloudFormation Template> -r <Rules File>
```

(NOTE: The `--` in the middle is necessary to disambiguate whether the flags are being passed to Cargo or to the program)

### Building the binary

**NOTE: By default rust compiles to binaries for whatever platform you run the build on.  [You can cross-compile in rust](https://github.com/japaric/rust-cross), if you need to.**

#### Mac/Linux
Running

```
make
```

will compile the release binary and drop it in the `bin/` directory under the directory you compiled it in.

#### Windows
1. Run `cargo build --release`.
2. Run the binary with `target\release\cfn-guard.exe`

### Logging

If you'd like to see the logic `cfn-guard` is applying at runtime, there are a number of log levels you can access.

To increase the verbosity, simply add more v's to the verbosity flag (eg, -v, -vv, -vvv)

NOTE: The same log levels can be accessed either in the target binary or with `cargo run`

# To Test

If you modify the source and wish to run the unit tests, just do

```
cargo test
```

If you wish to use example CloudFormation templates and rule sets, please see the `Examples` directory.
