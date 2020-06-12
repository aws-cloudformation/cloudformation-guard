# [PREVIEW] AWS CloudFormation Guard
A command line tool for validating AWS CloudFormation resources against policy.

## Table of Contents

* [About](#about)
* [Writing Rules](#writing-rules)
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
AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99
AWS::IAM::Role AssumeRolePolicyDocument.Version == 2012-10-18
AWS::EC2::Volume AvailabilityZone != /us-east-.*/
```

You can check the compliance of that template with those rules:

```
> cfn-guard -t ebs_volume_template.json -r ebs_volume_rule_set
"[NewVolume2] failed because [AvailabilityZone] is [us-east-1b] and the pattern [us-east-.*] is not permitted"
"[NewVolume2] failed because [Encrypted] is [true] and that value is not permitted"
"[NewVolume2] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]"
"[NewVolume] failed because [AvailabilityZone] is [us-east-1b] and the pattern [us-east-.*] is not permitted"
"[NewVolume] failed because [Size] is [100] and the permitted value is [101]"
"[NewVolume] failed because [Size] is [100] and the permitted value is [99]"
"[NewVolume] failed because [us-east-1b] is in [us-east-1a,us-east-1b,us-east-1c] which is not permitted for [AvailabilityZone]"
Number of failures: 7
```

We designed `cfn-guard` to be plugged into your build processes.  

If CloudFormation Guard validates the CloudFormation templates successfully, it gives you no output and an exit status (`$?` in bash) of `0`. If CloudFormation Guard identifies a rule violation, it gives you a count of the rule violations, an explanation for why the rules failed, and an exit status of `2`.

If you want CloudFormation Guard to get the result of the rule check but still get an exit value of `0`, use the `-w` Warn flag.


# Writing Rules

## Basic syntax

We modeled `cfn-guard` rules on firewall rules.  They're easy to write and have a declarative syntax.

The most basic CloudFormation Guard rule has the form:

```
<CloudFormation Resource Type> <Property> == <Value>
```

The available operations are:

* `==` - Equal
* `!=` - Not Equal
* `IN` - In a list of form `[x, y, z]`
* `NOT_IN` - Not in a list of form `[x, y, z]` 


## Rule Logic

Each rule in a given rule set is implicitly `AND`'d to every other rule.

You can `OR` rules to provide alternate acceptable values of arbitrary types using `|OR|`:

``` 
AWS::EBS::Volume Size == 500 |OR| AWS::EBS::Volume AvailabiltyZone == us-east-1b
```

## Checking nested fields
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
## Wildcard Syntax

You can also refer to list items as wildcards (`*`).  Wildcards are a preprocessor macro that examines both the rules file and the template to expand the wildcards into lists of rules of the same length as those contained in the template that's being checked.

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

Note carefully the different semantic meanings between equality (`==`) and inequality (`!=`) with wildcards:

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

You can also declare variables using a `let` syntax:

```
let <VAR NAME> = <list or scalar>
```

For example:

```
let size = 500
let azs = [us-east-1b, us-east-1b]
```

And then refer to those variables in rules using `%`:

```
AWS::EBS::Volume Size == %size
```

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
"[NewVolume] failed because [AvailabilityZone] is [[\"EC2Instance\",\"AvailabilityZone\"]] and the permitted value is [!GetAtt [EC2Instance, AvailabilityZone]]"
```
That effect, combined with the parser stripping out whitespace between values means that the rule would need to be written as:
``` 
AWS::EC2::Volume AvailabilityZone == ["EC2Instance","AvailabilityZone"]
```
where the values are quoted and with no space behind the `,` in order to match.

If you see something that should match but doesn't, the failure message (`[\"EC2Instance\",\"AvailabilityZone\"]`) will help you identify why. 

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
"[NewVolume] failed because [AvailabilityZone] is [{\"Fn::GetAtt\":[\"EC2Instance\",\"AvailabilityZone\"]}] and the permitted value is [[\"EC2Instance\",\"AvailabilityZone\"]]"
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

### Runtime Arguments

`cfn-guard` uses the Rust Clap library to parse arguments.  Its `--help` output will show you what options are available:

```
CloudFormation Guard 0.5.0
Check CloudFormation templates against rules

USAGE:
    cfn-guard [FLAGS] --rule_set <RULE_SET_FILE> --template <TEMPLATE_FILE>

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
