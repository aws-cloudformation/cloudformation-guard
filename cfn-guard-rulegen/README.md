# [PREVIEW] CloudFormation Guard Rulegen

A CLI tool to automatically generate [CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard) rules from CloudFormation Templates.

# Example

If you supply the `cfn-guard-rulegen` tool with a CloudFormation template:

``` 
AWSTemplateFormatVersion: '2010-09-09'
Metadata:
  License: Apache-2.0
Description: 'AWS CloudFormation Sample Template for cfn-guard blog, for developers.
  It creates an Amazon EC2 instance running the latest Amazon Linux AMI, based on the region
  in which the stack is run, with restricted sizes. It also creates an EC2 security group
  for the instance to give you SSH access on a non-standard port.
  **WARNING** This template creates an Amazon EC2 instance, and you will be billed for
  it once the stack is deployed.  Delete the stack after you have completed your tests to
  avoid additional charges'
Parameters:
  KeyName:
    Description: Name of an existing EC2 KeyPair to enable SSH access to the instance
    Type: AWS::EC2::KeyPair::KeyName
    ConstraintDescription: must be the name of an existing EC2 KeyPair.
  SSHLocation:
    Description: The IP address range that can be used to SSH to the EC2 instances
    Type: String
    MinLength: 9
    MaxLength: 18
    Default: 0.0.0.0/0
    AllowedPattern: (\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/(\d{1,2})
    ConstraintDescription: Must be a company approved, valid IP CIDR range of the form x.x.x.x/x.
  LatestAmiId:
    Type:  'AWS::SSM::Parameter::Value<AWS::EC2::Image::Id>'
    Default: '/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
Resources:
  EC2Instance:
    Type: AWS::EC2::Instance
    Properties:
      InstanceType: t3.medium
      SecurityGroups: [!Ref 'InstanceSecurityGroup']
      KeyName: !Ref 'KeyName'
      ImageId: !Ref 'LatestAmiId'
  InstanceSecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      GroupDescription: Enable SSH access via custom port 33322
      SecurityGroupIngress:
      - IpProtocol: tcp
        FromPort: 22
        ToPort: 22
        CidrIp: !Ref 'SSHLocation'
  NewVolume:
    Type: AWS::EC2::Volume
    Properties:
      Size: 512
      AvailabilityZone: !GetAtt [EC2Instance, AvailabilityZone]
Outputs:
  InstanceId:
    Description: InstanceId of the newly created EC2 instance
    Value: !Ref 'EC2Instance'
  AZ:
    Description: Availability Zone of the newly created EC2 instance
    Value: !GetAtt [EC2Instance, AvailabilityZone]
  PublicDNS:
    Description: Public DNSName of the newly created EC2 instance
    Value: !GetAtt [EC2Instance, PublicDnsName]
  PublicIP:
    Description: Public IP address of the newly created EC2 instance
    Value: !GetAtt [EC2Instance, PublicIp]
```

It will convert the template resources' properties to CloudFormation Guard rules:

``` 
⋊>  cfn-guard-rulegen test-ec2.yaml | sort                                                                                                                                    16:57:26
AWS::EC2::Instance ImageId == LatestAmiId
AWS::EC2::Instance InstanceType == t3.medium
AWS::EC2::Instance KeyName == KeyName
AWS::EC2::Instance SecurityGroups == ["InstanceSecurityGroup"]
AWS::EC2::SecurityGroup GroupDescription == Enable SSH access via custom port 33322
AWS::EC2::SecurityGroup SecurityGroupIngress == [{"CidrIp":"SSHLocation","FromPort":22,"IpProtocol":"tcp","ToPort":22}]
AWS::EC2::Volume AvailabilityZone == ["EC2Instance","AvailabilityZone"]
AWS::EC2::Volume Size == 512
```

Given the potential for hundreds or even thousands of rules to emerge, we recommend piping the output through `sort` and into a file for editing:

```
cfn-guard-rulegen Examples/aws-waf-security-automations.template | sort > ~/waf_rules
```

# To Build and Run

## Install Rust
See the instructions in the [top-level README](../README.md#install-rust).
 
## Run the tool

Open whatever shell you prefer (eg, `bash` on Mac/Linux or `cmd.exe` on Windows) and cd into the directory where the source has been downloaded.

### Using Cargo

With cargo, you can run right from the git directory, but it won't be as fast as a compiled build-release.

```
cargo run -- <CloudFormation Template>
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
2. Run the binary with `target\release\cfn-guard-rulegen.exe`

### Runtime Arguments

Rulegen uses the Rust Clap library to parse arguments.  Its `--help` output will show you what options are available:

```
$> cfn-guard-rulegen --help

CloudFormation Guard RuleGen 0.5.0
Generate CloudFormation Guard rules from a CloudFormation template

USAGE:
    cfn-guard-rulegen [FLAGS] <TEMPLATE>

FLAGS:
    -h, --help       Prints help information
    -v               Sets the level of verbosity - add v's to increase output
    -V, --version    Prints version information

ARGS:
    <TEMPLATE> 
```

### Logging

If you'd like to see the logic cfn-guard-rulegen is applying at runtime, there are a number of log levels you can access.

To increase the verbosity, simply add more v's to the verbosity flag (eg, -v, -vv, -vvv)

NOTE: The same log levels can be accessed either in the target binary or with `cargo run`

