# AWS CloudFormation Guard

This repo contains source code for the following tools:

* `CloudFormation Guard` A CLI tool that 
	* Checks AWS CloudFormation templates for policy compliance using a simple, policy-as-code, declarative syntax
	* Can autogenerate rules from existing CloudFormation templates
* `CloudFormation Guard Lambda` is the AWS Lambda version of CloudFormation Guard's `check` functionality 
* `CloudFormation Guard Rulegen Lambda` is the AWS Lambda version of CloudFormation Guard's `rulegen` functionality

## Table of Contents

* [How it works](#how-it-works)
* [Installation](#installation)
* [Development](#development)
* [Additional Documentation](#additional-documentation)
* [Frequently Asked Questions](#frequently-asked-questions)



## How it works

### Checking Templates
`CloudFormation Guard` uses a simple rule syntax to allow you to specify the characteristics you want (or don't want) in your CloudFormation Resources.

For example, given a CloudFormation template:

```
{
    "Resources": {
        "NewVolume" : {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                "Size" : 500,
                "Encrypted": false,
                "AvailabilityZone" : "us-west-2b"
            }
        },
        "NewVolume2" : {
            "Type" : "AWS::EC2::Volume",
            "Properties" : {
                "Size" : 50,
                "Encrypted": false,
                "AvailabilityZone" : "us-west-2c"
            }
        }
    }
}
```

And a set of rules:

```
let encryption_flag = true

AWS::EC2::Volume Encrypted == %encryption_flag
AWS::EC2::Volume Size <= 100
```

You can check the template to ensure that it adheres to the rules.

```
$> cfn-guard check -t Examples/ebs_volume_template.json -r Examples/ebs_volume_template.ruleset

[NewVolume2] failed because [Encrypted] is [false] and the permitted value is [true]
[NewVolume] failed because [Encrypted] is [false] and the permitted value is [true]
[NewVolume] failed because [Size] is [500] and the permitted value is [<= 100]
Number of failures: 3
```

### Evaluating Security Policies

CloudFormation Guard can be used to evaluate security best practices for infrastructure deployed via CloudFormation. A number of example rules are included:

```
$> cfn-guard check -t Examples/security_template.json -r Examples/security_rules.ruleset
   "[AmazonMQBroker] failed because [AutoMinorVersionUpgrade] is [false] and Version upgrades should be enabled to receive security updates"
   "[AmazonMQBroker] failed because [EncryptionOptions.UseAwsOwnedKey] is [true] and CMKs should be used instead of AWS-provided KMS keys"
   "[AmazonMQBroker] failed because [EngineVersion] is [5.15.9] and Broker engine version should be at least 5.15.10"
   ...
```

More details on how to write rules and how the tool can work with build systems can be found [here](cfn-guard/README.md).

### Automatically Generating Rules
You can also use the `CloudFormation Guard` tool to automatically generate rules from known-good CloudFormation templates.

Using the same template as above, `cfn-guard rulegen` would produce:

```
$> cfn-guard rulegen Examples/ebs_volume_template.json
AWS::EC2::Volume Encrypted == false
AWS::EC2::Volume Size == 101 |OR| AWS::EC2::Volume Size == 99
AWS::EC2::Volume AvailabilityZone == us-west-2b |OR| AWS::EC2::Volume AvailabilityZone == us-west-2c 
```

From there, you can pipe them into a file and add, edit or remove rules as you need.

### Using the tool as an AWS Lambda

Everything that can be checked from the command-line version of the tool can be checked using [the Lambda version](./cfn-guard-lambda/README.md).  The same is true for the [rulegen functionality](./cfn-guard-rulegen-lambda/README.md).

## Installation

### Mac

The CLI tool for cfn-guard is available via [homebrew](https://formulae.brew.sh/formula/cloudformation-guard).

Installation via homebrew:
```
brew install cloudformation-guard
```

### Windows
The CLI tool for cfn-guard is available via [chocolatey](https://chocolatey.org/packages/cloudformation-guard/1.0.0).

Installation via chocolatey:
```
choco install cloudformation-guard --version=1.0.0
```

### Linux
The CLI tool for cfn-guard is available from GitHub releases. 

Grab the latest release from our [releases page](https://github.com/aws-cloudformation/cloudformation-guard/releases):

```
wget https://github.com/aws-cloudformation/cloudformation-guard/releases/download/VERSION/cfn-guard-linux-VERSION.tar.gz
tar -xvf cfn-guard-linux-1.0.0.tar.gz
cd ./cfn-guard-linux
./cfn-guard 
CloudFormation Guard 1.0.0

USAGE:
    cfn-guard [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    check      Check CloudFormation templates against rules
    help       Prints this message or the help of the given subcommand(s)
    rulegen    Autogenerate rules from an existing CloudFormation template
```

You can then move this to the directory of your choosing so it is on  your $PATH

Binaries are also available for Mac and Windows on the [releases page](https://github.com/aws-cloudformation/cloudformation-guard/releases) in a tarball with corresponding documents.

## Development

### Clone this repo:

```
git clone git@github.com:aws-cloudformation/cloudformation-guard.git
```

Or click the green "Clone or download" button and select "Download Zip". Unzip the contents to view and compile the source code.

### Install Rust
#### Mac/ Ubuntu

```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

If you haven't already, run `source $HOME/.cargo/env` as recommended by the rust installer.

Read [here](https://rustup.rs/) for more information

If building on `Ubuntu`, it's recommended to run `sudo apt-get update; sudo apt install build-essential`

#### Windows 10

1. Create a Windows 10 workspace
2. Install the version of Microsoft Visual C++ Build Tools 2019 which provides just the Visual C++ build
     tools: https://visualstudio.microsoft.com/downloads/#build-tools-for-visual-studio-2019
   1. Download the installer and run it.
   2. Select the "Individual Components" tab and check "Windows 10 SDK"
   3. Select the "Language Packs" tab and make sure that at least "English" is selected
   4. Click "Install"
   5. Let it download and reboot if asked
3. Install [rust](https://forge.rust-lang.org/infra/other-installation-methods.html#other-ways-to-install-rustup)
   1. Download [rust-init.exe](https://static.rust-lang.org/rustup/dist/i686-pc-windows-gnu/rustup-init.exe)
   2. Run it and accept the defaults

### Using the Makefile

The primary interface to the toolchain is the [Makefile](Makefile).  To build the binaries or deploy the lambda you want, simply run their make target (eg `make cfn-guard`).  A copy of the resulting binary will be moved to the top-level `cfn-guard-toolchain/bin/` directory.  (Note that the files inside `bin/` aren't version-controlled, though.)

`cfn-guard-lambda` is a little trickier since it's a lambda, not a binary, and therefore has different steps for `install` and `update`.  It also requires you to set up some things before you can deploy it from the Makefile.  (Please see [its documentation](cfn-guard-lambda/README.md) for more information.). Once it's set up, it can be deployed from the top-level Makefile with targets for `cfn-guard-lambda_install` and `cfn-guard-lambda_update`.

### Grabbing a copy to distribute

Releases are available via the repo's [GitHub releases](https://github.com/aws-cloudformation/cloudformation-guard/releases) for each platform. Alternatively, you can build a copy from source.

There are two make targets that package up the source without the git history, etc.

`make release` will package the source into a file called `cloudformation-guard.tar.gz` without the git history.

`make release_with_binaries` will first do a `cargo build --release` for both `cfn-guard-rulegen` and `cfn-guard` targeting whatever architecture the make command is run on (eg, your laptop's OS), placing the binaries in the `cloudformation-guard/bin/` directory.  Note that cfn-guard contains the functionality of cfn-guard-rulegen under the `rulegen` subcommand. From there, it tars them and the necessary source files into `cloudformation-guard.tar.gz`.  (NOTE: Mail messages with binaries in zip files may get blocked by spam filters.)

## Additional Documentation

Details on how to use each tool and how to build them are available in each tool's README.

[CloudFormation Guard](cfn-guard/README.md)

[CloudFormation Guard Lambda](cfn-guard-lambda/README.md)

[CloudFormation Guard Rulegen Lambda](cfn-guard-rulegen-lambda/README.md)

For a detailed walkthrough of CloudFormation Guard, please follow [this blog](https://aws.amazon.com/blogs/mt/write-preventive-compliance-rules-for-aws-cloudformation-templates-the-cfn-guard-way/)

## Frequently Asked Questions

### Q: Why should you use Guard?

A: Guard solves a number of use-cases:

* It can be used to check repositories of CloudFormation templates for policy violations with automation.
* It can be a deployment gate in a CI/CD pipeline. 
* It allows you to define a single source-of-truth for what constitutes valid infrastructure definitions. Define rules once and have them run both locally and as lambdas in your AWS account for integration with other AWS services.
* It allows for pre-deployment safety checks of your CloudFormation template resources. You can both require settings to be included and prohibit configurations that have caused issues previously.  
* It's easy to get started.  You can extract rules you want from existing, known-good templates using the rulegen functionality of cfn-guard.


### Q: How does CloudFormation Guard relate to other services?
A: Guard is a command-line tool with the ability to check local CloudFormation templates.  It can also deploy as an AWS Lambda Function and be linked to other AWS services that have Lambda integration.


## License
This project is licensed under the Apache-2.0 License.
