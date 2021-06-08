# Guard: Complex Composition

This chapter is a more advanced topic. Readers are encouraged to read all the other chapters before reading this one.

Let’s recall key learnings from the [Guard: Clauses](CLAUSES.md) document.

1. Structure of a named rule block:

```
rule <rule name> [when <condition>] {
    Guard_rule_A
    Guard_rule_B
    ...
}
```

Where Guard rule is an umbrella term for clause, query block, `when` block or named rule block.

Query blocks and named rule blocks allow for re-usability, improved composition, and reduced verbosity and repetition. This document will focus on demonstrating these features in-depth.

## Clause evaluation

Each clause is an independent statement whose result is the evaluation on its entire query result based on the clause's scope. This is best explained with an example,

### Example 1

```
let s3_buckets = Resources.*[ Type == "AWS::S3::Bucket" ]

when %s3_buckets !empty {
  %s3_buckets.Properties.AccessControl exists               << Clause 1 >>
  %s3_buckets.Properties.LoggingConfiguration exists        << Clause 2 >>
}
```

The pseudocode for the above example is a follows,

```
boolean isAccessControlExists = true
boolean isLoggingConfigurationExists = true

for each_s3_bucket in s3_buckets do
    if each_s3_bucket.Properties.AccessControl == null then
        isAccessControlExists = false
    end if
end for

for each_s3_bucket in s3_buckets do
    if each_s3_bucket.Properties.LoggingConfiguration == null then
        isLoggingConfigurationExists = false
    end if
end for

return isAccessControlExists and isLoggingConfigurationExists
```

In the above example,
1. `Clause 1` and `Clause 2` are independent statements.
1. `Clause 1` is evaluated on `AccessControl` property of all S3 buckets and the result of `Clause 1` is the cumulative result of the evaluation.
1. `Clause 2` is evaluated after complete evaluation of `Clause 1`.
1. `Clause 2` is evaluated on `LoggingConfiguration` property of all S3 buckets and the result of `Clause 2` is the cumulative result of the evaluation.

### Example 2

```
let s3_buckets = Resources.*[ Type == "AWS::S3::Bucket" ]

when %s3_buckets !empty {
  %s3_buckets {
    Properties.AccessControl exists               << Clause 1 >>
    Properties.LoggingConfiguration exists        << Clause 2 >>
  }
}
```

The pseudocode for the above example is a follows,

```
isAccessControlExists = true
isLoggingConfigurationExists = true
result = true

for each_s3_bucket in s3_buckets do
    if each_s3_bucket.Properties.AccessControl == null then
        isAccessControlExists = false
    end of

    if each_s3_bucket.Properties.LoggingConfiguration == null then
        isLoggingConfigurationExists = false
    end if

    result = result and (isAccessControlExists and isLoggingConfigurationExists)
end for

return result
```

In the above example,
1. `Clause 1` and `Clause 2` are independent statements **within the scope of the query block**, i.e. for each S3 bucket in `%s3_buckets`.
1. `Clause 1` is evaluated on `AccessControl` property of the first S3 bucket in `%s3_buckets`.
1. `Clause 2` is evaluated after evaluation of `Clause 1` for that same S3 bucket.
1. `Clause 2` is evaluated on `LoggingConfiguration` property of that same S3 bucket.
1. Steps 2 through 4 are executed in that order for the remaining S3 buckets in `%s3_buckets` one after the other until there are no more S3 buckets in `%s3_buckets`.

### Example 1 vs Example 2

There is clearly a difference in the style of execution between Example 1 and Example 2. The clauses in Example 1 can be referred to as **Independent Clause Composition** with respect to S3 buckets in `%s3_buckets` and the clauses in Example 2 can be referred to as **Conjoined Clause Composition** with respect to S3 buckets in `%s3_buckets`. But looking at the pseudo code and the execution order description you can observe that the outcomes of both the examples are the same. However if the conjunction between `Clause 1` and `Clause 2` is switched to disjunction the outcomes would be different. Let us look at Example 1 and Example 2 with conjunction between `Clause 1` and `Clause 2`.

### Example 3 - Example 1 with disjunction between clauses

```
let s3_buckets = Resources.*[ Type == "AWS::S3::Bucket" ]

when %s3_buckets !empty {
  %s3_buckets.Properties.AccessControl exists <b>OR</b>            << Clause 1 >>
  %s3_buckets.Properties.LoggingConfiguration exists        << Clause 2 >>
}
```

The pseudocode for the above example is a follows,

```
isAccessControlExists = true
isLoggingConfigurationExists = true

for each_s3_bucket in s3_buckets do
    if each_s3_bucket.Properties.AccessControl == null then
        isAccessControlExists = false
    end if
end for

for each_s3_bucket in s3_buckets do
    if each_s3_bucket.Properties.LoggingConfiguration == null then
        isLoggingConfigurationExists = false
    end if
end for

return isAccessControlExists or isLoggingConfigurationExists
```

### Example 4 - Example 2 with disjunction between clauses

```
let s3_buckets = Resources.*[ Type == "AWS::S3::Bucket" ]

when %s3_buckets !empty {
  %s3_buckets {
    Properties.AccessControl exists <b>OR</b>            << Clause 1 >>
    Properties.LoggingConfiguration exists        << Clause 2 >>
  }
}
```

The pseudocode for the above example is a follows,

```
isAccessControlExists = true
isLoggingConfigurationExists = true
result = true

for each_s3_bucket in s3_buckets do
    if each_s3_bucket.Properties.AccessControl == null then
        isAccessControlExists = false
    end if

    if each_s3_bucket.Properties.LoggingConfiguration == null then
        isLoggingConfigurationExists = false
    end if

    result = result and (isAccessControlExists or isLoggingConfigurationExists)
end for

return result
```

### Example 3 vs Example 4

You can clearly see from the psuedo code for Example 3 and Example 4 that the order of evaluation in case of disjunction between `Clause 1` and `Clause 2` changes the outcome. From the above examples it is clear that using Conjoined Clause Composition allows you to write programatically intutive rules. We recommend using Conjoined Clause Composition over Independent Clause Composition for most cases.

## Complex Composition with Named Rule Blocks

There are two styles of composition where named rule blocks can demonstrate its capability for re-usability, improved composition, and reduced verbosity:

* Conditional dependency composition
* Correlational dependency composition

### Conditional dependency composition

In this style of composition, the evaluation of a `when` block or a named rule block has a conditional dependency on the evaluation result of one or more other named rule blocks and/or clauses. This can be achieved as follows:

```
# Named rule block, rule_name_A
rule rule_name_A {
    Guard_rule_1
    Guard_rule_2
    ...
}

# Example-1, Named rule block, rule_name_B, taking a conditional dependency on rule_name_A
rule rule_name_B when rule_name_A {
    Guard_rule_3
    Guard_rule_4
    ...
}

# Example-2, When block taking a conditional dependency on rule_name_A
when rule_name_A {
    Guard_rule_3
    Guard_rule_4
    ...
}

# Example-3, Named rule block, rule_name_C, taking a conditional dependency on rule_name_A ^ rule_name_B
rule rule_name_C when rule_name_A
                      rule_name_B {
    Guard_rule_3
    Guard_rule_4
    ...
}

# Example-4, Named rule block, rule_name_D, taking a conditional dependency on (rule_name_A v clause_A) ^ clause_B ^ rule_name_B
rule rule_name_D when rule_name_A OR
                      clause_A
                      clause_B
                      rule_name_B {
    Guard_rule_3
    Guard_rule_4
    ...
}
```

Let us take Example-1 to analyze how the evaluation result of `rule_name_A` influences the evaluation of `rule_name_B`.

* `rule_name_A` evaluates to a **PASS**

The Guard rules encapsulated by `rule_name_B` are evaluated.

* `rule_name_A` evaluates to a **FAIL**

The Guard rules encapsulated by `rule_name_B` are not evaluated. `rule_name_B` evaluates to a **SKIP**.

* `rule_name_A` evaluates to a **SKIP -** This can happen if `rule_name_A` conditionally depended on a Guard rule which evaluated to a **FAIL** and resulted in `rule_name_A` evaluating to a **SKIP**. 

The Guard rules encapsulated by `rule_name_B` are not evaluated. `rule_name_B` evaluates to a **SKIP**.

Let us take an example of examining a configuration management database (CMDB) configuration item from an AWS Config item for ingress and egress security groups information to see conditional dependency composition in action. 

```
rule check_resource_type_and_parameter {
    resourceType == /AWS::EC2::SecurityGroup/
    InputParameters.TcpBlockedPorts NOT EMPTY 
}

rule check_parameter_validity when check_resource_type_and_parameter {
    InputParameters.TcpBlockedPorts[*] {
        this in r[0,65535] 
    }
}

rule check_ip_procotol_and_port_range_validity when check_parameter_validity {
    let ports = InputParameters.TcpBlockedPorts[*]

    # 
    # select all ipPermission instances that can be reached by ANY IP address
    # IPv4 or IPv6 and not UDP
    #
    let configuration = configuration.ipPermissions[ 
        some ipv4Ranges[*].cidrIp == "0.0.0.0/0" or
        some ipv6Ranges[*].cidrIpv6 == "::/0"
        ipProtocol != 'udp' ] 
    when %configuration !empty {
        %configuration {
            ipProtocol != '-1'

            when fromPort exists 
                toPort exists {
                let ip_perm_block = this
                %ports {
                    this < %ip_perm_block.fromPort or
                    this > %ip_perm_block.toPort
                }
            }
        }
    }
}
```

`check_parameter_validity` is conditionally dependent on `check_resource_type_and_parameter` and `check_ip_procotol_and_port_range_validity` is conditionally dependent on `check_parameter_validity`. Below is a CMDB configuration item which conforms to the above rules:

```yaml
---
version: '1.3'
resourceType: 'AWS::EC2::SecurityGroup'
resourceId: sg-12345678abcdefghi
configuration:
  description: Delete-me-after-testing
  groupName: good-sg-test-delete-me
  ipPermissions:
    - fromPort: 172
      ipProtocol: tcp
      ipv6Ranges: []
      prefixListIds: []
      toPort: 172
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: 0.0.0.0/0
      ipRanges:
        - 0.0.0.0/0
    - fromPort: 89
      ipProtocol: tcp
      ipv6Ranges:
        - cidrIpv6: '::/0'
      prefixListIds: []
      toPort: 89
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: 0.0.0.0/0
      ipRanges:
        - 0.0.0.0/0
  ipPermissionsEgress:
    - ipProtocol: '-1'
      ipv6Ranges: []
      prefixListIds: []
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: 0.0.0.0/0
      ipRanges:
        - 0.0.0.0/0
  tags:
    - key: Name
      value: good-sg-delete-me
  vpcId: vpc-0123abcd
InputParameters:
  TcpBlockedPorts:
    - 3389
    - 20
    - 110
    - 142
    - 1434
    - 5500
supplementaryConfiguration: {}
resourceTransitionStatus: None
```

### Correlational dependency composition

In this style of composition the evaluation of a `when` block or a named rule block has a correlational dependency on the evaluation result of one or more other Guard rules. This can be achieved as follows:

```
# Named rule block, rule_name_A, taking a correlational dependency on all the Guard rules encapsulated by the named rule block
rule rule_name_A {
    Guard_rule_1
    Guard_rule_2
    ...
}

# When block taking a correlational dependency on all the Guard rules encapsulated by the when block
when condition {
    Guard_rule_1
    Guard_rule_2
    ...
}
```

Let us look at an example set of Guard rules to help you understand correlational dependency composition better.

```
#
# Allowed valid protocols for ELB
#
let allowed_protocols = [ "HTTPS", "TLS" ]

let elbs = Resources.*[ Type == 'AWS::ElasticLoadBalancingV2::Listener' ]

#
# If there ELBs present, ensure that ELBs have protocols specified from the 
# allows list and the Certificates are not empty
#
rule ensure_all_elbs_are_secure when %elbs !empty {
    %elbs.Properties {
        Protocol in %allowed_protocols
        Certificates !empty
    }
}

# 
# In addition to secure settings, ensure that ELBs are only private
#
rule ensure_elbs_are_internal_and_secure when %elbs !empty {
    ensure_all_elbs_are_secure
    %elbs.Properties.Scheme == 'internal'
}
```

`ensure_elbs_are_internal_and_secure` has a correlational dependency with `ensure_all_elbs_are_secure`. Below is an example CloudFormation template which conforms to the above rules.

```yaml
Resources:
  ServiceLBPublicListener46709EAA:
    Type: 'AWS::ElasticLoadBalancingV2::Listener'
    Properties:
      Scheme: internal
      Protocol: HTTPS
      Certificates:
        - CertificateArn: 'arn:aws:acm...'
  ServiceLBPublicListener4670GGG:
    Type: 'AWS::ElasticLoadBalancingV2::Listener'
    Properties:
      Scheme: internal
      Protocol: HTTPS
      Certificates:
        - CertificateArn: 'arn:aws:acm...'
```

## Validating Multiple Rules against Multiple Data Files

Guard is purpose-built for policy definition and evaluation on structured JSON- and YAML- formatted data. For better maintainability of rules, rule authors can write rules into multiple files and section them however they see fit and still be able to validate multiple rule files against a data file or multiple data files. The cfn-guard validate command can take a directory of files for the `--data` and `--rules` options. More information can be found in the [cfn-guard README](../guard/README.md).

```bash
cfn-guard validate --data /path/to/dataDirectory --rules /path/to/ruleDirectory
```

Where `/path/to/dataDirectory` has one or more data files and `/path/to/ruleDirectory` has one or more rules files.

Consider you are writing rules to check if various resources defined in multiple CloudFormation templates have appropriate property assignments which guarantees encryption at rest. For ease of searchability and maintainability you can decide to have rules for checking encryption at rest in each resource in separate files, e.g. `s3_bucket_encryption.guard`, `ec2_volume_encryption.guard`, `rds_dbinstance_encrytion.guard` and so on all inside one directory, `~/GuardRules/encryption_at_rest`. You have all your CloudFormation templates that you need to validate under `~/CloudFormation/templates`. The command will be as follows:

```bash
cfn-guard validate --data ~/CloudFormation/templates --rules ~/GuardRules/encryption_at_rest
```

We are currently working on a feature which might offer rule reusability across multiple files. More details to come as we make progress on the feature.
