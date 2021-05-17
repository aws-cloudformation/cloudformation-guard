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

1. Named rule blocks allow for re-usability, improved composition, and reduced verbosity and repetition. This document will focus on demonstrating these features of named rule blocks in-depth.

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

Guard is purpose-built for policy definition and evaluation on structured JSON- and YAML- formatted data. For better maintainability of rules, rule authors can write rules into multiple files and section them however they see fit and still be able to validate multiple rule files against a data file or multiple data files. The cfn-guard validate command can take a directory of files for the `--data` and `--rules` options. More information can be found in the [cfn-guard README](../cfn-guard/README.md).

```bash
cfn-guard validate --data /path/to/dataDirectory --rules /path/to/ruleDirectory
```

Where `/path/to/dataDirectory` has one or more data files and `/path/to/ruleDirectory` has one or more rules files.

Consider you are writing rules to check if various resources defined in multiple CloudFormation templates have appropriate property assignments which guarantees encryption at rest. For ease of searchability and maintainability you can decide to have rules for checking encryption at rest in each resource in separate files, e.g. `s3_bucket_encryption.guard`, `ec2_volume_encryption.guard`, `rds_dbinstance_encrytion.guard` and so on all inside one directory, `~/GuardRules/encryption_at_rest`. You have all your CloudFormation templates that you need to validate under `~/CloudFormation/templates`. The command will be as follows:

```bash
cfn-guard validate --data ~/CloudFormation/templates --rules ~/GuardRules/encryption_at_rest
```

We are currently working on a feature which might offer rule reusability across multiple files. More details to come as we make progress on the feature.

