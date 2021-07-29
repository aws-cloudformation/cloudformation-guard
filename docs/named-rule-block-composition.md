# Composing named\-rule blocks in AWS CloudFormation Guard<a name="named-rule-block-composition"></a>

When writing named\-rule blocks using AWS CloudFormation Guard, you can use the following two styles of composition:
+ Conditional dependency 
+ Correlational dependency 

Using either of these styles of dependency composition helps promote reusability and reduces verbosity and repetition in named\-rule blocks\.

**Topics**
+ [Prerequisites](#named-rules-prerequisites)
+ [Conditional dependency composition](#named-rules-conditional-dependency)
+ [Correlational dependency composition](#named-rules-correlational-dependency)

## Prerequisites<a name="named-rules-prerequisites"></a>

Learn about named\-rule blocks in [Writing rules](writing-rules.md#named-rule-blocks)\.

## Conditional dependency composition<a name="named-rules-conditional-dependency"></a>

In this style of composition, the evaluation of a `when` block or a named\-rule block has a conditional dependency on the evaluation result of one or more other named\-rule blocks or clauses\. The following example Guard rules file contains named\-rule blocks that demonstrate conditional dependencies\.

```
# Named-rule block, rule_name_A
rule rule_name_A {
    Guard_rule_1
    Guard_rule_2
    ...
}

# Example-1, Named-rule block, rule_name_B, takes a conditional dependency on rule_name_A
rule rule_name_B when rule_name_A {
    Guard_rule_3
    Guard_rule_4
    ...
}

# Example-2, when block takes a conditional dependency on rule_name_A
when rule_name_A {
    Guard_rule_3
    Guard_rule_4
    ...
}

# Example-3, Named-rule block, rule_name_C, takes a conditional dependency on rule_name_A ^ rule_name_B
rule rule_name_C when rule_name_A
                      rule_name_B {
    Guard_rule_3
    Guard_rule_4
    ...
}

# Example-4, Named-rule block, rule_name_D, takes a conditional dependency on (rule_name_A v clause_A) ^ clause_B ^ rule_name_B
rule rule_name_D when rule_name_A OR
                      clause_A
                      clause_B
                      rule_name_B {
    Guard_rule_3
    Guard_rule_4
    ...
}
```

In the preceding example rules file, `Example-1` has the following possible outcomes:
+ If `rule_name_A` evaluates to `PASS`, the Guard rules encapsulated by `rule_name_B` are evaluated\.
+ If `rule_name_A` evaluates to `FAIL`, the Guard rules encapsulated by `rule_name_B` are not evaluated\. `rule_name_B` evaluates to `SKIP`\.
+ If `rule_name_A` evaluates to `SKIP`, the Guard rules encapsulated by `rule_name_B` are not evaluated\. `rule_name_B` evaluates to `SKIP`\.
**Note**  
This case happens if `rule_name_A` conditionally depends on a rule that evaluates to `FAIL` and results in `rule_name_A` evaluating to `SKIP`\.

Following is an example of a configuration management database \(CMDB\) configuration item from an AWS Config item for ingress and egress security groups information\. This example demonstrates conditional dependency composition\.

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

In the preceding example, `check_parameter_validity` is conditionally dependent on `check_resource_type_and_parameter` and `check_ip_procotol_and_port_range_validity` is conditionally dependent on `check_parameter_validity`\. The following is a configuration management database \(CMDB\) configuration item that conforms to the preceding rules\.

```
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

## Correlational dependency composition<a name="named-rules-correlational-dependency"></a>

In this style of composition, the evaluation of a `when` block or a named\-rule block has a correlational dependency on the evaluation result of one or more other Guard rules\. Correlational dependency can be achieved as follows\.

```
# Named-rule block, rule_name_A, takes a correlational dependency on all of the Guard rules encapsulated by the named-rule block
rule rule_name_A {
    Guard_rule_1
    Guard_rule_2
    ...
}

# when block takes a correlational dependency on all of the Guard rules encapsulated by the when block
when condition {
    Guard_rule_1
    Guard_rule_2
    ...
}
```

To help you understand correlational dependency composition, review the following example of a Guard rules file\.

```
#
# Allowed valid protocols for AWS::ElasticLoadBalancingV2::Listener resources
#
let allowed_protocols = [ "HTTPS", "TLS" ]

let elbs = Resources.*[ Type == 'AWS::ElasticLoadBalancingV2::Listener' ]

#
# If there are AWS::ElasticLoadBalancingV2::Listener resources present, ensure that they have protocols specified from the 
# list of allowed protocols and that the Certificates property is not empty
#
rule ensure_all_elbs_are_secure when %elbs !empty {
    %elbs.Properties {
        Protocol in %allowed_protocols
        Certificates !empty
    }
}

# 
# In addition to secure settings, ensure that AWS::ElasticLoadBalancingV2::Listener resources are private
#
rule ensure_elbs_are_internal_and_secure when %elbs !empty {
    ensure_all_elbs_are_secure
    %elbs.Properties.Scheme == 'internal'
}
```

In the preceding rules file, `ensure_elbs_are_internal_and_secure` has a correlational dependency on `ensure_all_elbs_are_secure`\. The following is an example CloudFormation template that conforms to the preceding rules\.

```
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