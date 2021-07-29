# Defining queries and filtering<a name="query-and-filtering"></a>

This topic covers writing queries and using filtering when writing Guard rule clauses\.

## Prerequisites<a name="query-filtering-prerequisites"></a>

Filtering is an advanced AWS CloudFormation Guard concept\. We recommend that you review the following foundational topics before you learn about filtering:
+ [What is AWS CloudFormation Guard?](what-is-guard.md)
+ [Writing rules, clauses](writing-rules.md)

## Defining queries<a name="defining-queries"></a>

Query expressions are simple dot `(.)` separated expressions written to traverse hierarchical data\. Query expressions can include filter expressions to target a subset of values\. When queries are evaluated, they result in a collection of values, similar to a result set returned from an SQL query\.

The following example query searces a AWS CloudFormation template for `AWS::IAM::Role` resources\.

```
Resources.*[ Type == 'AWS::IAM::Role' ]
```

Queries follow these basic principles:
+ Each dot `(.)` part of the query traverses down the hierarchy when an explicit key term is used, such as `Resources` or `Properties.Encrypted.` If any part of the query doesn't match the incoming datum, Guard throws a retrieval error\.
+ A dot `(.)` part of the query that uses a wildcard `*` traverses all values for the structure at that level\.
+ A dot `(.)` part of the query that uses an array wildcard `[*]` traverses all indices for that array\.
+ All collections can be filtered by specifying filters inside square brackets `[]`\. Collections can be encountered in the following ways:
  + Naturally occurring arrays in datum are collections\. Following are examples:

    Ports: `[20, 21, 110, 190]`

    Tags: `[{"Key": "Stage", "Value": "PROD"}, {"Key": "App", "Value": "MyService"}]`
  + When traversing all values for a structure like `Resources.*`
  + Any query result is itself a collection from which values can be further filtered\. See the following example\.

    ```
    let all_resources = Resource.* # query let iam_resources = %resources[ Type == /IAM/ ] # filter from query results let managed_policies = %iam_resources[ Type == /ManagedPolicy/ ] # further refinements %managed_policies { # traversing each value # do something with each }
    ```

The following is an example CloudFormation template snippet\.

```
Resources:
  SampleRole:
    Type: AWS::IAM::Role
    ...
  SampleInstance:
    Type: AWS::EC2::Instance
    ...
  SampleVPC:
     Type: AWS::EC2::VPC
    ...
  SampleSubnet1:
    Type: AWS::EC2::Subnet
    ...
  SampleSubnet2:
    Type: AWS::EC2::Subnet
    ...
```

Based on this template, the path traversed is `SampleRole` and the final value selected is `Type: AWS::IAM::Role`\.

```
Resources:
  SampleRole:
    Type: AWS::IAM::Role
    ...
```

The resulting value of the query `Resources.*[ Type == 'AWS::IAM::Role' ]` in YAML format is shown in the following example\.

```
- Type: AWS::IAM::Role
  ...
```

Some of the ways that you can use queries are as follows:
+ Assign a query to variables so that query results can be accessed by referencing those variables\.
+ Follow the query with a block that tests against each of the selected values\.
+ Compare a query directly against a basic clause\.

## Assigning queries to variables<a name="queries-and-filtering-variables"></a>

Guard supports one\-shot variable assignments within a given scope\. For more information about variables in Guard rules, see [Assigning and referencing variables in Guard rules](variables.md)\.

You can assign queries to variables so that you can write queries once and then reference them elsewhere in your Guard rules\. See the following example variable assignments that demonstrate query principles discussed later in this section\.

```
#
# Simple query assignment
#
let resources = Resources.* # All resources

#
# A more complex query here (this will be explained below)
#
let iam_policies_allowing_log_creates = Resources.*[
    Type in [/IAM::Policy/, /IAM::ManagedPolicy/]
    some Properties.PolicyDocument.Statement[*] {
         some Action[*] == 'cloudwatch:CreateLogGroup'
         Effect == 'Allow'
    }
]
```

## Directly looping through values from a variable assigned to a query<a name="variable-assigned-from-query"></a>

Guard supports directly running against the results from a query\. In the following example, the `when` block tests against the `Encrypted`, `VolumeType`, and `AvailabilityZone` property for each `AWS::EC2::Volume` resource found in a CloudFormation template\.

```
let ec2_volumes = Resources.*[ Type == 'AWS::EC2::Volume' ] 

when %ec2_volumes !empty {
    %ec2_volumes {
        Properties {
            Encrypted == true
            VolumeType in ['gp2', 'gp3']
            AvailabilityZone in ['us-west-2b', 'us-west-2c']
        }
    }
}
```

## Direct clause\-level comparisons<a name="direct-clause-level-comparisons"></a>

Guard also supports queries as a part of direct comparisons\. For example, see the following\.

```
let resources = Resources.*
    
    some %resources.Properties.Tags[*].Key == /PROD$/
    some %resources.Properties.Tags[*].Value == /^App/
```

In the preceding example, the two clauses \(starting with the `some` keyword\) expressed in the form shown are considered independent clauses and are evaluated separately\.

### Single clause and block clause form<a name="single-versus-block-clause-form"></a>

Taken together, the two example clauses shown in the preceding section aren't equivalent to the following block\.

```
let resources = Resources.*

some %resources.Properties.Tags[*] {
    Key == /PROD$/
    Value == /^App/
}
```

This block queries for each `Tag` value in the collection and compares its property values to the expected property values\. The combined form of the clauses in the preceding section evaluates the two clauses independently\. Consider the following input\.

```
Resources:
  ...
  MyResource:
    ...
    Properties:
      Tags:
        - Key: EndPROD
          Value: NotAppStart
        - Key: NotPRODEnd
          Value: AppStart
```

Clauses in the first form evaluate to `PASS`\. When validating the first clause in first form, the following path across `Resources`, `Properties`, `Tags`, and `Key` matches the value `NotPRODEnd` and does not match the expected value `PROD`\.

```
Resources:
  ...
  MyResource:
    ...
    Properties:
      Tags:
        - Key: EndPROD
          Value: NotAppStart
        - Key: NotPRODEnd
          Value: AppStart
```

The same happens with the second clause of the first form\. The path across `Resources`, `Properties`, `Tags`, and `Value` matches the value `AppStart`\. As a result, the second clause independently\.

The overall result is a `PASS`\.

However, the block form evaluates as follows\. For each `Tags` value, it compares if both the `Key` and `Value` does match; `NotAppStart` and `NotPRODEnd` values are not matched in the following example\.

```
Resources:
  ...
  MyResource:
    ...
    Properties:
      Tags:
        - Key: EndPROD
          Value: NotAppStart
        - Key: NotPRODEnd
          Value: AppStart
```

Because evaluations check for both `Key == /PROD$/`, and `Value == /^App/`, the match is not complete\. Therefore, the result is `FAIL`\.

**Note**  
When working with collections, we recommend that you use the block clause form when you want to compare multiple values for each element in the collection\. Use the single clause form when the collection is a set of scalar values, or when you only intend to compare a single attribute\.

## Query outcomes and associated clauses<a name="query-outcomes"></a>

All queries return a list of values\. Any part of a traversal, such as a missing key, empty values for an array \(`Tags: []`\) when accessing all indices, or missing values for a map when encountering an empty map \(`Resources: {}`\), can lead to retrieval errors\.

All retrieval errors are considered failures when evaluating clauses against such queries\. The only exception is when explicit filters are used in the query\. When filters are used, associated clauses are skipped\.

The following block failures are associated with running queries\.
+ If a template does not contain resources, then the query evaluates to `FAIL`, and the associated block level clauses also evaluate to `FAIL`\.
+ When a template contains an empty resources block like `{ "Resources": {} }`, the query evaluates to `FAIL`, and the associated block level clauses also evaluate to `FAIL`\.
+ If a template contains resources but none match the query, then the query returns empty results, and the block level clauses are skipped\.

## Using filters in queries<a name="filtering"></a>

Filters in queries are effectively Guard clauses that are used as selection criteria\. Following is the structure of a clause\.

```
 <query> <operator> [query|value literal] [message] [or|OR]
```

Keep in mind the following key points from [](writing-rules.md) when you work with filters:
+ Combine clauses by using [Conjunctive Normal Form \(CNF\)](https://en.wikipedia.org/wiki/Conjunctive_normal_form)\.
+ Specify each conjunction \(`and`\) clause on a new line\.
+ Specify disjunctions \(`or`\) by using the `or` keyword between two clauses\.

The following example demonstrates conjunctive and disjunctive clauses\.

```
resourceType == 'AWS::EC2::SecurityGroup'
InputParameters.TcpBlockedPorts not empty 

InputParameters.TcpBlockedPorts[*] {
    this in r(100, 400] or 
    this in r(4000, 65535]
}
```

### Using clauses for selection criteria<a name="selection-criteria"></a>

You can apply filtering to any collection\. Filtering can be applied directly on attributes in the input that are already a collection like `securityGroups: [....]`\. You can also apply filtering against a query, which is always a collection of values\. You can use all features of clauses, including conjunctive normal form, for filtering\.

The following common query is often used when selecting resources by type from a CloudFormation template\.

```
Resources.*[ Type == 'AWS::IAM::Role' ]
```

The query `Resources.*` returns all values present in the `Resources` section of the input\. For the example template input in [Defining queries](#defining-queries), the query returns the following\.

```
- Type: AWS::IAM::Role
  ...
- Type: AWS::EC2::Instance
  ...
- Type: AWS::EC2::VPC
  ...
- Type: AWS::EC2::Subnet
  ...
- Type: AWS::EC2::Subnet
  ...
```

Now, apply the filter against this collection\. The criterion to match is `Type == AWS::IAM::Role`\. Following is the output of the query after the filter is applied\.

```
- Type: AWS::IAM::Role
  ...
```

Next, check various clauses for `AWS::IAM::Role` resources\.

```
let all_resources = Resources.*
let all_iam_roles = %all_resources[ Type == 'AWS::IAM::Role' ]
```

The following is an example filtering query that selects all `AWS::IAM::Policy` and `AWS::IAM::ManagedPolicy` resources\.

```
Resources.*[
    Type in [ /IAM::Policy/,
              /IAM::ManagedPolicy/ ]
]
```

The following example checks if these policy resources have a `PolicyDocument` specified\.

```
Resources.*[ 
    Type in [ /IAM::Policy/,
              /IAM::ManagedPolicy/ ]
    Properties.PolicyDocument exists
]
```

### Building out more complex filtering needs<a name="complex-filtering"></a>

Consider the following example of an AWS Config configuration item for ingress and egress security groups information\.

```
---
resourceType: 'AWS::EC2::SecurityGroup'
configuration:
  ipPermissions:
    - fromPort: 172
      ipProtocol: tcp
      toPort: 172
      ipv4Ranges:
        - cidrIp: 10.0.0.0/24
        - cidrIp: 0.0.0.0/0
    - fromPort: 89
      ipProtocol: tcp
      ipv6Ranges:
        - cidrIpv6: '::/0'
      toPort: 189
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: 1.1.1.1/32
    - fromPort: 89
      ipProtocol: '-1'
      toPort: 189
      userIdGroupPairs: []
      ipv4Ranges:
        - cidrIp: 1.1.1.1/32
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
InputParameter:
  TcpBlockedPorts:
    - 3389
    - 20
    - 21
    - 110
    - 143
```

Note the following:
+ `ipPermissions` \(ingress rules\) is a collection of rules inside a configuration block\.
+ Each rule structure contains attributes such as `ipv4Ranges` and `ipv6Ranges` to specify a collection of CIDR blocks\.

Let’s write a rule that selects any ingress rules that allow connections from any IP address and verifies that the rules do not allow TCP blocked ports to be exposed\.

Start with the query portion that covers IPv4, as shown in the following example\.

```
configuration.ipPermissions[
    #
    # at least one ipv4Ranges equals ANY IPv4
    #
    some ipv4Ranges[*].cidrIp == '0.0.0.0/0'
]
```

The `some` keyword is useful in this context\. All queries return a collection of values that match the query\. By default, Guard evaluates that all values returned as a result of the query are matched against checks\. However, this behavior might not always be what you need for checks\. Consider the following part of the input from the configuration item\.

```
ipv4Ranges: 
  - cidrIp: 10.0.0.0/24
  - cidrIp: 0.0.0.0/0 # any IP allowed
```

There are two values present for `ipv4Ranges`\. Not all `ipv4Ranges` values equal an IP address denoted by `0.0.0.0/0`\. You want to see if at least one value matches `0.0.0.0/0`\. You tell Guard that not all results returned from a query need to match, but at least one result must match\. The `some` keyword tells Guard to ensure that one or more values from the resultant query match the check\. If no query result values match, Guard throws an error\.

Next, add IPv6, as shown in the following example\.

```
configuration.ipPermissions[
    #
    # at-least-one ipv4Ranges equals ANY IPv4
    #
    some ipv4Ranges[*].cidrIp == '0.0.0.0/0' or
    #
    # at-least-one ipv6Ranges contains ANY IPv6
    #    
    some ipv6Ranges[*].cidrIpv6 == '::/0'
]
```

Finally, in the following example, validate that the protocol is not `udp`\.

```
configuration.ipPermissions[
    #
    # at-least-one ipv4Ranges equals ANY IPv4
    #
    some ipv4Ranges[*].cidrIp == '0.0.0.0/0' or
    #
    # at-least-one ipv6Ranges contains ANY IPv6
    #    
    some ipv6Ranges[*].cidrIpv6 == '::/0'
    
    #
    # and ipProtocol is not udp
    #
    ipProtocol != 'udp' ] 
]
```

The following is the complete rule\.

```
rule any_ip_ingress_checks
{

    let ports = InputParameter.TcpBlockedPorts[*]

    let targets = configuration.ipPermissions[
        #
        # if either ipv4 or ipv6 that allows access from any address
        #
        some ipv4Ranges[*].cidrIp == '0.0.0.0/0' or
        some ipv6Ranges[*].cidrIpv6 == '::/0'

        #
        # the ipProtocol is not UDP
        #
        ipProtocol != 'udp' ]
        
    when %targets !empty
    {
        %targets {
            ipProtocol != '-1'
            <<
              result: NON_COMPLIANT
              check_id: HUB_ID_2334
              message: Any IP Protocol is allowed
            >>

            when fromPort exists 
                 toPort exists 
            {
                let each_target = this
                %ports {
                    this < %each_target.fromPort or
                    this > %each_target.toPort
                    <<
                        result: NON_COMPLIANT
                        check_id: HUB_ID_2340
                        message: Blocked TCP port was allowed in range
                    >>
                }
            }

        }       
     }
}
```

### Separating collections based on their contained types<a name="splitting-collection"></a>

When using infrastructure as code \(IaC\) configuration templates, you might encounter a collection that contains references to other entities within the configuration template\. The following is an example CloudFormation template that describes Amazon Elastic Container Service \(Amazon ECS\) tasks with a local reference to `TaskRoleArn`, a reference to `TaskArn`, and a direct string reference\.

```
Parameters:
  TaskArn:
    Type: String
Resources:
  ecsTask:
    Type: 'AWS::ECS::TaskDefinition'
    Metadata:
      SharedExectionRole: allowed
    Properties:
      TaskRoleArn: 'arn:aws:....'
      ExecutionRoleArn: 'arn:aws:...'
  ecsTask2:
    Type: 'AWS::ECS::TaskDefinition'
    Metadata:
      SharedExectionRole: allowed
    Properties:
      TaskRoleArn:
        'Fn::GetAtt':
          - iamRole
          - Arn
      ExecutionRoleArn: 'arn:aws:...2'
  ecsTask3:
    Type: 'AWS::ECS::TaskDefinition'
    Metadata:
      SharedExectionRole: allowed
    Properties:
      TaskRoleArn:
        Ref: TaskArn
      ExecutionRoleArn: 'arn:aws:...2'
  iamRole:
    Type: 'AWS::IAM::Role'
    Properties:
      PermissionsBoundary: 'arn:aws:...3'
```

Consider the following query\.

```
let ecs_tasks = Resources.*[ Type == 'AWS::ECS::TaskDefinition' ]
```

This query returns a collection of values that contains all three `AWS::ECS::TaskDefinition` resources shown in the example template\. Separate `ecs_tasks` that contain `TaskRoleArn` local references from others, as shown in the following example\.

```
let ecs_tasks = Resources.*[ Type == 'AWS::ECS::TaskDefinition' ]

let ecs_tasks_role_direct_strings = %ecs_tasks[ 
    Properties.TaskRoleArn is_string ]

let ecs_tasks_param_reference = %ecs_tasks[
    Properties.TaskRoleArn.'Ref' exists ]

rule task_role_from_parameter_or_string {
    %ecs_tasks_role_direct_strings !empty or
    %ecs_tasks_param_reference !empty
}

rule disallow_non_local_references {
    # Known issue for rule access: Custom message must start on the same line
    not task_role_from_parameter_or_string 
    <<
        result: NON_COMPLIANT
        message: Task roles are not local to stack definition
    >>
}
```