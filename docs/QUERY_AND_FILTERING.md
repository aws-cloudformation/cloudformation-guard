# Guard: Query and Filtering    

This chapter is very foundational for writing effective Guard policy rules. Since this is a more advanced topic, readers are encouraged to complete [AWS CloudFormation Guard](../README.md) introduction and [Guard: Clauses](CLAUSES.md) document. Let’s begin.

## Defining Queries

*Query expressions* are simple decimal dot formatted expressions written to traverse hierarchical data. Query expressions can include filter expressions to target a subset of values. When queries are evaluated they result in a collection of values, similar to a result set returned from an SQL query.

Let us begin with a sample query that is common when dealing with AWS CloudFormation templates:

```
Resources.*[ Type == 'AWS::IAM::Role' ]
```

Let’s look at the structure of the example CloudFormation template snippet below to understand the query: 

```yaml
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

Queries follow these basic principles:

1. Each decimal dotted portion traverses down the hierarchy when an explicit key term is used, like `Resources` or `Properties.Encrypted`. It is a retrieval error if any part does not match the incoming datum. 
2. Dotted portion that uses a wildcard `*` traverses all values for the structure at that level. 
3. Dotted portion that uses an array wildcard `[*]` traverses all indices for that array. 
4. All collections can be filtered by specifying filters inside square brackets `[]`. Collections can be encountered in 3 ways:
    1. Naturally occurring arrays in datum are collections. For example, `ports: [20, 21, 110, 190]` or `Tags: [{"Key": "Stage", "Value": "PROD"}, {"Key": "App", "Value": "MyService"}]` 
    2. When traversing all values for a struct like, `Resources.*`  
    3. Any query result is itself a collection, from which values can be further filtered. For example:
    4. let all_resources = Resource.* # query
        let iam_resources = %resources[ Type == /IAM/ ] # filter from query results
        let managed_policies = %iam_resources[ Type == /ManagedPolicy/ ] # further refinements
        %managed_policies { # traversing each value
           # do something with each
        }

What is the result of the query `Resources.*[ Type == 'AWS::IAM::Role' ]`? The path traversed is `SampleRole` and the final value selected is `Type: AWS::IAM::Role`:

```yaml
Resources:
  SampleRole:
    Type: AWS::IAM::Role
    ...
```

The resulting value for the query, in YAML format, is:

```yaml
- Type: AWS::IAM::Role
  ...
```

Queries can: 

* be assigned to variables and query results can be accessed using variables.
* have a block following the query that works against each of the selected values.
* be directly compared against for a basic clause.

Let’s discover each of these.

## Variable Assignments

Guard supports single shot variable assignments within a given scope. There can be only one same named variable defined within a scope. Queries are often assigned to variables so that can be written once and referenced everywhere else. Here are some sample examples:

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

## Directly Looping through Values from a Variable Assigned from Query

Guard supports directly executing against the results from the query. Here is an example: 

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

The associated block shown with `{}` after the query `Resources.*[ Type == 'AWS::EC2::Volume' ]` will test against every `AWS::EC2::Volume` found inside a CloudFormation template.

## Direct Clause Level Comparisons

Guard supports queries as a part of direct comparisons as well. Here is an example: 

```
let resources = Resources.*

some %resources.Properties.Tags[*].Key == /PROD$/
some %resources.Properties.Tags[*].Value == /^App/
```

The two clauses (starting with `some`) expressed in the form shown above are considered *_independent_* clauses, and are evaluated separately.

### Understanding difference between single clause and Bbock clause form

The two clauses shown above (starting with `some`) together are not equivalent to the block shown below:

```
let resources = Resources.*

some %resources.Properties.Tags[*] {
    Key == /PROD$/
    Value == /^App/
}
```

This second form anchors for each `Tag` value in the collection and compares. The first form evaluates two clauses independently instead. Consider the following input:

```yaml
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

Clauses in the first form will `PASS`, but the second form will `FAIL`. Recall, the `some` keyword matches at-least-one or more. When validating against the first clause in first form, the path shown below across `Resources`, `Properties`, `Tags` and `Key` matches; *`NotPRODEnd`* shown below does not match: since the comparison is at-least-one,  `some %resources.Properties.Tags[*].Key == /PROD$/` does match:

```yaml
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

The same happens with the second clause of the first form: the path across `Resources`, `Properties`, `Tags` and `Value` matches, `NotAppStart` does not match and `AppStart` matches. Hence, the second clause independently matches:

```yaml
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

The overall result ends up being a `PASS`. 

The block form, on the other hand, evaluates as follows: for each `Tag` value, it compares if both the `Key` and `Value` does match; `NotAppStart` and `NotPRODEnd` values shown below are not matched:

```yaml
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

As evaluations check for both `Key == /PROD$/`, and `Value == /^App/` we failed to completely match and hence the result is `FAIL`.


> **PRO TIP:** When dealing with collections, always prefer the block clause form when multiple values need to be compared for each element in the collection. It is safe to use the single clause form when the collection is a set of scalar values or you only intend to compare a single attribute.


## Understanding Query Outcomes and Associated Clauses

All queries return a list of values. Any part of a traversal like missing key, empty values for an array (`Tags: []`) when accessing all indices or missing values for a map when encountering an empty map (`Resources: {}`) all lead to retrieval errors.

All retrieval errors are considered failures when evaluating clauses against such queries. The only exception to this is when explicit filters are being used as a part of the query. When filters are associated as a part of the query then clauses associated are skipped. 

### Understanding query executions and associated block failures

1. If a template contains no `Resources` (e.g., `{}`), then the query will `FAIL` and the associated block level clauses will also `FAIL`.
2. When a template contains an empty `Resources` block like `{ "Resources": {} }`, the query will `FAIL` and the associated block level clauses also `FAIL`.
3. A template contains resources but none match, for example, a `AWS::EC2::Volume` resource type, then the query will return empty results and the block level clauses will be skipped.

## Introducing Filtering

Before we introduce filters in depth, let us summarize Guard clauses. Filters in queries are effectively Guard clauses that are used as selection criteria. Recall the structure of a clause:

```
  <query> <operator> [query|value literal] [message] [or|OR]
```


Key learnings from the [Guard: Clauses](CLAUSES.md) document that we should keep in mind:

1. Clauses can be combined using the Conjunctive Normal Form (CNF).
2. Conjunctions (`and`) clauses are specified on a separate new line for each one. 
3. Disjunctions (`or`) are specified by using the `or` keyword between 2 clauses. 

Example set of conjunction clauses and disjunction:

```
resourceType == 'AWS::EC2::SecurityGroup'
InputParameters.TcpBlockedPorts not empty 

InputParameters.TcpBlockedPorts[*] {
    this in r(100, 400] **or** 
    this in r(4000, 65535]
}
```

### Using clauses for selection criteria


> **IMPORTANT**: Filtering can be applied to any collection. Filtering can be applied directly on attributes in the input that are already a collection like `securityGroups: [....]`. It can also be applied against a query which is always a collection of values. Examples shown below often exercise filtering against query results.


Here is a common clause we saw earlier in the document that is often used when selecting resources by type from with a CloudFormation template:

```
Resources.*[ Type == 'AWS::IAM::Role' ]
```

Here `Resources.*` is a query that returns all values present for the `Resources` attribute in the input. For the template input shown, the query returns: 

```yaml
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

Now the filter is applied against this collection. The criterion to match is `Type == AWS::IAM::Role`. Hence, the output of the query after with the filter is applied is: 

```yaml
- Type: AWS::IAM::Role
  ...
```

Now various clauses can be checked for `AWS::IAM::Role` resource types. One can imagine the evaluation to be in 2 steps as shown next:

```
let all_resources = Resources.*
let all_iam_roles = %all_resources[ Type == 'AWS::IAM::Role' ]
```

You can read more about variable assignment for queries, applying further filtering and view projections in [ADD LINK HERE].

Here is an example filtering query that selects all `IAM::Policy` and `IAM::ManagedPolicy` resource types: 

```
Resources.*[
    Type in [ /IAM::Policy/,
              /IAM::ManagedPolicy/ ]
]
```

`AND` further checks if these policies that have a `PolicyDocument` specified. The complete power of clauses, including Conjunctive Normal Form, can be used for filtering:

```
Resources.*[ 
    Type in [ /IAM::Policy/,
              /IAM::ManagedPolicy/ ]
    Properties.PolicyDocument exists
]
```

### Building out more complex filtering needs

Let us take an example of examining an AWS Config item for Ingress and Egress security groups information. A sample of the Configuration Item is shown next:

A sample of the Configuration Item is as shown 

```yaml
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

Note:

1. `ipPermissions` (ingress rules) is a collection of rules inside `configuration` block
2. each `Rule` structure contains attributes such as `ipv4Ranges`, `ipv6Ranges` to specify a collection of CIDR blocks

Let’s write a rule as follows: select any ingress rule that allows connections from any IP address, and verify that the rule does not allow TCP blocked ports from being exposed.

Let’s start with the query portion that covers IPv4:

```
configuration.ipPermissions[
    #
    # at-least-one ipv4Ranges equals ANY IPv4
    #
    some ipv4Ranges[*].cidrIp == '0.0.0.0/0'
]
```

Let’s look into the `some` keyword in this context. All queries return a collection of values that match the query. By default, Guard evaluates that all values returned as a result of the query are matched against checks. However, this behavior might not be what you need for checks all the time. Consider this part of the input from the configuration item shown above:

```yaml
ipv4Ranges: 
  - cidrIp: 10.0.0.0/24
  - cidrIp: 0.0.0.0/0 # any IP allowed
```

Here we have 2 values present for `ipv4Ranges`. Not all `ipv4Ranges` values equal any IP address denoted by `'0.0.0.0/0'`. You intend to see if at-least-one value matches `'0.0.0.0/0'`. You tell Guard that not all results returned from a query need to match, we want at-least-one to match, and the `some` keyword tells Guard exactly that. It is effectively saying to ensure one or more values from the resultant query match the check. It is a failure if `none` match. 

You then add IPv6 (it is an `or` as either IPv4 exists or IPv6):

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

And finally, validate the protocol is not `udp`:

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

Let’s put it all together for a complete rule:

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

### Splitting collection based on contained type

When dealing with infrastructure-as-code configuration templates, you can often encounter a collection that contains references to other entities within the configuration template. The following is an example of a CloudFormation template that describes Amazon Elastic Container Service (Amazon ECS) tasks with a local reference for `TaskRoleArn`, a reference to the `TaskArn` parameter, and a direct string reference: 

```yaml
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

Consider the following query: 

```
let ecs_tasks = Resources.*[ Type == 'AWS::ECS::TaskDefinition' ]
```

This query returns a collection of values that contains all 3 `AWS::ECS::TaskDefinition` resources shown in the example above. You want to split `ecs_tasks` that contain `TaskRoleArn` local references from others:

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
    # known issue for rule access - need custom message to start on the same line
    not task_role_from_parameter_or_string 
    << 
        result: NON_COMPLIANT
        message: Task roles are not local to stack definition
    >>
}
```




