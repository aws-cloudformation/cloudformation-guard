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

### Understanding difference between single clause and Block clause form

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

What a filter applies to is decided by the part of the query directly before it. After a part that names a collection -- a key such as `Resources`, the `this` keyword, or a variable standing in a key's place such as `%names` -- the filter selects among that collection's entries: `Resources[ Type == 'AWS::S3::Bucket' ]` and `Resources { this[ Type == 'AWS::S3::Bucket' ] ... }` select the same buckets, and over a bare `Resources:` or `Resources: {}` both select nothing (with a capture, the key spelling `Resources[ id | ... ]` binds the logical ids, and the `this` spelling is refused until binding after `this` over a map is designed; see the table under captures below, and the note after it for an absent `Resources`). After a part that names one value -- an index such as `Rules[0]`, an earlier filter, a `[ keys == ... ]` filter, or the member a `[*]` or `.*` wildcard expanded -- the filter tests that one value and keeps it when the predicate holds: `Rules[0][ Action == 'allow' ]` is the first rule if its action is `allow` and nothing otherwise. Over a list the filter always selects among the members. A `[*]` over a map hands the map on when it is one object rather than a collection, so that `Statement[*].Action` reads an IAM `Statement` written as one object or as a list, and a filter straight after it tests that object. The map's shape decides: a map one of whose entries is a non-null scalar is one object, because the members a filter over properties selects among are maps; a map whose entries are all maps, lists or nulls, as `Resources` and `Parameters` are (even with a parameter literally named `Type`, or a bare key beside a resource), is a collection, and `[*]` enumerates it and the filter selects among its entries, as `.*` does; a null entry is an absent value, not a field. So `Statement[*][ Effect == 'Allow' Action == '*' ] empty`, `Statement[*][ Principal.AWS == '*' ] empty`, `Statement[*][ this.Effect == 'Allow' this.Action == '*' ] empty` and `Statement[*][ Condition !exists ] !empty` read the one-object and the one-element-list statement alike, whatever the predicate names, where over the one object they used to expand it into entries the filter could not test, and `empty` passed a statement that allows everything at exit 0. A capture on the wildcard or in the filter (`Statement[ s ][ ... ]`, `Statement[*][ s | ... ]`) binds the object itself, as it binds a list's element. A map that mixes map-valued entries with a scalar, `Resources` with a string entry beside the resources, keeps the one-object reading unless the predicate names a key its map-valued entries hold (`Type`, which every resource carries): then the filter is refused in both polarities, naming the stray entry, since the author wrote a selection among members. A filter after `.*` over a map with the one-object shape is refused in both polarities as well: `.*` enumerates entries and has no array-or-single reading, so `Statement.*[ Effect == 'Allow' Action == '*' ] empty` no longer passes a one-object allow-all statement; write `Statement[*][ ... ]`. A one-object statement whose every field is an intrinsic or a list has no scalar entry and is read as a collection; that is the limit of a reading by shape, and it is disclosed rather than guessed at. A filter after a key that holds a scalar has nothing to select among and is an error in both polarities, and a filter over a scalar member that a wildcard expanded is reported as unresolved, as that member is a field of the object the author named rather than a thing a predicate over properties can test. The entry a `[ keys == ... ]` filter selects is one value the author asked for by key, so a filter after it tests that value: `Tags[ keys == 'Name' ][ this == 'alpha' ] exists` holds when the `Name` tag is `alpha`, and when two keys match each selected entry is tested on its own.

One consequence for block rules: in `Rules[*] { this[ Action == 'allow' ] exists }` the `this` inside the block is one rule, a map, so `this[ Action == 'allow' ]` selects among that rule's own entries and selects nothing; it never asks about the rule's action. Because `Action` is a key of the rule itself, the clause is refused rather than left not applicable: it fails in both polarities, the file exits with the validation failure code, and the refusal names the spellings that carry the intent, leading with the one that is right where the clause sits. To test each member's own property, write the clause without the filter in the block, `Rules[*] { Action == 'allow' }`; from outside the block, `X[*] { Key == value }` or `X[*].Key == value`, where `X` is the query that named the member (`Rules` here) and `Key` the key the predicate read, reads a `Rules` written as one object and as a list alike, where the key-spelled filter `Rules[ Action == 'allow' ] exists` reads only the list and over the one object is the misreading described next.

The key spelling of the same misreading is refused the same way, and it is the more common one: `Resources.B1[ Type == 'AWS::S3::Bucket' ] exists` selects among `B1`'s own entries, `Type` and `Properties`, keeps none, and `Type` is a key of `B1` itself, so the clause fails in both polarities and the file exits with the validation failure code where it used to report the rule as not applicable at exit 0. The refusal names the two spellings that read one map and a list of such maps alike, `X[*] { Key == value }` and `X[*].Key == value`, and then says once what `X` and `Key` stand for: `X` is the query the author wrote before the filter, `Resources.B1`, and `Key` the key the predicate read, so the spellings test the map in hand, `Resources.B1[*] { Type == 'AWS::S3::Bucket' }` or `Resources.B1[*].Type == 'AWS::S3::Bucket'`. After a key it does not lead with the in-block spelling `Resources.B1 { Type == 'AWS::S3::Bucket' }`, which reads nothing over a list; inside a block over members (above), where the block is already over one member, the in-block spelling comes first. The placeholders keep the spellings short, and the console summary prints the refusal whole, so both spellings and the definition of `X` show for a key as long as `ServerSideEncryptionConfiguration`, with the path last. Where the entry under the key is itself a plain member map, a member named like the key, one more sentence sits between the definition of `X` and the path, "For each member's own `Key`: `X.*.Key` or `X.* { Key == value }`.", for the author who meant the members; it shows whole on the console and in the JSON and YAML reports, whatever the length of the key and of the query written before the filter. The shape this reaches most is an IAM `Statement` written as a single object: `PolicyDocument.Statement[ Effect == 'Allow' Action == '*' ] empty` passed such a statement whatever its `Action`, and is now refused; `Statement[*] { Effect == 'Allow' Action != '*' }` and `Statement[*].Action != '*'` read the single object and the list the same way, where `Statement.Action` reads only the object; `Statement[*][ Effect == 'Allow' Action == '*' ] empty` reads both as well, since the filter after `[*]` tests the one object (above), but is not named by the refusal because a filter is what it refused. A filter that keeps an entry and whose later parts then find nothing is not refused, and neither is a filter over a collection whose members each carry the key, even when the collection has an entry named like it (`Parameters[ Type == 'Number' ]` with a parameter called `Type`).


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

#### Filtering through a variable

A filter applied through a variable reads the value the variable holds by its shape, classified as the author's `%r[*][ ... ]` classifies it, and parts from `[*]` where the `[*]` rule refuses or enumerates what cfn-guard 3.2.1 decided on the map. Over a list it walks the elements, exactly as the same filter on the literal path does: `let l = Cfg.Items` followed by `%l[ this > 80 ]` selects the same elements as `Cfg.Items[ this > 80 ]`. Over a map with no scalar entry that holds no key the predicate names it walks the entries, as the literal and `[*]` do: `let r = Resources` followed by `%r[ Type == 'AWS::S3::Bucket' ]` selects the same resources as `Resources[ Type == 'AWS::S3::Bucket' ]`. Over a map holding one member map that lacks the key an absence predicate names it tests the map as one object, as 3.2.1 did: `let md = Resources.Node.Metadata` followed by `%md[ "AWS::CloudFormation::Authentication" !exists ]` over a `Metadata` holding only an init block selects the map, where the literal and `[*]` select the block. Over a map with a non-null scalar entry whose keys the predicate does not read as member keys it tests the map itself as one object, as `[*]` does. Over a map with no scalar entry that holds a key the predicate names, alone or beside a sub-map that holds it too, it tests the map as one object, the reading 3.2.1 gave, where `[*]` refuses the first shape and enumerates the second. Over a mixed map, a scalar beside a sub-map that holds a key the predicate names, it tests the map as one object too, as 3.2.1 did, except where the literal `K[ ... ]` refuses the filter, when the variable is refused the same way; `[*]` refuses every mixed map.

This matters when the variable holds a map and the predicate is written against that map's own keys. `let m = Resources.WebServer` followed by `%m[ Metadata."AWS::CloudFormation::Authentication" exists ]` tests the one resource named `WebServer` as one object, since its `Type` string is a scalar entry, and selects it when the block is there, as `Resources.WebServer[*][ ... ]` does. A `Metadata` attribute holding only sub-maps, under `let md = Resources.WebServer.Metadata` and `%md[ "AWS::CloudFormation::Authentication" exists ]`, is one object too and selects the map, the reading cfn-guard 3.2.1 gave, where the literal `Resources.WebServer.Metadata[ ... ]` is refused; the same `Metadata` with a `Wrapper` entry that holds an authentication block of its own is still one object, and a rule over the selection reads the map's own block, where the literal selects `Wrapper`; a map with no scalar entry under a predicate naming no key of the map itself is walked, as the literal is, except a map holding one member map that lacks the key an absence predicate names, which is one object, as 3.2.1 read it; a map whose own key the predicate names is one object even where that key is also the name of one of its members (`let r = Resources` then `%r[ BucketA exists ]` selects `Resources`, where the literal `Resources[ BucketA exists ]` is refused). See [Guard: Clauses](CLAUSES.md#filtering-through-a-variable) for what the selection then holds and what a rule over it reports, for the notice that reports a filter whose selection changed, and for the two ways to write what was meant.

### Capturing what a filter selected

A filter can name what it selects by writing a variable name and a `|` ahead of its clauses. The name is bound for the rest of the scope the filter is written in, and later clauses read it as `%name`:

```
rule buckets_are_named_for_their_id {
    Resources[ id | Type == 'AWS::S3::Bucket' ] !empty
    %id == /^Bucket/
}
```

What the name is bound to follows one contract, whichever path the filter is reached by:

- A filter over a map's entries binds the **keys** of the entries it kept. `Resources[ id | ... ]`, `Resources[*][ id | ... ]`, `Resources.*[ id | ... ]` and a filter on a variable holding `Resources.*[ ... ]` all bind the logical ids.
- A filter over a list binds the **elements** it kept. `Tags[ t | Key == 'Name' ]` and `Tags[*][ t | Key == 'Name' ]` bind the matching tag, so `%t.Value == 'dev'` reads its value and `%t exists` is decided rather than skipped. A named wildcard over a list, `Tags[ t ]`, binds every element.
- A map key filter, `Resources[ id | keys == /^Bucket/ ]`, binds the matching keys.

A captured value is read whole: `%t[ Key == 'Name' ]` tests the captured tag itself, not the tag's own entries, and a captured list is a list to `IS_LIST`.

The name lives in the scope the filter is written in. Inside a block clause or a type block it is bound per iteration -- per resource -- so a clause reading it in one resource's turn sees that resource's capture only, and a clause after the block reads the union over every iteration. A capture made in a rule's `when` condition belongs to that rule and is not visible to a rule that references it, nor the other way round.

Two limits. A captured value used as an interpolated key, `Resources.%name`, has to be a string, so a tag bound by a list filter is refused there. And a filter whose preceding part is neither a key nor a wildcard -- `Rules[0][ name | ... ]`, `this[ name | ... ]` -- binds only over a list, where the members are the entries. What each position does with each kind of value, with and without a capture, is one table; a capture never changes which value is selected, it binds or it is refused. "Refused" means the clause fails in both polarities and the run goes on to report every other rule (the template's value decides whether a position binds: `this` is whatever the block is over, and `Rules[0]` is a list on one template and a map on another), and a refused capture is announced once per clause on stderr as a warning naming the capture and the clause, so an `or` sibling that decides past it does not hide it. Inside a filter predicate, `Resources.*[ Properties.Rules[0][ r | Action == 'allow' ] exists ]`, the refusal is read as a key filter nobody can decide is read there: a resource whose first rule is a map leaves a selection nobody could decide, the predicate's clause raises on it, no entry is selected or deselected on it, and the clause that uses the filter fails closed whatever the operator (`exists`, `!exists` or `empty`), with the warning and the reason naming the capture. A refusal is not an absence: read as one, `!exists` and `empty` would have selected that resource for the capture's sake, and the capture would have changed the selection.

| the part before the filter | a list | a map with entries | `{}` | `null` | a scalar |
| --- | --- | --- | --- | --- | --- |
| a key, no capture | selects among the members | selects among the entries | selects nothing | the absent key: unresolved | refused, with a notice |
| a key, with a capture | binds the members | binds the keys | selects nothing | the absent key: unresolved | refused, with a notice |
| `this`, no capture | selects among the members | selects among the entries | selects nothing | the absent key: unresolved | refused, with a notice |
| `this`, with a capture | binds the members | refused, warning | selects nothing | the absent key: unresolved | refused, with a notice and the warning; inside a filter predicate the capture is what is refused, with the warning and no notice |
| an index, an earlier filter or a map-key filter, no capture | selects among the members | tests the value, keeps it when the predicate holds | tests the value | tests the value | tests the value |
| an index, an earlier filter or a map-key filter, with a capture | binds the members | refused, warning | refused, warning | refused, warning | refused, warning |

"The absent key: unresolved" is the reading a filter after a key gets when the key is missing, and a bare `Tags:` (`null` in YAML) is that key spelled with no value. The polarity decides what that means: under `exists` the assertion fails, a surrounding filter deselects the resource and a `when` gate over it stays closed; under `!exists` the assertion passes, the surrounding filter selects the resource and the gate opens. The one exception is directly on the document's own population, where a bare `Resources:` selects nothing as `{}` does, in the key spelling `Resources[ ... ]` and in the block spelling `Resources { this[ ... ] ... }` alike (the block over the population knows that its `this` is the population, so `this.*[ ... ]` over `Resources: {}` is the empty selection `Resources.*[ ... ]` is, too). An absent `Resources` is the empty selection in the key spelling, while the block clause has no value to open its block over and fails, as every block clause over an absent value does.

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
      SharedExecutionRole: allowed
    Properties:
      TaskRoleArn: 'arn:aws:....'
      ExecutionRoleArn: 'arn:aws:...'
  ecsTask2:
    Type: 'AWS::ECS::TaskDefinition'
    Metadata:
      SharedExecutionRole: allowed
    Properties:
      TaskRoleArn:
        'Fn::GetAtt':
          - iamRole
          - Arn
      ExecutionRoleArn: 'arn:aws:...2'
  ecsTask3:
    Type: 'AWS::ECS::TaskDefinition'
    Metadata:
      SharedExecutionRole: allowed
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




