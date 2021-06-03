# Guard: Clauses

Clauses are the foundational underpinning of Guard rules. Clauses are boolean statements which evaluate to a `true` (`PASS`)/ `false` (`FAIL`) and take the following format:

```
  <query> <operator> [query|value literal] 
```

You must specify a `query` and an `operator` in the clause section:

* `query` in its most simple form is a decimal dot (`.`) formatted expressions written to traverse hierarchical data. More information on this section of the clause can be found in the [Guard: Query and Filtering](QUERY_AND_FILTERING.md) document.

* `operator` can use *unary* or *binary* operators. Both of these operators will be discussed in-depth later in this document:

  * *Unary Operators:* `exists`, `empty`, `is_string`, `is_list`, `is_struct`, `not(!)`
  * *Binary Operators:* `==`, `!=`, `>`, `>=`, `<`, `<=`, `IN`

The `query|value literal` section of the clause is optional:

* `query|value literal` the third section of a clause is needed when a binary operator is used. It can be a `query` as defined above or it can be any supported value literal like `string`, `integer(64)`, etc.

Below are some examples for clauses:

* Clauses using unary operator:

```
# The collection TcpBlockedPorts cannot be empty
InputParameters.TcpBlockedPorts not empty  
```

```
# ExecutionRoleArn must be a string
Properties.ExecutionRoleArn is_string
```

* Clauses using binary operator:

```
# BucketName must not contain the string "encrypt" irrespective of casing
Properties.BucketName != /(?i)encrypted/
```

```
# ReadCapacityUnits must be less than or equal to 5000
Properties.ProvisionedThroughtput.ReadCapacityUnits <= 5000
```

## Operators

Let us look at Guard supported `operators` in-depth. Information on each operator will be accompanied by examples based on the following example CloudFormation template to help you understand the various operators. All examples in this section will be based on the following template:

```yaml
# Template-1
Resources:
  S3Bucket:
    Type: "AWS::S3::Bucket"
    Properties:
      BucketName: "MyServiceS3Bucket"
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: 'aws:kms'
              KMSMasterKeyID: 'arn:aws:kms:us-east-1:123456789:key/056ea50b-1013-3907-8617-c93e474e400'
      Tags:
        - Key: "stage"
          Value: "prod"
        - Key: "service"
          Value: "myService"
```

### Unary Operators

#### `empty` and `exists` operators

Guard introduces `empty` and `exists` operators to assist authors verify states of the `query` in a clause. You can use the  `not(!)` operator with both these operators to check the inverse state.

`empty`- Checks if a collection is empty. It can also be used to check if a query has values in a hierarchical data as all queries result in a collection, more about queries is mentioned in the [Guard: Query and Filtering](QUERY_AND_FILTERING.md) document.

```
# Checks if the template has resources defined
Resources !empty
```

```
# Checks if one or more tags defined
Resources.S3Bucket.Properties.Tags !empty
```

The above two clauses will `PASS` for the example template. 

* The first clause checks to see if the template has resources defined under `Resources` , and the template has one resource with `S3Bucket` as the logical resource ID. 
* The second clause checks to see if one or more tags are defined in `S3Bucket`. It has two tags defined under `Tags`.

`empty` can’t be used to check if string value queries have an empty string (`""`) defined.

`exists` - Checks if each occurrence of the query has a value and can be used in place of `!= null`.

```
# Checks if BucketEncryption is defined
Resources.S3Bucket.Properties.BucketEncryption exists
```

The above clause will `PASS` for the example template as `BucketEncryption` is defined for `S3Bucket`.

> **IMPORTANT**: `empty` and `not exists` checks evaluate to true for missing property keys when traversing the input data. E.g. if we check `Resources.S3Bucket.Properties.Tags empty` if `Properties` was not present in the template for S3Bucket, then `empty` evaluates to true. 

#### `is_string`, `is_list`, and `is_struct` operators

`is_string` - Checks if each occurrence of the query is of `string` type.

```
# Checks if BucketName is defined as a string
Resources.S3Bucket.Properties.BucketName is_string
```

`is_list` - Checks if each occurrence of the query is of `list` type.

```
# Checks if Tags is defined as a list
Resources.S3Bucket.Properties.Tags is_list
```

`is_struct` - Checks if each occurrence of the query is a structured data.

```
# Checks if BucketEncryption is defined as a structured data
Resources.S3Bucket.Properties.BucketEncryption is_struct
```

All the above example clauses will `PASS` for the example template. You can use the  `not(!)` operator with the above operators to check the inverse state.

### Binary Operators

Below are binary operators supported in Guard. The left-hand side (LHS) to the operator as mentioned above must always be a query and the right-hand side (RHS) can be a query or a value literal:

```
  ==    Equal
  !=    Not Equal
  >     Greater Than
  >=    Greater Than Or Equal To
  <     Less Than
  <=    Less Than Or Equal To
  IN    In a list of form [x, y, z]
```

 A value literal can be from any of the following supported categories,

* all primitives `string`, `integer(64)`, `float(64)`, `bool`, `char`, `regex`
* a specialized range type for expressing `integer`, `float`, `char` ranges, expressed as,
    *  `r[<lower_limit>, <upper_limit>]`, which translates to any value `k` that satisfies the following expression: `lower_limit` <= k <= `upper_limit`
    *  `r[<lower_limit>, <upper_limit>)`, which translates to any value `k` that satisfies the following expression: `lower_limit` <= k < `upper_limit`
    *  `r(<lower_limit>, <upper_limit>]`, which translates to any value `k` that satisfies the following expression: `lower_limit` < k <= `upper_limit`
    *  `r(<lower_limit>, <upper_limit>)`, which translates to any value `k` that satisfies the following expression: `lower_limit` < k < `upper_limit`
* associative arrays (a.k.a map) for nested key value structured data like:
```
{ "my-map": { "nested-maps": [ { "key": 10, "value": 20 } ] } }
```
* arrays of primitive/associative array types

Below are a couple of examples of clauses using binary operators:

* Based on the Template-1 example template:

```
# Checks if BucketName does not contain the string "encrypt" irrespective of casing
Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
```

* Consider the following CloudFormation template:

```yaml
# Template-2
Resources:
  NewVolume:
    Type: AWS::EC2::Volume
    Properties: 
      Size: 100
      VolumeType: io1
      Iops: 100
      AvailabilityZone:
        Fn::Select:
          - 0
          - Fn::GetAZs: us-east-1
      Tags:
        - Key: environment
          Value: test
    DeletionPolicy: Snapshot
```

Below are a few Guard clauses based on the above template:

```
# Checks Size of the EC2 volume is within a specific range, 50<= Size <= 200
Resources.NewVolume.Properties.Size IN r[50,200]
```

```
# Checks VolumeType is one of io1, io2 or gp3
Resources.NewVolume.Properties.VolumeType IN [ 'io1','io2','gp3' ]
```

> While these examples illustrate using `S3Bucket`, `NewVolume` in the query, often these are user defined and can be arbitrarily named in an IaC template. To write a rule that is generic and applies to all `AWS::S3::Bucket` resources defined in the template the most common form of query used is `Resources.*[ Type == ‘AWS::S3::Bucket’ ]` to select them. See [Guard: Query and Filtering](QUERY_AND_FILTERING.md) for details on usage and explore the examples directory.

## Custom Message

You can add a custom message to a clause. A custom message is added at the end of a clause as follows:

```
  <query> <operator> [query|value literal] [custom message]
```

`custom message` is expressed as `<<message>>` where message is any string which ideally provides information regarding the clause preceding it. This message is displayed in the verbose outputs of the validate (provide links) and test (provide links) commands and can be used to supply information helpful for understanding/debugging rules file evaluation on hierarchical data. The Template-2 example template clauses with custom message will look as follows:

```
Resources.NewVolume.Properties.Size IN r[50,200] 
<<
    EC2Volume size must be between 50 and 200, 
    not including 50 and 200
>>
Resources.NewVolume.Properties.VolumeType IN [ 'io1','io2','gp3' ] <<Allowed Volume Types are io1, io2, and gp3>>
```

### Combining Clauses

Now that we have a complete picture of what constitutes a clause, let us learn to combine clauses. In Guard, each clause written on a new line is combined implicitly with the next clause using conjunction (boolean `and` logic):

```
# clause_A ^ clause_B ^ clause_C
clause_A
clause_B
clause_C
```

You can also combine a clause with the next clause using disjunction by specifying `or|OR` at the end of the first clause.

```
  <query> <operator> [query|value literal] [custom message] [or|OR]
```

Disjunctions are evaluated first followed by conjunctions, and hence Guard rules can be defined as a conjunction of disjunction of clauses that evaluate to a `true` (`PASS`) / `false` (`FAIL`). This can be best explained with a few examples:

```
# (clause_E v clause_F) ^ clause_G
clause_E OR clause_F
clause_G

# (clause_H v clause_I) ^ (clause_J v clause_K)
clause_H OR
clause_I
clause_J OR
clause_K

# (clause_L v clause_M v clause_N) ^ clause_O
clause_L OR
clause_M OR
clause_N 
clause_O
```

This is similar to the [Conjunctive Normal Form (CNF)](https://en.wikipedia.org/wiki/Conjunctive_normal_form).

All clauses written based on the Template-1 example template can be combined as follows:

```
Resources.S3Bucket.Properties.BucketName is_string
Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
Resources.S3Bucket.Properties.BucketEncryption exists
Resources.S3Bucket.Properties.BucketEncryption is_struct
Resources.S3Bucket.Properties.Tags is_list
Resources.S3Bucket.Properties.Tags !empty
```

All clauses above are combined using conjunction. As you can see, there is repetition of part of the query expression in every clause. You can improve composability and remove verbosity and repetition from a set of related clauses with the same initial query path using a query block. 

## Blocks

### Query blocks

The above set of clauses can be written in block format as follows:

```
Resources.S3Bucket.Properties {
    BucketName is_string
    BucketName != /(?i)encrypt/
    BucketEncryption exists
    BucketEncryption is_struct
    Tags is_list
    Tags !empty
}
```

The above composition is referred to as query block as the query preceding the block sets the context for clauses inside the block. This improves composability and removes verbosity and repetition while writing multiple related clauses with the same initial query path. 

> **NOTE**: Query blocks are executed in a different way compared to their elaborate version. This will be explained in [Guard: Complex Composition](COMPLEX_COMPOSITION.md) document in detail.

### When blocks - When condition for conditional evaluation

Blocks can be evaluated conditionally using `when` blocks; `when` blocks take the following form:

```
  when <condition> {
      Guard_rule_1
      Guard_rule_2
      ...
  }
```

* The `when` keyword designates the start of the when block.

* `condition` can be any Guard rule. The block is evaluated only if the evaluation of the condition results in `true` (`PASS`).

Below is an example using the Template-1 example template:

```
when Resources.S3Bucket.Properties.BucketName is_string {
    Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
}
```

The clause within the when block will only execute if `BucketName` is a string. If the value for `BucketName` was being referenced from a Parameter as shown below, the clause within the when block will not be executed.

```
Parameters:
  S3BucketName:
    Type: String

Resources:
  S3Bucket:
    Type: "AWS::S3::Bucket"
    Properties:
      BucketName: 
        Ref: S3BucketName
    ...
```

### Named rule blocks

Named rule blocks allow for re-usability, improved composition and remove verbosity and repetition. They take the following form:

```
  rule <rule name> [when <condition>] {
      Guard_rule_1
      Guard_rule_2
      ...
  }
```

* The `rule` keyword designates the start of a named rule block.

* `rule name` can be any string that is human-readable and ideally should uniquely identify a named rule block. It can be thought of as a label to the set of Guard rules it encapsulates where Guard rules is an umbrella term for clauses, query blocks, when blocks and named rule blocks. The `rule name` can be used to refer to the evaluation result of the set of Guard rules it encapsulates, this is what makes named rule blocks re-usable. It also helps provide context in the validate (provide links) and test (provide links) command output as to what exactly failed. The `rule name` is displayed along with it block’s evaluation status - `PASS`, `FAIL`, or `SKIP`, in the evaluation output of the rules file:

```
# Sample output of an evaluation where check1, check2, and check3 are rule names.
_Summary__ __Report_ Overall File Status = **FAIL**
**PASS/****SKIP** **rules**
check1 **SKIP**
check2 **PASS**
**FAILED rules**
check3 **FAIL**
```

* Named rule blocks can also be evaluated conditionally by specifying the `when` keyword followed with a `condition` after the `rule name`.

Reiterating the `when` block example below:

```
rule checkBucketNameStringValue when Resources.S3Bucket.Properties.BucketName is_string {
    Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
}

# The above can also be written as follows
rule checkBucketNameIsString {
    Resources.S3Bucket.Properties.BucketName is_string
}
rule checkBucketNameStringValue when checkBucketNameIsString {
    Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
}
```

Named rule blocks can be re-used and grouped together with other Guard rules. Below are a few examples:

```
rule rule_name_A {
    Guard_rule_1 OR
    Guard_rule_2
    ...
}

rule rule_name_B {
    Guard_rule_3
    Guard_rule_4
    ...
}

rule rule_name_C {
    rule_name_A OR rule_name_B
}

rule rule_name_D {
    rule_name_A
    rule_name_B
}

rule rule_name_E when rule_name_D {
    Guard_rule_5
    Guard_rule_6
    ...
}
```

The above styles of compositions will be discussed in-depth in the [Guard: Complex Composition](COMPLEX_COMPOSITION.md) document.
