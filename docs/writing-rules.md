# Writing AWS CloudFormation Guard rules<a name="writing-rules"></a>

In AWS CloudFormation Guard, *rules* are policy\-as\-code rules\. You write rules in the Guard domain\-specific language \(DSL\) that you can validate your JSON\- or YAML\-formatted data against\. Rules are made up of *clauses*\.

You can save rules written using the Guard DSL into plaintext files that use any file extension\.

You can create multiple rule files and categorize them as a *rule set* so that you can validate your JSON\- or YAML\-formatted data against multiple rule files at the same time\.

**Topics**
+ [Clauses](#clauses)
+ [Using queries in clauses](#clauses-queries)
+ [Using operators in clauses](#clauses-operators)
+ [Using custom messages in clauses](#clauses-custom-messages)
+ [Combining clauses](#combining-clauses)
+ [Using blocks with Guard rules](#blocks)
+ [Defining queries and filtering](query-and-filtering.md)
+ [Assigning and referencing variables in AWS CloudFormation Guard rules](variables.md)
+ [Composing named\-rule blocks in AWS CloudFormation Guard](named-rule-block-composition.md)
+ [Writing clauses to perform context\-aware evaluations](context-aware-evaluations.md)

## Clauses<a name="clauses"></a>

Clauses are Boolean expressions that evaluate to either true \(`PASS`\) or false \(`FAIL`\)\. Clauses use either binary operators to compare two values or unary operators that operate on a single value\.

**Examples of unary clauses**

The following unary clause evaluates whether the collection `TcpBlockedPorts` is empty\.

```
InputParameters.TcpBlockedPorts not empty
```

The following unary clause evaluates whether the `ExecutionRoleArn` property is a string\.

```
Properties.ExecutionRoleArn is_string
```

**Examples of binary clauses**

The following binary clause evaluates whether the `BucketName` property contains the string `encrypted`, regardless of casing\.

```
Properties.BucketName != /(?i)encrypted/
```

The following binary clause evaluates whether the `ReadCapacityUnits` property is less than or equal to 5,000\.

```
Properties.ProvisionedThroughput.ReadCapacityUnits <= 5000
```

### Syntax for writing Guard rule clauses<a name="clauses-syntax"></a>

```
<query> <operator> [query|value literal] [custom message]
```

### Properties of Guard rule clauses<a name="clauses-properties"></a>

`query`  <a name="clauses-properties-query"></a>
A dot `(.)` separated expression written to traverse hierarchical data\. Query expressions can include filter expressions to target a subset of values\. Queries can be assigned to variables so that you can write them once and reference them elsewhere in a rule set and so that you can access query results\.  
For more information about writing queries and filtering, see [Defining queries and filtering](query-and-filtering.md)\.  
 *Required*: Yes

`operator`  <a name="clauses-properties-operator"></a>
A unary or binary operator that helps check the state of the query\. The left\-hand side \(LHS\) of a binary operator must be a query and the right\-hand side \(RHS\) must be either a query or a value literal\.  
 *Supported binary operators*: `==` \(Equal\) \| `!=` \(Not equal\) \| `>` \(Greater than\) \| `>=` \(Greater than or equal to\) \| `<` \(Less than\) \| `<=` \(Less than or equal to\) \| `IN` \(In a list of form \[x, y, z\]  
 *Supported unary operators*: `exists` \| `empty` \| `is_string` \| `is_list` \| `is_struct` \| `not(!)`  
 *Required*: Yes

`query|value literal`  <a name="clauses-properties-value-literal"></a>
A query or a supported value literal such as `string` or `integer(64)`\.   
*Supported value literals*:  
+ All primitive types: `string`, `integer(64)`, `float(64)`, `bool`, `char`, `regex`
+ All specialized range types for expressing `integer(64)`, `float(64)`, or `char` ranges expressed as:
  + `r[<lower_limit>, <upper_limit>]`, which translates to any value `k` that satisfies the following expression: `lower_limit <= k <= upper_limit`
  + `r[<lower_limit>, <upper_limit>`\), which translates to any value `k` that satisfies the following expression: `lower_limit <= k < upper_limit`
  + `r(<lower_limit>, <upper_limit>]`, which translates to any value `k` that satisfies the following expression: `lower_limit < k <= upper_limit`
  + `r(<lower_limit>, <upper_limit>),` which translates to any value `k` that satisfies the following expression: `lower_limit < k < upper_limit`
+ Associative arrays \(maps\) for nested key\-value structure data\. For example:

  \{ "my\-map": \{ "nested\-maps": \[ \{ "key": 10, "value": 20 \} \] \} \}
+ Arrays of primitive types or associative array types
 *Required*: Conditional; required when a binary operator is used\.

`custom message`  <a name="clauses-properties-custom-message"></a>
A string that provides information about the clause\. The message is displayed in the verbose outputs of the `validate` and `test` commands and can be useful for understanding or debugging rule evaluation on hierarchical data\.  
 *Required*: No

## Using queries in clauses<a name="clauses-queries"></a>

For information about writing queries, see [Defining queries and filtering](query-and-filtering.md) and [Assigning and referencing variables in Guard rules](variables.md)\.

## Using operators in clauses<a name="clauses-operators"></a>

The following are example CloudFormation templates, `Template-1` and `Template-2`\. To demonstrate the use of supported operators, the example queries and clauses in this section refer to these example templates\.

**Template\-1**

```
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

**Template\-2**

```
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

### Examples of clauses that use unary operators<a name="clauses-unary-operators"></a>
+ `empty` – Checks if a collection is empty\. You can also use it to check if a query has values in a hierarchical data because queries result in a collection\. You can't use it to check whether string value queries have an empty string \(`""`\) defined\. For more information, see [Defining queries and filtering](query-and-filtering.md)\.

  The following clause checks whether the template has one or more resources defined\. It evaluates to `PASS` because a resource with the logical ID `S3Bucket` is defined in `Template-1`\.

  ```
  Resources !empty
  ```

  The following clause checks whether one or more tags are defined for the `S3Bucket` resource\. It evaluates to `PASS` because `S3Bucket` has two tags defined for the `Tags` property in `Template-1`\.

  ```
  Resources.S3Bucket.Properties.Tags !empty
  ```
+ `exists` – Checks whether each occurrence of the query has a value and can be used in place of `!= null`\.

  The following clause checks whether the `BucketEncryption` property is defined for the `S3Bucket`\. It evaluates to `PASS` because `BucketEncryption` is defined for `S3Bucket` in `Template-1`\.

  ```
  Resources.S3Bucket.Properties.BucketEncryption exists
  ```

**Note**  
The `empty` and `not exists` checks evaluate to `true` for missing property keys when traversing the input data\. For example, if the `Properties` section isn't defined in the template for the `S3Bucket`, the clause `Resources.S3Bucket.Properties.Tag empty` evaluates to `true`\. The `exists` and `empty` checks don't display the JSON pointer path inside the document in the error messages\. Both of these clauses often have retrieval errors that don't maintain this traversal information\.
+ `is_string` – Checks whether each occurrence of the query is of `string` type\.

  The following clause checks whether a string value is specified for the `BucketName` property of the `S3Bucket` resource\. It evaluates to `PASS` because the string value `"MyServiceS3Bucket"` is specified for `BucketName` in `Template-1`\.

  ```
  Resources.S3Bucket.Properties.BucketName is_string
  ```
+ `is_list` – Checks whether each occurrence of the query is of `list` type\.

  The following clause checks whether a list is specified for the `Tags` property of the `S3Bucket` resource\. It evaluates to `PASS` because two key\-value pairs are specified for `Tags` in `Template-1`\.

  ```
  Resources.S3Bucket.Properties.Tags is_list
  ```
+ `is_struct` – Checks whether each occurrence of the query is structured data\.

  The following clause checks whether structured data is specified for the `BucketEncryption` property of the `S3Bucket` resource\. It evaluates to `PASS` because `BucketEncryption` is specified using the `ServerSideEncryptionConfiguration` property type *\(object\)* in `Template-1`\.

**Note**  
To check the inverse state, you can use the \(` not !`\) operator with the `is_string`, `is_list`, and `is_struct` operators \.

### Examples of clauses that use binary operators<a name="clauses-binary-operators"></a>

The following clause checks whether the value specified for the `BucketName` property of the `S3Bucket` resource in `Template-1` contains the string `encrypt`, regardless of casing\. This evaluates to `PASS` because the specified bucket name `"MyServiceS3Bucket"` does not contain the string `encrypt`\.

```
Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
```

The following clause checks whether the value specified for the `Size` property of the `NewVolume` resource in `Template-2` is within a specific range: 50 <= `Size` <= 200\. It evaluates to `PASS` because `100` is specified for `Size`\.

```
Resources.NewVolume.Properties.Size IN r[50,200]
```

The following clause checks whether the value specified for the `VolumeType` property of the `NewVolume` resource in `Template-2` is `io1`, `io2`, or `gp3`\. It evaluates to `PASS` because `io1` is specified for `NewVolume`\.

```
Resources.NewVolume.Properties.NewVolume.VolumeType IN [ 'io1','io2','gp3' ]
```

**Note**  
The example queries in this section demonstrate the use of operators using the resources with logical IDs `S3Bucket` and `NewVolume`\. Resource names are often user\-defined and can be arbitrarily named in an infrastructure as code \(IaC\) template\. To write a rule that is generic and applies to all `AWS::S3::Bucket` resources defined in the template, the most common form of query used is `Resources.*[ Type == ‘AWS::S3::Bucket’ ]`\. For more information, see [Defining queries and filtering](query-and-filtering.md) for details about usage and explore the [examples](https://github.com/aws-cloudformation/cloudformation-guard/tree/main/guard-examples) directory in the `cloudformation-guard` GitHub repository\.

## Using custom messages in clauses<a name="clauses-custom-messages"></a>

In the following example, clauses for `Template-2` include a custom message\.

```
Resources.NewVolume.Properties.Size IN r[50,200] 
<<
    EC2Volume size must be between 50 and 200, 
    not including 50 and 200
>>
Resources.NewVolume.Properties.VolumeType IN [ 'io1','io2','gp3' ] <<Allowed Volume Types are io1, io2, and gp3>>
```

## Combining clauses<a name="combining-clauses"></a>

In Guard, each clause written on a new line is combined implicitly with the next clause by using conjunction \(Boolean `and` logic\)\. See the following example\.

```
# clause_A ^ clause_B ^ clause_C
clause_A
clause_B
clause_C
```

You can also use disjunction to combine a clause with the next clause by specifying `or|OR` at the end of the first clause\.

```
<query> <operator> [query|value literal] [custom message] [or|OR]
```

In a Guard clause, disjunctions are evaluated first, followed by conjunctions\. Guard rules can be defined as a conjunction of disjunction of clauses \(an `and|AND` of `or|OR`s\) that evaluate to either `true` \(`PASS`\) or `false` \(`FAIL`\)\. This is similar to [Conjunctive normal form](https://en.wikipedia.org/wiki/Conjunctive_normal_form)\. 

The following examples demonstrate the order of evaluations of clauses\.

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

All clauses that are based on the example `Template-1` can be combined by using conjunction\. See the following example\.

```
Resources.S3Bucket.Properties.BucketName is_string
Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
Resources.S3Bucket.Properties.BucketEncryption exists
Resources.S3Bucket.Properties.BucketEncryption is_struct
Resources.S3Bucket.Properties.Tags is_list
Resources.S3Bucket.Properties.Tags !empty
```

## Using blocks with Guard rules<a name="blocks"></a>

Blocks are compositions that remove verbosity and repetition from a set of related clauses, conditions, or rules\. There are three types of blocks:
+ Query blocks
+ `when` blocks
+ Named\-rule blocks

### Query blocks<a name="query-blocks"></a>

Following are the clauses that are based on the example `Template-1`\. Conjunction was used to combine the clauses\.

```
Resources.S3Bucket.Properties.BucketName is_string
Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
Resources.S3Bucket.Properties.BucketEncryption exists
Resources.S3Bucket.Properties.BucketEncryption is_struct
Resources.S3Bucket.Properties.Tags is_list
Resources.S3Bucket.Properties.Tags !empty
```

Parts of the query expression in each clause are repeated\. You can improve composability and remove verbosity and repetition from a set of related clauses with the same initial query path by using a query block\. The same set of clauses can be written as shown in the following example\.

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

In a query block, the query preceding the block sets the context for the clauses inside the block\.

For more information about using blocks, see [Composing named\-rule blocks](named-rule-block-composition.md)\.

### `when` blocks<a name="when-blocks"></a>

You can evaluate blocks conditionally by using `when` blocks, which take the following form\.

```
  when <condition> {
       Guard_rule_1
       Guard_rule_2
       ...
   }
```

The `when` keyword designates the start of the `when` block\. `condition` is a Guard rule\. The block is only evaluated if the evaluation of the condition results in `true` \(`PASS`\)\.

The following is an example `when` block that is based on `Template-1`\.

```
when Resources.S3Bucket.Properties.BucketName is_string {
     Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
 }
```

The clause within the `when` block is only evaluated if the value specified for `BucketName` is a string\. If the value specified for `BucketName` is referenced in the `Parameters` section of the template as shown in the following example, the clause within the `when` block is not evaluated\.

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

### Named\-rule blocks<a name="named-rule-blocks"></a>

You can assign a name to a set of rules \(*rule set*\), and then reference these modular validation blocks, called *named\-rule blocks*, in other rules\. Named\-rule blocks take the following form\.

```
  rule <rule name> [when <condition>] {
    Guard_rule_1
    Guard_rule_2
    ...
    }
```

The `rule` keyword designates the start of the named\-rule block\.

`rule name` is a human\-readable string to uniquely identify a named\-rule block\. It's a label for the Guard rule set that it encapsulates\. In this use, the term *Guard rule* includes clauses, query blocks, `when` blocks, and named\-rule blocks\. The rule name can be used to refer to the evaluation result of the rule set that it encapsulates, which makes named\-rule blocks reusable\. The rule name also provides context about rule failures in the `validate` and `test` command outputs\. The rule name is displayed along with the block’s evaluation status \(`PASS`, `FAIL`, or `SKIP`\) in the evaluation output of the rules file\. See the following example\.

```
# Sample output of an evaluation where check1, check2, and check3 are rule names.
_Summary__ __Report_ Overall File Status = **FAIL**
**PASS/****SKIP** **rules**
check1 **SKIP**
check2 **PASS**
**FAILED rules**
check3 **FAIL**
```

You can also evaluate named\-rule blocks conditionally by specifying the `when` keyword followed by a condition after the rule name\.

Following is the example `when` block that was discussed previously in this topic\.

```
rule checkBucketNameStringValue when Resources.S3Bucket.Properties.BucketName is_string {
    Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
}
```

Using named\-rule blocks, the preceding can also be written as follows\.

```
rule checkBucketNameIsString {
    Resources.S3Bucket.Properties.BucketName is_string
}
rule checkBucketNameStringValue when checkBucketNameIsString {
    Resources.S3Bucket.Properties.BucketName != /(?i)encrypt/
}
```

You can reuse and group named\-rule blocks with other Guard rules\. Following are a few examples\.

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