# Guard built-in functions and stateful rules

As of version 3.0.0 guard now supplies some builtin functions, allowing for stateful rules. 

Built-in functions are supported only through assignment to a variable at the moment.

There are some limitations with the current implementation of functions. We **do not** support inline usage yet. Please [read through more about this limitation here](./KNOWN_ISSUES.md#function-limitation).

NOTE: all examples are operating off the following yaml template

```yaml
Resources:
  newServer:
    Type: AWS::New::Service
    Properties:
      Policy: |
        {
           "Principal": "*",
           "Actions": ["s3*", "ec2*"]
        }
      Arn: arn:aws:newservice:us-west-2:123456789012:Table/extracted
      Encoded: This%20string%20will%20be%20URL%20encoded
    Collection:
      - a
      - b
      - c
    BucketPolicy:
      PolicyText: '{"Version":"2012-10-17","Statement":[{"Sid":"DenyReducedReliabilityStorage","Effect":"Deny","Principal":"*","Action":"s3:*","Resource":"arn:aws:s3:::s3-test-123/*","Condition":{"StringEquals":{"s3:x-amz-storage-class-123":["ONEZONE_IA","REDUCED_REDUNDANCY"]}}}]}'

  s3:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
  bucket:
    Type: AWS::S3::Bucket
    Properties:
      PublicAccessBlockConfiguration:
        BlockPublicAcls: false
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true
```

## String Manipulation

The following functions all operate on queries that resolve to string values

### json_parse

The `json_parse` function adds support for parsing inline JSON strings from a given template. After parsing the string into an object,
you can now evaluate certain properties of this struct just like with a normal JSON/YAML object

#### Argument(s)

1. `json_string`: Either be a query that resolves to a string or a string literal. Example, `'{"a": "basic", "json": "object"}'`

#### Return value

Query of JSON value(s) corresponding to every string literal resolved from input query

#### Example

The following example shows how you could parse 2 fields on the above template and then write clauses on the results:

```
let template = Resources.*[ Type == 'AWS::New::Service']
let expected = {
        "Principal": "*",
        "Actions": ["s3*", "ec2*"]
    }
rule TEST_JSON_PARSE when %template !empty {
    let policy = %template.Properties.Policy

    let res = json_parse(%policy)

    %res !empty
    %res == %expected
    <<
        Violation: the IAM policy does not match with the recommended policy
    >>

    let policy_text = %template.BucketPolicy.PolicyText
    let res2 = json_parse(%policy_text)

    %res2.Statement[*]
    {
            Effect == "Deny"
            Resource == "arn:aws:s3:::s3-test-123/*"
    }
    
}
```

### regex_replace

The `regex_replace` function adds support for replacing one regular expression with another

#### Argument(s)

1. `base_string`:  A query, each string that is resolved from this query will be operated on. Example, `%s3_resource.Properties.BucketName`
2. `regex_to_extract`: A regular expression that we are looking for to extract from the `base_string`
  - Note: if this string does not resolve to a valid regular expression an error will occur
3. `regex_replacement` A regular expression that will replace the part we extracted, also supports capture groups

#### Return value

A query where each string from the input has gone through the replacements

#### Example

In this simple example, we will re-format an ARN by moving around some sections in it.

We will start with a normal ARN that has the following pattern: `arn:<Partition>:<Service>:<Region>:<AccountID>:<ResourceType>/<ResourceID>`
and we will try to convert it to: `<Partition>/<AccountID>/<Region>/<Service>-<ResourceType>/<ResourceID>`

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule TEST_REGEX_REPLACE when %template !empty {
    %template.Properties.Arn exists
    let arn = %template.Properties.Arn

    let arn_partition_regex = "^arn:(\w+):(\w+):([\w0-9-]+):(\d+):(.+)$"
    let capture_group_reordering = "${1}/${4}/${3}/${2}-${5}"
    let res = regex_replace(%arn, %arn_partition_regex, %capture_group_reordering)

    %res == "aws/123456789012/us-west-2/newservice-Table/extracted"
    << Violation: Resulting reformatted ARN does not match the expected format >>
}
```

### join

The `join` function adds support to collect a query, and then join their values using the provided delimiter.

#### Argument(s)

1. `collection`: A query, all string values resolved from this query are candidates of elements to be joined
2. `delimiter`: A query or a literal value that resolves to a string or character to be used as delimiter

#### Return value

Query where each string that was resolved from the input is joined with the provided delimiter

#### Example

The following example queries the template for a Collection field on a given resource, it then provides a join on ONLY the string values that this query resolves to with a `,` delimiter

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule TEST_COLLECTION when %template !empty {
    let collection = %template.Collection.*

    let res = join(%collection, ",")
    %res == "a,b,c"
    << Violation: The joined value does not match the expected result >>
}
```

### to_lower 

This function can be used to change the casing of the all characters in the string passed to all lowercase.

#### Argument(s)

1. `base_string`: A query that resolves to string(s) 

#### Return value

Returns the `base_string` in all lowercase

```
let type = Resources.newServer.Type

rule STRING_MANIPULATION when %type !empty {
    let lower = to_lower(%type)

    %lower == /aws::new::service/
    << Violation: expected a value to be all lowercase >>
}
```

### to_upper

This function can be used to change the casing of the all characters in the string passed to all uppercase.

#### Argument(s)

1. `base_string`: A query that resolves to string(s)

#### Return value

Returns capitalized version of the `base_string`

#### Example

```
let type = Resources.newServer.Type

rule STRING_MANIPULATION when %type !empty {
    let upper = to_upper(%type)

    %upper == "AWS::NEW::SERVICE"
    << Violation: expected a value to be all uppercase >>
}
```

### substring

The `substring` function allows to extract a part of string(s) resolved from a query

#### Argument(s)

1. `base_string`: A query that resolves to string(s)
2. `start_index`:  A query that resolves to an int or a literal int, this is the starting index for the substring (inclusive)
3. `end_index`: A query that resolves to an int or a literal int, this is the ending index for the substring (exclusive)

#### Return value

A result of substrings for each `base_string` passed as input

 - Note: Any string that would result in an index out of bounds from the 2nd or 3rd argument is skipped

#### Example

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule TEST_SUBSTRING when %template !empty {
    %template.Properties.Arn exists
    let arn = %template.Properties.Arn

    let res = substring(%arn, 0, 3)

    %res == "arn"
    << Violation: Substring extracted does not match with the expected outcome >>
}
```

### url_decode

This function can be used to transform URL encoded strings into their decoded versions

#### Argument(s)

1. `base_string`: A query that resolves to a string or a string literal

#### Return value

A query containing URL decoded version of every string value from `base_string`

#### Example

The following rule shows how you could `url_decode` the string `This%20string%20will%20be%20URL%20encoded`

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule SOME_RULE when %template !empty {
    %template.Properties.Encoded exists
    let encoded = %template.Properties.Encoded

    let res = url_decode(%encoded)
    %res == "This string will be URL encoded"
    << 
        Violation: The result of URL decoding does not 
        match with the expected outcome
    >>
}
```

## Collection functions

### count

This function can be used to count the number of items that a query resolves to

#### Argument(s)

1. `collection`: A query that can resolves to any type

#### Return value

The number of resolved values from `collection` is returned as the result

The following rules show different ways we can use the count function.

- One queries a struct, and counts the number of properties.
- The second queries a list object, and counts the elements in the list
- The third queries for all resources that are s3 buckets and have a PublicAccessBlockConfiguration property

#### Example

```
let template = Resources.*[ Type == 'AWS::New::Service' ]
rule SOME_RULE when %template !empty {
    let props = %template.Properties.*
    let res = count(%props)
    %res >= 3
    << Violation: There must be at least 3 properties set for this service >>

    let collection = %template.Collection.*
    let res2 = count(%collection)
    %res2 >= 3
    << Violation: Collection should contain at least 3 items >>

    let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]
    let b = %buckets[ Properties.PublicAccessBlockConfiguration exists ]
    let res3 = count(%b)
    %res3 >= 2
    << Violation: At least 2 buckets should have PublicAccessBlockConfiguration set  >>

}
```
