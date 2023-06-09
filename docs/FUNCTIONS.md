# Guard built-in functions and stateful rules

As of version 3.0.0 guard now supplies some builtin functions, allowing for stateful rules

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

The json_parse function adds support for parsing inline json strings from a given template. After parsing the string into an object,
you can now evaluate certain properties of this struct just like with a normal json/yaml object

This function accepts a single argument:

- this argument can either be a query that resolves to a string or a string literal.

The return value for this function is a query where each string that was resolved from the input is parsed into its json value

The following example shows how you could parse 2 fields on the above template and then write clauses on the results

```
let template = Resources.*[ Type == 'AWS::New::Service']
rule TEST_JSON_PARSE when %template !empty {
    let policy = %template.Properties.Policy

    let res = json_parse(%policy)

    %res !empty
    %res == %expected

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

The regex_replace function adds support for replacing one regular expression with another

This function accepts 3 arguments:

- The first argument is a query, each string that is resolved from this query will be operated on
- The second argument is either a query that resolves to a string or a string literal, this is the expression we are looking for to extract
  - Note: if this string does not resolve to a valid regular expression an error will occur
- The third argument is either a query that resolves to a string or a string literal, this is the expression we are going to use replace the extracted part of the string

The return value for this function is a query where each string that was resolved from the input that contains the the regex from our 2nd argument is replaced with the regex in the 3rd argument

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
}
```

### join

The join function adds support to collect a query, and then join their values using the provided delimiter.

This function accepts 2 arguments:

- The first argument is a query, all string values resolved from this query will then be joined using the delimter argument
- The second argument is either a query that resolves to a string/character, or a literal value that is either a string or character

The return value for this function is query where each string that was resolved from the input is joined with the provided delimiter

The following example queries the template for a Collection field on a given resource, it then provides a join on ONLY the string values that this query resolves to with a `,` delimiter

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule TEST_COLLECTION when %template !empty {
    let collection = %template.Collection.*

    let res = join(%collection, ",")
    %res == "a,b,c"
}
```

### to_lower and to_upper

Both functions accept a single argument:

- This argument is a query that resolves to a string(s) - all strings resolved will have the operation applied on them

Both these functions are very similar, one manipulates all resolved strings from a query to lower case, and the other to upper case

```
let type = Resources.newServer.Type

rule STRING_MANIPULATION when %type !empty {
    let lower = to_lower(%type)
    %lower == "aws::new::service"
    %lower == /aws::new::service/

    let upper = to_upper(%type)
    %upper == "AWS::NEW::SERVICE"
    %upper == /AWS::NEW::SERVICE/
}
```

### substring

The substring function adds support to collect a part of all strings resolved from a query

This function accepts 3 arguments:

- The first argument is a query, each string that is resolved from this query will be operated on
- The second argument is either a query that resolves to an int or a literal int, this is the starting index for the substring (inclusive)
- The third argument is either a query that resolves to an int or a literal int, this is the ending index for the substring (exclusive)

The return value for this function takes the strings resolved from the first argument, and returns a result of substrings for each one of them:
Note: Any string that would result in an index out of bounds from the 2nd or 3rd argument is skipped

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule TEST_SUBSTRING when %template !empty {
    %template.Properties.Arn exists
    let arn = %template.Properties.Arn

    let res = substring(%arn, 0, 3)

    %res == "arn"
}
```

### url_decode

This function accepts a single argument:

- this argument can either be a query that resolves to a string or a string literal.

The return value for this function is a query that contains each url decoded version of every string value from the input

The following rule shows how you could url_decode the string `This%20string%20will%20be%20URL%20encoded`

```
let template = Resources.*[ Type == 'AWS::New::Service']

rule SOME_RULE when %template !empty {
    %template.Properties.Encoded exists
    let encoded = %template.Properties.Encoded

    let res = url_decode(%encoded)
    %res == "This string will be URL encoded"
}
```

## Collection functions

### count

The count function adds support to count the number of items that a query resolves to

This function accepts a single argument:

- This argument is a query that can resolve to any type - the number of resolved values from this query is returned as the result

The following rules show different ways we can use the count function.

- One queries a struct, and counts the number of properties.
- The second queries a list object, and counts the elements in the list
- The third queries for all resources that are s3 buckets and have a PublicAcessBlockConfiguration property

```
let template = Resources.*[ Type == 'AWS::New::Service' ]
rule SOME_RULE when %template !empty {
    let props = %template.Properties.*
    let res = count(%props)
    %res == 3

    let collection = %template.Collection.*
    let res2 = count(%collection)
    %res2 == 3

    let buckets = Resources.*[ Type == 'AWS::S3::Bucket' ]
    let b = %buckets[ Properties.PublicAccessBlockConfiguration exists ]
    let res3 = count(%b)
    %res3 == 2

}
```
