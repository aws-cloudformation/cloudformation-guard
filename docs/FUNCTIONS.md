# Guard built-in functions and stateful rules

As of version 3.0.0 guard now supplies some builtin functions, allowing for stateful rules.

Built-in functions are used in two places: assigned to a variable with `let`, and as the right-hand side of a map key filter, `Map[ keys == to_lower(Wanted) ]`. Other inline positions, such as the left-hand side of an operator, are not supported yet; please [read through more about this limitation here](./KNOWN_ISSUES.md#function-limitation).

A query written as a function's argument inside a map key filter is relative to the map being filtered, as the plain right-hand side `Map[ keys == Wanted ]` is: `Wanted` names the map's own `Wanted` entry. An argument whose first key the map does not hold is then read from the scope the filter was reached in: the resource, for a filter on `Resources.*.Properties.Mappings` or inside a block clause, so `Mappings[ keys == to_upper(Properties.Env) ]` reads the `Env` beside the map. That fallback belongs to a key filter whose query is rooted at a key or at `this`. A key filter reached through a bound name, `%p.M[ keys == to_lower(Wanted) ]` over `let p = Resources.Cfg.Properties`, reads its argument from the bound map alone: an argument that map lacks fails the filter closed with the in-map miss (the clause names the map's path and the unresolved argument), whatever the resource beside the filter or the document root holds, and the verdict is the same for every resource a type block evaluates it for. A key the map holds is always the map's answer, even when it resolves to an empty list or to members that lack the field asked for. For a filter written at the file's root the enclosing scope is the document root; reading an argument from there keeps the older behavior, which read every such argument from the document root, and prints a deprecation notice on stderr naming the call. The argument is read there as a value beside the map, never as the document's own population: a first key that holds null (a bare `Wanted:`, or a bare `Resources:` under `to_lower(Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.BucketName)`) is the absent key's unresolved read, so the filter fails closed naming the path, as it does when the map holds that null, where the older behavior read a null population as the empty selection and reported the rule not applicable at exit 0. An empty population (`Resources: {}`) under such an enumeration stays the empty set on either side, and the plain clause `Resources.*[ ... ].Properties.BucketName empty` over either document keeps its population reading. To compare the keys against a value from elsewhere in the document, bind it to a variable first and pass `%name` as the argument.

The move has a second side. When the map holds the key and the enclosing scope holds the same name with a different value, the map's value is the argument where earlier versions read the enclosing scope's, and a rule written for that reading may change verdict. The enclosing scope is the document root for a filter written at the file's root, and the resource beside the map for one reached through `Resources.*`, inside a block clause, or through a variable bound to the resources (`%resource.Map[ keys == to_lower(Wanted) ]` over `let resource = Resources.*`). Where the two readings differ, a warning on stderr names the argument, the map's position, the enclosing scope's value and its position, the data file and the call:

```text
Warning: the function argument `Wanted` in a map key filter is read from the map being filtered, at /Resources/Cfg/Map[L:5,C:7] in data file template.yaml, where it differs from the value in the enclosing scope (the document root), at /Wanted[L:1,C:9]. Earlier versions read it from the enclosing scope, so a rule written for that reading may change verdict here. To read the enclosing scope's value, bind it to a variable and pass `%name`. The call is at Location[file:rules.guard, line:4, column:44].
```

A filter spelled on a variable bound to the map itself (`%map[ keys == to_lower(Wanted) ]` over `let map = Resources.Cfg.Map`) has no second side: a query rooted at a variable runs over the bound value, so its argument read the map's `Wanted` in earlier versions too, nothing moved, and nothing is printed.

The warning is one line per argument of a call and per input file, across every map and `test` case a run evaluates: a filter reached through `Resources.*` whose every resource differs prints the first map it moved for and counts the rest ("N more maps under this call read a differing value for this argument in this data file; only the first is shown"), a call whose two arguments both moved (`regex_replace(Wanted, Pattern, 'a')` with the map's `Wanted` and `Pattern` both differing from the enclosing scope's) prints two lines, one per argument, each counting the maps that argument moved on, a `validate` run over several data files prints one line per data file whose reading moved, each naming its file and counting that file's maps, a spec with several cases reaching one call prints one line, and a `when` condition the run never evaluated (the other side of an `or` decided it) prints nothing even though the evaluator reads it once more to measure the `when`. Under `cfn-guard test`, which reads a case's inline input and no data file, the line names the case and its spec file in place of the data file ("in case `two maps` of `tests.yaml`", or "in case 2 of `tests.yaml`" for a case with no name, numbered by its position in its own file), the count says "in this case", a spec file with several cases reaching one call prints one line, the first case's, whose count covers every case of the file that recorded the call ("N more maps under this call read a differing value for this argument across K cases in this file"), so a later case that failed on the moved reading is counted even though the first case is the one named, and a run over several spec files prints one line per spec file for the call, each naming its file. Only the argument's leading keys and indices are compared (`Wanted` of `Wanted[ Use == true ].Name` or of `Wanted[ w ]`), before the function runs, in order and as they are: a list is one value and a scalar is not a one-element list, because `join` over `[a, b]` and `[b, a]` selects different keys. So the warning says "may": `to_lower` agrees on values that differ only in case or in order, and a filter inside the argument can select the same members from two lists that differ. Nothing is printed when the two values are the same or when the enclosing scope has no such name.

`this.` inside the argument is the map-relative reading spelled out, and it is a behavior change of its own: `Map[ keys == to_lower(this.Wanted) ]` reads the map's `Wanted` and nothing else, where earlier versions read `this` as the enclosing scope. `this` means this map, so when the map has no `Wanted` the argument is unresolved and the filter fails closed on it as on any right-hand side it cannot read (the rule reports a failure naming where the read stopped, not "not applicable"), with no fallback to the resource beside the map or to the document root, and no deprecation notice. The spelling is compared like every other argument: whenever the map's reading differs from what the enclosing scope would have given, including a map that resolves nothing where the scope has a value, the same warning is printed, naming both readings.

An argument that names a property holding a list, or a list literal, is read as that list's elements, one level deep, the same way the comparison operators read one. `count(%template.Collection)` and `count(%template.Collection.*)` both answer 3 against the template below, `join(%allowed, ",")` over `let allowed = ["a", "b", "c"]` is `"a,b,c"`, and `parse_int(%ports)` over `Ports: ["80"]` is `80`. A list inside a list is one element. The last step of the argument's query decides: a query whose last step is a key (`Resources.*.Properties.L`, `%template.Collection`) is expanded, so its lists' elements are what the function sees even when an earlier step enumerated resources; a query whose last step enumerates (`.*`, `[*]`, a filter) is left as it is, each result being one value, so `count(%template.Properties.*)` counts properties even when one of them is a list, and `count(%nested[*])` over a list of lists counts the inner lists. Over several resources' lists, a function sees the elements of all of them; to count how many resources carry a property, filter on it, as the third `count` example below does.

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
  SecurityGroup:
    Type: AWS::EC2::SecurityGroup
    Properties:
      SecurityGroupIngress:
        String: "true"
        Char: "1"
        Int: 1
        Float: 1.5
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

1. `base_string`: A query, each string that is resolved from this query will be operated on. Example, `%s3_resource.Properties.BucketName`
2. `regex_to_extract`: A regular expression that we are looking for to extract from the `base_string`

- Note: if this string does not resolve to a valid regular expression, or the expression cannot be evaluated against a value within the regex engine's backtracking budget, the report names the pattern and where it came from. A pattern that came from the template fails the clause that uses the result and the run goes on; a pattern written in the rules file that does not compile is the rule's own mistake and stops the run (exit code 5)

3. `regex_replacement` A regular expression that will replace the part we extracted, also supports capture groups

- Note: `regex_to_extract` and `regex_replacement` must each resolve to exactly one value. An argument that resolves to more is refused naming the argument and the count: when the values came from the template the clause fails; when they were written in the rules file (a literal, or a variable bound to one) the run stops (exit code 5)

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

1. `collection`: A query that resolves to strings. Every value it resolves to is joined; a value that is not a string is an error, so a rule that joins a mixed collection fails rather than silently dropping members
2. `delimiter`: A query or a literal value that resolves to a string or character to be used as delimiter

- Note: `delimiter` must resolve to exactly one value. An argument that resolves to more is refused naming the argument and the count: when the values came from the template the clause fails; when they were written in the rules file (a literal, or a variable bound to one) the run stops (exit code 5)

#### Return value

The values resolved from `collection`, joined with the provided delimiter. The join is an error if any resolved value is not a string.

A collection that is present and holds no members joins to the empty string `""`, the same way `count` answers `0` for it. A query that names a key the data does not have is an error.

#### Example

The following example queries the template for a Collection field on a given resource, it then joins the values that this query resolves to with a `,` delimiter. Every value in `Collection` has to be a string.

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
2. `start_index`: A query that resolves to an int or a literal int, this is the starting index for the substring (inclusive)
3. `end_index`: A query that resolves to an int or a literal int, this is the ending index for the substring (exclusive)

- Note: `start_index` and `end_index` must each resolve to exactly one value. An argument that resolves to more is refused naming the argument and the count: when the values came from the template the clause fails; when they were written in the rules file (a literal, or a variable bound to one) the run stops (exit code 5)

#### Return value

A result of substrings for each `base_string` passed as input

- Note: A string for which the 2nd or 3rd argument is out of bounds gets no substring: a start past the end (`start > end`), or an end past the string's length. Its entry in the result is unresolved, so a clause that compares the result fails for that string, and the report names the string and which of the two it was. A range whose start and end are equal is in bounds whenever the end is not past the length of the string, and selects the empty string: `substring("abc", 1, 1)` is `""`, and so is `substring("", 0, 0)`.

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

## Collection Functions

### count

This function can be used to count the number of items that a query resolves to

#### Argument(s)

1. `collection`: A query that can resolves to any type

#### Return value

The number of resolved values from `collection` is returned as the result. A value that is a list counts as its elements, so `count(%template.Collection)` is 3, the same as `count(%template.Collection.*)`.

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

## Converter Functions

When the argument passed to a function resolves to several values, the result has one entry per value. An element of a type the function does not take is not dropped: its entry is unresolved, a clause that compares the result fails for that element, and the report names the element, its type and the function. The same holds for the string functions above. So `parse_int` over `["1", true, 2]` answers `1` and `2` and an unresolved entry for `true`, and `let res = parse_int(...)  %res exists` fails on the `true`, with the report saying it is a bool, which the function does not take. This is different from a value of an accepted type the function refuses: `parse_int` over `"x"` is an error ("failed to convert a string: x into an integer"), and the clause that uses the result fails as a whole.

An element the query could not find at all (a missing key) keeps the query's own unresolved result, so the report reads as it does for the bare query.

An unresolved entry stays unresolved when one function's result is handed to another. `join` refuses it and the clause fails; `count` does not count it, and answers nothing when nothing in its argument resolved. So `let lowered = to_lower(%protocols)` over `["TCP", -1]` followed by `join(%lowered, ",")` fails on the `-1` rather than joining `"tcp"` alone.

One unresolved entry is refused before any function runs: the selection a map-key filter could not decide (a right-hand side the document lacks, or a comparison the engine could not finish, over one map; see [CLAUSES.md](CLAUSES.md)). That selection is unknown rather than absent, so no answer built over it can be trusted: `count(Resources.*.Cfg[ keys == Names[*].Name ])` over one map whose `Names` has no `Name` beside one decided map does not answer 1, and `to_lower` over the same selection does not hand on the decided map's strings. Every function fails closed on it with the filter's own reason, as an assertion and as a `when` condition alike, the way the filter fails when its selection is read directly. Inside another map-key filter's right-hand side (`Outer[ keys IN to_lower(Inner[ keys == Names[*].Name ]) ]`) the refusal is that one map's answer: the map whose `Inner` could not be decided fails closed, and the other maps the query selected are decided and reported, as they are when the filter's own right-hand side cannot be decided. An entry the document lacks (a missing key, a function with no answer) keeps the reading above.

### parse_float

This function converts strings, ints, and chars to floating numbers

NOTE: Strings that cannot be represented as a number will cause this function to error

#### Argument(s)

1. `args`: A query that resolves to either a literal or variable

#### Example

```
let security_group = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule check when %security_group !EMPTY {
    let converted = parse_float(%security_group.Properties.Int)
    1.0 == %converted
}
```

### parse_int

This function converts strings, floats, and chars to integers

NOTE: floating point numbers are truncated to their integer representation, chars/strings that cannot be represented as an int will cause this function to error

#### Argument(s)

1. `args`: A query that resolves to either a literal or variable

#### Example

```
let security_group = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule check when %security_group !EMPTY {
    let converted = parse_int(%security_group.Properties.Float)
    1 == %converted
}
```

### parse_boolean

This function converts strings to their boolean equivalent

NOTE: this function is not case sensitive meaning `tRuE`, `true`, `TRUE`, `True`, etc will all be successfully converted

#### Argument(s)

1. `args`: A query that resolves to either a literal or variable

#### Example

```
let security_group = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule check when %security_group !EMPTY {
    let converted = parse_boolean(%security_group.Properties.String)
    %converted == true
}
```

### parse_string

This function converts floats, booleans, chars, and ints to their String equivalents

NOTE: a float keeps its decimal point, so `2.0` converts to `"2.0"` and `1.5` to `"1.5"`. An int converts without one, so the int `2` converts to `"2"`.

#### Argument(s)

1. `args`: A query that resolves to either a literal or variable

#### Example

```
let security_group = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule check when %security_group !EMPTY {
    let converted = parse_string(%security_group.Properties.Float)
    %converted == "1.5"
}
```

### parse_char

This function converts strings, and ints to their char equivalents

NOTE: this function will cause an error if the int is not 0 <= n <= 9, it will also error out if a string is longer than one character. Length is counted in characters, not bytes, so a single character that is not ASCII converts like any other.

#### Argument(s)

1. `args`: A query that resolves to either a literal or variable

#### Example

```
let security_group = Resources.*[ Type == "AWS::EC2::SecurityGroup" ]

rule check when %security_group !EMPTY {
    let converted = parse_char(%security_group.Properties.Char)
    %converted == '1'
}
```

## Notices in this release

Changes in how a function's result is read move verdicts that existing rules may depend on. Each such move is announced for this release only, as a `DEPRECATION:` line on stderr, once per clause; the next release applies the new reading without the line. One change is not announced: a scalar argument (`join`'s delimiter, `substring`'s bounds, `regex_replace`'s pattern and replacement) that resolves to several values is now refused naming the count, where it was read for one of those values. There is no reading to retire, because the answer over one of several values was never the question the rule asked; the refusal is the notice.

- A `when` whose conditions read a function's result holding entries the function had no answer for (a resource that lacks the property the function was given) is evaluated a second time, as a whole, with those entries dropped, which is how every release before this one read such a result. When that moves the `when` between opening its block and not, the run says so, once per `when` and direction of the move (a block that ran and is skipped now, a block that was skipped and runs now, each at most once) and, across the data files of one `validate` run, once per `when` and direction for the run, with the single-line output's `NOTE:` trailer naming the later files that drew it (see [how `validate` writes notices](CLAUSES.md#notices)): the notice names, as the rule spells it, the first condition whose own answer moved and both of its answers, the `when`'s two answers and what the move means for the block, every function result the conditions read with how many entries it is read as now and was read as before (how many had no answer beside how many values did, or, for a name derived from the result, beside how many values the name holds, and the first such entry with its reason), and the spelling that decides the block by the resources that have the property (gate on the property itself, or filter the resources before the function). A `when` that is evaluated once per resource (a type block's own condition, `AWS::S3::Bucket when %p !empty { ... }`, or a `when` block inside a type block's or a block clause's body) also names the resource it was deciding when its answer moved: the first resource of the block whose answer moved that way, with a resource that moved the other way getting its own line and no other resource listed; a `when` at the rule level names none. The shape of the condition does not matter: `!empty`, `some ... !exists`, a comparison such as `%t == "aws::s3::bucket"`, the result anywhere in either side's query (at its root, as an interpolated key such as `Resources.%names`, inside a filter predicate, as a map-key filter's right-hand side, as a nested call's argument), a `let` alias of the result (`let q = %p`, `let q = %p[*]`), a `let` that reads into it (`let mode = %p.Mode`, `let k = %p[ n ]`, through any number of `let`s), and a parameter a parameterized rule was handed as a function call, as such a name or as such a query (`guarded(%p)`, `guarded(%p.Mode)`, `guarded(%mode)`) are all measured the same way. A `let` or an argument that reads into the result carries the function's entries beside entries of its own (a key the parsed value lacks, an index past a list's end, an enumeration over an empty list), which earlier releases kept; the measurement tells the two apart by identity, drops only the function's, and the notice says the name is "derived from a function's result" and counts the entries "its own query adds, kept in both readings". A `when` whose answer did not move gets no line: `%p !empty or %q !empty` where `%q` decides either way, `%p empty`, `not %p !empty`, a `!empty` over an empty string, and a condition over a derived name whose only unresolved entries are the query's own. A filter predicate and the body of a referenced rule are never measured on their own.
- A function over an argument that names a list value (a query whose last step is a key, a nested call such as `count(json_parse(%s))`, or an inline list literal) reads the list as its elements, where it read it as one value. When that changes what the function answers, the notice names the call as the rule spells it (a filter with its predicate, `count(Resources.*[ Type == 'AWS::S3::Bucket' ].Properties.Tags)`, in text that parses back as the query) and both answers: for `count` the old and the new number, with the spelling that counts resources rather than elements (filter on the property and count the filter's result), and for every other function how many values it answered on each side (`parse_int(Resources.*.Properties.Ports)` over `Ports: ["80"]` answers 1 value where it answered no values). When the expansion leaves `count` nothing beside a resource that lacks the property, it has no answer and the clause fails naming it, and the notice says "has no answer" rather than a number. The line is printed once per call site with the first answers seen, so a call inside a block over resources prints one line. A document with no list among the values, and the `[*]` spelling, change no answer and get no notice.
