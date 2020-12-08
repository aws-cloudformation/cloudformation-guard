# Clause Statements

Each clause statement is of the form 

<pre>
    [not / ! ] <em>query</em> <em>operator</em> [<em>query</em> / <em>value</em>] [<b>&lt;&lt;</b> message <b>&gt;&gt;</b>]
</pre>

### Value Types

We will start with value types as they are needed for subsequent term explanations. Values types are scalars,
structured data, and collections ```[]``` of them. 

#### Scalar Types

- **Strings** are quoted values that are enclosed with ```"``` or ```'```. Double quotes can enclose single quoted strings 
and vice versa. Example of string are <code>"us-east-2", 'This has "embedded string" inside it', "This has 'single quoted' 
inside it" </code>. 
- **Integers** positive or negative 64 bit numbers. Examples <code> 10, 20, -10 </code>
- **Floats** 64 bit precision numbers with decimals and exponents. Examples <code> 10.1, 10E+10, 0.89 </code>
- **Character** any UTF-8 encoded character
- **booleans** true/false 
- **Regex** are regular expression string that are enclosed in-between ```/```. If the string contains a ```/```, it needs 
to be escaped using <code>\\</code>. Examples <code>  /^.\*.dkr.ecr.\*.amazonaws[.\*]\*.com\\/.\*[:@]+(.\*){2,255}$/ </code>

#### Structured or Map Type

This value type provides associative data with _strings_ as keys and values that can be scalars, collection or another 
 map type separated with a ```:``` and enclosed between ```{}```. Keys can be barewords (a.k.a symbols) without quotes. 
Examples
<pre>
# example of map/structured object 
{
    'postgres':      ["postgresql", "upgrade"],
    'mariadb':       ["audit", "error", "general", "slowquery"],
    'mysql':         ["audit", "error", "general", "slowquery"],
    'oracle-ee':     ["trace", "audit", "alert", "listener"],
    'oracle-se':     ["trace", "audit", "alert", "listener"],
    'oracle-se1':    ["trace", "audit", "alert", "listener"],
    'oracle-se2':    ["trace", "audit", "alert", "listener"],
    'sqlserver-ee':  ["error", "agent"],
    'sqlserver-ex':  ["error"],
    'sqlserver-se':  ["error", "agent"],
    'sqlserver-web': ["error", "agent"],
    'aurora':        ["audit", "error", "general", "slowquery"],
    'aurora-mysql':  ["audit", "error", "general", "slowquery"],
    'aurora-postgresql': ["postgresql", "upgrade"]
}

# Example of map/structured type with keys without "" or '', a.k.a symbols.
{ prod-id: "prod-app-x123345", app-id: "app-X123434" }
</pre>

#### Collection Type

The value type represent ordered list of values contained inside ```[]``` separated by a common. The value type can be 
scalar, map type, or a collection type. Examples 
<pre>
# collection scalars like string, number etc.
["postgresql", "upgrade"]
[ 10, 20, 40 ]

# collection of map-types.
[ { prod-id: "prod-app-x123345", app-id: "app-X123434" }, 
  { prod-id: "prod-app-x23rer", app-id: "app-Y1234" } ]
  
# collection of collection type
[ [10, 20, 30], [60, 70, 80] ]
</pre>


### Query 

A query represents an access to extract views of data from a structured data (like JSON). The query allows for 
traversal of the hierarchy using a simple dotted notation with support for predicate clauses for filtering down selections. 
The query permits selecting all elements in a collection or selecting a particular indexed element.

Here are example queries  
<pre>
BucketName
configuration.containerDefinitions.*.image
block_device_mappings[*].device_name
resources.*[type == "AWS::RDS::DBCluster"].properties
%aurora_dbs.BackupRetentionPeriod
</pre>

For in depth treatise read detailed [query](query-RFC.md) document. For the remainder of this document we will use 
simpler queries to demonstrate the language and its usage.

### Operator

The next part of the clause is an Operator. Operator is either unary or binary. Unary operators like ```NOT, EXISTS, EMPTY``` 
and others operate on single arguments. Binary operators like ```==, <=, >, !=``` and more operate on 2 arguments. To 
improve readability of clauses the operators are embedded (specified using infix notation). E.g

```
resources.* NOT EMPTY      # uanry 
resources.*.Type == /RDS/  # binary has LHS, and RHS

# tags contains KEYS that have PROD substring in them 
resources.*.properties.tags[*] KEYS == /PROD/

# tags VALUES contains PROD, tags: [{"PROD-ID": "PROD-122434"}, ... ]  
resources.*.properties.tags[*].* == /PROD/ 

# select tags where KEYS match /aws:application/ and check if 
# the values start with app-x1234 
resources.*.properties.tags[ KEYS == /aws:application/ ].* == /^app-x1234/ 

```

Here is the list of the **Unary Operators**

- *NOT* used to negate the result of the clause 
- *EMPTY* used to check is a collection is empty 
- *EXISTS* used to check is a property was set or not

Here are the list of **Binary Operators**

**Equality Operation**

Equality operator is denoted using ```==``` and is used for exact match semantics. The negation operator using ```!=```
allows to specify NOT equals. Here are example of this usage

<pre>
keyName == "Key"
security_groups == ["sg-1234567", "sg-1234err5"] # exact match
keyName != "Key2" 
</pre> 

Key points
- if the LHS query provides a collection, then every element in the collection must be ```==``` or ```!=```
- if the RHS side is a regular expression, then it evaluates to a match against that expression for all elements
- if the RHS is a collection and LHS is a collection they have to be equal

**Comparison Operators**

The standard comparison operators are ```>, >=, <, <=``` are used for checking order. Comparison operator can be used 
directly on scalar or collection of scalars. Examples 

<pre>
resources.*[ type == /AWS::RDS/ ].BackupRetentionPeriod >= 7
</pre>

Queries can be assigned to variables and then compared using operators

<pre>
#
# select all Aurora DB clusters in the template.
#
let aurora_db_clusters = resources.*[type == /AWS::RDS::DBCluster/]

#
# For each cluster selected checks for the all of these being set (with ANDs)
# - Backup is >= 7 days
# - deletion protection is enabled
# - storage encryption is on
#
%aurora_db_clusters.BackupRetentionPeriod >= 7
%aurora_db_clusters.deletion_protection == true  # the tool must support casing differences for match. 
%aurora_db_clusters.StorageEncrypted == true
</pre>

**Special Operators**

There are 2 special purpose operators <code>KEYS, IN</code>. 

<ul>
<li> <em>KEYS</em>: is used in the context of map/structured types to access the "keys" for the structured type. This is useful when 
the keys are not based on pre-defined schema. E.g when tags are specified, the keys are not known ahead of time. It 
 is effectively a list of key-value pairs, e.g. <code>[ { "prod-id": "prod-env-ID233434", "app-id": "app-ID12343sdfsf" } ]</code>
 KEYS is used in the scenarios to collect all the keys contained in the structure. Example usages 
 <pre>
    resources.*.properties.tags[*] KEYS == /prod/
 </pre>
 This effectively selects tags from all resources inside a CFN template and extracts the KEYS for them. This would return
 <code>[ "prod-id", "app-id" ]</code> which is then compared against the Regex. In this case it fails as "app-id" does not
 match. <p>
 In this example the incoming tags contains <code>[ { "aws:application-id": "app-x1233434" }, { "prod-env": "prod-IDasasas" } ]</code> 
 <pre>    
    resources.*.properties.tags[ KEYS == /aws:application/ ].* == /^app-x1234/ 
 </pre>
 This is a variation that uses <em>KEYS</em> for filtering. This is selecting all tags key-value pairs when the "key" matches
 "aws:application". The above query will return <code>[ { "aws:application-id": "app-x1233434" } ]</code>. We then select 
 all values from the tag structured object that resolves to <code>[ "app-x1233434" ]</code>. The comparison succeeds againts
 the Regex.
</li>
<li><em>IN</em>: operator is used when we need to match ANY one of the values in the list. Example usage 
<pre>
    let aurora_db_clusters = resources.*[type == /AWS::RDS::DBCluster/]
    %aurora_db_clusters.enable_cloudwatch_logs_exports IN 
        ["audit", error, general, "slowquery"]
</pre> 
This is equivalent to the following 
<pre>
    %aurora_db_clusters.enable_cloudwatch_logs_exports == "audit"       OR
    %aurora_db_clusters.enable_cloudwatch_logs_exports == "error"       OR
    %aurora_db_clusters.enable_cloudwatch_logs_exports == "general"     OR
    %aurora_db_clusters.enable_cloudwatch_logs_exports == "slowquery"
</pre>
Values can be scalars, map-types or even collections.
</li>
</ul>
