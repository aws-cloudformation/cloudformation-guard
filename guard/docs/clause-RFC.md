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
to be escaped using ```\```. Examples <code>  /^.*.dkr.ecr..*.amazonaws[.*]*.com\/.*[:@]+(.*){2,255}$/, </code>

#### Structured or Map Type

This value type provides associative data with _strings_ as keys and values that can be scalars, collection or another 
 map type separated with a ```:``` and enclosed between ```{}```. Keys can be barewords (a.k.a symbols) without quotes. 
Examples
<pre><code>
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
</code></pre>

#### Collection Type

The value type represent ordered list of values contained inside ```[]``` separated by a common. The value type can be 
either a scalar, map type, or a collection type. Examples 
<pre><code>
["postgresql", "upgrade"]
</code></pre>

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

The next part of the clause is an Operator. Operator is either unary, that do not have an RHS (right hand side) to 
evaluate or binary which does. Here are set of operators

#### Binary Operators 

In the remainder of the section we will use LHS to mean left hand side of the operator and RHS mean right have side. All
clauses in the language the LHS is always a query expression. The RHS can either be a query expression or value object.

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
directly on scalar or collection of scalar. They can also be used for 

The language comprises of rules that are defined in blocks. Each block contains clauses in CNF form to be evaluated 
for the rule. A clause can reference other rules for decomposing complex evaluations. 


i) a simple but expressive query clause, ii) single assignment variables to value objects for both literal constants or from queries iii) value objects for string, regex, int, float, boolean for primitive types, and structued types composed of primitives, iv) collections of value objects r from queries, for literal and dynamic, property access notation on variables and incoming payload context, implicit ANDs with explicit ORs (CNF), and named rule references for composition is shown below.

