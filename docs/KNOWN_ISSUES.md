# Known Issues and Workarounds

No software is perfect, here is a list of known issues /gotchas that is worth noting with potential workarounds when you do encounter them (and for some, where you don’t really have a solution) 

1. Queries assigned to variables (see [Guard: Variable, Projections and Interpolations](QUERY_PROJECTION_AND_INTERPOLATION.md)) can be accessed using two forms when defining clauses, E.g. `let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]`
    
```
%api_gws.Properties.EndpointConfiguration.Types[*] == "PRIVATE"` 
```
    
or 
    
```
%api_gws {
    Properties.EndpointConfiguration.Types[*] == "PRIVATE"
}
```

The block form iterates over all `AWS::ApiGateway::RestApi` resources found in the input. The first form short circuits and returns immediately after the first resource failure. 

> **Workaround**: use the block form to traverse all values to show all resource failures and not just the first one that failed. We are tracking to resolve this issue.
2. Need `when` guards with filter expressions- When a query uses filters like `Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]`, if there are no `ApiGatway` resources, then Guard will fail the clause today when performing the check 

```
%api_gws.Properties.EndpointConfiguration.Types[*] == "PRIVATE"
``` 
    
> **Workaround**: assign filters to variables and use `when` condition check e.g. 

```
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]
    when %api_gws !empty { ...}
```

3. When performing `!=` comparison, if the values are incompatible like comparing a `string` to `int`, an error is thrown internally but currently suppressed and converted to `false` to satisfy the requirements of Rust’s [PartialEq](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html). We are tracking to release a fix for this issue soon.
4. `exists` and `empty` checks do not display the JSON pointer path inside the document in the error messages. Both these clauses often have retrieval errors which does not maintain this traversal information today. We are tracking to resolve this issue. 
5. Currently, for `string` literals, Guard does not support embedded escaped strings. We are tracking to resolve this issue soon.
6. We have support for built-in functions, however, this is currently limited to assignment of the return value to a variable. For example, we can use a function and assign its result to a variable such as `let no_of_instances = count(Instances.*)` and then this variable can be used elsewhere in the conditions such as `%no_of_instances < 2`. However, we **cannot** re-write the same condition as `count(Instances.*) < 2` at this point of time.