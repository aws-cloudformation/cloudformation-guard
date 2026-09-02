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

> **Workaround**: use the block form to traverse all values to show all resource failures and not just the first one that failed. We are tracking to resolve this issue. 2. Need `when` guards with filter expressions- When a query uses filters like `Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]`, if there are no `ApiGateway` resources, then Guard will fail the clause today when performing the check

```
%api_gws.Properties.EndpointConfiguration.Types[*] == "PRIVATE"
```

> **Workaround**: assign filters to variables and use `when` condition check e.g.

```
let api_gws = Resources.*[ Type == 'AWS::ApiGateway::RestApi' ]
    when %api_gws !empty { ...}
```

2. When performing `!=` comparison, if the values are incompatible like comparing a `string` to `int`, an error is thrown internally but currently suppressed and converted to `false` to satisfy the requirements of Rust’s [PartialEq](https://doc.rust-lang.org/std/cmp/trait.PartialEq.html). We are tracking to release a fix for this issue soon.

   `integer` and `float` are no longer among the incompatible pairs: they compare against each other as numbers, so `Size > 10` holds for a `Size` of `50.5` and `Size == 50` holds for a `Size` of `50.0`. See [Guard: Clauses](CLAUSES.md) for the details, including why it mattered inside a `when` condition.

   The non-finite spellings are strings, not numbers. `nan`, `inf` and `infinity` in a document are read as strings, which is what YAML resolves them to -- it spells the non-finite floats `.nan` and `.inf`, and those were always read as strings here. A clause comparing one of them against a number is therefore an incompatible pair as described above. A number in a document that is out of range for a 64 bit float, such as `1e999`, is read the same way and for the same reason -- it would otherwise become an infinity, which no comparison can decide against. A float literal in a *rule* that is out of range, or that rounds to zero, is a parse error rather than a silently different bound, because a rule is authored and its author can be told.
3. `exists` and `empty` checks do not display the JSON pointer path inside the document in the error messages. Both these clauses often have retrieval errors which does not maintain this traversal information today. We are tracking to resolve this issue.
4. <a name="function-limitation"></a> **No support for calling functions inline on the LHS of an operator**

   We **do not** support inline usage of functions on the LHS of operators at the moment. The support for built-in functions when being used on the LHS of an operator is currently limited to assignment of the return value to a variable.

   Consider an example wherein our template has a node named `Instances` which is a collection. We need to author a rule that checks to ensure this collection contains a certain number of minimum items, say 2.

   These following examples are currently **NOT SUPPORTED**:

   ```
   # Not supported at the moment

   rule INSTANCES_COUNT_CHECK {
      count(Instances.*) < 2
      << Violation: We should have at least 2 instances >>
   }

   # OR

   rule VERIFY_COUNT_RETURNS_INT {
      count(Instances.*) is_int
      << Violation: We should have at least 2 instances >>
   }
   ```

   While the above code snippet might be tempting to use we haven't made the changes required to support it in our grammar yet.

   > **Workaround**:
   > When working with unary operators. assign the result of the function to a variable.
   > When working with binary operators, you have the choice to have the function call on the RHS of the operator, or assign the result of the function call to a variable, and then you are free to have this variable on either side of the operator.

   So, our example rule now becomes:

   ```
   # Use this instead

   rule INSTANCES_COUNT_CHECK {
      let no_of_instances = count(Instances.*)

      # all of the following options are valid ways to write this clause
      %no_of_instances < 2
      2 > %no_of_instances
      2 > count(Instances.*)
      << Violation: We should have at least 2 instances >>
   }

   rule VERIFY_COUNT_RETURNS_INT {
      let no_of_instances = count(Instances.*)
      %no_of_instances is_int
   }

   ```

   5. Key names containing dashes
      Currently dashes in key names are treated as special characters. This means that if you're trying to access a key that has a dash in it, you must wrap that key in quotes.

   eg: given the following sample template

   ```
    Resources:
      bucket:
        Type: AWS::S3::Bucket
        Properties:
          some-key: true
   ```

   if we wanted to check the `some-key` key here we would need to write a rule like so

   ```
    let root = Resources.*[ Type == "AWS::S3::Bucket" ]

    rule example_with_dash_in_key when %root !empty {
        %root.Properties."some-key" == true
    }
   ```

   Key names that read as integers need the same quoting, for a different reason: unquoted, `.80` is an
   array index, because that is how a list element is addressed without brackets. Quoted, `."80"` is a
   key name. So an account id under `Mappings` is written

   ```
    Mappings.AccountToEnv."123456789012".Env == "prod"
   ```

6. **Backward-incompatible: `\\` in a rule literal changed meaning, and a rule written for 3.2.x may no longer parse**

   A regular expression or string literal is now read by walking forward from the opening delimiter, so a backslash always consumes the character after it. Guard used to decide where a literal ended by looking at the character *before* a closing delimiter, which made a backslash's meaning depend on where it sat.

   The construct that breaks is `\\` immediately followed by `/` inside a regular expression. It used to read as one backslash plus an escaped `/`, so that `/` stayed inside the expression. The `\\` pair now closes itself and the `/` behind it ends the literal, which leaves the rest of the expression truncated -- usually as an unterminated character class or group.

   The failure is a parse error and not a changed verdict. Nothing is evaluated, no rule is reported, and the run exits `5`. The message names the fragment it could not parse, but it does not say that the escaping rule changed, so it reads like a rule that was always wrong:

   ```
   Could not parse regular expression: Parsing error at position 16: Invalid character class,
   fragment  /(?<![A-Za-z0-9\\/+=])[A-Za-z0-9\\/+=]{40}(?![A-Za-z0-9\\/+=])/
   ```

   > **Workaround**: write `\/` where you meant an escaped slash.

   ```
   # written for 3.2.x: exits 5
   NotSecretAccessKey != /(?<![A-Za-z0-9\\/+=])[A-Za-z0-9\\/+=]{40}(?![A-Za-z0-9\\/+=])/

   # the same expression, in the spelling that means what it always meant
   NotSecretAccessKey != /(?<![A-Za-z0-9\/+=])[A-Za-z0-9\/+=]{40}(?![A-Za-z0-9\/+=])/
   ```

   `\/` is accepted by both versions, so a rewritten rule keeps working against an older Guard -- with one exception: `\/` immediately before the closing `/`, as in `/a\//`, is newly writable and 3.2.x rejects it. If you meant a literal backslash followed by a literal slash rather than an escaped slash, write `\\\/`; both versions parse that.

   String literals changed in the same way, and there the effect is a different value rather than a refusal to parse. `\\` inside a string is now one backslash where it was two, so `"a\\b"` is the three characters `a\b`. A clause comparing against a doubled backslash stops matching data that carries two of them and starts matching data that carries one. What the change buys is that a string can now end in a backslash: `'x\\'` is `x\`, and 3.2.x rejected that literal outright with no spelling that produced it.

   A backslash before anything else is unchanged in both kinds of literal -- it stays in the value, backslash included -- so `/^\d{4}-\d{2}$/` and `"^arn:(\w+):(\d+)$"` mean what they always did. See [Guard: Clauses](CLAUSES.md) for the full escaping rules.

   To find candidates before upgrading, search your rules for a doubled backslash: `grep -rn '\\\\' --include='*.guard' .` That over-reports, so check each hit against the two cases above: `\\` only breaks where a `/` follows it in a regular expression, and only changes a value inside a string literal.
